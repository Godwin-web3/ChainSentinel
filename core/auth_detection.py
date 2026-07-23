"""
core/auth_detection.py — Structural auth & reentrancy-guard detection

Replaces name/string-matching heuristics (modifier name lists, variable
name allowlists, regex over revert-message text) with detection grounded
in real Slither IR: does a function or modifier's own body — or any
function/modifier it internally calls — contain a genuine comparison
between msg.sender/tx.origin and a state variable, or a role/mapping
lookup keyed by msg.sender? That comparison is real evidence of access
control regardless of what the developer named the variable or the
modifier — a custom-named modifier like `gatekept` enforcing
`require(msg.sender == pendingOwner)` is exactly as valid an auth gate
as one named `onlyOwner`, and this module treats them identically.

Three detectors:
  compute_own_auth()      — is this function/modifier itself (or
                             something it calls) a real auth check?
  is_reentrancy_guard()   — is this modifier structurally a reentrancy
                             guard (read-check-set-before/reset-after
                             around its own PLACEHOLDER node)?
  find_self_scoped_writes() — for a given entry function, which
                             privileged storage writes reachable from it
                             are PROVABLY keyed by msg.sender itself (an
                             attacker can only ever affect their OWN
                             slot, e.g. AccessControl.renounceRole's
                             require(account == _msgSender()) before
                             writing _roles[role].members[account])? A
                             narrower, sink-specific question than
                             compute_own_auth: NOT "is this call gated
                             at all" but "is the specific storage this
                             call can corrupt limited to the caller's
                             own identity." Deliberately does not treat
                             ANY parameter-vs-msg.sender comparison
                             anywhere in a function as blanket auth
                             evidence (that would be a real weakening —
                             e.g. checking caller==msg.sender proves
                             nothing about a write keyed by an unrelated
                             victim parameter); only the EXACT write
                             whose own index key is proven msg.sender
                             -bound is ever recorded.

Both operate on live Slither Function/Modifier objects — they must run
where those objects are already in scope (core/graph.py's live Slither
session), not in analysis/enricher.py's separate subprocess+text-parsing
pipeline, which never has real IR to inspect.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from slither.slithir.operations import (
    Assignment, Binary, HighLevelCall, Index, InternalCall, LibraryCall, LowLevelCall,
    Member, Return, Send, SolidityCall, Transfer, TypeConversion,
)
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.variables.temporary import TemporaryVariable
from slither.core.cfg.node import NodeType

from core.destination_origin import resolve_variable_origin, DestinationOrigin
from core.edges import (
    _follow_reference,
    _is_state_variable,
    _is_storage_mapping,
    _is_const_value,
    _find_defining_op,
    _func_canonical_id,
    _node_can_revert,
    _is_view_or_pure_callee,
)

# Origins that count as "not caller-controlled" on the non-msg.sender side
# of a comparison — a real access-control check compares msg.sender
# against something the caller cannot also freely supply.
_FIXED_ORIGINS = (DestinationOrigin.STATE_VARIABLE, DestinationOrigin.IMMUTABLE)


@dataclass
class AuthFinding:
    score: int                              # 0-3, same scale the rest of the codebase uses
    evidence_type: str                      # "direct_comparison" | "role_mapping" | "internal_call_delegated" | "none"
    matched_state_var: Optional[str] = None  # stringified StateVariable the comparison/lookup targeted


_NONE = AuthFinding(score=0, evidence_type="none", matched_state_var=None)


def _is_msg_sender_origin(origin: DestinationOrigin) -> bool:
    return origin == DestinationOrigin.MSG_SENDER


def _resolve_operand(var, f, known_msg_sender: frozenset = frozenset(), max_depth: int = 2):
    """
    Resolve a comparison/lookup operand. Two things beyond plain
    resolve_variable_origin():

    1. known_msg_sender — a set of THIS function's own parameter objects
       already proven, at the call site that invoked f, to have been
       passed msg.sender/tx.origin as the argument (see
       _msg_sender_params_for_call below). A generic helper like OZ's
       `hasRole(bytes32 role, address account)` has no idea msg.sender is
       involved just from its own body — `account` is an opaque
       parameter until you look at how THIS caller invoked it
       (`hasRole(role, _msgSender())`). This is real interprocedural
       argument binding, not a guess: the parameter is only ever treated
       as msg.sender when a real call site's own resolved argument
       proves it.
    2. Unwraps single-hop _msgSender()/_msgData()-style internal-call
       wrappers (OpenZeppelin's Context base contract) that
       resolve_variable_origin can't see through on its own — it
       correctly stops at RETURN_VALUE for any call, since in general a
       call's return value could be anything. Verifies the callee's own
       body actually, structurally, returns msg.sender/tx.origin before
       treating the wrapper's result as such.
    """
    if any(var is p for p in known_msg_sender):
        return DestinationOrigin.MSG_SENDER, var

    origin, resolved = resolve_variable_origin(var, f)
    if origin != DestinationOrigin.RETURN_VALUE or max_depth <= 0:
        return origin, resolved
    defining_op = _find_defining_op(var, f)
    if not isinstance(defining_op, InternalCall):
        return origin, resolved
    callee = getattr(defining_op, "function", None)
    if callee is None:
        return origin, resolved
    callee_known = _msg_sender_params_for_call(defining_op, f, known_msg_sender, callee)
    try:
        callee_nodes = list(getattr(callee, "nodes", []) or [])
    except Exception:
        return origin, resolved
    for node in callee_nodes:
        for ir in node.irs:
            if isinstance(ir, Return):
                for v in (getattr(ir, "values", None) or []):
                    r_origin, r_var = _resolve_operand(v, callee, callee_known, max_depth - 1)
                    if _is_msg_sender_origin(r_origin):
                        return DestinationOrigin.MSG_SENDER, r_var
    return origin, resolved


def _msg_sender_params_for_call(call_ir, caller_f, caller_known: frozenset, callee) -> frozenset:
    """
    For an InternalCall, resolve each real argument in the CALLER's own
    context (recursively honoring the caller's own known_msg_sender
    bindings) and return the set of the CALLEE's parameter objects whose
    corresponding argument resolves to msg.sender/tx.origin. Positional
    only — Solidity internal calls are positional.
    """
    try:
        args = list(getattr(call_ir, "arguments", None) or [])
        params = list(getattr(callee, "parameters", None) or [])
    except Exception:
        return frozenset()
    out = set()
    for param, arg in zip(params, args):
        arg_origin, _ = _resolve_operand(arg, caller_f, caller_known)
        if _is_msg_sender_origin(arg_origin):
            out.add(param)
    return frozenset(out)


def _direct_comparison_ir(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    """
    Core matcher (no node-level gating): a Binary EQUAL/NOT_EQUAL op
    comparing msg.sender/tx.origin (possibly via a _msgSender()-style
    wrapper, or a parameter proven bound to msg.sender at the call site —
    see known_msg_sender) against a state variable (or immutable) — real,
    not caller-controlled.
    """
    for ir in node.irs:
        if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        left_origin, left_var = _resolve_operand(ir.variable_left, f, known_msg_sender)
        right_origin, right_var = _resolve_operand(ir.variable_right, f, known_msg_sender)
        if _is_msg_sender_origin(left_origin) and right_origin in _FIXED_ORIGINS:
            return AuthFinding(score=3, evidence_type="direct_comparison", matched_state_var=str(right_var))
        if _is_msg_sender_origin(right_origin) and left_origin in _FIXED_ORIGINS:
            return AuthFinding(score=3, evidence_type="direct_comparison", matched_state_var=str(left_var))
    return None


def _direct_comparison_in_node(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    """
    Gated to nodes that can plausibly act as a control-flow gate: an IF
    node (its condition governs which branch executes), or an EXPRESSION
    node that itself can revert (the comparison and the require/assert
    live in the same node for the overwhelmingly common single-line
    `require(msg.sender == x)` shape — confirmed against real Slither IR).
    """
    if not (node.type == NodeType.IF or _node_can_revert(node)):
        return None
    return _direct_comparison_ir(node, f, known_msg_sender)


def _external_view_comparison_ir(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    """
    A Binary EQUAL/NOT_EQUAL comparing msg.sender/tx.origin against the
    return value of an EXTERNAL, read-only (view/pure) call whose own
    destination resolves to a fixed origin (state variable/immutable,
    never caller-controlled) — the real Uniswap V3 onlyFactoryOwner
    shape, found live this session:
        require(msg.sender == IUniswapV3Factory(factory).owner());
    _direct_comparison_ir alone can't see this: resolve_variable_origin
    correctly stops at RETURN_VALUE for any call in general (a random
    function's return could be attacker-influenced through calldata it
    reads), but here the CALL DESTINATION itself is fixed and the call
    is view-only (cannot have side effects) — the same trust basis
    _FIXED_ORIGINS already grants a plain state-variable read, just one
    real external hop further. Distinct from _resolve_operand's
    _msgSender()-unwrap (which verifies an INTERNAL callee's own body,
    something we can actually inspect) — this is for an EXTERNAL
    interface call whose implementation can never be inspected at all;
    trust comes from the destination being fixed and the call being
    provably side-effect-free, not from reasoning about the callee's
    own logic.
    """
    for ir in node.irs:
        if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        left_origin, _ = _resolve_operand(ir.variable_left, f, known_msg_sender)
        right_origin, _ = _resolve_operand(ir.variable_right, f, known_msg_sender)
        if _is_msg_sender_origin(left_origin):
            call_var = ir.variable_right
        elif _is_msg_sender_origin(right_origin):
            call_var = ir.variable_left
        else:
            continue

        call_ir = _find_defining_op(call_var, f)
        if not isinstance(call_ir, HighLevelCall):
            continue
        callee = getattr(call_ir, "function", None)
        if not _is_view_or_pure_callee(callee):
            continue
        dest = getattr(call_ir, "destination", None)
        if dest is None:
            continue
        dest_origin, dest_var = resolve_variable_origin(dest, f)
        if dest_origin in _FIXED_ORIGINS:
            return AuthFinding(score=3, evidence_type="external_view_comparison", matched_state_var=str(dest_var))
    return None


def _external_view_comparison_in_node(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    if not (node.type == NodeType.IF or _node_can_revert(node)):
        return None
    return _external_view_comparison_ir(node, f, known_msg_sender)


def _is_fixed_call_destination(var, f, max_depth: int = 3) -> bool:
    """
    True if var resolves to a fixed (state variable / immutable) origin
    directly, OR var is the return value of an internal call whose own
    body does nothing but forward to (return) a HighLevelCall on a
    view/pure function whose OWN destination is, recursively, fixed by
    this same definition. The real Balancer/Berachain BEX shape, found
    live against ProtocolFeesCollector.sol:
        function _canPerform(...) internal view returns (bool) {
            return _getAuthorizer().canPerform(...);
        }
        function _getAuthorizer() internal view returns (IAuthorizer) {
            return vault.getAuthorizer();
        }
    where `vault` is `IVault public immutable`. Trust here rests on the
    same basis _external_view_comparison_ir already relies on for a
    single external hop (a view/pure call can't have side effects, and a
    fixed destination can't be attacker-supplied) — this just lets that
    trust cross an internal forwarding layer too, since the indirection
    itself introduces no destination of its own to manipulate; it only
    ever returns what a fixed-basis external view call reports.
    """
    origin, _ = resolve_variable_origin(var, f)
    if origin in _FIXED_ORIGINS:
        return True
    if origin != DestinationOrigin.RETURN_VALUE or max_depth <= 0:
        return False
    defining_op = _find_defining_op(var, f)
    if not isinstance(defining_op, InternalCall):
        return False
    callee = getattr(defining_op, "function", None)
    if callee is None:
        return False
    try:
        callee_nodes = list(getattr(callee, "nodes", []) or [])
    except Exception:
        return False
    for node in callee_nodes:
        for ir in node.irs:
            if not isinstance(ir, Return):
                continue
            for v in (getattr(ir, "values", None) or []):
                call_ir = _find_defining_op(v, callee)
                if isinstance(call_ir, HighLevelCall):
                    callee_fn = getattr(call_ir, "function", None)
                    if not _is_view_or_pure_callee(callee_fn):
                        continue
                    call_dest = getattr(call_ir, "destination", None)
                    if call_dest is not None and _is_fixed_call_destination(call_dest, callee, max_depth - 1):
                        return True
                elif _is_fixed_call_destination(v, callee, max_depth - 1):
                    return True
    return False


def _external_view_return_verdict_ir(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    """
    A Return node whose value is directly (no `==`/`!=` comparison) the
    boolean result of an external, read-only (view/pure) call whose
    destination resolves to fixed origin (possibly through an internal
    forwarding hop — see _is_fixed_call_destination) and whose ARGUMENTS
    include a value proven msg.sender-bound. The real Balancer/
    Berachain BEX Authorizer shape, found live against real
    ProtocolFeesCollector.withdrawCollectedFees():
        function _canPerform(bytes32 actionId, address account)
            internal view override returns (bool)
        {
            return _getAuthorizer().canPerform(actionId, account, address(this));
        }
    _external_view_comparison_ir can't see this: there is no `==`/`!=`
    anywhere — the callee's raw boolean return IS the verdict, forwarded
    unchanged up through a revert-wrapper like `_require(...)`. A
    fixed-destination, side-effect-free call that receives the caller's
    own identity as an argument and reports a yes/no answer is
    structurally identical to comparing msg.sender against a stored
    allowlist — just phrased as a query instead of a comparison, and
    without that a genuine on-chain, actively-used authorization pattern
    (Balancer's real Authorizer/actionId permission model) would be
    misclassified as unguarded.
    """
    for ir in node.irs:
        if not isinstance(ir, Return):
            continue
        for val in (getattr(ir, "values", None) or []):
            v = val
            call_ir = _find_defining_op(v, f)
            if isinstance(call_ir, TypeConversion):
                v = call_ir.variable
                call_ir = _find_defining_op(v, f)
            if not isinstance(call_ir, HighLevelCall):
                continue
            callee = getattr(call_ir, "function", None)
            if not _is_view_or_pure_callee(callee):
                continue
            if str(getattr(call_ir.lvalue, "type", None)) != "bool":
                continue
            dest = getattr(call_ir, "destination", None)
            if dest is None or not _is_fixed_call_destination(dest, f):
                continue
            for arg in (getattr(call_ir, "arguments", None) or []):
                arg_origin, _ = _resolve_operand(arg, f, known_msg_sender)
                if _is_msg_sender_origin(arg_origin):
                    return AuthFinding(
                        score=3, evidence_type="external_view_return_verdict", matched_state_var=str(dest)
                    )
    return None


def _resolve_mapping_base(var, f, max_depth: int = 6):
    """
    Backward-slice a mapping-lookup base (possibly through nested
    Index/Member hops, e.g. _roles[role].members[msg.sender] — real
    OpenZeppelin AccessControl's actual struct-wrapped role storage, not
    just a flat nested mapping) to the root StateVariable, returning it
    only if it's actually a mapping type. Same backward-slice shape as
    core/edges.py::_key_derives_from_struct, applied to a different
    question (identify the root, not match a param).
    """
    current = var
    seen: Set[int] = set()
    for _ in range(max_depth):
        if id(current) in seen:
            return None
        seen.add(id(current))
        followed = _follow_reference(current)
        if _is_state_variable(followed):
            return followed if _is_storage_mapping(followed) else None
        defining_op = _find_defining_op(current, f)
        if defining_op is None or not isinstance(defining_op, (Index, Member)):
            return None
        current = getattr(defining_op, "variable_left", None)
        if current is None:
            return None
    return None


def _role_mapping_ir(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    """
    Core matcher (no node-level gating): an Index op whose key resolves
    to msg.sender/tx.origin (directly, or via a parameter proven bound
    to it at the call site — see known_msg_sender), whose base resolves
    (possibly through nested mapping/struct hops) to a real storage
    mapping, AND whose result is used as a boolean-shaped permission
    flag — either (a) the Index's own VALUE TYPE is bool (real OZ
    AccessControl's `_roles[role].members[msg.sender]`), or (b) the
    Index result feeds a Binary EQUAL/NOT_EQUAL comparison against a
    literal CONSTANT (real MakerDAO's `wards[msg.sender] == 1` — a
    pre-0.8-style numeric membership flag, semantically identical to a
    bool but stored as uint for historical/gas reasons across the
    entire DSS ecosystem: Vat, Jug, Pot, Spot, Cat, Dog, Vow, Flap,
    Flop, End, every Join). Both are the same structural claim: the
    mapping holds a caller-independent, admin-set permission bit,
    detected with zero name matching.

    The type/comparison gate is load-bearing, not decorative: without
    it, this matches ANY msg.sender-keyed mapping read inside a
    revert-capable node — including a plain ECONOMIC allowance check
    like real Dai's `require(allowance[src][msg.sender] >= wad)`, which
    has the IDENTICAL Index shape (key=msg.sender, base=a real mapping)
    but is a numeric spending-limit comparison, not an access-control
    flag. Confirmed via real IR: allowance[src][msg.sender]'s Index
    result type is uint256; real AccessControl's
    _roles[role].members[account]'s Index result type is bool. Found
    live this session — Dai's transferFrom() scored auth_score=3
    (AUTHENTICATED) purely from its own allowance-underflow guard,
    despite being a fully permissionless ERC20 function.

    Branch (b) stays safely distinct from that same false positive
    because it requires BOTH equality (not ordering — Dai's allowance
    check is `>=`, never `==`) AND a literal constant on the other side
    (not a variable — an amount like Dai's `wad` is caller-supplied,
    never a constant). A real economic threshold check can't satisfy
    both at once. Found live this session: MakerDAO's `wards` pattern
    stopped scoring AUTHENTICATED at all after the bool-type gate
    landed (its Index result type is uint256, not bool), silently
    losing auth detection — and with it, `wards`' STORAGE_CORRUPTION
    "privileged" classification — across every DSS contract.
    """
    for ir in node.irs:
        if not isinstance(ir, Index):
            continue
        key_origin, _ = _resolve_operand(ir.variable_right, f, known_msg_sender)
        if not _is_msg_sender_origin(key_origin):
            continue
        is_bool = str(getattr(ir.lvalue, "type", None)) == "bool"
        is_const_equality_flag = is_bool or any(
            isinstance(other, Binary)
            and other.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL)
            and (
                (other.variable_left is ir.lvalue and _is_const_value(other.variable_right))
                or (other.variable_right is ir.lvalue and _is_const_value(other.variable_left))
            )
            for other in node.irs
        )
        if not is_const_equality_flag:
            continue
        base = _resolve_mapping_base(ir.variable_left, f)
        if base is not None:
            return AuthFinding(score=3, evidence_type="role_mapping", matched_state_var=str(base))
    return None


def _role_mapping_in_node(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    if not _node_can_revert(node):
        return None
    return _role_mapping_ir(node, f, known_msg_sender)


_ORDERING_COMPARISON_TYPES = (
    BinaryType.LESS, BinaryType.GREATER, BinaryType.LESS_EQUAL, BinaryType.GREATER_EQUAL,
)


def find_economic_threshold_vars(f, max_depth: int = 2, _visited: Optional[set] = None) -> Set[str]:
    """
    Real variable names read via a msg.sender-keyed Index whose result
    is NUMERIC (not bool) and feeds a numeric ordering comparison
    (<, >, <=, >=) — the real Dai.transferFrom()/Fraxlend shape:
        require(allowance[src][msg.sender] >= wad, "...");
        if (userBorrowShares[msg.sender] > 0) { ... }
    Deliberately the MIRROR IMAGE of _role_mapping_ir's bool-type gate
    (same key/base shape, opposite value-type requirement) — NOT an
    access-control signal (a numeric threshold/allowance check is not a
    role/permission grant; Dai's transferFrom is correctly NOT
    auth-scored just because it checks an allowance, and this function
    is never consulted for auth_score/AUTHENTICATED evidence).

    Gated on the comparison itself, NOT on the containing node being
    revert-capable (_node_can_revert) — real Fraxlend's
    `if (userBorrowShares[msg.sender] > 0) { ... conditional stuff ... }`
    doesn't revert directly in either branch (the actual revert, if any,
    is several statements deeper, conditional on unrelated state), so a
    revert-capable gate misses it entirely. The comparison itself is
    already real, structural evidence that the protocol treats this
    value as an economic threshold — no revert requirement needed for
    that narrower claim.

    Used ONLY to feed core/sinks.py::_privileged_vars_by_contract's
    OTHER purpose: identifying economically-sensitive (debt/balance/
    allowance) variables whose writes deserve MISSING_HEALTH_CHECK
    scrutiny — exactly the kind of numeric accounting Euler's
    donateToReserves-shaped bugs corrupt. Splitting this out as its own
    signal (rather than reusing structural_auth_var, which the bool-type
    fix deliberately narrowed) is what lets Dai.transferFrom() stay
    correctly UNAUTHENTICATED while real Fraxlend's repayAsset()/
    liquidate() still register userBorrowShares as sink-worthy — found
    live this session: without this split, fixing the real
    transferFrom() false-AUTHENTICATED bug silently made
    _privileged_vars_by_contract blind to userBorrowShares entirely,
    losing a genuine, correct MISSING_HEALTH_CHECK finding.
    """
    if _visited is None:
        _visited = set()
    fid = id(f)
    if fid in _visited:
        return set()
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return set()

    found: Set[str] = set()
    for node in nodes:
        for ir in node.irs:
            if not isinstance(ir, Index):
                continue
            if str(getattr(ir.lvalue, "type", None)) == "bool":
                continue
            key_origin, _ = _resolve_operand(ir.variable_right, f)
            if not _is_msg_sender_origin(key_origin):
                continue
            if not any(
                isinstance(other, Binary)
                and other.type in _ORDERING_COMPARISON_TYPES
                and (other.variable_left is ir.lvalue or other.variable_right is ir.lvalue)
                for other in node.irs
            ):
                continue
            base = _resolve_mapping_base(ir.variable_left, f)
            if base is not None:
                found.add(str(base))

    if max_depth > 0:
        for node in nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                    found |= find_economic_threshold_vars(ir.function, max_depth - 1, _visited)
    return found


def _evidence_anywhere_in_body(f, max_depth: int, _visited: set, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    """
    Scan f's ENTIRE body for direct-comparison or role-mapping evidence
    WITHOUT the revert-capable/IF node gate, recursing into internal
    calls (propagating parameter->msg.sender bindings at each call site).
    Used only when f is reached via a node in a CALLER that's already
    proven to be a real control-flow gate — the shape real OpenZeppelin
    AccessControl actually uses: _checkRole()'s IF node calls
    hasRole(role, account), and hasRole()'s own body is a plain
    `return _roles[role].members[account];` with no revert of its own.
    That's still real evidence — trusted here because the caller already
    reverts based on it, not guessed from a function name like "hasRole".
    """
    fid = id(f)
    if fid in _visited or max_depth < 0:
        return None
    _visited.add(fid)
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None

    for node in nodes:
        finding = _direct_comparison_ir(node, f, known_msg_sender)
        if finding is not None:
            return finding
        finding = _role_mapping_ir(node, f, known_msg_sender)
        if finding is not None:
            return finding
        finding = _external_view_comparison_ir(node, f, known_msg_sender)
        if finding is not None:
            return finding
        finding = _external_view_return_verdict_ir(node, f, known_msg_sender)
        if finding is not None:
            return finding

    if max_depth <= 0:
        return None

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                callee_known = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                nested = _evidence_anywhere_in_body(ir.function, max_depth - 1, _visited, callee_known)
                if nested is not None:
                    return nested
    return None


def compute_own_auth(
    f, max_depth: int = 3, _visited: Optional[set] = None, known_msg_sender: frozenset = frozenset()
) -> AuthFinding:
    """
    Structural auth evidence for f: a real msg.sender/tx.origin
    comparison or role-mapping lookup in f's own body, or (bounded
    recursion) in any function f internally calls. Works identically for
    a Function or a Modifier object — both expose the same .nodes API.
    known_msg_sender carries parameter->msg.sender bindings down from
    whatever call site reached f (see _msg_sender_params_for_call).
    """
    if _visited is None:
        _visited = set()
    fid = id(f)
    if fid in _visited:
        return _NONE
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return _NONE

    for node in nodes:
        finding = _direct_comparison_in_node(node, f, known_msg_sender)
        if finding is not None:
            return finding
        finding = _role_mapping_in_node(node, f, known_msg_sender)
        if finding is not None:
            return finding
        finding = _external_view_comparison_in_node(node, f, known_msg_sender)
        if finding is not None:
            return finding

    if max_depth <= 0:
        return _NONE

    # A gating node (IF / revert-capable) whose CONDITION calls an
    # internal function — trust evidence found ANYWHERE in that
    # callee's body (not just its own revert-capable nodes), since the
    # callee is being consumed by an already-proven gate here. This is
    # the real OZ AccessControl shape: _checkRole()'s IF calls
    # hasRole(), whose own body is a plain return with no revert.
    for node in nodes:
        if not (node.type == NodeType.IF or _node_can_revert(node)):
            continue
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                callee_known = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                nested = _evidence_anywhere_in_body(ir.function, max_depth - 1, set(_visited), callee_known)
                if nested is not None:
                    return AuthFinding(
                        score=nested.score,
                        evidence_type="gated_internal_call",
                        matched_state_var=nested.matched_state_var,
                    )

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                callee_known = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                nested = compute_own_auth(ir.function, max_depth - 1, _visited, callee_known)
                if nested.score >= 3:
                    return AuthFinding(
                        score=nested.score,
                        evidence_type="internal_call_delegated",
                        matched_state_var=nested.matched_state_var,
                    )
    return _NONE


def _params_proven_msg_sender(f) -> frozenset:
    """
    Scan f's own body (revert-gated nodes only — a real ENFORCED
    constraint, not an incidental comparison) for a Binary EQUAL/
    NOT_EQUAL between msg.sender/tx.origin and one of f's own
    parameters. Returns the parameter objects f's own require/assert
    has proven bound to msg.sender — e.g. `account` in
    `require(account == _msgSender())`.

    This is deliberately separate from _direct_comparison_ir (which
    requires the OTHER side to be a STATE_VARIABLE/IMMUTABLE — proof of
    a REAL admin-style gate). A parameter proven == msg.sender proves
    nothing about general access control on its own (that's exactly why
    _FIXED_ORIGINS excludes PARAMETER there) — it only tells
    find_self_scoped_writes what to propagate when f calls something
    else, passing that parameter along.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return frozenset()
    out = set()
    for node in nodes:
        if not (node.type == NodeType.IF or _node_can_revert(node)):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                continue
            left_origin, left_var = _resolve_operand(ir.variable_left, f)
            right_origin, right_var = _resolve_operand(ir.variable_right, f)
            if _is_msg_sender_origin(left_origin) and right_origin == DestinationOrigin.PARAMETER:
                out.add(right_var)
            elif _is_msg_sender_origin(right_origin) and left_origin == DestinationOrigin.PARAMETER:
                out.add(left_var)
    return frozenset(out)


def _params_proven_ecrecover_signer(f) -> frozenset:
    """
    Scan f's own body (revert-gated nodes only, same basis as
    _params_proven_msg_sender) for a Binary EQUAL/NOT_EQUAL between one
    of f's own parameters and the return value of a genuine ecrecover(
    ...) SolidityCall — the real EIP-2612 permit() shape found live
    against MakerDAO's Dai.sol:
        require(holder == ecrecover(digest, v, r, s), "invalid-permit");
        ...
        allowance[holder][spender] = wad;

    An attacker cannot forge a valid ECDSA signature recovering to an
    arbitrary address: `holder` isn't caller-chosen the way an ordinary
    parameter is — the signature determines it. A storage write keyed
    by such a parameter is therefore exactly as safe as one keyed by
    msg.sender itself, just authenticated by a signature instead of the
    transaction sender. Same role as _params_proven_msg_sender: this
    proves nothing about general access control on its own (permit() is
    deliberately callable by anyone — that's the whole point of a
    gasless meta-transaction) — it only tells find_self_scoped_writes
    which parameter is safe to treat as a caller-equivalent identity for
    the outer/inner-key self-scoping checks below.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return frozenset()
    out = set()
    for node in nodes:
        if not (node.type == NodeType.IF or _node_can_revert(node)):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                continue
            for candidate, other in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
                defining_op = _find_defining_op(other, f)
                if not isinstance(defining_op, SolidityCall):
                    continue
                callee = getattr(defining_op, "function", None)
                name = (getattr(callee, "name", "") or "").split("(")[0]
                if name != "ecrecover":
                    continue
                origin, resolved = resolve_variable_origin(candidate, f)
                if origin == DestinationOrigin.PARAMETER:
                    out.add(resolved)
    return frozenset(out)


def _signer_params_for_call(call_ir, caller_f, caller_known_signer: frozenset, callee) -> frozenset:
    """
    For an InternalCall, mirrors _msg_sender_params_for_call but for
    ecrecover-proven signer parameters: if the caller passes one of its
    own known_signer parameters straight through as an argument, the
    corresponding callee parameter is equally signer-proven — the real
    shape of a permit() that factors its actual write into a shared
    internal _approve(holder, spender, wad) helper.
    """
    try:
        args = list(getattr(call_ir, "arguments", None) or [])
        params = list(getattr(callee, "parameters", None) or [])
    except Exception:
        return frozenset()
    out = set()
    for param, arg in zip(params, args):
        if any(arg is p for p in caller_known_signer):
            out.add(param)
    return frozenset(out)


def find_self_scoped_writes(
    f, max_depth: int = 3, _visited: Optional[set] = None,
    known_msg_sender: frozenset = frozenset(), known_signer: frozenset = frozenset(),
) -> Set[tuple]:
    """
    Walk f's own body and (bounded, parameter-binding-aware) recursion
    into internal calls, collecting state-write keys — SAME format as
    core.invariants.extract_field_precise_writes / Sink.privileged_writes,
    i.e. exactly what core.invariants.get_node_write(node) returns for
    that node, so the result is directly, exactly comparable to a Sink's
    own privileged_writes with no lossy re-normalization — for writes
    whose STORAGE KEY (the final Index's key, e.g. `account` in
    `_roles[role].members[account] = false`) is provably msg.sender
    itself, or a parameter proven bound to msg.sender at the exact call
    site that reached this function (known_msg_sender, propagated the
    same way compute_own_auth's interprocedural binding works) — or,
    since this session, a parameter proven bound to a cryptographically
    recovered ECDSA signer via ecrecover(...) (known_signer, the real
    EIP-2612 permit() shape: `require(holder == ecrecover(digest, v, r,
    s))` before `allowance[holder][spender] = wad`). Both are the same
    underlying claim — this key isn't caller-chosen — just proven by a
    different mechanism (the transaction sender vs. a valid signature).

    Deliberately narrow: only the write whose OWN index key resolves to
    msg.sender is recorded. A function like
    badWithdraw(address caller, address victim, uint amount) that checks
    require(caller == msg.sender) but writes balances[victim] records
    NOTHING here — the write's key is `victim`, never `caller`, so
    `victim` is never in known_msg_sender and the write is never treated
    as self-scoped. This is what keeps the check sink-specific instead
    of degrading into "any msg.sender comparison anywhere counts."

    Public entry point — does the conservative subtraction described in
    _self_scoped_and_unsafe_writes below.
    """
    self_scoped, unsafe = _self_scoped_and_unsafe_writes(
        f, max_depth, _visited if _visited is not None else set(), known_msg_sender, known_signer
    )
    return self_scoped - unsafe


def _self_scoped_and_unsafe_writes(
    f, max_depth: int, _visited: set, known_msg_sender: frozenset, known_signer: frozenset = frozenset(),
):
    """
    Returns (self_scoped_keys, unsafe_keys). Two Sink.privileged_writes-
    format keys ((root_var, member_path) — root-and-field level, NOT
    index-value level) collapse to the SAME key regardless of which
    actual index/key was written, e.g. balances[victim] and
    balances[caller] are BOTH just ('balances', ()) — the existing write-
    key format has no way to distinguish them. That means a single
    function writing the same root/field via both a self-scoped key
    (caller, proven == msg.sender) and an unrelated one (victim, not
    proven) must NOT have that key end up in the final self-scoped set —
    doing so would suppress a real vulnerability (this exact shape was
    caught live: a synthetic badWithdraw(caller, victim, amount) with
    require(caller==msg.sender) but a write to balances[victim] initially
    got wrongly marked fully self-scoped before this split was added).
    Tracking self_scoped and unsafe separately, unioned across the WHOLE
    recursive call tree from this entry, and subtracting only once at
    the public entry point (find_self_scoped_writes) is what keeps this
    conservative regardless of which function in the call chain contains
    the unsafe write.
    """
    from core.invariants import get_node_write

    fid = id(f)
    if fid in _visited:
        return set(), set()
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return set(), set()

    # Fold in any of f's OWN parameters that f's own require/assert has
    # proven bound to msg.sender — this is what lets renounceRole's
    # require(account == _msgSender()) propagate into the _revokeRole()
    # call it makes right after, passing `account` along.
    known_msg_sender = known_msg_sender | _params_proven_msg_sender(f)
    # Same idea for a parameter proven bound to an ecrecover(...)-
    # recovered signer — the real Dai.permit() shape.
    known_signer = known_signer | _params_proven_ecrecover_signer(f)

    self_scoped: Set[tuple] = set()
    unsafe: Set[tuple] = set()
    for node in nodes:
        for ir in node.irs:
            # Plain `x = y` is an Assignment; compound `x -= y`/`x += y`
            # etc. lower to a Binary op whose lvalue is the SAME
            # ReferenceVariable being read and written (confirmed against
            # real IR: `balances[msg.sender] -= amount` produces
            # `Binary REF_2(-> balances) = REF_2 (c)- amount`, not an
            # Assignment) — a plain comparison's Binary lvalue is always
            # a fresh boolean TemporaryVariable, never a ReferenceVariable,
            # so this check doesn't accidentally match those.
            if not isinstance(ir, (Assignment, Binary)):
                continue
            if not isinstance(getattr(ir, "lvalue", None), ReferenceVariable):
                continue
            write_key = get_node_write(node)
            if write_key is None:
                continue
            # Find the Index op, in this SAME node, that produced this
            # exact lvalue reference — the innermost/final index of the
            # write's Index/Member chain (e.g. the `[account]` in
            # `_roles[role].members[account] = false`).
            defining_index = None
            for cand in node.irs:
                if isinstance(cand, Index) and cand.lvalue is ir.lvalue:
                    defining_index = cand
                    break
            if defining_index is None:
                # A write we can't identify the key material for at all
                # (e.g. a plain struct field, no index) — conservatively
                # not self-scopable, never suppress on its account.
                unsafe.add(write_key)
                continue
            key_origin, key_var = _resolve_operand(defining_index.variable_right, f, known_msg_sender)
            if _is_msg_sender_origin(key_origin) or any(key_var is p for p in known_signer):
                self_scoped.add(write_key)
                continue
            # The innermost key isn't msg.sender, but for a NESTED
            # mapping the OUTERMOST key might be — the real MakerDAO
            # Vat.hope()/nope() shape: `can[msg.sender][usr] = 1`. The
            # outer index (msg.sender) confines the ENTIRE write to the
            # caller's own subtree of storage — no choice of the inner
            # key (usr) can ever reach another caller's data — exactly
            # the same guarantee ERC20's allowances[owner][spender]
            # pattern relies on. Distinct from (and checked only after)
            # the innermost-key case above, which is the renounceRole
            # shape (`_roles[role].members[account]`, where the OUTER
            # key is attacker-irrelevant `role` and only the INNER key
            # `account` matters). Also the real Dai.permit() shape:
            # `allowance[holder][spender] = wad` — the outer key
            # (holder) is proven bound to an ecrecover-recovered signer
            # rather than msg.sender, but the same "attacker can't
            # choose this key" guarantee holds either way.
            outer_key = _outermost_index_key(defining_index, f)
            if outer_key is not None:
                outer_origin, outer_var = _resolve_operand(outer_key, f, known_msg_sender)
                if _is_msg_sender_origin(outer_origin) or any(outer_var is p for p in known_signer):
                    self_scoped.add(write_key)
                    continue
            unsafe.add(write_key)

    if max_depth > 0:
        for node in nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                    callee_known = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                    callee_known_signer = _signer_params_for_call(ir, f, known_signer, ir.function)
                    nested_scoped, nested_unsafe = _self_scoped_and_unsafe_writes(
                        ir.function, max_depth - 1, _visited, callee_known, callee_known_signer
                    )
                    self_scoped |= nested_scoped
                    unsafe |= nested_unsafe
    return self_scoped, unsafe


def _outermost_index_key(index_ir, f, max_depth: int = 6):
    """
    Walk BACKWARD through an Index chain (via variable_left) from a
    given Index op to find the OUTERMOST index — the one applied
    directly to the root mapping state variable — and return its key
    operand (variable_right), or None if unresolvable.

    E.g. for `can[msg.sender][usr] = 1`, real IR:
        Index REF_2 -> can[msg.sender]      (variable_left=can, variable_right=msg.sender)
        Index REF_3 -> REF_2[usr]           (variable_left=REF_2, variable_right=usr)
    starting from the INNER index (REF_3, key=usr), this walks back via
    REF_3.variable_left (REF_2) to find REF_2's OWN defining Index —
    confirmed its variable_left (can) IS the state variable root, so
    REF_2's Index is outermost — and returns its key, msg.sender.

    A Member hop (struct field access) anywhere in the chain bails
    (returns None) rather than guessing — outer/inner scoping doesn't
    have a well-defined meaning once a struct field is involved.

    Checks `base` itself (unresolved) before ever calling
    _follow_reference on it: for a nested Index chain, `base` (e.g.
    REF_2 above) is itself a ReferenceVariable produced by the OUTER
    Index op — and REF_2.points_to resolves straight past that op to
    the ROOT state variable (`can`) in a single hop. Resolving it
    first would make `_is_state_variable(resolved_base)` true one
    level too early, short-circuiting the walk before it reaches the
    true outermost key — confirmed live as a real regression the
    moment core/edges.py::_follow_reference's stale import was fixed
    (it had been a no-op, so this ordering issue never manifested
    before). _follow_reference is still tried as a fallback, for a
    genuine alias base (e.g. a storage-pointer local variable) that
    _find_defining_op can't walk any further via Index.
    """
    current = index_ir
    seen: Set[int] = set()
    for _ in range(max_depth):
        base = getattr(current, "variable_left", None)
        if base is None:
            return None
        if _is_state_variable(base):
            return current.variable_right
        if id(base) in seen:
            return None
        seen.add(id(base))
        defining_op = _find_defining_op(base, f)
        if isinstance(defining_op, Index):
            current = defining_op
            continue
        if _is_state_variable(_follow_reference(base)):
            return current.variable_right
        return None
    return None


# Real ERC20/721/1155 transfer-shaped signatures, split by which
# argument position is the fund SOURCE ("from" — safe when it's
# msg.sender: the caller is only ever moving funds they've already
# approved, exactly the guarantee ERC20's own allowance mechanism
# already enforces) vs the fund DESTINATION ("to" — safe when it's
# msg.sender: the caller can only ever redirect funds back to
# themselves, never to an arbitrary address). Same canonical signature
# set as core/edges.py::TOKEN_TRANSFER_SIGNATURES, split with role
# information that module doesn't need for its own (sink-classification)
# purpose.
_TRANSFER_FROM_ARG_INDEX = {
    "transferFrom(address,address,uint256)": 0,
    "safeTransferFrom(address,address,uint256)": 0,
    "safeTransferFrom(address,address,uint256,bytes)": 0,
    "safeTransferFrom(address,address,uint256,uint256,bytes)": 0,
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)": 0,
}
_TRANSFER_TO_ARG_INDEX = {
    "transfer(address,uint256)": 0,
    "safeTransfer(address,uint256)": 0,
}


def _transfer_call_signature(ir) -> Optional[str]:
    """
    Real canonical signature for a HighLevelCall — the resolved callee's
    own solidity_signature when statically known, or one reconstructed
    from the call IR's own resolved argument types otherwise. Mirrors
    core/edges.py::_is_token_transfer_call's resolution, needed here as
    a string (not just a membership boolean) to look up argument roles.

    LibraryCall is a HighLevelCall subclass (e.g. OpenZeppelin's
    `using SafeERC20 for IERC20; ... token.safeTransferFrom(from, to,
    amount)`) — real IR confirmed live against Fraxlend's
    `_repayAsset`: Slither's own solidity_signature for that call is
    `safeTransferFrom(address,address,address,uint256)`, one arg longer
    than the literal ERC20 shape, because the library's own "self"
    receiver (the token) is prepended as a real leading parameter. Strip
    it so the signature matches the canonical keys in
    _TRANSFER_FROM_ARG_INDEX/_TRANSFER_TO_ARG_INDEX the same way a
    direct HighLevelCall would — callers must then use
    _transfer_call_arg_offset(ir) to index into ir.arguments correctly,
    since the arguments list itself still includes that leading token.
    """
    try:
        fn = getattr(ir, "function", None)
        if fn is not None and hasattr(fn, "solidity_signature"):
            sig = fn.solidity_signature
        else:
            fname = str(getattr(ir, "function_name", "") or "")
            if not fname:
                return None
            from slither.utils.type import convert_type_for_solidity_signature_to_string
            arg_types = []
            for a in (getattr(ir, "arguments", None) or []):
                t = getattr(a, "type", None)
                if t is None:
                    return None
                arg_types.append(convert_type_for_solidity_signature_to_string(t))
            sig = f"{fname}({','.join(arg_types)})"

        if isinstance(ir, LibraryCall):
            open_paren = sig.index("(")
            fname, arg_str = sig[:open_paren], sig[open_paren + 1:-1]
            arg_types = arg_str.split(",") if arg_str else []
            if arg_types:
                sig = f"{fname}({','.join(arg_types[1:])})"
        return sig
    except Exception:
        return None


def _transfer_call_arg_offset(ir) -> int:
    """
    Index offset into ir.arguments for _TRANSFER_FROM_ARG_INDEX/
    _TRANSFER_TO_ARG_INDEX lookups. A LibraryCall's arguments list keeps
    the leading "self" token receiver that _transfer_call_signature
    strips from the matched signature, so an index resolved against
    that stripped signature needs +1 to land on the real from/to arg.
    """
    return 1 if isinstance(ir, LibraryCall) else 0


def _returned_reference(callee):
    """First value in callee's own Return IR, or None (e.g. void functions)."""
    try:
        nodes = list(getattr(callee, "nodes", []) or [])
    except Exception:
        return None
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Return):
                values = getattr(ir, "values", None) or []
                if values:
                    return values[0]
    return None


def _is_self_scoped_getter_ref(var, f, known_msg_sender: frozenset) -> bool:
    """
    True if var was assigned from a LibraryCall/InternalCall ("get()"-
    shaped accessor) whose call-site arguments prove one of them is
    msg.sender-bound, and whose OWN body's returned value traces to an
    Index into one of its OTHER parameters (the "self" storage mapping)
    keyed either directly by that msg.sender-bound parameter, or by the
    result of a keccak256/sha256 hash whose own arguments include it —
    the real Uniswap V3 Position.get(self, owner, tickLower, tickUpper)
    shape:
        position = self[keccak256(abi.encodePacked(owner, tickLower, tickUpper))];
    An attacker calling collect() can choose tickLower/tickUpper
    freely, but never `owner` — that argument is hardcoded to
    msg.sender at the real call site (`positions.get(msg.sender,
    tickLower, tickUpper)`) — so no matter what else is hashed
    alongside it, the resulting slot can only ever fall in the
    CALLER's own subtree. Exactly the same "outer key is fixed"
    guarantee _outermost_index_key already relies on for a plain
    nested mapping (`can[msg.sender][usr]`), just one indirection (a
    getter call + a hash) further — real Slither IR confirmed live
    this session: Position.get()'s only Index op keys `self` by
    exactly this keccak256(abi.encodePacked(owner, ...)) shape, and
    its Return IR returns precisely that Index's own lvalue, no branches
    or alternate paths to second-guess.
    """
    defining_op = _find_defining_op(var, f)
    # `Position.Info storage position = positions.get(...)` lowers to a
    # LibraryCall assigning a TEMPORARY, then a separate Assignment
    # into the named local `position` — one hop to see through before
    # reaching the actual call, confirmed via real IR (`position :=
    # TMP_2`, TMP_2 being the LibraryCall's own lvalue).
    if isinstance(defining_op, Assignment):
        defining_op = _find_defining_op(defining_op.rvalue, f)
    if not isinstance(defining_op, (LibraryCall, InternalCall)):
        return False
    callee = getattr(defining_op, "function", None)
    if callee is None:
        return False

    args = list(getattr(defining_op, "arguments", None) or [])
    params = list(getattr(callee, "parameters", None) or [])
    if len(args) != len(params):
        return False

    bound_params = set()
    for param, arg in zip(params, args):
        origin, _ = _resolve_operand(arg, f, known_msg_sender)
        if _is_msg_sender_origin(origin):
            bound_params.add(param)
    if not bound_params:
        return False

    return_var = _returned_reference(callee)
    if return_var is None:
        return False

    index_ir = _find_defining_op(return_var, callee)
    if isinstance(index_ir, Assignment):
        index_ir = _find_defining_op(index_ir.rvalue, callee)
    if not isinstance(index_ir, Index):
        return False

    key = index_ir.variable_right
    if any(key is p for p in bound_params):
        return True

    key_op = _find_defining_op(key, callee)
    if isinstance(key_op, SolidityCall):
        name = (getattr(key_op.function, "name", "") or "").split("(")[0]
        if name in ("keccak256", "sha256", "sha3"):
            for hash_arg in getattr(key_op, "arguments", None) or []:
                if any(hash_arg is p for p in bound_params):
                    return True
                inner_op = _find_defining_op(hash_arg, callee)
                if isinstance(inner_op, SolidityCall):
                    for inner_arg in getattr(inner_op, "arguments", None) or []:
                        if any(inner_arg is p for p in bound_params):
                            return True
    return False


def _amount_is_self_funded_decrement(amount_var, f, known_msg_sender: frozenset) -> bool:
    """
    True if, anywhere in f's own body, there is a compound decrement
    (`x -= amount_var`) whose written field's BASE reference is proven
    self-scoped via a getter call (_is_self_scoped_getter_ref) — the
    real Uniswap V3 collect() shape:
        position.tokensOwed0 -= amount0;
        token0.transfer(recipient, amount0);
    where `position` comes from `positions.get(msg.sender, ...)`. The
    exact SAME variable identity is required for both the decrement
    and the transferred amount — no separate "same root" tracing
    needed (unlike find_self_scoped_liability_reductions, which has to
    see through a unit-conversion helper) since here it's literally
    the same value moved without transformation: the caller can never
    transfer out more than what was just debited from their OWN
    accrued balance in this SAME call, regardless of `to`.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False
    for node in nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type != BinaryType.SUBTRACTION:
                continue
            if ir.variable_right is not amount_var:
                continue
            if not isinstance(getattr(ir, "lvalue", None), ReferenceVariable):
                continue
            base_member = None
            for cand in node.irs:
                if isinstance(cand, Member) and cand.lvalue is ir.lvalue:
                    base_member = cand
                    break
            if base_member is None:
                continue
            base = getattr(base_member, "variable_left", None)
            if base is not None and _is_self_scoped_getter_ref(base, f, known_msg_sender):
                return True
    return False


def find_self_scoped_asset_moves(
    f, max_depth: int = 3, _visited: Optional[set] = None, known_msg_sender: frozenset = frozenset()
) -> Set[str]:
    """
    Walk f's own body and (bounded, parameter-binding-aware) recursion
    into internal calls, collecting the canonical_ids of REACHABLE
    functions whose asset-moving operations (real ERC20/721/1155
    transfer-shaped calls, or ETH Send/Transfer/lowlevel .call{value})
    are ALL provably safe without any auth gate:
      - transferFrom(from, ...)-shaped: `from` resolves to msg.sender.
        The caller can only ever move funds they've already approved —
        that guarantee is ERC20's own, the protocol needs no additional
        gate (this is the real shape behind Morpho-style permissionless
        supply()/deposit() functions).
      - transfer(to, ...)-shaped / ETH send: `to` resolves to
        msg.sender. The caller can only ever receive funds back to
        themselves, never redirect them to an arbitrary address (the
        real shape behind Liquity's withdrawFromSP() ->
        _sendETHGainToDepositor(), found live this session — the ETH
        destination is msg.sender directly, no auth gate needed or
        present in the real, audited contract).
      - transfer(to, amount)-shaped with an ARBITRARY `to`: safe
        instead when `amount` is proven a self-funded decrement
        (_amount_is_self_funded_decrement) — the real Uniswap V3
        collect() shape, where the caller's own accrued fee balance
        (looked up via a msg.sender-bound getter, see
        _is_self_scoped_getter_ref) is what's debited and sent, not an
        arbitrary amount. A self-scoped DESTINATION and a self-scoped
        SOURCE are different proofs of the same underlying safety
        property — either the caller can only receive their own funds,
        or the caller can only ever move funds that were already
        theirs — so both count as safe without an auth gate.

    Same conservative principle as find_self_scoped_writes: a function
    that ALSO makes a single unsafe move (e.g. transferFrom(victim, ...)
    or transfer(arbitraryRecipient, ...)) is excluded entirely, even if
    it makes other safe moves — self_scoped - unsafe, subtracted once at
    the public entry point. A function with NO asset-moving operations
    at all reachable from it is never included (nothing to prove safe).
    """
    self_scoped, unsafe = _self_scoped_and_unsafe_asset_moves(
        f, max_depth, _visited if _visited is not None else set(), known_msg_sender
    )
    return self_scoped - unsafe


def _self_scoped_and_unsafe_asset_moves(f, max_depth: int, _visited: set, known_msg_sender: frozenset):
    """Returns (self_scoped_function_ids, unsafe_function_ids) — see find_self_scoped_asset_moves."""
    fid = id(f)
    if fid in _visited:
        return set(), set()
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return set(), set()

    known_msg_sender = known_msg_sender | _params_proven_msg_sender(f)
    own_cid = _func_canonical_id(f)

    self_scoped: Set[str] = set()
    unsafe: Set[str] = set()

    def _record(is_safe: bool) -> None:
        if own_cid is None:
            return
        (self_scoped if is_safe else unsafe).add(own_cid)

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall):
                sig = _transfer_call_signature(ir)
                if sig is None:
                    continue
                if sig in _TRANSFER_FROM_ARG_INDEX:
                    idx = _TRANSFER_FROM_ARG_INDEX[sig]
                elif sig in _TRANSFER_TO_ARG_INDEX:
                    idx = _TRANSFER_TO_ARG_INDEX[sig]
                else:
                    continue
                idx += _transfer_call_arg_offset(ir)
                args = list(getattr(ir, "arguments", None) or [])
                if idx >= len(args):
                    continue
                origin, _ = _resolve_operand(args[idx], f, known_msg_sender)
                is_safe = _is_msg_sender_origin(origin)
                # transfer(to, amount)-shaped with an unproven `to`:
                # try the OTHER safety basis — a self-funded amount
                # (real Uniswap V3 collect() shape). Only meaningful
                # for the 2-arg transfer/safeTransfer shape (amount is
                # always the argument right after `to`), not
                # transferFrom (a 3-arg pull with a different safety
                # story already covered above).
                if not is_safe and sig in _TRANSFER_TO_ARG_INDEX:
                    amount_idx = idx + 1
                    if amount_idx < len(args):
                        is_safe = _amount_is_self_funded_decrement(args[amount_idx], f, known_msg_sender)
                _record(is_safe)
            elif isinstance(ir, (LowLevelCall, Send, Transfer)):
                dest = getattr(ir, "destination", None)
                if dest is None:
                    continue
                origin, _ = _resolve_operand(dest, f, known_msg_sender)
                _record(_is_msg_sender_origin(origin))

    if max_depth > 0:
        for node in nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                    callee_known = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                    nested_scoped, nested_unsafe = _self_scoped_and_unsafe_asset_moves(
                        ir.function, max_depth - 1, _visited, callee_known
                    )
                    self_scoped |= nested_scoped
                    unsafe |= nested_unsafe
    return self_scoped, unsafe


def _resolve_amount_roots(
    var, f, known_amount_origin: Dict[int, Set[int]], max_depth: int = 5, _seen: Optional[set] = None
) -> Set[int]:
    """
    Backward-slice `var` within f to the id()s of ALL its possible root
    identities — unlike core/edges.py::_trace_temp_to_source's single
    deterministic "last read" walk (which exists for a different,
    single-answer purpose elsewhere), this explores EVERY read at each
    defining-op step, bounded by max_depth, so a value derived through
    a pure helper call with several arguments (e.g. real Fraxlend's
    `_totalBorrow.toAmount(_shares, true)`) can still be correlated back
    to `_shares` even though it isn't the only, or the last, argument.

    known_amount_origin maps id(some variable) -> an ALREADY-RESOLVED
    set of root ids, established at whatever internal-call site bound
    it (see _amount_origins_for_call) — this is what gives a value a
    stable identity comparable across function boundaries: real
    Fraxlend's `_repayAsset(_totalBorrow, _amountToRepay.toUint128(),
    _shares.toUint128(), msg.sender, _borrower)` passes two SEPARATE
    parameters (`_amountToRepay`, `_shares`) that were computed TOGETHER
    one call frame up (`_amountToRepay = _totalBorrow.toAmount(_shares,
    true)`) — without crossing that call boundary, _repayAsset's own
    body has no way to know they're related at all.
    """
    if _seen is None:
        _seen = set()
    vid = id(var)
    if vid in _seen or max_depth <= 0:
        return {vid}
    _seen.add(vid)

    resolved = _follow_reference(var)
    rid = id(resolved)

    if rid in known_amount_origin:
        return known_amount_origin[rid]

    # A named return variable (e.g. real Fraxlend's `returns (uint256
    # _amountToRepay)`) is a LocalVariable, not a TemporaryVariable, but
    # still has its own defining Assignment (`_amountToRepay :=
    # <libraryCall result>`) that needs tracing through — only a
    # PARAMETER is a genuine root with nothing further to trace (it's
    # an input, not a computed value).
    from slither.core.variables.local_variable import LocalVariable
    is_traceable_local = isinstance(resolved, LocalVariable) and not getattr(resolved, "is_parameter", False)
    if not (isinstance(resolved, TemporaryVariable) or is_traceable_local):
        return {rid}

    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        return {rid}
    reads = list(getattr(defining_op, "read", []) or [])
    if not reads:
        return {rid}

    roots: Set[int] = set()
    for r in reads:
        roots |= _resolve_amount_roots(r, f, known_amount_origin, max_depth - 1, _seen)
    return roots


def _amount_origins_for_call(call_ir, caller_f, caller_known_amount_origin: Dict[int, Set[int]], callee) -> Dict[int, Set[int]]:
    """
    For an InternalCall, resolve each real argument's root ids in the
    CALLER's own context (honoring the caller's own known_amount_origin
    bindings), and return id(callee_param) -> that resolved root-id
    set. Positional only — Solidity internal calls are positional.
    """
    try:
        args = list(getattr(call_ir, "arguments", None) or [])
        params = list(getattr(callee, "parameters", None) or [])
    except Exception:
        return {}
    out: Dict[int, Set[int]] = {}
    for param, arg in zip(params, args):
        out[id(param)] = _resolve_amount_roots(arg, caller_f, caller_known_amount_origin)
    return out


def find_self_scoped_liability_reductions(
    f,
    max_depth: int = 3,
    _visited: Optional[set] = None,
    known_msg_sender: frozenset = frozenset(),
    known_amount_origin: Optional[Dict[int, Set[int]]] = None,
) -> Set[tuple]:
    """
    Walk f's own body and (bounded, parameter- AND amount-binding-aware)
    recursion into internal calls, collecting state-write keys (same
    format as find_self_scoped_writes / Sink.privileged_writes) for
    writes that DECREASE a privileged value by an amount PROVABLY tied
    to a real, self-scoped payment the caller is simultaneously making
    into the protocol — the real shape behind Compound/Fraxlend-style
    permissionless repayBehalf()/repayAsset(): anyone can pay down an
    ARBITRARY borrower's debt, safely, because (a) the write only ever
    DECREASES what that borrower owes — strictly better for them, never
    worse — and (b) the decrease is bounded by a real payment out of the
    caller's own pocket (found live: FraxlendPairCore._repayAsset writes
    `userBorrowShares[_borrower] -= _shares` and, in the SAME call,
    pulls `_amountToRepay` — derived from that SAME `_shares` value one
    call frame up, in repayAsset() — via `assetContract.safeTransferFrom
    (_payer, address(this), _amountToRepay)` with `_payer == msg.sender`).

    Deliberately does NOT treat "any decrease" as safe on its own — an
    unconditional decrease with no corresponding real payment (e.g.
    `collateralBalance[victim] -= amount` with no transferFrom in
    sight) is a genuine attack on an ASSET-shaped variable (draining a
    claim the victim could otherwise withdraw), structurally
    indistinguishable from a safe liability decrease by "subtraction"
    alone. Requiring the decrease amount to trace back to the SAME root
    as a real, self-scoped inbound payment is what rules that out: an
    attacker can't fake having paid real value out of their own pocket.
    """
    if known_amount_origin is None:
        known_amount_origin = {}
    decreases, payment_roots = _collect_liability_reduction_evidence(
        f, max_depth, _visited if _visited is not None else set(), known_msg_sender, known_amount_origin
    )
    return {write_key for write_key, roots in decreases if roots & payment_roots}


def _collect_liability_reduction_evidence(
    f, max_depth: int, _visited: set, known_msg_sender: frozenset, known_amount_origin: Dict[int, Set[int]],
) -> Tuple[List[Tuple[tuple, Set[int]]], Set[int]]:
    """Returns (decrease_writes_with_roots, payment_amount_roots) — see find_self_scoped_liability_reductions."""
    from core.invariants import get_node_write

    fid = id(f)
    if fid in _visited:
        return [], set()
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return [], set()

    known_msg_sender = known_msg_sender | _params_proven_msg_sender(f)

    decreases: List[Tuple[tuple, Set[int]]] = []
    payment_roots: Set[int] = set()

    for node in nodes:
        for ir in node.irs:
            if (
                isinstance(ir, Binary)
                and ir.type == BinaryType.SUBTRACTION
                and isinstance(getattr(ir, "lvalue", None), ReferenceVariable)
            ):
                write_key = get_node_write(node)
                if write_key is not None:
                    roots = _resolve_amount_roots(ir.variable_right, f, known_amount_origin)
                    decreases.append((write_key, roots))
            elif isinstance(ir, HighLevelCall):
                sig = _transfer_call_signature(ir)
                if sig not in _TRANSFER_FROM_ARG_INDEX:
                    continue
                args = list(getattr(ir, "arguments", None) or [])
                from_idx = _TRANSFER_FROM_ARG_INDEX[sig] + _transfer_call_arg_offset(ir)
                if from_idx >= len(args):
                    continue
                from_origin, _ = _resolve_operand(args[from_idx], f, known_msg_sender)
                if not _is_msg_sender_origin(from_origin):
                    continue
                # amount is always the LAST argument across every
                # signature in _TRANSFER_FROM_ARG_INDEX.
                amount_arg = args[-1]
                payment_roots |= _resolve_amount_roots(amount_arg, f, known_amount_origin)

    if max_depth > 0:
        for node in nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                    callee_known_sender = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                    callee_known_amount = _amount_origins_for_call(ir, f, known_amount_origin, ir.function)
                    nested_decreases, nested_payment_roots = _collect_liability_reduction_evidence(
                        ir.function, max_depth - 1, _visited, callee_known_sender, callee_known_amount
                    )
                    decreases.extend(nested_decreases)
                    payment_roots |= nested_payment_roots
    return decreases, payment_roots


def is_reentrancy_guard(modifier_obj) -> bool:
    """
    True if modifier_obj's real body matches a reentrancy guard's
    structural signature: some state variable is written before the
    PLACEHOLDER node (marking "entered") and the SAME variable is
    written again after it (restoring "not entered"), with a
    revert-capable node reading that variable somewhere before the
    placeholder (the "already entered" check).

    Anchored on NodeType.PLACEHOLDER (Slither's real marker for a
    modifier's `_;`) rather than any name — a modifier called `xyzzy`
    with this shape is detected identically to one called `nonReentrant`.

    Node lists on both sides of the placeholder are expanded (bounded,
    one hop) through any InternalCall they make before checking
    read/write/revert evidence — required because modern OpenZeppelin
    (v4.8+, the current standard) refactored nonReentrant to delegate
    its actual guard logic to two private helpers:
        modifier nonReentrant() {
            _nonReentrantBefore();
            _;
            _nonReentrantAfter();
        }
    The modifier's OWN body is just two InternalCalls straddling the
    placeholder — none of the real require/write logic is directly in
    it — confirmed live against real Fraxlend IR, where this caused
    nonReentrant to score is_reentrancy_guard=False and every
    nonReentrant-protected function (borrowAsset, liquidate, etc.) to
    false-positive on REENTRANCY_CEI.
    """
    try:
        nodes = list(getattr(modifier_obj, "nodes", []) or [])
    except Exception:
        return False

    placeholder_idx = None
    for i, node in enumerate(nodes):
        if node.type == NodeType.PLACEHOLDER:
            placeholder_idx = i
            break
    if placeholder_idx is None:
        return False

    before = _expand_with_internal_calls(nodes[:placeholder_idx])
    after = _expand_with_internal_calls(nodes[placeholder_idx + 1:])

    return _guard_shape_from_before_after(before, after) or _counter_fence_guard_shape(before, after)


def _guard_shape_from_before_after(before: list, after: list) -> bool:
    """
    Shared core: True if `before`/`after` node lists match a
    reentrancy-guard's structural signature — a state variable written
    in both, read somewhere in `before`, with a revert-capable node
    also in `before`. Used both by is_reentrancy_guard (split at a
    modifier's PLACEHOLDER) and has_inline_reentrancy_guard (split
    around a plain function's own candidate guard-variable writes).
    """
    written_before = _state_vars_written(before)
    written_after = _state_vars_written(after)
    candidates = written_before & written_after
    if not candidates:
        return False

    read_before = _state_vars_read(before)
    guarded_before = any(_node_can_revert(n) for n in before)

    return bool(candidates & read_before) and guarded_before


def _counter_fence_guard_shape(before: list, after: list) -> bool:
    """
    Alternate reentrancy-guard structural signature: a monotonic
    counter fence instead of a boolean lock. Some state variable is
    incremented in `before`, its post-increment value snapshotted into
    a LOCAL variable, and a revert-capable node in `after` requires
    that snapshot still equals the state variable's current value. If
    a reentrant call re-enters through the SAME modifier during the
    placeholder, it also increments the counter, so the post-call
    comparison fails and reverts — exactly the same protective
    guarantee as a boolean lock's set-before/reset-after, just
    detecting the reentrant mutation directly instead of a sentinel
    flag, and on the OTHER side of the placeholder from where
    _guard_shape_from_before_after looks for its revert-capable check.

    Found live this session against Mento Protocol's real Broker
    (Celo, 0x1B78f6acD05e7BcB00f74863bfd8a7C264143e37): its
    ReentrancyGuard.sol is OpenZeppelin's own v2.x-era guard (before
    the boolean `_status` sentinel that later replaced it):
        modifier nonReentrant() {
            _guardCounter += 1;
            uint256 localCounter = _guardCounter;
            _;
            require(localCounter == _guardCounter, "reentrant call");
        }
    _guard_shape_from_before_after requires the SAME variable written
    on BOTH sides of the placeholder (the boolean lock's set/reset
    idiom) — _guardCounter is written only in `before`, never in
    `after`, so `candidates` was always empty and this guard scored
    is_reentrancy_guard=False, false-positiving REENTRANCY_CEI +
    FLASHLOAN_WINDOW on every nonReentrant-protected function
    (swapIn/swapOut).
    """
    written_before = _state_vars_written(before)
    if not written_before:
        return False

    # Local variables in `before` assigned directly from one of
    # written_before's state variables — the post-increment snapshot.
    snapshots: Dict[int, str] = {}
    for node in before:
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            rvalue = _follow_reference(ir.rvalue)
            if _is_state_variable(rvalue) and str(rvalue) in written_before:
                snapshots[id(ir.lvalue)] = str(rvalue)

    if not snapshots:
        return False

    for node in after:
        if not _node_can_revert(node):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                continue
            for snap_side, other_side in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
                if id(snap_side) not in snapshots:
                    continue
                other_resolved = _follow_reference(other_side)
                if _is_state_variable(other_resolved) and str(other_resolved) == snapshots[id(snap_side)]:
                    return True
    return False


def has_inline_reentrancy_guard(func_obj) -> bool:
    """
    True if func_obj — a REGULAR function, not a modifier — contains an
    inlined reentrancy-guard shape directly in its own body: some state
    variable is written at least twice, read somewhere before its FIRST
    write, with a revert-capable node also before that first write, and
    written again later. The same structural signature
    is_reentrancy_guard() detects wrapped around a modifier's
    placeholder, just flattened directly into the function instead.

    Real shape found live this session: Uniswap V3's swap() inlines its
    own `lock` modifier's exact logic directly in its body instead of
    attaching the modifier (`require(slot0Start.unlocked, 'LOK');
    ... slot0.unlocked = false; ... slot0.unlocked = true;`) — a gas
    optimization on its single hottest-path function. mint()/collect()/
    flash()/collectProtocol() use the real `lock` modifier and are
    already covered by is_reentrancy_guard; swap() needed this.
    """
    try:
        nodes = list(getattr(func_obj, "nodes", []) or [])
    except Exception:
        return False

    write_positions: Dict[str, List[int]] = {}
    for i, node in enumerate(nodes):
        for var in getattr(node, "state_variables_written", []) or []:
            write_positions.setdefault(str(var), []).append(i)

    for positions in write_positions.values():
        if len(positions) < 2:
            continue
        first_idx, last_idx = positions[0], positions[-1]
        if last_idx <= first_idx:
            continue
        before = _expand_with_internal_calls(nodes[:first_idx + 1])
        after = _expand_with_internal_calls(nodes[last_idx:])
        if _guard_shape_from_before_after(before, after):
            return True
    return False


def has_state_write_after_external_call(f, max_depth: int = 30) -> bool:
    """
    True if function f's own body contains an external call (HighLevelCall
    or LowLevelCall, not a LibraryCall — libraries are stateless and
    can't reenter) from which a node writing a state variable is CFG-
    reachable (via node.sons, bounded, cycle-safe) — the real execution-
    order CEI violation, as opposed to merely having both a state write
    and an external call SOMEWHERE in the function regardless of order.

    Replaces the coarser "does this function have any state write AND
    any external call" co-occurrence signal (core/paths.py's
    node_has_state/node_has_external), which can't distinguish a real
    violation from CEI-compliant code. Found live this session: real
    Liquity's _sendETHGainToDepositor writes `ETH = newETH` BEFORE its
    `msg.sender.call{value: _amount}("")` (confirmed via real node
    order: the Assignment is node 5, the LowLevelCall is node 9) —
    CEI-compliant for that variable, correctly protected by ordering
    rather than a guard — but the co-occurrence check flagged it
    regardless, since it never looked at which came first.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False

    def _reaches_state_write(node, depth: int, visited: set) -> bool:
        if id(node) in visited or depth <= 0:
            return False
        visited.add(id(node))
        if getattr(node, "state_variables_written", None):
            return True
        for son in getattr(node, "sons", []) or []:
            if _reaches_state_write(son, depth - 1, visited):
                return True
        return False

    for node in nodes:
        has_external = any(
            isinstance(ir, (HighLevelCall, LowLevelCall)) and not isinstance(ir, LibraryCall)
            for ir in getattr(node, "irs", []) or []
        )
        if not has_external:
            continue
        if _reaches_state_write(node, max_depth, set()):
            return True
    return False


def _snapshot_read_identity(ir):
    """
    If ir is a "balance-snapshot"-style read — an InternalCall to a
    real function (e.g. Uniswap V3's own `balance0()` helper), or a
    HighLevelCall whose destination and function name are both
    resolvable (e.g. an inlined `token.balanceOf(address(this))`) —
    return a hashable identity for WHAT it reads, so a second read of
    the SAME thing later in the function can be recognized as a
    matching before/after pair. Returns None for anything else (a
    plain arithmetic op, a state-variable field read via Member, etc.)
    — deliberately narrow, since those shapes don't reliably identify
    "the same external quantity" the way a repeated call does.
    """
    if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
        return ("internal", ir.function)
    if isinstance(ir, HighLevelCall):
        dest = getattr(ir, "destination", None)
        fname = getattr(ir, "function_name", None)
        if dest is not None and fname is not None:
            return ("highlevel", str(dest), str(fname))
    return None


def _touched_leaf_vars(var, f, max_depth: int = 4, _visited: Optional[set] = None) -> Set:
    """
    Bounded, cycle-safe backward walk from var through its OWN defining
    op (Assignment/Binary/LibraryCall/TypeConversion), collecting every
    variable touched along the way — e.g. `balance0Before.add(fee0)`
    (a LibraryCall with arguments=[balance0Before, fee0]) touches both
    balance0Before and fee0. Used to recognize a require() that
    compares a WRAPPED before-snapshot (through a SafeMath-style helper
    call) against a raw after-snapshot, not just a bare variable-to-
    variable comparison.
    """
    if _visited is None:
        _visited = set()
    if var is None or id(var) in _visited or max_depth <= 0:
        return set()
    _visited.add(id(var))
    result = {var}
    defining_op = _find_defining_op(var, f)
    if defining_op is None:
        return result
    operands = []
    for attr in ("variable_left", "variable_right", "rvalue", "variable"):
        v = getattr(defining_op, attr, None)
        if v is not None:
            operands.append(v)
    operands.extend(getattr(defining_op, "arguments", None) or [])
    for op in operands:
        result |= _touched_leaf_vars(op, f, max_depth - 1, _visited)
    return result


def has_balance_invariant_after_external_call(f, max_depth: int = 30) -> bool:
    """
    True if f's own body contains a genuine snapshot-callback-reverify
    invariant around an external call — the real Uniswap V3 flash()
    shape that's the actual mechanism preventing a flash-loan callback
    exploit, not just "some check exists somewhere":
        uint256 balance0Before = balance0();
        ...
        IUniswapV3FlashCallback(msg.sender).uniswapV3FlashCallback(...);
        uint256 balance0After = balance0();
        require(balance0Before.add(fee0) <= balance0After, 'F0');

    Requires ALL THREE: (1) a snapshot read BEFORE the external call,
    (2) a snapshot read of the SAME thing (_snapshot_read_identity)
    CFG-reachable AFTER it, and (3) a revert-capable node, also
    reachable after the call, whose comparison touches BOTH snapshot
    variables (through a bounded backward walk that sees through
    SafeMath-style wrapper calls). No single one of these alone is
    real proof — e.g. a stray comparison touching only the after-
    snapshot (never the before-snapshot) proves nothing about state
    continuity across the callback window.

    core/constraints.py::_check_flashloan_window's OWN docstring
    already promises "external call + state write before it + no
    invariant enforced after" — but its code never actually checked
    for that missing third clause, so a real, present invariant like
    this one never suppressed anything. Found live this session: real
    Uniswap V3 Pool's flash()/swap()/collect() all flagged
    FLASHLOAN_WINDOW despite flash() enforcing exactly this invariant.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False

    for node in nodes:
        has_external = any(
            isinstance(ir, (HighLevelCall, LowLevelCall)) and not isinstance(ir, LibraryCall)
            for ir in getattr(node, "irs", []) or []
        )
        if not has_external:
            continue

        after_ids = set()
        stack = [node]
        while stack:
            cur = stack.pop()
            if id(cur) in after_ids or len(after_ids) > max_depth:
                continue
            after_ids.add(id(cur))
            stack.extend(getattr(cur, "sons", []) or [])

        before_snapshots = {}
        for n in nodes:
            if id(n) in after_ids:
                continue
            for ir in getattr(n, "irs", []) or []:
                src = _snapshot_read_identity(ir)
                lvalue = getattr(ir, "lvalue", None)
                if src is not None and lvalue is not None:
                    before_snapshots[src] = lvalue
        if not before_snapshots:
            continue

        after_snapshots = {}
        for n in nodes:
            if id(n) not in after_ids:
                continue
            for ir in getattr(n, "irs", []) or []:
                src = _snapshot_read_identity(ir)
                lvalue = getattr(ir, "lvalue", None)
                if src is not None and src in before_snapshots and lvalue is not None:
                    after_snapshots[src] = lvalue
        if not after_snapshots:
            continue

        for n in nodes:
            if id(n) not in after_ids or not _node_can_revert(n):
                continue
            for ir in n.irs:
                if not isinstance(ir, Binary) or ir.type not in (
                    BinaryType.LESS_EQUAL, BinaryType.GREATER_EQUAL,
                    BinaryType.LESS, BinaryType.GREATER, BinaryType.EQUAL,
                ):
                    continue
                touched = _touched_leaf_vars(ir.variable_left, f) | _touched_leaf_vars(ir.variable_right, f)
                for src, before_var in before_snapshots.items():
                    after_var = after_snapshots.get(src)
                    if after_var is not None and before_var in touched and after_var in touched:
                        return True
    return False


def has_revert_capable_body(f) -> bool:
    """
    True if ANY node in f's own body is revert-capable (core/edges.py::
    _node_can_revert — a require()/assert() SolidityCall, or an
    if(cond) revert pattern). Distinct from auth_score, which only
    counts a require/revert as evidence when its condition compares
    against msg.sender/tx.origin or a role mapping — this is broader,
    general "does this function gate on something and revert if it
    fails" evidence. Needed for health-check guards whose condition is
    derived from an EXTERNAL dependency (e.g. an oracle/registry call)
    rather than a caller-identity check — real shape: Liquity's
    _requireNoUnderCollateralizedTroves(), which reverts based on
    troveManager.getCurrentICR(...)/priceFeed.fetchPrice() and has
    auth_score=0 (no msg.sender comparison anywhere in it) despite
    being a genuine, real health check.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False
    return any(_node_can_revert(n) for n in nodes)


def _expand_with_internal_calls(nodes, max_depth: int = 2, _visited: Optional[set] = None) -> list:
    """
    Returns `nodes` plus the CFG nodes of any function directly reached
    from them via InternalCall, recursively up to max_depth hops
    (cycle-safe via _visited). Lets structural checks over a node list
    (state vars written/read, revert-capability) see evidence that
    lives inside a helper function the caller delegates to, rather than
    only what's inlined directly in the given nodes themselves.
    """
    if _visited is None:
        _visited = set()
    out = list(nodes)
    if max_depth <= 0:
        return out
    for node in nodes:
        for ir in getattr(node, "irs", []) or []:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                callee = ir.function
                cid = id(callee)
                if cid in _visited:
                    continue
                _visited.add(cid)
                try:
                    callee_nodes = list(getattr(callee, "nodes", []) or [])
                except Exception:
                    continue
                out.extend(_expand_with_internal_calls(callee_nodes, max_depth - 1, _visited))
    return out


def _state_vars_written(nodes) -> Set[str]:
    out: Set[str] = set()
    for node in nodes:
        for var in getattr(node, "state_variables_written", []) or []:
            out.add(str(var))
    return out


def _state_vars_read(nodes) -> Set[str]:
    out: Set[str] = set()
    for node in nodes:
        for var in getattr(node, "state_variables_read", []) or []:
            out.add(str(var))
    return out
