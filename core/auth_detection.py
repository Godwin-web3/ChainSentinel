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
from typing import Optional, Set

from slither.slithir.operations import (
    Assignment, Binary, HighLevelCall, Index, InternalCall, LowLevelCall,
    Member, Return, Send, SolidityCall, Transfer,
)
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.reference import ReferenceVariable
from slither.core.cfg.node import NodeType

from core.destination_origin import resolve_variable_origin, DestinationOrigin
from core.edges import (
    _follow_reference,
    _is_state_variable,
    _is_storage_mapping,
    _find_defining_op,
    _func_canonical_id,
    _node_can_revert,
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
    to it at the call site — see known_msg_sender) and whose base
    resolves (possibly through nested mapping/struct hops) to a real
    storage mapping — the structural shape of AccessControl.hasRole-style
    role lookups (`_roles[role][msg.sender]` or real OZ's
    `_roles[role].members[msg.sender]`), detected with zero name
    matching.
    """
    for ir in node.irs:
        if not isinstance(ir, Index):
            continue
        key_origin, _ = _resolve_operand(ir.variable_right, f, known_msg_sender)
        if not _is_msg_sender_origin(key_origin):
            continue
        base = _resolve_mapping_base(ir.variable_left, f)
        if base is not None:
            return AuthFinding(score=3, evidence_type="role_mapping", matched_state_var=str(base))
    return None


def _role_mapping_in_node(node, f, known_msg_sender: frozenset = frozenset()) -> Optional[AuthFinding]:
    if not _node_can_revert(node):
        return None
    return _role_mapping_ir(node, f, known_msg_sender)


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


def find_self_scoped_writes(
    f, max_depth: int = 3, _visited: Optional[set] = None, known_msg_sender: frozenset = frozenset()
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
    same way compute_own_auth's interprocedural binding works).

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
        f, max_depth, _visited if _visited is not None else set(), known_msg_sender
    )
    return self_scoped - unsafe


def _self_scoped_and_unsafe_writes(f, max_depth: int, _visited: set, known_msg_sender: frozenset):
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
            key_origin, _ = _resolve_operand(defining_index.variable_right, f, known_msg_sender)
            if _is_msg_sender_origin(key_origin):
                self_scoped.add(write_key)
            else:
                unsafe.add(write_key)

    if max_depth > 0:
        for node in nodes:
            for ir in node.irs:
                if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                    callee_known = _msg_sender_params_for_call(ir, f, known_msg_sender, ir.function)
                    nested_scoped, nested_unsafe = _self_scoped_and_unsafe_writes(
                        ir.function, max_depth - 1, _visited, callee_known
                    )
                    self_scoped |= nested_scoped
                    unsafe |= nested_unsafe
    return self_scoped, unsafe


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
    """
    try:
        fn = getattr(ir, "function", None)
        if fn is not None and hasattr(fn, "solidity_signature"):
            return fn.solidity_signature
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
        return f"{fname}({','.join(arg_types)})"
    except Exception:
        return None


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
                args = list(getattr(ir, "arguments", None) or [])
                if idx >= len(args):
                    continue
                origin, _ = _resolve_operand(args[idx], f, known_msg_sender)
                _record(_is_msg_sender_origin(origin))
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

    before = nodes[:placeholder_idx]
    after = nodes[placeholder_idx + 1:]

    written_before = _state_vars_written(before)
    written_after = _state_vars_written(after)
    candidates = written_before & written_after
    if not candidates:
        return False

    read_before = _state_vars_read(before)
    guarded_before = any(_node_can_revert(n) for n in before)

    return bool(candidates & read_before) and guarded_before


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
