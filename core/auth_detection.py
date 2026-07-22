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

Two detectors:
  compute_own_auth()   — is this function/modifier itself (or something
                          it calls) a real auth check?
  is_reentrancy_guard() — is this modifier structurally a reentrancy
                          guard (read-check-set-before/reset-after around
                          its own PLACEHOLDER node)?

Both operate on live Slither Function/Modifier objects — they must run
where those objects are already in scope (core/graph.py's live Slither
session), not in analysis/enricher.py's separate subprocess+text-parsing
pipeline, which never has real IR to inspect.
"""

from dataclasses import dataclass
from typing import Optional, Set

from slither.slithir.operations import Binary, Index, Member, InternalCall, Return, SolidityCall
from slither.slithir.operations.binary import BinaryType
from slither.core.cfg.node import NodeType

from core.destination_origin import resolve_variable_origin, DestinationOrigin
from core.edges import (
    _follow_reference,
    _is_state_variable,
    _is_storage_mapping,
    _find_defining_op,
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
