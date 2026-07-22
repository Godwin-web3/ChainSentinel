"""
core/edges.py — Typed edge extraction from Slither IR

Two layers:
  Layer 1 — IR truth: what Slither actually sees
  Layer 2 — Semantic inference: what it means for an attacker
  Layer 2.5 — Trust: who can write the destination address (data flow)

Edge types (raw):
  internal          InternalCall
  dynamic           InternalDynamicCall (function pointer, uncertain target)
  highlevel         HighLevelCall (external, typed)
  lowlevel_call     LowLevelCall where function_name == "call"
  delegatecall      LowLevelCall where function_name == "delegatecall"
  codecall          LowLevelCall where function_name == "codecall"
  library           LibraryCall
  eth_send          Send
  eth_transfer      Transfer
  new_contract      NewContract
  solidity          SolidityCall

Trust signal (highlevel only):
  trusted=True  -> destination is a storage variable written only by
                   auth-scored functions (owner/admin-gated) or the
                   constructor. Not a reentrancy surface.
  trusted=False -> destination derives from calldata / msg.sender /
                   a caller-controlled variable, or source unresolvable.
"""

from dataclasses import dataclass, field
from typing import Optional
from slither.slithir.operations import (
    InternalCall,
    InternalDynamicCall,
    HighLevelCall,
    LowLevelCall,
    LibraryCall,
    Send,
    Transfer,
    NewContract,
    SolidityCall,
)


# ── Data model ────────────────────────────────────────────────────

@dataclass
class CallEdge:
    src: str                      # canonical ID of caller
    dst: str                      # canonical ID or unresolved label

    # Layer 1 — IR truth
    raw_type: str                 # see module docstring

    # Layer 2 — semantic properties
    is_delegation: bool           # storage context inherited (delegatecall)
    is_external: bool             # crosses trust boundary
    is_value_transfer: bool       # ETH or token movement
    is_state_crossing: bool       # may mutate state in callee context
    uncertain: bool               # target unknown at static analysis time
    exploration_required: bool    # needs runtime trace or symbolic exec

    # Optional metadata
    function_name: Optional[str] = None   # resolved callee name if known
    destination: Optional[str] = None     # destination expression if external

    # Trust signal (highlevel calls only)
    # True  -> destination is a state variable written only by auth-scored
    #          functions (owner/admin-gated) or the constructor; not a
    #          reentrancy surface.
    # False -> destination derives from calldata / msg.sender / a caller-
    #          controlled variable, or source is unresolvable (conservative).
    trusted: bool = False

    # Stricter than `trusted`: True only when there is a REAL, ongoing,
    # non-constructor auth-gated setter for the destination — evidence of
    # an actively protocol-governed contract (e.g. Comptroller, changeable
    # via the admin-only _setComptroller()), as opposed to a merely
    # immutable/constructor-fixed destination (e.g. a market's underlying
    # ERC20 token) which `trusted` also marks True but which is still the
    # classic reentrancy vector real hacks exploit. See
    # core/edges.py::_writers_are_governance_gated.
    governance_gated: bool = False

    # True if this highlevel call's real, resolved argument types match a
    # canonical ERC20/721/1155 transfer-shaped signature (see
    # TOKEN_TRANSFER_SIGNATURES) — grounded in Slither's resolved types,
    # never the calling function's own name. A custom 3-arg
    # transfer(address,uint256,bytes) does NOT match; a real
    # transfer(address,uint256) does, regardless of what the surrounding
    # function is called.
    is_token_transfer: bool = False


# ── Layer 1: IR normalization ─────────────────────────────────────

def _raw_type_from_ir(ir) -> str:
    """Classify IR operation into raw call type. No inference here."""
    if isinstance(ir, InternalCall):
        return "internal"
    if isinstance(ir, InternalDynamicCall):
        return "dynamic"
    if isinstance(ir, LibraryCall):
        return "library"
    if isinstance(ir, HighLevelCall):
        return "highlevel"
    if isinstance(ir, LowLevelCall):
        fname = getattr(ir, "function_name", "") or ""
        fname = fname.lower()
        if fname == "delegatecall":
            return "delegatecall"
        if fname == "codecall":
            return "codecall"
        return "lowlevel_call"
    if isinstance(ir, Send):
        return "eth_send"
    if isinstance(ir, Transfer):
        return "eth_transfer"
    if isinstance(ir, NewContract):
        return "new_contract"
    if isinstance(ir, SolidityCall):
        return "solidity"
    return "unknown"


# ── Layer 2: Semantic inference ───────────────────────────────────

def _semantic_properties(raw_type: str) -> dict:
    """
    Derive semantic flags from raw type.
    These are attacker-relevant properties, not IR labels.
    """
    return {
        "internal": dict(
            is_delegation=False,
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=False,
            exploration_required=False,
        ),
        "dynamic": dict(
            is_delegation=False,
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=True,               # target is a stored function pointer
            exploration_required=True,    # can't resolve statically
        ),
        "highlevel": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=False,
            exploration_required=False,
        ),
        "lowlevel_call": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=True,       # .call{value:}() is common
            is_state_crossing=True,
            uncertain=True,               # destination may be attacker-controlled
            exploration_required=True,
        ),
        "delegatecall": dict(
            is_delegation=True,           # inherits storage context
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,       # writes to caller's storage
            uncertain=True,               # destination may be attacker-controlled
            exploration_required=True,
        ),
        "codecall": dict(
            is_delegation=True,
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=True,
            exploration_required=True,
        ),
        "library": dict(
            is_delegation=False,          # library calls are stateless by design
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=False,      # libraries cannot write caller state
            uncertain=False,
            exploration_required=False,
        ),
        "eth_send": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=True,
            is_state_crossing=False,
            uncertain=False,
            exploration_required=False,
        ),
        "eth_transfer": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=True,
            is_state_crossing=False,
            uncertain=False,
            exploration_required=False,
        ),
        "new_contract": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=False,
            exploration_required=False,
        ),
        "solidity": dict(
            is_delegation=False,
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=False,
            uncertain=False,
            exploration_required=False,
        ),
    }.get(raw_type, dict(
        is_delegation=False,
        is_external=False,
        is_value_transfer=False,
        is_state_crossing=False,
        uncertain=True,
        exploration_required=True,
    ))


# ── Layer 2.5: Trust resolution (data flow only, no name lists) ────
#
# A highlevel call is trusted when its destination address is a storage
# variable written only by auth-scored functions (owner/admin-gated) or
# the constructor. It is untrusted when the destination comes from
# calldata, msg.sender, or a caller-controlled variable.
#
# Trust is decided purely by data flow: who can write the destination
# address. No name-based allow/deny lists are used.

# Minimum auth_score (from enricher) for a writer to count as privileged.
# 3 == strong auth (e.g. onlyOwner / onlyRole / msg.sender == owner).
AUTH_TRUST_THRESHOLD = 3


def _is_state_variable(var) -> bool:
    """True if var is a Slither StateVariable (storage slot)."""
    try:
        from slither.core.variables.state_variable import StateVariable
        return isinstance(var, StateVariable)
    except Exception:
        return False


def _is_caller_controlled(var) -> bool:
    """
    True if var derives from calldata or a caller-controlled source:
    msg.sender / msg.data / msg.sig, or a function parameter (calldata).

    The composed-global check is isinstance-gated (SolidityVariableComposed)
    before any string comparison — proves var IS one of Slither's known
    global composed variables before checking WHICH one, rather than a
    bare substring match on an arbitrary stringified expression.
    """
    try:
        from slither.core.declarations.solidity_variables import SolidityVariableComposed
        if isinstance(var, SolidityVariableComposed) and str(var) in ("msg.sender", "msg.data", "msg.sig"):
            return True
        from slither.core.variables.local_variable import LocalVariable
        if isinstance(var, LocalVariable):
            if getattr(var, "is_parameter", False):
                return True
            location = str(getattr(var, "location", "")).lower()
            if "calldata" in location:
                return True
        return False
    except Exception:
        return False


def _follow_reference(var, max_depth: int = 5):
    """Follow ReferenceVariable.points_to chains to the underlying variable."""
    try:
        from slither.core.variables.reference_variable import ReferenceVariable
    except Exception:
        return var
    seen = set()
    for _ in range(max_depth):
        if id(var) in seen:
            break
        seen.add(id(var))
        if not isinstance(var, ReferenceVariable):
            break
        try:
            var = var.points_to
        except Exception:
            break
    return var


def _trace_temp_to_source(temp, f, max_depth: int = 5):
    """
    Backward-slice a TemporaryVariable to its source variable by scanning
    the function's IR for the operation that defines it. Returns the
    underlying source variable, or None if unresolvable.
    """
    try:
        from slither.core.variables.temporary_variable import TemporaryVariable
    except Exception:
        return None
    seen = set()
    current = temp
    for _ in range(max_depth):
        if id(current) in seen:
            break
        seen.add(id(current))
        if not isinstance(current, TemporaryVariable):
            return current
        nxt = None
        try:
            for node in f.nodes:
                for ir in node.irs:
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is None:
                        lvalue = getattr(ir, "destination", None)
                    if lvalue is current:
                        reads = getattr(ir, "read", [])
                        if reads:
                            nxt = reads[-1]
                            break
                if nxt is not None:
                    break
        except Exception:
            break
        if nxt is None:
            break
        current = nxt
    return current


def _func_canonical_id(func) -> Optional[str]:
    """Build a canonical_id matching graph.canonical_id for a Slither Function."""
    try:
        return f"{func.contract_declarer.name}.{func.full_name}"
    except Exception:
        return None


def _state_var_writers(state_var, contract) -> list:
    """
    Return Slither Function objects that write to state_var.
    Uses state_var.written first; falls back to scanning the contract's
    state_variables_written on each function.
    """
    writers = []
    try:
        for entry in state_var.written:
            if isinstance(entry, tuple) and len(entry) >= 2:
                writers.append(entry[1])
            else:
                writers.append(entry)
    except Exception:
        pass
    if not writers and contract is not None:
        try:
            fns = list(contract.functions) + list(getattr(contract, "modifiers", []) or [])
            for f in fns:
                if state_var in f.state_variables_written:
                    writers.append(f)
        except Exception:
            pass
    seen = set()
    unique = []
    for w in writers:
        if id(w) not in seen:
            seen.add(id(w))
            unique.append(w)
    return unique


def _writers_are_trusted(state_var, contract, auth_lookup: Optional[dict]) -> bool:
    """
    True if every function that writes to state_var is either the
    constructor (inherently trusted — runs once at deploy) or an
    auth-scored function (auth_score >= AUTH_TRUST_THRESHOLD).
    No writers (immutable/constant) counts as trusted.
    """
    writers = _state_var_writers(state_var, contract)
    if not writers:
        return True
    for w in writers:
        try:
            if w.is_constructor:
                continue
        except Exception:
            pass
        wcid = _func_canonical_id(w)
        if wcid is None:
            return False
        auth_score = auth_lookup.get(wcid, 0) if auth_lookup else 0
        if auth_score < AUTH_TRUST_THRESHOLD:
            return False
    return True


def _writers_are_governance_gated(state_var, contract, auth_lookup: Optional[dict]) -> bool:
    """
    Stricter than _writers_are_trusted: True only if state_var has at
    least one REAL, non-constructor writer, and every such writer is
    auth-scored (auth_score >= AUTH_TRUST_THRESHOLD).

    _writers_are_trusted intentionally treats "no writers" (immutable/
    constant) and "constructor-only" as trusted — appropriate for its
    purpose (core/sinks.py: is this destination redirectable BY THE
    CALLER at call time?). But that same broad definition also marks an
    immutable `underlying` ERC20 token — set once at market deployment,
    never re-governed — as "trusted", which is wrong for a narrower
    question core/cross_market.py needs answered: is this destination a
    protocol-governed hub/registry contract (e.g. Compound's own
    Comptroller, changeable only via the admin-gated _setComptroller),
    as opposed to an arbitrary external asset contract that merely
    happens to be fixed post-deployment (the classic ERC777/malicious-
    token reentrancy vector — fixed at deploy time, still hands control
    to an attacker). A real, ongoing, auth-gated SETTER is the evidence
    that distinguishes the two; mere immutability is not.
    """
    writers = _state_var_writers(state_var, contract)
    non_constructor = []
    for w in writers:
        try:
            if w.is_constructor:
                continue
        except Exception:
            pass
        non_constructor.append(w)
    if not non_constructor:
        return False
    for w in non_constructor:
        wcid = _func_canonical_id(w)
        if wcid is None:
            return False
        auth_score = auth_lookup.get(wcid, 0) if auth_lookup else 0
        if auth_score < AUTH_TRUST_THRESHOLD:
            return False
    return True


# ── Layer 2.5b: Registry-validated struct parameters ──────────────
#
# A calldata struct parameter may source an external-call destination
# via one of its address fields (e.g. marketParams.irm). Although the
# struct itself is caller-supplied, the protocol may have already
# validated that the struct maps to an on-chain registered entity by
# reading a storage mapping keyed by an id/hash derived from that same
# struct inside a require() or if/revert.
#
# Pattern (purely structural, no name lists):
#   calldata struct ─► hash/id derivation ─► storage mapping read
#                                              in a require/if-revert
# If found before the external call, the destination is trusted: the
# protocol already proved the struct corresponds to registered data.


def _same_var(a, b) -> bool:
    """Identity or string-equality match for two Slither variable objects."""
    if a is b or id(a) == id(b):
        return True
    try:
        sa, sb = str(a), str(b)
        return bool(sa) and sa == sb
    except Exception:
        return False


def _is_struct_param(var) -> bool:
    """True if var is a calldata function parameter of struct type."""
    try:
        from slither.core.variables.local_variable import LocalVariable
        if not isinstance(var, LocalVariable):
            return False
        if not getattr(var, "is_parameter", False):
            return False
        t = getattr(var, "type", None)
        if t is None:
            return False
        from slither.core.solidity_types import ElementaryType
        if isinstance(t, ElementaryType):
            return False
        # Non-elementary parameter type => user-defined (struct or enum).
        # Enums are not used as call-destination bases, so this is a struct.
        return True
    except Exception:
        return False


def _is_storage_mapping(var) -> bool:
    """True if var is a StateVariable whose type is (or includes) a mapping."""
    if not _is_state_variable(var):
        return False
    try:
        from slither.core.solidity_types import MappingType
        t = getattr(var, "type", None)
        if t is not None and isinstance(t, MappingType):
            return True
        for t in (getattr(var, "types", None) or []):
            if isinstance(t, MappingType):
                return True
    except Exception:
        pass
    return False


def _is_const_value(var) -> bool:
    """True if var is a literal constant (not a real variable)."""
    try:
        from slither.core.variables.constant_variable import ConstantVariable
        if isinstance(var, ConstantVariable):
            return True
    except Exception:
        pass
    return type(var).__name__ == "Constant"


def _find_defining_op(var, f):
    """Return the IR operation that assigns to var in function f, or None."""
    try:
        for node in f.nodes:
            for ir in node.irs:
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is None:
                    lvalue = getattr(ir, "destination", None)
                if _same_var(lvalue, var):
                    return ir
    except Exception:
        pass
    return None


def _op_reads_var(ir, target) -> bool:
    """True if ir reads target (directly or through a reference chain)."""
    candidates = list(getattr(ir, "read", []) or [])
    dest = getattr(ir, "destination", None)
    if dest is not None:
        candidates.append(dest)
    for c in candidates:
        if _same_var(_follow_reference(c), target):
            return True
    return False


def _key_derives_from_struct(key, f, struct_param, max_depth: int = 6) -> bool:
    """
    Backward-slice a storage mapping key to determine whether it derives
    from struct_param. Handles id derivation via method calls on the
    struct (marketParams.id()) and hash derivations
    (keccak256(abi.encode(marketParams))).
    """
    seen = set()
    current = key
    for _ in range(max_depth):
        if id(current) in seen:
            break
        seen.add(id(current))
        current = _follow_reference(current)
        if _same_var(current, struct_param):
            return True
        if _is_state_variable(current) or _is_const_value(current):
            break
        defining_op = _find_defining_op(current, f)
        if defining_op is None:
            break
        if _op_reads_var(defining_op, struct_param):
            return True
        reads = list(getattr(defining_op, "read", []) or [])
        dest = getattr(defining_op, "destination", None)
        if dest is not None:
            reads.append(dest)
        next_vars = [r for r in reads if not _is_const_value(r)]
        if not next_vars:
            break
        current = next_vars[0]
    return False


def _node_can_revert(node) -> bool:
    """True if the node is a validation point that can revert on failure."""
    try:
        from slither.core.cfg.node import NodeType
        # require() / assert() SolidityCall — SolidityCall exposes its
        # callee as ir.function (a SolidityFunction with .name), NOT
        # ir.function_name (that attribute belongs to HighLevelCall /
        # LowLevelCall / InternalCall / LibraryCall, not SolidityCall —
        # getattr(..., "") silently swallowed the AttributeError here,
        # making this branch a no-op for every require()/assert() call
        # until fixed).
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                callee = getattr(ir, "function", None)
                fname = str(getattr(callee, "name", "") or "").lower()
                if fname.startswith("require") or fname.startswith("assert"):
                    return True
        # if (cond) revert  —  IF node with a reverting successor
        if getattr(node, "type", None) == getattr(NodeType, "IF", None):
            for son in getattr(node, "sons", []) or []:
                if getattr(son, "type", None) == getattr(NodeType, "THROW", None):
                    return True
                for sir in getattr(son, "irs", []) or []:
                    if isinstance(sir, SolidityCall):
                        callee = getattr(sir, "function", None)
                        sname = str(getattr(callee, "name", "") or "").lower()
                        if sname.startswith("revert"):
                            return True
        return False
    except Exception:
        return False


def _registry_validates_struct(f, struct_param, call_node=None) -> bool:
    """
    True if function f contains a registry validation of struct_param
    at or before call_node. A registry validation is a require() or
    if/revert node that reads a storage mapping keyed by a value derived
    from struct_param.
    """
    try:
        from slither.slithir.operations import Index
    except Exception:
        Index = None

    try:
        nodes = list(f.nodes)
        call_idx = None
        if call_node is not None:
            try:
                call_idx = nodes.index(call_node)
            except ValueError:
                call_idx = None

        for idx, node in enumerate(nodes):
            if call_idx is not None and idx > call_idx:
                break
            if not _node_can_revert(node):
                continue
            for ir in node.irs:
                if Index is not None:
                    is_index = isinstance(ir, Index)
                else:
                    is_index = type(ir).__name__ == "Index"
                if not is_index:
                    continue
                reads = list(getattr(ir, "read", []) or [])
                mapping_base = None
                key = None
                for r in reads:
                    rf = _follow_reference(r)
                    if _is_storage_mapping(rf):
                        mapping_base = r
                    else:
                        key = r
                if mapping_base is None or key is None:
                    continue
                if _key_derives_from_struct(key, f, struct_param):
                    return True
        return False
    except Exception:
        return False


def _resolve_trust(ir, raw_type: str, f, auth_lookup: Optional[dict], node=None) -> tuple:
    """
    Decide trust for a call edge destination. Only highlevel calls are
    considered (lowlevel / delegatecall destinations are always untrusted).

    Returns (trusted, governance_gated):
      trusted            -> destination is a storage variable written only
                             by auth-scored functions or the constructor
                             (including immutable/no-writer destinations);
                             OR a field of a calldata struct parameter
                             validated by a registry check (storage
                             mapping read keyed by an id/hash derived from
                             the same struct) earlier in the function.
                             Untrusted -> destination derives from
                             calldata / msg.sender / a caller-controlled
                             variable, or is otherwise unresolvable.
      governance_gated    -> stricter: True only when there is a REAL,
                             ongoing, non-constructor auth-gated setter
                             for the destination (see
                             _writers_are_governance_gated) — evidence of
                             an actively protocol-governed contract (e.g.
                             Comptroller via _setComptroller), as opposed
                             to a merely immutable/constructor-fixed one
                             (e.g. a market's underlying ERC20 token,
                             which is "trusted" in the caller-redirect
                             sense but is still the classic reentrancy
                             vector real hacks exploit).
    Default -> (False, False), conservative.
    """
    if raw_type != "highlevel":
        return False, False
    if not auth_lookup:
        return False, False

    try:
        dest = ir.destination
    except Exception:
        return False, False

    contract = getattr(f, "contract_declarer", None)

    # Resolve reference chains to the underlying variable
    dest = _follow_reference(dest)

    # Direct storage variable destination
    if _is_state_variable(dest):
        return (
            _writers_are_trusted(dest, contract, auth_lookup),
            _writers_are_governance_gated(dest, contract, auth_lookup),
        )

    # Caller-controlled destination (calldata / msg.sender / parameter)
    if _is_caller_controlled(dest):
        # Struct field of a calldata parameter: may be registry-validated.
        if _is_struct_param(dest) and _registry_validates_struct(f, dest, node):
            return True, False
        return False, False

    # Temporary variable — backward-slice to its source via the function IR
    try:
        from slither.core.variables.temporary_variable import TemporaryVariable
        if isinstance(dest, TemporaryVariable):
            source = _trace_temp_to_source(dest, f)
            if source is not None:
                source = _follow_reference(source)
                if _is_state_variable(source):
                    return (
                        _writers_are_trusted(source, contract, auth_lookup),
                        _writers_are_governance_gated(source, contract, auth_lookup),
                    )
                if _is_caller_controlled(source):
                    # Struct field of a calldata parameter: may be registry-validated.
                    if _is_struct_param(source) and _registry_validates_struct(f, source, node):
                        return True, False
                    return False, False
    except Exception:
        pass

    # Unresolvable source — conservative: untrusted
    return False, False


# ── Destination resolution ────────────────────────────────────────

def _resolve_dst(ir, src_id: str, raw_type: str, f=None, auth_lookup: Optional[dict] = None, node=None, slither=None, unresolved_deps=None) -> tuple:
    """
    Attempt to resolve destination canonical ID and name.
    Returns (dst_id, function_name, destination_str, trusted, governance_gated).
    Unresolvable targets return a labeled unknown with trusted=False,
    governance_gated=False. Only highlevel calls may resolve either True.
    """
    if raw_type == "internal":
        try:
            fn = ir.function
            cid = f"{fn.contract_declarer.name}.{fn.full_name}"
            return cid, fn.name, None, False, False
        except Exception:
            return f"{src_id}.__unresolved_internal__", None, None, False, False

    if raw_type == "library":
        try:
            fn = ir.function
            cid = f"{fn.contract_declarer.name}.{fn.full_name}"
            return cid, fn.name, None, False, False
        except Exception:
            return f"{src_id}.__unresolved_library__", None, None, False, False

    if raw_type == "dynamic":
        # Function pointer — target is unknown at static analysis time
        return f"{src_id}.__dynamic_target__", None, None, False, False

    if raw_type == "highlevel":
        try:
            dest = str(ir.destination)
            fname = getattr(ir, "function_name", "") or ""
            fname = str(fname) if fname else ""
            trusted, governance_gated = _resolve_trust(ir, raw_type, f, auth_lookup, node)

            # Attempt real cross-contract resolution. Only when a concrete
            # destination is PROVEN (RESOLVED) do we return a canonical ID
            # that could actually match a node in the graph — everything
            # else keeps the prior synthetic-label behavior unchanged, so
            # existing single-contract findings are not affected.
            if slither is not None and f is not None:
                try:
                    from core.call_resolution import resolve_call
                    from core.resolution import ResolutionStatus
                    resolution = resolve_call(ir, f, slither)
                    if (
                        resolution.resolution.status == ResolutionStatus.RESOLVED
                        and resolution.resolved_contract
                        and resolution.resolved_function
                    ):
                        real_cid = f"{resolution.resolved_contract}.{resolution.resolved_function}"
                        return real_cid, fname, dest, trusted, governance_gated
                    elif (
                        resolution.resolved_variable_name
                        and unresolved_deps is not None
                    ):
                        # Status may be RESOLVED-but-empty (ambiguous/zero implementers,
                        # e.g. missing sibling contract) or otherwise non-RESOLVED, but we
                        # have a real fixed variable name (STATE_VARIABLE/IMMUTABLE origin
                        # only — never PARAMETER/MSG_SENDER). Record it so the caller can
                        # attempt to fetch the missing dependency and retry.
                        declaring_contract = (
                            f.contract_declarer.name
                            if f is not None and f.contract_declarer is not None
                            else None
                        )
                        unresolved_deps.append({
                            "variable_name": resolution.resolved_variable_name,
                            "declaring_contract": declaring_contract,
                        })

                        # Carry the real typed signature (name + arg types),
                        # taken directly from Slither's IR on the interface's
                        # own declared function — real data, not a guess —
                        # into the synthetic label. This is what lets a later
                        # cross-compilation merge (core/multi_compile.py)
                        # match by exact signature instead of bare name.
                        if resolution.interface_signature:
                            fname = resolution.interface_signature
                except Exception:
                    pass  # fall through to prior synthetic-label behavior

            return f"external.{dest}.{fname}", fname, dest, trusted, governance_gated
        except Exception:
            return f"{src_id}.__unresolved_external__", None, None, False, False

    if raw_type in ("lowlevel_call", "delegatecall", "codecall"):
        try:
            dest = str(ir.destination)
            fname = getattr(ir, "function_name", "") or "call"
            return f"lowlevel.{dest}.{fname}", fname, dest, False, False
        except Exception:
            return f"{src_id}.__unresolved_lowlevel__", None, None, False, False

    if raw_type in ("eth_send", "eth_transfer"):
        try:
            dest = str(ir.destination)
            return f"eth.{dest}", None, dest, False, False
        except Exception:
            return f"{src_id}.__unresolved_eth__", None, None, False, False

    if raw_type == "new_contract":
        try:
            contract_name = ir.contract_name if hasattr(ir, "contract_name") else "unknown"
            return f"new.{contract_name}", contract_name, None, False, False
        except Exception:
            return f"{src_id}.__unresolved_new__", None, None, False, False

    return f"{src_id}.__unresolved__", None, None, False, False


# ── Token-transfer detection (real resolved types, never a name guess) ──

# Canonical ERC20/721/1155 transfer-shaped signatures, matched against
# Slither's REAL resolved argument types — the callee's own
# solidity_signature when statically resolvable, or reconstructed from
# the call IR's own argument types otherwise. A custom, differently-typed
# transfer(address,uint256,bytes) does not match; a same-named function
# on an unrelated interface with these exact argument types does — this
# is intentional, since the signature IS the ABI-level contract, real
# data derived from resolved types, not a guess about the developer's
# naming convention.
TOKEN_TRANSFER_SIGNATURES = {
    "transfer(address,uint256)",                                       # ERC20
    "transferFrom(address,address,uint256)",                           # ERC20
    "safeTransfer(address,uint256)",                                   # common ERC20 wrapper
    "safeTransferFrom(address,address,uint256)",                       # ERC721 / SafeERC20-style
    "safeTransferFrom(address,address,uint256,bytes)",                 # ERC721 with data
    "safeTransferFrom(address,address,uint256,uint256,bytes)",         # ERC1155 single
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",  # ERC1155 batch
}


def _is_token_transfer_call(ir) -> bool:
    """
    True if this HighLevelCall's real signature — the resolved callee's
    own solidity_signature when statically known, or one reconstructed
    from the call IR's own resolved argument types otherwise — matches a
    canonical token-transfer-shaped signature.
    """
    try:
        if not isinstance(ir, HighLevelCall):
            return False
        fn = getattr(ir, "function", None)
        if fn is not None and hasattr(fn, "solidity_signature"):
            if fn.solidity_signature in TOKEN_TRANSFER_SIGNATURES:
                return True
        fname = str(getattr(ir, "function_name", "") or "")
        if not fname:
            return False
        from slither.utils.type import convert_type_for_solidity_signature_to_string
        arg_types = []
        for a in (getattr(ir, "arguments", None) or []):
            t = getattr(a, "type", None)
            if t is None:
                return False
            arg_types.append(convert_type_for_solidity_signature_to_string(t))
        return f"{fname}({','.join(arg_types)})" in TOKEN_TRANSFER_SIGNATURES
    except Exception:
        return False


# ── Public API ────────────────────────────────────────────────────

def extract_edges(src_id: str, f, auth_lookup: Optional[dict] = None, slither=None, unresolved_deps=None) -> list[CallEdge]:
    """
    Extract all typed call edges from a Slither function object.

    Args:
        src_id: canonical ID of the calling function
        f: Slither Function object
        auth_lookup: optional dict mapping canonical_id -> auth_score (int).
                     Used to compute the `trusted` flag on highlevel call
                     edges. When omitted, all highlevel edges default to
                     trusted=False (conservative).

    Returns:
        List of CallEdge objects
    """
    edges = []

    for node in f.nodes:
        for ir in node.irs:
            try:
                raw_type = _raw_type_from_ir(ir)
                if raw_type == "unknown":
                    continue

                dst_id, fname, dest_str, trusted, governance_gated = _resolve_dst(
                    ir, src_id, raw_type, f, auth_lookup, node, slither, unresolved_deps
                )
                props = _semantic_properties(raw_type)

                edges.append(CallEdge(
                    src=src_id,
                    dst=dst_id,
                    raw_type=raw_type,
                    function_name=str(fname) if fname is not None else None,
                    destination=str(dest_str) if dest_str is not None else None,
                    trusted=trusted,
                    governance_gated=governance_gated,
                    is_token_transfer=_is_token_transfer_call(ir) if raw_type == "highlevel" else False,
                    **props,
                ))

            except Exception:
                continue

    return edges
