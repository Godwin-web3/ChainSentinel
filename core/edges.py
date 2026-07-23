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
  staticcall        LowLevelCall where function_name == "staticcall" —
                     EVM-enforced read-only: can never transfer value or
                     write state, unlike a plain .call(...)
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
from slither.slithir.operations.unpack import Unpack


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

    # True if a low-level call's own `bool success` return (always
    # index 0 of its (bool, bytes) tuple, for .call/.delegatecall/
    # .codecall/.staticcall alike) is unpacked and then read by a
    # revert-capable node SOMEWHERE in the same function — the real
    # require(success, ...) pattern virtually every professionally-
    # written low-level call uses. Only meaningful for raw_type in
    # (lowlevel_call, delegatecall, codecall, staticcall); False
    # (its default) for every other raw_type, where it carries no
    # meaning at all.
    return_checked: bool = False


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
        # ir.function_name is a Slither Constant object, not a plain
        # str — calling .lower() on it directly raises AttributeError.
        # That exception was previously swallowed by extract_edges'
        # broad try/except, silently dropping the edge entirely for
        # EVERY raw low-level call in the codebase (.call(...),
        # .call{value}(...), delegatecall, codecall) — found live
        # probing a synthetic checks-effects-interactions violation
        # that should have fired REENTRANCY_CEI but produced zero
        # edges, let alone paths, because the call itself was invisible
        # to the whole graph.
        raw_fname = getattr(ir, "function_name", None)
        fname = str(raw_fname).lower() if raw_fname is not None else ""
        if fname == "delegatecall":
            return "delegatecall"
        if fname == "codecall":
            return "codecall"
        if fname == "staticcall":
            return "staticcall"
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

def _is_view_or_pure_callee(fn) -> bool:
    """
    True if fn is provably side-effect-free: either a real Function/
    Modifier declared view/pure, or a StateVariable — i.e. a call that
    resolves to a `public` state variable's compiler-synthesized getter
    (`uint256 public foo;` -> callable as `foo()`), for ANY visibility-
    exposed variable, constant/immutable or plain mutable storage alike.

    Slither resolves such a call's ir.function to a StateVariable
    object, NOT a Function — so it carries no .view/.pure attribute at
    all (both getattr(fn, "view", False) and getattr(fn, "pure", False)
    silently return the False default). Confirmed live against the real
    Compound V2 fork Takara Lend on Sei: `newComptroller.
    isComptroller()`, a call to `bool public constant isComptroller =
    true;` declared on an abstract base contract, resolves ir.function
    to a StateVariable — every mutability check in this module was
    treating it as an ordinary, unknown-mutability external call,
    causing a false REENTRANCY_CEI/FLASHLOAN_WINDOW on
    TToken._setComptroller().

    Not limited to constant/immutable: a public variable's
    auto-generated getter can ONLY ever be a compiler-synthesized
    SLOAD-and-return accessor — Solidity gives no way to attach custom
    logic to it (any custom logic requires writing a real explicit
    function instead, which resolves to a genuine Function object with
    real .view/.pure attributes, not a StateVariable). That holds
    regardless of whether the underlying value can change over time, so
    ANY StateVariable-resolved call is unconditionally safe from state-
    crossing/reentrancy — it can never itself write state or call back
    into anything.
    """
    if fn is None:
        return False
    if getattr(fn, "view", False) or getattr(fn, "pure", False):
        return True
    from slither.core.variables.state_variable import StateVariable
    return isinstance(fn, StateVariable)


def _semantic_properties(raw_type: str, ir=None) -> dict:
    """
    Derive semantic flags from raw type.
    These are attacker-relevant properties, not IR labels.

    A "highlevel" call whose resolved callee is declared view/pure
    compiles to STATICCALL under the hood — the EVM itself then
    prevents any state mutation during the call, exactly the same
    guarantee already carved out for an explicit `.staticcall(...)`
    (raw_type "staticcall") below. Slither's raw_type only reflects
    the literal call SYNTAX used (`Foo(addr).bar()` is "highlevel"
    regardless of `bar()`'s own mutability), so this is real semantic
    inference belonging here in Layer 2, not a raw-type distinction.
    Found live this session: real Velodrome's setName() makes exactly
    one external call, `IVoter(_voter).emergencyCouncil()` (a view
    function) — REENTRANCY_CEI/FLASHLOAN_WINDOW both flagged it as a
    genuine callback-capable interaction purely because "highlevel"
    unconditionally set is_state_crossing=True, with no reference to
    the callee's own declared mutability at all.
    """
    props = {
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
        "staticcall": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=False,       # EVM guarantees: cannot send value
            is_state_crossing=False,       # EVM guarantees: cannot write state
            uncertain=True,                # destination may be attacker-controlled
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

    if raw_type == "highlevel" and ir is not None:
        fn = getattr(ir, "function", None)
        if _is_view_or_pure_callee(fn):
            props["is_state_crossing"] = False

    return props


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
        # The real module is slither.slithir.variables.temporary —
        # slither.core.variables.temporary_variable (the previous
        # import here) doesn't exist at all, raising ModuleNotFoundError
        # on every call, silently caught by this except and returning
        # None unconditionally. That made this entire function a no-op
        # for its whole life: every TypeConversion-wrapped call
        # destination (IFoo(stateVar).bar() — the standard interface-
        # cast pattern used by virtually every external call in
        # Solidity) fell through _resolve_trust straight to "untrusted",
        # since the TemporaryVariable branch below could never resolve
        # a source to check. Found live re-verifying Convex Booster's
        # admin-only functions (setFeeInfo/shutdownPool/shutdownSystem):
        # their external calls target `registry`/`staker` — a constant
        # and a constructor-set immutable, both genuinely trusted —  but
        # scored trusted=False regardless.
        from slither.slithir.variables.temporary import TemporaryVariable
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
    constructor (inherently trusted — runs once at deploy), Slither's
    own synthetic constant/immutable-initializer function (real,
    constant `= value` / immutable-set-in-declaration state variables —
    is_constructor_variables — deploy-time only, exactly as trusted as
    the real constructor, not a name guess but a genuine FunctionType
    Slither itself assigns), or an auth-scored function (auth_score >=
    AUTH_TRUST_THRESHOLD). No writers counts as trusted.
    """
    writers = _state_var_writers(state_var, contract)
    if not writers:
        return True
    for w in writers:
        try:
            if w.is_constructor or w.is_constructor_variables:
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
            if w.is_constructor or w.is_constructor_variables:
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


def _function_can_revert(fn, max_depth: int = 4, _visited: Optional[set] = None) -> bool:
    """
    True if fn's own body contains a real revert path: a require()/
    assert()/revert(...) SolidityCall — including one Slither's assembly
    IR decoder synthesizes for a raw `assembly { revert(...) }` block
    (confirmed live against real Balancer/Berachain BEX's
    `_revert(uint256)` helper: its entire body is inline assembly ending
    in the EVM REVERT opcode, which Slither still lowers to a normal
    `SolidityCall ... revert(uint256,uint256)(...)` IR op on the
    EXPRESSION node between the ASSEMBLY/ENDASSEMBLY markers) — or a call
    to ANOTHER internal function that itself can revert, bounded
    recursion (the real Balancer pattern: `_require(cond, code) { if
    (!cond) _revert(code); }` calling `_revert`, whose body is exactly
    the assembly case above). Same "raw EVM opcode is unambiguous
    ground truth" basis already used for `create2` detection in
    core/invariants.py's `_fresh_deployment_destinations`.
    """
    if _visited is None:
        _visited = set()
    fid = id(fn)
    if fid in _visited or max_depth < 0:
        return False
    _visited.add(fid)
    try:
        nodes = list(getattr(fn, "nodes", []) or [])
    except Exception:
        return False
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                callee = getattr(ir, "function", None)
                name = str(getattr(callee, "name", "") or "").lower()
                if name.startswith("require") or name.startswith("assert") or name.startswith("revert"):
                    return True
            elif isinstance(ir, InternalCall) and max_depth > 0:
                callee = getattr(ir, "function", None)
                if callee is not None and _function_can_revert(callee, max_depth - 1, _visited):
                    return True
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
            # A call to a user-defined revert-wrapper function, e.g. real
            # Balancer/Berachain BEX's free-function `_require(bool
            # condition, uint256 errorCode) { if (!condition)
            # _revert(errorCode); }` — structurally identical to a
            # built-in require(), just one indirection through a custom
            # helper (common wherever a codebase centralizes revert
            # reasons/error codes instead of inlining every require()).
            if isinstance(ir, InternalCall):
                callee = getattr(ir, "function", None)
                if callee is not None and _function_can_revert(callee):
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


def _low_level_return_checked(ir, f) -> bool:
    """
    True if a low-level call's own `bool success` return — always index
    0 of its (bool, bytes) tuple lvalue, for .call/.delegatecall/
    .codecall/.staticcall alike — is unpacked and then read by a
    revert-capable node somewhere in the same function, OR passed as an
    argument to an internal call whose corresponding parameter is
    itself checked the same way (bounded, cycle-safe recursion).

    Real evidence, not a heuristic: virtually every professionally-
    written low-level call checks its own return this way —
    TransferHelper.safeTransfer's `require(success && ...)`, Liquity's
    `require(success, "...")` in _sendETHGainToDepositor, and (the
    reason the indirect/parameter-binding case exists at all) OZ's
    Address.functionCallWithValue, used by Convex's
    _callOptionalReturn:
        (bool success, bytes memory returndata) = target.call{...}(data);
        return _verifyCallResult(success, returndata, errorMessage);
    where _verifyCallResult does `if (success) {...} else { revert(...); }`
    one call-frame deeper — `success` is never itself read by a
    revert-capable node in functionCallWithValue's OWN body, only
    passed on. core/constraints.py::_check_unchecked_return previously
    never inspected any of this — it fired whenever ANY low-level call
    existed on a path, regardless of whether the return was actually
    validated, a false positive on essentially any competently-written
    contract. Found live re-verifying Convex Booster, Liquity
    StabilityPool, and Uniswap V3 after the low-level-call
    edge-extraction fix made these calls visible for the first time
    this session.
    """
    lvalue = getattr(ir, "lvalue", None)
    if lvalue is None:
        return False  # return value discarded entirely — genuinely unchecked

    try:
        all_nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False

    success_var = None
    for node in all_nodes:
        for other_ir in getattr(node, "irs", []) or []:
            if (
                isinstance(other_ir, Unpack)
                and getattr(other_ir, "tuple", None) is lvalue
                and getattr(other_ir, "index", None) == 0
            ):
                success_var = other_ir.lvalue
                break
        if success_var is not None:
            break

    # Some shapes check the call's own (undestructured) lvalue directly
    # rather than an Unpack'd component — fall back to it too.
    candidates = [v for v in (success_var, lvalue) if v is not None]

    return _value_checked_or_propagated(candidates, all_nodes, max_depth=3)


def _value_checked_or_propagated(candidates: list, nodes: list, max_depth: int, _visited: Optional[set] = None) -> bool:
    """
    True if any variable in `candidates` is read by a revert-capable
    node among `nodes`, OR is passed as an argument to an InternalCall
    whose corresponding parameter is itself checked the same way in the
    callee's own body (recursively, bounded by max_depth, cycle-safe
    via _visited on callee identity).
    """
    for node in nodes:
        read_vars = list(getattr(node, "variables_read", []) or [])
        if not any(rv is c for rv in read_vars for c in candidates):
            continue
        if _branch_reaches_revert(node):
            return True

    if max_depth <= 0:
        return False

    if _visited is None:
        _visited = set()

    for node in nodes:
        for ir in getattr(node, "irs", []) or []:
            if not (isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None):
                continue
            callee = ir.function
            cid = id(callee)
            if cid in _visited:
                continue
            args = list(getattr(ir, "arguments", None) or [])
            params = list(getattr(callee, "parameters", None) or [])
            matched_params = [p for p, a in zip(params, args) if any(a is c for c in candidates)]
            if not matched_params:
                continue
            _visited.add(cid)
            try:
                callee_nodes = list(getattr(callee, "nodes", []) or [])
            except Exception:
                continue
            if _value_checked_or_propagated(matched_params, callee_nodes, max_depth - 1, _visited):
                return True
    return False


def _branch_reaches_revert(node, max_depth: int = 4, _visited: Optional[set] = None) -> bool:
    """
    True if `node` itself is revert-capable (_node_can_revert), or any
    node reachable from it via CFG sons within max_depth hops is.
    _node_can_revert alone only looks one hop ahead (a THROW son, or a
    revert SolidityCall directly on a son) — real code often nests
    deeper, e.g. OZ's _verifyCallResult:
        if (success) { return returndata; }
        else {
            if (returndata.length > 0) { assembly { revert(...) } }
            else { revert(errorMessage); }
        }
    The node reading `success` (`CONDITION success`) has sons
    [RETURN, IF] — no direct THROW son — with the actual revert two
    more hops down the false branch. Scoped to this module's low-level-
    return-check use only; does not change _node_can_revert's own
    behavior or any of its other call sites.
    """
    if _visited is None:
        _visited = set()
    if id(node) in _visited or max_depth < 0:
        return False
    _visited.add(id(node))
    if _node_can_revert(node):
        return True
    for son in getattr(node, "sons", []) or []:
        if _branch_reaches_revert(son, max_depth - 1, _visited):
            return True
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
    Decide trust for a call edge destination. Highlevel calls and
    delegatecall/codecall are considered (raw .call()/.staticcall()
    destinations are always untrusted — a low-level call's destination
    carries no ABI-level identity to even ask "which state variable is
    this," and .call() specifically is the highest-risk, most-arbitrary
    call shape, so it stays conservative regardless).

    delegatecall/codecall share the same destination-trust question as
    a highlevel call: is the address a real, actively-governed storage
    slot (e.g. a transparent proxy's `comptrollerImplementation`, set
    only via a real 2-step admin handoff), or genuinely attacker/
    caller-controlled? Found live this session against the real
    Compound V2 fork Takara Lend on Sei: `Unitroller.fallback()`
    delegatecalls `comptrollerImplementation.delegatecall(msg.data)`
    with no auth check of its own — correct, since the actual privilege
    enforcement happens inside each of the implementation's own
    functions (`require(msg.sender == admin)`, reading the SAME shared
    storage slot the delegatecall preserves) — but this function
    previously hardcoded trusted=False for EVERY delegatecall
    regardless of destination, so core/sinks.py's fallback/receive
    proxy-dispatcher carve-out (which depends on this signal) could
    never actually fire.

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
    if raw_type not in ("highlevel", "delegatecall", "codecall"):
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
        from slither.slithir.variables.temporary import TemporaryVariable
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
    governance_gated=False. Only highlevel and delegatecall/codecall
    edges may resolve either True (see _resolve_trust).
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

    if raw_type in ("delegatecall", "codecall"):
        try:
            dest = str(ir.destination)
            fname = getattr(ir, "function_name", "") or "call"
            trusted, governance_gated = _resolve_trust(ir, raw_type, f, auth_lookup, node)
            return f"lowlevel.{dest}.{fname}", fname, dest, trusted, governance_gated
        except Exception:
            return f"{src_id}.__unresolved_lowlevel__", None, None, False, False

    if raw_type in ("lowlevel_call", "staticcall"):
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
                props = _semantic_properties(raw_type, ir)

                edges.append(CallEdge(
                    src=src_id,
                    dst=dst_id,
                    raw_type=raw_type,
                    function_name=str(fname) if fname is not None else None,
                    destination=str(dest_str) if dest_str is not None else None,
                    trusted=trusted,
                    governance_gated=governance_gated,
                    is_token_transfer=_is_token_transfer_call(ir) if raw_type == "highlevel" else False,
                    return_checked=(
                        _low_level_return_checked(ir, f)
                        if raw_type in ("lowlevel_call", "delegatecall", "codecall", "staticcall")
                        else False
                    ),
                    **props,
                ))

            except Exception:
                continue

    return edges
