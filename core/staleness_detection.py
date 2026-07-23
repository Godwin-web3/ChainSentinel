"""
core/staleness_detection.py — Structural Chainlink price-feed
staleness-check detection (Slither IR, source-level).

Not to be confused with core/oracle_detection.py (bytecode-level oracle
TYPE classification for market-discovery) or core/spot_price_detection.py
(AMM getReserves()/slot0() spot-price manipulation). This module
answers a narrower question: when a function calls Chainlink's
AggregatorV3Interface.latestRoundData(), does it actually verify the
returned price is FRESH before using it?

Real precedent (this is one of the single most common high-severity
findings in real Code4rena/Sherlock audits): the real 2024-07-loopfi
finding (code-423n4/2024-07-loopfi-findings#494, #521) against
AuraVault.sol's real `_chainlinkSpot()` — the `updatedAt` return value
is destructured with a blank comma (`uint256 /*updatedAt*/`), never
bound to any variable at all, so the feed's actual freshness is never
checked before `price = wdiv(uint256(answer), ...)`. The same finding
pattern recurs near-verbatim across dozens of real audits (2024-05-
predy#69, 2024-08-sentiment-v2#51, 2023-12-the-standard#438).

A subtler real case, confirmed live via IR probe against Cryptex
Finance's actual deployed ChainlinkOracle.sol
(cryptexfinance/contracts): `getLatestAnswer()` DOES check
`timeStamp != 0` (round-complete) and `answeredInRound >= roundID`
(stale-round), but NEVER checks elapsed real time
(`block.timestamp - timeStamp` against a bound) — the check real audits
actually require, since `answeredInRound` is explicitly documented by
Chainlink as an unreliable staleness indicator on newer aggregator
versions. This module only accepts a genuine elapsed-time comparison
as protective, not round-completeness checks alone.

The real, correct pattern — confirmed live via IR probe against
ButtonWood Protocol's actual deployed ChainlinkOracle.sol
(buttonwood-protocol/button-wrappers) — computes
`diff = block.timestamp - updatedAt` and compares it against a
staleness threshold. Notably, ButtonWood's real implementation doesn't
even `require()` inline — it PROPAGATES the check as a returned `bool
valid` for the caller to act on. Both a revert-capable check and a
propagated-via-Return check are treated as protective here, matching
how this codebase already treats "checked or propagated" for low-level
call return values (core/edges.py::_value_checked_or_propagated).

A cross-function case, found live this session via direct verification
against Liquity V2 (Bold)'s actual, currently-deployed
MainnetPriceFeedBase.sol: `_getCurrentChainlinkResponse()` calls
latestRoundData() and packs `updatedAt` straight into a
`ChainlinkResponse` struct's `.timestamp` field with NO check in that
same function at all — the freshness check
(`block.timestamp - chainlinkResponse.timestamp < threshold`) lives in
a SEPARATE sibling function, `_isValidChainlinkPrice()`, called by
their shared caller with the returned struct. This module's single-
function-scoped check originally missed this real, genuinely-safe
pattern; see _struct_field_written_from/_field_freshness_check_present
for the struct-field-name-keyed cross-function extension.
"""

from typing import Optional

from slither.slithir.operations import Assignment, Binary, HighLevelCall, InternalCall, Member, Return
from slither.slithir.operations.binary import BinaryType
from slither.slithir.operations.unpack import Unpack

from core.edges import (
    _follow_reference,
    _find_defining_op,
    _resolves_to_block_timestamp,
    _same_var,
    _branch_reaches_revert,
)
from core.auth_detection import _expand_with_internal_calls

_LATEST_ROUND_DATA_NAME = "latestrounddata"

# AggregatorV3Interface.latestRoundData() returns (roundId, answer,
# startedAt, updatedAt, answeredInRound) — this fixed positional order
# is Chainlink's own real, standard interface, confirmed live via IR
# probe (Unpack.index lines up with this exact order regardless of
# local variable naming, including when a slot is destructured with a
# blank comma and never bound to any variable at all).
_ANSWER_INDEX = 1
_UPDATED_AT_INDEX = 3

_CRITICAL_STATE_KEYWORDS = ("collateral", "debt", "borrow", "liquidat", "health", "price", "value")

# Binary op types that can genuinely LINK an updatedAt value to a
# block.timestamp-derived cutoff — both the real ButtonWood two-step
# shape (`diff = block.timestamp - updatedAt`, then `diff <=
# threshold`) and the common single-step shape (`require(updatedAt >
# block.timestamp - MAX_DELAY)`) go through one of these.
_LINKING_BINARY_TYPES = {
    BinaryType.SUBTRACTION,
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
    BinaryType.EQUAL,
    BinaryType.NOT_EQUAL,
}


def _unpack_index_value(tuple_var, index: int, f):
    """
    Return the LVALUE Slither binds a latestRoundData() tuple's given
    positional index to in f — or None if that slot was destructured
    with a blank comma and never bound to any variable at all (the real
    LoopFi AuraVault.sol shape: confirmed live via IR probe, Slither
    simply emits NO Unpack op for a discarded slot, not an Unpack with
    an unused placeholder lvalue).
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Unpack) and getattr(ir, "tuple", None) is tuple_var and getattr(ir, "index", None) == index:
                return ir.lvalue
    return None


def _derives_from_block_timestamp_within_one_hop(var, f) -> bool:
    """
    True if var IS block.timestamp, or is a Binary ADDITION/SUBTRACTION
    one hop away from it (the real `block.timestamp - MAX_DELAY`-style
    cutoff constant every single-step staleness check computes).
    """
    if _resolves_to_block_timestamp(var, f):
        return True
    resolved = _follow_reference(var)
    defining_op = _find_defining_op(resolved, f)
    if isinstance(defining_op, Binary) and defining_op.type in (BinaryType.ADDITION, BinaryType.SUBTRACTION):
        return _resolves_to_block_timestamp(defining_op.variable_left, f) or _resolves_to_block_timestamp(defining_op.variable_right, f)
    return False


def _find_freshness_linking_op(updated_at_var, f):
    """
    Find a Binary op in f that links updated_at_var directly to a
    block.timestamp-derived value — either operand order — covering
    both the real ButtonWood two-step shape (SUBTRACTION producing an
    elapsed-time diff, checked in a LATER op) and the common single-step
    comparison shape (updatedAt compared directly against a
    block.timestamp-derived cutoff). Returns the linking Binary op, or
    None if updated_at_var is never linked to block.timestamp at all.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None
    for node in nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in _LINKING_BINARY_TYPES:
                continue
            left, right = ir.variable_left, ir.variable_right
            if _same_var(_follow_reference(left), updated_at_var) and _derives_from_block_timestamp_within_one_hop(right, f):
                return ir
            if _same_var(_follow_reference(right), updated_at_var) and _derives_from_block_timestamp_within_one_hop(left, f):
                return ir
    return None


def _member_field_map(f) -> dict:
    """
    Map id(reference variable) -> field name, for every Member op in f
    — e.g. `REF_6 -> chainlinkResponse.timestamp` becomes
    {id(REF_6): "timestamp"}. A Member op's own `.variable_right` is
    the field-name Constant regardless of which struct instance is
    being accessed — confirmed live via IR probe against a faithful
    reproduction of the real Liquity V2 (Bold) shape.
    """
    out = {}
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return out
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Member):
                out[id(ir.lvalue)] = str(ir.variable_right)
    return out


def _struct_field_written_from(updated_at_var, f) -> Optional[str]:
    """
    True (the field name) if updated_at_var is written directly into a
    struct field within f, via `REF -> obj.field` (Member) followed by
    `REF := updated_at_var` (Assignment) — the real Liquity V2 (Bold)
    MainnetPriceFeedBase.sol shape:
    `chainlinkResponse.timestamp = updatedAt`, where the struct is then
    returned and the actual freshness check happens in a DIFFERENT,
    sibling function against that field, read back out through a
    brand-new (differently-identified) reference variable. Returns the
    field name (e.g. "timestamp"), or None if updated_at_var is never
    packed into a struct field at all in f.
    """
    field_map = _member_field_map(f)
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Assignment) and _same_var(_follow_reference(ir.rvalue), updated_at_var):
                fname = field_map.get(id(ir.lvalue))
                if fname is not None:
                    return fname
    return None


def _field_freshness_check_present(field_name, f) -> bool:
    """
    Same structural signature as _staleness_check_present, but matches
    the freshness-linking Binary's operand by STRUCT FIELD NAME (see
    _member_field_map) instead of variable identity — for the real
    cross-function shape where updatedAt is captured in one function,
    packed into a struct, and only checked in a DIFFERENT function
    against that struct's field, read back out via a brand-new Member
    op producing a DIFFERENT reference-variable identity than the one
    that originally wrote it.
    """
    field_map = _member_field_map(f)
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False
    linking_op = None
    for node in nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in _LINKING_BINARY_TYPES:
                continue
            left, right = ir.variable_left, ir.variable_right
            if field_map.get(id(left)) == field_name and _derives_from_block_timestamp_within_one_hop(right, f):
                linking_op = ir
                break
            if field_map.get(id(right)) == field_name and _derives_from_block_timestamp_within_one_hop(left, f):
                linking_op = ir
                break
        if linking_op is not None:
            break
    if linking_op is None:
        return False
    return _reaches_protective_use(linking_op.lvalue, f)


def _reachable_functions(f, max_depth: int = 3, _visited: Optional[set] = None) -> list:
    """
    All functions reachable from f via bounded InternalCall hops
    (including f itself) — the scope _staleness_check_present's cross-
    function struct-field extension searches for a sibling function
    that performs the actual freshness check, since a callee (like the
    real _getCurrentChainlinkResponse) cannot see its OWN caller's
    other callees (like the real _isValidChainlinkPrice) via forward
    expansion alone.
    """
    if _visited is None:
        _visited = set()
    fid = id(f)
    if fid in _visited or max_depth < 0:
        return []
    _visited.add(fid)
    out = [f]
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return out
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                out.extend(_reachable_functions(ir.function, max_depth - 1, _visited))
    return out


def _reaches_protective_use(seed, f, max_depth: int = 6) -> bool:
    """
    Forward-taint seed through f's own IR, in bounded fixed-point
    iteration over node order, to determine whether the freshness-
    linking op's own result is EITHER (a) read by a revert-capable node
    — the common `require(...)`/`if (stale) revert(...)` shape — OR
    (b) read by a Return op — the real ButtonWood shape, which never
    reverts inline but propagates a `bool valid` for the caller to act
    on (matching how this codebase already treats "checked or
    propagated" for low-level call returns —
    core/edges.py::_value_checked_or_propagated).
    """
    tainted = {id(seed)}
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False

    for _ in range(max_depth):
        progressed = False
        for node in nodes:
            node_is_revert_capable = None  # lazily computed, at most once per node per pass
            for ir in node.irs:
                reads = list(getattr(ir, "read", []) or [])
                if not any(id(_follow_reference(r)) in tainted for r in reads):
                    continue
                if isinstance(ir, Return):
                    return True
                # Check revert-capability against the NODE containing the
                # ir that reads a tainted IR-level temp — node.
                # variables_read only reflects the expression's original
                # SOURCE-level variables (e.g. `updatedAt`, `MAX_DELAY`),
                # never intermediate temporaries like the comparison's own
                # boolean result, so it can never match anything in
                # `tainted` here. Confirmed live via IR probe: this was a
                # real bug — the require()-based single-step staleness
                # check (`require(updatedAt >= block.timestamp -
                # MAX_DELAY)`) was going undetected as protective until
                # fixed to check ir-level reads instead.
                if node_is_revert_capable is None:
                    node_is_revert_capable = _branch_reaches_revert(node)
                if node_is_revert_capable:
                    return True
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and id(lvalue) not in tainted:
                    tainted.add(id(lvalue))
                    progressed = True
        if not progressed:
            break
    return False


def _staleness_check_present(updated_at_var, f, cross_function_scope: Optional[list] = None) -> bool:
    """
    True if updated_at_var is genuinely, structurally freshness-checked
    in f: linked to block.timestamp via a real Binary op (see
    _find_freshness_linking_op), whose result reaches either a
    revert-capable check or a Return (see _reaches_protective_use).
    Deliberately does NOT accept round-completeness-only checks
    (`timeStamp != 0`, `answeredInRound >= roundID`) as sufficient —
    confirmed live via IR probe against Cryptex Finance's actual
    deployed ChainlinkOracle.sol, which has exactly these checks and
    NOTHING else, matching a real, common, incomplete pattern real
    audits still flag as vulnerable to genuine staleness.

    Falls back to the cross-function struct-field case (see
    _struct_field_written_from/_field_freshness_check_present) if
    updated_at_var isn't checked directly in f but IS packed into a
    struct field there — the real Liquity V2 (Bold)
    MainnetPriceFeedBase.sol shape, where the actual check lives in a
    SIBLING function reached from f's own caller, not from f itself.
    cross_function_scope is the bounded reachable-function set computed
    once at find_unstaled_latest_round_data_dependency's own top level
    (see _reachable_functions) — a callee cannot see its own caller's
    OTHER callees via forward expansion alone.
    """
    if updated_at_var is None:
        return False
    linking_op = _find_freshness_linking_op(updated_at_var, f)
    if linking_op is not None and _reaches_protective_use(linking_op.lvalue, f):
        return True
    if cross_function_scope:
        field_name = _struct_field_written_from(updated_at_var, f)
        if field_name is not None:
            for g in cross_function_scope:
                if g is f:
                    continue
                if _field_freshness_check_present(field_name, g):
                    return True
    return False


def _writes_critical_state(nodes) -> bool:
    """
    True if any node in `nodes` writes a state variable whose name
    matches a real lending/valuation accounting surface — the same
    co-occurrence pattern core/spot_price_detection.py's own
    _writes_critical_state and core/vault_detection.py's
    _writes_share_supply_state already use: the unprotected price read
    and the consequential state mutation living in the same function-
    or-reachable-helper scope is this codebase's established bar for
    this class of structural co-occurrence claim.
    """
    for node in nodes:
        for var in getattr(node, "state_variables_written", []) or []:
            name = str(var).lower()
            if any(kw in name for kw in _CRITICAL_STATE_KEYWORDS):
                return True
    return False


def _find_unstaled_latest_round_data_evidence(f, max_depth: int, cross_function_scope: Optional[list] = None, _visited: Optional[set] = None) -> Optional[str]:
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal OR resolved high-level call it makes, for a
    latestRoundData() call whose answer IS consumed (index 1 captured)
    but whose updatedAt (index 3) is NOT genuinely freshness-checked —
    either never captured at all (the real LoopFi AuraVault.sol shape)
    or captured but never linked to block.timestamp via a
    revert-capable-or-propagated check, in f itself OR (see
    _staleness_check_present's cross-function fallback) a sibling
    function reached from the ORIGINAL top-level entry point.
    Returns the call's own stringified IR as evidence, or None.
    """
    if _visited is None:
        _visited = set()
    fid = id(f)
    if fid in _visited or max_depth < 0:
        return None
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None

    for node in nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fname = str(getattr(ir, "function_name", "") or "").lower()
            if fname != _LATEST_ROUND_DATA_NAME:
                continue
            tuple_var = ir.lvalue
            answer_var = _unpack_index_value(tuple_var, _ANSWER_INDEX, f)
            if answer_var is None:
                continue  # answer itself discarded — nothing to protect
            updated_at_var = _unpack_index_value(tuple_var, _UPDATED_AT_INDEX, f)
            if _staleness_check_present(updated_at_var, f, cross_function_scope):
                continue  # genuinely protected
            return str(ir)

    if max_depth <= 0:
        return None

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, (InternalCall, HighLevelCall)) and getattr(ir, "function", None) is not None:
                nested = _find_unstaled_latest_round_data_evidence(ir.function, max_depth - 1, cross_function_scope, _visited)
                if nested is not None:
                    return nested
    return None


def find_unstaled_latest_round_data_dependency(f, max_depth: int = 3) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string) if f's own
    body, or anything it reaches via bounded internal/high-level calls,
    BOTH (a) calls Chainlink's latestRoundData() and consumes the
    answer without a genuine elapsed-time freshness check on updatedAt
    — see _find_unstaled_latest_round_data_evidence — AND (b) writes
    real lending/valuation-shaped critical state somewhere in that same
    reachable scope — see _writes_critical_state — keeping this from
    firing on a pure informational/view getter with no consequence.
    """
    scope = _reachable_functions(f, max_depth)
    evidence = _find_unstaled_latest_round_data_evidence(f, max_depth, scope)
    if evidence is None:
        return None
    expanded = _expand_with_internal_calls(list(getattr(f, "nodes", []) or []), max_depth)
    if not _writes_critical_state(expanded):
        return None
    return evidence
