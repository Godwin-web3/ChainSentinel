"""
core/spot_price_detection.py — Structural spot-price-oracle-
manipulation detection (Slither IR, source-level).

Not to be confused with core/oracle_detection.py, which classifies an
oracle's TYPE from live on-chain bytecode (Chainlink/TWAP/spot/
unguarded) for market-discovery/adapter purposes — a completely
different subsystem operating on a completely different data source
(raw deployed bytecode selectors, not Slither IR over fetched source).
This module answers a narrower, source-level question: does an
analyzed function ITSELF unsafely consume an AMM pool's spot price in
a security-critical calculation?

Real attack (grounded in real, well-documented exploits — Harvest
Finance's real $24M loss, Oct 2020, priced vault shares from a live
Curve pool reserve ratio with no time-weighting; Warp Finance's real
$8M loss, Dec 2020): a security-critical calculation (collateral
value, liquidation threshold, mint/borrow amount) reads price directly
from a single AMM pool's INSTANTANEOUS state — Uniswap V2's
`getReserves()` (reserve0/reserve1, a spot ratio) or Uniswap V3's
`slot0()` (sqrtPriceX96, a spot price) — with no time-weighting at
all. Within one transaction (a flash loan is enough), an attacker can
swap to skew that instantaneous state, use the skewed price for one
call, then reverse the swap — the classic single-block manipulation
every one of these real incidents shares.

The unsafe value doesn't have to be consumed in the SAME function that
reads it. Confirmed live via cmichel.io's real writeup of the actual
Warp Finance exploit: its UniswapLPOracleFactory.sol read raw
getReserves() and passed the RAW reserve AMOUNT as an ARGUMENT into a
separate oracle contract's own consult()-style function, which
internally multiplied a real TWAP-protected average price by that
unprotected amount — neither contract's own body looked unsafe in
isolation. This module's evidence-tracing follows that exact shape: a
bounded chain of call-site parameter bindings across resolved
InternalCalls AND HighLevelCalls (Slither resolves HighLevelCall.
function to the concrete callee when the call target's static type is
a known, in-project contract), not just a single function's own body.

The real, industry-standard mitigation — confirmed live via IR probe
against Uniswap's own real reference implementations (v2-periphery's
ExampleOracleSimple.sol, v3-periphery's OracleLibrary.sol) — is NOT
avoiding getReserves()/slot0() (a TWAP still ultimately reads
accumulator state derived from the same pool) but dividing by a REAL
ELAPSED TIME value: V2's `(price0Cumulative - price0CumulativeLast) /
timeElapsed` where `timeElapsed = blockTimestamp - blockTimestampLast`,
and V3's `tickCumulativesDelta / secondsAgo`. A single-block
manipulation can move the instantaneous reserves/tick, but its
contribution to a value divided by a real elapsed-time window (hours,
not one block) is diluted to economic irrelevance.
"""

from typing import Optional

from slither.slithir.operations import Assignment, Binary, HighLevelCall, TypeConversion
from slither.slithir.operations.binary import BinaryType
from slither.slithir.operations.unpack import Unpack
from slither.core.declarations.solidity_variables import SolidityVariableComposed

from core.edges import _follow_reference, _find_defining_op
from core.auth_detection import _expand_with_internal_calls

# Real Uniswap V2/V3 spot-price-shaped accessor names — both return a
# TUPLE (reserve0/reserve1/blockTimestampLast for V2's getReserves();
# sqrtPriceX96/tick/... for V3's slot0()), confirmed live via IR probe
# to lower to the SAME Unpack IR shape, so both are handled uniformly.
_SPOT_PRICE_ACCESSOR_NAMES = {"getreserves", "slot0"}

_CRITICAL_STATE_KEYWORDS = ("collateral", "debt", "borrow", "liquidat", "health", "price", "value")


def _single_source_operand(defining_op):
    """
    Return the one meaningful source operand of a pass-through IR op —
    TypeConversion's `.variable` (`uint32(x)`-style casts) or
    Assignment's `.rvalue` (the plain `lhs = rhs` op Slither inserts
    between a temp and a named local — confirmed live via IR probe:
    `uint32 timeElapsed = uint32(block.timestamp) - lastUpdate;` lowers
    to a Binary SUBTRACTION into a TEMP, then a SEPARATE Assignment op
    `timeElapsed := TEMP`, so callers resolving through a named local
    variable must unwrap this hop too, not just TypeConversion) — or
    None if defining_op isn't one of these pass-through shapes.
    """
    if isinstance(defining_op, TypeConversion):
        return getattr(defining_op, "variable", None)
    if isinstance(defining_op, Assignment):
        return getattr(defining_op, "rvalue", None)
    return None


def _resolves_to_block_timestamp(var, f, max_depth: int = 3) -> bool:
    """
    True if var is (or, via bounded TypeConversion/Assignment/reference
    hops, resolves to) Solidity's own `block.timestamp` — confirmed live
    via IR probe: `uint32(block.timestamp)` lowers to a TypeConversion
    whose own `.variable` is a SolidityVariableComposed("block.timestamp"),
    and a named local like `timeElapsed` resolves to its Binary
    SUBTRACTION only through an intervening Assignment op — see
    _single_source_operand.
    """
    if max_depth < 0:
        return False
    if isinstance(var, SolidityVariableComposed) and str(var) == "block.timestamp":
        return True
    resolved = _follow_reference(var)
    if isinstance(resolved, SolidityVariableComposed) and str(resolved) == "block.timestamp":
        return True
    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        return False
    inner = _single_source_operand(defining_op)
    if inner is not None and max_depth > 0:
        return _resolves_to_block_timestamp(inner, f, max_depth - 1)
    return False


def _is_elapsed_time_subtraction(ir, f) -> bool:
    """
    True if ir is a Binary SUBTRACTION where at least one operand
    resolves to block.timestamp (directly or via a stored prior-
    timestamp state variable subtracted from a fresh block.timestamp
    read) — the real V2 `blockTimestamp - blockTimestampLast` /
    equivalent "how much real time has passed" computation every real
    TWAP implementation performs before trusting a cumulative delta.
    """
    if not isinstance(ir, Binary) or ir.type != BinaryType.SUBTRACTION:
        return False
    return _resolves_to_block_timestamp(ir.variable_left, f) or _resolves_to_block_timestamp(ir.variable_right, f)


def _unwrap_passthrough_defining_op(var, f, max_depth: int = 3):
    """
    Resolve var to its defining op, skipping bounded TypeConversion/
    Assignment pass-through hops (see _single_source_operand) to reach
    the first "real" (non-pass-through) op — e.g. a named local like
    `timeElapsed` resolves through its own Assignment op straight to
    the real Binary SUBTRACTION that computed it, confirmed live via IR
    probe: `uint32 timeElapsed = uint32(block.timestamp) - lastUpdate;`
    lowers to Binary(SUBTRACTION) -> a TEMP -> Assignment(timeElapsed).
    """
    if max_depth < 0:
        return None
    defining_op = _find_defining_op(_follow_reference(var), f)
    if defining_op is None:
        return None
    inner = _single_source_operand(defining_op)
    if inner is not None:
        return _unwrap_passthrough_defining_op(inner, f, max_depth - 1)
    return defining_op


def _is_elapsed_time_division(ir, f) -> bool:
    """
    True if ir is a Binary DIVISION whose divisor traces to an elapsed-
    time subtraction (see _is_elapsed_time_subtraction) — the real TWAP
    shape confirmed live via IR probe against both Uniswap V2's real
    ExampleOracleSimple.sol (`(price0Cumulative - price0CumulativeLast)
    / timeElapsed`) and Uniswap V3's real OracleLibrary.sol
    (`tickCumulativesDelta / secondsAgo`) reference implementations.
    """
    if not isinstance(ir, Binary) or ir.type != BinaryType.DIVISION:
        return False
    divisor = _follow_reference(ir.variable_right)
    if _resolves_to_block_timestamp(divisor, f):
        return True
    defining_op = _unwrap_passthrough_defining_op(divisor, f)
    return defining_op is not None and _is_elapsed_time_subtraction(defining_op, f)


def _propagates_through_elapsed_time_division(seed, f, max_depth: int = 6) -> bool:
    """
    Forward-taint seed (the LVALUE of the specific unsafe Binary op that
    consumed the spot-price-accessor-traced operand) through f's own IR,
    in bounded fixed-point iteration over node order, to determine
    whether THAT SPECIFIC value is itself diluted by a real elapsed-time
    division before this analysis stops looking.

    Deliberately narrower than an earlier "any elapsed-time division
    anywhere in the same reachable scope" version: a contract can
    legitimately have an UNRELATED elapsed-time subtraction/division
    elsewhere in the same function for a different purpose entirely
    (a staking cooldown, a reward-rate accrual) that has nothing to do
    with the unsafe price read. Treating that as protective would be a
    real false suppression of a genuine vulnerability. Requiring the
    taint to actually reach the division (via real IR read/lvalue
    chains, not mere co-occurrence) closes that gap while still
    matching the real V2/V3 TWAP shape: the raw spot read's own
    contribution must pass through the division to count as diluted.
    """
    tainted = {id(seed)}
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False

    for _ in range(max_depth):
        progressed = False
        for node in nodes:
            for ir in node.irs:
                reads = list(getattr(ir, "read", []) or [])
                if not any(id(_follow_reference(r)) in tainted for r in reads):
                    continue
                if _is_elapsed_time_division(ir, f):
                    return True
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and id(lvalue) not in tainted:
                    tainted.add(id(lvalue))
                    progressed = True
        if not progressed:
            break
    return False


def _resolve_via_call_site(var, f, call_stack):
    """
    If var is one of f's own formal parameters and call_stack is
    non-empty, resolve it to the ACTUAL argument expression at the
    (most recent) call site that reached f — confirmed live via IR
    probe against a faithful reproduction of the real Warp Finance
    UniswapLPOracleFactory.sol + a TWAP consult() oracle instance shape:
    HighLevelCall.arguments lines up positionally with the resolved
    callee's .function.parameters, so a parameter used inside the
    callee's own Binary op can be traced back to whatever expression
    the CALLER actually passed in. Returns (arg_var, caller_f,
    remaining_call_stack), or None if var isn't a parameter of f or
    there's no call site to resolve through.
    """
    if not call_stack:
        return None
    try:
        params = list(getattr(f, "parameters", []) or [])
    except Exception:
        return None
    idx = None
    for i, p in enumerate(params):
        if p is var:
            idx = i
            break
    if idx is None:
        return None
    caller_f, call_ir = call_stack[-1]
    args = list(getattr(call_ir, "arguments", []) or [])
    if idx >= len(args):
        return None
    return args[idx], caller_f, call_stack[:-1]


def _traces_to_spot_price_accessor(var, f, call_stack=None) -> Optional[str]:
    """
    True (returning the accessor call's own stringified defining op as
    evidence) if var traces — directly, via a single Unpack hop (the
    real IR shape for `(reserve0, reserve1, ) = pair.getReserves();` /
    `(sqrtPriceX96, , , , , , ) = pool.slot0();`, confirmed live via IR
    probe), or via a bounded chain of call-site parameter bindings (see
    _resolve_via_call_site — the real Warp Finance shape: a raw
    getReserves() output passed as an ARGUMENT into a separate oracle
    contract's own price-computing function, rather than consumed
    directly in the same function that read it) — to a HighLevelCall
    whose function_name matches a known Uniswap V2/V3 spot-price-shaped
    accessor (getReserves/slot0).
    """
    if call_stack is None:
        call_stack = []
    resolved = _follow_reference(var)
    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        via_call = _resolve_via_call_site(resolved, f, call_stack)
        if via_call is None:
            return None
        arg, caller_f, remaining_stack = via_call
        return _traces_to_spot_price_accessor(arg, caller_f, remaining_stack)

    # `uint256(reserve1)`-style casts are extremely common around a
    # raw uint112 reserve value before it's used in a wider-precision
    # ratio computation — confirmed live via IR probe: the real
    # Warp-Finance-shaped `(uint256(reserve1) * 1e18) / uint256(reserve0)`
    # lowers to a TypeConversion whose OWN lvalue (not reserve1 itself)
    # is what the surrounding Binary op actually reads. Unwrap one hop
    # before giving up.
    if isinstance(defining_op, TypeConversion):
        inner = getattr(defining_op, "variable", None)
        if inner is not None:
            return _traces_to_spot_price_accessor(inner, f, call_stack)
        return None

    if isinstance(defining_op, Unpack):
        tuple_var = getattr(defining_op, "tuple", None)
        if tuple_var is None:
            return None
        tuple_op = _find_defining_op(_follow_reference(tuple_var), f)
        if isinstance(tuple_op, HighLevelCall):
            fname = str(getattr(tuple_op, "function_name", "") or "").lower()
            if fname in _SPOT_PRICE_ACCESSOR_NAMES:
                return str(tuple_op)
        return None

    if isinstance(defining_op, HighLevelCall):
        fname = str(getattr(defining_op, "function_name", "") or "").lower()
        if fname in _SPOT_PRICE_ACCESSOR_NAMES:
            return str(defining_op)
        return None

    return None


def _writes_critical_state(nodes) -> bool:
    """
    True if any node in `nodes` writes a state variable whose name
    matches a real lending/valuation accounting surface — collateral,
    debt, borrow, liquidation, health, price, value — via Slither's own
    real per-node state_variables_written attribute, the same
    established co-occurrence pattern core/vault_detection.py's own
    _writes_share_supply_state already uses for the sibling donation-
    attack detector: the vulnerable price read and the consequential
    state mutation living in the same function-or-reachable-helper
    scope is this codebase's established bar for this class of
    structural co-occurrence claim.
    """
    for node in nodes:
        for var in getattr(node, "state_variables_written", []) or []:
            name = str(var).lower()
            if any(kw in name for kw in _CRITICAL_STATE_KEYWORDS):
                return True
    return False


def _find_unsafe_spot_price_evidence(f, max_depth: int, _visited: Optional[set] = None, call_stack=None):
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal OR resolved high-level (cross-contract) call it makes —
    each scanned in its OWN correct function scope, since
    _traces_to_spot_price_accessor's _find_defining_op lookup requires
    the operand and its function object to match — for a value used in
    a price/value computation (a Binary MULTIPLICATION or DIVISION
    operand) that traces to an unprotected AMM spot-price accessor
    call, INCLUDING through a bounded chain of call-site parameter
    bindings (see _resolve_via_call_site).

    Crossing resolved HighLevelCalls (not just InternalCalls) matters:
    confirmed live via IR probe against a faithful reproduction of the
    real Warp Finance shape (cmichel.io's real writeup of the actual
    $8M Dec 2020 exploit) — UniswapLPOracleFactory.sol reads raw
    getReserves() and passes the RAW reserve AMOUNT as an argument into
    a SEPARATE oracle contract's own consult()-style function, which
    internally multiplies a real TWAP-protected average price by that
    unprotected amount. Neither contract's own body looks unsafe in
    isolation; the vulnerability only exists across the call boundary.
    Slither resolves HighLevelCall.function to the concrete callee
    Function when the call target's static type is a known, in-project
    contract (not just an interface with no implementation) — the same
    real IR fact this recursion relies on.

    Returns (evidence_str, binary_ir, containing_function), or None —
    the Binary op and its OWN containing function are returned (not
    just the evidence string) so a caller can forward-taint from that
    SPECIFIC op's lvalue in its OWN correct function scope, rather than
    assuming it lives in f.
    """
    if _visited is None:
        _visited = set()
    if call_stack is None:
        call_stack = []
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
            if not isinstance(ir, Binary) or ir.type not in (BinaryType.MULTIPLICATION, BinaryType.DIVISION):
                continue
            for operand in (ir.variable_left, ir.variable_right):
                evidence = _traces_to_spot_price_accessor(operand, f, call_stack)
                if evidence is not None:
                    return evidence, ir, f

    if max_depth <= 0:
        return None

    from slither.slithir.operations import InternalCall
    for node in nodes:
        for ir in node.irs:
            callee = None
            if isinstance(ir, (InternalCall, HighLevelCall)) and getattr(ir, "function", None) is not None:
                callee = ir.function
            if callee is None:
                continue
            nested = _find_unsafe_spot_price_evidence(callee, max_depth - 1, _visited, call_stack + [(f, ir)])
            if nested is not None:
                return nested
    return None


def find_unsafe_spot_price_dependency(f, max_depth: int = 3) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string) if f's own
    body, or anything it reaches via bounded internal calls, ALL of:
      (a) computes a price/value from an unprotected AMM spot-price
          accessor call (getReserves()/slot0()) used directly in a
          multiplication/division — see _find_unsafe_spot_price_evidence;
      (b) that SPECIFIC value is not itself forward-tainted into a
          real elapsed-time-gated division within its own containing
          function — see _propagates_through_elapsed_time_division.
          Deliberately scoped to the specific value, not "any
          elapsed-time division anywhere in the reachable scope": a
          contract can have a wholly unrelated elapsed-time
          computation elsewhere (a staking cooldown, a reward-rate
          accrual) that must not be treated as diluting a genuinely
          unsafe, unrelated price read;
      (c) writes real lending/valuation-shaped critical state
          somewhere in that same reachable scope — see
          _writes_critical_state — keeping this from firing on a
          pure informational/view getter with no consequence.
    """
    found = _find_unsafe_spot_price_evidence(f, max_depth)
    if found is None:
        return None
    evidence, unsafe_ir, containing_f = found

    if _propagates_through_elapsed_time_division(unsafe_ir.lvalue, containing_f):
        return None

    expanded = _expand_with_internal_calls(list(getattr(f, "nodes", []) or []), max_depth)
    if not _writes_critical_state(expanded):
        return None
    return evidence
