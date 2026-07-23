"""
core/precision_loss_detection.py — Structural divide-before-multiply
precision-loss detection (Slither IR, source-level).

Real attack (grounded in a real, well-documented audit finding — Code4
rena's real 2022-05-cally-findings#280, Cally.sol's real
getDutchAuctionStrike()): each line individually LOOKS like the safe
"multiply, then divide" shape, but the FIRST line's division result
gets reused as an input to a SECOND multiplication:

    uint256 progress = (1e18 * delta) / AUCTION_DURATION;
    uint256 auctionStrike = (progress * progress * startingStrike) / (1e18 * 1e18);

`progress` is already truncated by the first division; squaring it
(`progress * progress`) then compounds that truncation error into the
final result. A naive "does `/` appear before `*` in the same
expression" heuristic would MISS this real bug entirely — both
individual lines are locally mul-before-div. The real defect only
shows up by tracing the DATA FLOW of the division's own result across
statement boundaries into a later multiplication — confirmed live via
IR probe against a faithful reproduction of the real vulnerable code.

The real, industry-standard mitigation — confirmed live via IR probe
against the real Cally fix, OpenZeppelin's actual Math.mulDiv (full
512-bit `mul512(x, y)` computed BEFORE any division), and Solmate's
actual FixedPointMathLib.mulDivDown (`div(mul(x, y), denominator)` in
one fused assembly instruction) — is to eliminate the intermediate
division entirely: multiply everything first, divide once, at the very
end. Real, mulDiv-family library calls are naturally opaque to this
detector: their internal division lives inside an assembly block,
never lowering to a visible Slither Binary DIVISION op at the caller's
own IR level — confirmed live via IR probe — so they require no
special-case name exclusion at all, unlike this codebase's other
mulDiv-aware detectors (core/vault_detection.py's own _MULDIV_NAMES,
needed there because that detector inspects the DIVISOR of a ratio
directly, a different question than this module's).
"""

from typing import Optional

from slither.slithir.operations import Binary
from slither.slithir.operations.binary import BinaryType

from core.auth_detection import _expand_with_internal_calls

_CRITICAL_STATE_KEYWORDS = ("share", "balance", "amount", "price", "strike", "value", "collateral", "debt")


def _find_division_ops(nodes: list):
    """Yield every raw Binary DIVISION op across `nodes`."""
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
                yield ir


def _division_reaches_multiply_then_write(div_result, f, max_depth: int = 6) -> Optional[str]:
    """
    Forward-taint div_result (a raw Binary DIVISION's own lvalue)
    through f's own IR, in bounded fixed-point iteration over node
    order, to determine whether that SPECIFIC (already-truncated)
    value later becomes an operand of a Binary MULTIPLICATION —
    confirmed live via IR probe: the real Cally shape has `progress`
    (a division's result, via a pass-through Assignment) read directly
    by `progress * progress` — and whether THAT multiplication's own
    result then reaches a write to real share/balance/price-shaped
    accounting state. Returns the written state variable's own name as
    evidence, or None.
    """
    tainted = {id(div_result)}
    saw_multiply_after_division = False
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None

    for _ in range(max_depth):
        progressed = False
        for node in nodes:
            for ir in node.irs:
                reads = list(getattr(ir, "read", []) or [])
                if not any(id(r) in tainted for r in reads):
                    continue
                if isinstance(ir, Binary) and ir.type == BinaryType.MULTIPLICATION:
                    saw_multiply_after_division = True
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and id(lvalue) not in tainted:
                    tainted.add(id(lvalue))
                    progressed = True
            if not saw_multiply_after_division:
                continue
            for var in getattr(node, "state_variables_written", []) or []:
                name = str(var).lower()
                if not any(kw in name for kw in _CRITICAL_STATE_KEYWORDS):
                    continue
                ir_reads = {
                    id(r)
                    for ir in node.irs
                    for r in (getattr(ir, "read", []) or [])
                }
                if ir_reads & tainted:
                    return str(var)
        if not progressed:
            break
    return None


def _find_unsafe_precision_loss_evidence(f, max_depth: int, _visited: Optional[set] = None) -> Optional[str]:
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal function it calls, for a raw Binary DIVISION whose result
    reaches a later multiplication feeding critical accounting state —
    see _division_reaches_multiply_then_write. Returns the written
    state variable's own name as evidence, or None.
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

    for div_ir in _find_division_ops(nodes):
        evidence = _division_reaches_multiply_then_write(div_ir.lvalue, f)
        if evidence is not None:
            return evidence

    if max_depth <= 0:
        return None

    from slither.slithir.operations import InternalCall
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                nested = _find_unsafe_precision_loss_evidence(ir.function, max_depth - 1, _visited)
                if nested is not None:
                    return nested
    return None


def find_unsafe_divide_before_multiply(f, max_depth: int = 3) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string — the written
    state variable's own name) if f's own body, or anything it reaches
    via bounded internal calls, contains a raw Binary DIVISION whose
    (already-truncated) result later becomes an operand of a Binary
    MULTIPLICATION, feeding a write to real share/balance/price-shaped
    accounting state — see _find_unsafe_precision_loss_evidence. A
    real, mulDiv-family library call's internal division lives inside
    an assembly block and never appears as a visible Binary DIVISION
    op at this level, so it's naturally excluded with no special-case
    name list needed.
    """
    return _find_unsafe_precision_loss_evidence(f, max_depth)
