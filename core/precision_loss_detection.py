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

from slither.slithir.operations import Binary, InternalCall, Member, Return
from slither.slithir.operations.binary import BinaryType

_CRITICAL_STATE_KEYWORDS = (
    "share", "balance", "amount", "price", "strike", "value", "collateral", "debt",
    # "vault" added after live-verifying against the real, actual
    # Cally.sol source this module is grounded in
    # (code-423n4/2022-05-cally-findings#280): the real vulnerable
    # write is `_vaults[vaultId] = vault;` — a whole-struct write whose
    # STATE variable name is `_vaults`, not `currentStrike` (the
    # struct's own field, invisible at the state-write level for a
    # wholesale struct assignment). "vault" is as canonical a DeFi
    # accounting-state name as any already in this list.
    "vault",
)


def _find_division_ops(nodes: list):
    """Yield every raw Binary DIVISION op across `nodes`."""
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
                yield ir


def _forward_taint_to_critical_write(seed, f, seen_multiply: bool, max_depth: int = 6) -> Optional[str]:
    """
    Forward-taint seed through f's own IR, in bounded fixed-point
    iteration over node order, to determine whether that SPECIFIC
    (already-truncated) value later becomes an operand of a Binary
    MULTIPLICATION — confirmed live via IR probe: the real Cally shape
    has `progress` (a division's result, via a pass-through Assignment)
    read directly by `progress * progress` — and whether THAT
    multiplication's own result then reaches a write to real share/
    balance/price/vault-shaped accounting state. Returns the written
    state variable's own name as evidence, or None.

    seen_multiply lets a caller seed this already past the
    "has a multiplication been seen yet" gate — see
    _reaches_multiplied_return/_find_unsafe_precision_loss_evidence's
    cross-function bridging, for the real Cally shape where the
    multiplication already happened inside a callee before the tainted
    value ever reached this function at all (via its return value).
    """
    tainted = {id(seed)}
    saw_multiply_after_division = seen_multiply
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None

    for _ in range(max_depth):
        progressed = False
        for node in nodes:
            # Member ops in THIS node, mapped reference-lvalue -> base
            # object — e.g. `REF -> vault.currentStrike` maps REF's own
            # id to `vault`. Confirmed live via IR probe against the
            # real Cally.buyOption(): `vault.currentStrike =
            # getDutchAuctionStrike(...)` taints the FIELD's own
            # reference (REF_254), but the actual critical write three
            # statements later is `_vaults[vaultId] = vault;` — a
            # WHOLE-STRUCT copy that reads `vault` itself, never REF_254
            # directly. Without propagating taint from a tainted field
            # write back to the struct's own base variable, that later
            # whole-struct read never shows up as tainted at all.
            ref_to_base = {}
            for ir in node.irs:
                if isinstance(ir, Member):
                    base = getattr(ir, "variable_left", None)
                    if base is not None:
                        ref_to_base[id(ir.lvalue)] = base
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
                    base = ref_to_base.get(id(lvalue))
                    if base is not None and id(base) not in tainted:
                        tainted.add(id(base))
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


def _division_reaches_multiply_then_write(div_result, f, max_depth: int = 6) -> Optional[str]:
    return _forward_taint_to_critical_write(div_result, f, seen_multiply=False, max_depth=max_depth)


def _reaches_multiplied_return(seed, f, max_depth: int = 6) -> bool:
    """
    True if seed, after a later Binary MULTIPLICATION, reaches a
    Return op in f — f "hands off" an already-precision-lossy value to
    its caller instead of writing state itself.
    """
    tainted = {id(seed)}
    saw_multiply = False
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False

    for _ in range(max_depth):
        progressed = False
        for node in nodes:
            for ir in node.irs:
                reads = list(getattr(ir, "read", []) or [])
                if not any(id(r) in tainted for r in reads):
                    continue
                if isinstance(ir, Binary) and ir.type == BinaryType.MULTIPLICATION:
                    saw_multiply = True
                if isinstance(ir, Return) and saw_multiply:
                    return True
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and id(lvalue) not in tainted:
                    tainted.add(id(lvalue))
                    progressed = True
        if not progressed:
            break
    return False


def _function_returns_multiplied_division(f, max_depth: int = 6) -> bool:
    """
    True if f itself contains a raw division whose result, after a
    later multiplication, reaches a Return — the real, currently-
    deployed Cally.getDutchAuctionStrike() shape
    (code-423n4/2022-05-cally-findings#280): a pure/view helper that
    hands off an already-squared, already-truncated value to its
    caller (Cally.buyOption(), via `vault.currentStrike =
    getDutchAuctionStrike(...)`) instead of writing state itself — the
    caller's OWN later `_vaults[vaultId] = vault;` is the actual
    critical write, invisible from inside the pure helper. Found live
    verifying against the real deployed source: this module's own
    primary real-world grounding case scored a false negative before
    this cross-function bridge existed, since the division-then-
    multiply chain and the critical write lived in two different
    functions with no in-scope connection.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return False
    for div_ir in _find_division_ops(nodes):
        if _reaches_multiplied_return(div_ir.lvalue, f, max_depth):
            return True
    return False


def _find_unsafe_precision_loss_evidence(f, max_depth: int, _visited: Optional[set] = None) -> Optional[str]:
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal function it calls, for a raw Binary DIVISION whose result
    reaches a later multiplication feeding critical accounting state —
    see _division_reaches_multiply_then_write. Returns the written
    state variable's own name as evidence, or None.

    Also bridges the real cross-function Cally shape: if an
    InternalCall's own callee hands back an already division-then-
    multiplied value via its own Return (see
    _function_returns_multiplied_division) with no state write of its
    own, the call's own lvalue is treated as an already-multiplied
    taint seed and the search continues in THIS function's scope —
    the caller's own eventual write is the real evidence.
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

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                callee = ir.function
                if ir.lvalue is not None and _function_returns_multiplied_division(callee, max_depth):
                    evidence = _forward_taint_to_critical_write(ir.lvalue, f, seen_multiply=True, max_depth=max_depth)
                    if evidence is not None:
                        return evidence
                nested = _find_unsafe_precision_loss_evidence(callee, max_depth - 1, _visited)
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
