"""
core/vault_detection.py — Structural share-price-manipulation
(ERC4626 donation/inflation attack) detection.

Replaces core/constraints.py's old name-matching heuristic
(_check_share_inflation / _rate_is_balance_derived, which grepped
CallEdge.function_name strings for words like "totalassets",
"converttoshares", "offset", "virtual", "dead", "minimum" — unable to
verify a balanceOf() call's ARGUMENT is actually address(this), unable
to verify a "virtual offset" is a real additive term on the actual
divisor rather than a coincidentally-named function anywhere on the
path) with detection grounded in real Slither IR.

The real attack (found live via real audits this session — Sherlock's
2024-01-napier-judging#125, Zellic's Perennial report): a vault mints
shares via `shares = assets * totalSupply / totalAssets`. If
totalAssets is a raw `token.balanceOf(address(this))` read, an
attacker can donate tokens directly to the vault (bypassing deposit())
to inflate totalAssets without inflating totalSupply, rounding later
depositors' shares down to zero.

The real, industry-standard mitigation (OpenZeppelin's ERC4626 v4.9+/
v5, confirmed live via real IR probe against the exact library shape):
NOT avoiding balanceOf(this) — OZ's own totalAssets() still calls it
unconditionally — but adding a nonzero additive "virtual offset" to
the divisor itself (`totalAssets() + 1`), which the real IR renders as
a Binary ADDITION op sitting directly on the divisor operand. A vault
that tracks totalAssets via its own internal ledger (incremented only
through its own deposit/withdraw bookkeeping, e.g. real Aave/Compound-
style accounting) is safe for a different, independent reason: a
direct token donation never touches that internal variable at all, so
the ratio's denominator can't be manipulated regardless of any offset.
"""

from typing import Optional

from slither.slithir.operations import (
    Binary, HighLevelCall, InternalCall, LibraryCall, Return,
)
from slither.slithir.operations.binary import BinaryType

from core.edges import _follow_reference, _find_defining_op, _resolves_to_self
from core.auth_detection import _expand_with_internal_calls

# Real math-library divide helper names, confirmed live against the
# actual Solmate FixedPointMathLib (mulDivDown/mulDivUp — used verbatim
# by a huge fraction of real ERC4626 vaults) and OpenZeppelin's Math
# library (mulDiv). The DIVISOR is always the LAST positional argument
# across all of these — confirmed live via real IR probe.
_MULDIV_NAMES = {"muldivdown", "muldivup", "muldiv", "divdown", "divup", "divwaddown", "divwadup"}


def _traces_to_raw_balance_of_self(var, f, max_depth: int = 4, _visited: Optional[set] = None) -> bool:
    """
    True if var, with NO additive term sitting directly on its own
    defining expression, resolves — directly, or via bounded recursion
    into an internal helper's own Return value (the real
    `totalAssets()` indirection every vault uses) — to a HighLevelCall
    matching `<token>.balanceOf(address(this))`.

    A Binary ADDITION as var's own defining op is treated as real,
    sufficient virtual-offset protection and returns False immediately
    — this matches the real OpenZeppelin v4.9+/v5 shape confirmed live
    via IR probe: `totalAssets() + 1` renders as a single Binary
    ADDITION whose left operand is the InternalCall to totalAssets()
    and whose right operand is the constant `1` — exactly the
    additive-term-on-the-divisor-itself shape being checked for, not a
    claim that no addition exists anywhere deeper in the tree.
    """
    if _visited is None:
        _visited = set()
    if max_depth < 0:
        return False
    vid = id(var)
    if vid in _visited:
        return False
    _visited.add(vid)

    resolved = _follow_reference(var)
    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        return False

    # ANY Binary op sitting directly on the divisor (not just ADDITION
    # specifically) means it isn't a raw, untouched balanceOf(this)
    # read — conservatively treated as "not proven unsafe" rather than
    # trying to enumerate every transformation that would or wouldn't
    # still be dangerous. ADDITION is the real, common, positively-
    # confirmed protective case (OpenZeppelin's own `+ 1`/`+
    # 10**offset`); anything else just isn't the shape this function
    # is proving exists at all.
    if isinstance(defining_op, Binary):
        return False

    if isinstance(defining_op, HighLevelCall):
        fname = str(getattr(defining_op, "function_name", "") or "")
        if fname != "balanceOf":
            return False
        args = list(getattr(defining_op, "arguments", None) or [])
        return len(args) == 1 and _resolves_to_self(args[0], f)

    if isinstance(defining_op, InternalCall) and max_depth > 0:
        callee = getattr(defining_op, "function", None)
        if callee is None:
            return False
        try:
            callee_nodes = list(getattr(callee, "nodes", []) or [])
        except Exception:
            return False
        for node in callee_nodes:
            for ir in node.irs:
                if isinstance(ir, Return):
                    for v in (getattr(ir, "values", None) or []):
                        if _traces_to_raw_balance_of_self(v, callee, max_depth - 1, _visited):
                            return True
        return False

    return False


def _divisor_operand(ir):
    """
    Return the divisor operand of a ratio-computing IR op, or None if
    ir isn't one: a raw Binary DIVISION (variable_right), or a
    (Library)Call to a known mulDiv-family helper (the last positional
    argument — confirmed live via real IR probe against the actual
    Solmate FixedPointMathLib.mulDivDown/mulDivUp shape).
    """
    if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
        return ir.variable_right
    if isinstance(ir, (LibraryCall, InternalCall)):
        fname = str(getattr(ir, "function_name", "") or "")
        if fname.lower() in _MULDIV_NAMES:
            args = list(getattr(ir, "arguments", None) or [])
            if args:
                return args[-1]
    return None


def _writes_share_supply_state(nodes) -> bool:
    """
    True if any node in `nodes` writes a state variable whose name
    matches the real ERC4626/ERC20 share-supply-shaped accounting
    surface — `totalSupply` itself, or a balance/shares mapping — via
    Slither's own real per-node state_variables_written attribute
    (the same real IR-level signal _state_vars_written elsewhere in
    this codebase already relies on), not a raw text grep over
    unrelated strings. Deliberately the SAME co-occurrence pattern
    (not full dataflow slicing from divisor to write) core/
    auth_detection.py's own _guard_shape_from_before_after already
    uses for reentrancy-guard detection — the vulnerable ratio and the
    share-supply mutation living in the same function-or-reachable-
    helper scope is the established bar this codebase uses elsewhere
    for this class of structural co-occurrence claim.
    """
    for node in nodes:
        for var in getattr(node, "state_variables_written", []) or []:
            name = str(var).lower()
            if "totalsupply" in name or "shares" in name or "balances" in name:
                return True
    return False


def _find_unsafe_ratio_evidence(f, max_depth: int, _visited: Optional[set] = None) -> Optional[str]:
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal function it calls — each scanned in its OWN correct
    function scope, since _traces_to_raw_balance_of_self's
    _find_defining_op lookup requires the divisor operand and its
    function object to match — for a ratio-computing op whose divisor
    is an unprotected balanceOf(this) read. Returns the divisor's own
    stringified defining op as evidence, or None.
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
            divisor = _divisor_operand(ir)
            if divisor is None:
                continue
            if _traces_to_raw_balance_of_self(divisor, f):
                return str(divisor)

    if max_depth <= 0:
        return None

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                nested = _find_unsafe_ratio_evidence(ir.function, max_depth - 1, _visited)
                if nested is not None:
                    return nested
    return None


def find_unsafe_share_price_divisor(f, max_depth: int = 3) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string) if f's own
    body, or anything it reaches via bounded internal calls, BOTH (a)
    computes a share/asset conversion ratio whose divisor is an
    unprotected `token.balanceOf(address(this))` read — see
    _find_unsafe_ratio_evidence — AND (b) writes share-supply-shaped
    state somewhere in that same reachable scope — see
    _writes_share_supply_state. Requiring both keeps this from firing
    on a read-only quote/preview function in isolation while still
    catching the real `deposit()`-calls-`convertToShares()`-then-
    `totalSupply += shares` shape, where the ratio and the write live
    in different functions.
    """
    evidence = _find_unsafe_ratio_evidence(f, max_depth)
    if evidence is None:
        return None
    expanded = _expand_with_internal_calls(list(getattr(f, "nodes", []) or []), max_depth)
    if _writes_share_supply_state(expanded):
        return evidence
    return None
