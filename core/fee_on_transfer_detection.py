"""
core/fee_on_transfer_detection.py — Structural fee-on-transfer/
rebasing-token accounting-mismatch detection (Slither IR, source-level).

Real attack (grounded in a real, well-documented exploit — Balancer's
real $500K loss, June 2020): a Balancer pool held Statera (STA), a
deflationary token that burns 1% of every transfer. Balancer's pool
math assumed a swap's IN amount was fully received, but STA delivered
1% less each time. An attacker flash-loaned WETH and swapped back and
forth with STA 24 times; the pool's internal accounting drifted
further from its real token balance on every iteration (the
discrepancy compounds — each swap's "phantom" surplus becomes the base
for the next), until the attacker could drain the pool's OTHER real
assets (WBTC, LINK, SNX) against a balance the pool never actually
held.

The same root cause — trusting a transfer's nominal `amount` argument
instead of the contract's own actual balance delta — is one of the
single most common real Code4rena/Sherlock findings across dozens of
audits (the recommended fix appears near-verbatim in reports for
Popcorn, Numoen, THORChain, and many others): "measure the contract
balance before and after the transfer, and use the difference as the
amount, rather than the stated amount." Confirmed live via IR probe
against the real Popcorn finding (code-423n4/2023-01-popcorn-findings
#503, MultiRewardEscrow.lock()): `token.safeTransferFrom(msg.sender,
address(this), amount)` followed by crediting the SAME `amount`
parameter directly into `escrows[id].balance` — never checking what
the contract actually received.

The real, industry-standard mitigation is NOT unique to a name-brand
library (there's no OpenZeppelin "SafeDeposit" helper) — it's a
structural pattern found in real fixes across the audits above, and in
Uniswap V2's own canonical pull-based accounting (UniswapV2Pair.mint():
`amount0 = balance0.sub(_reserve0)`, deriving the real received amount
from `balanceOf(address(this))` itself, never trusting any caller-
supplied amount at all): snapshot `balanceOf(address(this))` before the
transfer, snapshot it again after, and use the DIFFERENCE — not the
original `amount` argument — for any accounting that depends on how
much was actually received.
"""

from typing import Optional

from slither.slithir.operations import LibraryCall

from core.edges import _is_token_transfer_call, _resolves_to_self, _follow_reference
from core.auth_detection import _expand_with_internal_calls

_CRITICAL_STATE_KEYWORDS = ("balance", "deposit", "shares", "escrow", "principal", "collateral")

# Real function names used for this purpose by every `using X for Y`
# safe-transfer library found live this session (OpenZeppelin's
# SafeERC20/SafeERC20Upgradeable — by far the most widely-deployed
# instance) — a raw ERC20's own transferFrom used the same way is the
# same shape.
_LIBRARY_TRANSFER_FROM_NAMES = {"transferfrom", "safetransferfrom"}


def _find_self_pull_transfer_amount_args(f):
    """
    Yield the raw `amount` argument Variable of every real token-
    transfer-shaped call in f's own body that PULLS tokens INTO this
    contract — either (a) a 3-(or 4-)argument transferFrom/
    safeTransferFrom HighLevelCall whose `to` (argument index 1)
    resolves to address(this) — the plain interface-call shape
    (`IERC20(token).transferFrom(from, to, amount)`) — or (b) the real,
    single most common shape in practice: a `using SafeERC20 for
    IERC20`-style LibraryCall, confirmed live via IR probe against the
    ACTUAL, currently-deployed Popcorn MultiRewardEscrow.lock()
    (code-423n4/2023-01-popcorn-findings#503) — `token.safeTransferFrom
    (msg.sender, address(this), amount)` lowers to a LibraryCall whose
    own `.arguments` is the library FUNCTION's full declared parameter
    list, `(token, from, to, amount)` — the "for" instance becomes a
    real LEADING positional argument, shifting `to`/`amount` one slot
    later than the HighLevelCall case. This was a real, undetected gap
    in this module's own primary real-world grounding: the original
    fixture only reproduced the plain-interface-call shape, never the
    actual library-delegation mechanics SafeERC20 uses.

    Deliberately scoped to the PULL direction only — the real, most
    common, most clearly-defined instance of this bug class (crediting
    a deposit based on a nominal amount rather than what was actually
    received); an outbound transfer()/push's accounting risk is a
    materially different, less clear-cut question left out of scope.
    """
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return
    for node in nodes:
        for ir in node.irs:
            if _is_token_transfer_call(ir):
                args = list(getattr(ir, "arguments", None) or [])
                if len(args) < 3:
                    continue
                if not _resolves_to_self(args[1], f):
                    continue
                yield args[2]
            elif isinstance(ir, LibraryCall):
                fname = str(getattr(ir, "function_name", "") or "").lower()
                if fname not in _LIBRARY_TRANSFER_FROM_NAMES:
                    continue
                args = list(getattr(ir, "arguments", None) or [])
                if len(args) < 4:
                    continue
                if not _resolves_to_self(args[-2], f):
                    continue
                yield args[-1]


def _reaches_critical_accounting_write(seed, f, max_depth: int = 6) -> Optional[str]:
    """
    Forward-taint seed (the raw transfer `amount` argument) through f's
    own IR, in bounded fixed-point iteration over node order, to
    determine whether that SPECIFIC value — undiluted by any
    intervening balanceOf(address(this))-delta computation — directly
    reaches a write to real deposit/balance-shaped accounting state.
    Returns the written state variable's own name as evidence, or None.

    Confirmed live via IR probe: the real Popcorn-shaped vulnerable
    case has the transferFrom's own `amount` LocalVariable read
    directly by the critical Assignment (`escrows[id].balance =
    amount`) — a single hop. The real balance-before/after protected
    shape never reads `amount` again after the transfer call at all
    (the accounting write instead reads a locally-computed
    `actualAmount := balanceAfter - balanceBefore`, which has no data-
    flow link back to `amount` whatsoever) — so this taint search
    correctly finds no evidence there.
    """
    tainted = {id(seed)}
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None

    for _ in range(max_depth):
        progressed = False
        for node in nodes:
            for ir in node.irs:
                reads = list(getattr(ir, "read", []) or [])
                if not any(id(_follow_reference(r)) in tainted for r in reads):
                    continue
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and id(lvalue) not in tainted:
                    tainted.add(id(lvalue))
                    progressed = True
            for var in getattr(node, "state_variables_written", []) or []:
                name = str(var).lower()
                if not any(kw in name for kw in _CRITICAL_STATE_KEYWORDS):
                    continue
                # Checked at the IR level, not node.variables_read
                # (source-level named variables only) — a real bug
                # found live building the sibling staleness detector:
                # node.variables_read never contains an intermediate IR
                # temporary, so a tainted value that passed through even
                # one TypeConversion/Binary hop would silently fail to
                # match here if checked that way.
                ir_reads = {
                    id(_follow_reference(r))
                    for ir in node.irs
                    for r in (getattr(ir, "read", []) or [])
                }
                if ir_reads & tainted:
                    return str(var)
        if not progressed:
            break
    return None


def _find_unsafe_fee_on_transfer_evidence(f, max_depth: int, _visited: Optional[set] = None) -> Optional[str]:
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal function it calls, for a self-pull transfer whose raw
    amount argument reaches a critical accounting write undiluted by a
    balance-delta computation. Returns the written state variable's own
    name as evidence, or None.
    """
    if _visited is None:
        _visited = set()
    fid = id(f)
    if fid in _visited or max_depth < 0:
        return None
    _visited.add(fid)

    for amount_arg in _find_self_pull_transfer_amount_args(f):
        evidence = _reaches_critical_accounting_write(amount_arg, f)
        if evidence is not None:
            return evidence

    if max_depth <= 0:
        return None

    from slither.slithir.operations import InternalCall
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                nested = _find_unsafe_fee_on_transfer_evidence(ir.function, max_depth - 1, _visited)
                if nested is not None:
                    return nested
    return None


def find_unsafe_fee_on_transfer_credit(f, max_depth: int = 3) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string — the written
    state variable's own name) if f's own body, or anything it reaches
    via bounded internal calls, pulls tokens in via transferFrom/
    safeTransferFrom and directly credits the RAW, nominal amount
    argument into real deposit/balance-shaped accounting state, with no
    balanceOf(address(this))-delta computation interposed — see
    _find_unsafe_fee_on_transfer_evidence. A fee-on-transfer or
    rebasing token can deliver less than the nominal amount, corrupting
    this accounting permanently (the real Balancer/Statera $500K loss,
    June 2020 — the discrepancy compounds across repeated calls until
    the contract's recorded accounting exceeds what it actually holds).
    """
    return _find_unsafe_fee_on_transfer_evidence(f, max_depth)
