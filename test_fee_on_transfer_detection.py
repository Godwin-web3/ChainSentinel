"""
Regression tests for core/fee_on_transfer_detection.py — structural
fee-on-transfer/rebasing-token accounting-mismatch detection.

Real precedent for the vulnerable shape: Balancer's real $500K loss
(June 2020) — a pool holding Statera (STA), a deflationary token that
burns 1% per transfer, assumed each swap's IN amount was fully
received; the discrepancy compounded across 24 flash-loaned swaps
until the attacker drained the pool's other real assets. Also the real
code-423n4/2023-01-popcorn-findings#503 (MultiRewardEscrow.lock()).
Real precedent for the protected shape: the balance-before/after delta
pattern from those same audit fixes, and Uniswap V2's own canonical
pull-based accounting, confirmed live via IR probe against the actual
reference source.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/fee_on_transfer_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_raw_amount_credited_directly_detected():
    """
    Reproduces the real Popcorn MultiRewardEscrow.lock() shape:
    transferFrom(msg.sender, address(this), amount) followed by
    crediting the SAME `amount` directly into accounting. Must fire
    evidence.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["VulnerableEscrow.lock(IERC20,uint256)"]
    assert fn.unsafe_fee_on_transfer_credit is not None, "expected unsafe fee-on-transfer credit evidence"
    print("test_raw_amount_credited_directly_detected: PASS —",
          "evidence:", fn.unsafe_fee_on_transfer_credit)


def test_balance_before_after_delta_suppresses_finding():
    """
    The real recommended fix across dozens of real audits:
    balanceBefore/balanceAfter delta feeds accounting instead of the
    raw `amount` argument. Must NOT flag.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["ProtectedEscrow.lock(IERC20,uint256)"]
    assert fn.unsafe_fee_on_transfer_credit is None, f"balance-delta-protected credit must not flag, got {fn.unsafe_fee_on_transfer_credit}"
    print("test_balance_before_after_delta_suppresses_finding: PASS")


def test_uniswap_v2_style_pull_accounting_suppresses_finding():
    """
    The real Uniswap V2 pattern: no explicit "amount" argument is ever
    distrusted at all — the actual received amount comes purely from
    balanceOf(address(this)) against a tracked reserve. Must NOT flag.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["UniswapV2StylePullAccounting.deposit()"]
    assert fn.unsafe_fee_on_transfer_credit is None, f"Uniswap-V2-style pull accounting must not flag, got {fn.unsafe_fee_on_transfer_credit}"
    print("test_uniswap_v2_style_pull_accounting_suppresses_finding: PASS")


def test_unrelated_balance_check_does_not_suppress_real_finding():
    """
    Critical adversarial regression: an unrelated balanceOf() call
    exists in the same function (an informational observation), but it
    does NOT bracket the transfer — the critical write still directly
    credits the raw nominal amount. "Any balanceOf call somewhere in
    scope" must not suppress a genuine finding. Must fire evidence.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["UnrelatedBalanceCheckDoesNotSuppress.lock(IERC20,uint256)"]
    assert fn.unsafe_fee_on_transfer_credit is not None, "unrelated balanceOf call must not suppress the real finding"
    print("test_unrelated_balance_check_does_not_suppress_real_finding: PASS —",
          "evidence:", fn.unsafe_fee_on_transfer_credit)


def test_name_decoy_does_not_false_positive():
    """
    Proves this isn't just a different set of magic names that happens
    to work on the obvious cases: NameDecoyOnly's names are balance/
    deposit/escrow — every keyword the OLD name-matching heuristic
    would grep for — but it never actually pulls tokens via
    transferFrom at all. Must NOT flag.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["NameDecoyOnly.deposit()"]
    assert fn.unsafe_fee_on_transfer_credit is None, f"name-decoy-only contract must not flag, got {fn.unsafe_fee_on_transfer_credit}"
    print("test_name_decoy_does_not_false_positive: PASS")


def test_third_party_relay_does_not_false_positive():
    """
    Pulls tokens via transferFrom, but the destination is NOT this
    contract (a third-party relay) — this contract never claims to
    have received anything, so a fee-on-transfer token here doesn't
    corrupt ITS OWN accounting. Must NOT flag.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["ThirdPartyRelayDoesNotFalsePositive.relay(IERC20,address,uint256)"]
    assert fn.unsafe_fee_on_transfer_credit is None, f"third-party relay must not flag, got {fn.unsafe_fee_on_transfer_credit}"
    print("test_third_party_relay_does_not_false_positive: PASS")


def test_safe_erc20_library_call_shape_detected():
    """
    Live-verification regression: found via direct re-check against
    the real, currently-deployed Popcorn MultiRewardEscrow.lock()
    (code-423n4/2023-01-popcorn-findings#503) — this module's own
    primary real-world grounding — which uses `token.safeTransferFrom
    (msg.sender, address(this), amount)` via `using SafeERC20 for
    IERC20`. This lowers to a LibraryCall whose own `.arguments` is the
    library FUNCTION's full declared parameter list `(token, from, to,
    amount)` — a real, undetected gap: the original detection only
    handled the plain HighLevelCall interface-call shape
    (`IERC20(token).transferFrom(from, to, amount)`, 3 args), never the
    LibraryCall shape's shifted argument positions. Must fire evidence.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["VulnerableEscrowViaSafeERC20.lock(IERC20,uint256)"]
    assert fn.unsafe_fee_on_transfer_credit is not None, "expected unsafe fee-on-transfer credit evidence via the real SafeERC20 LibraryCall shape"
    print("test_safe_erc20_library_call_shape_detected: PASS —",
          "evidence:", fn.unsafe_fee_on_transfer_credit)


def test_safe_erc20_library_call_balance_delta_suppresses_finding():
    """
    The same real SafeERC20 `using-for` LibraryCall shape, but with the
    real balance-before/after delta fix applied. Proves the new
    LibraryCall handling doesn't just blanket-flag every SafeERC20
    pull — the delta must actually feed the write. Must NOT flag.
    """
    nodes, *_ = _build("UnsafeCredit.sol")
    fn = nodes["ProtectedEscrowViaSafeERC20.lock(IERC20,uint256)"]
    assert fn.unsafe_fee_on_transfer_credit is None, f"balance-delta-protected SafeERC20 credit must not flag, got {fn.unsafe_fee_on_transfer_credit}"
    print("test_safe_erc20_library_call_balance_delta_suppresses_finding: PASS")


def test_fee_on_transfer_constraint_fires_only_on_real_vulnerable_contracts():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual FEE_ON_TRANSFER_ACCOUNTING finding fires CONFIRMED on
    both genuinely vulnerable contracts and does not fire on any of
    the four protected/decoy contracts.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("UnsafeCredit.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for vulnerable_entry in (
        "VulnerableEscrow.lock(IERC20,uint256)",
        "UnrelatedBalanceCheckDoesNotSuppress.lock(IERC20,uint256)",
        "VulnerableEscrowViaSafeERC20.lock(IERC20,uint256)",
    ):
        vulnerable_findings = [
            r for r in report.confirmed
            if "FEE_ON_TRANSFER" in r.constraint_type and r.path.entry == vulnerable_entry
        ]
        assert vulnerable_findings, f"{vulnerable_entry} must fire FEE_ON_TRANSFER_ACCOUNTING CONFIRMED"

    for safe_entry in (
        "ProtectedEscrow.lock(IERC20,uint256)",
        "UniswapV2StylePullAccounting.deposit()",
        "NameDecoyOnly.deposit()",
        "ThirdPartyRelayDoesNotFalsePositive.relay(IERC20,address,uint256)",
        "ProtectedEscrowViaSafeERC20.lock(IERC20,uint256)",
    ):
        safe_findings = [
            r for r in all_results
            if "FEE_ON_TRANSFER" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire FEE_ON_TRANSFER_ACCOUNTING, got {safe_findings}"

    print("test_fee_on_transfer_constraint_fires_only_on_real_vulnerable_contracts: PASS —",
          "both vulnerable entries CONFIRMED, all four safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_raw_amount_credited_directly_detected()
    test_balance_before_after_delta_suppresses_finding()
    test_uniswap_v2_style_pull_accounting_suppresses_finding()
    test_unrelated_balance_check_does_not_suppress_real_finding()
    test_name_decoy_does_not_false_positive()
    test_third_party_relay_does_not_false_positive()
    test_safe_erc20_library_call_shape_detected()
    test_safe_erc20_library_call_balance_delta_suppresses_finding()
    test_fee_on_transfer_constraint_fires_only_on_real_vulnerable_contracts()
    print("\nAll fee_on_transfer_detection tests passed.")
