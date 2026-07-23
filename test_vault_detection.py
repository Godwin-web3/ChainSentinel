"""
Regression tests for core/vault_detection.py — structural ERC4626
donation/inflation (share-price-manipulation) attack detection.

Replaces core/constraints.py's old _check_share_inflation /
_rate_is_balance_derived, which grepped CallEdge.function_name strings
for words like "totalassets", "converttoshares", "offset", "virtual",
"dead", "minimum" — unable to verify a balanceOf() call's ARGUMENT is
actually address(this), unable to verify a "virtual offset" is a real
additive term on the actual divisor rather than a coincidentally-named
function anywhere on the path.

Real precedent for the vulnerable shape: Sherlock's real
2024-01-napier-judging#125 finding against Napier's
BaseLSTAdapter.totalAssets(), and Zellic's real Perennial audit
finding of the identical shape. Real precedent for the protected
shape: OpenZeppelin's actual ERC4626 v4.9+/v5 _convertToShares,
confirmed live via IR probe against the real library source.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/vault_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_unprotected_balance_derived_divisor_detected():
    """
    Reproduces the real Napier/Perennial shape: VulnerableVault's
    convertToShares() divides by totalAssets(), which is a raw
    asset.balanceOf(address(this)) read with no virtual offset and no
    internal accounting. Must fire SHARE_INFLATION (CONFIRMED).
    """
    nodes, *_ = _build("ShareInflation.sol")
    fn = nodes["VulnerableVault.deposit(uint256,address)"]
    assert fn.unsafe_share_price_divisor is not None, "expected unsafe divisor evidence"
    print("test_unprotected_balance_derived_divisor_detected: PASS —",
          "evidence:", fn.unsafe_share_price_divisor)


def test_virtual_offset_protection_suppresses_finding():
    """
    Reproduces the real OpenZeppelin v4.9+/v5 shape: same raw
    balanceOf(this)-derived totalAssets, but the ratio includes a real
    additive virtual-offset term on the divisor (`totalAssets() + 1`).
    Must NOT flag as unsafe.
    """
    nodes, *_ = _build("ShareInflation.sol")
    fn = nodes["ProtectedVaultVirtualOffset.deposit(uint256,address)"]
    assert fn.unsafe_share_price_divisor is None, f"virtual-offset-protected vault must not flag, got {fn.unsafe_share_price_divisor}"
    print("test_virtual_offset_protection_suppresses_finding: PASS")


def test_internal_accounting_suppresses_finding():
    """
    Reproduces the real Aave/Compound-style shape: totalAssets is
    tracked via the vault's own internal ledger, never a raw balanceOf
    read — a direct token donation is invisible to the ratio
    regardless of any offset. Must NOT flag as unsafe.
    """
    nodes, *_ = _build("ShareInflation.sol")
    fn = nodes["ProtectedVaultInternalAccounting.deposit(uint256,address)"]
    assert fn.unsafe_share_price_divisor is None, f"internally-tracked vault must not flag, got {fn.unsafe_share_price_divisor}"
    print("test_internal_accounting_suppresses_finding: PASS")


def test_name_decoy_does_not_false_positive():
    """
    Proves this isn't just a different set of magic names that happens
    to work on the obvious cases: NameDecoyOnly's functions/variables
    are named totalAssets/convertToShares/previewDeposit/
    virtualOffset/decimalsOffset/donate — every keyword the OLD
    name-matching heuristic grepped for — but none of it actually
    computes a balanceOf(this)-derived ratio. Must NOT flag.
    """
    nodes, *_ = _build("ShareInflation.sol")
    fn = nodes["NameDecoyOnly.deposit(uint256,address)"]
    assert fn.unsafe_share_price_divisor is None, f"name-decoy-only contract must not flag, got {fn.unsafe_share_price_divisor}"
    print("test_name_decoy_does_not_false_positive: PASS")


def test_unrelated_balance_of_read_does_not_false_positive():
    """
    Proves the fix doesn't flag every balanceOf(this) read on sight —
    BalanceOfUnrelatedUse reads it only for an unrelated informational
    getter (currentReserves()); its actual convertToShares() divides
    by a fixed, constructor-set price, never balanceOf(this)-derived
    at all. Must NOT flag.
    """
    nodes, *_ = _build("ShareInflation.sol")
    fn = nodes["BalanceOfUnrelatedUse.deposit(uint256,address)"]
    assert fn.unsafe_share_price_divisor is None, f"unrelated balanceOf(this) read must not flag, got {fn.unsafe_share_price_divisor}"
    print("test_unrelated_balance_of_read_does_not_false_positive: PASS")


def test_share_inflation_constraint_fires_only_on_real_vulnerable_vault():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual SHARE_INFLATION finding fires CONFIRMED on
    VulnerableVault.deposit() and does not fire on any of the four
    protected/decoy contracts.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ShareInflation.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    vulnerable_findings = [
        r for r in report.confirmed
        if "SHARE_INFLATION" in r.constraint_type and r.path.entry == "VulnerableVault.deposit(uint256,address)"
    ]
    assert vulnerable_findings, "VulnerableVault.deposit() must fire SHARE_INFLATION CONFIRMED"

    for safe_entry in (
        "ProtectedVaultVirtualOffset.deposit(uint256,address)",
        "ProtectedVaultInternalAccounting.deposit(uint256,address)",
        "NameDecoyOnly.deposit(uint256,address)",
        "BalanceOfUnrelatedUse.deposit(uint256,address)",
    ):
        safe_findings = [
            r for r in all_results
            if "SHARE_INFLATION" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire SHARE_INFLATION, got {safe_findings}"

    print("test_share_inflation_constraint_fires_only_on_real_vulnerable_vault: PASS —",
          "VulnerableVault CONFIRMED, all four safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_unprotected_balance_derived_divisor_detected()
    test_virtual_offset_protection_suppresses_finding()
    test_internal_accounting_suppresses_finding()
    test_name_decoy_does_not_false_positive()
    test_unrelated_balance_of_read_does_not_false_positive()
    test_share_inflation_constraint_fires_only_on_real_vulnerable_vault()
    print("\nAll vault_detection tests passed.")
