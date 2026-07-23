"""
Regression tests for core/staleness_detection.py — structural Chainlink
price-feed staleness-check detection.

One of the single most common high-severity findings in real
Code4rena/Sherlock audits: a function calls Chainlink's
AggregatorV3Interface.latestRoundData() and consumes the returned
price without ever verifying the feed is fresh.

Real precedent for the vulnerable shape: code-423n4/2024-07-loopfi-
findings#494/#521 (AuraVault.sol's real _chainlinkSpot() — updatedAt
destructured with a blank comma, never bound to any variable), and
Cryptex Finance's actual deployed ChainlinkOracle.sol
(cryptexfinance/contracts) — a subtler real case that checks round
completeness/staleness but never elapsed real time. Real precedent for
the protected shape: ButtonWood Protocol's actual deployed
ChainlinkOracle.sol (buttonwood-protocol/button-wrappers), confirmed
live via IR probe against the real reference source.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/staleness_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_discarded_updated_at_detected():
    """
    Reproduces the real LoopFi AuraVault.sol shape: updatedAt is
    destructured with a blank comma inside a private helper, never
    bound to any variable, and never freshness-checked. Must fire
    evidence.
    """
    nodes, *_ = _build("StaleOracle.sol")
    fn = nodes["LoopFiStyleVault.updateCollateralValue(address,uint256)"]
    assert fn.unstaled_latest_round_data_dependency is not None, "expected unstaled latestRoundData() evidence"
    print("test_discarded_updated_at_detected: PASS —",
          "evidence:", fn.unstaled_latest_round_data_dependency)


def test_round_completeness_only_detected():
    """
    Reproduces the real Cryptex Finance ChainlinkOracle.sol shape:
    checks timeStamp != 0 and answeredInRound >= roundID, but never a
    genuine elapsed-time freshness check. A real, deployed,
    "seemingly careful" shape that is still genuinely vulnerable to
    staleness. Must fire evidence.
    """
    nodes, *_ = _build("StaleOracle.sol")
    fn = nodes["CryptexStyleOracle.updateCollateralValue(address,uint256)"]
    assert fn.unstaled_latest_round_data_dependency is not None, "expected round-completeness-only shape to still flag"
    print("test_round_completeness_only_detected: PASS —",
          "evidence:", fn.unstaled_latest_round_data_dependency)


def test_propagated_return_check_suppresses_finding():
    """
    Reproduces the real ButtonWood Protocol ChainlinkOracle.sol shape:
    a genuine elapsed-time check, never reverting inline but
    PROPAGATED as a return-value bool for the caller to act on. Must
    NOT flag.
    """
    nodes, *_ = _build("StaleOracle.sol")
    fn = nodes["ButtonWoodStyleOracle.updateCollateralValue(address,uint256)"]
    assert fn.unstaled_latest_round_data_dependency is None, f"propagated-return-checked feed must not flag, got {fn.unstaled_latest_round_data_dependency}"
    print("test_propagated_return_check_suppresses_finding: PASS")


def test_require_style_check_suppresses_finding():
    """
    The common textbook require(updatedAt >= block.timestamp -
    MAX_DELAY) single-step staleness check. Must NOT flag.
    """
    nodes, *_ = _build("StaleOracle.sol")
    fn = nodes["RequireStyleOracle.updateCollateralValue(address,uint256)"]
    assert fn.unstaled_latest_round_data_dependency is None, f"require()-checked feed must not flag, got {fn.unstaled_latest_round_data_dependency}"
    print("test_require_style_check_suppresses_finding: PASS")


def test_name_decoy_does_not_false_positive():
    """
    Proves this isn't just a different set of magic names that happens
    to work on the obvious cases: NameDecoyOnly's names are oracle/
    stale/updatedAt/freshness — every keyword an old name-matching
    heuristic would grep for — but it never actually calls
    latestRoundData() at all. Must NOT flag.
    """
    nodes, *_ = _build("StaleOracle.sol")
    fn = nodes["NameDecoyOnly.updateCollateralValue(address,uint256)"]
    assert fn.unstaled_latest_round_data_dependency is None, f"name-decoy-only contract must not flag, got {fn.unstaled_latest_round_data_dependency}"
    print("test_name_decoy_does_not_false_positive: PASS")


def test_informational_use_does_not_false_positive():
    """
    Proves the fix doesn't flag every unstaled latestRoundData() call
    on sight — InformationalPriceDecoy has the identical unsafe shape
    as LoopFiStyleVault, but the answer only ever feeds a purely
    informational state variable, never collateral/debt/borrow/
    liquidation/health/price/value-shaped state. Must NOT flag.
    """
    nodes, *_ = _build("StaleOracle.sol")
    fn = nodes["InformationalPriceDecoy.observeFeed()"]
    assert fn.unstaled_latest_round_data_dependency is None, f"informational-only use must not flag, got {fn.unstaled_latest_round_data_dependency}"
    print("test_informational_use_does_not_false_positive: PASS")


def test_stale_oracle_constraint_fires_only_on_real_vulnerable_contracts():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual STALE_ORACLE_DEPENDENCY finding fires CONFIRMED on both
    genuinely vulnerable contracts and does not fire on any of the four
    protected/decoy contracts.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("StaleOracle.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for vulnerable_entry in (
        "LoopFiStyleVault.updateCollateralValue(address,uint256)",
        "CryptexStyleOracle.updateCollateralValue(address,uint256)",
    ):
        vulnerable_findings = [
            r for r in report.confirmed
            if "STALE_ORACLE" in r.constraint_type and r.path.entry == vulnerable_entry
        ]
        assert vulnerable_findings, f"{vulnerable_entry} must fire STALE_ORACLE_DEPENDENCY CONFIRMED"

    for safe_entry in (
        "ButtonWoodStyleOracle.updateCollateralValue(address,uint256)",
        "RequireStyleOracle.updateCollateralValue(address,uint256)",
        "NameDecoyOnly.updateCollateralValue(address,uint256)",
        "InformationalPriceDecoy.observeFeed()",
    ):
        safe_findings = [
            r for r in all_results
            if "STALE_ORACLE" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire STALE_ORACLE_DEPENDENCY, got {safe_findings}"

    print("test_stale_oracle_constraint_fires_only_on_real_vulnerable_contracts: PASS —",
          "both vulnerable contracts CONFIRMED, all four safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_discarded_updated_at_detected()
    test_round_completeness_only_detected()
    test_propagated_return_check_suppresses_finding()
    test_require_style_check_suppresses_finding()
    test_name_decoy_does_not_false_positive()
    test_informational_use_does_not_false_positive()
    test_stale_oracle_constraint_fires_only_on_real_vulnerable_contracts()
    print("\nAll staleness_detection tests passed.")
