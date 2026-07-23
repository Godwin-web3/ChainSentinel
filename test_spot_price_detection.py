"""
Regression tests for core/spot_price_detection.py — structural AMM
spot-price-oracle-manipulation detection.

Replaces core/constraints.py's old _check_oracle_dependency, which
grepped CallEdge.function_name strings for substrings like "oracle",
"pricefeed", "twap", "getreserves" — unable to verify the value was
ever used in a price computation at all, unable to distinguish a raw
single-block spot read from a fully time-weighted average that happens
to also call getReserves() somewhere upstream.

Real precedent for the vulnerable shape: Harvest Finance's real $24M
loss (Oct 2020, priced vault shares from a live Curve pool reserve
ratio with no time-weighting), Warp Finance's real $8M loss (Dec 2020,
confirmed live via cmichel.io's writeup of the actual exploit — the
factory read raw getReserves() and passed the RAW reserve AMOUNT as an
ARGUMENT into a separate oracle contract's own consult(), which
internally multiplied a real TWAP-protected average price by that
unprotected amount; neither contract's own body looked unsafe in
isolation). Real precedent for the protected shape: Uniswap's own real
v2-periphery ExampleOracleSimple.sol, confirmed live via IR probe
against the actual reference source.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/spot_price_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_raw_reserves_derived_collateral_detected():
    """
    Reproduces the real Warp Finance shape: VulnerableLendingPool.borrow()
    computes collateralValue directly from getReserves(), a raw
    single-block spot read, with no elapsed-time dilution anywhere.
    Must fire evidence.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["VulnerableLendingPool.borrow(uint256)"]
    assert fn.unsafe_spot_price_dependency is not None, "expected unsafe spot-price evidence"
    print("test_raw_reserves_derived_collateral_detected: PASS —",
          "evidence:", fn.unsafe_spot_price_dependency)


def test_cached_twap_average_suppresses_finding():
    """
    Reproduces the real Uniswap V2 ExampleOracleSimple.sol shape:
    borrow() only ever reads a cached price0Average maintained
    elsewhere via a genuine elapsed-time division — it never calls
    getReserves() itself. Must NOT flag as unsafe.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["ProtectedLendingPoolTWAP.borrow(uint256)"]
    assert fn.unsafe_spot_price_dependency is None, f"cached-TWAP-derived vault must not flag, got {fn.unsafe_spot_price_dependency}"
    print("test_cached_twap_average_suppresses_finding: PASS")


def test_inline_elapsed_time_division_suppresses_finding():
    """
    getReserves() IS read directly inside the same function that
    writes collateralValue, but the SPECIFIC raw-reserve-derived value
    is itself divided by a real elapsed-time value before it reaches
    collateralValue. This is the case that actually exercises the
    forward-taint suppression path (not just co-occurrence). Must NOT
    flag as unsafe.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["ProtectedInlineElapsedDivision.borrow(uint256)"]
    assert fn.unsafe_spot_price_dependency is None, f"inline-elapsed-time-diluted price must not flag, got {fn.unsafe_spot_price_dependency}"
    print("test_inline_elapsed_time_division_suppresses_finding: PASS")


def test_unrelated_elapsed_time_division_does_not_suppress_real_finding():
    """
    Regression for the exact false-suppression risk this detector was
    tightened against: a genuinely unsafe direct-reserve collateral
    computation coexists in the SAME function with an entirely
    UNRELATED elapsed-time division (a staking cooldown multiplier
    applied to rewardBoost, not collateralValue). A blanket "any
    elapsed-time division anywhere in scope" check would wrongly
    suppress this. Must still fire evidence.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["VulnerableWithUnrelatedElapsedDivision.borrow(uint256)"]
    assert fn.unsafe_spot_price_dependency is not None, "unrelated elapsed-time division must not suppress the real finding"
    print("test_unrelated_elapsed_time_division_does_not_suppress_real_finding: PASS —",
          "evidence:", fn.unsafe_spot_price_dependency)


def test_name_decoy_does_not_false_positive():
    """
    Proves this isn't just a different set of magic names that happens
    to work on the obvious cases: NameDecoyOnly's function/variable
    names are oracle/priceFeed/twap/consult — every keyword the OLD
    name-matching heuristic grepped for — but none of it actually
    reads a real getReserves()/slot0() accessor. Must NOT flag.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["NameDecoyOnly.borrow(uint256)"]
    assert fn.unsafe_spot_price_dependency is None, f"name-decoy-only contract must not flag, got {fn.unsafe_spot_price_dependency}"
    print("test_name_decoy_does_not_false_positive: PASS")


def test_unrelated_reserves_read_does_not_false_positive():
    """
    Proves the fix doesn't flag every getReserves() read on sight —
    ReservesUnrelatedUse reads it only for an unrelated informational
    getter (poolDepth()); its actual borrow() divides by a fixed,
    constructor-set price, never getReserves()-derived at all. Must
    NOT flag.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["ReservesUnrelatedUse.borrow(uint256)"]
    assert fn.unsafe_spot_price_dependency is None, f"unrelated getReserves() read must not flag, got {fn.unsafe_spot_price_dependency}"
    print("test_unrelated_reserves_read_does_not_false_positive: PASS")


def test_cross_contract_warp_finance_shape_detected():
    """
    Faithful minimal reproduction of the real Warp Finance exploit
    (confirmed live via cmichel.io's writeup of the actual $8M Dec 2020
    loss): WarpStyleLPOracleFactory.borrow() reads raw getReserves()
    and passes the RAW reserve amount as an ARGUMENT into a separate
    WarpStyleTWAPOracle.consult(), which internally multiplies a real
    TWAP-protected average price by that unprotected amount. Neither
    contract's own function body looks unsafe in isolation — this only
    fires if evidence-tracing follows the parameter binding across the
    HighLevelCall boundary. Must fire evidence.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["WarpStyleLPOracleFactory.borrow(address)"]
    assert fn.unsafe_spot_price_dependency is not None, "expected cross-contract Warp-Finance-shaped evidence"
    print("test_cross_contract_warp_finance_shape_detected: PASS —",
          "evidence:", fn.unsafe_spot_price_dependency)


def test_cross_contract_fixed_unit_price_does_not_false_positive():
    """
    Safe cross-contract counterpart: SafeCrossContractOracleFactory
    calls consult() with a FIXED unit amount (1e18), never the raw
    reserve itself, and never reads getReserves() at all. Must NOT
    flag.
    """
    nodes, *_ = _build("OracleManipulation.sol")
    fn = nodes["SafeCrossContractOracleFactory.borrow(address,uint256)"]
    assert fn.unsafe_spot_price_dependency is None, f"fixed-unit-price cross-contract call must not flag, got {fn.unsafe_spot_price_dependency}"
    print("test_cross_contract_fixed_unit_price_does_not_false_positive: PASS")


def test_oracle_dependency_constraint_fires_only_on_real_vulnerable_pools():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual ORACLE_DEPENDENCY finding fires CONFIRMED on every
    genuinely vulnerable pool (including the cross-contract Warp
    Finance shape) and does not fire on any of the six protected/decoy
    contracts.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("OracleManipulation.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for vulnerable_entry in (
        "VulnerableLendingPool.borrow(uint256)",
        "VulnerableWithUnrelatedElapsedDivision.borrow(uint256)",
        "WarpStyleLPOracleFactory.borrow(address)",
    ):
        vulnerable_findings = [
            r for r in report.confirmed
            if "ORACLE_DEPENDENCY" in r.constraint_type and r.path.entry == vulnerable_entry
        ]
        assert vulnerable_findings, f"{vulnerable_entry} must fire ORACLE_DEPENDENCY CONFIRMED"

    for safe_entry in (
        "ProtectedLendingPoolTWAP.borrow(uint256)",
        "ProtectedInlineElapsedDivision.borrow(uint256)",
        "NameDecoyOnly.borrow(uint256)",
        "ReservesUnrelatedUse.borrow(uint256)",
        "SafeCrossContractOracleFactory.borrow(address,uint256)",
    ):
        safe_findings = [
            r for r in all_results
            if "ORACLE_DEPENDENCY" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire ORACLE_DEPENDENCY, got {safe_findings}"

    print("test_oracle_dependency_constraint_fires_only_on_real_vulnerable_pools: PASS —",
          "all three vulnerable entries CONFIRMED (including cross-contract Warp shape), "
          "all five safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_raw_reserves_derived_collateral_detected()
    test_cached_twap_average_suppresses_finding()
    test_inline_elapsed_time_division_suppresses_finding()
    test_unrelated_elapsed_time_division_does_not_suppress_real_finding()
    test_name_decoy_does_not_false_positive()
    test_unrelated_reserves_read_does_not_false_positive()
    test_cross_contract_warp_finance_shape_detected()
    test_cross_contract_fixed_unit_price_does_not_false_positive()
    test_oracle_dependency_constraint_fires_only_on_real_vulnerable_pools()
    print("\nAll spot_price_detection tests passed.")
