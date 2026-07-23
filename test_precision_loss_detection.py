"""
Regression tests for core/precision_loss_detection.py — structural
divide-before-multiply precision-loss detection.

Real precedent for the vulnerable shape: Code4rena's real
2022-05-cally-findings#280 — Cally.sol's real getDutchAuctionStrike():
each line individually LOOKS like the safe "multiply, then divide"
shape, but the first line's division result gets reused in a SECOND
multiplication, compounding truncation error into the option's strike
price. A naive "does / appear before * in the same expression"
heuristic would MISS this real bug — both lines are locally
mul-before-div. Real precedent for the protected shapes: the real
Cally fix and Solmate's actual FixedPointMathLib.mulDivDown, confirmed
live via IR probe against both real reference sources.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/precision_loss_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_division_result_reused_in_multiplication_detected():
    """
    Reproduces the real Cally getDutchAuctionStrike() shape: a
    division's truncated result is reused in a later multiplication
    feeding accounting state. Must fire evidence.
    """
    nodes, *_ = _build("DivideBeforeMultiply.sol")
    fn = nodes["VulnerableAuction.exercise(uint256,uint256,uint256)"]
    assert fn.unsafe_divide_before_multiply is not None, "expected divide-before-multiply evidence"
    print("test_division_result_reused_in_multiplication_detected: PASS —",
          "evidence:", fn.unsafe_divide_before_multiply)


def test_reordered_single_division_suppresses_finding():
    """
    The real recommended fix — eliminate the intermediate division,
    multiply everything first, divide once at the very end. Must NOT
    flag.
    """
    nodes, *_ = _build("DivideBeforeMultiply.sol")
    fn = nodes["ProtectedAuction.exercise(uint256,uint256,uint256)"]
    assert fn.unsafe_divide_before_multiply is None, f"reordered single-division computation must not flag, got {fn.unsafe_divide_before_multiply}"
    print("test_reordered_single_division_suppresses_finding: PASS")


def test_muldiv_library_call_suppresses_finding():
    """
    The real Solmate FixedPointMathLib.mulDivDown fused pattern — its
    internal division lives inside an assembly block and never
    produces a visible Binary DIVISION op at the caller's level. Must
    NOT flag.
    """
    nodes, *_ = _build("DivideBeforeMultiply.sol")
    fn = nodes["ProtectedMulDivLibrary.exercise(uint256,uint256,uint256)"]
    assert fn.unsafe_divide_before_multiply is None, f"mulDiv-library-protected computation must not flag, got {fn.unsafe_divide_before_multiply}"
    print("test_muldiv_library_call_suppresses_finding: PASS")


def test_unrelated_division_and_multiplication_do_not_false_positive():
    """
    Critical adversarial regression: an unrelated division and an
    unrelated multiplication both exist in the same function, but the
    division's own result never flows into the multiplication at all.
    Proves the detector requires the actual dataflow link, not mere
    co-occurrence. Must NOT flag.
    """
    nodes, *_ = _build("DivideBeforeMultiply.sol")
    fn = nodes["UnrelatedDivisionAndMultiplicationDoNotFalsePositive.exercise(uint256,uint256,uint256)"]
    assert fn.unsafe_divide_before_multiply is None, f"unrelated division/multiplication must not flag, got {fn.unsafe_divide_before_multiply}"
    print("test_unrelated_division_and_multiplication_do_not_false_positive: PASS")


def test_name_decoy_does_not_false_positive():
    """
    Proves this isn't just a different set of magic names that happens
    to work on the obvious cases: NameDecoyOnly's names are
    sharePrice/strikeValue — every keyword a name-matching heuristic
    would grep for — but it never performs a division whose result
    later feeds a multiplication at all. Must NOT flag.
    """
    nodes, *_ = _build("DivideBeforeMultiply.sol")
    fn = nodes["NameDecoyOnly.exercise(uint256)"]
    assert fn.unsafe_divide_before_multiply is None, f"name-decoy-only contract must not flag, got {fn.unsafe_divide_before_multiply}"
    print("test_name_decoy_does_not_false_positive: PASS")


def test_precision_loss_constraint_fires_only_on_real_vulnerable_contracts():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual DIVIDE_BEFORE_MULTIPLY finding fires CONFIRMED on the
    genuinely vulnerable contract and does not fire on any of the four
    protected/decoy contracts.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("DivideBeforeMultiply.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    vulnerable_findings = [
        r for r in report.confirmed
        if "DIVIDE_BEFORE_MULTIPLY" in r.constraint_type and r.path.entry == "VulnerableAuction.exercise(uint256,uint256,uint256)"
    ]
    assert vulnerable_findings, "VulnerableAuction.exercise() must fire DIVIDE_BEFORE_MULTIPLY CONFIRMED"

    for safe_entry in (
        "ProtectedAuction.exercise(uint256,uint256,uint256)",
        "ProtectedMulDivLibrary.exercise(uint256,uint256,uint256)",
        "UnrelatedDivisionAndMultiplicationDoNotFalsePositive.exercise(uint256,uint256,uint256)",
        "NameDecoyOnly.exercise(uint256)",
    ):
        safe_findings = [
            r for r in all_results
            if "DIVIDE_BEFORE_MULTIPLY" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire DIVIDE_BEFORE_MULTIPLY, got {safe_findings}"

    print("test_precision_loss_constraint_fires_only_on_real_vulnerable_contracts: PASS —",
          "VulnerableAuction CONFIRMED, all four safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_division_result_reused_in_multiplication_detected()
    test_reordered_single_division_suppresses_finding()
    test_muldiv_library_call_suppresses_finding()
    test_unrelated_division_and_multiplication_do_not_false_positive()
    test_name_decoy_does_not_false_positive()
    test_precision_loss_constraint_fires_only_on_real_vulnerable_contracts()
    print("\nAll precision_loss_detection tests passed.")
