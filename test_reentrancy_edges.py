"""
Regression tests for three real, structural bugs in core/paths.py and
core/edges.py, found live this session while investigating why Uniswap
V3's swap()/flash() produced zero findings:

  1. core/paths.py::_dfs gated the sink-check to depth > 0, so a
     function that is its OWN sink (state write + external call in the
     same function, no intermediate hop) never registered a path.
  2. core/edges.py::_raw_type_from_ir called .lower() on
     LowLevelCall.function_name (a Slither Constant, not a str),
     raising an AttributeError silently swallowed by extract_edges'
     broad except — dropping EVERY raw low-level call edge in the
     entire codebase, at any depth.
  3. Once (2) was fixed, .staticcall(...) was exposed as misclassified
     into the same semantic bucket as a value-carrying .call(...) —
     flagged as is_value_transfer=True (ASSET_DRAIN) and a reentrancy
     surface (CALLBACK_SINK), both structurally impossible since the
     EVM makes STATICCALL's read-only context transitive.

See fixture/reentrancy_edges/ReentrancyEdgeCases.sol for the exact
shapes and full rationale.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/reentrancy_edges")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_entry_level_cei_violation_detected():
    """
    withdraw() is its own sink (depth 0) — a direct, unguarded low-level
    call with a state write in the same function, no intermediate hop.
    Must produce a real edge for the low-level call and fire
    REENTRANCY_CEI on the entry itself.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    edges = graph_edges.get("ReentrancyEdgeCases.withdraw()", [])
    lowlevel_edges = [e for e in edges if e.raw_type == "lowlevel_call"]
    assert lowlevel_edges, "the low-level .call{value:0}(\"\") must produce a real graph edge"
    assert lowlevel_edges[0].is_external and lowlevel_edges[0].is_value_transfer

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)

    cei_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "ReentrancyEdgeCases.withdraw()" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert cei_findings, "withdraw() is an unguarded, real CEI violation reached at depth 0 — must fire"
    print("test_entry_level_cei_violation_detected: PASS —", cei_findings[0].verdict)


def test_staticcall_not_misclassified_as_asset_drain_or_callback():
    """
    checkBalance() makes a .staticcall(...) with a co-located state
    write — structurally identical in shape to withdraw() above, but a
    staticcall can never transfer value or mutate state (EVM-enforced,
    transitively, for everything reachable from it). Must NOT be
    classified ASSET_DRAIN or CALLBACK_SINK, and must NOT fire
    REENTRANCY_CEI.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    edges = graph_edges.get("ReentrancyEdgeCases.checkBalance()", [])
    static_edges = [e for e in edges if e.raw_type == "staticcall"]
    assert static_edges, "the .staticcall(...) must produce a real graph edge, typed distinctly"
    assert not static_edges[0].is_value_transfer, "a staticcall can never carry value"
    assert not static_edges[0].is_state_crossing, "a staticcall can never write state"

    sinks = classify_sinks(nodes, graph_edges)
    sink = sinks.get("ReentrancyEdgeCases.checkBalance()")
    assert sink is None, f"a staticcall + co-located state write must not classify as any sink, got {sink}"

    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    findings = [
        r for r in (report.confirmed + report.likely + report.possible)
        if r.path.entry == "ReentrancyEdgeCases.checkBalance()"
    ]
    assert not findings, f"staticcall-based read must not produce any finding, got {findings}"
    print("test_staticcall_not_misclassified_as_asset_drain_or_callback: PASS — 0 findings on checkBalance()")


def test_inline_reentrancy_guard_detected_without_weakening():
    """
    Reproduces the real Uniswap V3 swap() shape found live this
    session: an inline reentrancy guard flattened directly into a
    REGULAR function's own body (require(!locked); locked = true; ...;
    locked = false;) instead of expressed as a modifier — the same
    structural signature is_reentrancy_guard() detects around a
    modifier's placeholder, just flattened. withdrawLocked() must be
    suppressed.

    withdrawFakeInline() proves this doesn't weaken detection: a state
    variable written twice around the external call, but never read or
    revert-checked before its first write (not a real guard, just an
    unrelated counter bump) — must NOT be misdetected as guarded;
    REENTRANCY_CEI must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    locked = nodes["ReentrancyEdgeCases.withdrawLocked()"]
    fake = nodes["ReentrancyEdgeCases.withdrawFakeInline()"]
    assert locked.has_inline_reentrancy_guard is True, "withdrawLocked() has the real inline guard shape"
    assert fake.has_inline_reentrancy_guard is False, (
        "withdrawFakeInline()'s counter is never read/revert-checked before its first write — must not false-positive"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)

    locked_findings = [
        r for r in (report.confirmed + report.likely + report.possible)
        if r.path.entry == "ReentrancyEdgeCases.withdrawLocked()" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert not locked_findings, f"withdrawLocked() is protected by its own inline guard — must be suppressed, got {locked_findings}"

    fake_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "ReentrancyEdgeCases.withdrawFakeInline()" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert fake_findings, "withdrawFakeInline() has no real guard — REENTRANCY_CEI must still fire"
    print("test_inline_reentrancy_guard_detected_without_weakening: PASS —",
          "withdrawLocked suppressed, withdrawFakeInline still", fake_findings[0].verdict)


if __name__ == "__main__":
    test_entry_level_cei_violation_detected()
    test_staticcall_not_misclassified_as_asset_drain_or_callback()
    test_inline_reentrancy_guard_detected_without_weakening()
    print("\nAll reentrancy_edges tests passed.")
