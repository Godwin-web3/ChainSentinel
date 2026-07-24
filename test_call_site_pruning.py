"""
Regression test for the real ASSET_DRAIN false positive found live this
session against Flaunch's real, currently-deployed PositionManager
(Base): a shared library function branches on whether its own `payer`
parameter equals `address(this)`, and every real call site passes that
literal argument — making the `transferFrom` branch dead code — but the
old flat, branch-unaware edge extraction (core/edges.py::extract_edges)
had no notion of which specific argument a call site passed, so it
reported the dead branch as a live 99%-confidence "direct theft of user
funds" sink.

See fixture/call_site_pruning/CallSitePruning.sol for the exact shape.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/call_site_pruning")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_call_site_argument_prunes_dead_branch_without_weakening_reachable_one():
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("CallSitePruning.sol")

    # Direct edge-level check: the library's own edges must carry the
    # correct gate requirements regardless of caller.
    settle_edges = graph_edges.get("Settler.settle(IERC20,address,address,uint256)", [])
    transfer_from_edges = [e for e in settle_edges if "transferFrom" in e.dst]
    transfer_edges = [e for e in settle_edges if e.dst.endswith(".transfer") or ".transfer" in e.dst and "transferFrom" not in e.dst]
    assert transfer_from_edges and transfer_from_edges[0].param_gate_requirements == (("payer", False),), (
        f"transferFrom must be gated on payer != self, got {transfer_from_edges}"
    )
    assert transfer_edges and transfer_edges[0].param_gate_requirements == (("payer", True),), (
        f"transfer must be gated on payer == self, got {transfer_edges}"
    )

    # The safe call site must prove payer was bound to self.
    safe_call_edges = graph_edges.get("SafeSettler.settleOwnFunds(uint256)", [])
    settle_call = [e for e in safe_call_edges if e.dst.startswith("Settler.settle")]
    assert settle_call and settle_call[0].self_bound_params == frozenset({"payer"}), (
        f"settleOwnFunds() passes address(this) literally for payer — must be proven self-bound, got {settle_call}"
    )

    # The unsafe call site must NOT prove any self-binding (payer is a
    # genuine, caller-supplied parameter).
    unsafe_call_edges = graph_edges.get("UnsafeSettler.settleArbitraryFunds(address,uint256)", [])
    unsafe_settle_call = [e for e in unsafe_call_edges if e.dst.startswith("Settler.settle")]
    assert unsafe_settle_call and unsafe_settle_call[0].self_bound_params == frozenset(), (
        f"settleArbitraryFunds()'s payer is caller-controlled — must NOT be proven self-bound, got {unsafe_settle_call}"
    )

    # Full-pipeline check: the dead transferFrom branch must not surface
    # as a finding from the safe entry point, but the genuinely reachable
    # one (from the unsafe entry point, where payer is NOT proven self)
    # must still fire — same standard as every other suppression fix
    # this session: prove the fix doesn't blanket-suppress the sink.
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    safe_transfer_from_findings = [
        r for r in all_results
        if r.path.entry == "SafeSettler.settleOwnFunds(uint256)" and "transferFrom" in r.path.sink.node_id
    ]
    assert not safe_transfer_from_findings, (
        f"settleOwnFunds() always passes payer=address(this) — the transferFrom branch is dead code, must not fire, got {safe_transfer_from_findings}"
    )

    unsafe_transfer_from_findings = [
        r for r in all_results
        if r.path.entry == "UnsafeSettler.settleArbitraryFunds(address,uint256)" and "transferFrom" in r.path.sink.node_id
    ]
    assert unsafe_transfer_from_findings, (
        "settleArbitraryFunds()'s payer is genuinely caller-controlled — the transferFrom branch IS reachable, must still fire"
    )
    print(
        "test_call_site_argument_prunes_dead_branch_without_weakening_reachable_one: PASS — "
        "settleOwnFunds() transferFrom pruned, settleArbitraryFunds() transferFrom still",
        unsafe_transfer_from_findings[0].verdict,
    )


if __name__ == "__main__":
    test_call_site_argument_prunes_dead_branch_without_weakening_reachable_one()
    print("\nAll call_site_pruning tests passed.")
