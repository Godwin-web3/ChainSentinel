"""
Regression test for core/cross_market.py against fixture/cross_market/,
a synthetic reproduction of the Cream Finance ($18.8M, Aug 2021) /
dForce ($25M, 2020) / Rari Fuse ($80M, 2022) vulnerability shape:
a CEI violation in one market, exploited by reentering a DIFFERENT
market that reads the first market's stale state through a shared hub.

Two assertions:
  1. The vulnerable variant (MarketA writes state AFTER its external
     call) produces exactly the expected finding, with the real traced
     path through the hub.
  2. A CEI-safe variant (MarketA writes state BEFORE its external call)
     produces zero findings — the check must not fire when the actual
     vulnerability condition (a genuine post-callback write) is absent.
"""
import os
import shutil
import tempfile

from core.graph import build_graph
from core.cross_market import check_cross_market_reentrancy

FIXTURE_DIR = os.path.abspath("fixture/cross_market")


def _build(project_root, entry_file):
    nodes, graph_edges, *_ = build_graph(
        project_root=project_root,
        entry_file=entry_file,
        solc_version="0.8.19",
        enrichment={},
    )
    return nodes, graph_edges


def test_vulnerable():
    nodes, graph_edges = _build(FIXTURE_DIR, os.path.join(FIXTURE_DIR, "_wrapper.sol"))
    findings = check_cross_market_reentrancy(nodes, graph_edges)
    assert len(findings) == 1, f"expected exactly 1 finding, got {len(findings)}"
    f = findings[0]
    assert f.vulnerable_entry == "MarketA.borrow(uint256)"
    assert f.reentry_entry == "MarketB.borrow(uint256)"
    assert f.shared_read_path == [
        "MarketB.borrow(uint256)", "Hub.totalBorrowed(address)", "MarketA.accountBorrowsOf(address)",
    ]
    assert ("MarketA", "accountBorrows", ()) in f.at_risk_keys
    print("test_vulnerable: PASS —", f.vulnerable_entry, "->", f.reentry_entry, "via", " -> ".join(f.shared_read_path))


def test_cei_safe():
    tmpdir = tempfile.mkdtemp(prefix="cross_market_safe_")
    try:
        for fname in os.listdir(FIXTURE_DIR):
            shutil.copy(os.path.join(FIXTURE_DIR, fname), os.path.join(tmpdir, fname))
        market_a_path = os.path.join(tmpdir, "MarketA.sol")
        with open(market_a_path) as fh:
            src = fh.read()
        # Swap the write/external-call order — CEI now respected.
        vulnerable_body = "        underlying.transfer(msg.sender, amount);\n        accountBorrows[msg.sender] += amount;\n"
        safe_body = "        accountBorrows[msg.sender] += amount;\n        underlying.transfer(msg.sender, amount);\n"
        assert vulnerable_body in src, "fixture body changed — update this test's string swap"
        with open(market_a_path, "w") as fh:
            fh.write(src.replace(vulnerable_body, safe_body))

        nodes, graph_edges = _build(tmpdir, os.path.join(tmpdir, "_wrapper.sol"))
        assert nodes["MarketA.borrow(uint256)"].state_writes_after_callback == [], \
            "CEI-safe MarketA should have no post-callback writes"
        findings = check_cross_market_reentrancy(nodes, graph_edges)
        assert len(findings) == 0, f"expected 0 findings on CEI-safe variant, got {len(findings)}"
        print("test_cei_safe: PASS — 0 findings when CEI is respected")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    test_vulnerable()
    test_cei_safe()
    print("\nAll cross_market tests passed.")
