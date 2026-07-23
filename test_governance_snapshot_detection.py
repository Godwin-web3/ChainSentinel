"""
Regression tests for core/governance_snapshot_detection.py —
structural flash-loan governance-voting-power detection.

Real precedent for the vulnerable shape: Beanstalk Farms' real $182M
loss (April 17 2022) — the actual GovernanceFacet.sol's
emergencyCommit() executed a proposal via a delegatecall-based diamond
cut once LIVE voting power cleared a supermajority threshold, with no
delay between voting and execution. The attacker flash-loaned over
$1B, deposited it to mint stalk, instantly cleared the threshold, and
executed a malicious diamond cut that drained the protocol — all
within one transaction. Real precedent for the protected shape:
Compound's actual, widely-deployed Governor Bravo (getPriorVotes(voter,
proposal.startBlock)) and OpenZeppelin's own Governor.sol
(getVotes(account, proposalSnapshot(id))), confirmed live via IR probe
against both real reference sources.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/governance_snapshot_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_live_voting_power_execution_detected():
    """
    Reproduces the real Beanstalk emergencyCommit() shape: live voting
    power (a plain mapping, no historical dimension) checked against a
    supermajority threshold, then immediately delegatecall-executes.
    Must fire evidence.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["VulnerableGovernance.emergencyCommit(address,bytes)"]
    assert fn.unsafe_live_voting_power_execution is not None, "expected unsafe live-voting-power evidence"
    print("test_live_voting_power_execution_detected: PASS —",
          "evidence:", fn.unsafe_live_voting_power_execution)


def test_compound_bravo_style_checkpoint_suppresses_finding():
    """
    Reproduces the real Compound Governor Bravo shape: voting power
    read via getPriorVotes(voter, proposal.startBlock), where
    startBlock was captured and stored at proposal-creation time — an
    earlier transaction. Must NOT flag.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["ProtectedGovernanceBravoStyle.execute(uint256)"]
    assert fn.unsafe_live_voting_power_execution is None, f"checkpoint-protected execution must not flag, got {fn.unsafe_live_voting_power_execution}"
    print("test_compound_bravo_style_checkpoint_suppresses_finding: PASS")


def test_previous_block_style_suppresses_finding():
    """
    The real "one block ago" pattern — block.number - 1, computed
    fresh inline but still referencing the PREVIOUS block, which a
    same-block flash loan cannot retroactively alter. Must NOT flag.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["ProtectedPreviousBlockStyle.execute(address,bytes)"]
    assert fn.unsafe_live_voting_power_execution is None, f"previous-block-protected execution must not flag, got {fn.unsafe_live_voting_power_execution}"
    print("test_previous_block_style_suppresses_finding: PASS")


def test_fake_checkpoint_current_block_does_not_suppress_real_finding():
    """
    Critical adversarial regression: a 2-argument accessor IS used (so
    it LOOKS checkpoint-shaped at a glance), but the timepoint argument
    is the raw, unmodified CURRENT block.number — querying "right now"
    provides zero protection against a same-block flash loan. Proves
    the detector checks the actual timepoint VALUE, not just whether a
    2-arg accessor exists. Must still fire.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["FakeCheckpointCurrentBlockStyle.execute(address,bytes)"]
    assert fn.unsafe_live_voting_power_execution is not None, "querying the raw current block must not suppress the real finding"
    print("test_fake_checkpoint_current_block_does_not_suppress_real_finding: PASS —",
          "evidence:", fn.unsafe_live_voting_power_execution)


def test_name_decoy_does_not_false_positive():
    """
    Proves this isn't just a different set of magic names that happens
    to work on the obvious cases: NameDecoyOnly's names are
    votingPower/quorum/execute — every keyword a name-matching
    heuristic would grep for — but neither function actually combines
    a live-voting-power revert-capable gate with an execution call.
    Must NOT flag.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["NameDecoyOnly.execute()"]
    assert fn.unsafe_live_voting_power_execution is None, f"name-decoy-only contract must not flag, got {fn.unsafe_live_voting_power_execution}"
    print("test_name_decoy_does_not_false_positive: PASS")


def test_vote_recording_without_execution_does_not_false_positive():
    """
    Proves the fix doesn't flag every live voting-power check on
    sight — VoteRecordingOnlyDoesNotFalsePositive has a genuinely LIVE,
    revert-capable voting-power comparison, but the consequence is only
    a state write (recording a vote), never an arbitrary external/low-
    level call. Must NOT flag.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["VoteRecordingOnlyDoesNotFalsePositive.castVote(uint256)"]
    assert fn.unsafe_live_voting_power_execution is None, f"check-without-execution must not flag, got {fn.unsafe_live_voting_power_execution}"
    print("test_vote_recording_without_execution_does_not_false_positive: PASS")


def test_compound_bravo_real_cancel_shape_does_not_false_positive():
    """
    Live-verification regression: found firing on Compound's actual,
    currently-deployed GovernorBravoDelegate.sol's real cancel()
    function. Two distinct real-world idioms combine: (1)
    sub256(block.number, 1) — the extremely common pre-Solidity-0.8
    SafeMath-style subtraction-wrapper idiom, equivalent to the raw
    `block.number - 1` this module already recognized, and (2) a
    HighLevelCall (through a KNOWN, resolved interface) to a fixed,
    governance-set state variable (timelock.cancelTransaction) — not
    an arbitrary delegatecall to caller-supplied data. Both gaps are
    now fixed. Must NOT flag.
    """
    nodes, *_ = _build("FlashLoanGovernance.sol")
    fn = nodes["CompoundBravoStyleCancel.cancel()"]
    assert fn.unsafe_live_voting_power_execution is None, f"real Compound Bravo cancel() shape must not flag, got {fn.unsafe_live_voting_power_execution}"
    print("test_compound_bravo_real_cancel_shape_does_not_false_positive: PASS")


def test_governance_snapshot_constraint_fires_only_on_real_vulnerable_contracts():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual FLASHLOAN_GOVERNANCE finding fires CONFIRMED on both
    genuinely vulnerable contracts and does not fire on any of the four
    protected/decoy contracts.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("FlashLoanGovernance.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for vulnerable_entry in (
        "VulnerableGovernance.emergencyCommit(address,bytes)",
        "FakeCheckpointCurrentBlockStyle.execute(address,bytes)",
    ):
        vulnerable_findings = [
            r for r in report.confirmed
            if "FLASHLOAN_GOVERNANCE" in r.constraint_type and r.path.entry == vulnerable_entry
        ]
        assert vulnerable_findings, f"{vulnerable_entry} must fire FLASHLOAN_GOVERNANCE CONFIRMED"

    for safe_entry in (
        "ProtectedGovernanceBravoStyle.execute(uint256)",
        "ProtectedPreviousBlockStyle.execute(address,bytes)",
        "NameDecoyOnly.execute()",
        "VoteRecordingOnlyDoesNotFalsePositive.castVote(uint256)",
        "CompoundBravoStyleCancel.cancel()",
    ):
        safe_findings = [
            r for r in all_results
            if "FLASHLOAN_GOVERNANCE" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire FLASHLOAN_GOVERNANCE, got {safe_findings}"

    print("test_governance_snapshot_constraint_fires_only_on_real_vulnerable_contracts: PASS —",
          "both vulnerable entries CONFIRMED, all five safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_live_voting_power_execution_detected()
    test_compound_bravo_style_checkpoint_suppresses_finding()
    test_previous_block_style_suppresses_finding()
    test_fake_checkpoint_current_block_does_not_suppress_real_finding()
    test_name_decoy_does_not_false_positive()
    test_vote_recording_without_execution_does_not_false_positive()
    test_compound_bravo_real_cancel_shape_does_not_false_positive()
    test_governance_snapshot_constraint_fires_only_on_real_vulnerable_contracts()
    print("\nAll governance_snapshot_detection tests passed.")
