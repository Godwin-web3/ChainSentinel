// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/governance_snapshot_detection.py::
// find_unsafe_live_voting_power_execution — detects a governance
// execution path gated by LIVE (un-checkpointed) voting power instead
// of a historical snapshot.
//
// Real precedent for the vulnerable shape: Beanstalk Farms' real $182M
// loss (April 17 2022) — the actual GovernanceFacet.sol's
// emergencyCommit() executed a proposal (_execute -> cutBip ->
// LibDiamond's delegatecall-based diamond cut, confirmed live via the
// real fetched source and Immunefi's technical writeup: "The private
// _execute function uses delegatecall to borrow some logic from a
// given address, and the hacker supplied logic that would transfer
// all funds to the attacker contract") once LIVE voting power
// (bipVotePercent, computed from whatever the Silo currently holds —
// no historical dimension) cleared a supermajority threshold, with no
// delay between voting and execution. The attacker flash-loaned over
// $1B, deposited it to mint stalk, instantly cleared the threshold,
// and executed a malicious diamond cut that drained the protocol —
// all within one transaction, repaying the loan at the end of the
// SAME transaction. Real precedent for the protected shape: Compound's
// actual, widely-deployed Governor Bravo (getPriorVotes(voter,
// proposal.startBlock), where startBlock was captured at proposal-
// creation time — an earlier transaction) and OpenZeppelin's own
// Governor.sol (getVotes(account, proposalSnapshot(id))), confirmed
// live via IR probe against both real reference sources.

interface IComp {
    function getPriorVotes(address account, uint256 blockNumber) external view returns (uint256);
}

// DANGEROUS: faithful minimal reproduction of the real Beanstalk
// GovernanceFacet.emergencyCommit() shape — LIVE voting power (a
// plain mapping, no historical dimension at all), checked against a
// supermajority threshold, then immediately delegatecall-executes an
// attacker-supplied target — one function, one transaction. Must fire
// evidence.
contract VulnerableGovernance {
    mapping(address => uint256) public stalk;
    uint256 public totalStalk;

    function emergencyCommit(address target, bytes calldata proposalData) external {
        uint256 votes = stalk[msg.sender];
        require(votes >= totalStalk * 2 / 3, "not enough support");
        (bool success, ) = target.delegatecall(proposalData);
        require(success, "execution failed");
    }
}

// Safe: faithful minimal reproduction of the real Compound Governor
// Bravo shape — voting power is read via getPriorVotes(voter,
// proposal.startBlock), where startBlock was captured and STORED at
// proposal-creation time (an earlier transaction), not the current
// block. Must NOT fire.
contract ProtectedGovernanceBravoStyle {
    struct Proposal { uint256 startBlock; address target; bytes data; }
    mapping(uint256 => Proposal) public proposals;
    IComp public comp;
    uint256 public quorumVotes;

    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        uint256 votes = comp.getPriorVotes(msg.sender, p.startBlock);
        require(votes >= quorumVotes, "not enough support");
        (bool success, ) = p.target.delegatecall(p.data);
        require(success, "execution failed");
    }
}

// Safe: the real Compound Bravo / OZ Governor "one block ago" pattern
// — block.number - 1, computed fresh inline but still referencing the
// PREVIOUS block, which a same-block flash loan cannot retroactively
// alter. Must NOT fire.
contract ProtectedPreviousBlockStyle {
    IComp public comp;
    uint256 public quorumVotes;

    function execute(address target, bytes calldata proposalData) external {
        uint256 votes = comp.getPriorVotes(msg.sender, block.number - 1);
        require(votes >= quorumVotes, "not enough support");
        (bool success, ) = target.delegatecall(proposalData);
        require(success, "execution failed");
    }
}

// DANGEROUS: the critical adversarial regression case — a 2-argument
// accessor IS used (so it LOOKS checkpoint-shaped at a glance), but
// the timepoint argument is the raw, unmodified CURRENT block.number —
// querying "right now" provides zero protection against a same-block
// flash loan. Proves the detector checks the ACTUAL timepoint value,
// not just "does a 2-arg accessor exist". Must still fire.
contract FakeCheckpointCurrentBlockStyle {
    IComp public comp;
    uint256 public quorumVotes;

    function execute(address target, bytes calldata proposalData) external {
        uint256 votes = comp.getPriorVotes(msg.sender, block.number);
        require(votes >= quorumVotes, "not enough support");
        (bool success, ) = target.delegatecall(proposalData);
        require(success, "execution failed");
    }
}

// Negative control: names deliberately chosen to match every keyword a
// name-matching heuristic would grep for ("votingPower", "quorum",
// "execute") but neither function actually combines a live-voting-
// power revert-capable gate with an execution call. Must NOT fire.
contract NameDecoyOnly {
    mapping(address => uint256) public votingPower;
    uint256 public quorum;

    function checkQuorum() external view returns (bool) {
        return votingPower[msg.sender] >= quorum;
    }

    event Executed();

    function execute() external {
        emit Executed();
    }
}

// Negative control: a genuinely LIVE voting-power comparison, revert-
// capable, but the consequence is only a state write (recording a
// vote) — no arbitrary external/low-level call follows. Proves the
// detector requires the FULL check-then-execute chain, not just a
// live check existing anywhere. Must NOT fire.
contract VoteRecordingOnlyDoesNotFalsePositive {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => uint256) public votesFor;
    uint256 public minVotesToRecord;

    function castVote(uint256 proposalId) external {
        uint256 power = votingPower[msg.sender];
        require(power >= minVotesToRecord, "below minimum");
        votesFor[proposalId] += power;
    }
}
