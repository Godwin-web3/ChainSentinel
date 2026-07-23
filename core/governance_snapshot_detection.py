"""
core/governance_snapshot_detection.py — Structural flash-loan
governance-voting-power detection (Slither IR, source-level).

Real attack (grounded in a real, well-documented exploit — Beanstalk
Farms' real $182M loss, April 17 2022): Beanstalk's governance let a
proposal be executed via `emergencyCommit()` once voting power backing
it cleared a 2/3 supermajority, with NO delay between voting and
execution. Voting power ("stalk") was read LIVE — a plain, current
balance — with no historical/checkpoint dimension at all. The attacker
flash-loaned over $1B, deposited it into Beanstalk to mint a massive
amount of stalk, instantly cleared the 2/3 threshold, and executed a
malicious proposal that drained the protocol — all within one
transaction, repaying the flash loan at the end of the SAME
transaction.

The real, industry-standard mitigation — confirmed live via IR probe
against Compound's actual, widely-deployed Governor Bravo
(GovernorBravoDelegate.sol) and OpenZeppelin's own Governor.sol — is a
CHECKPOINT: voting power is looked up as of a PAST block/timepoint
(`getPriorVotes(voter, proposal.startBlock)`, where `startBlock` was
captured and stored at proposal-CREATION time, an earlier transaction;
or `getVotes(account, proposalSnapshot(proposalId))`). A flash loan
taken out and repaid within the CURRENT transaction cannot retroactively
alter a checkpoint that reflects state as of an EARLIER block — this is
also why real code commonly queries `block.number - 1` rather than
`block.number` itself even for same-function checks (Compound Bravo's
own `propose()` proposer-threshold check): querying the raw, unmodified
CURRENT block provides zero protection, since the flash-loaned balance
IS already reflected in "right now". Only a reference to a PAST
block/timepoint — a subtraction from the current block, or a value
already captured in storage before this call — genuinely defeats a
same-block flash loan.

This module does not name any specific framework's accessor function
(getVotes/getPriorVotes/balanceOf/a custom mapping all vary by
protocol) — it structurally asks: does the timepoint argument (if any)
resolve to a PAST value, or does querying it right now provide no
historical protection at all?
"""

from typing import Optional

from slither.slithir.operations import (
    Binary, HighLevelCall, InternalCall, LibraryCall, LowLevelCall, Member, Index,
)
from slither.slithir.operations.binary import BinaryType
from slither.core.declarations.solidity_variables import SolidityVariableComposed

from core.edges import _follow_reference, _find_defining_op, _resolves_to_block_timestamp, _single_source_operand, _node_can_revert
from core.auth_detection import _expand_with_internal_calls

_COMPARISON_TYPES = {BinaryType.GREATER, BinaryType.GREATER_EQUAL, BinaryType.LESS, BinaryType.LESS_EQUAL}


def _resolves_to_current_block_number(var, f, max_depth: int = 3) -> bool:
    """
    True if var is (or, via bounded pass-through hops, resolves to)
    Solidity's own `block.number`, unmodified — the "right now" case
    that provides zero protection against a same-block flash loan.
    Mirrors core/edges.py::_resolves_to_block_timestamp exactly, for
    block.number instead of block.timestamp — governance checkpoints
    conventionally key on block NUMBER, not timestamp.
    """
    if max_depth < 0:
        return False
    if isinstance(var, SolidityVariableComposed) and str(var) == "block.number":
        return True
    resolved = _follow_reference(var)
    if isinstance(resolved, SolidityVariableComposed) and str(resolved) == "block.number":
        return True
    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        return False
    inner = _single_source_operand(defining_op)
    if inner is not None and max_depth > 0:
        return _resolves_to_current_block_number(inner, f, max_depth - 1)
    return False


def _base_of_pass_through(defining_op):
    """
    Unwrap a value one hop closer to its original source, across every
    pass-through IR shape relevant here: TypeConversion/Assignment
    (core/edges.py::_single_source_operand) PLUS Member/Index — a
    struct-field or mapping-element access's own `.variable_left`, the
    BASE object being accessed (`p` in `p.startBlock`; `proposals` in
    `proposals[proposalId]`). core/edges.py::_follow_reference is a
    documented no-op in the currently installed slither-analyzer
    (0.11.5 — its own import targets a module path that doesn't exist
    in this version); rather than fix that shared, 29-call-site
    function as a side effect of this new detector, this module
    resolves Member/Index chains itself.
    """
    inner = _single_source_operand(defining_op)
    if inner is not None:
        return inner
    if isinstance(defining_op, (Member, Index)):
        return getattr(defining_op, "variable_left", None)
    return None


def _resolves_to_past_timepoint(var, f, max_depth: int = 6) -> bool:
    """
    True if var is genuinely immune to same-block flash-loan
    manipulation as a governance voting-power timepoint argument:
    either (a) a Binary SUBTRACTION whose LEFT operand is the CURRENT
    block.number/block.timestamp (`block.number - k` — the real
    Compound Governor Bravo / OZ Governor pattern), or (b) traces back
    — through bounded pass-through hops (see _base_of_pass_through) —
    to a value with NO local defining IR op in f at all: a state
    variable, a struct field read from persistent storage, or a
    function parameter, none of which can be freshly computed from the
    CURRENT block within this same call (the real Compound Bravo
    shape: `proposal.startBlock`, captured and stored at proposal-
    creation time — an EARLIER transaction).

    False if var IS (or resolves to) the raw, unmodified CURRENT
    block.number/block.timestamp — querying "right now" provides zero
    protection against a same-block flash loan.
    """
    if max_depth < 0:
        return False
    resolved = _follow_reference(var)
    if _resolves_to_current_block_number(resolved, f) or _resolves_to_block_timestamp(resolved, f):
        return False
    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        return True
    if isinstance(defining_op, Binary) and defining_op.type == BinaryType.SUBTRACTION:
        left = defining_op.variable_left
        if _resolves_to_current_block_number(left, f) or _resolves_to_block_timestamp(left, f):
            return True
    inner = _base_of_pass_through(defining_op)
    if inner is not None:
        return _resolves_to_past_timepoint(inner, f, max_depth - 1)
    return False


def _is_live_voting_power_accessor(defining_op, f) -> bool:
    """
    True if defining_op is a HighLevelCall/InternalCall/LibraryCall
    with NO timepoint argument at all (a plain balanceOf(account)-
    shaped 1-argument accessor — no historical dimension is even
    possible) or with a LAST argument that resolves to the raw current
    block (see _resolves_to_past_timepoint) — OR a plain Index
    (mapping) read, which by definition has no historical dimension —
    confirmed live via IR probe: the real Beanstalk-shaped
    `stalk[msg.sender]` is exactly this Index shape.
    """
    if isinstance(defining_op, (HighLevelCall, InternalCall, LibraryCall)):
        args = list(getattr(defining_op, "arguments", None) or [])
        if len(args) < 2:
            return True
        timepoint = args[-1]
        return not _resolves_to_past_timepoint(timepoint, f)
    if isinstance(defining_op, Index):
        return True
    return False


def _traces_to_live_voting_power(var, f, max_depth: int = 4) -> Optional[str]:
    """
    Backward-trace var (a threshold-comparison operand) through
    bounded pass-through hops to determine whether it resolves to a
    live (un-checkpointed) voting-power-shaped read — see
    _is_live_voting_power_accessor. Returns the defining op's own
    stringified form as evidence, or None.
    """
    if max_depth < 0:
        return None
    resolved = _follow_reference(var)
    defining_op = _find_defining_op(resolved, f)
    if defining_op is None:
        return None
    if _is_live_voting_power_accessor(defining_op, f):
        return str(defining_op)
    inner = _base_of_pass_through(defining_op)
    if inner is not None:
        return _traces_to_live_voting_power(inner, f, max_depth - 1)
    return None


def _has_arbitrary_call_after(nodes: list, check_node) -> bool:
    """
    True if any node AFTER check_node (in program order within the
    same node list) contains a HighLevelCall or LowLevelCall — the
    real "execute the proposal" consequence (an arbitrary encoded
    action, or a raw .call()), confirmed live via IR probe against a
    faithful reproduction of the real Beanstalk emergencyCommit() shape.
    """
    try:
        idx = nodes.index(check_node)
    except ValueError:
        return False
    for node in nodes[idx + 1:]:
        for ir in node.irs:
            if isinstance(ir, (HighLevelCall, LowLevelCall)):
                return True
    return False


def _find_unsafe_governance_evidence(f, max_depth: int, _visited: Optional[set] = None) -> Optional[str]:
    """
    Recursively scan f's own nodes, and (bounded, cycle-safe) any
    internal function it calls, for a revert-capable threshold
    comparison whose voting-power operand is LIVE (see
    _traces_to_live_voting_power), with an arbitrary external/low-level
    call reachable afterward in the same scope (see
    _has_arbitrary_call_after) — the real Beanstalk emergencyCommit()
    shape: check live voting power, then execute, in one transaction.
    Returns the live accessor's own stringified form as evidence, or
    None.
    """
    if _visited is None:
        _visited = set()
    fid = id(f)
    if fid in _visited or max_depth < 0:
        return None
    _visited.add(fid)

    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None

    for node in nodes:
        if not _node_can_revert(node):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in _COMPARISON_TYPES:
                continue
            for operand in (ir.variable_left, ir.variable_right):
                evidence = _traces_to_live_voting_power(operand, f)
                if evidence is None:
                    continue
                if _has_arbitrary_call_after(nodes, node):
                    return evidence

    if max_depth <= 0:
        return None

    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall) and getattr(ir, "function", None) is not None:
                nested = _find_unsafe_governance_evidence(ir.function, max_depth - 1, _visited)
                if nested is not None:
                    return nested
    return None


def find_unsafe_live_voting_power_execution(f, max_depth: int = 3) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string) if f's own
    body, or anything it reaches via bounded internal calls, gates an
    arbitrary external/low-level call behind a revert-capable threshold
    comparison whose voting-power operand is read LIVE — no historical/
    checkpoint dimension at all, or one that queries the raw, unmodified
    current block — see _find_unsafe_governance_evidence. A same-block
    flash loan can inflate the live value, clear the threshold, and
    trigger the execution, all repaid within the same transaction: the
    real Beanstalk Farms $182M exploit (April 2022).
    """
    return _find_unsafe_governance_evidence(f, max_depth)
