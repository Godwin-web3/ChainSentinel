"""
Regression tests for core/auth_detection.py — structural auth and
reentrancy-guard detection, replacing name/string-matching heuristics.

Each fixture is deliberately named to NOT match the old name lists
(AUTH_MODIFIER_PATTERNS, REENTRANCY_GUARDS/PREFIXES, PRIV_VARS) it
replaces — proving the fix removes false NEGATIVES (custom-named real
guards), not just the false POSITIVES found live this session
(Ownable2Step.acceptOwnership() on a real Fraxlend run).
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/auth_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_custom_named_auth_modifier_detected():
    nodes, *_ = _build("CustomAuthModifier.sol")
    fn = nodes["CustomAuthModifier.acceptOwnership()"]
    assert fn.auth_score >= 3, f"expected structural auth evidence, got {fn.auth_score}"
    assert fn.auth_state == "AUTHENTICATED"
    print("test_custom_named_auth_modifier_detected: PASS —", fn.auth_score, fn.auth_state)


def test_real_access_control_struct_shape_detected():
    """
    Reproduces the real OpenZeppelin AccessControl shape found live
    against Aave's ACLManager this session — struct-wrapped role storage
    (Index -> Member -> Index, not a flat nested mapping) plus
    _msgSender() indirection where the checked value is a PARAMETER only
    provably bound to msg.sender by tracing the call site
    (onlyRole -> _checkRole(role, _msgSender()) -> hasRole(role, account)).
    Before the fix: auth_score was 0 everywhere in this exact shape.
    """
    nodes, *_ = _build("RealAccessControlShape.sol")
    grant = nodes["RealAccessControlShape.grantRole(bytes32,address)"]
    assert grant.auth_score >= 3, f"expected structural auth evidence via onlyRole, got {grant.auth_score}"
    assert grant.auth_state == "AUTHENTICATED"

    only_role = nodes["RealAccessControlShape.onlyRole(bytes32)"]
    assert only_role.auth_score >= 3
    assert only_role.structural_auth_var and "_roles" in only_role.structural_auth_var

    set_param = nodes["RealAccessControlShape.setCriticalParam(uint256)"]
    assert set_param.auth_score >= 3, "same onlyRole modifier should gate any function it's attached to"
    print("test_real_access_control_struct_shape_detected: PASS —", grant.auth_score, only_role.structural_auth_var)


def test_access_control_role_mapping_detected():
    nodes, *_ = _build("AccessControlRoles.sol")
    fn = nodes["AccessControlRoles.setCriticalParam(uint256)"]
    assert fn.auth_score >= 3, f"expected role-mapping evidence, got {fn.auth_score}"
    assert fn.auth_state == "AUTHENTICATED"
    print("test_access_control_role_mapping_detected: PASS —", fn.auth_score, fn.auth_state)


def test_custom_named_reentrancy_guard_detected():
    nodes, *_ = _build("CustomReentrancyGuard.sol")
    guard_mod = nodes["CustomReentrancyGuard.xyzzy()"]
    fake_mod = nodes["CustomReentrancyGuard.fakeGuard()"]
    assert guard_mod.is_reentrancy_guard is True, "xyzzy() has the real guard shape — should be detected"
    assert fake_mod.is_reentrancy_guard is False, "fakeGuard() is NOT a real guard — must not false-positive"
    print("test_custom_named_reentrancy_guard_detected: PASS — xyzzy=True, fakeGuard=False")


def test_reentrancy_cei_suppressed_by_custom_guard():
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("CustomReentrancyGuard.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    reentrancy_findings = [
        r for r in (report.confirmed + report.likely + report.possible)
        if r.constraint_type == "REENTRANCY_CEI" and r.path.entry == "CustomReentrancyGuard.withdraw()"
    ]
    assert not reentrancy_findings, (
        f"withdraw() is protected by a custom-named real guard (xyzzy) — "
        f"REENTRANCY_CEI should not fire, got {reentrancy_findings}"
    )
    print("test_reentrancy_cei_suppressed_by_custom_guard: PASS — 0 REENTRANCY_CEI findings on withdraw()")


def test_self_scoped_write_suppressed_without_weakening():
    """
    Reproduces the real renounceRole() false positive found live against
    Aave's ACLManager: require(param == msg.sender) before a privileged
    write keyed by that SAME param is self-only by construction and must
    be suppressed. Critically, ALSO proves this does NOT weaken
    detection: a structurally similar function that checks one param
    against msg.sender but writes storage keyed by a DIFFERENT,
    unconstrained param (the exact shape a naive "any param==msg.sender
    counts" fix would wrongly suppress) must still fire ACCESS_CONTROL_GAP.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("PrivilegedBadWrite.sol")

    safe = nodes["PrivilegedBadWrite.setOperatorForSelf(bool)"]
    assert ("operators", ()) in safe.self_scoped_write_keys

    dangerous = nodes["PrivilegedBadWrite.corruptOperator(address,address,bool)"]
    assert dangerous.self_scoped_write_keys == set(), (
        "corruptOperator writes operators[target], never proven == msg.sender — "
        "must NOT be marked self-scoped just because a DIFFERENT param (caller) is"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_gap = [r for r in all_results if r.path.entry == safe.id and r.constraint_type == "ACCESS_CONTROL_GAP"]
    assert not safe_gap, f"setOperatorForSelf is self-scoped — ACCESS_CONTROL_GAP should not fire, got {safe_gap}"

    dangerous_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous.id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert dangerous_gap, "corruptOperator is a genuine access-control gap — must still fire, self-scoping fix must not weaken this"
    print("test_self_scoped_write_suppressed_without_weakening: PASS —",
          "setOperatorForSelf suppressed, corruptOperator still", dangerous_gap[0].verdict)


def test_self_scoped_asset_move_replaces_economic_interfaces_list():
    """
    Reproduces the real Liquity StabilityPool.withdrawFromSP() false
    positive found live this session (ECONOMIC_INTERFACES' exact-match
    name list didn't include "withdrawfromsp", only "withdraw") and
    proves the structural replacement (find_self_scoped_asset_moves)
    doesn't weaken detection: stealApproved (pulls an arbitrary victim's
    approved tokens to an attacker, despite also checking an unrelated
    caller==msg.sender-shaped condition in drainTo's sibling) must still
    fire, while depositMine (caller only ever moves their own approved
    funds in) is suppressed.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("BadAssetMove.sol")

    # Unit-level: direct ETH .call{value} cases (single-hop, no
    # intermediate function — enumerate_paths doesn't synthesize a path
    # for these, a pre-existing, unrelated limitation) still get the
    # right structural answer directly from the detector.
    drain_to = nodes["BadAssetMove.drainTo(address,address)"]
    claim_gain = nodes["BadAssetMove.claimGain()"]
    assert drain_to.self_scoped_asset_move_functions == set(), (
        "drainTo sends ETH to an arbitrary recipient parameter — must NOT be self-scoped"
    )
    assert "BadAssetMove.claimGain()" in claim_gain.self_scoped_asset_move_functions

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    steal_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "BadAssetMove.stealApproved(address,address,uint256)"
        and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert steal_gap, "stealApproved pulls an arbitrary victim's approved funds — must still fire"

    deposit_gap = [
        r for r in all_results
        if r.path.entry == "BadAssetMove.depositMine(uint256)" and r.constraint_type == "ACCESS_CONTROL_GAP"
    ]
    assert not deposit_gap, f"depositMine only ever moves the caller's own approved funds — must be suppressed, got {deposit_gap}"
    print("test_self_scoped_asset_move_replaces_economic_interfaces_list: PASS —",
          "stealApproved still", steal_gap[0].verdict, "| depositMine suppressed")


def test_self_scoped_liability_reduction_replaces_missing_precision():
    """
    Reproduces the real repayAsset()/liquidate() ACCESS_CONTROL_GAP false
    positive found live against Fraxlend's FraxlendPairCore this session,
    after ECONOMIC_INTERFACES was removed: _repayAsset() reduces
    userBorrowShares[_borrower] for an ARBITRARY _borrower (the standard
    permissionless repayBehalf pattern), which find_self_scoped_writes
    alone can't recognize since the beneficiary is never msg.sender.
    Safety instead comes from the write's magnitude being the SAME root
    value as a real payment pulled from msg.sender.

    Also proves this doesn't weaken detection: badReduce() reproduces the
    shape a naive "any self-scoped payment exists somewhere" fix would
    wrongly suppress — a real payment from msg.sender, but for a
    completely decoupled, caller-chosen amount (pay 1 wei, erase a real,
    unrelated debt). Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("LiabilityReduction.sol")

    safe = nodes["LiabilityReduction.repayFor(address,uint256)"]
    assert ("userBorrowShares", ()) in safe.self_scoped_liability_reduction_keys

    dangerous = nodes["LiabilityReduction.badReduce(address,uint256,uint256)"]
    assert dangerous.self_scoped_liability_reduction_keys == set(), (
        "badReduce's payment amount is decoupled from the write amount — "
        "must NOT be marked safe just because SOME payment from msg.sender exists"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_gap = [r for r in all_results if r.path.entry == safe.id and r.constraint_type == "ACCESS_CONTROL_GAP"]
    assert not safe_gap, f"repayFor is a correlated repayBehalf pattern — ACCESS_CONTROL_GAP should not fire, got {safe_gap}"

    dangerous_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous.id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert dangerous_gap, "badReduce lets an attacker erase arbitrary debt for a decoupled amount — must still fire"
    print("test_self_scoped_liability_reduction_replaces_missing_precision: PASS —",
          "repayFor suppressed, badReduce still", dangerous_gap[0].verdict)


def test_ownable2step_accept_ownership_suppressed():
    """
    Reproduces the real false positive found live this session against
    Fraxlend's FraxlendPair (inherits Ownable2Step): acceptOwnership()
    was flagged ACCESS_CONTROL_GAP -> ASSET_DRAIN on _transferOwnership,
    because its auth check (require(msg.sender == pendingOwner)) doesn't
    match any AUTH_MODIFIER_PATTERNS-style name (it's an inline check,
    not a modifier at all). Must now be suppressed.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("Ownable2Step.sol")
    accept = nodes["Ownable2Step.acceptOwnership()"]
    assert accept.auth_score >= 3, f"expected structural auth evidence, got {accept.auth_score}"

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    gap_findings = [
        r for r in (report.confirmed + report.likely + report.possible)
        if r.path.entry == "Ownable2Step.acceptOwnership()"
    ]
    assert not gap_findings, f"acceptOwnership() is auth-gated — expected suppression, got {gap_findings}"
    print("test_ownable2step_accept_ownership_suppressed: PASS — 0 findings on acceptOwnership()")


if __name__ == "__main__":
    test_custom_named_auth_modifier_detected()
    test_real_access_control_struct_shape_detected()
    test_access_control_role_mapping_detected()
    test_custom_named_reentrancy_guard_detected()
    test_reentrancy_cei_suppressed_by_custom_guard()
    test_self_scoped_write_suppressed_without_weakening()
    test_self_scoped_asset_move_replaces_economic_interfaces_list()
    test_self_scoped_liability_reduction_replaces_missing_precision()
    test_ownable2step_accept_ownership_suppressed()
    print("\nAll auth_detection tests passed.")
