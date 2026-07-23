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


def test_external_view_comparison_auth_detected():
    """
    Reproduces the real Uniswap V3 onlyFactoryOwner() false positive
    found live this session: require(msg.sender ==
    IUniswapV3Factory(factory).owner()) compares msg.sender against the
    RETURN VALUE of an external view call, not a plain state variable —
    invisible to the direct-comparison detector before this fix.

    badAuthCallerSuppliedFactory and badAuthStateChangingCall prove this
    doesn't weaken detection: an attacker-supplied call destination, and
    a call that isn't provably view/pure, must NOT be treated as auth
    evidence even though both superficially resemble the real shape.
    """
    nodes, *_ = _build("ExternalViewAuth.sol")

    only_factory_owner = nodes["ExternalViewAuth.onlyFactoryOwner()"]
    assert only_factory_owner.auth_score >= 3, f"expected external-view-comparison evidence, got {only_factory_owner.auth_score}"
    assert only_factory_owner.structural_auth_var == "factory"

    set_param = nodes["ExternalViewAuth.setCriticalParam(uint256)"]
    assert set_param.auth_score >= 3
    assert set_param.auth_state == "AUTHENTICATED"

    bad_caller_supplied = nodes["ExternalViewAuth.badAuthCallerSuppliedFactory(IFactory,uint256)"]
    assert bad_caller_supplied.auth_score < 3, (
        "the call destination is an attacker-supplied parameter, not a fixed factory — must not score as auth"
    )

    bad_state_changing = nodes["ExternalViewAuth.badAuthStateChangingCall(uint256)"]
    assert bad_state_changing.auth_score < 3, (
        "reportCaller() is not view/pure — must not be trusted as a side-effect-free auth check"
    )
    print("test_external_view_comparison_auth_detected: PASS —",
          "onlyFactoryOwner", only_factory_owner.auth_score, "| bad variants correctly unscored")


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


def test_delegated_reentrancy_guard_detected():
    """
    Reproduces the real modern OpenZeppelin nonReentrant shape (v4.8+,
    the current standard) found live against Fraxlend this session: the
    modifier itself is just two InternalCalls straddling the
    placeholder (_nonReentrantBefore()/_nonReentrantAfter()-style), with
    the actual require/write logic living in those private helpers, not
    inlined in the modifier body. Before the fix, this scored
    is_reentrancy_guard=False, producing false-positive REENTRANCY_CEI
    on every real nonReentrant-protected Fraxlend function.

    fakeDelegatedGuard proves this doesn't weaken detection: it ALSO
    delegates to helper functions before/after the placeholder (same
    shape at a glance), but the two helpers don't share a written+read
    state variable — must NOT be misdetected as a guard just because
    internal calls are now followed.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("CustomReentrancyGuard.sol")

    real_guard = nodes["CustomReentrancyGuard.delegatedGuard()"]
    fake_guard = nodes["CustomReentrancyGuard.fakeDelegatedGuard()"]
    assert real_guard.is_reentrancy_guard is True, "delegatedGuard() has the real nonReentrant shape — should be detected"
    assert fake_guard.is_reentrancy_guard is False, (
        "fakeDelegatedGuard()'s helpers don't share a written+read state var — must not false-positive"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)

    guarded_findings = [
        r for r in (report.confirmed + report.likely + report.possible)
        if r.constraint_type == "REENTRANCY_CEI" and r.path.entry == "CustomReentrancyGuard.withdrawDelegated()"
    ]
    assert not guarded_findings, (
        f"withdrawDelegated() is protected by delegatedGuard — REENTRANCY_CEI should not fire, got {guarded_findings}"
    )
    print("test_delegated_reentrancy_guard_detected: PASS — delegatedGuard=True, fakeDelegatedGuard=False, "
          "0 REENTRANCY_CEI findings on withdrawDelegated()")


def test_counter_fence_reentrancy_guard_detected():
    """
    Reproduces the real false positive found live this session against
    Mento Protocol's Broker (Celo, 0x1B78f6acD05e7BcB00f74863bfd8a7C264143e37):
    its ReentrancyGuard.sol is OpenZeppelin's own v2.x-era guard shape
    (before the boolean `_status` sentinel that later replaced it) — a
    monotonic counter fence instead of a boolean lock:
        modifier nonReentrant() {
            _guardCounter += 1;
            uint256 localCounter = _guardCounter;
            _;
            require(localCounter == _guardCounter, "reentrant call");
        }
    _guard_shape_from_before_after requires the SAME variable written
    on BOTH sides of the placeholder (the boolean lock's set/reset
    idiom) and its revert-capable check BEFORE the placeholder — the
    counter is written only in `before`, and its check lives AFTER —
    so this scored is_reentrancy_guard=False, false-positiving
    REENTRANCY_CEI + FLASHLOAN_WINDOW on every real
    nonReentrant-protected Broker function (swapIn, swapOut).

    fakeCounterFenceGuard proves this doesn't weaken detection: it
    ALSO increments a counter before the placeholder and snapshots it
    into a local (same shape at a glance), but the after-side check
    compares the snapshot against an UNRELATED variable, not the
    counter itself — must NOT be misdetected as a guard.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("CustomReentrancyGuard.sol")

    real_guard = nodes["CustomReentrancyGuard.counterFenceGuard()"]
    fake_guard = nodes["CustomReentrancyGuard.fakeCounterFenceGuard()"]
    assert real_guard.is_reentrancy_guard is True, "counterFenceGuard() has the real Mento/OZ v2.x guard shape — should be detected"
    assert fake_guard.is_reentrancy_guard is False, (
        "fakeCounterFenceGuard()'s after-check compares the wrong variable — must not false-positive"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)

    guarded_findings = [
        r for r in (report.confirmed + report.likely + report.possible)
        if "REENTRANCY_CEI" in r.constraint_type and r.path.entry == "CustomReentrancyGuard.withdrawCounterFenced()"
    ]
    assert not guarded_findings, (
        f"withdrawCounterFenced() is protected by counterFenceGuard — REENTRANCY_CEI should not fire, got {guarded_findings}"
    )

    unguarded_findings = [
        r for r in (report.confirmed + report.likely)
        if "REENTRANCY_CEI" in r.constraint_type and r.path.entry == "CustomReentrancyGuard.notReallyGuardedCounterFence()"
    ]
    assert unguarded_findings, "notReallyGuardedCounterFence() is NOT really guarded — REENTRANCY_CEI must still fire"
    print("test_counter_fence_reentrancy_guard_detected: PASS — counterFenceGuard=True, fakeCounterFenceGuard=False, "
          "0 REENTRANCY_CEI on withdrawCounterFenced(), still", unguarded_findings[0].verdict, "on notReallyGuardedCounterFence()")


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


def test_nested_mapping_outer_key_self_scoping():
    """
    Reproduces the real MakerDAO Vat.hope()/nope() false positive found
    live this session: `can[msg.sender][usr] = 1` writes a NESTED
    mapping where the OUTER key is msg.sender and the INNER key (usr)
    is an arbitrary, caller-chosen parameter — the opposite shape from
    AccessControl.renounceRole's `_roles[role].members[account]` (outer
    key attacker-irrelevant, inner key must be msg.sender), which
    find_self_scoped_writes already handled. Checking only the
    innermost index missed this real, common delegation/approval
    pattern (identical in shape to ERC20's allowances[owner][spender]).

    corruptAllowance() proves this doesn't weaken detection: neither the
    outer key (victim) nor the inner key (spender) is msg.sender — must
    NOT be self-scoped, ACCESS_CONTROL_GAP must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("NestedMappingSelfScope.sol")

    hope = nodes["NestedMappingSelfScope.hope(address)"]
    assert ("can", ()) in hope.self_scoped_write_keys

    dangerous = nodes["NestedMappingSelfScope.corruptAllowance(address,address,bool)"]
    assert dangerous.self_scoped_write_keys == set(), (
        "corruptAllowance writes allowances[victim][spender] — neither key is msg.sender — "
        "must NOT be marked self-scoped"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_gap = [r for r in all_results if r.path.entry == hope.id and "ACCESS_CONTROL_GAP" in r.constraint_type]
    assert not safe_gap, f"hope() is self-scoped via its outer key — ACCESS_CONTROL_GAP should not fire, got {safe_gap}"

    dangerous_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous.id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert dangerous_gap, "corruptAllowance is a genuine access-control gap — must still fire"
    print("test_nested_mapping_outer_key_self_scoping: PASS —",
          "hope suppressed, corruptAllowance still", dangerous_gap[0].verdict)


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


def test_self_scoped_asset_move_suppression_reaches_intermediate_hops():
    """
    Reproduces the real Compound III (Comet) buyCollateral() ->
    doTransferIn() -> transferFrom false positive found live this
    session: find_self_scoped_asset_moves correctly aggregated the proof
    onto doTransferIn's own canonical id (the real function whose body
    makes the transferFrom call), but constraints.py's suppression check
    only compared path.entry and path.sink.node_id against that set —
    neither matches when the proof lives on an INTERMEDIATE hop. Widened
    to scan every node id in path.edge_chain.

    stealViaHelper reproduces the exact shape a naive "any node on this
    path counts" fix without per-entry recomputation would get wrong:
    the SAME helper (_pullIn) is called safely from depositViaHelper
    (from=msg.sender) and unsafely from stealViaHelper (from=victim) —
    each entry's own self_scoped_asset_move_functions is recomputed
    fresh from that entry's own call-site bindings, so the two must not
    cross-contaminate.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("BadAssetMove.sol")

    deposit_via_helper = nodes["BadAssetMove.depositViaHelper(uint256)"]
    steal_via_helper = nodes["BadAssetMove.stealViaHelper(address,uint256)"]
    assert "BadAssetMove._pullIn(address,uint256)" in deposit_via_helper.self_scoped_asset_move_functions
    assert steal_via_helper.self_scoped_asset_move_functions == set(), (
        "_pullIn(victim, amount) is never proven msg.sender-bound from stealViaHelper's own call site — "
        "must NOT be marked safe just because the same helper is safe when called from elsewhere"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    deposit_gap = [
        r for r in all_results
        if r.path.entry == deposit_via_helper.id and r.constraint_type == "ACCESS_CONTROL_GAP"
    ]
    assert not deposit_gap, f"depositViaHelper only ever pulls the caller's own approved funds — must be suppressed, got {deposit_gap}"

    steal_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == steal_via_helper.id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert steal_gap, "stealViaHelper pulls an arbitrary victim's approved funds via the same helper shape — must still fire"
    print("test_self_scoped_asset_move_suppression_reaches_intermediate_hops: PASS —",
          "depositViaHelper suppressed, stealViaHelper still", steal_gap[0].verdict)


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

    safe_gap = [r for r in all_results if r.path.entry == safe.id and "ACCESS_CONTROL_GAP" in r.constraint_type]
    assert not safe_gap, f"repayFor is a correlated repayBehalf pattern — ACCESS_CONTROL_GAP should not fire, got {safe_gap}"

    # MISSING_HEALTH_CHECK must be just as consistent as ACCESS_CONTROL_GAP
    # on this same evidence (core/constraints.py::_check_missing_health_check's
    # self-scoped-liability-reduction block, added to fix the real Dai.approve()
    # inconsistency: a write ACCESS_CONTROL_GAP already proved safe via this
    # exact evidence must not still trip MISSING_HEALTH_CHECK on its own).
    safe_mhc = [r for r in all_results if r.path.entry == safe.id and "MISSING_HEALTH_CHECK" in r.constraint_type]
    assert not safe_mhc, f"repayFor's write is provably safe (repayBehalf-correlated) — MISSING_HEALTH_CHECK should not fire, got {safe_mhc}"

    dangerous_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous.id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert dangerous_gap, "badReduce lets an attacker erase arbitrary debt for a decoupled amount — must still fire"

    dangerous_mhc = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous.id and "MISSING_HEALTH_CHECK" in r.constraint_type
    ]
    assert dangerous_mhc, "badReduce's decoupled amount is NOT self-scoped-liability-reduction evidence — MISSING_HEALTH_CHECK must still fire"
    print("test_self_scoped_liability_reduction_replaces_missing_precision: PASS —",
          "repayFor suppressed (ACL+MHC), badReduce still", dangerous_gap[0].verdict)


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


def test_numeric_equality_constant_role_flag_detected():
    """
    Reproduces the real regression found live this session against
    MakerDAO's Vat.sol: `wards[msg.sender] == 1` is a numeric (uint,
    not bool) membership flag used by the `auth` modifier across every
    DSS contract. It stopped scoring as auth evidence entirely once
    _role_mapping_ir was gated to bool-typed Index results only (the
    earlier fix for Dai's `allowance[...][msg.sender] >= wad` false-
    AUTHENTICATED bug) — silently losing wards' STORAGE_CORRUPTION
    "privileged" classification too (confirmed live: Vat.sol's sink
    count dropped from 2 to 0, hiding rely()/deny() entirely instead of
    correctly suppressing them as auth-gated).

    Also proves this doesn't reopen the Dai false positive: corruptWards()
    reproduces the exact shape that must stay excluded — an equality
    check against a caller-supplied VARIABLE (not a constant), which is
    a numeric exact-match check structurally identical to an economic
    guard, not a permission flag. Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("WardsStyleAuth.sol")

    auth_modifier = nodes["WardsStyleAuth.auth()"]
    assert auth_modifier.auth_score >= 3, f"expected structural auth evidence on the auth() modifier, got {auth_modifier.auth_score}"

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    rely_gap = [
        r for r in all_results
        if r.path.entry == "WardsStyleAuth.rely(address)" and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert not rely_gap, f"rely() is gated by the auth modifier — ACCESS_CONTROL_GAP should not fire, got {rely_gap}"

    corrupt_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "WardsStyleAuth.corruptWards(address,uint256)" and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert corrupt_gap, "corruptWards()'s guard is a variable-equality check, not a real permission flag — ACCESS_CONTROL_GAP must still fire"
    print("test_numeric_equality_constant_role_flag_detected: PASS —",
          "rely suppressed, corruptWards still", corrupt_gap[0].verdict)


def test_ecrecover_signer_self_scoping_detected():
    """
    Reproduces the real Dai.permit() false positive found live this
    session against MakerDAO's Dai.sol: `require(holder ==
    ecrecover(digest, v, r, s))` before `allowance[holder][spender] =
    wad` — a genuine EIP-2612 signature-based authorization that
    find_self_scoped_writes previously couldn't recognize at all (it
    only understood msg.sender/tx.origin comparisons).

    Also proves this doesn't weaken detection:
    corruptViaUnrelatedSignature() reproduces the shape a naive "any
    ecrecover check anywhere counts" fix would wrongly suppress — a
    real signature check, but over a completely different parameter
    (signer) than the one used as the write's key (victim). An
    attacker can supply their own valid signature while still
    corrupting an arbitrary victim's allowance row. Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("EcrecoverPermit.sol")

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_id = "EcrecoverPermit.permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
    safe_gap = [r for r in all_results if r.path.entry == safe_id and "ACCESS_CONTROL_GAP" in r.constraint_type]
    assert not safe_gap, f"permit()'s write is provably keyed by the ecrecover-proven signer — ACCESS_CONTROL_GAP should not fire, got {safe_gap}"

    dangerous_id = "EcrecoverPermit.corruptViaUnrelatedSignature(address,address,address,uint256,uint8,bytes32,bytes32)"
    dangerous_gap = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous_id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert dangerous_gap, "corruptViaUnrelatedSignature()'s signature check is decoupled from the write's key — ACCESS_CONTROL_GAP must still fire"
    print("test_ecrecover_signer_self_scoping_detected: PASS —",
          "permit suppressed, corruptViaUnrelatedSignature still", dangerous_gap[0].verdict)


def test_balance_invariant_suppresses_flashloan_window():
    """
    Reproduces the real false positive found live this session against
    Uniswap V3's UniswapV3Pool.flash()/swap(): a value snapshotted
    before an external callback is re-read after it and enforced via a
    revert-capable invariant — the actual mechanism that makes an
    unauthenticated flash-loan callback safe.
    _check_flashloan_window's own docstring already claimed to check
    for "no invariant enforced after", but the code never did — this
    fired FLASHLOAN_WINDOW at 99% confidence on real, safe code.

    Also proves this doesn't weaken detection: flashUnsafe() reproduces
    the real PancakeBunny-style shape — a state write before the
    callback with NO re-verification afterward at all. Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("FlashLoanInvariant.sol")

    safe = nodes["FlashLoanInvariant.flash(address,uint256)"]
    assert safe.has_balance_invariant_after_call, "flash()'s balance0Before/After + require should be recognized as a real invariant"

    dangerous = nodes["FlashLoanInvariant.flashUnsafe(address,uint256)"]
    assert not dangerous.has_balance_invariant_after_call, "flashUnsafe() has no re-verification at all — must not be marked safe"

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_window = [r for r in all_results if r.path.entry == safe.id and "FLASHLOAN_WINDOW" in r.constraint_type]
    assert not safe_window, f"flash()'s callback window is closed by a real invariant — FLASHLOAN_WINDOW should not fire, got {safe_window}"

    dangerous_window = [
        r for r in (report.confirmed + report.likely + report.possible)
        if r.path.entry == dangerous.id and "FLASHLOAN_WINDOW" in r.constraint_type
    ]
    assert dangerous_window, "flashUnsafe() has no invariant re-check at all — FLASHLOAN_WINDOW must still fire"
    print("test_balance_invariant_suppresses_flashloan_window: PASS —",
          "flash suppressed, flashUnsafe still", dangerous_window[0].verdict)


def test_self_scoped_getter_funds_asset_move():
    """
    Reproduces the real Uniswap V3 UniswapV3Pool.collect() false
    positive found live this session: `recipient` is an arbitrary
    parameter (safe by design — collect() lets you withdraw your fees
    to any address), and find_self_scoped_asset_moves previously only
    understood a self-scoped DESTINATION (to == msg.sender) or a
    self-scoped SOURCE via transferFrom's `from` — neither matches this
    shape. Safety instead comes from the AMOUNT: it's bounded by, and
    simultaneously debited from, the caller's own accrued balance,
    looked up via a getter whose owner argument is hardcoded to
    msg.sender at the real call site.

    Also proves this doesn't weaken detection:
      - collectFor() reproduces the shape a naive "any getter-derived
        decrement counts" fix would wrongly suppress — the getter is
        called with an ATTACKER-CHOSEN owner, not msg.sender. Must
        still fire.
      - collectDecoupled() reproduces a real self-scoped getter
        reference, but the transferred amount is a completely
        different, decoupled parameter from the one actually debited.
        Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("SelfScopedGetterCollect.sol")

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_id = "SelfScopedGetterCollect.collect(address,int24,int24,uint128)"
    safe_gap = [r for r in all_results if r.path.entry == safe_id and "ACCESS_CONTROL_GAP" in r.constraint_type]
    assert not safe_gap, f"collect()'s amount is provably self-funded from the caller's own position — ACCESS_CONTROL_GAP should not fire, got {safe_gap}"

    for dangerous_id in (
        "SelfScopedGetterCollect.collectFor(address,address,int24,int24,uint128)",
        "SelfScopedGetterCollect.collectDecoupled(address,int24,int24,uint128,uint128)",
    ):
        dangerous_gap = [
            r for r in (report.confirmed + report.likely)
            if r.path.entry == dangerous_id and "ACCESS_CONTROL_GAP" in r.constraint_type
        ]
        assert dangerous_gap, f"{dangerous_id} is not actually self-funded — ACCESS_CONTROL_GAP must still fire"
    print("test_self_scoped_getter_funds_asset_move: PASS —",
          "collect suppressed, collectFor/collectDecoupled still fire")


def test_fresh_deployment_destination_excludes_cross_function_race():
    """
    Reproduces the real CROSS_FUNCTION_STATE_RACE false positive found
    live this session against QuickSwap/UniswapV2Factory.createPair()
    on Polygon: `IUniswapV2Pair(pair).initialize(token0, token1)` is a
    genuine HighLevelCall to a non-view function, but `pair` was
    CREATE2'd two lines earlier from this same factory's own, fully-
    known bytecode (type(UniswapV2Pair).creationCode) — not an
    attacker-substitutable address. core/invariants.py::_classify_call
    previously treated it as CALLBACK_CAPABLE purely from the callee's
    mutability, with zero awareness of destination trust.

    Also proves this doesn't weaken detection: UnsafeFactory's deployed
    contract (UnsafeKnownPair) is freshly-CREATE2'd the exact same way,
    but its own initialize() makes a real external call to an
    attacker-supplied hookTarget — "freshly deployed" alone doesn't
    prove the deployed code itself is safe. Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("FreshDeploymentCallback.sol")

    safe = nodes["KnownFactory.createPair(address,address)"]
    assert safe.race_findings == [], f"createPair()'s callback target is freshly CREATE2'd known bytecode with no external call of its own — race_findings should be empty, got {safe.race_findings}"

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_race = [r for r in all_results if r.path.entry == safe.id and "CROSS_FUNCTION_STATE_RACE" in r.constraint_type]
    assert not safe_race, f"createPair()'s deployed contract makes no external call of its own — CROSS_FUNCTION_STATE_RACE should not fire, got {safe_race}"

    dangerous_id = "UnsafeFactory.createPair(address,address,address)"
    dangerous_race = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous_id and "CROSS_FUNCTION_STATE_RACE" in r.constraint_type
    ]
    assert dangerous_race, "UnsafeFactory's deployed contract calls back out to an attacker-supplied address — CROSS_FUNCTION_STATE_RACE must still fire"
    print("test_fresh_deployment_destination_excludes_cross_function_race: PASS —",
          "createPair suppressed, UnsafeFactory.createPair still", dangerous_race[0].verdict)


def test_transparent_proxy_fallback_governance_gated_destination_excludes_delegation_sink():
    """
    Reproduces the real false positive found live this session against
    Takara Lend, a real Compound V2 fork deployed on Sei (Comptroller
    at 0x56A171Acb1bBa46D4fdF21AfBE89377574B8D9BD):
    SafeUnitroller.fallback() unconditionally delegatecalls
    `comptrollerImpl.delegatecall(msg.data)` with no auth check of its
    own — the standard transparent-proxy pattern. That's correct: the
    actual privilege enforcement happens inside each of the
    implementation's own functions, re-checked against the SAME shared
    storage the delegatecall preserves. core/edges.py hardcoded
    trusted=False for EVERY delegatecall regardless of destination, and
    core/sinks.py's carve-out for exactly this pattern checked
    `not e.uncertain` — a flag ALSO hardcoded True for every
    delegatecall — so the carve-out could never actually fire.

    Also proves this doesn't weaken detection: UnsafeProxy.fallback()
    is structurally identical, except its implementation slot is set by
    a completely UNGUARDED function — must still fire ACCESS_CONTROL_GAP
    and classify as DELEGATION_SINK.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("TransparentProxyDelegation.sol")

    sinks = classify_sinks(nodes, graph_edges)
    safe_id = "SafeUnitroller.fallback()"
    unsafe_id = "UnsafeProxy.fallback()"
    assert safe_id not in sinks, f"SafeUnitroller.fallback()'s implementation slot is governance-gated — must not be a sink at all, got {sinks.get(safe_id)}"
    assert unsafe_id in sinks and sinks[unsafe_id].category == "DELEGATION_SINK", (
        f"UnsafeProxy.fallback()'s implementation slot is unguarded — must still classify as DELEGATION_SINK, got {sinks.get(unsafe_id)}"
    )

    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    safe_findings = [r for r in all_results if r.path.entry == safe_id and "ACCESS_CONTROL_GAP" in r.constraint_type]
    assert not safe_findings, f"SafeUnitroller.fallback() must not fire ACCESS_CONTROL_GAP, got {safe_findings}"

    unsafe_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == unsafe_id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert unsafe_findings, "UnsafeProxy.fallback()'s implementation slot is unguarded — ACCESS_CONTROL_GAP must still fire"
    print("test_transparent_proxy_fallback_governance_gated_destination_excludes_delegation_sink: PASS —",
          "SafeUnitroller excluded, UnsafeProxy still", unsafe_findings[0].verdict)


def test_self_delegatecall_multicall_excludes_delegation_sink():
    """
    Reproduces the real false positive found live this session against
    INIT Capital's real InitCore.sol (Blast): the real OpenZeppelin-
    style Multicall.multicall() batches calls via `address(this).
    delegatecall(_data[i])` — a SELF-delegatecall, not a proxy
    dispatching to a separate implementation. `address(this)` lowers to
    a TypeConversion producing a TemporaryVariable, so it never matched
    core/edges.py::_resolve_trust's state-variable trust path at all —
    and core/sinks.py's carve-out was gated to functions literally
    named "fallback"/"receive", which "multicall" isn't, so even a
    perfectly-trusted self-delegatecall could never be excluded.

    Also proves this doesn't weaken detection: UnsafeDelegateToParam.
    batchCall() is structurally similar (a delegatecall inside a loop,
    no fallback()/receive() name), but the destination is an
    ATTACKER-SUPPLIED PARAMETER, not `address(this)` — must NOT be
    misdetected as safe just because it superficially resembles a
    multicall helper; must still fire ACCESS_CONTROL_GAP and classify
    as DELEGATION_SINK.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("TransparentProxyDelegation.sol")

    sinks = classify_sinks(nodes, graph_edges)
    safe_id = "SelfMulticall.multicall(bytes[])"
    unsafe_id = "UnsafeDelegateToParam.batchCall(address,bytes[])"
    assert safe_id not in sinks, f"SelfMulticall.multicall()'s destination is address(this) — must not be a sink at all, got {sinks.get(safe_id)}"
    assert unsafe_id in sinks and sinks[unsafe_id].category == "DELEGATION_SINK", (
        f"UnsafeDelegateToParam.batchCall()'s destination is an attacker-supplied parameter — must still classify as DELEGATION_SINK, got {sinks.get(unsafe_id)}"
    )

    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    safe_findings = [r for r in all_results if r.path.entry == safe_id and "ACCESS_CONTROL_GAP" in r.constraint_type]
    assert not safe_findings, f"SelfMulticall.multicall() must not fire ACCESS_CONTROL_GAP, got {safe_findings}"

    unsafe_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == unsafe_id and "ACCESS_CONTROL_GAP" in r.constraint_type
    ]
    assert unsafe_findings, "UnsafeDelegateToParam.batchCall()'s destination is attacker-supplied — ACCESS_CONTROL_GAP must still fire"
    print("test_self_delegatecall_multicall_excludes_delegation_sink: PASS —",
          "SelfMulticall excluded, UnsafeDelegateToParam still", unsafe_findings[0].verdict)


def test_external_view_return_verdict_auth_detected():
    """
    Reproduces the real Balancer/Berachain BEX Authorizer false positive
    found live this session against ProtocolFeesCollector.
    withdrawCollectedFees() (deployed on Berachain at
    0x4Be03f781C497A489E3cB0287833452cA9B9E80B): the auth verdict is the
    RAW boolean return of a fixed-destination, view-only external call —
    no `==`/`!=` comparison anywhere — gated by a free-function revert
    wrapper (`_require`/`_revert`) whose actual revert happens via raw
    inline assembly.

    badAuthCallerSuppliedAuthorizer, badAuthNoCallerArgument,
    badAuthMutatingCall, and fakeRequireNeverReverts prove this doesn't
    weaken detection: an attacker-supplied call destination, a call
    whose arguments never actually involve msg.sender, a call that
    isn't provably view/pure, and a wrapper that looks like a revert
    gate but never actually reverts, must NOT be treated as auth
    evidence even though each superficially resembles the real shape.
    """
    nodes, *_ = _build("AuthorizerReturnVerdict.sol")

    withdraw = nodes["AuthorizerReturnVerdict.withdrawCollectedFees(uint256)"]
    assert withdraw.auth_score >= 3, f"expected external-view-return-verdict evidence, got {withdraw.auth_score}"
    assert withdraw.auth_state == "AUTHENTICATED"
    assert withdraw.structural_auth_var == "authorizer"

    bad_caller_supplied = nodes["AuthorizerReturnVerdict.badAuthCallerSuppliedAuthorizer(IAuthorizer,uint256)"]
    assert bad_caller_supplied.auth_score < 3, (
        "the authorizer destination is an attacker-supplied parameter, not the fixed immutable — must not score as auth"
    )

    bad_no_caller_arg = nodes["AuthorizerReturnVerdict.badAuthNoCallerArgument(uint256)"]
    assert bad_no_caller_arg.auth_score < 3, (
        "msg.sender is never passed as an argument to the view call — must not score as auth"
    )

    bad_mutating = nodes["AuthorizerReturnVerdict.badAuthMutatingCall(uint256)"]
    assert bad_mutating.auth_score < 3, (
        "reportAndApprove() is not view/pure — must not be trusted as a side-effect-free auth check"
    )

    fake_wrapper = nodes["AuthorizerReturnVerdict.fakeRequireNeverReverts(uint256)"]
    assert fake_wrapper.auth_score < 3, (
        "_fakeRequire never actually reverts on failure — must not be treated as a real gate"
    )
    print("test_external_view_return_verdict_auth_detected: PASS —",
          "withdrawCollectedFees", withdraw.auth_score, "| bad variants correctly unscored")


if __name__ == "__main__":
    test_custom_named_auth_modifier_detected()
    test_real_access_control_struct_shape_detected()
    test_access_control_role_mapping_detected()
    test_external_view_comparison_auth_detected()
    test_custom_named_reentrancy_guard_detected()
    test_reentrancy_cei_suppressed_by_custom_guard()
    test_delegated_reentrancy_guard_detected()
    test_counter_fence_reentrancy_guard_detected()
    test_self_scoped_write_suppressed_without_weakening()
    test_nested_mapping_outer_key_self_scoping()
    test_self_scoped_asset_move_replaces_economic_interfaces_list()
    test_self_scoped_asset_move_suppression_reaches_intermediate_hops()
    test_self_scoped_liability_reduction_replaces_missing_precision()
    test_ownable2step_accept_ownership_suppressed()
    test_numeric_equality_constant_role_flag_detected()
    test_ecrecover_signer_self_scoping_detected()
    test_balance_invariant_suppresses_flashloan_window()
    test_self_scoped_getter_funds_asset_move()
    test_fresh_deployment_destination_excludes_cross_function_race()
    test_transparent_proxy_fallback_governance_gated_destination_excludes_delegation_sink()
    test_self_delegatecall_multicall_excludes_delegation_sink()
    test_external_view_return_verdict_auth_detected()
    print("\nAll auth_detection tests passed.")
