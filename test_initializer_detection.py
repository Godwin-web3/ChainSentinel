"""
Regression tests for core/initializer_detection.py — structural
front-runnable/missing-initializer-protection detection.

Real precedent: the Parity Multisig Wallet Library (Nov 2017) — its
real initWallet() set `owner` with zero re-invocation guard. An
attacker called it directly on the shared library contract, became its
owner, then called the library's own kill() — selfdestructing it and
permanently freezing ~513,774 ETH (~$280M) across 587 dependent
wallets. The same root cause recurs constantly in modern proxy-based
upgradeable contracts under "missing initializer modifier" /
"front-runnable initialize()" — one of the most common real
Code4rena/Sherlock findings for proxy-based protocols. Real precedent
for the protected shape: OpenZeppelin's actual widely-deployed v4.9
Initializable.sol, confirmed live via IR probe against the real
reference source.
"""
import os

from core.graph import build_graph
from core.sinks import classify_sinks
from core.paths import enumerate_paths
from core.constraints import validate_paths

FIXTURE_DIR = os.path.abspath("fixture/initializer_detection")


def _build(filename):
    entry = os.path.join(FIXTURE_DIR, filename)
    return build_graph(
        project_root=FIXTURE_DIR,
        entry_file=entry,
        solc_version="0.8.19",
        enrichment={},
    )


def test_unguarded_owner_write_detected():
    """
    Reproduces the real Parity WalletLibrary shape: initWallet() sets
    `owner` with zero guard against re-invocation. Must fire evidence.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["ParityStyleWallet.initWallet(address)"]
    assert fn.unprotected_initializer_write is not None, "expected unprotected initializer evidence"
    print("test_unguarded_owner_write_detected: PASS —",
          "evidence:", fn.unprotected_initializer_write)


def test_oz_initializer_modifier_suppresses_finding():
    """
    Reproduces the real, widely-deployed OZ v4.9 Initializable.sol
    shape: a genuine one-time latch (_initialized, never reset). Must
    NOT flag.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["ProtectedInitializable.initialize(address)"]
    assert fn.unprotected_initializer_write is None, f"OZ-initializer-protected function must not flag, got {fn.unprotected_initializer_write}"
    print("test_oz_initializer_modifier_suppresses_finding: PASS")


def test_inline_self_referential_guard_suppresses_finding():
    """
    The common self-referential shape: require(owner == address(0))
    immediately before setting owner. Must NOT flag.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["InlineGuardedInit.initialize(address)"]
    assert fn.unprotected_initializer_write is None, f"self-referential-guarded function must not flag, got {fn.unprotected_initializer_write}"
    print("test_inline_self_referential_guard_suppresses_finding: PASS")


def test_reentrancy_guard_does_not_suppress_finding():
    """
    Critical adversarial regression: a real nonReentrant-style guard
    only TOGGLES its flag (set before, reset after) — it protects
    against reentrant calls DURING one transaction, not against being
    called again in a SEPARATE later transaction. A reentrancy guard
    is not a substitute for a one-time latch. Must still fire.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["NonReentrantIsNotAnInitializerGuard.initialize(address)"]
    assert fn.unprotected_initializer_write is not None, "nonReentrant alone must not suppress the real finding"
    print("test_reentrancy_guard_does_not_suppress_finding: PASS —",
          "evidence:", fn.unprotected_initializer_write)


def test_real_constructor_does_not_false_positive():
    """
    owner is set ONLY in the real Solidity constructor — EVM-enforced
    single-invocation already. Must NOT flag.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["ConstructorOnly.constructor(address)"]
    assert fn.unprotected_initializer_write is None, f"real constructor must not flag, got {fn.unprotected_initializer_write}"
    print("test_real_constructor_does_not_false_positive: PASS")


def test_internal_helper_does_not_false_positive():
    """
    The unprotected owner-setting logic lives in an INTERNAL helper,
    never externally callable on its own. Must NOT flag.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["InternalHelperOnly._setupOwner(address)"]
    assert fn.unprotected_initializer_write is None, f"internal-only helper must not flag, got {fn.unprotected_initializer_write}"
    print("test_internal_helper_does_not_false_positive: PASS")


def test_ownable2step_style_accept_does_not_false_positive():
    """
    Critical adversarial regression: the real OpenZeppelin Ownable2Step
    shape. acceptOwnership() writes owner/pendingOwner with NO one-time
    latch (by design — it's a repeatable acceptance step, not a
    single-use initializer), but IS genuinely protected by a real
    msg.sender comparison against pendingOwner, a value only the
    current owner could have set. A one-time latch is not the only
    valid protection — genuine msg.sender-based auth is equally valid.
    Must NOT flag.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["Ownable2StepStyleAccept.acceptOwnership()"]
    assert fn.unprotected_initializer_write is None, f"genuinely auth-gated acceptOwnership() must not flag, got {fn.unprotected_initializer_write}"
    print("test_ownable2step_style_accept_does_not_false_positive: PASS")


def test_metamorpho_style_timelock_gated_accept_does_not_false_positive():
    """
    Live-verification regression: found firing on Morpho Labs' actual,
    currently-deployed MetaMorpho.acceptGuardian() (CONFIRMED, 99%
    through the full pipeline). acceptOwner() writes owner (privileged)
    with no one-time latch and no msg.sender check — it's genuinely
    permissionless — but is gated by afterTimelock(pendingOwner.validAt),
    a real elapsed-time delay since submitOwner's own onlyOwner call
    scheduled it. A time-delay gate against an externally-sourced
    deadline is a real, distinct protective mechanism. Must NOT flag.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["TimelockGatedAccept.acceptOwner()"]
    assert fn.unprotected_initializer_write is None, f"real MetaMorpho-style timelock-gated accept must not flag, got {fn.unprotected_initializer_write}"
    print("test_metamorpho_style_timelock_gated_accept_does_not_false_positive: PASS")


def test_fake_timelock_does_not_suppress_finding():
    """
    Critical adversarial regression: proves the fix checks the
    deadline's actual PROVENANCE, not just "some elapsed-time
    comparison exists somewhere". The deadline here is freshly
    computed WITHIN the same call, from the current block.timestamp —
    pure theater, zero protection. Must still fire.
    """
    nodes, *_ = _build("UnprotectedInit.sol")
    fn = nodes["FakeTimelockDoesNotSuppressFinding.acceptOwner(address)"]
    assert fn.unprotected_initializer_write is not None, "a same-call, freshly-computed fake deadline must not suppress the real finding"
    print("test_fake_timelock_does_not_suppress_finding: PASS —",
          "evidence:", fn.unprotected_initializer_write)


def test_vat_style_self_scoped_permission_write_suppresses_finding():
    """
    Live-verification regression: found firing on the real, currently-
    deployed MakerDAO Vat.sol — one of the most important, highest-TVL
    contracts in all of DeFi. hope(usr)/nope(usr) write
    `can[msg.sender][usr]` — a per-caller delegate-permission mapping —
    with no one-time-latch and no msg.sender-based own-auth check
    (there's genuinely no identity check needed: the write can only
    ever land inside the CALLER's own subtree). The raw FunctionNode
    field still reports evidence (that's the correct, narrower claim —
    "this write is initializer-shaped"); the full constraint pipeline
    must suppress it via the same self-scoped-write exemption
    ACCESS_CONTROL_GAP already has. corruptGrant() proves this doesn't
    weaken detection: the identical mapping, with neither key
    self-scoped, must still fire CONFIRMED.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("UnprotectedInit.sol")

    hope = nodes["VatStyleSelfScopedPermission.hope(address)"]
    nope = nodes["VatStyleSelfScopedPermission.nope(address)"]
    assert hope.unprotected_initializer_write is not None, "raw field should still report evidence — the exemption applies at the constraint level"
    assert nope.unprotected_initializer_write is not None

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for safe_entry in ("VatStyleSelfScopedPermission.hope(address)", "VatStyleSelfScopedPermission.nope(address)"):
        safe_findings = [
            r for r in all_results
            if "UNPROTECTED_INITIALIZER" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} (real Vat shape) must not fire UNPROTECTED_INITIALIZER, got {safe_findings}"

    dangerous_findings = [
        r for r in report.confirmed
        if "UNPROTECTED_INITIALIZER" in r.constraint_type
        and r.path.entry == "VatStyleSelfScopedPermission.corruptGrant(address,address)"
    ]
    assert dangerous_findings, "corruptGrant() (neither key self-scoped) must still fire UNPROTECTED_INITIALIZER CONFIRMED"
    print("test_vat_style_self_scoped_permission_write_suppresses_finding: PASS —",
          "hope/nope suppressed, corruptGrant still", dangerous_findings[0].verdict)


def test_modifier_only_auth_evidence_exempts_unprotected_initializer():
    """
    Live-verification finding against MatrixDock's real, currently-
    deployed STBTv2 (a real RWA stablecoin): the real OpenZeppelin
    AccessControl.grantRole()/revokeRole() shape —
    `onlyRole(getRoleAdmin(role))`, a modifier invoked with a COMPUTED
    argument. Both false-positived UNPROTECTED_INITIALIZER despite
    being genuinely, correctly access-controlled.

    Root cause: core/graph.py's find_unprotected_initializer call was
    passed structural_auth_score — compute_own_auth(f) on the
    function's OWN body only — as the "is this already proven
    protected" exemption check. grantRole's own body is just
    `_grantRole(role, account);`, which carries zero auth evidence of
    its own; the real check lives entirely inside the attached
    onlyRole modifier. The EFFECTIVE score that folds in attached
    modifiers is computed in graph.py's later Layer 3b pass, but that
    runs only after find_unprotected_initializer had already been
    called with the too-narrow score.

    Fixed by scoring each attached modifier directly (compute_own_auth
    is safe to call again — modifiers are already real Slither
    objects on f regardless of node-build order) and taking the max
    with the function's own score before the exemption check.

    grantRoleUnsafe (FakeArgumentModifierIsNotRealAuth) proves this
    doesn't weaken detection: fakeGate takes an argument too
    (superficially resembling the real onlyRole(getRoleAdmin(role))
    shape) but its body performs no real check at all — a naive fix
    that exempted any function with an argument-taking modifier would
    wrongly suppress this. Must still fire CONFIRMED.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("UnprotectedInit.sol")

    grant_role = nodes["RoleBasedAccessControl.grantRole(bytes32,address)"]
    revoke_role = nodes["RoleBasedAccessControl.revokeRole(bytes32,address)"]
    assert grant_role.unprotected_initializer_write is None, (
        f"grantRole is genuinely onlyRole-gated (via its attached modifier) — must not report unprotected-initializer "
        f"evidence at all, got {grant_role.unprotected_initializer_write}"
    )
    assert revoke_role.unprotected_initializer_write is None
    assert grant_role.auth_score >= 3
    assert revoke_role.auth_score >= 3

    fake_gated = nodes["FakeArgumentModifierIsNotRealAuth.grantRoleUnsafe(bytes32,address)"]
    assert fake_gated.unprotected_initializer_write is not None, (
        "fakeGate performs no real check — must still report unprotected-initializer evidence"
    )
    assert fake_gated.auth_score < 3

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for safe_entry in ("RoleBasedAccessControl.grantRole(bytes32,address)", "RoleBasedAccessControl.revokeRole(bytes32,address)"):
        safe_findings = [r for r in all_results if r.path.entry == safe_entry]
        assert not safe_findings, f"{safe_entry} (real MatrixDock shape) must not fire any finding, got {safe_findings}"

    dangerous_findings = [
        r for r in report.confirmed
        if "UNPROTECTED_INITIALIZER" in r.constraint_type
        and r.path.entry == "FakeArgumentModifierIsNotRealAuth.grantRoleUnsafe(bytes32,address)"
    ]
    assert dangerous_findings, "grantRoleUnsafe() (fake, no-op modifier) must still fire UNPROTECTED_INITIALIZER CONFIRMED"
    print("test_modifier_only_auth_evidence_exempts_unprotected_initializer: PASS —",
          "grantRole/revokeRole suppressed, grantRoleUnsafe still", dangerous_findings[0].verdict)


def test_ternary_guarded_initializer_via_cfg_reachability_suppresses_finding():
    """
    Live-verification finding against SPOT Cash's real, currently-
    deployed Tranche.init() (a real ButtonTranche bond token): OZ
    v4.5.0's real Initializable.sol guards with a TERNARY inside its
    require():
        require(_initializing ? _isConstructor() : !_initialized, "...");
    Solidity lowers that ternary to actual IF/branch/ENDIF control
    flow. Confirmed live via direct IR probe against this exact real
    source: Slither's own flat .nodes list places those lowered nodes
    AFTER the modifier's PLACEHOLDER in list order, even though they
    execute BEFORE it (real order, per .sons/.fathers graph edges:
    ENTRYPOINT -> the ternary's IF/branch/ENDIF -> isTopLevelCall setup
    -> PLACEHOLDER -> the after-block). is_initializer_guard used to
    split before/after by flat list index, which put the require()'s
    _initialized read in the WRONG (after) set, so the one-time latch
    was never recognized despite being genuine and correctly
    implemented — Tranche.init() false-positived UNPROTECTED_
    INITIALIZER even though clone deployment + init() are atomic (no
    front-running window) AND init() has a real one-time latch.

    UnrelatedTernaryDoesNotSuppressFinding proves this doesn't weaken
    detection: its ternary condition reads a completely unrelated flag
    (never the variable actually being latched) — a naive fix that
    just "trusted any ternary/branch shape near the placeholder" would
    wrongly suppress this too. Must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("UnprotectedInit.sol")

    safe = nodes["TrancheStyleTernaryLatch.init(address)"]
    assert safe.unprotected_initializer_write is None, (
        f"real OZ v4.5.0 ternary-guarded initializer must not report unprotected-initializer evidence, "
        f"got {safe.unprotected_initializer_write}"
    )
    assert safe.has_initializer_guard is True

    dangerous = nodes["UnrelatedTernaryDoesNotSuppressFinding.init(address)"]
    assert dangerous.unprotected_initializer_write is not None, (
        "ternary checks the WRONG flag — must still report unprotected-initializer evidence"
    )
    assert dangerous.has_initializer_guard is False

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    safe_findings = [
        r for r in all_results
        if "UNPROTECTED_INITIALIZER" in r.constraint_type and r.path.entry == "TrancheStyleTernaryLatch.init(address)"
    ]
    assert not safe_findings, f"real SPOT Cash shape must not fire UNPROTECTED_INITIALIZER, got {safe_findings}"

    dangerous_findings = [
        r for r in report.confirmed
        if "UNPROTECTED_INITIALIZER" in r.constraint_type
        and r.path.entry == "UnrelatedTernaryDoesNotSuppressFinding.init(address)"
    ]
    assert dangerous_findings, "wrong-flag ternary must still fire UNPROTECTED_INITIALIZER CONFIRMED"
    print("test_ternary_guarded_initializer_via_cfg_reachability_suppresses_finding: PASS —",
          "TrancheStyleTernaryLatch suppressed, UnrelatedTernaryDoesNotSuppressFinding still", dangerous_findings[0].verdict)


def test_unprotected_initializer_constraint_fires_only_on_real_vulnerable_contracts():
    """
    End-to-end: runs the full path-enumeration + constraint-validation
    pipeline (not just the precomputed FunctionNode field) and checks
    the actual UNPROTECTED_INITIALIZER finding fires CONFIRMED on both
    genuinely vulnerable contracts and does not fire on any of the
    three protected/decoy contracts. Also confirms the gate on
    core/sinks.py's own STORAGE_CORRUPTION sink classification (not a
    hand-rolled auth-var list) is what makes `owner` count as
    privileged here — proven by the onlyOwner-gated withdraw()
    function present in every contract.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("UnprotectedInit.sol")
    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    for vulnerable_entry in (
        "ParityStyleWallet.initWallet(address)",
        "NonReentrantIsNotAnInitializerGuard.initialize(address)",
        "FakeTimelockDoesNotSuppressFinding.acceptOwner(address)",
    ):
        vulnerable_findings = [
            r for r in report.confirmed
            if "UNPROTECTED_INITIALIZER" in r.constraint_type and r.path.entry == vulnerable_entry
        ]
        assert vulnerable_findings, f"{vulnerable_entry} must fire UNPROTECTED_INITIALIZER CONFIRMED"

    for safe_entry in (
        "ProtectedInitializable.initialize(address)",
        "InlineGuardedInit.initialize(address)",
        "ConstructorOnly.constructor(address)",
        "TimelockGatedAccept.acceptOwner()",
    ):
        safe_findings = [
            r for r in all_results
            if "UNPROTECTED_INITIALIZER" in r.constraint_type and r.path.entry == safe_entry
        ]
        assert not safe_findings, f"{safe_entry} must not fire UNPROTECTED_INITIALIZER, got {safe_findings}"

    print("test_unprotected_initializer_constraint_fires_only_on_real_vulnerable_contracts: PASS —",
          "both vulnerable entries CONFIRMED, all three safe/decoy contracts correctly unflagged")


if __name__ == "__main__":
    test_unguarded_owner_write_detected()
    test_oz_initializer_modifier_suppresses_finding()
    test_inline_self_referential_guard_suppresses_finding()
    test_reentrancy_guard_does_not_suppress_finding()
    test_real_constructor_does_not_false_positive()
    test_internal_helper_does_not_false_positive()
    test_ownable2step_style_accept_does_not_false_positive()
    test_metamorpho_style_timelock_gated_accept_does_not_false_positive()
    test_fake_timelock_does_not_suppress_finding()
    test_vat_style_self_scoped_permission_write_suppresses_finding()
    test_modifier_only_auth_evidence_exempts_unprotected_initializer()
    test_ternary_guarded_initializer_via_cfg_reachability_suppresses_finding()
    test_unprotected_initializer_constraint_fires_only_on_real_vulnerable_contracts()
    print("\nAll initializer_detection tests passed.")
