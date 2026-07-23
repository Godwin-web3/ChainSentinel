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


def test_unchecked_return_requires_real_dataflow_evidence():
    """
    Reproduces the real finding that core/constraints.py::
    _check_unchecked_return fired on ANY low-level call regardless of
    whether its return was validated. withdraw() (checked via
    `require(ok, ...)`) must NOT fire UNCHECKED_RETURN; withdrawUnchecked()
    (return value fully discarded) must.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    checked_edges = [e for e in graph_edges.get("ReentrancyEdgeCases.withdraw()", []) if e.raw_type == "lowlevel_call"]
    assert checked_edges and checked_edges[0].return_checked is True

    unchecked_edges = [
        e for e in graph_edges.get("ReentrancyEdgeCases.withdrawUnchecked()", []) if e.raw_type == "lowlevel_call"
    ]
    assert unchecked_edges and unchecked_edges[0].return_checked is False

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    checked_findings = [
        r for r in all_results
        if r.path.entry == "ReentrancyEdgeCases.withdraw()" and "UNCHECKED_RETURN" in r.constraint_type
    ]
    assert not checked_findings, f"withdraw() checks its return via require(ok, ...) — must not fire, got {checked_findings}"

    unchecked_findings = [
        r for r in all_results
        if r.path.entry == "ReentrancyEdgeCases.withdrawUnchecked()" and "UNCHECKED_RETURN" in r.constraint_type
    ]
    assert unchecked_findings, "withdrawUnchecked() discards its return value entirely — must fire"
    print("test_unchecked_return_requires_real_dataflow_evidence: PASS —",
          "withdraw() suppressed, withdrawUnchecked() still", unchecked_findings[0].verdict)


def test_trusted_interface_cast_destination_excludes_callback_sink():
    """
    Reproduces the real Convex Booster false positive found live this
    session: admin-only functions (setFeeInfo/shutdownPool/
    shutdownSystem) call out to `registry` (a constant) and `staker`
    (a constructor-set immutable) via the standard interface-cast
    pattern (IFoo(stateVar).bar()) — both genuinely trusted, fixed
    destinations, but two compounding bugs in core/edges.py's trust
    resolution (a broken TemporaryVariable import path, and Slither's
    synthetic constant-variable initializer not being recognized as
    constructor-equivalent) made them score trusted=False regardless.

    adminOnlyAction() (registry/staker, both fixed) must not classify
    as a sink at all. attackerControlled() (an arbitrary parameter)
    proves this doesn't weaken detection — must still classify
    CALLBACK_SINK and fire REENTRANCY_CEI.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("TrustedCalleeReentrancy.sol")

    safe_edges = [e for e in graph_edges.get("TrustedCalleeReentrancy.adminOnlyAction()", []) if e.is_external]
    assert safe_edges and all(e.trusted for e in safe_edges), (
        f"registry (constant) and staker (constructor-set immutable) are both genuinely fixed — must score trusted=True, got {safe_edges}"
    )

    dangerous_edges = [e for e in graph_edges.get("TrustedCalleeReentrancy.attackerControlled(address)", []) if e.is_external]
    assert dangerous_edges and not any(e.trusted for e in dangerous_edges), (
        "an arbitrary caller-supplied parameter must not score trusted=True"
    )

    sinks = classify_sinks(nodes, graph_edges)
    assert sinks.get("TrustedCalleeReentrancy.adminOnlyAction()") is None, (
        "a call to a genuinely trusted, fixed destination is not a reentrancy surface — must not classify as any sink"
    )
    assert sinks.get("TrustedCalleeReentrancy.attackerControlled(address)") is not None

    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    safe_findings = [r for r in all_results if r.path.entry == "TrustedCalleeReentrancy.adminOnlyAction()"]
    assert not safe_findings, f"adminOnlyAction() only calls trusted, fixed destinations — must have zero findings, got {safe_findings}"

    dangerous_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "TrustedCalleeReentrancy.attackerControlled(address)" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert dangerous_findings, "attackerControlled() calls an arbitrary caller-supplied destination — REENTRANCY_CEI must still fire"
    print("test_trusted_interface_cast_destination_excludes_callback_sink: PASS —",
          "adminOnlyAction 0 findings, attackerControlled still", dangerous_findings[0].verdict)


def test_cei_check_is_order_aware_not_co_occurrence():
    """
    Reproduces the real Liquity StabilityPool false positive found live
    this session: _sendETHGainToDepositor writes `ETH = newETH` BEFORE
    its `msg.sender.call{value: _amount}("")` — CEI-compliant for that
    variable, confirmed via real node order — but the old co-occurrence
    check ("does this function have both a state write and an external
    call ANYWHERE") flagged it regardless of order.

    withdrawOrdered() (write before call) must NOT fire REENTRANCY_CEI;
    withdraw() (write after call, from the earlier test) already proves
    the genuine violation still fires — this test confirms the two are
    correctly told apart at the FunctionNode field level too.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    ordered = nodes["ReentrancyEdgeCases.withdrawOrdered()"]
    unordered = nodes["ReentrancyEdgeCases.withdraw()"]
    assert ordered.state_write_follows_external_call is False, (
        "withdrawOrdered() writes balance BEFORE its external call — must not be flagged as order-violating"
    )
    assert unordered.state_write_follows_external_call is True, (
        "withdraw() writes balance AFTER its external call — must be flagged as order-violating"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    ordered_findings = [
        r for r in all_results
        if r.path.entry == "ReentrancyEdgeCases.withdrawOrdered()" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert not ordered_findings, f"withdrawOrdered() is CEI-compliant by ordering — must not fire, got {ordered_findings}"
    print("test_cei_check_is_order_aware_not_co_occurrence: PASS — withdrawOrdered() correctly suppressed")


def test_health_check_recognizes_trusted_external_dependency():
    """
    Reproduces the real Liquity StabilityPool false positive found live
    this session: withdrawFromSP() calls _requireNoUnderCollateralizedTroves()
    as a sibling guard — its entire condition comes from
    priceFeed.fetchPrice()/sortedTroves.getLast()/troveManager.
    getCurrentICR(...), all fixed, protocol-governed contracts, never
    touching StabilityPool's OWN state — invisible to the old
    local-storage-overlap-only check.

    withdraw() (real, trusted oracle) must NOT fire MISSING_HEALTH_CHECK.
    withdrawUnsafe() (attacker-supplied oracle, same shape) proves this
    doesn't weaken detection — must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ExternalHealthCheck.sol")

    guard = nodes["ExternalHealthCheck._requireHealthySystem()"]
    assert guard.has_revert_capable_body is True

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    safe_findings = [
        r for r in all_results
        if r.path.entry == "ExternalHealthCheck.withdraw(uint256)" and "MISSING_HEALTH_CHECK" in r.constraint_type
    ]
    assert not safe_findings, f"withdraw() is guarded by a trusted external oracle check — must not fire, got {safe_findings}"

    unsafe_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "ExternalHealthCheck.withdrawUnsafe(uint256,IPriceOracle)" and "MISSING_HEALTH_CHECK" in r.constraint_type
    ]
    assert unsafe_findings, "withdrawUnsafe()'s oracle is attacker-supplied, not trusted — MISSING_HEALTH_CHECK must still fire"
    print("test_health_check_recognizes_trusted_external_dependency: PASS —",
          "withdraw suppressed, withdrawUnsafe still", unsafe_findings[0].verdict)


def test_view_call_not_misclassified_as_reentrancy_or_flashloan_vector():
    """
    Reproduces the real false positive found live this session against
    Velodrome's Pool.setName(): its only external interaction,
    `IVoter(_voter).emergencyCouncil()`, is a view function — compiles
    to STATICCALL under the hood, the same EVM guarantee already
    carved out for an explicit .staticcall(...). core/edges.py::
    _semantic_properties gave every "highlevel" call is_state_crossing
    =True unconditionally, with no reference to the resolved callee's
    own declared mutability, so REENTRANCY_CEI and FLASHLOAN_WINDOW
    both fired on a call structurally incapable of reentering.

    Also proves this doesn't weaken detection:
    setNameViaMutatingCall() is structurally identical (same auth-check
    shape, same state write) except its external call is to a real
    non-view function — must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_id = "ReentrancyEdgeCases.setNameLikeVelodrome(string)"
    safe_findings = [
        r for r in all_results
        if r.path.entry == safe_id and ("REENTRANCY_CEI" in r.constraint_type or "FLASHLOAN_WINDOW" in r.constraint_type)
    ]
    assert not safe_findings, f"setNameLikeVelodrome()'s only external call is view-only — must not fire, got {safe_findings}"

    dangerous_id = "ReentrancyEdgeCases.setNameViaMutatingCall(string)"
    dangerous_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous_id and ("REENTRANCY_CEI" in r.constraint_type or "FLASHLOAN_WINDOW" in r.constraint_type)
    ]
    assert dangerous_findings, "setNameViaMutatingCall()'s external call is a real state-mutating function — must still fire"
    print("test_view_call_not_misclassified_as_reentrancy_or_flashloan_vector: PASS —",
          "setNameLikeVelodrome suppressed, setNameViaMutatingCall still", dangerous_findings[0].verdict)


def test_constant_variable_getter_not_misclassified_as_reentrancy_vector():
    """
    Reproduces the real false positive found live this session against
    Takara Lend (a real Compound V2 fork deployed on Sei):
    TToken._setComptroller() calls `newComptroller.isComptroller()`,
    where `isComptroller` is `bool public constant` on an abstract base
    contract. Slither resolves that call's ir.function to a
    StateVariable, not a Function — so it carries no .view/.pure
    attribute at all, and core/edges.py::_semantic_properties'
    view/pure carve-out (built for the Velodrome fix above) silently
    fell through to "unknown mutability, treat as dangerous."

    Also proves this doesn't weaken detection:
    setNameViaFakeMarker() is structurally identical (same call shape,
    same state write) except the callee is a real function that can
    have side effects, not an auto-generated constant-variable getter —
    must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible + report.suppressed

    safe_id = "ReentrancyEdgeCases.setNameViaConstantMarker(string)"
    safe_findings = [
        r for r in all_results
        if r.path.entry == safe_id and ("REENTRANCY_CEI" in r.constraint_type or "FLASHLOAN_WINDOW" in r.constraint_type)
    ]
    assert not safe_findings, f"setNameViaConstantMarker()'s only external call is a constant-variable getter — must not fire, got {safe_findings}"

    dangerous_id = "ReentrancyEdgeCases.setNameViaFakeMarker(string)"
    dangerous_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == dangerous_id and ("REENTRANCY_CEI" in r.constraint_type or "FLASHLOAN_WINDOW" in r.constraint_type)
    ]
    assert dangerous_findings, "setNameViaFakeMarker()'s external call is a real function, not a constant getter — must still fire"
    print("test_constant_variable_getter_not_misclassified_as_reentrancy_vector: PASS —",
          "setNameViaConstantMarker suppressed, setNameViaFakeMarker still", dangerous_findings[0].verdict)


def test_local_cache_guard_read_detected_without_coincidental_match():
    """
    Live-verification regression against the real, currently-deployed
    Uniswap V3 UniswapV3Pool.sol source.

    swapLikeUniswapV3() reproduces swap()'s real inline-guard shape: the
    revert-capable check reads a LOCAL cache of the state variable
    (`Slot0 memory slot0Start = slot0;` then
    `require(slot0Start.unlocked, "LOK")`), one hop removed from the
    direct state write (`slot0.unlocked = false`) —
    _guard_shape_from_before_after originally required the revert node
    to read the candidate STATE variable directly, missing this real,
    extremely common cache-then-check gas optimization. Must be
    suppressed.

    flashLikeUniswapV3WithoutRealGuard() reproduces the critical
    adversarial regression found live verifying flash(): two UNRELATED
    compound-assignment accumulator writes to the same struct
    (protocolFees.token0/token1 += ...) plus an unrelated
    require(liquidity > 0) elsewhere coincidentally satisfied the
    OLD, looser check ("some candidate read somewhere" AND "some
    revert-capable node somewhere", checked independently) with zero
    actual guard relationship. Must NOT be suppressed — REENTRANCY_CEI
    must still fire.
    """
    nodes, graph_edges, state_writers, state_readers, invariant_index, _ = _build("ReentrancyEdgeCases.sol")

    real_cache_guard = nodes["ReentrancyEdgeCases.swapLikeUniswapV3()"]
    coincidental = nodes["ReentrancyEdgeCases.flashLikeUniswapV3WithoutRealGuard()"]
    assert real_cache_guard.has_inline_reentrancy_guard is True, (
        "swapLikeUniswapV3()'s require reads a local cache of the state variable one hop removed — must be recognized"
    )
    assert coincidental.has_inline_reentrancy_guard is False, (
        "flashLikeUniswapV3WithoutRealGuard()'s two accumulator writes and unrelated require() must not coincidentally match"
    )

    sinks = classify_sinks(nodes, graph_edges)
    paths = enumerate_paths(nodes, graph_edges, sinks)
    report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)
    all_results = report.confirmed + report.likely + report.possible

    guarded_findings = [
        r for r in all_results
        if r.path.entry == "ReentrancyEdgeCases.swapLikeUniswapV3()" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert not guarded_findings, f"swapLikeUniswapV3() has a real inline guard — must be suppressed, got {guarded_findings}"

    coincidental_findings = [
        r for r in (report.confirmed + report.likely)
        if r.path.entry == "ReentrancyEdgeCases.flashLikeUniswapV3WithoutRealGuard()" and "REENTRANCY_CEI" in r.constraint_type
    ]
    assert coincidental_findings, "flashLikeUniswapV3WithoutRealGuard() has no real guard — REENTRANCY_CEI must still fire"
    print("test_local_cache_guard_read_detected_without_coincidental_match: PASS —",
          "swapLikeUniswapV3 suppressed, flashLikeUniswapV3WithoutRealGuard still", coincidental_findings[0].verdict)


if __name__ == "__main__":
    test_entry_level_cei_violation_detected()
    test_staticcall_not_misclassified_as_asset_drain_or_callback()
    test_inline_reentrancy_guard_detected_without_weakening()
    test_unchecked_return_requires_real_dataflow_evidence()
    test_trusted_interface_cast_destination_excludes_callback_sink()
    test_cei_check_is_order_aware_not_co_occurrence()
    test_health_check_recognizes_trusted_external_dependency()
    test_view_call_not_misclassified_as_reentrancy_or_flashloan_vector()
    test_constant_variable_getter_not_misclassified_as_reentrancy_vector()
    test_local_cache_guard_read_detected_without_coincidental_match()
    print("\nAll reentrancy_edges tests passed.")
