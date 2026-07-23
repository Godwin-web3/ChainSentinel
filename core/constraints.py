"""
core/constraints.py — Invariant validation layer

Takes exploit paths from paths.py and validates them against
protocol-level constraints. Drops paths that are not exploitable.
Elevates paths that violate real invariants.

Six constraint categories, grounded in real DeFi exploit history:

  REENTRANCY_CEI      checks-effects-interactions violated (Fei $80M, Cream $130M)
  ACCESS_CONTROL_GAP  public function reaches privileged sink (majority of 2024 losses)
  MISSING_HEALTH_CHECK asset-moving function skips solvency validation (Euler $197M)
  ORACLE_DEPENDENCY   asset flow reads from manipulable price source (bZx, Mango $116M)
  FLASHLOAN_WINDOW    state read and write separated by external callback (most flash loan hacks)
  UNCHECKED_RETURN    low-level call return value ignored (silent failure pattern)

Each constraint produces:
  verdict: CONFIRMED | LIKELY | POSSIBLE | SUPPRESSED
  confidence: 0-100
  reasoning: human-readable explanation
  immunefi_impact: what Immunefi category this maps to
"""

from dataclasses import dataclass, field
from typing import List, Set, Optional
from core.paths import ExploitPath
from core.sinks import (
    ASSET_DRAIN, STORAGE_CORRUPTION, DELEGATION_SINK,
    CALLBACK_SINK, SELFDESTRUCT_SINK,
)
from core.edges import CallEdge

# ── Verdict constants ─────────────────────────────────────────────

CONFIRMED  = "CONFIRMED"   # high confidence, minimal FP risk
LIKELY     = "LIKELY"      # strong signal, needs manual confirmation
POSSIBLE   = "POSSIBLE"    # weak signal, worth investigating
SUPPRESSED = "SUPPRESSED"  # path is NOT exploitable — drop it
CROSS_FUNCTION_STATE_RACE = "CROSS_FUNCTION_STATE_RACE"

VERDICT_SCORE = {
    CONFIRMED:  100,
    LIKELY:     70,
    POSSIBLE:   40,
    SUPPRESSED: 0,
}

# Whether an unauthenticated path to an asset-moving sink is "expected,
# not exploitable" is decided structurally — see core/auth_detection.py
# ::find_self_scoped_asset_moves — never by matching the entry
# function's name against a list of common DeFi verb names. A function
# named `swap`/`deposit`/`supply`/etc. gets no special treatment; a
# custom-named function with the same real proof (moves only funds the
# caller already approved, or sends value only back to the caller) is
# treated identically.

# Reentrancy guards are detected structurally — see
# core/auth_detection.py::is_reentrancy_guard, computed once per modifier
# in core/graph.py and looked up via FunctionNode.is_reentrancy_guard /
# modifier_ids. No name list needed.

# ── Data model ────────────────────────────────────────────────────

@dataclass
class ConstraintResult:
    path: ExploitPath
    verdict: str                    # CONFIRMED / LIKELY / POSSIBLE / SUPPRESSED
    confidence: int                 # 0-100
    constraint_type: str            # which constraint fired
    reasoning: str                  # human-readable
    immunefi_impact: str            # Immunefi impact category
    final_score: int                # path_score * confidence multiplier


@dataclass
class ValidationReport:
    confirmed: List[ConstraintResult] = field(default_factory=list)
    likely: List[ConstraintResult] = field(default_factory=list)
    possible: List[ConstraintResult] = field(default_factory=list)
    suppressed: List[ConstraintResult] = field(default_factory=list)

    def all_findings(self) -> List[ConstraintResult]:
        return sorted(
            self.confirmed + self.likely + self.possible,
            key=lambda x: x.final_score,
            reverse=True
        )

    def total(self) -> int:
        return len(self.confirmed) + len(self.likely) + len(self.possible)


# ── Public API ────────────────────────────────────────────────────

def validate_paths(
    paths: List[ExploitPath],
    nodes: dict,
    graph_edges: dict,
    state_writers: dict = None,
    state_readers: dict = None,
    invariant_index: dict = None,
) -> ValidationReport:
    """
    Validate all exploit paths against protocol invariants.

    Args:
        paths:       from paths.enumerate_paths()
        nodes:       from graph.build_graph()
        graph_edges: from graph.build_graph()

    Returns:
        ValidationReport with findings bucketed by confidence
    """
    report = ValidationReport()

    for path in paths:
        result = _validate_path(path, nodes, graph_edges, state_writers, state_readers, invariant_index)
        if result.verdict == CONFIRMED:
            report.confirmed.append(result)
        elif result.verdict == LIKELY:
            report.likely.append(result)
        elif result.verdict == POSSIBLE:
            report.possible.append(result)
        else:
            report.suppressed.append(result)

    return report


# ── Per-path validation ───────────────────────────────────────────

def _validate_path(
    path: ExploitPath,
    nodes: dict,
    graph_edges: dict,
    state_writers: dict = None,
    state_readers: dict = None,
    invariant_index: dict = None,
) -> ConstraintResult:
    """
    Run all constraint checks on a single path.
    Aggregates all non-suppressed signals into one result.
    Multiple firing constraints compound confidence and upgrade verdict.
    """
    results = []

    results.append(_check_reentrancy_cei(path, nodes, graph_edges))
    results.append(_check_access_control_gap(path, nodes, graph_edges))
    results.append(_check_missing_health_check(path, nodes, graph_edges))
    results.append(_check_oracle_dependency(path, nodes, graph_edges))
    results.append(_check_flashloan_window(path, nodes, graph_edges))
    results.append(_check_unchecked_return(path, nodes, graph_edges))
    results.append(_check_share_inflation(path, nodes, graph_edges))
    if invariant_index is not None:
        results.append(_check_cross_function_state_race(path, nodes, graph_edges, invariant_index))

    non_suppressed = [r for r in results if r.verdict != SUPPRESSED]

    if not non_suppressed:
        return _suppressed(path, "No constraint violations found on this path")

    if len(non_suppressed) == 1:
        return non_suppressed[0]

    # Aggregate multiple signals — diminishing returns per additional constraint
    sorted_results = sorted(non_suppressed, key=lambda r: r.confidence, reverse=True)
    base = sorted_results[0].confidence
    bonus = sum(
        r.confidence * (0.5 ** i)
        for i, r in enumerate(sorted_results[1:], 1)
    )
    combined_confidence = min(99, int(base + bonus))

    # Verdict upgrades when multiple constraints fire together.
    # A single CONFIRMED is pinned — it must NOT be downgraded by the
    # presence of a weaker second signal. Previous logic let CONFIRMED
    # fall through to the elif branch (LIKELY) when combined_confidence
    # dropped below 90 due to a weak secondary constraint.
    verdicts = [r.verdict for r in sorted_results]
    if verdicts.count(CONFIRMED) >= 1 or combined_confidence >= 90:
        verdict = CONFIRMED
    elif combined_confidence >= 70:
        verdict = LIKELY
    else:
        verdict = POSSIBLE

    constraint_types = " + ".join(r.constraint_type for r in sorted_results)
    reasoning = (
        f"[{len(non_suppressed)} constraints fired] {constraint_types}\n" +
        "\n".join(f"  [{r.constraint_type}] {r.reasoning[:120]}" for r in sorted_results)
    )

    return ConstraintResult(
        path=path,
        verdict=verdict,
        confidence=combined_confidence,
        constraint_type=constraint_types,
        reasoning=reasoning,
        immunefi_impact=sorted_results[0].immunefi_impact,
        final_score=_final_score(path, combined_confidence),
    )


# ── Constraint 1: Reentrancy / CEI violation ─────────────────────

def _has_state_crossing_external_call(path, nodes, graph_edges) -> bool:
    """
    True if at least one external call reachable on this path can
    actually mutate state during the call — core/edges.py::CallEdge.
    is_state_crossing, NOT the coarser is_external. A "highlevel" call
    to a view/pure function (e.g. real Velodrome's setName() calling
    `IVoter(_voter).emergencyCouncil()`) IS external — it does leave
    this contract — but compiles to STATICCALL under the hood, so the
    EVM itself guarantees it can never write state or re-enter, making
    it structurally incapable of being a reentrancy/callback vector
    regardless of what state this function writes around it.

    Deliberately narrower than the path's own coarse EXTERNAL_CALL
    flag (core/paths.py), which several OTHER constraints (
    ORACLE_DEPENDENCY, general asset-flow tracing) correctly still key
    off "crosses a trust boundary at all" — reading a price from a
    view call is exactly what THOSE checks care about. Only
    REENTRANCY_CEI and FLASHLOAN_WINDOW specifically need "can this
    call loop back and touch our own state," so only they call this.

    Checks both the entry's own outgoing edges and every edge in the
    path's own edge_chain — a 0-hop path (the vulnerable function is
    both entry and sink, e.g. setName()) only has entry-level edges;
    a multi-hop path's relevant call may be on an intermediate edge.
    """
    entry_edges = graph_edges.get(path.entry, [])
    if any(e.is_external and e.is_state_crossing for e in entry_edges):
        return True
    return any(e.is_external and e.is_state_crossing for e in path.edge_chain)


def _check_reentrancy_cei(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect checks-effects-interactions violation.
    Pattern: state written BEFORE external call, no reentrancy guard.
    Real exploits: Fei Protocol $80M, Cream Finance $130M, BurgerSwap $7.2M
    """
    flags = path.constraint_flags
    entry_node = nodes.get(path.entry)

    if "STATE_BEFORE_CALL" not in flags or "EXTERNAL_CALL" not in flags:
        return _suppressed(path, "No CEI violation signal")

    if not _has_state_crossing_external_call(path, nodes, graph_edges):
        return _suppressed(
            path,
            "Every external call on this path is view/pure (STATICCALL under "
            "the hood) — structurally incapable of reentering or mutating state"
        )

    # Check for a structurally-real reentrancy guard (core/auth_detection.py
    # ::is_reentrancy_guard — a modifier that reads/checks a status
    # variable, writes it before its own PLACEHOLDER node, and restores
    # it after) on the entry function, looked up by modifier_ids, never
    # by matching a modifier's name against a string. Also checks
    # has_inline_reentrancy_guard — the same structural shape flattened
    # directly into a REGULAR function's own body instead of a modifier
    # (real shape: Uniswap V3's swap(), which inlines its own `lock`
    # modifier's exact logic for gas on its single hottest-path
    # function, found live this session).
    def _guarded(node) -> bool:
        if node is None:
            return False
        if getattr(node, 'has_inline_reentrancy_guard', False):
            return True
        return any(
            nodes[mid].is_reentrancy_guard
            for mid in getattr(node, 'modifier_ids', [])
            if mid in nodes
        )

    has_guard = _guarded(entry_node)

    # Check if guard appears anywhere in call chain
    if not has_guard:
        for edge in path.edge_chain:
            callee = nodes.get(edge.dst)
            if _guarded(callee):
                has_guard = True
                break

    if has_guard:
        return _suppressed(path, "Reentrancy guard detected on call chain")

    # No guard, CEI violated. CALLBACK_SINK is the reentrancy surface
    # itself (external call with open state) — same tier as ASSET_DRAIN.
    # Previous logic capped CALLBACK_SINK at 75 (LIKELY), missing the
    # Fei/Cream pattern where the callback IS the exploit vector.
    confidence = 75
    if path.sink.category in (ASSET_DRAIN, CALLBACK_SINK):
        confidence = 90  # external call + state write + drain/callback = strong signal

    return ConstraintResult(
        path=path,
        verdict=CONFIRMED if confidence >= 85 else LIKELY,
        confidence=confidence,
        constraint_type="REENTRANCY_CEI",
        reasoning=(
            f"State written before external call with no reentrancy guard. "
            f"Entry: {path.entry}. "
            f"External call to: {_first_external(path.edge_chain)}. "
            f"Sink: {path.sink.node_id} ({path.sink.category}). "
            f"Pattern matches Fei/Cream style reentrancy."
        ),
        immunefi_impact="Direct theft of user funds",
        final_score=_final_score(path, confidence),
    )



def _auth_check_in_subgraph(node_id: str, nodes: dict, graph_edges: dict, depth: int = 3, _visited: set = None) -> bool:
    """
    Recursively walk the call graph from node_id up to `depth` hops.
    Returns True if any callee has real structural auth evidence.

    callee.auth_score is the EFFECTIVE score computed in
    core/graph.py's second pass — it already folds in the callee's own
    body evidence (a real msg.sender/tx.origin comparison or role-mapping
    lookup, core/auth_detection.py) AND its attached modifiers' own
    evidence, by canonical_id lookup, never by matching a modifier's or
    function's name against a string. A single threshold check here
    covers both cases without re-deriving them.
    """
    if _visited is None:
        _visited = set()
    if depth == 0 or node_id in _visited:
        return False
    _visited.add(node_id)

    for edge in graph_edges.get(node_id, []):
        callee = nodes.get(edge.dst)
        if callee and getattr(callee, 'auth_score', 0) >= 2:
            return True
        if _auth_check_in_subgraph(edge.dst, nodes, graph_edges, depth - 1, _visited):
            return True
    return False

# ── Constraint 2: Access control gap ─────────────────────────────

def _entry_has_direct_auth(node_id: str, nodes: dict) -> bool:
    """
    Check whether the entry function ITSELF carries real structural auth
    evidence, without walking the call subgraph.

    _auth_check_in_subgraph only inspects callees reached FROM node_id;
    it never looks at node_id's own evidence. This misses:
      - inline checks, e.g. if (keepers[account] != msg.sender) revert ...
      - modifiers applied directly to the entry function
    Both are real auth enforcement the callee-only walk can't see.
    entry_node.auth_score already folds in both (see core/graph.py's
    second pass and core/auth_detection.py) — a custom-named modifier
    enforcing require(msg.sender == pendingOwner) scores identically to
    one named onlyOwner.
    """
    entry_node = nodes.get(node_id)
    if not entry_node:
        return False
    return getattr(entry_node, 'auth_score', 0) >= 2


def _check_access_control_gap(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect unprotected path to privileged sink.
    Pattern: UNAUTHENTICATED entrypoint reaches STORAGE_CORRUPTION or DELEGATION_SINK.
    Real exploits: Ronin $625M, Wormhole $320M, most 2024 losses.
    """
    flags = path.constraint_flags

    if "AUTH_GAP" not in flags:
        return _suppressed(path, "No auth gap on path")

    # Deep auth check: walk call graph up to 3 hops before issuing verdict
    # Catches borrow() -> _validateBorrow() -> IIngress.validateBorrow()
    if _entry_has_direct_auth(path.entry, nodes):
        return _suppressed(path, "Auth enforced directly on entry function (modifier or inline check) - not a real gap")

    if _auth_check_in_subgraph(path.entry, nodes, graph_edges, depth=3):
        return _suppressed(path, "Auth enforced in call subgraph — not a real gap")

    # Self-scoped write: the sink's privileged write is PROVABLY keyed by
    # the caller's own identity (core/auth_detection.py::
    # find_self_scoped_writes, e.g. AccessControl.renounceRole's
    # require(account == _msgSender()) before writing
    # _roles[role].members[account]) — an attacker reaching this can only
    # ever corrupt their OWN storage slot, never another user's. This is
    # NOT "no auth gap" in general (there's no admin gate here by
    # design — renouncing your own role is meant to be permissionless);
    # it's a narrower, sink-specific claim that THIS particular privileged
    # write is safe regardless. Only fires when EVERY privileged write key
    # on the sink is self-scoped — a sink with even one write that isn't
    # (e.g. a function that also corrupts an unrelated victim's storage)
    # is deliberately excluded from self_scoped_write_keys entirely by
    # find_self_scoped_writes, so this stays conservative.
    #
    # Also folds in self-scoped LIABILITY REDUCTIONS (core/
    # auth_detection.py::find_self_scoped_liability_reductions): a
    # decrease-write (x -= y) whose subtracted amount is PROVABLY the
    # same root value as a real inbound payment from msg.sender.
    # Reproduces the real repayAsset()/liquidate() false positive found
    # live against Fraxlend's FraxlendPairCore: _repayAsset() reduces
    # userBorrowShares[_borrower] for an ARBITRARY _borrower (the
    # standard permissionless repayBehalf pattern — repaying someone
    # else's debt is a gift to the protocol, not an attack), which the
    # write-keyed check above can't recognize because the beneficiary is
    # never msg.sender. Safety instead comes from the write's magnitude
    # being provably funded by msg.sender's own payment, computed from
    # the same root value — a decoupled amount (e.g. paying 1 wei to
    # erase a real, unrelated debt) is excluded from this set entirely
    # by find_self_scoped_liability_reductions, so this stays just as
    # conservative as the write-keyed check.
    if path.sink.category == STORAGE_CORRUPTION and path.sink.privileged_writes:
        entry_node = nodes.get(path.entry)
        self_scoped = getattr(entry_node, "self_scoped_write_keys", set()) if entry_node else set()
        self_funded = getattr(entry_node, "self_scoped_liability_reduction_keys", set()) if entry_node else set()
        combined = self_scoped | self_funded
        if combined and path.sink.privileged_writes.issubset(combined):
            return _suppressed(
                path,
                f"All privileged writes on this path ({path.sink.evidence}) are provably "
                f"either keyed by the caller's own identity, or decrease-writes funded by "
                f"a correlated payment from the caller (repayBehalf-style) — not an "
                f"exploitable access-control gap"
            )

    # Self-scoped asset move: replaces name-matching against a list of
    # common DeFi verbs (swap/deposit/withdraw/supply/...) — see
    # core/auth_detection.py::find_self_scoped_asset_moves. The SINK
    # function's own asset-moving operations (reached from this entry,
    # with real parameter-binding carried across the call) are ALL
    # provably safe: either every transferFrom's `from` is msg.sender
    # (the caller only ever spends funds they've already approved — the
    # real shape behind permissionless supply()/deposit()), or every
    # transfer()/ETH send's `to` is msg.sender (the caller only ever
    # receives value back to themselves — the real shape behind
    # Liquity's withdrawFromSP() -> _sendETHGainToDepositor(), found
    # live this session). A sink function with even one unsafe move
    # (an arbitrary-recipient transfer, or pulling an unrelated victim's
    # approved funds) is excluded from self_scoped_asset_move_functions
    # entirely by find_self_scoped_asset_moves, so this stays
    # conservative — it does NOT cover AMM-invariant-based safety
    # (swap/addLiquidity/flashloan), which is a genuinely different,
    # harder question this check makes no claim about.
    if path.sink.category == ASSET_DRAIN:
        entry_node = nodes.get(path.entry)
        safe_functions = getattr(entry_node, "self_scoped_asset_move_functions", set()) if entry_node else set()
        # Three id shapes can carry the proof, because
        # find_self_scoped_asset_moves aggregates by the CANONICAL ID of
        # whichever function's own body directly makes the transfer —
        # not by path position:
        #   - path.sink.node_id, when the sink IS that real function
        #     (e.g. Liquity's _sendETHGainToDepositor, which itself
        #     makes the low-level ETH call).
        #   - path.entry, when the entry itself makes the call directly
        #     (e.g. depositMine() calling token.transferFrom inline).
        #   - any INTERMEDIATE hop's own id in path.edge_chain — e.g.
        #     real Compound III's buyCollateral() -> doTransferIn() ->
        #     external.<token>.transferFrom: the proof lives on
        #     doTransferIn (the real function whose body makes the
        #     unresolved interface call), which is neither the entry
        #     nor the sink's own (synthetic terminal) node_id. Found
        #     live this session — doTransferIn's own from==msg.sender
        #     leg was correctly proven safe by find_self_scoped_asset_
        #     moves but never reached by a check that only looked at
        #     the two endpoints.
        path_ids = {path.entry, path.sink.node_id}
        for e in path.edge_chain:
            path_ids.add(e.src)
            path_ids.add(e.dst)
        proof_id = next(iter(safe_functions & path_ids), None)
        if proof_id is not None:
            return _suppressed(
                path,
                f"The asset movement at {path.sink.node_id} is provably self-scoped to the "
                f"caller's own identity (msg.sender-bound source or destination, proven on "
                f"{proof_id}) — an attacker can only ever move their own funds, not another user's"
            )

    # High confidence: unprotected path to privileged sink
    if path.sink.category in (STORAGE_CORRUPTION, DELEGATION_SINK, SELFDESTRUCT_SINK):
        return ConstraintResult(
            path=path,
            verdict=CONFIRMED,
            confidence=90,
            constraint_type="ACCESS_CONTROL_GAP",
            reasoning=(
                f"Unauthenticated entrypoint {path.entry} reaches "
                f"{path.sink.category} sink at {path.sink.node_id}. "
                f"Privileged writes: {path.sink.evidence}. "
                f"No access control on entry path."
            ),
            immunefi_impact="Unauthorized access to privileged functions",
            final_score=_final_score(path, 90),
        )

    # Medium confidence: unprotected path to asset sink (may be intentional)
    if path.sink.category == ASSET_DRAIN:
        return ConstraintResult(
            path=path,
            verdict=LIKELY,
            confidence=60,
            constraint_type="ACCESS_CONTROL_GAP",
            reasoning=(
                f"Unauthenticated path to asset drain: {path.entry} -> "
                f"{path.sink.node_id}. May be intentional (DEX) or exploitable. "
                f"Verify whether auth is enforced at runtime."
            ),
            immunefi_impact="Direct theft of user funds",
            final_score=_final_score(path, 60),
        )

    return _suppressed(path, "AUTH_GAP present but sink is low risk")


# ── Constraint 3: Missing health check ───────────────────────────


def _node_touches_sink_state(node, sink) -> bool:
    """
    Structural debt/collateral-context check, no name matching.
    True if `node` reads or writes ANY variable that the sink itself
    writes (sink.state_writes) - i.e. the node operates on the same
    storage the sink ultimately mutates. This replaces lexical
    "debt"/"vault"/"collateral" substring matching: a renamed protocol
    still trips this because it's checking the actual storage overlap,
    not the variable's name.
    """
    from core.invariants import root_names
    if not sink.state_writes:
        return False
    node_vars = set(getattr(node, 'state_writes', set())) | set(getattr(node, 'reads', set()))
    node_vars_lower = {v.lower() for v in root_names(node_vars)}
    sink_vars_lower = {v.lower() for v in root_names(sink.state_writes)}
    return bool(node_vars_lower & sink_vars_lower)


def _guard_constrains_sink_state(node, sink, graph_edges=None) -> bool:
    """
    Structural health-check detection, no name matching.
    True if `node` reads at least one variable the sink writes -
    meaning this guard's check is actually a function of the same
    state the sink mutates - AND one of:
      (a) the node has auth/guard evidence (auth_score >= 2, i.e. a
          real modifier or require/revert pattern was found by the
          enricher), OR
      (b) the node is a view/pure function (read-only by definition,
          so a call to it is a check, not a mutation — exactly what
          a health/solvency guard looks like structurally).
    This is the direct fix for the Morpho case: _isHealthy() never
    matched any name pattern and has auth_score=0 (it's a view
    function with no auth patterns — the require() is at the call
    site, not inside it), but it reads the same debt/collateral
    storage the sink writes.

    ALSO true, independent of local storage overlap, if `node` has a
    real revert-capable body (has_revert_capable_body) AND makes a
    TRUSTED, non-delegation external call — a guard whose condition is
    derived from a fixed, protocol-governed EXTERNAL dependency rather
    than local storage. Real shape found live this session: Liquity's
    _requireNoUnderCollateralizedTroves() reverts based on
    troveManager.getCurrentICR(...)/priceFeed.fetchPrice() (both
    immutable, protocol-set addresses — the same real, resolved
    edge.trusted signal CALLBACK_SINK classification already relies on,
    not a guess) despite never reading any of StabilityPool's OWN state
    — invisible to the local-overlap check above, which requires
    node.reads to intersect the sink's writes at all.
    """
    from core.invariants import root_names
    if not sink.state_writes:
        return False

    node_reads_lower = {v.lower() for v in root_names(getattr(node, 'reads', set()))}
    sink_vars_lower = {v.lower() for v in root_names(sink.state_writes)}
    if node_reads_lower & sink_vars_lower:
        auth_score = getattr(node, 'auth_score', 0)
        if auth_score >= 2:
            return True
        if getattr(node, 'is_view', False):
            return True

    if graph_edges is not None and getattr(node, 'has_revert_capable_body', False):
        node_id = getattr(node, 'id', None)
        for e in graph_edges.get(node_id, []):
            if e.is_external and e.trusted and not e.is_delegation:
                return True

    return False


def _accumulate_path_state_writes(path, nodes) -> set:
    """
    Collect every state variable written by any node on the path —
    the entry function, every callee along the edge chain, and the
    sink's own writes (the terminal mutation). Returns a lower-cased
    set for case-insensitive overlap comparison.
    """
    writes = set()
    entry_node = nodes.get(path.entry)
    if entry_node:
        writes |= set(getattr(entry_node, 'state_writes', set()))
    for edge in path.edge_chain:
        callee = nodes.get(edge.dst)
        if callee:
            writes |= set(getattr(callee, 'state_writes', set()))
    sink = path.sink
    if sink is not None:
        writes |= set(getattr(sink, 'state_writes', set()))
    return {str(v).lower() for v in writes}


def _check_missing_health_check(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect asset-moving functions that skip solvency validation.
    Pattern: function modifies collateral/debt without a guard that
    reads the same storage the sink writes.
    Real exploit: Euler Finance $197M (donateToReserves + no checkLiquidity).

    Structural version: debt/collateral "context" and "health check"
    are both now defined by storage overlap with the sink, not by
    matching against a word list. A protocol that names its debt
    variable `_b` and its guard `_x()` still gets caught correctly.
    """
    # No sink-category gate: the structural overlap check
    # (_node_touches_sink_state) below filters paths that don't touch
    # the sink's storage. This lets CALLBACK_SINK paths like Morpho's
    # _accrueInterest() reach the health-check logic, while
    # STORAGE_CORRUPTION / DELEGATION_SINK paths that don't share
    # state with an asset sink are naturally suppressed.
    sink = path.sink

    if sink.category not in (ASSET_DRAIN, STORAGE_CORRUPTION, DELEGATION_SINK):
        return _suppressed(
            path,
            f"Sink category {sink.category} is not a health-check surface — "
            "reentrancy/callback risk is covered by REENTRANCY_CEI"
        )


    # Structural suppression (replaces the old entry_name allowlist).
    # If no auth-scored node anywhere in the contract reads any
    # variable this path writes, then no guard in the codebase can
    # possibly validate the state this path mutates — a "missing
    # health check" is structurally irrelevant to this path, not an
    # exploitable gap. This catches the same asset-in interfaces the
    # name list used to catch (deposit, mint, supply, …) without
    # matching on names: a renamed function still trips it because the
    # check is over actual storage read/write overlap.
    path_writes = _accumulate_path_state_writes(path, nodes)
    if path_writes:
        # Mirrors _guard_constrains_sink_state's own acceptance criteria
        # (auth_score >= 2, OR is_view, OR has_revert_capable_body) —
        # this is only a coarse PRE-filter ("could ANY function in the
        # contract possibly be a guard for this state"), so it must stay
        # at least as permissive as the real, later check or it silently
        # suppresses genuine findings before they're ever evaluated.
        # Previously auth_score-only, which missed is_view guards
        # (Morpho's _isHealthy()) and — found live this session — real
        # Fraxlend's removeCollateral()'s own
        # `if (userBorrowShares[msg.sender] > 0)` check: after fixing
        # _role_mapping_ir's real transferFrom() false-AUTHENTICATED
        # bug (a numeric threshold check misdetected as a role/
        # permission grant), removeCollateral() correctly dropped below
        # auth_score >= 2, which silently made this filter blind to
        # userBorrowShares entirely, losing repayAsset()'s genuine,
        # correct MISSING_HEALTH_CHECK finding as a side effect.
        guard_reads = {
            str(v).lower()
            for n in nodes.values()
            if getattr(n, 'auth_score', 0) >= 2 or getattr(n, 'is_view', False) or getattr(n, 'has_revert_capable_body', False)
            for v in getattr(n, 'reads', set())
        }
        sink_writes = {str(v).lower() for v in getattr(sink, 'state_writes', set())}
        if not (sink_writes & guard_reads):
            return _suppressed(
                path,
                "No guard-capable function in the contract reads any variable "
                "this path writes — health check structurally irrelevant",
            )

    # Owner-gating: structural auth evidence only (no name lists).
    # The enricher's auth_score/auth_state already capture modifier
    # and msg.sender evidence — a separate modifier-name list here
    # was redundant belt-and-suspenders.
    entry_node = nodes.get(path.entry)
    if entry_node is not None:
        auth_score = getattr(entry_node, 'auth_score', 0)
        auth_state = getattr(entry_node, 'auth_state', '')
        if auth_score >= 3 or auth_state == "AUTHENTICATED":
            return _suppressed(path, "owner-gated function — MHC not applicable")

    # Self-scoped write: the sink's privileged write is PROVABLY
    # confined to the caller's own storage slot (core/auth_detection.py
    # ::find_self_scoped_writes / find_self_scoped_liability_reductions
    # — the same evidence _check_access_control_gap already relies on).
    # Deliberately narrower than the ASSET_DRAIN self-scoped-move check
    # (which does NOT extend here — proven unsound live: a self-scoped
    # RECIPIENT doesn't validate the AMOUNT/CONDITION, confirmed by this
    # session's own adversarial withdrawUnsafe() fixture, an
    # attacker-controlled oracle behind a self-scoped ETH refund).
    # STORAGE writes are different: Euler's real donateToReserves shape
    # requires corrupting GLOBAL or CROSS-USER accounting (reserves, a
    # shared value) — a write structurally proven confined to
    # data[msg.sender] can never touch shared state, by construction,
    # so it cannot replicate that exploit shape regardless of amount.
    # Found live this session: Dai.approve()'s
    # `allowance[msg.sender][usr] = wad` (a pure permission grant, no
    # value moves until a LATER, separately-checked transferFrom) was
    # correctly proven self-scoped for ACCESS_CONTROL_GAP but MISSING_
    # HEALTH_CHECK never consulted the same evidence.
    if sink.category == STORAGE_CORRUPTION and sink.privileged_writes and entry_node is not None:
        self_scoped = getattr(entry_node, "self_scoped_write_keys", set())
        self_funded = getattr(entry_node, "self_scoped_liability_reduction_keys", set())
        combined = self_scoped | self_funded
        if combined and sink.privileged_writes.issubset(combined):
            return _suppressed(path, "Privileged write is provably confined to the caller's own storage — MHC not applicable")

    path_has_debt_context = False
    health_check_found = False

    if entry_node and _node_touches_sink_state(entry_node, sink):
        path_has_debt_context = True

    for edge in path.edge_chain:
        callee = nodes.get(edge.dst)
        if not callee:
            continue
        if _node_touches_sink_state(callee, sink):
            path_has_debt_context = True
        if _guard_constrains_sink_state(callee, sink, graph_edges):
            health_check_found = True
        # One-hop lookahead: catches guard() -> _validate() -> IIngress.validate()
        if not health_check_found:
            for inner_edge in graph_edges.get(edge.dst, []):
                inner_callee = nodes.get(inner_edge.dst)
                if inner_callee and _guard_constrains_sink_state(inner_callee, sink, graph_edges):
                    health_check_found = True
                    break

    # Modifier scan: a modifier ATTACHED to the entry (e.g. real
    # Fraxlend's `isSolvent(msg.sender)` on borrowAsset()/
    # leveragedPosition()/repayAssetWithCollateral()) is invisible to
    # the edge_chain/sibling-edge walks above — modifier attachment
    # isn't a call-graph edge, it's a separate relationship
    # (FunctionNode.modifier_ids), the same field
    # _check_reentrancy_cei's own guard scan already uses. Found live
    # this session: without this, these three real, isSolvent-protected
    # Fraxlend functions false-positived MISSING_HEALTH_CHECK once an
    # unrelated fix (widening the early "no possible guard exists"
    # pre-filter) stopped silently suppressing them for the WRONG
    # reason before they ever reached this scan.
    if not health_check_found and entry_node is not None:
        for mid in getattr(entry_node, 'modifier_ids', []) or []:
            modifier_node = nodes.get(mid)
            if not modifier_node:
                continue
            if _guard_constrains_sink_state(modifier_node, sink, graph_edges):
                health_check_found = True
                break
            for inner_edge in graph_edges.get(mid, []):
                inner_callee = nodes.get(inner_edge.dst)
                if inner_callee and _guard_constrains_sink_state(inner_callee, sink, graph_edges):
                    health_check_found = True
                    break
            if health_check_found:
                break

    # Sibling guard scan (Issue 5, widened): the edge_chain walk above
    # only inspects callees that lie ON the path to the sink. A guard
    # call the entry makes as a SEPARATE, sibling statement — not part
    # of the chain that happens to reach this particular sink — is
    # invisible to that walk. Two real shapes, found live:
    #   - Guard AFTER the sink call returns, e.g. Morpho's
    #     _isHealthy() following _accrueInterest() in liquidate().
    #   - Guard BEFORE the call that reaches the sink — the more
    #     common checks-effects-interactions order, e.g. real Fraxlend:
    #     `if (_isSolvent(_borrower, _exchangeRate)) revert
    #     BorrowerSolvent();` runs BEFORE liquidate() calls
    #     _repayAsset() — found live this session; the previous
    #     after-only scan missed it entirely, producing a false
    #     positive on a real, audited, currently-live protocol.
    # A revert-capable guard ANYWHERE in the entry's own body protects
    # the function's entire execution regardless of statement order —
    # Solidity functions run linearly to completion or revert, there is
    # no way for a later statement to execute if an earlier revert
    # fired. So this scans the entry's COMPLETE own edge list, not a
    # position-relative slice of it — still bounded by the same
    # _guard_constrains_sink_state bar (real storage overlap with the
    # sink's own writes, plus real view/auth evidence), just no longer
    # missing half of where that guard could legitimately be.
    if not health_check_found:
        for e in graph_edges.get(path.entry, []):
            callee = nodes.get(e.dst)
            if callee and _guard_constrains_sink_state(callee, sink, graph_edges):
                health_check_found = True
                break

    if not path_has_debt_context:
        return _suppressed(path, "No storage overlap between path and sink — no debt/collateral context")

    if health_check_found:
        return _suppressed(path, "Guard found that reads sink's storage and carries auth evidence (structural health check)")

    return ConstraintResult(
        path=path,
        verdict=CONFIRMED,
        confidence=85,
        constraint_type="MISSING_HEALTH_CHECK",
        reasoning=(
            f"Path {path.entry} -> {path.sink.node_id} modifies "
            f"debt/collateral state without a downstream health check. "
            f"Pattern matches Euler Finance donateToReserves vulnerability. "
            f"No auth-scored node in the contract reads the storage this path writes."
        ),
        immunefi_impact="Protocol insolvency / direct theft of user funds",
        final_score=_final_score(path, 85),
    )


# ── Constraint 8: Cross-function state race ──────────────────────

def _check_cross_function_state_race(path, nodes, graph_edges, invariant_index) -> ConstraintResult:
    """
    Detect invariant-relevant state written AFTER a callback-capable
    external call — the real reentrancy window, not just "shares a
    variable with another function" and not an approximation of
    ordering.

    Reads precomputed race_findings from FunctionNode, calculated in
    graph.py at build time via invariants.py's invariant_writes_
    between_calls — the exact, node-ordered, mutability-aware logic
    validated this session against Morpho's supply/repay/liquidate/
    setFee (0 false positives, correct suppression on all four for
    four independently-confirmed reasons: field precision, library-
    call classification, multi-call ordering, view/pure exclusion).

    This function is now a thin consumer — all real analysis already
    happened in graph.py, where the raw Slither function object and
    real node ordering are still available.
    """
    from core.invariants import state_key_to_display

    entry_node = nodes.get(path.entry)
    if entry_node is None:
        return _suppressed(path, "no entry node")

    race_findings = getattr(entry_node, "race_findings", [])
    if not race_findings:
        return _suppressed(path, "no invariant-relevant write follows any callback-capable call")

    event, at_risk = race_findings[0]
    contract = entry_node.contract
    risk_display = {state_key_to_display(k) for k in at_risk}

    invariants_at_risk = []
    for k in at_risk:
        full_key = (contract, k[0], k[1])
        invariants_at_risk.extend(invariant_index.get(full_key, []))

    inv_summary = "; ".join(
        inv.node_expr_str for inv in invariants_at_risk[:2]
    ) if invariants_at_risk else "an unspecified protocol guarantee"

    return ConstraintResult(
        path=path,
        verdict=LIKELY,
        confidence=70,
        constraint_type="CROSS_FUNCTION_STATE_RACE",
        reasoning=(
            f"{path.entry} calls {event.node_expr_str} (callback-capable), "
            f"then writes invariant-relevant field(s) {risk_display} after it, "
            f"confirmed by real node ordering. This field participates in: "
            f"{inv_summary}. A reentrant call during this callback can "
            f"observe or corrupt state before the invariant is restored."
        ),
        immunefi_impact="State corruption or fund loss via cross-function reentrancy",
        final_score=_final_score(path, 70),
    )


# ── Constraint 4: Oracle dependency ──────────────────────────────

def _check_oracle_dependency(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect spot-price-oracle-manipulation patterns via core/
    spot_price_detection.py::find_unsafe_spot_price_dependency,
    computed once from real Slither IR while building the graph (core/
    graph.py) — not re-derived here from lossy CallEdge.function_name
    string matching (the prior version grepped for substrings like
    "oracle", "pricefeed", "twap" anywhere in a call's NAME, unable to
    verify the value was ever actually used in a price computation, let
    alone an unprotected one — a `getReserves()` call feeding into a
    fully time-weighted average matched identically to a raw, single-
    block spot read).

    Real, verified IR shape (confirmed live via probe against Uniswap's
    own real reference implementations, v2-periphery's
    ExampleOracleSimple.sol and v3-periphery's OracleLibrary.sol): an
    unsafe dependency is a security-critical value (collateral, debt,
    borrow, liquidation, health, price) computed from Uniswap V2's
    getReserves() / V3's slot0() where that SPECIFIC value is never
    forward-tainted into a division by a real elapsed-time value before
    reaching critical state — a single-block flash-loan swap can skew
    the instantaneous reserves/tick, but a real TWAP dilutes that
    contribution to economic irrelevance.

    Real precedent: Harvest Finance's real $24M loss (Oct 2020, priced
    vault shares from a live Curve pool reserve ratio with no time-
    weighting), Warp Finance's real $8M loss (Dec 2020, priced
    collateral directly from a Uniswap V2 pair's getReserves()).

    Gated on path.sink.category == ASSET_DRAIN, matching this
    constraint's prior integration and the sibling SHARE_INFLATION
    check's convention: a lending/vault entry's own price-dependent
    path naturally reaches its own asset-moving sink (borrow, mint,
    liquidate), keeping this to one finding per real entry.
    """
    if path.sink.category != ASSET_DRAIN:
        return _suppressed(path, "Not an asset drain path")

    entry_node = nodes.get(path.entry)
    evidence = getattr(entry_node, "unsafe_spot_price_dependency", None) if entry_node else None
    if evidence is None:
        return _suppressed(
            path,
            "No unprotected AMM spot-price dependency found on this entry's reachable "
            "scope — either no getReserves()/slot0()-derived price computation feeds "
            "critical state, or the specific value is diluted by a real elapsed-time "
            "division before it gets there"
        )

    return ConstraintResult(
        path=path,
        verdict=CONFIRMED,
        confidence=85,
        constraint_type="ORACLE_DEPENDENCY",
        reasoning=(
            f"Entry {path.entry} computes a security-critical value from an unprotected "
            f"AMM spot-price accessor ({evidence}) — Uniswap V2's getReserves() or V3's "
            f"slot0() — with no elapsed-time-gated division diluting that specific value "
            f"before it reaches critical state. An attacker can flash-loan-swap to skew "
            f"the pool's instantaneous state within one transaction, use the skewed price "
            f"for this call, then reverse the swap. Sink: {path.sink.node_id}. Real "
            f"precedent: Harvest Finance's $24M loss (Oct 2020), Warp Finance's $8M loss "
            f"(Dec 2020)."
        ),
        immunefi_impact="Manipulation of protocol's price oracle / direct theft",
        final_score=_final_score(path, 85),
    )


# ── Constraint 5: Flash loan window ──────────────────────────────

def _check_flashloan_window(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect flash loan callback window vulnerabilities.
    Triggers on structural pattern: external call + state write before it
    + no invariant enforced after. Name matching boosts confidence only.
    Real exploits: PancakeBunny $45M, bZx, most callback-based exploits.
    """
    flags = path.constraint_flags

    # Core structural signal: state written before external call
    has_state_before_call = "STATE_BEFORE_CALL" in flags
    has_external = "EXTERNAL_CALL" in flags

    # Entry node state writes + any external call on path is the base pattern
    entry_node = nodes.get(path.entry)
    entry_has_state = bool(getattr(entry_node, 'state_writes', set()))

    structural_match = has_external and (has_state_before_call or entry_has_state)

    if not structural_match:
        return _suppressed(path, "No flash loan window pattern — no state+external signal")

    if not _has_state_crossing_external_call(path, nodes, graph_edges):
        return _suppressed(
            path,
            "Every external call on this path is view/pure (STATICCALL under "
            "the hood) — no callback window exists, nothing can execute during it"
        )

    # The "no invariant enforced after" half of this check's own
    # docstring, which the structural signal above never actually
    # verified — see core/auth_detection.py::
    # has_balance_invariant_after_external_call. The real Uniswap V3
    # flash()/swap() shape: a value snapshotted before the callback is
    # re-read after it and compared via a revert-capable require — the
    # actual mechanism that makes an unauthenticated flash-loan
    # callback safe, structurally distinct from merely having some
    # unrelated require() present somewhere in the function.
    if entry_node is not None and getattr(entry_node, "has_balance_invariant_after_call", False):
        return _suppressed(
            path,
            "Entry re-verifies a snapshotted quantity after the external call via a "
            "revert-capable invariant — the callback window is closed, not open"
        )

    # Name matching as confidence booster, not gate
    flashloan_signals = {
        "flashloan", "flash", "flashborrow", "executeoperation",
        "uniswapv3flashcallback", "uniswapv2call",
        "pancakeswap", "balancervault", "receive", "fallback",
        "onflashloan", "tokensreceived", "hookcallback",
    }

    entry_name = path.entry.split(".")[-1].split("(")[0].lower()
    is_flash_entry = any(sig in entry_name for sig in flashloan_signals)

    callback_names = [
        (edge.function_name or "").lower()
        for edge in path.edge_chain
        if edge.is_external
    ]
    has_flash_callback = any(
        sig in name for name in callback_names for sig in flashloan_signals
    )

    # Base confidence from structure alone
    # Name match upgrades it
    if is_flash_entry or has_flash_callback:
        confidence = 80
        verdict = LIKELY
        name_note = f"Flash loan name signals confirmed: entry={is_flash_entry}, callback={has_flash_callback}."
    else:
        confidence = 55
        verdict = POSSIBLE
        name_note = "No flash loan name signals — structural pattern only. Manual review needed."

    return ConstraintResult(
        path=path,
        verdict=verdict,
        confidence=confidence,
        constraint_type="FLASHLOAN_WINDOW",
        reasoning=(
            f"State written before external call on path: {path.entry}. "
            f"{name_note} "
            f"Sink: {path.sink.node_id}. "
            f"Pattern: external call creates manipulation window before invariant check."
        ),
        immunefi_impact="Flash loan attack / temporary price manipulation",
        final_score=_final_score(path, confidence),
    )


# ── Constraint 6: Unchecked return value ─────────────────────────

def _check_unchecked_return(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect ignored return values from low-level calls.
    Pattern: lowlevel_call edge where the return value is not validated
    — core/edges.py::_low_level_return_checked traces the call's own
    `bool success` (index 0 of its (bool, bytes) tuple) forward through
    any Unpack to a revert-capable read in the SAME function, real
    dataflow evidence rather than "a low-level call exists on this
    path" alone. That blanket version previously fired on every
    low-level call regardless of whether it was checked — a false
    positive on essentially any competently-written contract (found
    live: TransferHelper.safeTransfer, OZ's Address.functionCall, and
    Liquity's _sendETHGainToDepositor all check their own return, none
    of which the old version could tell apart from a genuinely
    unchecked call).
    Real exploits: King of Ether, multiple token transfer failures.
    """
    lowlevel_edges = [
        e for e in path.edge_chain
        if e.raw_type == "lowlevel_call" and not e.return_checked
    ]

    if not lowlevel_edges:
        return _suppressed(path, "No unchecked low-level calls on path")

    # Low-level calls to uncertain destinations are highest risk
    uncertain_low = [e for e in lowlevel_edges if e.uncertain]

    confidence = 80 if uncertain_low else 55

    return ConstraintResult(
        path=path,
        verdict=LIKELY if uncertain_low else POSSIBLE,
        confidence=confidence,
        constraint_type="UNCHECKED_RETURN",
        reasoning=(
            f"{len(lowlevel_edges)} low-level call(s) on path with an unchecked return value, "
            f"{len(uncertain_low)} with uncertain destination. "
            f"Entry: {path.entry} -> Sink: {path.sink.node_id}."
        ),
        immunefi_impact="Unexpected contract behavior / silent failure",
        final_score=_final_score(path, confidence),
    )


# ── Constraint 7: Share inflation / exchange rate manipulation ────

def _check_share_inflation(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect ERC4626 vault share-price-manipulation (donation/inflation
    attack) patterns via core/vault_detection.py::
    find_unsafe_share_price_divisor, computed once from real Slither
    IR while building the graph (core/graph.py) — not re-derived here
    from lossy CallEdge.function_name string matching. Real, verified
    IR shapes (confirmed live via probe against the actual Solmate
    FixedPointMathLib and OpenZeppelin ERC4626 v4.9+/v5 source):
    an unsafe divisor is a share/asset conversion ratio whose
    denominator traces to a raw `token.balanceOf(address(this))` read
    with no additive virtual-offset term on it, in the same function-
    or-reachable-helper scope as a share-supply-shaped state write.

    Real precedent: Sherlock's real 2024-01-napier-judging#125 finding
    against Napier's BaseLSTAdapter (`totalAssets()` summing
    `STETH.balanceOf(address(this))` with no offset), and Zellic's real
    Perennial audit finding of the identical shape.

    Gated on path.sink.category == ASSET_DRAIN, matching this
    constraint's prior integration: a vault's own deposit()/mint() path
    naturally reaches its own asset-moving sink (the token transfer it
    performs), keeping this to one finding per real entry rather than
    one per every path the entry happens to enumerate.
    """
    if path.sink.category != ASSET_DRAIN:
        return _suppressed(path, "Not an asset drain path")

    entry_node = nodes.get(path.entry)
    evidence = getattr(entry_node, "unsafe_share_price_divisor", None) if entry_node else None
    if evidence is None:
        return _suppressed(
            path,
            "No unprotected balanceOf(this)-derived share-price ratio found on this entry's "
            "reachable scope — either no such ratio exists, its divisor is internally tracked "
            "(immune to direct-donation manipulation), or it carries a real virtual-offset term"
        )

    return ConstraintResult(
        path=path,
        verdict=CONFIRMED,
        confidence=90,
        constraint_type="SHARE_INFLATION",
        reasoning=(
            f"Entry {path.entry} computes a share/asset conversion ratio whose divisor "
            f"({evidence}) is an unprotected balanceOf(address(this)) read, with no additive "
            f"virtual-offset term and no internal accounting — an attacker can donate tokens "
            f"directly to the contract (bypassing deposit()) to inflate this divisor without "
            f"inflating totalSupply, rounding later depositors' shares to zero. Sink: "
            f"{path.sink.node_id}. Real precedent: Sherlock 2024-01-napier-judging#125, "
            f"Zellic's Perennial ERC-4626 inflation attack finding."
        ),
        immunefi_impact="Direct theft of user funds via share price manipulation",
        final_score=_final_score(path, 90),
    )


# ── Helpers ───────────────────────────────────────────────────────

def _suppressed(path: ExploitPath, reason: str) -> ConstraintResult:
    return ConstraintResult(
        path=path,
        verdict=SUPPRESSED,
        confidence=0,
        constraint_type="NONE",
        reasoning=reason,
        immunefi_impact="N/A",
        final_score=0,
    )


def _first_external(edge_chain: List[CallEdge]) -> str:
    for edge in edge_chain:
        if edge.is_external:
            return edge.dst
    return "unknown"


def _final_score(path: ExploitPath, confidence: int) -> int:
    """Path score weighted by confidence."""
    return int(path.path_score * (confidence / 100))
