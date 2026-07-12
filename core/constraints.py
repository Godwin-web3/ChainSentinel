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
    PRIVILEGED_SLOTS
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

# ── Known safe patterns (suppress these) ─────────────────────────
# Functions that are intentionally open and move assets by design.
# An AUTH_GAP on these is expected, not exploitable.

ECONOMIC_INTERFACES = {
    "swap", "flash", "collect", "mint", "burn",
    "transfer", "transferfrom", "approve",
    "deposit", "withdraw", "redeem",
    "addliquidity", "removeliquidity",
    "execute", "multicall",
    # Morpho / Blue-style permissionless economic interfaces.
    # Additive only — existing entries preserved for Altitude.fi
    # and Exactly Protocol which depend on them.
    "supply", "borrow", "repay", "liquidate",
    "supplycollateral", "withdrawcollateral", "flashloan",
}

# Known reentrancy guard patterns in function names / modifiers
REENTRANCY_GUARDS = {
    "nonreentrant", "lock", "noreentrancy",
    "mutex", "reentrancyguard", "locked",
    "_lock", "_mutex", "entrancyguard",
    "noentry", "onlyonce",
}

REENTRANCY_GUARD_PREFIXES = (
    "nonreentrant", "lock", "mutex", "guard", "noreentr",
)

def _has_reentrancy_guard(name: str) -> bool:
    n = name.lower().replace("(", "").split("(")[0]
    if n in REENTRANCY_GUARDS:
        return True
    return any(n.startswith(p) or n.endswith(p) for p in REENTRANCY_GUARD_PREFIXES)

# Known health/solvency check function names
HEALTH_CHECK_FUNCTIONS = {
    "checkliquidity", "checkhealth", "checkaccounthealth",
    "checksolvency", "requirehealthy", "healthfactor",
    "isliquidatable", "getcollateralvalue", "getdebtvalue",
    "checkaccountstatus", "verifyhealth",
    "validateborrow", "validatewithdraw", "validatetransfer",
    "validaterepay", "validateaction", "validateposition",
    "requirevalid", "assertvalid", "beforewithdraw",
    "accrue", "_accrue", "accrueinterest",
}

# Prefix/suffix patterns for health check detection
# Covers protocols that use non-standard naming
HEALTH_CHECK_PREFIXES = (
    "validate", "_validate", "check", "_check",
    "require", "assert", "verify", "before",
)

def _is_health_check(name: str) -> bool:
    n = name.lower().replace("(", "").split("(")[0]
    if n in HEALTH_CHECK_FUNCTIONS:
        return True
    return any(n.startswith(p) for p in HEALTH_CHECK_PREFIXES)

# Oracle/price read function patterns
ORACLE_READ_PATTERNS = {
    "getprice", "latesranswer", "latestanswer", "consult",
    "getreserves", "price0cumulativelast", "price1cumulativelast",
    "twap", "gettwap", "oracle", "pricefeed",
    "slot0",  # Uniswap V3 spot price
}


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
        result = _validate_path(path, nodes, graph_edges, state_writers, state_readers)
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
    if state_writers is not None and state_readers is not None:
        results.append(_check_cross_function_state_race(path, nodes, graph_edges, state_writers, state_readers))

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

    # Check for reentrancy guard on entry function
    entry_modifiers = [
        m.lower() for m in getattr(entry_node, 'modifiers', [])
    ] if entry_node else []

    has_guard = any(_has_reentrancy_guard(m) for m in entry_modifiers)

    # Check if guard appears anywhere in call chain
    if not has_guard:
        for edge in path.edge_chain:
            callee = nodes.get(edge.dst)
            if callee:
                callee_mods = [m.lower() for m in getattr(callee, 'modifiers', [])]
                if any(_has_reentrancy_guard(m) for m in callee_mods):
                    has_guard = True
                    break
                callee_name = getattr(callee, 'name', '').lower()
                if _has_reentrancy_guard(callee_name):
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
    Returns True if any callee has auth signals: modifiers, msg.sender checks, role checks.
    """
    if _visited is None:
        _visited = set()
    if depth == 0 or node_id in _visited:
        return False
    _visited.add(node_id)

    for edge in graph_edges.get(node_id, []):
        callee = nodes.get(edge.dst)
        if callee:
            # Check modifiers on callee
            mods = [m.lower() for m in getattr(callee, 'modifiers', [])]
            if any(m for m in mods if not _has_reentrancy_guard(m) and m not in ("payable",)):
                return True
            # Check auth score from enricher
            if getattr(callee, 'auth_score', 0) >= 2:
                return True
            # Check name — validate*, onlyX, _checkX patterns
            name = getattr(callee, 'name', '').lower()
            if any(name.startswith(p) for p in ("validate", "_validate", "only", "_only", "_check", "_require")):
                return True
        if _auth_check_in_subgraph(edge.dst, nodes, graph_edges, depth - 1, _visited):
            return True
    return False

# ── Constraint 2: Access control gap ─────────────────────────────

def _entry_has_direct_auth(node_id: str, nodes: dict) -> bool:
    """
    Check whether the entry function ITSELF carries an auth signal -
    modifier, auth_score, or validating name pattern - without walking
    the call subgraph.

    _auth_check_in_subgraph only inspects callees reached FROM node_id;
    it never looks at node_id's own modifiers/auth_score. This misses:
      - inline checks, e.g. if (keepers[account] != msg.sender) revert ...
      - modifiers applied directly to the entry function (e.g. claimSender)
    Both are real auth enforcement that the callee-only walk can't see.
    """
    entry_node = nodes.get(node_id)
    if not entry_node:
        return False
    mods = [m.lower() for m in getattr(entry_node, 'modifiers', [])]
    if any(m for m in mods if not _has_reentrancy_guard(m) and m not in ("payable",)):
        return True
    if getattr(entry_node, 'auth_score', 0) >= 2:
        return True
    name = getattr(entry_node, 'name', '').lower()
    if any(name.startswith(p) for p in ("validate", "_validate", "only", "_only", "_check", "_require")):
        return True
    return False


def _check_access_control_gap(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect unprotected path to privileged sink.
    Pattern: UNAUTHENTICATED entrypoint reaches STORAGE_CORRUPTION or DELEGATION_SINK.
    Real exploits: Ronin $625M, Wormhole $320M, most 2024 losses.
    """
    flags = path.constraint_flags

    if "AUTH_GAP" not in flags:
        return _suppressed(path, "No auth gap on path")

    entry_name = path.entry.split(".")[-1].split("(")[0].lower()

    # Suppress if entrypoint is a known economic interface
    if entry_name in ECONOMIC_INTERFACES:
        if path.sink.category not in (STORAGE_CORRUPTION, DELEGATION_SINK, SELFDESTRUCT_SINK):
            return _suppressed(
                path,
                f"{entry_name} is an economic interface — AUTH_GAP expected"
            )

    # Deep auth check: walk call graph up to 3 hops before issuing verdict
    # Catches borrow() -> _validateBorrow() -> IIngress.validateBorrow()
    if _entry_has_direct_auth(path.entry, nodes):
        return _suppressed(path, "Auth enforced directly on entry function (modifier or inline check) - not a real gap")

    if _auth_check_in_subgraph(path.entry, nodes, graph_edges, depth=3):
        return _suppressed(path, "Auth enforced in call subgraph — not a real gap")

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


def _health_check_in_subgraph(node_id: str, graph_edges: dict, depth: int = 3, _visited: set = None) -> bool:
    """
    Recursively walk the call graph from node_id up to `depth` hops.
    Returns True if any callee name matches a health check pattern.
    """
    if _visited is None:
        _visited = set()
    if depth == 0 or node_id in _visited:
        return False
    _visited.add(node_id)
    for edge in graph_edges.get(node_id, []):
        name = (edge.function_name or "").lower()
        if _is_health_check(name):
            return True
        if _health_check_in_subgraph(edge.dst, graph_edges, depth - 1, _visited):
            return True
    return False

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
    if not sink.state_writes:
        return False
    node_vars = set(getattr(node, 'state_writes', set())) | set(getattr(node, 'reads', set()))
    node_vars_lower = {str(v).lower() for v in node_vars}
    sink_vars_lower = {str(v).lower() for v in sink.state_writes}
    return bool(node_vars_lower & sink_vars_lower)


def _guard_constrains_sink_state(node, sink) -> bool:
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
    """
    if not sink.state_writes:
        return False
    node_reads_lower = {str(v).lower() for v in getattr(node, 'reads', set())}
    sink_vars_lower = {str(v).lower() for v in sink.state_writes}
    if not bool(node_reads_lower & sink_vars_lower):
        return False
    auth_score = getattr(node, 'auth_score', 0)
    if auth_score >= 2:
        return True
    is_view = getattr(node, 'is_view', False)
    if is_view:
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
        guard_reads = {
            str(v).lower()
            for n in nodes.values()
            if getattr(n, 'auth_score', 0) >= 2
            for v in getattr(n, 'reads', set())
        }
        sink_writes = {str(v).lower() for v in getattr(sink, 'state_writes', set())}
        if not (sink_writes & guard_reads):
            return _suppressed(
                path,
                "No auth-scored guard in the contract reads any variable "
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
        if _guard_constrains_sink_state(callee, sink):
            health_check_found = True
        # One-hop lookahead: catches guard() -> _validate() -> IIngress.validate()
        if not health_check_found:
            for inner_edge in graph_edges.get(edge.dst, []):
                inner_callee = nodes.get(inner_edge.dst)
                if inner_callee and _guard_constrains_sink_state(inner_callee, sink):
                    health_check_found = True
                    break

    # Post-sink guard scan (Issue 5): the edge_chain walk above only
    # inspects callees that lie ON the path to the sink. A guard that
    # runs AFTER the sink call returns — e.g. Morpho's _isHealthy()
    # following _accrueInterest() in liquidate() — is invisible to
    # that walk because it is not on the path TO the sink, it is on
    # the path AFTER the sink. Scan the entry function's IR (edges in
    # graph_edges are extracted in source order) for callees that
    # appear after the first edge of the path and treat a
    # _guard_constrains_sink_state match there as a health check.
    #
    # We locate path.edge_chain[0] — the first call FROM path.entry,
    # which DFS took directly from graph_edges[path.entry] — by object
    # identity, then scan every edge after it. This is correct for
    # both 1-hop paths (edge_chain[0] IS the sink call) and multi-hop
    # paths (edge_chain[0] is the top-level call that transitively
    # reaches the sink; anything after it in the entry's IR runs after
    # the entire nested chain, including the sink, returns). Matching
    # by identity avoids format mismatches between e.dst and
    # sink.node_id (contract_declarer.name vs contract.name, etc.).
    if not health_check_found and path.edge_chain:
        first_edge = path.edge_chain[0]
        entry_edges = graph_edges.get(path.entry, [])
        sink_idx = next(
            (i for i, e in enumerate(entry_edges) if e is first_edge),
            None,
        )
        if sink_idx is None:
            sink_idx = next(
                (i for i, e in enumerate(entry_edges)
                 if e.dst == first_edge.dst
                 and (e.function_name or None) == (first_edge.function_name or None)
                 and e.raw_type == first_edge.raw_type),
                None,
            )
        if sink_idx is not None:
            for e in entry_edges[sink_idx + 1:]:
                callee = nodes.get(e.dst)
                if callee and _guard_constrains_sink_state(callee, sink):
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

def _check_cross_function_state_race(path, nodes, graph_edges, state_writers, state_readers) -> ConstraintResult:
    """
    Detect state shared across functions with no reentrancy guard
    spanning both. Catches read-only reentrancy and cross-function
    reentrancy: bugs where the vulnerable write and the exploited
    read live in DIFFERENT functions, invisible to single-path
    storage-overlap checks.

    Pattern: entry function makes an external call, then writes
    state X. A different function elsewhere in the same contract
    also touches state X. Neither shares a reentrancy-lock modifier.
    That gap is the race window.
    """
    entry_node = nodes.get(path.entry)
    if entry_node is None:
        return _suppressed(path, "no entry node")

    if not entry_node.external_callees:
        return _suppressed(path, "entry makes no external call — no reentrancy window")

    entry_modifiers = set(entry_node.modifiers)
    contract = entry_node.contract

    for var in entry_node.state_writes:
        key = f"{contract}.{var}"
        touchers = set(state_writers.get(key, [])) | set(state_readers.get(key, []))
        touchers.discard(path.entry)

        for other_cid in touchers:
            other_node = nodes.get(other_cid)
            if other_node is None:
                continue

            other_modifiers = set(other_node.modifiers)
            shared_guard = entry_modifiers & other_modifiers
            has_lock_word = any(
                "lock" in m.lower() or "nonreentrant" in m.lower() or "guard" in m.lower()
                for m in shared_guard
            )
            if has_lock_word:
                continue

            return ConstraintResult(
                path=path,
                verdict=LIKELY,
                confidence=70,
                constraint_type="CROSS_FUNCTION_STATE_RACE",
                reasoning=(
                    f"{path.entry} writes {contract}.{var} after an external call, "
                    f"with no shared reentrancy lock. {other_cid} independently "
                    f"reads or writes the same variable. A reentrant call during "
                    f"{path.entry}'s external call can let {other_cid} observe or "
                    f"corrupt state mid-transaction."
                ),
                immunefi_impact="State corruption or fund loss via cross-function reentrancy",
                final_score=_final_score(path, 70),
            )

    return _suppressed(path, "no unguarded cross-function state overlap found")


# ── Constraint 4: Oracle dependency ──────────────────────────────

def _check_oracle_dependency(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect asset flows that depend on manipulable price sources.
    Pattern: asset movement reads spot price from DEX pool (getReserves, slot0).
    Real exploits: bZx $600k, Harvest $34M, Mango $116M.
    """
    if path.sink.category != ASSET_DRAIN:
        return _suppressed(path, "Not an asset drain path")

    oracle_reads = []

    for edge in path.edge_chain:
        fname = (edge.function_name or "").lower()
        for pattern in ORACLE_READ_PATTERNS:
            if pattern in fname:
                oracle_reads.append(edge.function_name or fname)

    # Check entry node external calls for oracle patterns
    entry_node = nodes.get(path.entry)
    if entry_node:
        for edge in graph_edges.get(path.entry, []):
            fname = (edge.function_name or "").lower()
            for pattern in ORACLE_READ_PATTERNS:
                if pattern in fname and edge.is_external:
                    oracle_reads.append(f"external.{edge.function_name or fname}")

    if not oracle_reads:
        return _suppressed(path, "No oracle reads on path")

    # slot0 is especially dangerous — it's Uniswap V3 spot price, trivially manipulable
    has_spot_price = any("slot0" in r.lower() or "getreserves" in r.lower() for r in oracle_reads)
    confidence = 85 if has_spot_price else 65

    return ConstraintResult(
        path=path,
        verdict=CONFIRMED if has_spot_price else LIKELY,
        confidence=confidence,
        constraint_type="ORACLE_DEPENDENCY",
        reasoning=(
            f"Asset drain path reads from manipulable price source: {oracle_reads[:3]}. "
            f"{'slot0/getReserves is trivially manipulable via flash loan in single block. ' if has_spot_price else ''}"
            f"Entry: {path.entry} -> Sink: {path.sink.node_id}. "
            f"Pattern matches Harvest Finance and bZx oracle manipulation."
        ),
        immunefi_impact="Manipulation of protocol's price oracle / direct theft",
        final_score=_final_score(path, confidence),
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
    Pattern: lowlevel_call edge where return value is not validated.
    Real exploits: King of Ether, multiple token transfer failures.
    """
    lowlevel_edges = [
        e for e in path.edge_chain
        if e.raw_type == "lowlevel_call"
    ]

    if not lowlevel_edges:
        return _suppressed(path, "No low-level calls on path")

    # Low-level calls to uncertain destinations are highest risk
    uncertain_low = [e for e in lowlevel_edges if e.uncertain]

    confidence = 80 if uncertain_low else 55

    return ConstraintResult(
        path=path,
        verdict=LIKELY if uncertain_low else POSSIBLE,
        confidence=confidence,
        constraint_type="UNCHECKED_RETURN",
        reasoning=(
            f"{len(lowlevel_edges)} low-level call(s) on path, "
            f"{len(uncertain_low)} with uncertain destination. "
            f"Return value check cannot be confirmed statically. "
            f"Entry: {path.entry} -> Sink: {path.sink.node_id}."
        ),
        immunefi_impact="Unexpected contract behavior / silent failure",
        final_score=_final_score(path, confidence),
    )


# ── Constraint 7: Share inflation / exchange rate manipulation ────

def _rate_is_balance_derived(node_id: str, graph_edges: dict, depth: int = 2, _visited: set = None) -> bool:
    """
    Walk the subgraph from a totalAssets()/totalSupply()-style node up to
    `depth` hops. Returns True only if a live balance read (balanceOf,
    asset.balanceOf, address(this).balance) is found in its call tree -
    meaning the exchange-rate denominator CAN be inflated by directly
    transferring tokens into the contract (the donation-attack precondition).

    Protocols that track assets via internal accounting (a state variable
    updated only through tracked deposit/withdraw/accrual deltas, e.g.
    Aave, Compound, Exactly) are NOT balance-derived and are immune to
    this specific attack vector even without a virtual-shares offset.
    """
    if _visited is None:
        _visited = set()
    if depth == 0 or node_id in _visited:
        return False
    _visited.add(node_id)
    for edge in graph_edges.get(node_id, []):
        name = (edge.function_name or "").lower()
        if "balanceof" in name or "address(this).balance" in name:
            return True
        if _rate_is_balance_derived(edge.dst, graph_edges, depth - 1, _visited):
            return True
    return False


def _check_share_inflation(path, nodes, graph_edges) -> ConstraintResult:
    """
    Detect ERC4626 vault share inflation and donation attack patterns.
    Pattern: deposit/mint reads exchange rate from totalAssets/totalSupply
    without rounding protection or virtual offset.
    Real exploits: Wise Lending $460k, Sonne Finance $20M, numerous 2024 vaults.
    """
    if path.sink.category != ASSET_DRAIN:
        return _suppressed(path, "Not an asset drain path")

    inflation_signals = {
        "totalassets", "totalsupply", "converttoshares", "converttoassets",
        "previewdeposit", "previewmint", "previewwithdraw", "previewredeem",
        "exchangerate", "getrate", "pricepereshare", "shareprice",
        "assetsperShare", "virtualoffset", "decimalsoffset",
    }

    rounding_protection = {
        "offset", "virtual", "dead", "minimum", "minshares",
        "decimalsoffset", "roundingoffset",
    }

    donation_signals = {
        "donate", "transfer", "directtransfer", "selfbalance",
        "address(this).balance", "balanceof",
    }

    inflation_reads = []
    has_rounding_protection = False
    has_donation_vector = False

    for edge in path.edge_chain:
        fname = (edge.function_name or "").lower()

        for sig in inflation_signals:
            if sig in fname:
                inflation_reads.append(edge.function_name or fname)

        for sig in rounding_protection:
            if sig in fname:
                has_rounding_protection = True

        for sig in donation_signals:
            if sig in fname:
                has_donation_vector = True

        # One-hop lookahead
        for inner_edge in graph_edges.get(edge.dst, []):
            inner_name = (inner_edge.function_name or "").lower()
            for sig in inflation_signals:
                if sig in inner_name:
                    inflation_reads.append(inner_name)
            for sig in rounding_protection:
                if sig in inner_name:
                    has_rounding_protection = True

    # Re-scan specifically for totalAssets()/totalSupply()-style rate
    # functions (the actual exchange-rate denominator) and check whether
    # any of them is balance-derived. Catches protocols (Aave, Compound,
    # Exactly) that track assets via internal accounting state rather than
    # asset.balanceOf(address(this)), which are immune to the donation/
    # inflation attack precondition even without a virtual-shares offset.
    ACCOUNTING_RATE_SIGNALS = {"totalassets", "totalsupply"}
    rate_node_ids = []
    for edge in path.edge_chain:
        fname = (edge.function_name or "").lower()
        if any(sig in fname for sig in ACCOUNTING_RATE_SIGNALS):
            rate_node_ids.append(edge.dst)
        for inner_edge in graph_edges.get(edge.dst, []):
            inner_name = (inner_edge.function_name or "").lower()
            if any(sig in inner_name for sig in ACCOUNTING_RATE_SIGNALS):
                rate_node_ids.append(inner_edge.dst)

    if rate_node_ids and not any(
        _rate_is_balance_derived(n, graph_edges, depth=2) for n in rate_node_ids
    ):
        return _suppressed(
            path,
            "Exchange rate computed from internal accounting state, not live "
            "balanceOf - donation/inflation attack precondition not met"
        )

    # Check entry node for deposit/mint context
    entry_name = path.entry.split(".")[-1].split("(")[0].lower()
    vault_entry = any(sig in entry_name for sig in (
        "deposit", "mint", "withdraw", "redeem",
        "borrow", "supply", "lend",
    ))

    if not inflation_reads or not vault_entry:
        return _suppressed(path, "No share inflation signals on path")

    if has_rounding_protection:
        return _suppressed(path, "Rounding protection detected — inflation attack unlikely")

    # Confidence scaling
    confidence = 70
    if has_donation_vector:
        confidence = 85  # donation vector + no rounding = classic inflation attack
    if len(inflation_reads) >= 3:
        confidence = min(92, confidence + 10)

    verdict = CONFIRMED if confidence >= 85 else LIKELY

    return ConstraintResult(
        path=path,
        verdict=verdict,
        confidence=confidence,
        constraint_type="SHARE_INFLATION",
        reasoning=(
            f"Vault entry {path.entry} reads exchange rate from {inflation_reads[:3]} "
            f"without rounding protection. "
            f"{'Donation vector detected — first depositor attack possible. ' if has_donation_vector else ''}"
            f"Sink: {path.sink.node_id}. "
            f"Pattern matches ERC4626 inflation attacks (Wise Lending, Sonne Finance)."
        ),
        immunefi_impact="Direct theft of user funds via share price manipulation",
        final_score=_final_score(path, confidence),
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
