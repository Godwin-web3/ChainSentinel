"""
core/paths.py — Exploit path enumeration

Walks from EOA-reachable entrypoints through typed edges to classified sinks.
Only emits paths where damage is reachable. No symbolic execution yet.
Constraint flags on each path tell constraints.py what to validate.

Design decisions backed by research:
- DFS not BFS: avoids memory explosion on deep graphs (DeFiTainter approach)
- Depth limit 8: covers 99% of real DeFi call chains, prevents combinatorial blowup
- Cycle detection per path: prevents infinite loops through recursive functions
- Path keyed as tuple: (entry, edge_chain, sink) — unique, hashable, comparable
- Constraint flags emitted per path, not evaluated here (that's constraints.py)

Constraint flags:
  AUTH_GAP          entrypoint or intermediate node is UNAUTHENTICATED
  EXTERNAL_CALL     path crosses trust boundary before sink
  STATE_BEFORE_CALL state written before an external call (reentrancy signal)
  DELEGATION        delegatecall on path
  UNCERTAIN_TARGET  dynamic call or unresolved destination on path
  PRIVILEGED_SINK   sink writes privileged storage slot
  ASSET_SINK        sink moves tokens or ETH
"""

from dataclasses import dataclass, field
from typing import List, Set, Optional
from core.edges import CallEdge
from core.sinks import (
    Sink, ASSET_DRAIN, STORAGE_CORRUPTION, DELEGATION_SINK,
    CALLBACK_SINK, SELFDESTRUCT_SINK,
)

# ── Constants ─────────────────────────────────────────────────────

MAX_DEPTH = 8          # max call chain length
MAX_PATHS = 500        # cap total paths per contract to prevent blowup

# Constraint flag constants
AUTH_GAP          = "AUTH_GAP"
EXTERNAL_CALL     = "EXTERNAL_CALL"
STATE_BEFORE_CALL = "STATE_BEFORE_CALL"
DELEGATION        = "DELEGATION"
UNCERTAIN_TARGET  = "UNCERTAIN_TARGET"
PRIVILEGED_SINK   = "PRIVILEGED_SINK"
ASSET_SINK        = "ASSET_SINK"
SELFDESTRUCT      = "SELFDESTRUCT"


# ── Data model ────────────────────────────────────────────────────

@dataclass
class ExploitPath:
    entry: str                          # canonical ID of EOA-reachable entrypoint
    edge_chain: List[CallEdge]          # ordered list of edges from entry to sink
    sink: Sink                          # classified sink at end of path
    constraint_flags: Set[str]          # what constraints.py needs to validate
    path_score: int                     # combined score: sink severity + flag weights
    hops: int                           # number of edges in chain
    reasoning: str                      # human-readable summary


# ── Flag weight for path scoring ──────────────────────────────────

FLAG_WEIGHTS = {
    AUTH_GAP:          5,
    EXTERNAL_CALL:     2,
    STATE_BEFORE_CALL: 4,    # reentrancy signal
    DELEGATION:        4,
    UNCERTAIN_TARGET:  3,
    PRIVILEGED_SINK:   3,
    ASSET_SINK:        3,
    SELFDESTRUCT:      5,
}


# ── Path enumeration ──────────────────────────────────────────────

def enumerate_paths(
    nodes: dict,
    graph_edges: dict,
    sinks: dict,
) -> List[ExploitPath]:
    """
    Enumerate all exploit paths from EOA-reachable entrypoints to classified sinks.

    Args:
        nodes:       canonical_id -> FunctionNode
        graph_edges: canonical_id -> List[CallEdge]
        sinks:       canonical_id -> Sink

    Returns:
        List of ExploitPath, sorted by path_score descending
    """
    paths = []

    # Seed: EOA-reachable entrypoints only
    entrypoints = [
        cid for cid, node in nodes.items()
        if getattr(node, 'reachable_from_untrusted', False)
        and not getattr(node, 'is_constructor', False)
        and not getattr(node, 'is_modifier', False)
        and not getattr(node, 'is_view', False)
        and not getattr(node, 'is_library', False)
        and node.visibility in ('public', 'external')
    ]

    for entry_id in entrypoints:
        if len(paths) >= MAX_PATHS:
            break

        _dfs(
            current_id=entry_id,
            entry_id=entry_id,
            edge_chain=[],
            visited=set(),
            nodes=nodes,
            graph_edges=graph_edges,
            sinks=sinks,
            paths=paths,
            depth=0,
            accumulated_flags=set(),
            state_written=False,
            external_seen=False,
            self_bound_params=frozenset(),
            trusted_bound_params=frozenset(),
        )

    return sorted(paths, key=lambda p: p.path_score, reverse=True)


def _dfs(
    current_id: str,
    entry_id: str,
    edge_chain: List[CallEdge],
    visited: Set[str],
    nodes: dict,
    graph_edges: dict,
    sinks: dict,
    paths: List[ExploitPath],
    depth: int,
    accumulated_flags: Set[str],
    state_written: bool,
    external_seen: bool,
    self_bound_params: Set[str],
    trusted_bound_params: Set[str],
):
    if depth > MAX_DEPTH:
        return
    if len(paths) >= MAX_PATHS:
        return
    if current_id in visited:
        return

    visited = visited | {current_id}  # immutable copy per path branch

    # Get current node
    node = nodes.get(current_id)

    # This node's OWN structural evidence — needed BEFORE the sink-check
    # below, because a node can be its own vulnerability: the classic
    # CEI-violation shape (state write + external call in the SAME
    # function) IS what makes a node CALLBACK_SINK/ASSET_DRAIN in the
    # first place, and an unauthenticated function that directly does
    # the dangerous thing (no intermediate hop) is exactly Uniswap V3's
    # swap()/flash() — an untrusted callback with open state writes, no
    # helper function involved at all.
    #
    # Previously this evidence was computed AFTER the sink-check and
    # only fed to CHILDREN via accumulated_flags — meaning a sink node's
    # own external-call/state-write/auth evidence never appeared on its
    # OWN recorded path. Combined with the sink-check being gated to
    # depth > 0 (skipping the entry outright), this silently produced
    # zero REENTRANCY_CEI findings for the textbook single-function CEI
    # shape whenever the vulnerable function itself was the sink, at ANY
    # depth — confirmed live with a synthetic withdraw() -> _doWithdraw()
    # (state write after an unguarded external call) probe, which
    # produced 0 findings despite being an unguarded, real violation.
    node_has_state = bool(getattr(node, 'state_writes', set())) if node else False
    node_has_external = any(
        e.is_external for e in graph_edges.get(current_id, [])
    ) if node else False
    # A genuine execution-order CEI violation — a state write CFG-
    # reachable from an external call this node makes — not merely
    # "this node has both a state write and an external call somewhere,
    # regardless of order" (core/auth_detection.py::
    # has_state_write_after_external_call). The old co-occurrence
    # signal couldn't distinguish real Liquity's _sendETHGainToDepositor
    # (writes ETH BEFORE its ETH send — CEI-compliant for that
    # variable) from an actual violation.
    node_write_follows_call = bool(node) and getattr(node, 'state_write_follows_external_call', False)
    node_unauthenticated = bool(node) and getattr(node, 'auth_state', 'UNKNOWN') == 'UNAUTHENTICATED'

    # Flags used ONLY to decide whether THIS node registers as a sink.
    # EXTERNAL_CALL here means "this node itself makes an external
    # call" — deliberately kept separate from the edge-specific
    # EXTERNAL_CALL added per-child below (which means "the specific
    # edge walked to reach that child crossed a trust boundary"), so a
    # node with an external edge to one child doesn't leak EXTERNAL_CALL
    # onto an unrelated sibling reached via a purely internal edge.
    sink_check_flags = set(accumulated_flags)
    if node_write_follows_call:
        sink_check_flags.add(STATE_BEFORE_CALL)
    if node_has_external:
        sink_check_flags.add(EXTERNAL_CALL)
    if node_unauthenticated:
        sink_check_flags.add(AUTH_GAP)

    # Check if current node is a sink — including the entry itself
    # (depth 0): a function can be its own sink, so this is no longer
    # gated to depth > 0.
    if current_id in sinks:
        sink = sinks[current_id]
        flags = set(sink_check_flags)

        # Add sink-level flags
        if sink.category in (ASSET_DRAIN,):
            flags.add(ASSET_SINK)
        if sink.category == STORAGE_CORRUPTION:
            flags.add(PRIVILEGED_SINK)
        if sink.category == DELEGATION_SINK:
            flags.add(DELEGATION)
        if sink.category == SELFDESTRUCT_SINK:
            flags.add(SELFDESTRUCT)

        path = _build_path(entry_id, edge_chain, sink, flags, nodes)
        paths.append(path)
        # Don't return — sink may also have outgoing edges worth following
        # But cap to avoid path explosion through sink nodes
        if depth >= MAX_DEPTH - 2:
            return

    if node is None:
        return

    # Flags propagated to children: STATE_BEFORE_CALL/AUTH_GAP fold in
    # this node's own evidence (matches the sink-check flags above);
    # EXTERNAL_CALL stays edge-specific, added per-edge in the loop
    # below rather than here.
    if node_write_follows_call:
        accumulated_flags = accumulated_flags | {STATE_BEFORE_CALL}
    if node_unauthenticated:
        accumulated_flags = accumulated_flags | {AUTH_GAP}

    # self_bound_params/trusted_bound_params (function parameters,
    # accumulated as DFS state) are already exactly "which of
    # current_id's OWN parameters were proven self/trusted by the
    # specific call chain that reached it" — composed transitively
    # hop-by-hop below, not just from the single last edge, because a
    # proof can cross MULTIPLE internal/library calls before landing on
    # the parameter that actually gates something. Real shape found
    # live this session against Flaunch's PositionManager (Base):
    # beforeSwap passes its own `poolManager` immutable into
    # _internalSwap's `_poolManager` parameter, and _internalSwap
    # passes THAT parameter into CurrencySettler.settle's `manager`
    # parameter two hops later — proving `manager` trusted requires
    # chaining both hops, not just looking at settle's own direct
    # caller.

    # Walk edges
    for edge in graph_edges.get(current_id, []):
        # Prune an edge whose underlying node is only reachable via a
        # branch requiring one of THIS function's own parameters to
        # NOT equal address(this), when the call chain that got us into
        # this function PROVED that parameter was literally
        # address(this) — see core/edges.py's module docstring above
        # _self_gated_branches for the real Flaunch CurrencySettler.
        # settle() false positive this fixes. Only prunes on a PROVEN
        # contradiction (requires_self=False + proven self-bound);
        # never prunes on missing/unknown information.
        if edge.param_gate_requirements and any(
            (not requires_self) and (pname in self_bound_params)
            for pname, requires_self in edge.param_gate_requirements
        ):
            continue

        new_flags = set(accumulated_flags)

        if edge.is_external:
            new_flags.add(EXTERNAL_CALL)
            new_state_written = node_has_state
            new_external_seen = True
            # A different contract's own parameters/`this` share
            # nothing with the caller's — reset both accumulators.
            new_self_bound_params = frozenset()
            new_trusted_bound_params = frozenset()
        else:
            new_state_written = state_written or node_has_state
            new_external_seen = external_seen
            # Internal/library call: compose the callee's own
            # standalone proofs with transitively-propagated ones —
            # a passthrough param is proven only if the caller_param
            # it names was ITSELF already proven at this hop.
            new_self_bound_params = edge.self_bound_params | frozenset(
                callee_param
                for callee_param, caller_param in edge.self_passthrough_params.items()
                if caller_param in self_bound_params
            )
            new_trusted_bound_params = edge.trusted_bound_params | frozenset(
                callee_param
                for callee_param, caller_param in edge.trusted_passthrough_params.items()
                if caller_param in trusted_bound_params
            )

        if edge.is_delegation:
            new_flags.add(DELEGATION)
        if edge.uncertain:
            new_flags.add(UNCERTAIN_TARGET)

        # Only follow edges to known internal nodes
        # External unresolved destinations are terminal — don't recurse
        dst = edge.dst
        if dst.startswith("external.") or dst.startswith("lowlevel.") or dst.startswith("eth."):
            # Terminal external call — check if it's a sink pattern.
            # A transfer to a PROVEN-trusted destination (immutable/
            # constant/auth-gated, exactly the same bar CALLBACK_SINK
            # already requires elsewhere in this file) is not "direct
            # theft of user funds" — the classic ASSET_DRAIN exploit
            # pattern is an attacker REDIRECTING where funds go, which
            # is structurally impossible when the destination can never
            # vary. edge.trusted covers the direct case (destination is
            # this function's own state variable/immutable); the
            # dest_param_name + trusted_bound_params check covers a
            # shared library function whose destination is one of ITS
            # OWN parameters, proven fixed only by the specific call
            # chain that reached it (see core/edges.py's module
            # docstring above _destination_param_name for the real
            # Flaunch CurrencySettler.settle false positive this
            # fixes). Amount-correctness (was the right AMOUNT sent,
            # not just to the right place) is a different question,
            # covered by the dedicated precision-loss/fee-on-transfer/
            # vault-share-inflation detectors — not weakened here.
            dest_trusted = edge.trusted or (
                edge.dest_param_name is not None
                and edge.dest_param_name in trusted_bound_params
            )
            if (edge.is_value_transfer or edge.is_token_transfer) and not dest_trusted:
                # Synthesize a terminal asset drain path
                # Inherit state_writes from the calling node so the
                # structural health-check overlap test in constraints.py
                # (_node_touches_sink_state / _guard_constrains_sink_state)
                # can see the same storage the sink mutates. Without this,
                # MISSING_HEALTH_CHECK is dead for all terminal asset paths.
                terminal_sink = Sink(
                    node_id=dst,
                    category=ASSET_DRAIN,
                    severity=10,
                    evidence=f"direct asset transfer to {dst}",
                    asset_flows=[str(dst)],
                    state_writes=set(getattr(node, 'state_writes', set())),
                )
                flags = new_flags | {ASSET_SINK}
                path = _build_path(entry_id, edge_chain + [edge], terminal_sink, flags, nodes)
                paths.append(path)
            continue

        if dst not in nodes:
            continue

        _dfs(
            current_id=dst,
            entry_id=entry_id,
            edge_chain=edge_chain + [edge],
            visited=visited,
            nodes=nodes,
            graph_edges=graph_edges,
            sinks=sinks,
            paths=paths,
            depth=depth + 1,
            accumulated_flags=new_flags,
            state_written=new_state_written,
            external_seen=new_external_seen,
            self_bound_params=new_self_bound_params,
            trusted_bound_params=new_trusted_bound_params,
        )


def _build_path(
    entry_id: str,
    edge_chain: List[CallEdge],
    sink: Sink,
    flags: Set[str],
    nodes: dict,
) -> ExploitPath:
    """Construct an ExploitPath from accumulated DFS state."""

    # Path score: sink severity + flag weights
    score = sink.severity
    for flag in flags:
        score += FLAG_WEIGHTS.get(flag, 0)

    # Reasoning string
    chain_str = " -> ".join(
        [entry_id] + [e.dst for e in edge_chain]
    )
    flag_str = ", ".join(sorted(flags)) if flags else "none"
    reasoning = (
        f"Path: {chain_str}\n"
        f"Sink: [{sink.category}] {sink.node_id}\n"
        f"Flags: {flag_str}\n"
        f"Evidence: {sink.evidence}"
    )

    return ExploitPath(
        entry=entry_id,
        edge_chain=edge_chain,
        sink=sink,
        constraint_flags=flags,
        path_score=score,
        hops=len(edge_chain),
        reasoning=reasoning,
    )


# ── API ───────────────────────────────────────────────────────────

def top_paths(paths: List[ExploitPath], min_score: int = 10) -> List[ExploitPath]:
    """Return paths above score threshold."""
    return [p for p in paths if p.path_score >= min_score]
