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
    CALLBACK_SINK, SELFDESTRUCT_SINK, _is_asset_transfer,
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
):
    if depth > MAX_DEPTH:
        return
    if len(paths) >= MAX_PATHS:
        return
    if current_id in visited:
        return

    visited = visited | {current_id}  # immutable copy per path branch

    # Check if current node is a sink
    if current_id in sinks and depth > 0:
        sink = sinks[current_id]
        flags = set(accumulated_flags)

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

    # Get current node
    node = nodes.get(current_id)
    if node is None:
        return

    # Track state writes before external calls (reentrancy signal).
    # Detect CEI violation: state written AND an external call exists
    # on the SAME function. The previous condition (external_seen &&
    # node_has_state && node_has_external) only fired on the second
    # external call, missing single-hop withdraw() { state--; transfer(); }.
    node_has_state = bool(getattr(node, 'state_writes', set()))
    node_has_external = any(
        e.is_external for e in graph_edges.get(current_id, [])
    )
    if node_has_state and node_has_external:
        accumulated_flags = accumulated_flags | {STATE_BEFORE_CALL}

    # Auth gap on this node
    auth = getattr(node, 'auth_state', 'UNKNOWN')
    if auth == 'UNAUTHENTICATED':
        accumulated_flags = accumulated_flags | {AUTH_GAP}

    # Walk edges
    for edge in graph_edges.get(current_id, []):
        new_flags = set(accumulated_flags)

        if edge.is_external:
            new_flags.add(EXTERNAL_CALL)
            new_state_written = node_has_state
            new_external_seen = True
        else:
            new_state_written = state_written or node_has_state
            new_external_seen = external_seen

        if edge.is_delegation:
            new_flags.add(DELEGATION)
        if edge.uncertain:
            new_flags.add(UNCERTAIN_TARGET)

        # Only follow edges to known internal nodes
        # External unresolved destinations are terminal — don't recurse
        dst = edge.dst
        if dst.startswith("external.") or dst.startswith("lowlevel.") or dst.startswith("eth."):
            # Terminal external call — check if it's a sink pattern
            if edge.is_value_transfer or _is_asset_transfer(
                (edge.function_name or "").lower()
            ):
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
