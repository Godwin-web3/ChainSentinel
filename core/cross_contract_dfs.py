"""
Cross-contract DFS traversal.

Nodes are plain cid strings ("Contract.function(types)"), matching
core/graph.py's canonical_id() convention exactly. No RPC, no protocol
heuristics. An edge only exists in the graph when it was already proven
resolved (see cross_contract.py) — this module never re-checks status,
it only decides: traverse, or stop and record a boundary.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Set

from core.cross_contract import CrossContractEdge, BoundaryNode


@dataclass
class TraversalResult:
    visited: Set[str] = field(default_factory=set)
    boundaries: List[BoundaryNode] = field(default_factory=list)
    edges_traversed: List[CrossContractEdge] = field(default_factory=list)


class CrossContractDFS:
    """
    graph_provider(cid) must yield (next_cid, edge) pairs where edge is:
        None              — normal intra-contract step, always traverse
        CrossContractEdge — proven resolved, always traverse to next_cid
        BoundaryNode      — unresolved, record and stop, next_cid is None
    """

    def __init__(self, graph_provider: Callable, max_depth: int = 8):
        self.graph_provider = graph_provider
        self.max_depth = max_depth

    def run(self, start_cid: str):
        result = TraversalResult()
        self._dfs(start_cid, result, depth=0)
        return result

    def _dfs(self, cid: str, result: TraversalResult, depth: int):
        if depth > self.max_depth:
            return
        if cid in result.visited:
            return
        result.visited.add(cid)

        for next_cid, edge in self.graph_provider(cid):
            if edge is None:
                if next_cid is not None:
                    self._dfs(next_cid, result, depth + 1)
                continue

            if isinstance(edge, CrossContractEdge):
                result.edges_traversed.append(edge)
                if next_cid is not None:
                    self._dfs(next_cid, result, depth + 1)
                continue

            if isinstance(edge, BoundaryNode):
                result.boundaries.append(edge)
                continue
