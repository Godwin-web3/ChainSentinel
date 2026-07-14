"""
Cross-contract DFS traversal.

Extends graph traversal across CrossContractEdges. No RPC, no protocol
heuristics. An edge only exists in the graph when it was already proven
resolved (see cross_contract.py) — so this module never re-checks
resolution status. It only decides: traverse (None or CrossContractEdge)
or stop and record (BoundaryNode).
"""

from dataclasses import dataclass, field
from typing import Callable, List, Set, Tuple

from core.cross_contract import CrossContractEdge, BoundaryNode


@dataclass
class TraversalResult:
    visited: Set[Tuple[str, str]] = field(default_factory=set)
    boundaries: List[BoundaryNode] = field(default_factory=list)
    edges_traversed: List[CrossContractEdge] = field(default_factory=list)


class CrossContractDFS:
    """
    graph_provider(node) must yield (next_node, edge) pairs where edge is:
        None              — normal intra-contract step, always traverse
        CrossContractEdge — proven resolved, always traverse
        BoundaryNode      — unresolved, record and stop, no next_node
    """

    def __init__(self, graph_provider: Callable, max_depth: int = 8):
        self.graph_provider = graph_provider
        self.max_depth = max_depth

    def run(self, start_node):
        result = TraversalResult()
        self._dfs(start_node, result, depth=0)
        return result

    def _node_key(self, node):
        contract = getattr(node, "contract_name", None) or getattr(node, "contract", "UNKNOWN")
        function = getattr(node, "function_name", None) or getattr(node, "function", "UNKNOWN")
        return (str(contract), str(function))

    def _dfs(self, node, result, depth):
        if depth > self.max_depth:
            return

        key = self._node_key(node)
        if key in result.visited:
            return
        result.visited.add(key)

        for next_node, edge in self.graph_provider(node):
            if edge is None:
                self._dfs(next_node, result, depth + 1)
                continue

            if isinstance(edge, CrossContractEdge):
                result.edges_traversed.append(edge)
                self._dfs(next_node, result, depth + 1)
                continue

            if isinstance(edge, BoundaryNode):
                result.boundaries.append(edge)
                continue
