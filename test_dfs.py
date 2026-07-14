import os
from core.graph import build_graph
from core.cross_contract import CrossContractEdge, BoundaryNode
from core.cross_contract_dfs import CrossContractDFS

nodes, graph_edges, state_writers, state_readers, invariant_index = build_graph(
    project_root=os.path.abspath('fixture'),
    entry_file=os.path.abspath('fixture/CrossContractTest.sol'),
    solc_version='0.8.13',
    enrichment={},
)

def graph_provider(cid):
    node = nodes.get(cid)
    if node is None:
        return
    for callee_id in node.internal_callees:
        yield callee_id, None
    for edge in getattr(node, 'cross_contract_edges', []):
        if isinstance(edge, CrossContractEdge):
            dst_cid = f"{edge.dst_contract}.{edge.dst_function}"
            yield (dst_cid if dst_cid in nodes else None), edge
        elif isinstance(edge, BoundaryNode):
            yield None, edge

start = "VaultImmutable.getValue(address)"
print("start node exists in graph:", start in nodes)

dfs = CrossContractDFS(graph_provider)
result = dfs.run(start)

print("VISITED:", result.visited)
print("EDGES TRAVERSED:", result.edges_traversed)
print("BOUNDARIES:", result.boundaries)
