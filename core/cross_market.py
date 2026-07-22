"""
core/cross_market.py — Cross-contract / cross-market reentrancy detection

Real-world root cause behind Cream Finance ($18.8M, Aug 2021), dForce/
Lendf.me ($25M, Apr 2020), and Rari Capital Fuse ($80M, Apr 2022): a
per-contract reentrancy guard protects exactly one market. When a
protocol shares cross-market state — e.g. a Comptroller-style hub that
computes a user's total borrowed value by calling out to every market
they've entered — a checks-effects-interactions violation in Market A,
reachable via an attacker-controlled callback, can be exploited by
reentering a completely DIFFERENT contract, Market B, whose own guard
is fully correct and irrelevant: it protects against recursive calls
into itself, not against being called for the first time while Market
A's bookkeeping is mid-flight. Market B then reads Market A's stale
state through the shared hub and makes a decision (e.g. "does this user
have enough collateral to borrow more") based on data that hasn't been
written yet.

core/constraints.py's REENTRANCY_CEI checks for a guard on the entry
function's OWN call chain. core/constraints.py's CROSS_FUNCTION_STATE_RACE
checks for a write-after-callback within ONE function, filtered to
fields a LOCAL invariant/assertion elsewhere in the SAME contract also
references. Neither can see this shape even in principle: both reason
about one function or one contract's own call chain. This module
requires a UNIFIED graph spanning multiple contracts (see
core/protocol_graph.py) and walks REAL, Slither-resolved cross-contract
edges — never a name guess or an assumed relationship — to find entry
points in OTHER contracts whose reachable state reads overlap with a
window where THIS entry point has handed control to an attacker but not
yet finalized its own state.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class CrossMarketFinding:
    vulnerable_entry: str        # e.g. "MarketA.borrow(uint256)" — has the CEI violation
    reentry_entry: str           # e.g. "MarketB.borrow(uint256)" — attacker's reentry target
    shared_read_path: List[str]  # real node-id chain proving the read, e.g.
                                  # ["MarketB.borrow(uint256)", "Hub.totalBorrowed(address)",
                                  #  "MarketA.accountBorrowsOf(address)"]
    at_risk_keys: Set[tuple]     # the (contract, root, member_path) keys read stale
    call_event: object           # the CallEvent (from invariants.py) that opens the window
    callback_target_known: bool  # True if the callback-triggering call resolves to a
                                  # contract already present in the unified graph (a
                                  # protocol-owned contract, e.g. Compound's own
                                  # Comptroller) rather than a genuinely external/
                                  # unresolved target (an arbitrary token/contract the
                                  # caller supplies, e.g. the AMP token in the real
                                  # Cream hack). A known-internal target is materially
                                  # LOWER confidence: reentrancy needs the attacker to
                                  # receive control, and a fixed, protocol-deployed
                                  # contract handing control to an attacker requires
                                  # that contract to ITSELF call something external —
                                  # a deeper chain this check does not verify. An
                                  # unresolved/external target is the classic, high-
                                  # confidence shape: the call target is exactly the
                                  # kind of address a caller can supply arbitrarily.


def _transitive_reads(entry_id: str, nodes: dict, graph_edges: dict, max_depth: int = 6):
    """
    Breadth-first walk of the RESOLVED call graph from entry_id, following
    both internal calls and cross-contract edges that Slither's own
    resolution already proved (core/edges.py / core/call_resolution.py) —
    unresolved/boundary edges simply aren't in graph_edges as real dst
    IDs, so they're naturally excluded, never explicitly filtered here.

    Returns:
      qualified_reads: set of (contract, root, member_path) — every state
        read by every function reached, qualified by THAT function's OWN
        contract (never the calling contract). This is what makes "Hub
        reads MarketA's storage via MarketA's own getter" attribute
        correctly to MarketA, not to Hub.
      read_paths: dict mapping each qualified read key to the real node-id
        chain that reaches it, for reporting an actual trace rather than
        just asserting an overlap exists.
    """
    qualified_reads: Set[tuple] = set()
    read_paths: Dict[tuple, List[str]] = {}
    visited: Set[str] = set()
    frontier: List[Tuple[str, List[str]]] = [(entry_id, [entry_id])]
    depth = 0
    while frontier and depth < max_depth:
        next_frontier = []
        for node_id, path_so_far in frontier:
            if node_id in visited:
                continue
            visited.add(node_id)
            node = nodes.get(node_id)
            if node is None:
                continue
            for k in getattr(node, "reads", ()):
                qkey = (node.contract, k[0], k[1])
                if qkey not in qualified_reads:
                    qualified_reads.add(qkey)
                    read_paths[qkey] = path_so_far
            for edge in graph_edges.get(node_id, []):
                dst = edge.dst
                if dst in nodes and dst not in visited:
                    next_frontier.append((dst, path_so_far + [dst]))
        frontier = next_frontier
        depth += 1
    return qualified_reads, read_paths


def _callback_target_known(vuln_id: str, call_event, nodes: dict, graph_edges: dict) -> bool:
    """
    True if the specific call that opens the reentrancy window resolves
    to a contract already present in this unified graph — a known,
    protocol-owned contract (e.g. Compound's own Comptroller) — rather
    than a genuinely unresolved/external target (an arbitrary token or
    contract the caller supplies, e.g. the AMP token in the real Cream
    hack). Matched by function name against call_event's expression text
    since CallEdge doesn't carry a direct per-event back-reference;
    falls back to "do ALL of this function's non-internal edges resolve"
    when no confident single-edge match exists.
    """
    for edge in graph_edges.get(vuln_id, []):
        if edge.raw_type == "internal":
            continue
        if edge.function_name and edge.function_name in call_event.node_expr_str:
            return edge.dst in nodes
    external_edges = [e for e in graph_edges.get(vuln_id, []) if e.raw_type != "internal"]
    if not external_edges:
        return False
    return all(e.dst in nodes for e in external_edges)


def check_cross_market_reentrancy(nodes: Dict[str, object], graph_edges: dict) -> List[CrossMarketFinding]:
    """
    For every function with a genuine post-callback write (i.e. a real
    checks-effects-interactions violation — see
    FunctionNode.state_writes_after_callback), check every OTHER
    external/public, state-changing entry point in a DIFFERENT contract
    within the same unified graph: does ITS transitive read set overlap
    with the fields THIS function leaves stale during its callback
    window?

    Deliberately excludes same-contract reentry targets — that shape is
    REENTRANCY_CEI's job, already covered. This only fires on genuine
    cross-contract reentry, the shape neither existing check can see.
    """
    from core.constraints import _entry_has_direct_auth, _auth_check_in_subgraph

    findings: List[CrossMarketFinding] = []

    vulnerable = [
        (nid, n) for nid, n in nodes.items()
        if getattr(n, "state_writes_after_callback", None)
        and getattr(n, "visibility", None) in ("public", "external")
        # Reuses the SAME auth-signal detection REENTRANCY_CEI's sibling
        # checks already rely on (modifiers, auth_score, name patterns,
        # or an auth check within 3 hops of the entry) — an entry that's
        # already gated isn't a free attacker-reachable trigger. Known
        # gap, not silently papered over: an auth check enforced via an
        # UNRESOLVED cross-contract call (e.g. Compound's CToken.seize()
        # gating through comptroller.seizeAllowed(), found live — see
        # this module's git history) isn't visible to either check here,
        # since neither can walk into an edge that didn't resolve.
        and not _entry_has_direct_auth(nid, nodes)
        and not _auth_check_in_subgraph(nid, nodes, graph_edges)
    ]
    if not vulnerable:
        return findings

    # Candidate reentry targets: external/public functions that actually
    # write state (a pure getter can't cause harm even if it reads stale
    # data — the harm comes from a DECISION made using that stale read).
    reentry_candidates = [
        (nid, n) for nid, n in nodes.items()
        if getattr(n, "visibility", None) in ("public", "external")
        and getattr(n, "state_writes", None)
        and not getattr(n, "is_view", False)
    ]

    read_cache: Dict[str, Tuple[Set[tuple], Dict[tuple, List[str]]]] = {}

    for vuln_id, vuln_node in vulnerable:
        for call_event, at_risk in vuln_node.state_writes_after_callback:
            at_risk_qualified = {(vuln_node.contract, k[0], k[1]) for k in at_risk}
            for reentry_id, reentry_node in reentry_candidates:
                if reentry_node.contract == vuln_node.contract:
                    continue
                if reentry_id not in read_cache:
                    read_cache[reentry_id] = _transitive_reads(reentry_id, nodes, graph_edges)
                reads, read_paths = read_cache[reentry_id]
                overlap = reads & at_risk_qualified
                if overlap:
                    key = next(iter(overlap))
                    findings.append(CrossMarketFinding(
                        vulnerable_entry=vuln_id,
                        reentry_entry=reentry_id,
                        shared_read_path=read_paths.get(key, [reentry_id]),
                        at_risk_keys=overlap,
                        call_event=call_event,
                        callback_target_known=_callback_target_known(vuln_id, call_event, nodes, graph_edges),
                    ))

    return findings
