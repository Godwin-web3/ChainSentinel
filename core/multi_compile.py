"""
Merges FunctionNode/CallEdge graphs from multiple, independently-compiled
Slither runs into one registry keyed by canonical_id.

Why this exists: two real, separately-deployed sibling contracts (e.g.
Aave's Pool and PoolAddressesProvider) can require genuinely incompatible
solc pragma ranges. Forcing them into one Slither compilation unit (the
wrapper approach) fails in that case — there is no single compiler version
that satisfies both. The fix is not smarter imports, it's not requiring a
shared compilation at all.

core/paths.py's enumerate_paths / _dfs already traverses purely by
canonical_id string membership in `nodes` (`if dst not in nodes: continue`).
It has no dependency on which Slither instance produced a node. So merging
two compilations' output dicts by canonical_id is sufficient to let the
existing, already-wired path enumeration cross a real version boundary —
no new DFS logic needed.
"""
import re
from typing import Optional, Tuple, Dict


def extract_pragma_version(filepath: str) -> Optional[str]:
    """
    Reads a .sol file's pragma line and returns an exact version string
    if it's an exact pin (e.g. "pragma solidity 0.8.10;" -> "0.8.10").
    Returns None for range pragmas (^0.8.0, >=0.8.0 <0.9.0, etc) — those
    should just reuse whatever version the caller already has in hand.
    """
    try:
        with open(filepath) as f:
            content = f.read()
    except Exception:
        return None

    match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
    if not match:
        return None

    raw = match.group(1).strip()
    # Exact pin: just digits and dots, no ^, ~, >=, <, etc.
    if re.fullmatch(r'\d+\.\d+\.\d+', raw):
        return raw
    return None


def merge_build_results(
    base: Tuple[Dict, Dict, Dict, Dict, Dict, list],
    other: Tuple[Dict, Dict, Dict, Dict, Dict, list],
) -> Tuple[Dict, Dict, Dict, Dict, Dict, list]:
    """
    Merges two build_graph() return tuples into one, by canonical_id.
    canonical_id (Contract.function(types)) is globally unique by
    construction, so a plain dict union is safe — no collision handling
    needed beyond "other wins on exact duplicate key", which should never
    happen in practice since these come from genuinely different contracts.

    Returns a tuple in the same shape build_graph() returns, so callers
    (enumerate_paths, validate_paths) need no changes at all.
    """
    base_nodes, base_edges, base_writers, base_readers, base_invariants, base_unresolved = base
    other_nodes, other_edges, other_writers, other_readers, other_invariants, other_unresolved = other

    merged_nodes = {**base_nodes, **other_nodes}
    merged_edges = {**base_edges, **other_edges}
    merged_writers = {**base_writers, **other_writers}
    merged_readers = {**base_readers, **other_readers}
    merged_invariants = {**base_invariants, **other_invariants}
    merged_unresolved = list(base_unresolved) + list(other_unresolved)

    return merged_nodes, merged_edges, merged_writers, merged_readers, merged_invariants, merged_unresolved


def rewrite_unresolved_edges(
    graph_edges: Dict,
    dependency_nodes: Dict,
    var_name: str,
) -> int:
    """
    Rewrites CallEdge.dst in place for edges matching the
    "external.{var_name}.{function_name}" pattern (the label
    resolve_call() produces when a call target is a known on-chain
    address it can't resolve within the current compilation unit —
    see core/edges.py's _resolve_dst).

    Once the dependency has been compiled separately and its real
    FunctionNodes are available (dependency_nodes, keyed by
    canonical_id), this looks up the matching function by name and
    rewrites dst to the real canonical_id — but ONLY when exactly one
    function in the dependency matches that name. Ambiguous matches
    (overloads, or the same name on multiple contracts within the
    dependency) are left unresolved rather than guessed — same
    no-guessing discipline as resolve_call() itself.

    Returns the count of edges actually rewritten.
    """
    prefix = f"external.{var_name}."
    rewritten = 0

    for edges in graph_edges.values():
        for edge in edges:
            if not str(edge.dst).startswith(prefix):
                continue

            label = str(edge.dst)[len(prefix):]

            # label is now the real typed signature ("getPriceOracle()",
            # "someFn(address,uint256)") whenever core/edges.py had one
            # from resolution.interface_signature — real data straight
            # from Slither's IR, not a bare function name. Match EXACTLY
            # on this full signature. Do not fall back to name-only
            # matching: a name match with the wrong arg types is a false
            # resolution, worse than leaving the edge honestly unresolved.
            if "(" not in label:
                continue  # no real signature available — cannot safely match

            candidates = [
                cid for cid in dependency_nodes
                if cid.split(".", 1)[-1] == label
            ]

            if len(candidates) == 1:
                edge.dst = candidates[0]
                rewritten += 1
            # len == 0: dependency doesn't define this exact signature
            #   (inherited from an unfetched base, or genuinely absent)
            # len > 1: identical signature on multiple contracts within
            #   the dependency — leave unresolved, don't guess

    return rewritten
