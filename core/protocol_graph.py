"""
core/protocol_graph.py — Unified multi-contract graph for protocol-level analysis

Builds ONE compilation unit + ONE graph spanning a Comptroller-style hub
and every DISTINCT market implementation it enumerates, instead of
analyzing one contract in isolation. This is what makes
core/cross_market.py's cross-contract reentrancy detection possible at
all — it needs real, Slither-resolved edges between sibling markets and
their shared hub, which a single-contract compilation unit structurally
cannot produce.

Scope: only fires when the entry contract has a real, discoverable
enumeration getter (core/graph.find_any_enumeration_getter — the same
real, IR-grounded signal already used for cross-contract dependency
resolution and market discovery elsewhere in this codebase). Never a
name guess, never assumed.
"""

from typing import Optional, Tuple
from config.chains import Chain
from core.resolver import resolve
from core.graph import build_graph, find_any_enumeration_getter
from core.dependency_fetcher import merge_dependency_source, build_wrapper_entry
from core.multi_compile import extract_pragma_version, merge_build_results
from utils.rpc import get_address_array
from utils.logger import log


def build_protocol_graph(
    entry_address: str,
    entry_name: str,
    chain: Chain,
    project_root: str,
    entry_file: str,
    solc_version: str,
    enrichment: dict,
    base_build: Tuple[dict, dict, dict, dict, dict, list],
    remaps: Optional[list] = None,
    max_markets_scanned: int = 60,
    max_distinct_implementations: int = 6,
):
    """
    Extends a single-contract graph (base_nodes, already built for
    entry_address) into a unified graph spanning the entry contract and
    every DISTINCT market implementation reachable through a real
    array-returning getter.

    Returns (nodes, graph_edges, notes) or None if entry_address has no
    discoverable enumeration getter — this contract isn't a protocol hub
    by this definition, nothing to build.

    Deduping by real on-chain implementation address (not by market
    address) matters for two reasons: most markets in a delegate-proxy
    protocol share the SAME implementation, so compiling it once is both
    correct and tractable — but genuinely DIFFERENT implementations
    (e.g. a CEther market vs. a CErc20 market) are kept as distinct
    compiled contracts, which is exactly what makes cross-market
    reentrancy between them detectable at all (the real Cream Finance
    hack was crAMP, a CErc20-shaped delegate, reentering crETH, a
    CEther-shaped delegate — genuinely different source).
    """
    base_nodes = base_build[0]
    found = find_any_enumeration_getter(base_nodes, entry_name)
    if not found:
        return None
    getter_signature, element_type = found

    addresses = get_address_array(entry_address, getter_signature, chain, limit=max_markets_scanned)
    if not addresses:
        return None

    notes = [{
        "enumeration_getter": getter_signature,
        "element_type": element_type,
        "markets_found": len(addresses),
    }]
    log.info(f"Protocol graph: {getter_signature} found {len(addresses)} market(s), resolving distinct implementations")

    seen_impls = set()
    dependency_entry_files = []
    for addr in addresses:
        if len(seen_impls) >= max_distinct_implementations:
            break
        try:
            resolved = resolve(addr, chain)
        except Exception as e:
            notes.append({"market": addr, "status": "resolve_failed", "reason": str(e)})
            continue
        if not resolved or not resolved.get("verified"):
            continue
        impl_addr = resolved["address"]
        if impl_addr in seen_impls:
            continue
        seen_impls.add(impl_addr)
        merge_result = merge_dependency_source(impl_addr, chain, project_root)
        if merge_result.wrote and merge_result.entry_file:
            dependency_entry_files.append(merge_result.entry_file)
            notes.append({
                "market": addr, "implementation": impl_addr,
                "name": resolved.get("name"), "status": "fetched",
            })
            log.info(f"Protocol graph: distinct implementation {resolved.get('name')} @ {impl_addr} (market {addr})")

    if not dependency_entry_files:
        notes.append({"status": "no_distinct_implementations_fetched"})
        nodes, graph_edges = base_build[0], base_build[1]
        return nodes, graph_edges, notes

    # Attempt 1: single wrapper compile. Cheap, correct whenever the
    # entry and every distinct implementation's pragma ranges overlap.
    wrapper_entry = build_wrapper_entry(project_root, entry_file, dependency_entry_files)
    try:
        wrapper_result = build_graph(
            project_root, wrapper_entry, solc_version, enrichment, remaps or [],
        )
    except Exception as e:
        wrapper_result = None
        log.warn(f"Protocol graph: wrapper compile raised: {e}")

    if wrapper_result and wrapper_result[0]:
        nodes, graph_edges = wrapper_result[0], wrapper_result[1]
        notes.append({"unified_nodes": len(nodes), "status": "ok_single_compile"})
        return nodes, graph_edges, notes

    # Attempt 2: wrapper failed — almost certainly a genuine pragma
    # conflict across a protocol's history (proven live: Compound's
    # Comptroller at 0.5.16 vs. a later CErc20Delegate pinned to
    # 0.8.10). Compile the entry and every distinct implementation
    # SEPARATELY, each at its own real pragma, and merge the results by
    # canonical_id — core/multi_compile.py's merge_build_results already
    # does this correctly for the single-dependency case; nothing here
    # is dependency-count-specific, it folds in one contract at a time.
    log.info("Protocol graph: wrapper compile failed (likely pragma conflict) — falling back to separate multi-version compilation")
    merged = base_build
    for dep_entry in dependency_entry_files:
        dep_version = extract_pragma_version(dep_entry) or solc_version
        try:
            dep_result = build_graph(project_root, dep_entry, dep_version, {}, remaps or [])
        except Exception as de:
            notes.append({"implementation_file": dep_entry, "status": "compile_failed", "pragma_version": dep_version, "reason": str(de)})
            log.warn(f"Protocol graph: separate compile failed for {dep_entry} at {dep_version}: {de}")
            continue
        if not dep_result[0]:
            notes.append({"implementation_file": dep_entry, "status": "compile_empty", "pragma_version": dep_version})
            continue
        merged = merge_build_results(merged, dep_result)
        notes.append({"implementation_file": dep_entry, "status": "compiled_separately", "pragma_version": dep_version, "nodes": len(dep_result[0])})

    nodes, graph_edges = merged[0], merged[1]
    notes.append({"unified_nodes": len(nodes), "status": "ok_multi_version_merge"})
    return nodes, graph_edges, notes
