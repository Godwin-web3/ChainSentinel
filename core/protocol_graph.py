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

from typing import Optional
from config.chains import Chain
from core.resolver import resolve
from core.graph import build_graph, find_any_enumeration_getter
from core.dependency_fetcher import merge_dependency_source, build_wrapper_entry
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
    base_nodes: dict,
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
        return base_nodes, {}, notes

    wrapper_entry = build_wrapper_entry(project_root, entry_file, dependency_entry_files)
    try:
        nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps = build_graph(
            project_root, wrapper_entry, solc_version, enrichment, remaps or [],
        )
    except Exception as e:
        log.warn(f"Protocol graph: unified build failed: {e}")
        notes.append({"status": "unified_build_failed", "reason": str(e)})
        return None

    notes.append({"unified_nodes": len(nodes), "status": "ok"})
    return nodes, graph_edges, notes
