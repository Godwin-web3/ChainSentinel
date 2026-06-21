"""
core/graph.py — Function call graph + exploitability scoring
Layer 1: Slither IR extraction (no heuristics)
Layer 2: Normalization (canonical IDs)
Layer 3: Semantic tagging (constructor/modifier/library/artifact)
Layer 4: Graph construction (real call edges only)
Layer 5: Scoring (purely downstream)
"""

import os
import logging
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional

from slither.slither import Slither
from slither.slithir.operations import (
    InternalCall, HighLevelCall, LowLevelCall, SolidityCall
)

log = logging.getLogger("chainsentinel")

# ── Layer 5 constants ────────────────────────────────────────────
# Functions that are intentionally public economic interfaces.
# These are NOT zeroed — they still participate in asset-flow scoring.
# They are only excluded from auth-gap scoring.
ECONOMIC_INTERFACE = {
    "transfer", "transferfrom", "approve",
    "balanceof", "allowance", "totalsupply",
    "decimals", "symbol", "name",
}

# ── Layer 2: Canonical ID ────────────────────────────────────────
def canonical_id(contract_name: str, full_name: str) -> str:
    return f"{contract_name}.{full_name}"

# ── Layer 3: FunctionNode ────────────────────────────────────────
@dataclass
class FunctionNode:
    # Identity
    id: str
    name: str
    full_name: str
    contract: str

    # Layer 3 — semantic tags (Slither IR derived, no heuristics)
    visibility: str
    is_constructor: bool
    is_modifier: bool
    is_library: bool
    is_artifact: bool
    is_view: bool

    # Auth (from enricher)
    auth_state: str
    modifiers: List[str]

    # Layer 4 — graph edges (canonical IDs)
    internal_callees: List[str] = field(default_factory=list)
    external_callees: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)

    # Layer 1 — IR facts
    state_writes: Set[str] = field(default_factory=set)
    reads: Set[str] = field(default_factory=set)
    asset_flows: List[str] = field(default_factory=list)

    # Layer 5 — computed
    reachable_from_untrusted: bool = False
    exploit_score: int = 0


# ── Layer 1: IR extraction ───────────────────────────────────────
def _extract_calls(f) -> tuple:
    """Extract internal and external callees from Slither IR nodes."""
    int_callees = []
    ext_callees = []
    flows = []

    for node in f.nodes:
        for ir in node.irs:
            try:
                if isinstance(ir, InternalCall) and ir.function:
                    cid = canonical_id(
                        ir.function.contract_declarer.name,
                        ir.function.full_name
                    )
                    int_callees.append(cid)

                elif isinstance(ir, SolidityCall):
                    int_callees.append(f"solidity.{ir.function.name}")

                elif isinstance(ir, HighLevelCall):
                    dest = str(ir.destination) if hasattr(ir, 'destination') else '?'
                    fname = ir.function_name if hasattr(ir, 'function_name') else ''
                    ext_callees.append(f"{dest}.{fname}")
                    if fname in ('transfer', 'transferFrom', 'safeTransfer', 'safeTransferFrom'):
                        flows.append(f"token.{fname}")

                elif isinstance(ir, LowLevelCall):
                    dest = str(ir.destination) if hasattr(ir, 'destination') else '?'
                    ext_callees.append(f"{dest}.lowlevel")
                    flows.append("eth.lowlevel")

            except Exception:
                continue

    return int_callees, ext_callees, flows


# ── Layer 4: Graph builder ───────────────────────────────────────
def build_graph(
    project_root: str,
    entry_file: str,
    solc_version: str,
    enrichment: dict,
    remappings: list = None,
) -> Dict[str, FunctionNode]:
    """
    Build function graph from Slither IR.
    Returns (nodes, graph_edges) tuple.
    """
    os.environ["SOLC_VERSION"] = solc_version

    try:
        orig_dir = os.getcwd()
        os.chdir(project_root)
        rel_entry = os.path.relpath(entry_file, project_root)
        solc_remaps = " ".join(remappings[:50]) if remappings else ""
        s = Slither(rel_entry, solc='solc-wrapper', solc_args='--via-ir --optimize', solc_remaps=solc_remaps)
        os.chdir(orig_dir)
    except Exception as e:
        log.warning(f"Graph: Slither API failed: {e}")
        return {}, {}

    features = enrichment.get("features", {}) if enrichment else {}
    nodes: Dict[str, FunctionNode] = {}

    for contract in s.contracts:
        # Skip pure interfaces — no implementation to analyze
        if contract.is_interface:
            continue

        all_fns = list(contract.functions) + list(contract.modifiers)

        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)

                # Layer 3 — semantic tags from Slither IR
                is_constructor = f.is_constructor
                is_modifier = f.is_modifier if hasattr(f, 'is_modifier') else False
                is_library = contract.is_library
                is_artifact = "slitherConstructor" in f.full_name
                is_view = f.view or f.pure

                # Layer 1 — IR extraction
                int_callees, ext_callees, flows = _extract_calls(f)
                state_writes = set(v.name for v in f.state_variables_written)

                # Layer 3 — auth from enricher
                possible_keys = [
                    f"vars.{f.full_name}",
                    f"{f.contract_declarer.name}.{f.full_name}",
                    f"vars.{f.name}",
                ]
                enricher_data = {}
                for ek in possible_keys:
                    if ek in features:
                        enricher_data = features[ek]
                        break
                reads = set(enricher_data.get("reads", [])) if enricher_data else set()
                auth_state = enricher_data.get("auth_state", "UNKNOWN")

                nodes[cid] = FunctionNode(
                    id=cid,
                    name=f.name,
                    full_name=f.full_name,
                    contract=contract.name,
                    visibility=f.visibility,
                    is_constructor=is_constructor,
                    is_modifier=is_modifier,
                    is_library=is_library,
                    is_artifact=is_artifact,
                    is_view=is_view,
                    auth_state=auth_state,
                    modifiers=[m.name for m in f.modifiers],
                    internal_callees=int_callees,
                    external_callees=ext_callees,
                    state_writes=state_writes,
                    reads=reads,
                    asset_flows=flows,
                )

            except Exception as e:
                log.debug(f"Graph: skipping {f.name} in {contract.name}: {e}")
                continue

    # Layer 4 — build caller edges (reverse of callees)
    for cid, node in nodes.items():
        for callee_id in node.internal_callees:
            if callee_id in nodes:
                nodes[callee_id].callers.append(cid)

    # Layer 4 — reachability (using real canonical edges)
    _compute_reachability(nodes)

    # Layer 5 — scoring
    for node in nodes.values():
        node.exploit_score = _exploit_score(node)

    # Layer 4 — extract typed edges while Slither objects are in scope
    from core.edges import extract_edges
    graph_edges: Dict[str, list] = {}
    for contract in s.contracts:
        if contract.is_interface:
            continue
        all_fns = list(contract.functions) + list(contract.modifiers)
        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)
                if cid in nodes:
                    graph_edges[cid] = extract_edges(cid, f)
            except Exception:
                continue

    log.debug(f"Graph: built {len(nodes)} nodes, {sum(len(e) for e in graph_edges.values())} edges")
    return nodes, graph_edges


# ── Layer 4: Reachability ────────────────────────────────────────
def _compute_reachability(nodes: Dict[str, FunctionNode]):
    """
    Propagate reachability from untrusted EOA entry points.
    Uses canonical call graph edges — no name matching.
    """
    # Seed: public/external non-constructor functions
    for node in nodes.values():
        if (node.visibility in ('public', 'external')
                and not node.is_constructor
                and not node.is_modifier):
            node.reachable_from_untrusted = True

    # BFS propagation through internal call edges
    changed = True
    while changed:
        changed = False
        for node in nodes.values():
            if not node.reachable_from_untrusted:
                continue
            for callee_id in node.internal_callees:
                if callee_id in nodes and not nodes[callee_id].reachable_from_untrusted:
                    nodes[callee_id].reachable_from_untrusted = True
                    changed = True


# ── Layer 5: Scoring ─────────────────────────────────────────────
def _exploit_score(node: FunctionNode) -> int:
    """
    Score exploitability from semantic facts only.
    No name matching. No convention assumptions.
    """
    # Hard zeros — structural Solidity constructs
    if node.is_constructor:
        return 0
    if node.is_modifier:
        return 0
    if node.is_artifact:
        return 0
    if node.is_view:
        return 0

    # Library functions only matter if reachable
    if node.is_library and not node.reachable_from_untrusted:
        return 0

    # Internal functions only matter if reachable
    if node.visibility == "internal" and not node.reachable_from_untrusted:
        return 0

    # Authenticated = not exploitable
    if node.auth_state == "AUTHENTICATED":
        return 0

    # No state impact = nothing to exploit
    if not node.state_writes and not node.asset_flows:
        return 0

    score = 0

    if node.reachable_from_untrusted:
        score += 2

    if node.auth_state == "UNAUTHENTICATED":
        score += 3
    elif node.auth_state == "UNKNOWN":
        score += 1

    if node.state_writes:
        score += 2

    if node.asset_flows:
        score += 4

    # Economic interfaces — suppress auth-gap score
    # but preserve asset-flow score
    if node.name.lower() in ECONOMIC_INTERFACE:
        score = max(0, score - 3)

    return score


# ── API ──────────────────────────────────────────────────────────
def top_findings(nodes: Dict[str, FunctionNode], threshold: int = 5) -> list:
    """Return nodes above exploit score threshold, sorted by score."""
    findings = [n for n in nodes.values() if n.exploit_score >= threshold]
    return sorted(findings, key=lambda x: x.exploit_score, reverse=True)
