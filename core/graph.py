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
from core.invariants import extract_field_precise_writes, extract_field_precise_reads, get_call_events, extract_invariants
from slither.slithir.operations import (
    InternalCall, HighLevelCall, LowLevelCall, SolidityCall, LibraryCall
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
    call_events: List = field(default_factory=list)  # List[CallEvent] from invariants.py —
                                                        # ordered, classified external calls
                                                        # (callback_capable / read_only /
                                                        # unknown_external), source-order indexed
    race_findings: List = field(default_factory=list)  # List[(CallEvent, at_risk_keys)] —
                                                          # precomputed via invariants.py's
                                                          # invariant_writes_between_calls, using
                                                          # real node-order (not approximated).
                                                          # Empty means CEI-safe per this check.

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

                elif isinstance(ir, LibraryCall):
                    # LibraryCall is a subclass of HighLevelCall in Slither's
                    # IR, so it must be checked BEFORE the HighLevelCall
                    # branch below, or it silently falls through as an
                    # external call. Library code is linked into the
                    # contract and never leaves the trusted execution
                    # context — it cannot be a reentrancy vector.
                    fname = ir.function_name if hasattr(ir, 'function_name') else ''
                    int_callees.append(f"library.{fname}")

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
        return {}, {}, {}, {}, {}

    features = enrichment.get("features", {}) if enrichment else {}
    nodes: Dict[str, FunctionNode] = {}
    all_invariants = []
    fn_by_cid = {}

    for contract in s.contracts:
        # Skip pure interfaces — no implementation to analyze
        if contract.is_interface:
            continue

        all_fns = list(contract.functions) + list(contract.modifiers)

        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)
                fn_by_cid[cid] = f

                # Layer 3 — semantic tags from Slither IR
                is_constructor = f.is_constructor
                is_modifier = f.is_modifier if hasattr(f, 'is_modifier') else False
                is_library = contract.is_library
                is_artifact = "slitherConstructor" in f.full_name
                is_view = f.view or f.pure

                # Layer 1 — IR extraction
                int_callees, ext_callees, flows = _extract_calls(f)
                state_writes = extract_field_precise_writes(f)

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
                reads = extract_field_precise_reads(f)
                call_events = get_call_events(f)
                fn_invariants = extract_invariants(f, contract.name, cid)
                all_invariants.extend(fn_invariants)
                auth_state = enricher_data.get("auth_state", "UNKNOWN")
                auth_score = enricher_data.get("auth_score", 0)

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
                    call_events=call_events,
                )
                nodes[cid].auth_score = auth_score

            except Exception as e:
                log.debug(f"Graph: skipping {f.name} in {contract.name}: {e}")
                continue

    # Layer 4 — build caller edges (reverse of callees)
    for cid, node in nodes.items():
        for callee_id in node.internal_callees:
            if callee_id in nodes:
                nodes[callee_id].callers.append(cid)

    # Layer 4 — global state read/write index (cross-function view)
    # Keys are structured: (contract, root_var, member_path_tuple).
    # NOT joined strings — this preserves field precision so
    # supply()'s market.totalSupplyAssets and setFee()'s market.fee
    # are distinct keys, not collapsed into one "market" bucket.
    state_writers = {}
    state_readers = {}
    for cid, node in nodes.items():
        for (root_var, member_path) in node.state_writes:
            key = (node.contract, root_var, member_path)
            state_writers.setdefault(key, []).append(cid)
        for (root_var, member_path) in node.reads:
            key = (node.contract, root_var, member_path)
            state_readers.setdefault(key, []).append(cid)

    # Layer 4 — invariant reverse index: structured state key ->
    # list of Invariant objects that reference it. Built from every
    # require()/assert() found anywhere in the contract (not just
    # the current function), since e.g. market.fee's invariant lives
    # in setFee() but _accrueInterest() also needs to know it's
    # invariant-relevant. Preserves which invariant(s) care about
    # each field — NOT flattened into a bare set — so a finding can
    # later cite the actual guarantee at risk, not just "shared state".
    invariant_index: Dict = {}
    for inv in all_invariants:
        if inv.left.is_state:
            key = (inv.contract, inv.left.state_var_name, tuple(inv.left.member_path))
            invariant_index.setdefault(key, []).append(inv)
        if inv.right.is_state:
            key = (inv.contract, inv.right.state_var_name, tuple(inv.right.member_path))
            invariant_index.setdefault(key, []).append(inv)

    # Layer 4 — race findings: ordering-correct check of whether any
    # invariant-relevant field is written AFTER a callback-capable
    # call, per function. Computed here (not in constraints.py)
    # because it needs the raw Slither function object for real
    # node-order walking — validated against Morpho's supply/repay/
    # liquidate/setFee this session before being wired into the
    # live pipeline.
    from core.invariants import invariant_writes_between_calls
    for cid, node in nodes.items():
        f_obj = fn_by_cid.get(cid)
        if f_obj is None:
            continue
        relevant_bare = {
            (k[1], k[2]) for k in invariant_index.keys() if k[0] == node.contract
        }
        if not relevant_bare:
            continue
        node.race_findings = invariant_writes_between_calls(f_obj, relevant_bare)

    # Layer 4 — reachability (using real canonical edges)
    _compute_reachability(nodes)

    # Layer 5 — scoring
    for node in nodes.values():
        node.exploit_score = _exploit_score(node)

    # Layer 4 — extract typed edges while Slither objects are in scope
    from core.edges import extract_edges
    # Build auth_score lookup keyed by canonical_id so edge trust
    # resolution can check who can write a destination storage variable.
    auth_lookup = {
        cid: getattr(node, "auth_score", 0) for cid, node in nodes.items()
    }
    graph_edges: Dict[str, list] = {}
    for contract in s.contracts:
        if contract.is_interface:
            continue
        all_fns = list(contract.functions) + list(contract.modifiers)
        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)
                if cid in nodes:
                    graph_edges[cid] = extract_edges(cid, f, auth_lookup)
            except Exception:
                continue

    log.debug(f"Graph: built {len(nodes)} nodes, {sum(len(e) for e in graph_edges.values())} edges")
    return nodes, graph_edges, state_writers, state_readers, invariant_index


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
