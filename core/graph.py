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
from slither.core.declarations import Modifier
from core.invariants import extract_field_precise_writes, extract_field_precise_reads, get_call_events, extract_invariants
from core.auth_detection import compute_own_auth, is_reentrancy_guard
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

    # Auth — structurally computed (core/auth_detection.py), zero name
    # matching. auth_state/auth_score are the EFFECTIVE values (own body
    # OR any attached modifier's own body); structural_auth_score/
    # structural_auth_var are this function/modifier's OWN evidence only,
    # before folding in its modifiers (needed because a function's
    # modifiers may not have been visited yet when the function itself
    # is constructed — see the second pass in build_graph).
    auth_state: str
    modifiers: List[str]
    modifier_ids: List[str] = field(default_factory=list)
    structural_auth_score: int = 0
    structural_auth_var: Optional[str] = None
    is_reentrancy_guard: bool = False

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
    state_writes_after_callback: List = field(default_factory=list)
                                                          # List[(CallEvent, at_risk_keys)], same
                                                          # computation as race_findings but with
                                                          # THIS function's own full write-set as
                                                          # the "relevant" filter — i.e. every write
                                                          # that happens after a callback-capable
                                                          # call, full stop, not just ones a LOCAL
                                                          # invariant/assertion elsewhere also
                                                          # references. race_findings' narrower
                                                          # local-invariant relevance is the right
                                                          # bar for CROSS_FUNCTION_STATE_RACE; this
                                                          # broader one is what core/cross_market.py
                                                          # needs, since ITS relevance signal is a
                                                          # real cross-contract read elsewhere in the
                                                          # unified graph, not a same-contract
                                                          # assertion.

    # Layer 5 — computed
    reachable_from_untrusted: bool = False
    exploit_score: int = 0

    # Enumeration discovery — real Slither return-type data, used to find
    # one-to-many dependency getters (e.g. Comptroller.getAllMarkets()
    # returning CToken[]), never a name guess.
    returns_address_collection: bool = False
    # The array element's Contract type name when it's a UserDefinedType
    # (e.g. "CToken" for a CToken[] return) — None for plain address[].
    # This is what lets an unresolved dependency's declaring_contract
    # (e.g. "CToken") be matched back to the entry contract's own
    # enumeration getter that can produce a real instance of it.
    enumeration_element_type: Optional[str] = None


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
                    if ir.can_send_eth():
                        flows.append("eth.lowlevel")

            except Exception:
                continue

    return int_callees, ext_callees, flows


def find_enumeration_getter(nodes: Dict[str, "FunctionNode"], entry_contract: str, element_type: str) -> Optional[str]:
    """
    Looks for a no-arg function declared directly on entry_contract whose
    return type is an array of element_type (e.g. entry_contract=
    "Comptroller", element_type="CToken" -> "getAllMarkets()"). Used to
    resolve dependencies whose declaring_contract is a sibling TYPE rather
    than a single fixed address — there's no one "the" CToken, only real
    instances discoverable by calling this getter on the entry contract's
    own deployed address.

    Returns the getter's full_name (e.g. "getAllMarkets()") or None if no
    such function exists in this compilation.
    """
    for node in nodes.values():
        if (
            node.contract == entry_contract
            and node.enumeration_element_type == element_type
            and node.full_name.endswith("()")
        ):
            return node.full_name
    return None


def find_any_enumeration_getter(nodes: Dict[str, "FunctionNode"], entry_contract: str):
    """
    Same real, ABI/IR-grounded detection as find_enumeration_getter, but
    without requiring the target element type in advance — used when
    checking "does this contract enumerate a market/pool family at all",
    where the type isn't known until we find the getter.

    Returns (getter_full_name, element_type) or None.
    """
    for node in nodes.values():
        if (
            node.contract == entry_contract
            and node.returns_address_collection
            and node.enumeration_element_type
            and node.full_name.endswith("()")
        ):
            return node.full_name, node.enumeration_element_type
    return None


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
        # --via-ir did not exist before Solidity 0.8.13 — passing it to
        # an older compiler is a hard failure, not a warning, and Slither
        # silently returns nothing usable. Only include it when the
        # target compiler version actually supports it.
        def _supports_via_ir(version_str: str) -> bool:
            try:
                parts = version_str.split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                return (major, minor, patch) >= (0, 8, 13)
            except (ValueError, IndexError):
                return False  # unknown/malformed version — safest default

        if _supports_via_ir(solc_version):
            solc_args = '--via-ir --optimize'
        else:
            solc_args = '--optimize'

        # Guard against crytic-compile's upward-walking Foundry detection.
        # `locate_project_root` resolves the target to an absolute path and
        # walks every ancestor looking for foundry.toml. When project_root has
        # no foundry.toml of its own (e.g. fixture/morpho_blue), the walk
        # escapes past it and finds the repo-root foundry.toml (pinned to
        # 0.8.27), causing a solc version mismatch against the contract's own
        # pragma. Passing foundry_ignore=True disables Foundry platform
        # detection entirely and falls back to plain solc compilation.
        _has_local_foundry = os.path.isfile(os.path.join(project_root, "foundry.toml"))

        s = Slither(
            rel_entry,
            solc='solc-wrapper',
            solc_args=solc_args,
            solc_remaps=solc_remaps,
            foundry_ignore=not _has_local_foundry,
        )
        os.chdir(orig_dir)
    except Exception as e:
        log.warning(f"Graph: Slither API failed: {e}")
        return {}, {}, {}, {}, {}, []

    # NOTE: `enrichment` is accepted for API compatibility with existing
    # callers (main.py, core/protocol_graph.py) but is no longer consumed
    # here — auth_state/auth_score are now computed structurally (see
    # core/auth_detection.py) rather than from analysis/enricher.py's
    # name-matching-based score_auth() output.
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
                # Modifier objects carry no `is_modifier` attribute at all
                # (confirmed against installed Slither) — hasattr(...)
                # silently defaulted this to False for EVERY modifier
                # since this field was introduced. isinstance is the real
                # structural check.
                is_modifier = isinstance(f, Modifier)
                is_library = contract.is_library
                is_artifact = "slitherConstructor" in f.full_name
                is_view = f.view or f.pure

                # Layer 1 — IR extraction
                int_callees, ext_callees, flows = _extract_calls(f)
                state_writes = extract_field_precise_writes(f)

                # Cross-contract call resolution
                try:
                    from core.call_resolution import resolve_call
                    from core.cross_contract import build_cross_contract_edge
                    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

                    cross_contract_edges = []

                    for node in f.nodes:
                        for ir in node.irs:
                            if not isinstance(ir, (HighLevelCall, LibraryCall, LowLevelCall)):
                                continue
                            resolution = resolve_call(ir, f, s)
                            edge = build_cross_contract_edge(
                                caller_contract=contract.name,
                                caller_function=f.full_name,
                                resolution=resolution,
                            )
                            cross_contract_edges.append(edge)

                except Exception as e:
                    log.debug(f"Cross-contract resolution failed for {cid}: {e}")
                    cross_contract_edges = []

                reads = extract_field_precise_reads(f)
                call_events = get_call_events(f)
                fn_invariants = extract_invariants(f, contract.name, cid)
                all_invariants.extend(fn_invariants)

                # Layer 3 — structural auth (core/auth_detection.py): real
                # msg.sender/tx.origin comparisons or role-mapping lookups
                # in this function/modifier's own body (or internal calls
                # it makes) — zero name matching, a custom-named modifier
                # is scored identically to one named onlyOwner. This is
                # OWN-body evidence only; a function's attached modifiers
                # may not have their own FunctionNode yet (modifiers for
                # this contract are processed after its functions in
                # all_fns), so the EFFECTIVE auth_state/auth_score that
                # folds in modifier evidence is computed in a second pass
                # below, once every node in this contract exists.
                own_auth = compute_own_auth(f)
                structural_auth_score = own_auth.score
                structural_auth_var = own_auth.matched_state_var
                modifier_ids = [canonical_id(contract.name, m.full_name) for m in f.modifiers]
                guard = is_reentrancy_guard(f) if is_modifier else False
                auth_state = (
                    "AUTHENTICATED" if structural_auth_score >= 3 else
                    "UNKNOWN" if structural_auth_score == 2 else
                    "UNAUTHENTICATED"
                )

                # Structural check (real Slither return-type IR, never a
                # name guess): does this function return an array whose
                # element type is address, or a contract type (e.g.
                # CToken[], ApeToken[])? Used later to discover one-to-many
                # enumeration dependencies (factory/comptroller patterns).
                returns_address_collection = False
                enumeration_element_type = None
                if f.return_type:
                    from slither.core.solidity_types import ArrayType, ElementaryType, UserDefinedType
                    from slither.core.declarations.contract import Contract
                    for rt in f.return_type:
                        if isinstance(rt, ArrayType):
                            elem = rt.type
                            if isinstance(elem, ElementaryType) and elem.name == "address":
                                returns_address_collection = True
                                break
                            if isinstance(elem, UserDefinedType) and isinstance(elem.type, Contract):
                                returns_address_collection = True
                                enumeration_element_type = elem.type.name
                                break

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
                    modifier_ids=modifier_ids,
                    structural_auth_score=structural_auth_score,
                    structural_auth_var=structural_auth_var,
                    is_reentrancy_guard=guard,
                    internal_callees=int_callees,
                    external_callees=ext_callees,
                    state_writes=state_writes,
                    reads=reads,
                    asset_flows=flows,
                    call_events=call_events,
                    returns_address_collection=returns_address_collection,
                    enumeration_element_type=enumeration_element_type,
                )

                nodes[cid].cross_contract_edges = cross_contract_edges
                nodes[cid].auth_score = structural_auth_score

            except Exception as e:
                log.debug(f"Graph: skipping {f.name} in {contract.name}: {e}")
                continue

    # Layer 3b — effective auth score: fold each function's attached
    # modifiers' OWN structural auth evidence into the function's
    # effective auth_state/auth_score, via modifier_ids -> real
    # FunctionNode lookup (never a name match). Must run after every
    # node in every contract exists, since a function's modifiers are
    # processed after it within the same contract's all_fns list.
    for cid, node in nodes.items():
        modifier_scores = [
            nodes[mid].structural_auth_score for mid in node.modifier_ids if mid in nodes
        ]
        node.auth_score = max(node.structural_auth_score, max(modifier_scores, default=0))
        node.auth_state = (
            "AUTHENTICATED" if node.auth_score >= 3 else
            "UNKNOWN" if node.auth_score == 2 else
            "UNAUTHENTICATED"
        )

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
        if relevant_bare:
            node.race_findings = invariant_writes_between_calls(f_obj, relevant_bare)

        own_writes = extract_field_precise_writes(f_obj)
        if own_writes:
            node.state_writes_after_callback = invariant_writes_between_calls(f_obj, own_writes)

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
    unresolved_deps: list = []
    for contract in s.contracts:
        if contract.is_interface:
            continue
        all_fns = list(contract.functions) + list(contract.modifiers)
        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)
                if cid in nodes:
                    graph_edges[cid] = extract_edges(cid, f, auth_lookup, slither=s, unresolved_deps=unresolved_deps)
            except Exception:
                continue

    log.debug(f"Graph: built {len(nodes)} nodes, {sum(len(e) for e in graph_edges.values())} edges")
    return nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps


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
