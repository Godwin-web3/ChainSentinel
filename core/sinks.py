"""
core/sinks.py — Sink classification for exploit path termination

A sink is the end of an exploit path where damage actually happens.
Without a classified sink, a path is just a graph traversal.

Five sink categories (mapped to Immunefi impact levels):

  ASSET_DRAIN         — direct theft of funds (critical)
  STORAGE_CORRUPTION  — privileged slot write: owner, impl, oracle, pause (critical/high)
  DELEGATION_SINK     — delegatecall to uncertain/attacker-controlled dest (critical)
  CALLBACK_SINK       — untrusted external call mid-state-change (reentrancy surface) (high)
                        only fired when the external call edge has trusted=False
  SELFDESTRUCT_SINK   — contract destruction (critical)
"""

from dataclasses import dataclass, field
from typing import Set, List, Optional
from core.edges import CallEdge


# ── Sink category constants ───────────────────────────────────────

ASSET_DRAIN        = "ASSET_DRAIN"
STORAGE_CORRUPTION = "STORAGE_CORRUPTION"
DELEGATION_SINK    = "DELEGATION_SINK"
CALLBACK_SINK      = "CALLBACK_SINK"
SELFDESTRUCT_SINK  = "SELFDESTRUCT_SINK"

# Severity weight per sink category (used in path scoring)
SINK_SEVERITY = {
    ASSET_DRAIN:        10,
    DELEGATION_SINK:    10,
    SELFDESTRUCT_SINK:  10,
    STORAGE_CORRUPTION:  8,
    CALLBACK_SINK:       6,
}

# A state variable is "privileged" structurally, not by name — see
# _privileged_vars_for_contract() below: it's EVER (anywhere in the
# contract) a delegatecall target, or the real variable a genuine
# msg.sender/tx.origin auth check compares against
# (FunctionNode.structural_auth_var, core/auth_detection.py). A renamed
# `owner` or a French-named `proprietaire` are caught identically,
# because both get proven the same way — by how they're actually used,
# not what they're called.

# Real token transfers are detected structurally via
# core/edges.py::CallEdge.is_token_transfer (matched against Slither's
# resolved argument types, e.g. transfer(address,uint256)) — no name list.
# ETH movement is covered separately by CallEdge.is_value_transfer.

# Solidity built-ins that indicate selfdestruct
SELFDESTRUCT_NAMES = {"selfdestruct", "suicide"}


# ── Data model ────────────────────────────────────────────────────

@dataclass
class Sink:
    node_id: str                    # canonical ID of the sink function
    category: str                   # one of the five constants above
    severity: int                   # from SINK_SEVERITY
    evidence: str                   # what specifically triggered this classification
    state_writes: Set[str] = field(default_factory=set)
    asset_flows: List[str] = field(default_factory=list)
    privileged_writes: Set[str] = field(default_factory=set)
    has_delegation: bool = False
    has_callback: bool = False
    has_selfdestruct: bool = False


# ── Classification logic ──────────────────────────────────────────

def classify_sinks(nodes: dict, graph_edges: dict) -> dict:
    """
    Classify every node in the graph as a sink or not.

    Args:
        nodes: dict of canonical_id -> FunctionNode (from graph.py)
        graph_edges: dict of canonical_id -> List[CallEdge] (from edges.py)

    Returns:
        dict of canonical_id -> Sink (only nodes that are sinks)
    """
    sinks = {}
    privileged_by_contract = _privileged_vars_by_contract(nodes, graph_edges)

    for node_id, node in nodes.items():
        priv_vars = privileged_by_contract.get(getattr(node, "contract", None), set())
        found = _classify_node(node_id, node, graph_edges.get(node_id, []), priv_vars)
        if found:
            sinks[node_id] = found

    return sinks


def _privileged_vars_by_contract(nodes: dict, graph_edges: dict) -> dict:
    """
    Structurally derive, per contract, the set of state variable names
    that count as "privileged" for STORAGE_CORRUPTION — no name list.
    A variable qualifies if it is EVER, anywhere in the contract:
      (a) a delegatecall/codecall destination (proxy implementation
          slot-shaped — the actual routing mechanism, not a name guess), or
      (b) the real variable a genuine msg.sender/tx.origin auth check
          compares against or looks up by (FunctionNode.structural_auth_var,
          core/auth_detection.py — direct comparison or role-mapping
          evidence) — i.e. a variable the contract itself already treats
          as governing who's allowed to act, proven by usage.
    """
    by_contract: dict = {}
    for cid, node in nodes.items():
        contract = getattr(node, "contract", None)
        if contract is None:
            continue
        bucket = by_contract.setdefault(contract, set())
        auth_var = getattr(node, "structural_auth_var", None)
        if auth_var:
            bucket.add(str(auth_var).lower())
        for edge in graph_edges.get(cid, []):
            if edge.raw_type in ("delegatecall", "codecall") and edge.destination:
                dest_str = str(edge.destination)
                # Only a simple bare-variable reference is a real state
                # variable name (e.g. `implementation`) — a compound
                # expression (a call, a member access) isn't a name we
                # can safely treat as one, so it's left alone rather
                # than guessed at.
                if dest_str.isidentifier():
                    bucket.add(dest_str.lower())
    return by_contract


def _classify_node(node_id: str, node, edges: List[CallEdge], privileged_vars: Optional[Set[str]] = None) -> Optional[Sink]:
    """
    Classify a single node. Returns Sink if it qualifies, None otherwise.
    Priority: ASSET_DRAIN > DELEGATION_SINK > SELFDESTRUCT > STORAGE_CORRUPTION > CALLBACK_SINK
    """
    if privileged_vars is None:
        privileged_vars = set()

    # ── 0. Hard exclusions ───────────────────────────────────────
    # View/pure functions cannot drain assets or corrupt state
    if getattr(node, 'is_view', False):
        return None
    # Library functions are not entrypoints
    if getattr(node, 'is_library', False):
        return None
    # Constructors only run once at deploy time
    if getattr(node, 'is_constructor', False):
        return None
    # Proxy dispatcher functions are routing infrastructure, not sinks
    # They delegatecall to known implementation contracts by design
    PROXY_DISPATCHER_NAMES = {
        "_exec", "_delegate", "_dispatch", "_fallback",
        "_implementation", "_beforefallback",
        "functiondelegatecall", "_functiondelegatecall",
        "_calloptionalreturn", "verifycallresult",
    }
    node_name = getattr(node, 'name', '').lower().split('(')[0]
    if node_name in PROXY_DISPATCHER_NAMES:
        return None
    # Also exclude nodes whose only edges are delegatecalls to
    # statically known implementation slots (not attacker-controlled)
    if node_name in ("fallback", "receive") and all(
        e.raw_type in ("delegatecall", "codecall") and not e.uncertain
        for e in edges if e.raw_type in ("delegatecall", "codecall")
    ) and edges:
        return None

    # ── 1. Selfdestruct ──────────────────────────────────────────
    for edge in edges:
        if edge.raw_type == "solidity":
            fname = (str(edge.function_name) if edge.function_name else "").lower()
            if fname in SELFDESTRUCT_NAMES:
                return Sink(
                    node_id=node_id,
                    category=SELFDESTRUCT_SINK,
                    severity=SINK_SEVERITY[SELFDESTRUCT_SINK],
                    evidence=f"selfdestruct call in {node_id}",
                    has_selfdestruct=True,
                )

    # ── 2. Delegation to uncertain destination ───────────────────
    for edge in edges:
        if edge.raw_type in ("delegatecall", "codecall") and edge.uncertain:
            return Sink(
                node_id=node_id,
                category=DELEGATION_SINK,
                severity=SINK_SEVERITY[DELEGATION_SINK],
                evidence=f"delegatecall to uncertain destination: {edge.dst}",
                has_delegation=True,
            )

    # ── 3. Asset drain ───────────────────────────────────────────
    asset_evidence = []

    # From edge-level asset flows (TransferHelper.safeTransfer, etc.)
    for edge in edges:
        if edge.is_value_transfer:
            asset_evidence.append(f"eth movement via {edge.raw_type} to {edge.dst}")
        elif edge.is_token_transfer:
            asset_evidence.append(f"token transfer: {edge.function_name} -> {edge.dst}")

    # From node-level asset_flows (already extracted by graph.py)
    if hasattr(node, "asset_flows") and node.asset_flows:
        for flow in node.asset_flows:
            asset_evidence.append(f"asset flow: {flow}")

    if asset_evidence:
        return Sink(
            node_id=node_id,
            category=ASSET_DRAIN,
            severity=SINK_SEVERITY[ASSET_DRAIN],
            evidence="; ".join(asset_evidence[:3]),
            asset_flows=list(node.asset_flows) if hasattr(node, "asset_flows") else [],
        )

    # ── 4. Privileged storage write ──────────────────────────────
    if hasattr(node, "state_writes") and node.state_writes and privileged_vars:
        from core.invariants import root_names, state_key_to_display
        priv_root_names = {v.lower() for v in root_names(node.state_writes)}
        priv_hit = priv_root_names & privileged_vars
        if priv_hit:
            priv_writes = {
                k for k in node.state_writes if k[0].lower() in priv_hit
            }
            priv_display = {state_key_to_display(k) for k in priv_writes}
            return Sink(
                node_id=node_id,
                category=STORAGE_CORRUPTION,
                severity=SINK_SEVERITY[STORAGE_CORRUPTION],
                evidence=f"privileged slot write: {priv_display}",
                state_writes=node.state_writes,
                privileged_writes=priv_writes,
            )

    # ── 5. Callback into external contract mid-execution ─────────
    # External call where caller still has open state = reentrancy surface.
    # Only untrusted external calls count: a call whose destination is a
    # storage variable written only by auth-scored functions (owner/admin-
    # gated) is trusted and not a reentrancy surface (e.g. Morpho's
    # IIrm.borrowRate() where irm is set by owner at market creation).
    # A raw `.staticcall(...)` (e.g. Uniswap V3's balance0()/balance1()
    # helpers) is excluded regardless of trust: the EVM propagates the
    # static context transitively to every call reachable from a
    # STATICCALL, so nothing downstream — including a callback into this
    # very function — can ever write state. Not a reentrancy surface by
    # construction, not by heuristic.
    for edge in edges:
        if edge.is_external and not edge.is_delegation and not edge.trusted and edge.raw_type != "staticcall":
            # Check if there are state writes in the same function
            has_state = hasattr(node, "state_writes") and bool(node.state_writes)
            if has_state:
                from core.invariants import state_key_to_display
                writes_display = {state_key_to_display(k) for k in node.state_writes}
                return Sink(
                    node_id=node_id,
                    category=CALLBACK_SINK,
                    severity=SINK_SEVERITY[CALLBACK_SINK],
                    evidence=f"untrusted external call to {edge.dst} with open state writes: {writes_display}",
                    has_callback=True,
                    state_writes=node.state_writes,
                )

    return None


# ── Helpers ───────────────────────────────────────────────────────

def top_sinks(sinks: dict, min_severity: int = 6) -> list:
    """Return sinks above severity threshold, sorted by severity."""
    results = [s for s in sinks.values() if s.severity >= min_severity]
    return sorted(results, key=lambda x: x.severity, reverse=True)
