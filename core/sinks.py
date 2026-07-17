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

# ── Privileged storage variable names ────────────────────────────
# Writes to these slots after an auth gap = storage corruption sink
PRIVILEGED_SLOTS = {
    # Ownership
    "owner", "admin", "governance", "controller",
    "pendingOwner", "pendingAdmin",
    # Proxy / upgrade
    "implementation", "_implementation", "logic",
    "beacon", "_beacon",
    # Oracle / price
    "oracle", "priceOracle", "priceFeed",
    "price", "spot", "twap",
    # Pause / emergency
    "paused", "pausing", "frozen", "emergency",
    # Auth mappings
    "wards", "roles", "whitelist", "blacklist",
    "authorized", "operators",
    # Fee / parameter
    "fee", "feeRate", "protocolFee",
    "interestRate", "liquidationThreshold",
}

# ERC20 / ETH transfer function names that constitute asset movement.
# Matched via membership in ASSET_TRANSFER_FUNCTIONS OR prefix variants
# (_safeTransfer, _transfer, _safeTransferFrom). Includes Maker-style
# pull()/push() wrappers and the common `_pull`/`_push` internal helpers.
ASSET_TRANSFER_FUNCTIONS = {
    "transfer", "transferfrom",
    "safetransfer", "safetransferfrom",
    "send", "call",                    # ETH
    "withdraw", "withdrawall",
    "redeem", "redeemall",
    "claim", "claimreward",
    # Maker / Exactly-style wrappers
    "pull", "push", "move", "suck", "wipe",
    # Common internal helper names (Slither strips the leading underscore
    # for some IR ops but not all; we lowercase so the membership check
    # works either way)
    "_transfer", "_transferfrom",
    "_safetransfer", "_safetransferfrom",
    "_withdraw", "_redeem", "_claim",
}

# Underscore-prefixed variants whose lowercased form may retain the `_`.
# Used by the matching helper below so _safeTransfer / _transfer etc.
# are caught without breaking exact matches above.
ASSET_TRANSFER_PREFIXES = (
    "_transfer", "_safetransfer", "_safetransferfrom",
    "transferfrom", "safetransfer",
)


def _is_asset_transfer(fname: str) -> bool:
    """Membership + underscore-prefix match for asset-transfer function names."""
    if not fname:
        return False
    if fname in ASSET_TRANSFER_FUNCTIONS:
        return True
    return any(fname.startswith(p) for p in ASSET_TRANSFER_PREFIXES)

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

    for node_id, node in nodes.items():
        found = _classify_node(node_id, node, graph_edges.get(node_id, []))
        if found:
            sinks[node_id] = found

    return sinks


def _classify_node(node_id: str, node, edges: List[CallEdge]) -> Optional[Sink]:
    """
    Classify a single node. Returns Sink if it qualifies, None otherwise.
    Priority: ASSET_DRAIN > DELEGATION_SINK > SELFDESTRUCT > STORAGE_CORRUPTION > CALLBACK_SINK
    """

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
        fname = (str(edge.function_name) if edge.function_name else "").lower()
        if edge.is_value_transfer:
            asset_evidence.append(f"eth movement via {edge.raw_type} to {edge.dst}")
        elif _is_asset_transfer(fname):
            asset_evidence.append(f"token transfer: {edge.function_name} -> {edge.dst}")

    # From node-level asset_flows (already extracted by graph.py)
    if hasattr(node, "asset_flows") and node.asset_flows:
        for flow in node.asset_flows:
            asset_evidence.append(f"asset flow: {flow}")

    if asset_evidence:
        if "InitializableImmutableAdminUpgradeabilityProxy.initialize" in node_id:
            print(f"TEMP_DEBUG sink triggered on {node_id}: evidence={asset_evidence}")
        return Sink(
            node_id=node_id,
            category=ASSET_DRAIN,
            severity=SINK_SEVERITY[ASSET_DRAIN],
            evidence="; ".join(asset_evidence[:3]),
            asset_flows=list(node.asset_flows) if hasattr(node, "asset_flows") else [],
        )

    # ── 4. Privileged storage write ──────────────────────────────
    if hasattr(node, "state_writes") and node.state_writes:
        from core.invariants import root_names, state_key_to_display
        priv_slots_lower = {s.lower() for s in PRIVILEGED_SLOTS}
        priv_root_names = {v.lower() for v in root_names(node.state_writes)}
        priv_hit = priv_root_names & priv_slots_lower
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
    for edge in edges:
        if edge.is_external and not edge.is_delegation and not edge.trusted:
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
