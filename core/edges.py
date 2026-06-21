"""
core/edges.py — Typed edge extraction from Slither IR

Two layers:
  Layer 1 — IR truth: what Slither actually sees
  Layer 2 — Semantic inference: what it means for an attacker

Edge types (raw):
  internal          InternalCall
  dynamic           InternalDynamicCall (function pointer, uncertain target)
  highlevel         HighLevelCall (external, typed)
  lowlevel_call     LowLevelCall where function_name == "call"
  delegatecall      LowLevelCall where function_name == "delegatecall"
  codecall          LowLevelCall where function_name == "codecall"
  library           LibraryCall
  eth_send          Send
  eth_transfer      Transfer
  new_contract      NewContract
  solidity          SolidityCall
"""

from dataclasses import dataclass, field
from typing import Optional
from slither.slithir.operations import (
    InternalCall,
    InternalDynamicCall,
    HighLevelCall,
    LowLevelCall,
    LibraryCall,
    Send,
    Transfer,
    NewContract,
    SolidityCall,
)


# ── Data model ────────────────────────────────────────────────────

@dataclass
class CallEdge:
    src: str                      # canonical ID of caller
    dst: str                      # canonical ID or unresolved label

    # Layer 1 — IR truth
    raw_type: str                 # see module docstring

    # Layer 2 — semantic properties
    is_delegation: bool           # storage context inherited (delegatecall)
    is_external: bool             # crosses trust boundary
    is_value_transfer: bool       # ETH or token movement
    is_state_crossing: bool       # may mutate state in callee context
    uncertain: bool               # target unknown at static analysis time
    exploration_required: bool    # needs runtime trace or symbolic exec

    # Optional metadata
    function_name: Optional[str] = None   # resolved callee name if known
    destination: Optional[str] = None     # destination expression if external


# ── Layer 1: IR normalization ─────────────────────────────────────

def _raw_type_from_ir(ir) -> str:
    """Classify IR operation into raw call type. No inference here."""
    if isinstance(ir, InternalCall):
        return "internal"
    if isinstance(ir, InternalDynamicCall):
        return "dynamic"
    if isinstance(ir, LibraryCall):
        return "library"
    if isinstance(ir, HighLevelCall):
        return "highlevel"
    if isinstance(ir, LowLevelCall):
        fname = getattr(ir, "function_name", "") or ""
        fname = fname.lower()
        if fname == "delegatecall":
            return "delegatecall"
        if fname == "codecall":
            return "codecall"
        return "lowlevel_call"
    if isinstance(ir, Send):
        return "eth_send"
    if isinstance(ir, Transfer):
        return "eth_transfer"
    if isinstance(ir, NewContract):
        return "new_contract"
    if isinstance(ir, SolidityCall):
        return "solidity"
    return "unknown"


# ── Layer 2: Semantic inference ───────────────────────────────────

def _semantic_properties(raw_type: str) -> dict:
    """
    Derive semantic flags from raw type.
    These are attacker-relevant properties, not IR labels.
    """
    return {
        "internal": dict(
            is_delegation=False,
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=False,
            exploration_required=False,
        ),
        "dynamic": dict(
            is_delegation=False,
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=True,               # target is a stored function pointer
            exploration_required=True,    # can't resolve statically
        ),
        "highlevel": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=False,
            exploration_required=False,
        ),
        "lowlevel_call": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=True,       # .call{value:}() is common
            is_state_crossing=True,
            uncertain=True,               # destination may be attacker-controlled
            exploration_required=True,
        ),
        "delegatecall": dict(
            is_delegation=True,           # inherits storage context
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,       # writes to caller's storage
            uncertain=True,               # destination may be attacker-controlled
            exploration_required=True,
        ),
        "codecall": dict(
            is_delegation=True,
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=True,
            exploration_required=True,
        ),
        "library": dict(
            is_delegation=False,          # library calls are stateless by design
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=False,      # libraries cannot write caller state
            uncertain=False,
            exploration_required=False,
        ),
        "eth_send": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=True,
            is_state_crossing=False,
            uncertain=False,
            exploration_required=False,
        ),
        "eth_transfer": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=True,
            is_state_crossing=False,
            uncertain=False,
            exploration_required=False,
        ),
        "new_contract": dict(
            is_delegation=False,
            is_external=True,
            is_value_transfer=False,
            is_state_crossing=True,
            uncertain=False,
            exploration_required=False,
        ),
        "solidity": dict(
            is_delegation=False,
            is_external=False,
            is_value_transfer=False,
            is_state_crossing=False,
            uncertain=False,
            exploration_required=False,
        ),
    }.get(raw_type, dict(
        is_delegation=False,
        is_external=False,
        is_value_transfer=False,
        is_state_crossing=False,
        uncertain=True,
        exploration_required=True,
    ))


# ── Destination resolution ────────────────────────────────────────

def _resolve_dst(ir, src_id: str, raw_type: str) -> tuple:
    """
    Attempt to resolve destination canonical ID and name.
    Returns (dst_id, function_name, destination_str).
    Unresolvable targets return a labeled unknown.
    """
    if raw_type == "internal":
        try:
            fn = ir.function
            cid = f"{fn.contract_declarer.name}.{fn.full_name}"
            return cid, fn.name, None
        except Exception:
            return f"{src_id}.__unresolved_internal__", None, None

    if raw_type == "library":
        try:
            fn = ir.function
            cid = f"{fn.contract_declarer.name}.{fn.full_name}"
            return cid, fn.name, None
        except Exception:
            return f"{src_id}.__unresolved_library__", None, None

    if raw_type == "dynamic":
        # Function pointer — target is unknown at static analysis time
        return f"{src_id}.__dynamic_target__", None, None

    if raw_type == "highlevel":
        try:
            dest = str(ir.destination)
            fname = getattr(ir, "function_name", "") or ""
            fname = str(fname) if fname else ""
            return f"external.{dest}.{fname}", fname, dest
        except Exception:
            return f"{src_id}.__unresolved_external__", None, None

    if raw_type in ("lowlevel_call", "delegatecall", "codecall"):
        try:
            dest = str(ir.destination)
            fname = getattr(ir, "function_name", "") or "call"
            return f"lowlevel.{dest}.{fname}", fname, dest
        except Exception:
            return f"{src_id}.__unresolved_lowlevel__", None, None

    if raw_type in ("eth_send", "eth_transfer"):
        try:
            dest = str(ir.destination)
            return f"eth.{dest}", None, dest
        except Exception:
            return f"{src_id}.__unresolved_eth__", None, None

    if raw_type == "new_contract":
        try:
            contract_name = ir.contract_name if hasattr(ir, "contract_name") else "unknown"
            return f"new.{contract_name}", contract_name, None
        except Exception:
            return f"{src_id}.__unresolved_new__", None, None

    return f"{src_id}.__unresolved__", None, None


# ── Public API ────────────────────────────────────────────────────

def extract_edges(src_id: str, f) -> list[CallEdge]:
    """
    Extract all typed call edges from a Slither function object.

    Args:
        src_id: canonical ID of the calling function
        f: Slither Function object

    Returns:
        List of CallEdge objects
    """
    edges = []

    for node in f.nodes:
        for ir in node.irs:
            try:
                raw_type = _raw_type_from_ir(ir)
                if raw_type == "unknown":
                    continue

                dst_id, fname, dest_str = _resolve_dst(ir, src_id, raw_type)
                props = _semantic_properties(raw_type)

                edges.append(CallEdge(
                    src=src_id,
                    dst=dst_id,
                    raw_type=raw_type,
                    function_name=str(fname) if fname is not None else None,
                    destination=str(dest_str) if dest_str is not None else None,
                    **props,
                ))

            except Exception:
                continue

    return edges
