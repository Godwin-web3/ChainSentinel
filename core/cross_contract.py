"""
Cross-contract traversal helpers.

Converts a CallResolution into either:
    CrossContractEdge  — only when a concrete destination is proven
    BoundaryNode        — everything else, with the reason attached

No guessing. An edge only exists when resolution.status == RESOLVED.
"""

from dataclasses import dataclass
from typing import Optional

from core.call_resolution import CallResolution
from core.resolution import ResolutionStatus


@dataclass
class CrossContractEdge:
    src_contract: str
    src_function: str
    dst_contract: str
    dst_function: str
    resolution: object  # ResolutionInfo — kept for audit trail / reporting


@dataclass
class BoundaryNode:
    contract: str
    function: str
    reason: str
    details: Optional[str] = None


def build_cross_contract_edge(
    caller_contract: str,
    caller_function: str,
    resolution: CallResolution,
):
    if (
        resolution.resolution.status == ResolutionStatus.RESOLVED
        and resolution.resolved_contract
    ):
        return CrossContractEdge(
            src_contract=caller_contract,
            src_function=caller_function,
            dst_contract=resolution.resolved_contract,
            dst_function=resolution.resolved_function,
            resolution=resolution.resolution,
        )

    # A boundary can arise two distinct ways: the resolvability classifier
    # said REQUIRES_RUNTIME/AMBIGUOUS/UNRESOLVABLE (expected), or it said
    # RESOLVED (address is known) but no concrete resolved_contract could be
    # attached — e.g. a low-level call on a fixed address where Slither
    # cannot determine which function is actually invoked. That second case
    # must not be labeled "resolved", since nothing was actually resolved
    # to a traversable destination.
    if resolution.resolution.status == ResolutionStatus.RESOLVED:
        reason = "address_resolved_no_target_function"
    else:
        reason = resolution.resolution.status.value

    return BoundaryNode(
        contract=caller_contract,
        function=caller_function,
        reason=reason,
        details=resolution.resolution.notes or resolution.resolution.trust_anchor,
    )
