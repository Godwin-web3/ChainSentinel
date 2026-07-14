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

    return BoundaryNode(
        contract=caller_contract,
        function=caller_function,
        reason=resolution.resolution.status.value,
        details=resolution.resolution.notes or resolution.resolution.trust_anchor,
    )
