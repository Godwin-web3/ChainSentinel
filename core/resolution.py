"""
Resolvability classification — sits between DestinationOrigin (provenance)
and CrossContractEdge (graph construction).
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ResolutionStatus(Enum):
    RESOLVED = "resolved"
    REQUIRES_RUNTIME = "requires_runtime"
    AMBIGUOUS = "ambiguous"
    UNRESOLVABLE = "unresolvable"


class ResolutionMethod(Enum):
    LIBRARY_LINK = "library_link"
    LITERAL_CONSTANT = "literal_constant"
    PUBLIC_GETTER = "public_getter"
    STORAGE_SLOT = "storage_slot"
    SINGLE_IMPLEMENTER = "single_implementer"
    NONE = "none"


@dataclass
class CallTargetFacts:
    origin: object
    is_library: bool = False
    is_constant: bool = False
    is_immutable: bool = False
    public_getter: Optional[str] = None
    implementation_count: int = 0

    @property
    def is_literal(self) -> bool:
        return self.is_constant or self.is_immutable


@dataclass
class ResolutionInfo:
    status: ResolutionStatus
    method: ResolutionMethod
    trust_anchor: Optional[str] = None
    resolved_address: Optional[str] = None
    block: Optional[int] = None
    notes: Optional[str] = None


def classify_resolvability(facts: CallTargetFacts) -> ResolutionInfo:
    if facts.is_library:
        return ResolutionInfo(
            status=ResolutionStatus.RESOLVED,
            method=ResolutionMethod.LIBRARY_LINK,
            trust_anchor="library linkage",
        )

    if facts.is_literal:
        # The ADDRESS is fixed and provable from source. But if it points
        # at an interface type with multiple concrete implementers in this
        # compilation, the address alone does not tell us WHICH contract's
        # code actually runs there — that is genuine ambiguity, not a
        # resolved destination. implementation_count == 1 covers both a
        # concrete (non-interface) type and an interface with exactly one
        # known implementer, both real resolved cases.
        if facts.implementation_count > 1:
            return ResolutionInfo(
                status=ResolutionStatus.AMBIGUOUS,
                method=ResolutionMethod.NONE,
                notes=(
                    f"address is fixed, but interface type has "
                    f"{facts.implementation_count} candidate implementations, "
                    f"none provably selected"
                ),
            )
        return ResolutionInfo(
            status=ResolutionStatus.RESOLVED,
            method=ResolutionMethod.LITERAL_CONSTANT,
            trust_anchor="constant/immutable literal",
        )

    if origin_is_msg_sender(facts.origin):
        return ResolutionInfo(
            status=ResolutionStatus.UNRESOLVABLE,
            method=ResolutionMethod.NONE,
            notes="caller-controlled at call time — not a fixed target",
        )

    if origin_is_state_variable(facts.origin) and facts.public_getter:
        return ResolutionInfo(
            status=ResolutionStatus.REQUIRES_RUNTIME,
            method=ResolutionMethod.PUBLIC_GETTER,
            trust_anchor=f"{facts.public_getter}()",
        )

    if origin_is_state_variable(facts.origin) and not facts.public_getter:
        return ResolutionInfo(
            status=ResolutionStatus.REQUIRES_RUNTIME,
            method=ResolutionMethod.STORAGE_SLOT,
            notes="no public getter — requires raw storage read, proxy-unsafe",
        )

    if facts.implementation_count == 1:
        return ResolutionInfo(
            status=ResolutionStatus.RESOLVED,
            method=ResolutionMethod.SINGLE_IMPLEMENTER,
            trust_anchor="sole known implementation",
        )

    if facts.implementation_count > 1:
        return ResolutionInfo(
            status=ResolutionStatus.AMBIGUOUS,
            method=ResolutionMethod.NONE,
            notes=f"{facts.implementation_count} candidate implementations, none provably selected",
        )

    return ResolutionInfo(
        status=ResolutionStatus.UNRESOLVABLE,
        method=ResolutionMethod.NONE,
        notes="no static or runtime resolution path identified",
    )


from core.destination_origin import DestinationOrigin as _DestinationOrigin


def origin_is_msg_sender(origin) -> bool:
    return origin == _DestinationOrigin.MSG_SENDER


def origin_is_state_variable(origin) -> bool:
    return origin == _DestinationOrigin.STATE_VARIABLE
