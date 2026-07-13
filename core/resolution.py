"""
Resolvability classification — sits between DestinationOrigin (provenance)
and CrossContractEdge (graph construction).

Provenance answers: where did this call target come from.
Resolution answers: can we know its concrete value, and how.

This module answers ONE question: can this target be resolved, and by what
method. It never performs the resolution itself (no RPC calls here). That
keeps RuntimeResolver, when it's built, a thin executor of a plan this file
already decided — not a second place where resolution logic lives.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ResolutionStatus(Enum):
    RESOLVED = "resolved"                  # concrete value known — either proven
                                            # statically, or a runtime read already ran
    REQUIRES_RUNTIME = "requires_runtime"   # resolvable in principle, needs a live read
    AMBIGUOUS = "ambiguous"                # multiple candidates, none provably chosen
    UNRESOLVABLE = "unresolvable"          # no path to a concrete value, by design


class ResolutionMethod(Enum):
    LIBRARY_LINK = "library_link"               # library call, resolves via linkage
    LITERAL_CONSTANT = "literal_constant"       # constant/immutable with hardcoded address
    PUBLIC_GETTER = "public_getter"             # ABI getter exists, call it
    STORAGE_SLOT = "storage_slot"               # no getter, raw eth_getStorageAt fallback
    SINGLE_IMPLEMENTER = "single_implementer"   # exactly one known implementation
    NONE = "none"                               # no resolution method applies


@dataclass
class CallTargetFacts:
    """
    Everything the analysis engine already knows about a call target,
    gathered once upstream (enricher / fetcher / future proxy detection).
    classify_resolvability() consumes this — it discovers nothing itself.
    """
    origin: object                          # your existing DestinationOrigin value
    is_library: bool = False
    is_constant: bool = False
    is_immutable: bool = False
    public_getter: Optional[str] = None     # getter function name, if one exists
    implementation_count: int = 0           # known candidate implementations for this interface

    @property
    def is_literal(self) -> bool:
        return self.is_constant or self.is_immutable


@dataclass
class ResolutionInfo:
    status: ResolutionStatus
    method: ResolutionMethod
    trust_anchor: Optional[str] = None   # e.g. "comptroller()" or "slot 0x05"
    resolved_address: Optional[str] = None  # populated only after RuntimeResolver runs
    block: Optional[int] = None             # populated only after RuntimeResolver runs
    notes: Optional[str] = None             # short human-readable reason, for boundary display


def classify_resolvability(facts: CallTargetFacts) -> ResolutionInfo:
    """
    Pure function. Decides WHAT would be needed to resolve the edge,
    never performs the resolution. No RPC calls happen here.
    """

    # Library calls resolve at compile/link time — no ambiguity possible.
    if facts.is_library:
        return ResolutionInfo(
            status=ResolutionStatus.RESOLVED,
            method=ResolutionMethod.LIBRARY_LINK,
            trust_anchor="library linkage",
        )

    # Hardcoded address, provable from source text alone.
    if facts.is_literal:
        return ResolutionInfo(
            status=ResolutionStatus.RESOLVED,
            method=ResolutionMethod.LITERAL_CONSTANT,
            trust_anchor="constant/immutable literal",
        )

    # msg.sender, tx.origin — resolvable only at actual call time. Permanently
    # unresolvable by design, not a gap to fill later.
    if origin_is_msg_sender(facts.origin):
        return ResolutionInfo(
            status=ResolutionStatus.UNRESOLVABLE,
            method=ResolutionMethod.NONE,
            notes="caller-controlled at call time — not a fixed target",
        )

    # Mutable state variable with a public getter — resolvable via one live
    # read, ABI-based, proxy-safe. Method is fixed now; status flips to
    # RESOLVED only once RuntimeResolver actually performs the call.
    if origin_is_state_variable(facts.origin) and facts.public_getter:
        return ResolutionInfo(
            status=ResolutionStatus.REQUIRES_RUNTIME,
            method=ResolutionMethod.PUBLIC_GETTER,
            trust_anchor=f"{facts.public_getter}()",
        )

    # Mutable state variable, no getter — still resolvable, only via raw
    # storage read. Distinct method so callers can flag "brittle slot math"
    # separately from a clean ABI read.
    if origin_is_state_variable(facts.origin) and not facts.public_getter:
        return ResolutionInfo(
            status=ResolutionStatus.REQUIRES_RUNTIME,
            method=ResolutionMethod.STORAGE_SLOT,
            notes="no public getter — requires raw storage read, proxy-unsafe",
        )

    # Interface type with exactly one known implementation — not ambiguous,
    # just indirect. Treat as resolvable via that single candidate.
    if facts.implementation_count == 1:
        return ResolutionInfo(
            status=ResolutionStatus.RESOLVED,
            method=ResolutionMethod.SINGLE_IMPLEMENTER,
            trust_anchor="sole known implementation",
        )

    # Interface type with more than one known implementation — genuinely
    # branching, not a single unresolved unknown.
    if facts.implementation_count > 1:
        return ResolutionInfo(
            status=ResolutionStatus.AMBIGUOUS,
            method=ResolutionMethod.NONE,
            notes=f"{facts.implementation_count} candidate implementations, none provably selected",
        )

    # Function parameters, return values, anything else not yet classified.
    return ResolutionInfo(
        status=ResolutionStatus.UNRESOLVABLE,
        method=ResolutionMethod.NONE,
        notes="no static or runtime resolution path identified",
    )


# --- wire these to your real DestinationOrigin enum values ---
def origin_is_msg_sender(origin) -> bool:
    raise NotImplementedError("wire to your DestinationOrigin.MSG_SENDER check")


def origin_is_state_variable(origin) -> bool:
    raise NotImplementedError("wire to your DestinationOrigin.STATE_VARIABLE check")
