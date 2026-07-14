"""
CallResolution — composes DestinationOrigin (provenance) + ResolutionInfo
(resolvability) into the object cross_contract.py consumes.
"""

from dataclasses import dataclass
from typing import Optional

from slither.slithir.operations import HighLevelCall, LibraryCall

from core.destination_origin import DestinationOrigin, resolve_destination
from core.resolution import (
    CallTargetFacts,
    ResolutionInfo,
    ResolutionStatus,
    classify_resolvability,
)


@dataclass
class CallResolution:
    origin: DestinationOrigin
    resolution: ResolutionInfo
    resolved_contract: Optional[str] = None
    resolved_function: Optional[str] = None


def resolve_call(call_ir, function, slither) -> CallResolution:
    origin, variable = resolve_destination(call_ir, function)

    is_library = isinstance(call_ir, LibraryCall)
    is_constant = origin == DestinationOrigin.CONSTANT
    is_immutable = origin == DestinationOrigin.IMMUTABLE

    public_getter = None
    if origin == DestinationOrigin.STATE_VARIABLE and variable is not None:
        if getattr(variable, "visibility", None) == "public":
            public_getter = variable.name

    resolved_fn = getattr(call_ir, "function", None)
    resolved_contract_obj = resolved_fn.contract if resolved_fn else None

    implementation_count = 0
    if resolved_contract_obj is not None:
        if not resolved_contract_obj.is_interface:
            implementation_count = 1
        else:
            for candidate in slither.contracts:
                if candidate.is_interface:
                    continue
                if resolved_contract_obj in candidate.inheritance:
                    implementation_count += 1

    facts = CallTargetFacts(
        origin=origin,
        is_library=is_library,
        is_constant=is_constant,
        is_immutable=is_immutable,
        public_getter=public_getter,
        implementation_count=implementation_count,
    )

    resolution = classify_resolvability(facts)

    resolved_contract = None
    resolved_function = None
    if resolution.status == ResolutionStatus.RESOLVED and resolved_fn is not None:
        resolved_function = resolved_fn.name
        if resolved_fn.contract is not None:
            resolved_contract = resolved_fn.contract.name

    return CallResolution(
        origin=origin,
        resolution=resolution,
        resolved_contract=resolved_contract,
        resolved_function=resolved_function,
    )
