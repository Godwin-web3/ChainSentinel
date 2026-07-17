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
    resolved_variable_name: Optional[str] = None
    # The interface/declared function's own full typed signature
    # (name + arg types), taken directly from Slither's IR regardless
    # of whether a concrete implementer was found. This is real,
    # provable data — not a name guess — and is what any downstream
    # cross-compilation matching (core/multi_compile.py) should key on,
    # never bare function names.
    interface_signature: Optional[str] = None


def resolve_call(call_ir, function, slither) -> CallResolution:
    origin, variable = resolve_destination(call_ir, function)

    is_library = isinstance(call_ir, LibraryCall)
    is_constant = origin == DestinationOrigin.CONSTANT
    is_immutable = origin == DestinationOrigin.IMMUTABLE

    public_getter = None
    if origin in (DestinationOrigin.STATE_VARIABLE, DestinationOrigin.IMMUTABLE) and variable is not None:
        if getattr(variable, "visibility", None) == "public":
            public_getter = variable.name

    resolved_fn = getattr(call_ir, "function", None)
    resolved_contract_obj = resolved_fn.contract if resolved_fn else None
    interface_signature = resolved_fn.full_name if resolved_fn is not None else None

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
        resolved_function = resolved_fn.full_name
        target_contract = resolved_fn.contract

        # If the call target is an interface, the interface itself has no
        # function body — the graph has no node for it. Substitute the
        # concrete implementer when exactly one exists in this compilation.
        # With zero or multiple candidates, we genuinely do not know which
        # contract is deployed at this address from source alone, so the
        # edge should not claim a destination it cannot prove.
        if target_contract is not None and target_contract.is_interface:
            implementers = [
                c for c in slither.contracts
                if not c.is_interface and target_contract in c.inheritance
            ]
            if len(implementers) == 1:
                impl_fn = implementers[0].get_function_from_signature(resolved_fn.full_name)                     if hasattr(implementers[0], "get_function_from_signature") else None
                resolved_contract = implementers[0].name
                if impl_fn is not None:
                    resolved_function = impl_fn.full_name
                else:
                    resolved_function = resolved_fn.full_name
            else:
                # zero or ambiguous implementers — don not claim a destination
                resolved_contract = None
                resolved_function = None
        elif target_contract is not None:
            resolved_contract = target_contract.name
            resolved_function = resolved_fn.full_name

    return CallResolution(
        interface_signature=interface_signature,
        origin=origin,
        resolution=resolution,
        resolved_contract=resolved_contract,
        resolved_function=resolved_function,
        resolved_variable_name=public_getter,
    )
