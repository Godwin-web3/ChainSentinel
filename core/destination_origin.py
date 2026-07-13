"""
DestinationOrigin — classifies where a call's target address came from,
using only Slither's resolved IR. No names, no heuristics, no protocol-
specific logic — everything derives from actual data flow.

This traces a call's destination variable backward through the function's
IR (Assignment, Member, Index, TypeConversion) until it reaches a variable
whose origin is structurally unambiguous.
"""

from enum import Enum
from typing import Optional

from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityVariableComposed,
)
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.variables.constant import Constant
from slither.slithir.variables.temporary import TemporaryVariable
from slither.slithir.variables.reference import ReferenceVariable
from slither.slithir.operations import (
    Assignment,
    Member,
    Index,
    TypeConversion,
    HighLevelCall,
    LibraryCall,
    InternalCall,
    LowLevelCall,
)


class DestinationOrigin(Enum):
    MSG_SENDER = "msg_sender"
    PARAMETER = "parameter"
    STATE_VARIABLE = "state_variable"
    IMMUTABLE = "immutable"
    CONSTANT = "constant"
    LOCAL_VARIABLE = "local_variable"
    RETURN_VALUE = "return_value"
    UNKNOWN = "unknown"


def resolve_destination_origin(call_ir, function) -> DestinationOrigin:
    """
    Entry point. Given a call IR operation (HighLevelCall, LibraryCall, etc.)
    and the function it appears in, resolve the origin of its destination.
    """
    destination = getattr(call_ir, "destination", None)
    if destination is None:
        return DestinationOrigin.UNKNOWN

    return _resolve_variable(destination, function, seen=set())


def _resolve_variable(var, function, seen: set) -> DestinationOrigin:
    # Cycle guard — IR tracing should never loop, but never trust that blindly.
    var_id = id(var)
    if var_id in seen:
        return DestinationOrigin.UNKNOWN
    seen.add(var_id)

    # msg.sender / tx.origin — SolidityVariableComposed covers both.
    if isinstance(var, SolidityVariableComposed):
        if str(var) in ("msg.sender", "tx.origin"):
            return DestinationOrigin.MSG_SENDER
        return DestinationOrigin.UNKNOWN

    if isinstance(var, SolidityVariable):
        return DestinationOrigin.UNKNOWN

    # Literal address baked into bytecode.
    if isinstance(var, Constant):
        return DestinationOrigin.CONSTANT

    # State variable — split constant/immutable/plain mutable storage.
    if isinstance(var, StateVariable):
        if var.is_constant:
            return DestinationOrigin.CONSTANT
        if var.is_immutable:
            return DestinationOrigin.IMMUTABLE
        return DestinationOrigin.STATE_VARIABLE

    # Local variable — distinguish a real function parameter from a
    # local declared and assigned inside the function body.
    if isinstance(var, LocalVariable):
        if var in function.parameters:
            return DestinationOrigin.PARAMETER
        return _trace_local_assignment(var, function, seen)

    # ReferenceVariable — Member/Index access (e.g. struct field, array slot).
    # Slither tracks its base directly via points_to when available.
    if isinstance(var, ReferenceVariable):
        base = getattr(var, "points_to", None)
        if base is not None:
            return _resolve_variable(base, function, seen)
        return _trace_reference(var, function, seen)

    # TemporaryVariable — produced by some IR op (call return, cast, etc.).
    # Must search the function body for the IR that assigned it.
    if isinstance(var, TemporaryVariable):
        return _trace_temporary(var, function, seen)

    return DestinationOrigin.UNKNOWN


def _trace_local_assignment(var, function, seen) -> DestinationOrigin:
    """
    A non-parameter local — find the IR node where it was assigned and
    resolve the right-hand side instead.
    """
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Assignment) and ir.lvalue == var:
                return _resolve_variable(ir.rvalue, function, seen)
            if isinstance(ir, TypeConversion) and ir.lvalue == var:
                return _resolve_variable(ir.variable, function, seen)
    return DestinationOrigin.LOCAL_VARIABLE


def _trace_reference(var, function, seen) -> DestinationOrigin:
    """
    Fallback for ReferenceVariable when points_to isn't populated —
    search for the Member/Index op that produced it.
    """
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (Member, Index)) and ir.lvalue == var:
                base = getattr(ir, "variable_left", None) or getattr(ir, "variable", None)
                if base is not None:
                    return _resolve_variable(base, function, seen)
    return DestinationOrigin.UNKNOWN


def _trace_temporary(var, function, seen) -> DestinationOrigin:
    """
    Search for the IR operation that assigned this temporary. If it came
    from a call's return value, treat as a terminal boundary (RETURN_VALUE)
    rather than recursing into the called function — matches the design
    decision to ship this as a terminal boundary for now.
    """
    for node in function.nodes:
        for ir in node.irs:
            if getattr(ir, "lvalue", None) != var:
                continue
            if isinstance(ir, (HighLevelCall, LibraryCall, InternalCall, LowLevelCall)):
                return DestinationOrigin.RETURN_VALUE
            if isinstance(ir, Assignment):
                return _resolve_variable(ir.rvalue, function, seen)
            if isinstance(ir, TypeConversion):
                return _resolve_variable(ir.variable, function, seen)
            if isinstance(ir, (Member, Index)):
                base = getattr(ir, "variable_left", None) or getattr(ir, "variable", None)
                if base is not None:
                    return _resolve_variable(base, function, seen)
    return DestinationOrigin.UNKNOWN
