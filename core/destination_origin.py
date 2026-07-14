"""
DestinationOrigin — classifies where a call's target address came from,
using only Slither's resolved IR. No names, no heuristics, no protocol-
specific logic — everything derives from actual data flow.
"""

from enum import Enum
from typing import Tuple

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
    """Classification only. Thin wrapper over resolve_destination()."""
    origin, _ = resolve_destination(call_ir, function)
    return origin


def resolve_destination_variable(call_ir, function):
    """The resolved variable only, or None if never resolved to one."""
    _, var = resolve_destination(call_ir, function)
    return var


def resolve_destination(call_ir, function) -> Tuple[DestinationOrigin, object]:
    """
    Entry point. Returns (origin, resolved_variable_or_None).
    """
    if isinstance(call_ir, LibraryCall):
        return DestinationOrigin.UNKNOWN, None

    destination = getattr(call_ir, "destination", None)
    if destination is None:
        return DestinationOrigin.UNKNOWN, None

    return _resolve_variable(destination, function, seen=set())


def _resolve_variable(var, function, seen: set) -> Tuple[DestinationOrigin, object]:
    var_id = id(var)
    if var_id in seen:
        return DestinationOrigin.UNKNOWN, var
    seen.add(var_id)

    if isinstance(var, SolidityVariableComposed):
        if str(var) in ("msg.sender", "tx.origin"):
            return DestinationOrigin.MSG_SENDER, var
        return DestinationOrigin.UNKNOWN, var

    if isinstance(var, SolidityVariable):
        return DestinationOrigin.UNKNOWN, var

    if isinstance(var, Constant):
        return DestinationOrigin.CONSTANT, var

    if isinstance(var, StateVariable):
        if var.is_constant:
            return DestinationOrigin.CONSTANT, var
        if var.is_immutable:
            return DestinationOrigin.IMMUTABLE, var
        return DestinationOrigin.STATE_VARIABLE, var

    if isinstance(var, LocalVariable):
        if var in function.parameters:
            return DestinationOrigin.PARAMETER, var
        return _trace_local_assignment(var, function, seen)

    if isinstance(var, ReferenceVariable):
        base = getattr(var, "points_to", None)
        if base is not None:
            return _resolve_variable(base, function, seen)
        return _trace_reference(var, function, seen)

    if isinstance(var, TemporaryVariable):
        return _trace_temporary(var, function, seen)

    return DestinationOrigin.UNKNOWN, var


def _trace_local_assignment(var, function, seen) -> Tuple[DestinationOrigin, object]:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Assignment) and ir.lvalue == var:
                return _resolve_variable(ir.rvalue, function, seen)
            if isinstance(ir, TypeConversion) and ir.lvalue == var:
                return _resolve_variable(ir.variable, function, seen)
    return DestinationOrigin.LOCAL_VARIABLE, var


def _trace_reference(var, function, seen) -> Tuple[DestinationOrigin, object]:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (Member, Index)) and ir.lvalue == var:
                base = getattr(ir, "variable_left", None) or getattr(ir, "variable", None)
                if base is not None:
                    return _resolve_variable(base, function, seen)
    return DestinationOrigin.UNKNOWN, var


def _trace_temporary(var, function, seen) -> Tuple[DestinationOrigin, object]:
    for node in function.nodes:
        for ir in node.irs:
            if getattr(ir, "lvalue", None) != var:
                continue
            if isinstance(ir, (HighLevelCall, LibraryCall, InternalCall, LowLevelCall)):
                return DestinationOrigin.RETURN_VALUE, var
            if isinstance(ir, Assignment):
                return _resolve_variable(ir.rvalue, function, seen)
            if isinstance(ir, TypeConversion):
                return _resolve_variable(ir.variable, function, seen)
            if isinstance(ir, (Member, Index)):
                base = getattr(ir, "variable_left", None) or getattr(ir, "variable", None)
                if base is not None:
                    return _resolve_variable(base, function, seen)
    return DestinationOrigin.UNKNOWN, var
