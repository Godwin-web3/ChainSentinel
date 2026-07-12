"""
Invariant extraction — Layer 1, explicit constraints.

Extracts require()/assert() conditions from a function's AST and
resolves each operand back to the real StateVariable(s) it touches,
with struct-field granularity where applicable.

This is data-driven: no protocol names, no variable-name lists.
Any require/assert comparing two expressions, where at least one
side touches state, becomes a candidate invariant.
"""

from dataclasses import dataclass, field
from typing import Optional, Set, Any

from slither.slithir.operations import SolidityCall
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.expressions.identifier import Identifier


@dataclass
class ResolvedOperand:
    """One side of a comparison, resolved back to its real state path."""
    expr_str: str                          # human-readable, for reports
    state_var_name: Optional[str] = None   # e.g. "market" — None if not state
    member_path: list = field(default_factory=list)  # e.g. ["lastUpdate"]
    is_state: bool = False
    raw_expr: Any = None                   # original AST node, for later use


@dataclass
class Invariant:
    """
    A single require()/assert() condition, decomposed into two
    resolved operands and an operator. Source = 'explicit' always
    for this module (Layer 1). Layer 2 will add source='inferred'.
    """
    operator: str
    left: ResolvedOperand
    right: ResolvedOperand
    source: str                # "explicit"
    function_id: str           # canonical_id of the function this came from
    contract: str
    node_expr_str: str         # full require(...) text, for reports

    def touches_state(self) -> bool:
        return self.left.is_state or self.right.is_state

    def state_vars(self) -> Set[str]:
        out = set()
        if self.left.is_state:
            out.add(self.left.state_var_name)
        if self.right.is_state:
            out.add(self.right.state_var_name)
        return out


def _resolve_operand(expr) -> ResolvedOperand:
    """
    Walk an AST expression down to its real state variable, if any.
    Handles: MemberAccess (struct field / mapping value),
    IndexAccess (mapping/array indexing), Identifier (variable ref),
    and falls back to a literal/unresolvable operand otherwise.
    """
    expr_str = str(expr)

    # market[id].lastUpdate -> MemberAccess wrapping an IndexAccess
    if isinstance(expr, MemberAccess):
        member_path = [expr.member_name]
        base = _resolve_operand(expr.expression)
        base.member_path = member_path + base.member_path
        base.expr_str = expr_str
        return base

    # market[id] -> IndexAccess, base is the state var, key is usually local
    if isinstance(expr, IndexAccess):
        return _resolve_operand(expr.expression_left)

    # market -> Identifier, .value tells us if it's a StateVariable
    if isinstance(expr, Identifier):
        val = expr.value
        is_state = type(val).__name__ == "StateVariable"
        return ResolvedOperand(
            expr_str=expr_str,
            state_var_name=val.name if is_state else None,
            member_path=[],
            is_state=is_state,
            raw_expr=expr,
        )

    # Literal, type conversion, nested call, etc — not resolvable to state
    return ResolvedOperand(
        expr_str=expr_str,
        state_var_name=None,
        member_path=[],
        is_state=False,
        raw_expr=expr,
    )


def extract_invariants(f, contract_name: str, function_id: str) -> list:
    """
    Extract all require()/assert() invariants from a single function.

    Args:
        f: Slither Function object (must be f.is_implemented)
        contract_name: name of the declaring contract
        function_id: canonical_id, for tracing back to graph.py's nodes

    Returns:
        List[Invariant] — only conditions that are real Binary
        comparisons (skips library-wrapped predicates like
        UtilsLib.exactlyOneZero(...) — those have no BinaryOperation
        argument and are silently skipped, not crashed on).
    """
    invariants = []

    if not getattr(f, "is_implemented", False):
        return invariants

    for node in f.nodes:
        is_require = False
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                fname = ir.function.name if hasattr(ir.function, "name") else str(ir.function)
                if fname.startswith("require") or fname.startswith("assert"):
                    is_require = True
                    break

        if not is_require or node.expression is None:
            continue

        call_expr = node.expression
        if not hasattr(call_expr, "arguments") or not call_expr.arguments:
            continue

        first_arg = call_expr.arguments[0]
        if not isinstance(first_arg, BinaryOperation):
            # library-wrapped predicate (e.g. UtilsLib.exactlyOneZero(...))
            # — known gap, skip cleanly rather than guess
            continue

        left = _resolve_operand(first_arg.expression_left)
        right = _resolve_operand(first_arg.expression_right)

        inv = Invariant(
            operator=str(first_arg.type),
            left=left,
            right=right,
            source="explicit",
            function_id=function_id,
            contract=contract_name,
            node_expr_str=str(call_expr),
        )
        invariants.append(inv)

    return invariants


from slither.core.expressions.assignment_operation import AssignmentOperation


def extract_field_precise_writes(f) -> Set[str]:
    """
    Walk a function's nodes and extract every state write, resolved
    to field precision where possible: "market.totalSupplyShares"
    instead of just "market". Falls back to the bare variable name
    when the write target has no member access (e.g. a plain state
    var assignment with no struct/mapping field).

    Reuses _resolve_operand — the same AST resolution path proven
    against require() operands works identically for assignment
    targets, since both are ordinary Solidity expressions.
    """
    writes = set()

    if not getattr(f, "is_implemented", False):
        return writes

    for node in f.nodes:
        expr = node.expression
        if expr is None or not isinstance(expr, AssignmentOperation):
            continue

        left = expr.expression_left
        resolved = _resolve_operand(left)

        if resolved.is_state:
            if resolved.member_path:
                path = f"{resolved.state_var_name}.{'.'.join(resolved.member_path)}"
            else:
                path = resolved.state_var_name
            writes.add(path)

    return writes


def _collect_all_state_refs(expr, found: set):
    """
    Recursively walk ANY expression subtree and collect every
    field-precise state variable path found anywhere inside it —
    not just at the top level. Needed for reads, since a read can
    appear nested inside arithmetic, function args, etc, unlike a
    write which is always the clean top-level assignment target.
    """
    if expr is None:
        return

    if isinstance(expr, MemberAccess):
        resolved = _resolve_operand(expr)
        if resolved.is_state:
            if resolved.member_path:
                path = f"{resolved.state_var_name}.{'.'.join(resolved.member_path)}"
            else:
                path = resolved.state_var_name
            found.add(path)
        return  # _resolve_operand already recursed the base for us

    if isinstance(expr, IndexAccess):
        resolved = _resolve_operand(expr)
        if resolved.is_state:
            found.add(resolved.state_var_name)
        # also check the index key itself in case it's state-derived
        _collect_all_state_refs(expr.expression_right, found)
        return

    if isinstance(expr, Identifier):
        val = expr.value
        if type(val).__name__ == "StateVariable":
            found.add(val.name)
        return

    if isinstance(expr, BinaryOperation):
        _collect_all_state_refs(expr.expression_left, found)
        _collect_all_state_refs(expr.expression_right, found)
        return

    if isinstance(expr, AssignmentOperation):
        # for reads, we care about the RIGHT side only (what's being read)
        _collect_all_state_refs(expr.expression_right, found)
        return

    # CallExpression (function calls, library calls) — walk arguments
    if hasattr(expr, "arguments") and expr.arguments:
        for arg in expr.arguments:
            _collect_all_state_refs(arg, found)
        return


def extract_field_precise_reads(f) -> Set[str]:
    """
    Walk a function's nodes and extract every state variable READ,
    field-precise where possible. Unlike writes, reads can appear
    anywhere in an expression — inside requires, arithmetic, function
    calls — so this walks every node's full expression tree rather
    than just checking assignment targets.
    """
    reads = set()

    if not getattr(f, "is_implemented", False):
        return reads

    for node in f.nodes:
        expr = node.expression
        if expr is None:
            continue
        _collect_all_state_refs(expr, reads)

    return reads
