"""
Invariant extraction — Layer 1, explicit constraints.

Extracts require()/assert() conditions from a function's AST and
resolves each operand back to the real StateVariable(s) it touches,
with struct-field granularity where applicable.

This is data-driven: no protocol names, no variable-name lists.
Any require/assert comparing two expressions, where at least one
side touches state, becomes a candidate invariant.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Set, Any

from slither.slithir.operations import SolidityCall, Assignment
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.expressions.identifier import Identifier
from core.edges import _find_defining_op


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


def get_node_write(node):
    """
    Check a single node for a state-write assignment and return its
    structured key, or None if this node isn't a state-write.

    Node-level primitive — factored out so ordering analysis can
    call this on individual nodes or slices (e.g. only the nodes
    after an external call), not just whole-function scans. Named
    for what it does (extract a node's write), not what it returns,
    so it can grow to carry more than a key later without a rename.
    """
    expr = node.expression
    if expr is None or not isinstance(expr, AssignmentOperation):
        return None

    left = expr.expression_left
    resolved = _resolve_operand(left)
    return _resolved_to_key(resolved)


def extract_field_precise_writes(f) -> Set[str]:
    """
    Walk a function's nodes and extract every state write, resolved
    to field precision where possible: "market.totalSupplyShares"
    instead of just "market". Falls back to the bare variable name
    when the write target has no member access (e.g. a plain state
    var assignment with no struct/mapping field).

    Thin wrapper around get_node_write() applied to every node in
    the function — the real logic lives at node granularity so it
    can be reused for partial/sliced node lists (ordering analysis).
    """
    writes = set()

    if not getattr(f, "is_implemented", False):
        return writes

    for node in f.nodes:
        key = get_node_write(node)
        if key is not None:
            writes.add(key)

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
        key = _resolved_to_key(resolved)
        if key is not None:
            found.add(key)
        return  # _resolve_operand already recursed the base for us

    if isinstance(expr, IndexAccess):
        resolved = _resolve_operand(expr)
        key = _resolved_to_key(resolved)
        if key is not None:
            found.add((key[0], ()))  # bare root var, no member path at this level
        _collect_all_state_refs(expr.expression_right, found)
        return

    if isinstance(expr, Identifier):
        val = expr.value
        if type(val).__name__ == "StateVariable":
            found.add((val.name, ()))
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


def _resolved_to_key(resolved: ResolvedOperand):
    """
    Convert a ResolvedOperand into a structured, hashable key:
    (root_state_var, member_path_tuple). This is the canonical
    internal representation — NOT a joined string — so downstream
    code can query by root variable alone, by full path, or extend
    to arrays/nested structs without string-parsing hacks.

    Returns None if the operand isn't state.
    """
    if not resolved.is_state:
        return None
    return (resolved.state_var_name, tuple(resolved.member_path))


def state_key_to_display(key) -> str:
    """
    Human-readable form of a structured state key, for reports only.
    E.g. ('market', ('totalSupplyAssets',)) -> 'market.totalSupplyAssets'
    Never parse this string back — use the tuple key for logic.
    """
    root, path = key
    if path:
        return f"{root}.{'.'.join(path)}"
    return root


def root_names(keys) -> set:
    """
    Extract just the bare root variable names from a set of
    structured state keys — for consumers that only need coarse
    (variable-level, not field-level) matching, e.g. comparing
    against the enricher's plain-string reads, a separate data
    source that was never field-precise to begin with.
    """
    return {k[0] for k in keys}


from slither.slithir.operations import HighLevelCall, LowLevelCall, LibraryCall as _LibraryCallCheck


CALLBACK_CAPABLE = "callback_capable"   # can execute attacker logic
READ_ONLY = "read_only"                 # view/pure — cannot mutate
                                          # state during the call
                                          # (Solidity STATICCALL
                                          # semantics), so it cannot
                                          # itself corrupt invariant
                                          # state mid-transaction
UNKNOWN_EXTERNAL = "unknown_external"    # target/mutability could
                                          # not be resolved — treat
                                          # conservatively as if
                                          # callback-capable


@dataclass
class CallEvent:
    """One external call in a function, classified by threat shape."""
    node_index: int
    node_expr_str: str
    call_kind: str   # one of CALLBACK_CAPABLE, READ_ONLY, UNKNOWN_EXTERNAL


def _fresh_deployment_contract(f):
    """
    If f's own body computes creation bytecode via a real
    `type(X).creationCode`/`.runtimeCode` SolidityCall — X being an
    actual contract declared in this same compilation, whose entire
    source Slither has already parsed — return that Contract object X.
    None if no such pattern exists, or if more than one appears (an
    ambiguous case this stays conservative about rather than guessing
    which one a later CREATE2 destination belongs to).

    `ir.lvalue.type` for this SolidityCall shape is a
    TypeInformation node whose OWN `.type` is the real Contract
    reference (confirmed live via real IR: `type(address)(UniswapV2Pair)`
    ⇒ `ir.lvalue.type.type is <Contract UniswapV2Pair>`).
    """
    targets = []
    try:
        nodes = list(getattr(f, "nodes", []) or [])
    except Exception:
        return None
    for node in nodes:
        for ir in node.irs:
            if not isinstance(ir, SolidityCall):
                continue
            name = str(getattr(ir.function, "name", "") or "")
            if not name.startswith("type("):
                continue
            lvalue_type = getattr(ir.lvalue, "type", None)
            inner = getattr(lvalue_type, "type", None)
            if inner is not None and hasattr(inner, "functions"):
                targets.append(inner)
    if len(targets) == 1:
        return targets[0]
    return None


def _fresh_deployment_destinations(f) -> set:
    """
    Scan f's own body for the CREATE2-factory pattern — a create/
    create2 assigning a local variable, paired with a same-function
    _fresh_deployment_contract — and return the id()s of every such
    destination variable.

    Two real IR shapes, both confirmed live this session against the
    SAME source pattern compiled by different solc versions:
      1. Newer solc/Slither combinations actually decompose a simple
         inline-assembly create2 block into structured IR — a real
         `SolidityCall create2(uint256,uint256,uint256,uint256)(...)`
         whose own `.lvalue` IS the destination variable directly
         (confirmed live: solc 0.8.19 on a from-scratch fixture).
      2. Older solc/Slither combinations (confirmed live: real
         UniswapV2Factory on solc 0.5.16) leave the assembly block
         fully opaque — an ASSEMBLY node whose own node.irs is empty
         — so the raw `inline_asm` text is the only available signal.
         The EVM opcode mnemonic matched there is a fixed language
         keyword, not a developer-chosen name — the same category of
         match core/sinks.py's own SELFDESTRUCT_NAMES already relies
         on for selfdestruct/suicide.
    """
    contract = _fresh_deployment_contract(f)
    if contract is None:
        return set()
    destinations = set()
    try:
        nodes = list(getattr(f, "nodes", []) or [])
        variables = list(getattr(f, "variables", []) or [])
    except Exception:
        return set()
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                name = (getattr(ir.function, "name", "") or "")
                if name.startswith("create2(") or name.startswith("create("):
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None:
                        destinations.add(id(lvalue))
                        # The create2 SolidityCall's own lvalue is a
                        # fresh TEMPORARY (TMP_n); the actual named
                        # variable used later (`pair`) is assigned
                        # from it via a separate Assignment in the
                        # SAME node — confirmed live IR shape.
                        for other in node.irs:
                            if isinstance(other, Assignment) and other.rvalue is lvalue:
                                destinations.add(id(other.lvalue))
        if str(getattr(node, "type", "")) != "NodeType.ASSEMBLY":
            continue
        asm_text = getattr(node, "inline_asm", "") or ""
        for m in re.finditer(r'\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:=\s*create2?\s*\(', asm_text):
            var_name = m.group(1)
            for v in variables:
                if getattr(v, "name", None) == var_name:
                    destinations.add(id(v))
                    break
    return destinations


def _function_has_external_call(fn) -> bool:
    """True if fn's own body contains any HighLevelCall/LowLevelCall (not LibraryCall)."""
    try:
        nodes = list(getattr(fn, "nodes", []) or [])
    except Exception:
        return True  # unresolvable body — conservative, assume it could call out
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, _LibraryCallCheck):
                continue
            if isinstance(ir, (HighLevelCall, LowLevelCall)):
                return True
    return False


def _classify_call(ir, fresh_deployments: Optional[set] = None) -> str:
    """
    Classify a single call IR by whether it can execute attacker-
    controlled logic that mutates state. Based on the CALLED
    function's declared mutability, resolved by Slither from the
    interface/contract signature — not a name-based guess.

    view/pure calls are STATICCALL under the hood: the EVM itself
    prevents state modification during the call, so even if the
    call target is attacker-controlled, it cannot corrupt this
    contract's state as part of that call. It can still read state
    and could theoretically be used for other attacks, but it is
    not a state-mutation reentrancy vector — which is specifically
    what CROSS_FUNCTION_STATE_RACE checks for.

    A call to a destination this SAME function just deployed via
    CREATE2 with KNOWN, in-project bytecode (fresh_deployments — see
    _fresh_deployment_destinations) is a real second exception, found
    live this session against real UniswapV2Factory.createPair():
    `IUniswapV2Pair(pair).initialize(token0, token1)` is a genuine
    HighLevelCall to a non-view function — but `pair` was CREATE2'd
    two lines earlier from `type(UniswapV2Pair).creationCode`, this
    exact factory's own, fully-known contract, not an
    attacker-substitutable address. Verified sound rather than merely
    trusted: the REAL implementation's matching function (resolved via
    the deployed Contract object, not the abstract interface stub the
    call itself is typed through) is checked for having no external
    call of its own — real UniswapV2Pair.initialize() is a two-field
    setter with none, confirmed live — so this can't be reduced to
    "trust anything freshly deployed" when the deployed code itself
    turns around and calls back out to attacker logic.
    """
    fn = getattr(ir, "function", None)
    if fn is None:
        return UNKNOWN_EXTERNAL
    is_view = getattr(fn, "view", None)
    is_pure = getattr(fn, "pure", None)
    if is_view is None or is_pure is None:
        return UNKNOWN_EXTERNAL
    if is_view or is_pure:
        return READ_ONLY

    if fresh_deployments:
        dest = getattr(ir, "destination", None)
        defining_op = _find_defining_op(dest, ir.node.function) if dest is not None else None
        # A TypeConversion (`IUniswapV2Pair(pair)`) sits between the
        # raw CREATE2'd variable and the call's own destination — one
        # hop to see through, confirmed live via real IR.
        base = getattr(defining_op, "variable", None) if defining_op is not None else None
        if base is not None and id(base) in fresh_deployments:
            real_contract = _fresh_deployment_contract(ir.node.function)
            if real_contract is not None:
                for real_fn in real_contract.functions:
                    if real_fn.name == fn.name and not real_fn.is_shadowed:
                        if not _function_has_external_call(real_fn):
                            return READ_ONLY
                        break

    return CALLBACK_CAPABLE


def get_call_events(f) -> list:
    """
    Return every genuine external call in a function as an ordered
    list of CallEvent, in source order, each classified by whether
    it can actually mutate state (callback_capable) or is
    structurally incapable of doing so (read_only, via view/pure, or
    a freshly-CREATE2'd known-bytecode destination whose own matching
    function makes no external call — see _classify_call).
    Excludes LibraryCall (never leaves trust — see graph.py's
    _extract_calls for the same distinction).

    This replaces a single "trust boundary index" — a function can
    have multiple external calls of different threat shapes, and
    each is an independent point to reason about separately.
    """
    events = []
    if not getattr(f, "is_implemented", False):
        return events

    fresh_deployments = _fresh_deployment_destinations(f)

    for i, node in enumerate(f.nodes):
        for ir in node.irs:
            if isinstance(ir, _LibraryCallCheck):
                continue
            if isinstance(ir, (HighLevelCall, LowLevelCall)):
                events.append(CallEvent(
                    node_index=i,
                    node_expr_str=str(node.expression),
                    call_kind=_classify_call(ir, fresh_deployments),
                ))
    return events


def invariant_writes_between_calls(f, invariant_relevant_keys: set) -> list:
    """
    Walk every external-call event in source order. For each call,
    check whether any invariant-relevant field gets written strictly
    AFTER that call and before the function ends (or the next call —
    doesn't matter which, since ANY post-call invariant write is a
    potential race regardless of what follows it).

    Returns a list of (CallEvent, at_risk_keys) for every call that
    has at least one invariant-relevant write after it. Empty list
    means the function is safe under this check: every invariant-
    relevant write happens before every external call, no window
    exists anywhere in the function, not just relative to one call.

    This fixes the single-anchor bug: "first call" misses writes
    after later calls; "last call" misses writes after earlier
    calls but before a later one. Checking every call independently
    catches both.
    """
    events = get_call_events(f)
    if not events:
        return []

    findings = []
    for event in events:
        if event.call_kind != CALLBACK_CAPABLE:
            continue
        at_risk = set()
        for node in f.nodes[event.node_index:]:
            key = get_node_write(node)
            if key is not None and key in invariant_relevant_keys:
                at_risk.add(key)
        if at_risk:
            findings.append((event, at_risk))

    return findings
