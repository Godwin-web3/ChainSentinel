"""
core/initializer_detection.py — Structural front-runnable/missing-
initializer-protection detection (Slither IR, source-level).

Real precedent: the Parity Multisig Wallet Library (Nov 2017) —
WalletLibrary's real `initWallet()` set `owner` with ZERO guard against
being invoked more than once, or by anyone. On Nov 6 2017, an attacker
called `initWallet()` on the shared library contract itself (never
meant to be initialized directly), became its owner, then called the
library's own `kill()` — selfdestructing it. Every one of the 587
wallets that delegatecalled into that now-destroyed library was
permanently frozen, locking ~513,774 ETH (~$280M at the time). The same
root cause — an externally callable "logical constructor" with no
re-invocation guard — recurs constantly in modern proxy-based upgradeable
contracts (real, unnamed but well-documented findings across dozens of
Code4rena/Sherlock audits under "missing initializer modifier" /
"front-runnable initialize()"): since a proxy can't use a real Solidity
`constructor` (that only runs once, at the IMPLEMENTATION's own
deployment, never the proxy's), initialization logic is moved to a
plain external function — and if nothing guards it, an attacker can
call it first (front-running the deployer's own init transaction, or
directly on an un-initialized implementation contract) and become
owner/admin.

The real, industry-standard mitigation — confirmed live via IR probe
against OpenZeppelin's own real, widely-deployed
Initializable.sol (v4.9, the shape virtually every currently-deployed
upgradeable contract still uses; v5's ERC-7201 namespaced-storage
rewrite uses inline assembly for the same guard and is deliberately
out of scope here) — is a ONE-TIME LATCH: a dedicated flag
(`_initialized`) is read by a revert-capable check, then set
permanently, with NO reset anywhere in the guarded scope. This is
structurally distinct from a REENTRANCY guard (core/auth_detection.py::
is_reentrancy_guard), whose defining shape is the OPPOSITE — a flag
toggled (set THEN reset) around the guarded call — confirmed live: the
real OZ `initializer` modifier's OWN `_initializing` transient flag
DOES toggle (matching is_reentrancy_guard's shape, since it's ALSO
guarding against reentrant top-level calls during construction), but
its `_initialized` PERMANENT flag never resets — the latch this module
specifically looks for.

The other real protective shape (confirmed live via IR probe) is a
self-referential guard: checking the auth-critical variable ITSELF is
still at its zero-value sentinel before setting it —
`require(owner == address(0)); owner = msg.sender;` — common in
simpler, non-OZ contracts (closer to the shape Parity's WalletLibrary
was actually missing).

This module deliberately does NOT itself decide which state variable
is "privileged" — that structural proof (delegatecall-implementation-
shaped, or the real target of a msg.sender/tx.origin auth check
anywhere in the contract — FunctionNode.structural_auth_var) already
exists in core/sinks.py::_privileged_vars_by_contract, which
STORAGE_CORRUPTION sink classification already uses. This module only
proves the NARROWER, complementary fact: does THIS function write
SOME state and lack a one-time-latch guard entirely — the constraint
check in core/constraints.py gates on path.sink.category ==
STORAGE_CORRUPTION to combine both proofs, exactly mirroring how
sibling constraints gate on ASSET_DRAIN.
"""

from typing import Optional

from slither.core.cfg.node import NodeType

from core.edges import _node_can_revert
from core.auth_detection import _expand_with_internal_calls, _state_vars_written


def _has_one_time_latch(before: list, after: list) -> bool:
    """
    True if `before`/`after` node lists match a one-time-latch's
    structural signature: some state variable is written in `before`
    and NEVER written again in `after` (the defining difference from a
    reentrancy guard's toggle shape, core/auth_detection.py::
    _guard_shape_from_before_after, which requires the SAME variable
    written on BOTH sides), with a revert-capable node in `before` also
    reading that same variable — the real OZ `_initialized < 1` check
    immediately preceding `_initialized = 1`, confirmed live via IR
    probe.
    """
    written_before = _state_vars_written(before)
    written_after = _state_vars_written(after)
    latch_candidates = written_before - written_after
    if not latch_candidates:
        return False

    for node in before:
        if not _node_can_revert(node):
            continue
        for var in getattr(node, "state_variables_read", []) or []:
            if str(var) in latch_candidates:
                return True
    return False


def is_initializer_guard(modifier_obj) -> bool:
    """
    True if modifier_obj's real body matches a one-time-latch's
    structural signature around its PLACEHOLDER (Slither's real marker
    for a modifier's `_;`) — see _has_one_time_latch. Node lists on
    both sides are expanded (bounded, one hop) through any InternalCall
    they make, matching core/auth_detection.py::is_reentrancy_guard's
    own established convention for the same modern-OZ-delegates-to-
    private-helpers shape.
    """
    try:
        nodes = list(getattr(modifier_obj, "nodes", []) or [])
    except Exception:
        return False

    placeholder_idx = None
    for i, node in enumerate(nodes):
        if node.type == NodeType.PLACEHOLDER:
            placeholder_idx = i
            break
    if placeholder_idx is None:
        return False

    before = _expand_with_internal_calls(nodes[:placeholder_idx])
    after = _expand_with_internal_calls(nodes[placeholder_idx + 1:])
    return _has_one_time_latch(before, after)


def _has_inline_initializer_guard(func_obj) -> bool:
    """
    True if func_obj — a REGULAR function, not a modifier — contains an
    inlined one-time-latch shape directly in its own body: some state
    variable is written exactly once, with a revert-capable node
    reading that SAME variable somewhere before that write, and the
    variable is never written again afterward (excluding the
    reentrancy-guard toggle shape, core/auth_detection.py::
    has_inline_reentrancy_guard, which requires a SECOND write later).
    The real self-referential shape: `require(owner == address(0));
    owner = msg.sender;` — confirmed live via IR probe.
    """
    try:
        nodes = list(getattr(func_obj, "nodes", []) or [])
    except Exception:
        return False

    write_positions: dict = {}
    for i, node in enumerate(nodes):
        for var in getattr(node, "state_variables_written", []) or []:
            write_positions.setdefault(str(var), []).append(i)

    for var_name, positions in write_positions.items():
        first_idx = positions[0]
        before = _expand_with_internal_calls(nodes[: first_idx + 1])
        after = _expand_with_internal_calls(nodes[first_idx + 1 :])
        if var_name in _state_vars_written(after):
            continue  # written again later — a toggle, not a latch
        for node in before:
            if not _node_can_revert(node):
                continue
            for v in getattr(node, "state_variables_read", []) or []:
                if str(v) == var_name:
                    return True
    return False


def find_unprotected_initializer(f, own_auth_score: Optional[int] = None, max_depth: int = 2) -> Optional[str]:
    """
    Public entry point: True (a non-None evidence string — the state
    variable name(s) this function writes) if f, or anything it reaches
    via bounded internal calls (the real OZ `__Ownable_init()`-style
    one-hop delegation shape), ALL of:
      (a) is NOT the real Solidity constructor — a constructor is
          EVM-enforced single-invocation already, at the
          IMPLEMENTATION's own deployment, and needs no guard;
      (b) is externally reachable (external/public visibility) — an
          internal/private function can't be called directly by an
          attacker at all;
      (c) writes at least one state variable somewhere in that
          reachable scope — WHICH variable matters (privileged or not)
          is deliberately NOT decided here; the constraint check gates
          on core/sinks.py's own STORAGE_CORRUPTION sink classification
          (FunctionNode.structural_auth_var-derived) for that proof;
      (d) is protected by NEITHER an attached modifier implementing a
          one-time latch (see is_initializer_guard) NOR an inline
          equivalent directly in f's own body (see
          _has_inline_initializer_guard) NOR a genuine, already-proven
          msg.sender-based auth check (own_auth_score, threaded down
          from core/graph.py's own core.auth_detection.compute_own_auth
          call for this exact f, avoiding a redundant recompute).

    The (d) auth-score exemption is real, not defensive boilerplate:
    found live this session against the actual OpenZeppelin
    Ownable2Step.acceptOwnership() shape —
    `require(pendingOwner() == sender); _transferOwnership(sender);` —
    which writes `owner`/`pendingOwner` (privileged) with no one-time
    latch (by design: it's a REPEATABLE ownership-transfer acceptance,
    not a single-use initializer) but IS genuinely protected by a real
    msg.sender comparison against a value only the CURRENT owner could
    have set (via transferOwnership's own onlyOwner gate). Without this
    exemption, EVERY real Ownable2Step-based contract's
    acceptOwnership() false-positived UNPROTECTED_INITIALIZER.
    """
    if getattr(f, "is_constructor", False):
        return None

    visibility = str(getattr(f, "visibility", "") or "").lower()
    if visibility not in ("external", "public"):
        return None

    expanded = _expand_with_internal_calls(list(getattr(f, "nodes", []) or []), max_depth)
    written_vars = _state_vars_written(expanded)
    if not written_vars:
        return None

    if has_one_time_latch_protection(f):
        return None

    if own_auth_score is not None and own_auth_score >= 3:
        return None

    return ", ".join(sorted(written_vars))


def has_one_time_latch_protection(f) -> bool:
    """
    True if f is protected by a one-time-latch mechanism — an attached
    modifier implementing the shape (see is_initializer_guard), or an
    inline equivalent directly in f's own body (see
    _has_inline_initializer_guard) — independent of whether f actually
    writes any privileged state. Exposed separately from
    find_unprotected_initializer so other checks can recognize this as
    a real, distinct protective signal: a one-time latch answers "can
    this run more than once", which is a genuinely different question
    from "does msg.sender pass an identity check" (core/
    auth_detection.py's own auth-scoring machinery). A first-time
    initializer legitimately has NO msg.sender check at all — there's
    no owner yet to compare against — so treating "no auth check" alone
    as evidence of a real access-control gap produces a real false
    positive on exactly the OZ-recommended, correctly-guarded pattern.
    """
    try:
        modifiers = list(getattr(f, "modifiers", []) or [])
    except Exception:
        modifiers = []
    for m in modifiers:
        if is_initializer_guard(m):
            return True
    return _has_inline_initializer_guard(f)
