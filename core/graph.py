"""
core/graph.py — Function call graph + exploitability scoring
Layer 1: Slither IR extraction (no heuristics)
Layer 2: Normalization (canonical IDs)
Layer 3: Semantic tagging (constructor/modifier/library/artifact)
Layer 4: Graph construction (real call edges only)
Layer 5: Scoring (purely downstream)
"""

import os
import logging
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional

from slither.slither import Slither
from slither.core.declarations import Modifier
from core.invariants import extract_field_precise_writes, extract_field_precise_reads, get_call_events, extract_invariants
from core.auth_detection import (
    compute_own_auth, is_reentrancy_guard, has_inline_reentrancy_guard,
    has_state_write_after_external_call, has_revert_capable_body,
    has_balance_invariant_after_external_call,
    find_self_scoped_writes, find_self_scoped_asset_moves,
    find_self_scoped_liability_reductions, find_economic_threshold_vars,
)
from core.vault_detection import find_unsafe_share_price_divisor
from core.spot_price_detection import find_unsafe_spot_price_dependency
from core.staleness_detection import find_unstaled_latest_round_data_dependency
from core.initializer_detection import find_unprotected_initializer, has_one_time_latch_protection
from core.fee_on_transfer_detection import find_unsafe_fee_on_transfer_credit
from core.governance_snapshot_detection import find_unsafe_live_voting_power_execution
from core.precision_loss_detection import find_unsafe_divide_before_multiply
from slither.slithir.operations import (
    InternalCall, HighLevelCall, LowLevelCall, SolidityCall, LibraryCall
)

log = logging.getLogger("chainsentinel")

# ── Layer 5 constants ────────────────────────────────────────────
# Functions that are intentionally public economic interfaces.
# These are NOT zeroed — they still participate in asset-flow scoring.
# They are only excluded from auth-gap scoring.
ECONOMIC_INTERFACE = {
    "transfer", "transferfrom", "approve",
    "balanceof", "allowance", "totalsupply",
    "decimals", "symbol", "name",
}

# ── Layer 2: Canonical ID ────────────────────────────────────────
def canonical_id(contract_name: str, full_name: str) -> str:
    return f"{contract_name}.{full_name}"

# ── Layer 3: FunctionNode ────────────────────────────────────────
@dataclass
class FunctionNode:
    # Identity
    id: str
    name: str
    full_name: str
    contract: str

    # Layer 3 — semantic tags (Slither IR derived, no heuristics)
    visibility: str
    is_constructor: bool
    is_modifier: bool
    is_library: bool
    is_artifact: bool
    is_view: bool

    # Auth — structurally computed (core/auth_detection.py), zero name
    # matching. auth_state/auth_score are the EFFECTIVE values (own body
    # OR any attached modifier's own body); structural_auth_score/
    # structural_auth_var are this function/modifier's OWN evidence only,
    # before folding in its modifiers (needed because a function's
    # modifiers may not have been visited yet when the function itself
    # is constructed — see the second pass in build_graph).
    auth_state: str
    modifiers: List[str]
    modifier_ids: List[str] = field(default_factory=list)
    structural_auth_score: int = 0
    structural_auth_var: Optional[str] = None
    # Real variable names this function reads via a msg.sender-keyed
    # NUMERIC (non-bool) Index inside a revert-capable node — see
    # core/auth_detection.py::find_economic_threshold_vars. Deliberately
    # SEPARATE from structural_auth_var (which requires the mirror-image
    # bool-typed shape and feeds auth_score/AUTHENTICATED): a numeric
    # threshold check like Dai's `allowance[src][msg.sender] >= wad` is
    # NOT access-control evidence, but it DOES mark `allowance` as an
    # economically-sensitive variable core/sinks.py::
    # _privileged_vars_by_contract needs for MISSING_HEALTH_CHECK
    # purposes — real Fraxlend's userBorrowShares (checked via
    # `userBorrowShares[msg.sender] > 0`) needed exactly this split to
    # stay sink-worthy without also making Dai.transferFrom() wrongly
    # AUTHENTICATED.
    economic_threshold_vars: Set[str] = field(default_factory=set)
    is_reentrancy_guard: bool = False
    # True if this REGULAR function (not a modifier) contains an
    # inlined reentrancy-guard shape directly in its own body — see
    # core/auth_detection.py::has_inline_reentrancy_guard. Real shape:
    # Uniswap V3's swap() flattens its own `lock` modifier's exact
    # logic directly into its body (a gas optimization on its single
    # hottest-path function) instead of attaching the modifier, which
    # is_reentrancy_guard alone (modifier-only) can't see.
    has_inline_reentrancy_guard: bool = False
    # True if THIS function's own body has a state write CFG-reachable
    # from an external call it makes — the real execution-order CEI
    # violation — see core/auth_detection.py::
    # has_state_write_after_external_call. Distinct from state_writes/
    # external edges alone (which say nothing about order): real
    # Liquity's _sendETHGainToDepositor writes ETH BEFORE its ETH send,
    # CEI-compliant for that variable, which a co-occurrence-only
    # signal can't tell apart from a genuine violation.
    state_write_follows_external_call: bool = False
    # True if this function's own body has a require()/assert()/
    # if-revert node ANYWHERE — see core/auth_detection.py::
    # has_revert_capable_body. Broader than auth_score (msg.sender-
    # comparison specific): lets core/constraints.py::
    # _guard_constrains_sink_state recognize a health-check guard whose
    # condition is derived from a trusted EXTERNAL dependency (e.g. an
    # oracle) rather than local storage or caller identity.
    has_revert_capable_body: bool = False
    # True if this function's own body re-reads, AFTER an external call
    # it makes, the SAME quantity it snapshotted BEFORE that call, and
    # enforces a revert-capable invariant comparing the two — see
    # core/auth_detection.py::has_balance_invariant_after_external_call.
    # The real Uniswap V3 flash() shape (balance0Before/balance0After
    # + require(balance0Before.add(fee0) <= balance0After)) — the
    # actual mechanism that makes an unauthenticated flash-loan
    # callback safe, which core/constraints.py::_check_flashloan_window
    # never checked for despite its own docstring promising to.
    has_balance_invariant_after_call: bool = False
    # Privileged writes reachable from THIS entry that are PROVABLY keyed
    # by the caller's own identity (core/auth_detection.py::
    # find_self_scoped_writes) — e.g. AccessControl.renounceRole's
    # require(account == _msgSender()) before writing
    # _roles[role].members[account]. Same key format as state_writes /
    # Sink.privileged_writes, so directly comparable. An attacker
    # reaching one of these can only ever corrupt their OWN storage slot,
    # not another user's — real evidence a STORAGE_CORRUPTION path here
    # isn't exploitable, distinct from (and narrower than) auth_score.
    self_scoped_write_keys: Set[tuple] = field(default_factory=set)
    # Canonical_ids of REACHABLE functions (from this entry, bounded
    # recursion) whose asset-moving operations are ALL provably safe
    # without any auth gate — see core/auth_detection.py::
    # find_self_scoped_asset_moves. E.g. Liquity's withdrawFromSP() ->
    # _sendETHGainToDepositor(), where the ETH destination is msg.sender
    # directly (found live this session). A path whose sink function id
    # is in THIS set is provably not an arbitrary-recipient asset drain.
    self_scoped_asset_move_functions: Set[str] = field(default_factory=set)
    # Privileged writes reachable from THIS entry that are decrease-
    # writes (x -= y) whose subtracted amount is PROVABLY the same root
    # value as a real inbound payment from msg.sender — see
    # core/auth_detection.py::find_self_scoped_liability_reductions.
    # E.g. Fraxlend's repayAsset()/_repayAsset(): userBorrowShares
    # [_borrower] -= _shares for an ARBITRARY _borrower (the standard
    # permissionless repayBehalf pattern — repaying someone else's debt
    # is a gift, not an attack) is safe because _shares is the same
    # value the caller's own safeTransferFrom(msg.sender, ...) payment
    # is computed from — decoupling them (paying 1 wei to erase a real
    # debt) is what stays UNSAFE and must still fire. Distinct from
    # self_scoped_write_keys, which requires the write to be keyed BY
    # msg.sender itself; this instead requires the write's magnitude to
    # be provably funded BY msg.sender, regardless of who benefits.
    self_scoped_liability_reduction_keys: Set[tuple] = field(default_factory=set)
    # Non-None (the divisor's own evidence string) if this function, or
    # anything it reaches via bounded internal calls, computes a
    # share/asset conversion ratio (a raw Division or a mulDiv-family
    # library call) whose divisor is an unprotected `token.
    # balanceOf(address(this))` read AND writes share-supply-shaped
    # state in that same reachable scope — see core/vault_detection.py
    # ::find_unsafe_share_price_divisor. The real ERC4626 donation/
    # inflation attack shape (Sherlock 2024-01-napier-judging#125,
    # Zellic's Perennial report): an attacker donates tokens directly
    # to the vault (bypassing deposit()) to inflate totalAssets without
    # inflating totalSupply, rounding later depositors' shares to zero.
    unsafe_share_price_divisor: Optional[str] = None
    # Non-None (the accessor call's own evidence string) if this
    # function, or anything it reaches via bounded internal calls,
    # computes a price/value from an unprotected AMM spot-price
    # accessor call (Uniswap V2's getReserves() / V3's slot0()) used
    # directly in a multiplication/division, that SPECIFIC value is not
    # itself forward-tainted into a real elapsed-time-gated division
    # within its own containing function, AND writes real lending/
    # valuation-shaped critical state in that same reachable scope —
    # see core/spot_price_detection.py::find_unsafe_spot_price_dependency.
    # Real precedent: Harvest Finance's real $24M loss (Oct 2020),
    # Warp Finance's real $8M loss (Dec 2020) — both priced collateral
    # directly from a single AMM pool's instantaneous reserve state,
    # manipulable within one flash-loaned transaction.
    unsafe_spot_price_dependency: Optional[str] = None
    # Non-None (the call's own evidence string) if this function, or
    # anything it reaches via bounded internal/high-level calls, calls
    # Chainlink's AggregatorV3Interface.latestRoundData() and consumes
    # the answer without a genuine elapsed-time freshness check on
    # updatedAt (either a revert-capable check, or one propagated via a
    # returned bool), AND writes real lending/valuation-shaped critical
    # state in that same reachable scope — see core/
    # staleness_detection.py::find_unstaled_latest_round_data_dependency.
    # Real precedent: code-423n4/2024-07-loopfi-findings#494/#521 (the
    # real AuraVault.sol shape — updatedAt destructured with a blank
    # comma, never bound to any variable at all), and Cryptex Finance's
    # actual deployed ChainlinkOracle.sol (round-completeness checks
    # only, never elapsed real time).
    unstaled_latest_round_data_dependency: Optional[str] = None
    # Non-None (the written state var name(s)) if this function is
    # externally reachable, is not the real Solidity constructor,
    # writes at least one state variable, and is protected by NEITHER
    # an attached one-time-latch modifier (see core/
    # initializer_detection.py::is_initializer_guard) NOR an inline
    # equivalent in its own body. Deliberately does NOT itself decide
    # which written variable is privileged — that proof already exists
    # in core/sinks.py's own STORAGE_CORRUPTION sink classification
    # (structural_auth_var-derived); the constraint check combines
    # both. Real precedent: the Parity Multisig Wallet Library (Nov
    # 2017) — its real initWallet() set `owner` with zero re-invocation
    # guard, letting an attacker become owner of the shared library
    # contract and selfdestruct it, permanently freezing ~$280M across
    # 587 dependent wallets.
    unprotected_initializer_write: Optional[str] = None
    # True if this function (not a modifier) is protected by a one-time
    # -latch mechanism — see core/initializer_detection.py::
    # has_one_time_latch_protection — independent of whether it writes
    # any privileged state. A first-time initializer legitimately has
    # NO msg.sender-based auth check at all (there's no owner yet to
    # compare against), so core/auth_detection.py's own auth-scoring
    # machinery correctly scores it UNAUTHENTICATED; this is a
    # DIFFERENT, equally real protective signal _check_access_control_
    # gap needs to recognize separately to avoid flagging the OZ-
    # recommended, correctly-guarded initializer pattern as a real
    # access-control gap.
    has_initializer_guard: bool = False
    # Non-None (the written state var's own name) if this function, or
    # anything it reaches via bounded internal calls, pulls tokens in
    # via transferFrom/safeTransferFrom and directly credits the RAW,
    # nominal amount argument into real deposit/balance-shaped
    # accounting state, with no balanceOf(address(this))-delta
    # computation interposed — see core/fee_on_transfer_detection.py::
    # find_unsafe_fee_on_transfer_credit. Real precedent: Balancer's
    # real $500K loss (June 2020) — a pool holding a deflationary token
    # (Statera/STA, 1% burn per transfer) assumed each swap's IN amount
    # was fully received; the discrepancy compounded across repeated
    # flash-loaned swaps until the attacker drained the pool's other
    # real assets.
    unsafe_fee_on_transfer_credit: Optional[str] = None
    # Non-None (the live accessor's own evidence string) if this
    # function, or anything it reaches via bounded internal calls,
    # gates an arbitrary external/low-level call behind a revert-
    # capable threshold comparison whose voting-power operand is read
    # LIVE — no historical/checkpoint dimension at all, or one that
    # queries the raw, unmodified current block — see core/
    # governance_snapshot_detection.py::
    # find_unsafe_live_voting_power_execution. Real precedent:
    # Beanstalk Farms' real $182M loss (April 2022) — a same-block
    # flash loan minted enough live voting power ("stalk") to clear a
    # supermajority threshold and execute a malicious proposal, all
    # repaid within the same transaction.
    unsafe_live_voting_power_execution: Optional[str] = None
    # Non-None (the written state var's own name) if this function, or
    # anything it reaches via bounded internal calls, contains a raw
    # Binary DIVISION whose (already-truncated) result later becomes
    # an operand of a Binary MULTIPLICATION, feeding a write to real
    # share/balance/price-shaped accounting state — see core/
    # precision_loss_detection.py::find_unsafe_divide_before_multiply.
    # Real precedent: Code4rena's real 2022-05-cally-findings#280 —
    # Cally.sol's real getDutchAuctionStrike(), where each line
    # individually looked like the safe "multiply, then divide" shape,
    # but the first line's division result got reused (squared) in a
    # second multiplication, compounding truncation error into the
    # option's strike price.
    unsafe_divide_before_multiply: Optional[str] = None

    # Layer 4 — graph edges (canonical IDs)
    internal_callees: List[str] = field(default_factory=list)
    external_callees: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)

    # Layer 1 — IR facts
    state_writes: Set[str] = field(default_factory=set)
    reads: Set[str] = field(default_factory=set)
    asset_flows: List[str] = field(default_factory=list)
    call_events: List = field(default_factory=list)  # List[CallEvent] from invariants.py —
                                                        # ordered, classified external calls
                                                        # (callback_capable / read_only /
                                                        # unknown_external), source-order indexed
    race_findings: List = field(default_factory=list)  # List[(CallEvent, at_risk_keys)] —
                                                          # precomputed via invariants.py's
                                                          # invariant_writes_between_calls, using
                                                          # real node-order (not approximated).
                                                          # Empty means CEI-safe per this check.
    state_writes_after_callback: List = field(default_factory=list)
                                                          # List[(CallEvent, at_risk_keys)], same
                                                          # computation as race_findings but with
                                                          # THIS function's own full write-set as
                                                          # the "relevant" filter — i.e. every write
                                                          # that happens after a callback-capable
                                                          # call, full stop, not just ones a LOCAL
                                                          # invariant/assertion elsewhere also
                                                          # references. race_findings' narrower
                                                          # local-invariant relevance is the right
                                                          # bar for CROSS_FUNCTION_STATE_RACE; this
                                                          # broader one is what core/cross_market.py
                                                          # needs, since ITS relevance signal is a
                                                          # real cross-contract read elsewhere in the
                                                          # unified graph, not a same-contract
                                                          # assertion.

    # Layer 5 — computed
    reachable_from_untrusted: bool = False
    exploit_score: int = 0

    # Enumeration discovery — real Slither return-type data, used to find
    # one-to-many dependency getters (e.g. Comptroller.getAllMarkets()
    # returning CToken[]), never a name guess.
    returns_address_collection: bool = False
    # The array element's Contract type name when it's a UserDefinedType
    # (e.g. "CToken" for a CToken[] return) — None for plain address[].
    # This is what lets an unresolved dependency's declaring_contract
    # (e.g. "CToken") be matched back to the entry contract's own
    # enumeration getter that can produce a real instance of it.
    enumeration_element_type: Optional[str] = None


# ── Layer 1: IR extraction ───────────────────────────────────────
def _extract_calls(f) -> tuple:
    """Extract internal and external callees from Slither IR nodes."""
    int_callees = []
    ext_callees = []
    flows = []

    for node in f.nodes:
        for ir in node.irs:
            try:
                if isinstance(ir, InternalCall) and ir.function:
                    cid = canonical_id(
                        ir.function.contract_declarer.name,
                        ir.function.full_name
                    )
                    int_callees.append(cid)

                elif isinstance(ir, SolidityCall):
                    int_callees.append(f"solidity.{ir.function.name}")

                elif isinstance(ir, LibraryCall):
                    # LibraryCall is a subclass of HighLevelCall in Slither's
                    # IR, so it must be checked BEFORE the HighLevelCall
                    # branch below, or it silently falls through as an
                    # external call. Library code is linked into the
                    # contract and never leaves the trusted execution
                    # context — it cannot be a reentrancy vector.
                    fname = ir.function_name if hasattr(ir, 'function_name') else ''
                    int_callees.append(f"library.{fname}")

                elif isinstance(ir, HighLevelCall):
                    dest = str(ir.destination) if hasattr(ir, 'destination') else '?'
                    fname = ir.function_name if hasattr(ir, 'function_name') else ''
                    ext_callees.append(f"{dest}.{fname}")
                    if fname in ('transfer', 'transferFrom', 'safeTransfer', 'safeTransferFrom'):
                        flows.append(f"token.{fname}")

                elif isinstance(ir, LowLevelCall):
                    dest = str(ir.destination) if hasattr(ir, 'destination') else '?'
                    ext_callees.append(f"{dest}.lowlevel")
                    if ir.can_send_eth():
                        flows.append("eth.lowlevel")

            except Exception:
                continue

    return int_callees, ext_callees, flows


def find_enumeration_getter(nodes: Dict[str, "FunctionNode"], entry_contract: str, element_type: str) -> Optional[str]:
    """
    Looks for a no-arg function declared directly on entry_contract whose
    return type is an array of element_type (e.g. entry_contract=
    "Comptroller", element_type="CToken" -> "getAllMarkets()"). Used to
    resolve dependencies whose declaring_contract is a sibling TYPE rather
    than a single fixed address — there's no one "the" CToken, only real
    instances discoverable by calling this getter on the entry contract's
    own deployed address.

    Returns the getter's full_name (e.g. "getAllMarkets()") or None if no
    such function exists in this compilation.
    """
    for node in nodes.values():
        if (
            node.contract == entry_contract
            and node.enumeration_element_type == element_type
            and node.full_name.endswith("()")
        ):
            return node.full_name
    return None


def find_any_enumeration_getter(nodes: Dict[str, "FunctionNode"], entry_contract: str):
    """
    Same real, ABI/IR-grounded detection as find_enumeration_getter, but
    without requiring the target element type in advance — used when
    checking "does this contract enumerate a market/pool family at all",
    where the type isn't known until we find the getter.

    Returns (getter_full_name, element_type) or None.
    """
    for node in nodes.values():
        if (
            node.contract == entry_contract
            and node.returns_address_collection
            and node.enumeration_element_type
            and node.full_name.endswith("()")
        ):
            return node.full_name, node.enumeration_element_type
    return None


# ── Layer 4: Graph builder ───────────────────────────────────────
def build_graph(
    project_root: str,
    entry_file: str,
    solc_version: str,
    enrichment: dict,
    remappings: list = None,
) -> Dict[str, FunctionNode]:
    """
    Build function graph from Slither IR.
    Returns (nodes, graph_edges) tuple.
    """
    os.environ["SOLC_VERSION"] = solc_version

    try:
        orig_dir = os.getcwd()
        os.chdir(project_root)
        rel_entry = os.path.relpath(entry_file, project_root)
        solc_remaps = " ".join(remappings[:50]) if remappings else ""
        # --via-ir did not exist before Solidity 0.8.13 — passing it to
        # an older compiler is a hard failure, not a warning, and Slither
        # silently returns nothing usable. Only include it when the
        # target compiler version actually supports it.
        def _supports_via_ir(version_str: str) -> bool:
            try:
                parts = version_str.split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                return (major, minor, patch) >= (0, 8, 13)
            except (ValueError, IndexError):
                return False  # unknown/malformed version — safest default

        if _supports_via_ir(solc_version):
            solc_args = '--via-ir --optimize'
        else:
            solc_args = '--optimize'

        # Guard against crytic-compile's upward-walking Foundry detection.
        # `locate_project_root` resolves the target to an absolute path and
        # walks every ancestor looking for foundry.toml. When project_root has
        # no foundry.toml of its own (e.g. fixture/morpho_blue), the walk
        # escapes past it and finds the repo-root foundry.toml (pinned to
        # 0.8.27), causing a solc version mismatch against the contract's own
        # pragma. Passing foundry_ignore=True disables Foundry platform
        # detection entirely and falls back to plain solc compilation.
        _has_local_foundry = os.path.isfile(os.path.join(project_root, "foundry.toml"))

        s = Slither(
            rel_entry,
            solc='solc-wrapper',
            solc_args=solc_args,
            solc_remaps=solc_remaps,
            foundry_ignore=not _has_local_foundry,
        )
        os.chdir(orig_dir)
    except Exception as e:
        log.warning(f"Graph: Slither API failed: {e}")
        return {}, {}, {}, {}, {}, []

    # NOTE: `enrichment` is accepted for API compatibility with existing
    # callers (main.py, core/protocol_graph.py) but is no longer consumed
    # here — auth_state/auth_score are now computed structurally (see
    # core/auth_detection.py) rather than from analysis/enricher.py's
    # name-matching-based score_auth() output.
    nodes: Dict[str, FunctionNode] = {}
    all_invariants = []
    fn_by_cid = {}

    for contract in s.contracts:
        # Skip pure interfaces — no implementation to analyze
        if contract.is_interface:
            continue

        all_fns = list(contract.functions) + list(contract.modifiers)

        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)
                fn_by_cid[cid] = f

                # Layer 3 — semantic tags from Slither IR
                is_constructor = f.is_constructor
                # Modifier objects carry no `is_modifier` attribute at all
                # (confirmed against installed Slither) — hasattr(...)
                # silently defaulted this to False for EVERY modifier
                # since this field was introduced. isinstance is the real
                # structural check.
                is_modifier = isinstance(f, Modifier)
                is_library = contract.is_library
                is_artifact = "slitherConstructor" in f.full_name
                is_view = f.view or f.pure

                # Layer 1 — IR extraction
                int_callees, ext_callees, flows = _extract_calls(f)
                state_writes = extract_field_precise_writes(f)

                # Cross-contract call resolution
                try:
                    from core.call_resolution import resolve_call
                    from core.cross_contract import build_cross_contract_edge
                    from slither.slithir.operations import HighLevelCall, LibraryCall, LowLevelCall

                    cross_contract_edges = []

                    for node in f.nodes:
                        for ir in node.irs:
                            if not isinstance(ir, (HighLevelCall, LibraryCall, LowLevelCall)):
                                continue
                            resolution = resolve_call(ir, f, s)
                            edge = build_cross_contract_edge(
                                caller_contract=contract.name,
                                caller_function=f.full_name,
                                resolution=resolution,
                            )
                            cross_contract_edges.append(edge)

                except Exception as e:
                    log.debug(f"Cross-contract resolution failed for {cid}: {e}")
                    cross_contract_edges = []

                reads = extract_field_precise_reads(f)
                call_events = get_call_events(f)
                fn_invariants = extract_invariants(f, contract.name, cid)
                all_invariants.extend(fn_invariants)

                # Layer 3 — structural auth (core/auth_detection.py): real
                # msg.sender/tx.origin comparisons or role-mapping lookups
                # in this function/modifier's own body (or internal calls
                # it makes) — zero name matching, a custom-named modifier
                # is scored identically to one named onlyOwner. This is
                # OWN-body evidence only; a function's attached modifiers
                # may not have their own FunctionNode yet (modifiers for
                # this contract are processed after its functions in
                # all_fns), so the EFFECTIVE auth_state/auth_score that
                # folds in modifier evidence is computed in a second pass
                # below, once every node in this contract exists.
                own_auth = compute_own_auth(f)
                structural_auth_score = own_auth.score
                structural_auth_var = own_auth.matched_state_var
                economic_threshold_vars = find_economic_threshold_vars(f)
                modifier_ids = [canonical_id(contract.name, m.full_name) for m in f.modifiers]
                guard = is_reentrancy_guard(f) if is_modifier else False
                inline_guard = has_inline_reentrancy_guard(f) if not is_modifier else False
                write_follows_call = has_state_write_after_external_call(f)
                revert_capable = has_revert_capable_body(f)
                balance_invariant_after_call = has_balance_invariant_after_external_call(f)
                self_scoped_writes = find_self_scoped_writes(f)
                self_scoped_asset_moves = find_self_scoped_asset_moves(f)
                self_scoped_liability_reductions = find_self_scoped_liability_reductions(f)
                unsafe_share_price_divisor = find_unsafe_share_price_divisor(f) if not is_modifier else None
                unsafe_spot_price_dependency = find_unsafe_spot_price_dependency(f) if not is_modifier else None
                unstaled_latest_round_data_dependency = find_unstaled_latest_round_data_dependency(f) if not is_modifier else None
                # find_unprotected_initializer's own-auth exemption (a
                # genuine msg.sender/role check means this isn't an
                # unguarded "logical constructor") needs f's EFFECTIVE
                # auth score — own body OR any attached modifier — not
                # just structural_auth_score (own body only). The
                # second-pass fold below can't be used here: it runs
                # after every node in the contract exists, but a
                # function's modifiers may not have their own
                # FunctionNode yet at this point (see the Layer 3b
                # comment). Attached modifiers ARE already real Slither
                # objects on f regardless of node-build order, so score
                # them directly instead of waiting on the node lookup.
                # Found live this session against MatrixDock's real,
                # currently-deployed STBTv2: grantRole/revokeRole's own
                # bodies (just `_grantRole(role, account);`) carry zero
                # auth evidence of their own — the entire real
                # onlyRole(getRoleAdmin(role)) check lives in the
                # attached modifier — so structural_auth_score was 0
                # despite the function being genuinely, correctly
                # protected, and both false-positived UNPROTECTED_
                # INITIALIZER.
                own_or_modifier_auth_score = structural_auth_score
                if not is_modifier:
                    for m in f.modifiers:
                        own_or_modifier_auth_score = max(own_or_modifier_auth_score, compute_own_auth(m).score)
                unprotected_initializer_write = find_unprotected_initializer(f, own_or_modifier_auth_score) if not is_modifier else None
                init_guard = has_one_time_latch_protection(f) if not is_modifier else False
                unsafe_fee_on_transfer_credit = find_unsafe_fee_on_transfer_credit(f) if not is_modifier else None
                unsafe_live_voting_power_execution = find_unsafe_live_voting_power_execution(f) if not is_modifier else None
                unsafe_divide_before_multiply = find_unsafe_divide_before_multiply(f) if not is_modifier else None
                auth_state = (
                    "AUTHENTICATED" if structural_auth_score >= 3 else
                    "UNKNOWN" if structural_auth_score == 2 else
                    "UNAUTHENTICATED"
                )

                # Structural check (real Slither return-type IR, never a
                # name guess): does this function return an array whose
                # element type is address, or a contract type (e.g.
                # CToken[], ApeToken[])? Used later to discover one-to-many
                # enumeration dependencies (factory/comptroller patterns).
                returns_address_collection = False
                enumeration_element_type = None
                if f.return_type:
                    from slither.core.solidity_types import ArrayType, ElementaryType, UserDefinedType
                    from slither.core.declarations.contract import Contract
                    for rt in f.return_type:
                        if isinstance(rt, ArrayType):
                            elem = rt.type
                            if isinstance(elem, ElementaryType) and elem.name == "address":
                                returns_address_collection = True
                                break
                            if isinstance(elem, UserDefinedType) and isinstance(elem.type, Contract):
                                returns_address_collection = True
                                enumeration_element_type = elem.type.name
                                break

                nodes[cid] = FunctionNode(
                    id=cid,
                    name=f.name,
                    full_name=f.full_name,
                    contract=contract.name,
                    visibility=f.visibility,
                    is_constructor=is_constructor,
                    is_modifier=is_modifier,
                    is_library=is_library,
                    is_artifact=is_artifact,
                    is_view=is_view,
                    auth_state=auth_state,
                    modifiers=[m.name for m in f.modifiers],
                    modifier_ids=modifier_ids,
                    structural_auth_score=structural_auth_score,
                    structural_auth_var=structural_auth_var,
                    economic_threshold_vars=economic_threshold_vars,
                    is_reentrancy_guard=guard,
                    has_inline_reentrancy_guard=inline_guard,
                    state_write_follows_external_call=write_follows_call,
                    has_revert_capable_body=revert_capable,
                    has_balance_invariant_after_call=balance_invariant_after_call,
                    self_scoped_write_keys=self_scoped_writes,
                    self_scoped_asset_move_functions=self_scoped_asset_moves,
                    self_scoped_liability_reduction_keys=self_scoped_liability_reductions,
                    unsafe_share_price_divisor=unsafe_share_price_divisor,
                    unsafe_spot_price_dependency=unsafe_spot_price_dependency,
                    unstaled_latest_round_data_dependency=unstaled_latest_round_data_dependency,
                    unprotected_initializer_write=unprotected_initializer_write,
                    has_initializer_guard=init_guard,
                    unsafe_fee_on_transfer_credit=unsafe_fee_on_transfer_credit,
                    unsafe_live_voting_power_execution=unsafe_live_voting_power_execution,
                    unsafe_divide_before_multiply=unsafe_divide_before_multiply,
                    internal_callees=int_callees,
                    external_callees=ext_callees,
                    state_writes=state_writes,
                    reads=reads,
                    asset_flows=flows,
                    call_events=call_events,
                    returns_address_collection=returns_address_collection,
                    enumeration_element_type=enumeration_element_type,
                )

                nodes[cid].cross_contract_edges = cross_contract_edges
                nodes[cid].auth_score = structural_auth_score

            except Exception as e:
                log.debug(f"Graph: skipping {f.name} in {contract.name}: {e}")
                continue

    # Layer 3b — effective auth score: fold each function's attached
    # modifiers' OWN structural auth evidence into the function's
    # effective auth_state/auth_score, via modifier_ids -> real
    # FunctionNode lookup (never a name match). Must run after every
    # node in every contract exists, since a function's modifiers are
    # processed after it within the same contract's all_fns list.
    for cid, node in nodes.items():
        modifier_scores = [
            nodes[mid].structural_auth_score for mid in node.modifier_ids if mid in nodes
        ]
        node.auth_score = max(node.structural_auth_score, max(modifier_scores, default=0))
        node.auth_state = (
            "AUTHENTICATED" if node.auth_score >= 3 else
            "UNKNOWN" if node.auth_score == 2 else
            "UNAUTHENTICATED"
        )

    # Layer 4 — build caller edges (reverse of callees)
    for cid, node in nodes.items():
        for callee_id in node.internal_callees:
            if callee_id in nodes:
                nodes[callee_id].callers.append(cid)

    # Layer 4 — global state read/write index (cross-function view)
    # Keys are structured: (contract, root_var, member_path_tuple).
    # NOT joined strings — this preserves field precision so
    # supply()'s market.totalSupplyAssets and setFee()'s market.fee
    # are distinct keys, not collapsed into one "market" bucket.
    state_writers = {}
    state_readers = {}
    for cid, node in nodes.items():
        for (root_var, member_path) in node.state_writes:
            key = (node.contract, root_var, member_path)
            state_writers.setdefault(key, []).append(cid)
        for (root_var, member_path) in node.reads:
            key = (node.contract, root_var, member_path)
            state_readers.setdefault(key, []).append(cid)

    # Layer 4 — invariant reverse index: structured state key ->
    # list of Invariant objects that reference it. Built from every
    # require()/assert() found anywhere in the contract (not just
    # the current function), since e.g. market.fee's invariant lives
    # in setFee() but _accrueInterest() also needs to know it's
    # invariant-relevant. Preserves which invariant(s) care about
    # each field — NOT flattened into a bare set — so a finding can
    # later cite the actual guarantee at risk, not just "shared state".
    invariant_index: Dict = {}
    for inv in all_invariants:
        if inv.left.is_state:
            key = (inv.contract, inv.left.state_var_name, tuple(inv.left.member_path))
            invariant_index.setdefault(key, []).append(inv)
        if inv.right.is_state:
            key = (inv.contract, inv.right.state_var_name, tuple(inv.right.member_path))
            invariant_index.setdefault(key, []).append(inv)

    # Layer 4 — race findings: ordering-correct check of whether any
    # invariant-relevant field is written AFTER a callback-capable
    # call, per function. Computed here (not in constraints.py)
    # because it needs the raw Slither function object for real
    # node-order walking — validated against Morpho's supply/repay/
    # liquidate/setFee this session before being wired into the
    # live pipeline.
    from core.invariants import invariant_writes_between_calls
    for cid, node in nodes.items():
        f_obj = fn_by_cid.get(cid)
        if f_obj is None:
            continue
        relevant_bare = {
            (k[1], k[2]) for k in invariant_index.keys() if k[0] == node.contract
        }
        if relevant_bare:
            node.race_findings = invariant_writes_between_calls(f_obj, relevant_bare)

        own_writes = extract_field_precise_writes(f_obj)
        if own_writes:
            node.state_writes_after_callback = invariant_writes_between_calls(f_obj, own_writes)

    # Layer 4 — reachability (using real canonical edges)
    _compute_reachability(nodes)

    # Layer 5 — scoring
    for node in nodes.values():
        node.exploit_score = _exploit_score(node)

    # Layer 4 — extract typed edges while Slither objects are in scope
    from core.edges import extract_edges
    # Build auth_score lookup keyed by canonical_id so edge trust
    # resolution can check who can write a destination storage variable.
    auth_lookup = {
        cid: getattr(node, "auth_score", 0) for cid, node in nodes.items()
    }
    graph_edges: Dict[str, list] = {}
    unresolved_deps: list = []
    for contract in s.contracts:
        if contract.is_interface:
            continue
        all_fns = list(contract.functions) + list(contract.modifiers)
        for f in all_fns:
            try:
                cid = canonical_id(contract.name, f.full_name)
                if cid in nodes:
                    graph_edges[cid] = extract_edges(cid, f, auth_lookup, slither=s, unresolved_deps=unresolved_deps)
            except Exception:
                continue

    log.debug(f"Graph: built {len(nodes)} nodes, {sum(len(e) for e in graph_edges.values())} edges")
    return nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps


# ── Layer 4: Reachability ────────────────────────────────────────
def _compute_reachability(nodes: Dict[str, FunctionNode]):
    """
    Propagate reachability from untrusted EOA entry points.
    Uses canonical call graph edges — no name matching.
    """
    # Seed: public/external non-constructor functions
    for node in nodes.values():
        if (node.visibility in ('public', 'external')
                and not node.is_constructor
                and not node.is_modifier):
            node.reachable_from_untrusted = True

    # BFS propagation through internal call edges
    changed = True
    while changed:
        changed = False
        for node in nodes.values():
            if not node.reachable_from_untrusted:
                continue
            for callee_id in node.internal_callees:
                if callee_id in nodes and not nodes[callee_id].reachable_from_untrusted:
                    nodes[callee_id].reachable_from_untrusted = True
                    changed = True


# ── Layer 5: Scoring ─────────────────────────────────────────────
def _exploit_score(node: FunctionNode) -> int:
    """
    Score exploitability from semantic facts only.
    No name matching. No convention assumptions.
    """
    # Hard zeros — structural Solidity constructs
    if node.is_constructor:
        return 0
    if node.is_modifier:
        return 0
    if node.is_artifact:
        return 0
    if node.is_view:
        return 0

    # Library functions only matter if reachable
    if node.is_library and not node.reachable_from_untrusted:
        return 0

    # Internal functions only matter if reachable
    if node.visibility == "internal" and not node.reachable_from_untrusted:
        return 0

    # Authenticated = not exploitable
    if node.auth_state == "AUTHENTICATED":
        return 0

    # No state impact = nothing to exploit
    if not node.state_writes and not node.asset_flows:
        return 0

    score = 0

    if node.reachable_from_untrusted:
        score += 2

    if node.auth_state == "UNAUTHENTICATED":
        score += 3
    elif node.auth_state == "UNKNOWN":
        score += 1

    if node.state_writes:
        score += 2

    if node.asset_flows:
        score += 4

    # Economic interfaces — suppress auth-gap score
    # but preserve asset-flow score
    if node.name.lower() in ECONOMIC_INTERFACE:
        score = max(0, score - 3)

    return score


# ── API ──────────────────────────────────────────────────────────
def top_findings(nodes: Dict[str, FunctionNode], threshold: int = 5) -> list:
    """Return nodes above exploit score threshold, sorted by score."""
    findings = [n for n in nodes.values() if n.exploit_score >= threshold]
    return sorted(findings, key=lambda x: x.exploit_score, reverse=True)
