"""
core/market_discovery.py — Adapter-free market discovery via live probing

No protocol-specific event schema, no hardcoded function names, no
per-protocol adapter. Given any verified contract, calls every
zero-argument view/pure function in its real ABI and classifies what
comes back purely from its on-chain shape:
  - an address whose bytecode looks like an ERC20        -> candidate asset
  - an address whose bytecode looks like a price oracle   -> candidate oracle
    (core/oracle_detection.py — real bytecode facts, not a name guess)
  - a uint256 in a plausible ratio range (0, 1e18]        -> candidate threshold

Scope, honestly: this finds market config for single-market-per-contract
shapes (e.g. a Compound-style CToken exposing its own underlying/oracle
as 0-arg getters).

discover_multi_market() extends this to singleton contracts that hold
many markets but expose a real 0-arg getter returning address[] (e.g.
Compound's Comptroller.getAllMarkets() -> CToken[]) — it calls that
getter for real and runs probe_market_config() on every address it
returns. This still requires nothing protocol-specific: the getter is
found by its ABI-declared return type ("address[]"), not by name.

What neither function can do: discover markets on a singleton that has
NO on-chain enumeration function at all and only emits them via
historical event logs (Morpho Blue's CreateMarket pattern — no
getAllMarkets() exists there by design, since an unbounded permissionless
market list would be gas-prohibitive to maintain on-chain). Reaching
those generically would mean classifying which of a contract's *events*
is shaped like "market creation" from its ABI-declared parameter types,
which is a substantially noisier problem than classifying functions —
a Transfer or Deposit event has the same address+uint256 shape and
would collide with it. That's a real, unsolved limitation here, not
a bug to paper over.

Known gap, confirmed on live Compound: oracle discovery on each
per-market contract (e.g. a CToken) reliably comes back empty even on a
real market, because Compound's oracle isn't on the CToken at all — it's
one hop away, on the Comptroller (comptroller().oracle()). Extending
probe_market_config to also follow "returns another contract" getters
one hop and probe *that* address for an oracle would close this using
the exact same detect_oracle_type/is_erc20_shaped primitives already
here — not yet built, noted rather than silently missing.

Collateral vs. debt role is inherently ambiguous from shape alone — two
ERC20-shaped 0-arg results don't say which one a protocol treats as
collateral. This uses the real ABI function names (from the contract's
own verified source — real data, not a guess about a specific
protocol's schema) as a weak corroborating signal when available, and
is explicit in DiscoveryResult.confidence/notes when it can't tell.
"""

import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from web3 import Web3
from core.market_schema import MarketConfig
from core.oracle_detection import detect_oracle_type, is_erc20_shaped
from core.resolver import resolve
from utils.rpc import get_web3, get_address_array
from config.chains import Chain


@dataclass
class DiscoveryResult:
    market: Optional[MarketConfig]
    confidence: str  # "high" | "low" | "none"
    notes: List[str] = field(default_factory=list)
    oracle_candidates: List[str] = field(default_factory=list)
    asset_candidates: List[str] = field(default_factory=list)
    ratio_candidates: List[float] = field(default_factory=list)


@dataclass
class MultiMarketResult:
    getter: Optional[str]
    markets: List[Tuple[str, DiscoveryResult]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


_DEBT_HINTS = ("debt", "borrow", "loan")
_COLLATERAL_HINTS = ("collateral",)
_RATIO_HINTS = ("collateralfactor", "liquidationthreshold", "ltv", "maxltv", "liquidationltv")
# "factor" and bare "liquidation" were tried and removed: Compound-shape
# contracts have reserveFactorMantissa (protocol-fee cut, NOT a threshold)
# and liquidationIncentiveMantissa (liquidator bonus, NOT a threshold) —
# both plausible-looking, both wrong. Real name collisions found on a
# live contract during testing, not theoretical. Even this tighter list
# is still just string matching over whatever the deployer named things —
# it narrows the false-positive rate, it does not eliminate it.
# Well-known ERC20/standard-Solidity getters that return a uint256 in a
# range that can coincidentally land in (0, 1e18] but are never a risk
# ratio — excluding these is a generic standard-interface fact, not
# protocol-specific knowledge (they apply to any ERC20/any contract).
_RATIO_DENYLIST = ("totalsupply", "decimals", "accrualblocknumber", "blocknumber", "timestamp", "chainid", "balanceof")


def _zero_arg_view_functions(abi: list) -> list:
    out = []
    for item in abi:
        if item.get("type") != "function":
            continue
        if item.get("stateMutability") not in ("view", "pure"):
            continue
        if item.get("inputs"):
            continue
        if len(item.get("outputs", [])) != 1:
            continue
        out.append(item)
    return out


def _resolve_abi(address: str, chain: Chain):
    """
    Returns (abi_list, error_note). Most real singletons (Comptrollers,
    Pools, etc.) are upgradeable proxies whose own verified source is
    just admin/delegate boilerplate — the real functions live on the
    implementation. Calls core.resolver.resolve() (the same proxy-
    following used by the rest of the pipeline: storage-slot detection
    first, Etherscan's reported implementation as fallback) to get the
    implementation's real ABI, while callers keep using the original
    `address` for actual eth_call targets — that's the deployed instance
    holding real state; the bare implementation address usually isn't.
    """
    resolved = resolve(address, chain)
    if not resolved:
        return None, "resolution failed"
    source = resolved.get("source")
    if not source or not source.get("verified") or not source.get("abi"):
        return None, "contract not verified — no ABI to probe"
    try:
        return json.loads(source["abi"]), None
    except Exception:
        return None, "ABI did not parse"


def _order_by_hint(name_a: str, addr_a: str, name_b: str, addr_b: str):
    """Best-effort collateral/debt ordering from the real declared
    function names — corroborating signal only, never required."""
    a_lower, b_lower = name_a.lower(), name_b.lower()
    if any(h in a_lower for h in _COLLATERAL_HINTS) or any(h in b_lower for h in _DEBT_HINTS):
        return addr_a, addr_b
    if any(h in b_lower for h in _COLLATERAL_HINTS) or any(h in a_lower for h in _DEBT_HINTS):
        return addr_b, addr_a
    return addr_a, addr_b


def probe_market_config(address: str, chain: Chain) -> DiscoveryResult:
    w3 = get_web3(chain)
    abi, err = _resolve_abi(address, chain)
    if abi is None:
        return DiscoveryResult(market=None, confidence="none", notes=[err])

    checksum_address = Web3.to_checksum_address(address)
    contract = w3.eth.contract(address=checksum_address, abi=abi)

    oracle_candidates = []   # (name, address, oracle_type)
    asset_candidates = []    # (name, address)
    ratio_candidates = []    # (name, ratio)
    notes = []

    # The probed contract is often itself the collateral/position token
    # (e.g. a CToken is its own ERC20) — check it directly, not just what
    # its getters return.
    if is_erc20_shaped(checksum_address, w3):
        asset_candidates.append(("<self>", checksum_address))

    fns = _zero_arg_view_functions(abi)
    for fn in fns:
        name = fn["name"]
        out_type = fn["outputs"][0]["type"]
        try:
            result = getattr(contract.functions, name)().call()
        except Exception:
            continue

        if out_type == "address":
            try:
                if int(result, 16) == 0:
                    continue
                addr = Web3.to_checksum_address(result)
            except Exception:
                continue
            oracle_type = detect_oracle_type(addr, w3)
            if oracle_type != "unknown":
                oracle_candidates.append((name, addr, oracle_type))
            elif is_erc20_shaped(addr, w3):
                asset_candidates.append((name, addr))
        elif out_type == "uint256":
            if name.lower() in _RATIO_DENYLIST:
                continue
            try:
                v = int(result)
            except Exception:
                continue
            if 0 < v <= 10 ** 18:
                ratio_candidates.append((name, v / 1e18))

    notes.append(f"{len(fns)} zero-arg view/pure functions probed on-chain")

    # Order-preserving dedup — a plain set() here would make discovery
    # order (and therefore which candidate becomes "collateral" below)
    # non-deterministic between runs on identical input, since Python
    # doesn't guarantee set iteration order matches insertion order.
    seen_assets = set()
    distinct_assets = []
    asset_names_by_addr = {}
    for name, a in asset_candidates:
        if a not in seen_assets:
            seen_assets.add(a)
            distinct_assets.append(a)
            asset_names_by_addr[a] = name
    # Minimum bar for "this looks like a market at all": a real oracle or a
    # real asset pair. Ratio-shaped candidates alone don't count — tested
    # against a real governance contract (getProposalsCount, getVotingDelay)
    # and both landed in the (0, 1e18] range despite having nothing to do
    # with a market; without this gate they'd be enough on their own to
    # produce a (harmless but meaningless) all-zero MarketConfig.
    if not oracle_candidates and len(distinct_assets) < 2:
        return DiscoveryResult(
            market=None, confidence="none",
            notes=notes + ["no oracle candidate and no asset pair found — not a single-market-shaped contract"],
            oracle_candidates=[c[1] for c in oracle_candidates],
            asset_candidates=distinct_assets,
            ratio_candidates=[v for _, v in ratio_candidates],
        )

    oracle_address = oracle_candidates[0][1] if oracle_candidates else "0x0000000000000000000000000000000000000000"
    oracle_type = oracle_candidates[0][2] if oracle_candidates else "unknown"
    if len(oracle_candidates) > 1:
        notes.append(f"{len(oracle_candidates)} oracle-shaped candidates found ({[c[0] for c in oracle_candidates]}) — used the first, ambiguous")
    elif not oracle_candidates:
        notes.append("no oracle-shaped 0-arg getter found")

    hinted = [(n, v) for n, v in ratio_candidates if any(h in n.lower() for h in _RATIO_HINTS)]
    if hinted:
        threshold = max(v for _, v in hinted)
        if len(hinted) > 1:
            notes.append(f"{len(hinted)} risk-named ratio candidates found ({[n for n, _ in hinted]}) — used the largest")
        else:
            notes.append(f"liquidation_threshold taken from risk-named getter {hinted[0][0]!r}")
    elif ratio_candidates:
        # Deliberately does NOT fall back to "largest unrelated ratio" —
        # tested against a real contract and it picked up reserveFactorMantissa
        # (protocol fee cut) as a fake 100% liquidation threshold. A specific
        # wrong number is worse than admitting no signal: it would silently
        # feed a fabricated HIGH_LLTV finding into score_market_risk.
        threshold = 0.0
        notes.append(
            f"{len(ratio_candidates)} ratio-shaped candidates found ({[c[0] for c in ratio_candidates]}) but none "
            f"named like a risk parameter — not guessing; liquidation_threshold left at 0 (unscored)"
        )
    else:
        threshold = 0.0
        notes.append("no ratio-shaped (0, 1e18] value found — liquidation_threshold defaulted to 0")

    if len(distinct_assets) >= 2:
        addr_a, addr_b = distinct_assets[0], distinct_assets[1]
        collateral, debt = _order_by_hint(asset_names_by_addr[addr_a], addr_a, asset_names_by_addr[addr_b], addr_b)
        notes.append("collateral/debt role assigned from real function-name hints where available, otherwise discovery order — genuinely ambiguous from shape alone")
    elif len(distinct_assets) == 1:
        collateral = debt = distinct_assets[0]
        notes.append("only one asset-shaped candidate found — collateral and debt both set to it, likely wrong for a real 2-asset market")
    else:
        collateral = debt = "0x0000000000000000000000000000000000000000"
        notes.append("no asset-shaped candidates found at all")

    market = MarketConfig(
        protocol="discovered",
        market_id=checksum_address,
        collateral_asset=collateral,
        debt_asset=debt,
        oracle_address=oracle_address,
        oracle_type=oracle_type,
        liquidation_threshold=threshold,
    )

    signals_complete = bool(oracle_candidates) and bool(hinted) and len(distinct_assets) >= 2
    ambiguous = len(oracle_candidates) > 1 or len(hinted) > 1
    if signals_complete and not ambiguous:
        confidence = "high"
    elif oracle_candidates or ratio_candidates or distinct_assets:
        confidence = "low"
    else:
        confidence = "none"

    return DiscoveryResult(
        market=market,
        confidence=confidence,
        notes=notes,
        oracle_candidates=[c[1] for c in oracle_candidates],
        asset_candidates=distinct_assets,
        ratio_candidates=[v for _, v in ratio_candidates],
    )


_ENUMERATION_NAME_HINTS = ("allmarkets", "getallmarkets", "markets", "getmarkets", "allpools", "getallpools")


def _array_returning_functions(abi: list) -> list:
    """0-arg view/pure functions whose ABI-DECLARED output type is
    literally 'address[]' — the real, verified declaration, not a name
    guess. (The equivalent check in core/graph.py works from Slither's
    parsed IR for the static-analysis pipeline; this is the ABI-JSON
    version for this lightweight, adapter-free prober.)"""
    out = []
    for item in abi:
        if item.get("type") != "function":
            continue
        if item.get("stateMutability") not in ("view", "pure"):
            continue
        if item.get("inputs"):
            continue
        outputs = item.get("outputs", [])
        if len(outputs) == 1 and outputs[0].get("type") == "address[]":
            out.append(item)
    return out


def _pick_enumeration_getter(candidates: list) -> dict:
    """When more than one 0-arg getter returns address[], prefer one whose
    real declared name reads like an enumeration ('getAllMarkets',
    'allPairs', ...) — corroborating signal only; falls back to the
    first candidate found either way."""
    for c in candidates:
        if any(h in c["name"].lower() for h in _ENUMERATION_NAME_HINTS):
            return c
    return candidates[0]


def discover_multi_market(address: str, chain: Chain, market_limit: int = 50) -> MultiMarketResult:
    """
    For singleton contracts holding many markets, reachable via a real
    0-arg getter returning address[] (e.g. Compound's Comptroller.
    getAllMarkets() -> CToken[]). Calls that getter for real, then runs
    probe_market_config() on every address it returns — this works
    because each discovered market (a CToken) is itself single-contract-
    shaped, which probe_market_config already knows how to read.

    Does not cover markets only discoverable via historical event logs
    with no on-chain enumeration function at all (Morpho Blue's
    CreateMarket pattern) — see the module docstring.
    """
    abi, err = _resolve_abi(address, chain)
    if abi is None:
        return MultiMarketResult(getter=None, notes=[err])

    candidates = _array_returning_functions(abi)
    if not candidates:
        return MultiMarketResult(getter=None, notes=["no 0-arg getter returning address[] found — not a multi-market-enumerable contract this way"])

    getter_fn = _pick_enumeration_getter(candidates)
    signature = f"{getter_fn['name']}()"
    notes = [f"{len(candidates)} address[]-returning getter(s) found; using {signature!r}"]

    addresses = get_address_array(address, signature, chain, limit=market_limit) or []
    notes.append(f"{signature} returned {len(addresses)} address(es) (capped at {market_limit})")

    markets = [(addr, probe_market_config(addr, chain)) for addr in addresses]

    return MultiMarketResult(getter=signature, markets=markets, notes=notes)
