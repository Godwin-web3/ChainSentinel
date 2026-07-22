"""
core/adapters/morpho.py — Morpho Blue market adapter

Reads CreateMarket events through Etherscan's log API. Decodes
MarketParams into the protocol-agnostic MarketConfig shape. This is
the only file that knows Morpho's contract shape.
"""

from typing import Optional
import requests
from eth_abi.abi import decode as abi_decode
from web3 import Web3
from core.market_schema import MarketConfig
from utils.rpc import get_web3
from config.chains import Chain
from config.chains import ETHERSCAN_KEY as ETHERSCAN_API_KEY

MORPHO_ADDRESS = "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb"


_PUSH1 = 0x60
_PUSH32 = 0x7F
_SSTORE = 0x55
_CALLER = 0x33
_ORIGIN = 0x32


def _resolve_eip1167_target(code: str) -> Optional[str]:
    """
    EIP-1167 minimal proxies are exactly 45 bytes (90 hex chars) of fixed
    delegatecall boilerplate wrapped around a 20-byte implementation
    address — they contain none of their own function selectors, since
    every call is forwarded verbatim. Structural bytecode matching against
    a selector table can never see through one: it always falls to
    "unknown" regardless of what the implementation actually does. This
    decodes the standard clone template directly and returns the real
    implementation address so the caller can check *that* instead.
    """
    if len(code) == 90 and code.startswith("363d3d373d3d3d363d73") and code.endswith("5af43d82803e903d91602b57fd5bf3"):
        return "0x" + code[20:60]
    return None


def _iter_opcodes(code_bytes: bytes):
    """
    Minimal EVM bytecode walker: yields (pc, opcode) pairs. Correctly
    skips PUSH immediates so data bytes inside a PUSH's operand are never
    misread as instructions — a naive byte-by-byte scan for a target
    opcode would false-positive whenever that byte value happens to
    appear inside an unrelated pushed constant.
    """
    i = 0
    n = len(code_bytes)
    while i < n:
        op = code_bytes[i]
        yield i, op
        if _PUSH1 <= op <= _PUSH32:
            i += 1 + (op - _PUSH1 + 1)
        else:
            i += 1


def _has_unguarded_mutation(code: str) -> bool:
    """
    True if this contract's runtime bytecode contains an SSTORE (i.e. some
    external entry point can write to storage after deployment) but never
    once references CALLER or ORIGIN anywhere in the whole contract. Real
    access control on a state-mutating function needs a sender check
    *somewhere* in the bytecode — if neither opcode appears at all, no
    function in this contract can be gating anything by caller identity,
    which means whatever writes that storage is callable by anyone.

    Deliberately whole-contract rather than per-function: reconstructing
    precise function boundaries from raw bytecode (real jump-target CFG
    analysis) is a much bigger undertaking than this adapter needs: the
    absence of CALLER/ORIGIN across an entire contract that can still
    mutate storage is already a strong, real signal on its own.

    Immutable-only pricing (the common, legitimate case — e.g. a real
    Chainlink-wrapping oracle with constructor-set immutables) has zero
    runtime SSTORE at all, since Solidity bakes `immutable` values into
    the bytecode as constants rather than storage writes, so this does
    not fire on that path.

    A heuristic, not a proof: it can't see delegatecall-based auth
    (checked in a different contract) or gating via something other than
    sender identity. Treat a hit as "worth a human look", same spirit as
    every other check in this file — real bytecode facts, never a name
    guess, but not infallible either.
    """
    try:
        code_bytes = bytes.fromhex(code[2:] if code.startswith("0x") else code)
    except ValueError:
        return False

    has_sstore = False
    has_sender_check = False
    for _, op in _iter_opcodes(code_bytes):
        if op == _SSTORE:
            has_sstore = True
        elif op in (_CALLER, _ORIGIN):
            has_sender_check = True
        if has_sstore and has_sender_check:
            return False

    return has_sstore and not has_sender_check


def _detect_oracle_type(oracle_address: str, w3: Web3, _depth: int = 0) -> str:
    """
    Structural detection via bytecode selector matching. No name
    lists, no reliance on contract naming or verification metadata.
    """
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(oracle_address)).hex()
    except Exception:
        return "unknown"

    if not code or code == "0x":
        return "unknown"

    # Follow exactly one EIP-1167 hop before checking selectors — proxies
    # never carry their own selectors. A proxy-of-proxies isn't a real
    # Morpho oracle pattern, so this doesn't chase further.
    if _depth == 0:
        proxy_target = _resolve_eip1167_target(code)
        if proxy_target:
            return _detect_oracle_type(proxy_target, w3, _depth=1)

    has_morpho_price_iface = "a035b1fe" in code
    has_chainlink = "feaf968c" in code
    has_v3_observe = "883bdbfd" in code
    has_v2_reserves = "0902f1ac" in code

    if has_morpho_price_iface and has_chainlink:
        return "chainlink"
    if has_chainlink:
        return "chainlink"
    if has_v3_observe:
        return "twap"
    if has_v2_reserves:
        return "spot"
    if _has_unguarded_mutation(code):
        return "unguarded_mutable"

    return "unknown"


def fetch_markets(chain: Chain, from_block: int, to_block: str = "latest") -> list[MarketConfig]:
    w3 = get_web3(chain)
    latest_block = w3.eth.block_number if to_block == "latest" else int(to_block)

    topic0 = w3.keccak(text="CreateMarket(bytes32,(address,address,address,address,uint256))").hex()
    if not topic0.startswith("0x"):
        topic0 = "0x" + topic0

    raw_logs = []
    page = 1
    offset = 1000
    while True:
        resp = requests.get("https://api.etherscan.io/v2/api", params={
            "chainid": 1,
            "module": "logs",
            "action": "getLogs",
            "address": MORPHO_ADDRESS,
            "topic0": topic0,
            "fromBlock": from_block,
            "toBlock": latest_block,
            "page": page,
            "offset": offset,
            "apikey": ETHERSCAN_API_KEY,
        })
        data = resp.json()
        result = data.get("result", [])
        if not isinstance(result, list) or not result:
            break
        raw_logs.extend(result)
        if len(result) < offset:
            break
        page += 1

    markets = []
    for entry in raw_logs:
        try:
            market_id = entry["topics"][1]
            data_bytes = bytes.fromhex(entry["data"][2:])
            decoded = abi_decode(
                ["address", "address", "address", "address", "uint256"],
                data_bytes,
            )
            loan_token, collateral_token, oracle, irm, lltv = decoded

            markets.append(MarketConfig(
                protocol="morpho",
                market_id=market_id,
                collateral_asset=collateral_token,
                debt_asset=loan_token,
                oracle_address=oracle,
                oracle_type=_detect_oracle_type(oracle, w3),
                liquidation_threshold=lltv / 1e18,
                irm_address=irm,
            ))
        except Exception:
            continue

    return markets
