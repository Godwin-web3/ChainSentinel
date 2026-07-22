"""
core/oracle_detection.py — Protocol-agnostic oracle classification

Given any address, classifies what kind of price oracle it is from its
real deployed bytecode — selector matching, EIP-1167 proxy resolution,
and an access-control heuristic. Nothing here is Morpho-specific (it
was originally written inline in core/adapters/morpho.py, but there was
never anything Morpho-shaped about it — it works on any address). Any
adapter or discovery module can call detect_oracle_type() the same way.
"""

from typing import Optional
from web3 import Web3

_PUSH1 = 0x60
_PUSH32 = 0x7F
_SSTORE = 0x55
_CALLER = 0x33
_ORIGIN = 0x32


def resolve_eip1167_target(code: str) -> Optional[str]:
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


def iter_opcodes(code_bytes: bytes):
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


def has_unguarded_mutation(code: str) -> bool:
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
    analysis) is a much bigger undertaking than this needs — the absence
    of CALLER/ORIGIN across an entire contract that can still mutate
    storage is already a strong, real signal on its own.

    Immutable-only pricing (the common, legitimate case — e.g. a real
    Chainlink-wrapping oracle with constructor-set immutables) has zero
    runtime SSTORE at all, since Solidity bakes `immutable` values into
    the bytecode as constants rather than storage writes, so this does
    not fire on that path.

    A heuristic, not a proof: it can't see delegatecall-based auth
    (checked in a different contract) or gating via something other than
    sender identity. Treat a hit as "worth a human look" — real bytecode
    facts, never a name guess, but not infallible either.
    """
    try:
        code_bytes = bytes.fromhex(code[2:] if code.startswith("0x") else code)
    except ValueError:
        return False

    has_sstore = False
    has_sender_check = False
    for _, op in iter_opcodes(code_bytes):
        if op == _SSTORE:
            has_sstore = True
        elif op in (_CALLER, _ORIGIN):
            has_sender_check = True
        if has_sstore and has_sender_check:
            return False

    return has_sstore and not has_sender_check


def detect_oracle_type(oracle_address: str, w3: Web3, _depth: int = 0) -> str:
    """
    Structural detection via bytecode selector matching. No name lists,
    no reliance on contract naming or verification metadata — works on
    any address, verified or not, on any protocol.
    """
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(oracle_address)).hex()
    except Exception:
        return "unknown"

    if not code or code == "0x":
        return "unknown"

    # Follow exactly one EIP-1167 hop before checking selectors — proxies
    # never carry their own selectors. A proxy-of-proxies is rare enough
    # in practice that this doesn't chase further.
    if _depth == 0:
        proxy_target = resolve_eip1167_target(code)
        if proxy_target:
            return detect_oracle_type(proxy_target, w3, _depth=1)

    has_morpho_price_iface = "a035b1fe" in code  # Morpho's own IOracle.price() — extra corroborating evidence, not required
    has_chainlink = "feaf968c" in code            # latestRoundData()
    has_v3_observe = "883bdbfd" in code           # Uniswap V3 observe() — TWAP
    has_v2_reserves = "0902f1ac" in code          # Uniswap V2 getReserves() — spot

    if has_morpho_price_iface and has_chainlink:
        return "chainlink"
    if has_chainlink:
        return "chainlink"
    if has_v3_observe:
        return "twap"
    if has_v2_reserves:
        return "spot"
    if has_unguarded_mutation(code):
        return "unguarded_mutable"

    return "unknown"


# ERC20 selectors — used by market_discovery.py to classify candidate asset
# addresses the same structural way oracles are classified.
ERC20_SELECTORS = {
    "balanceOf": "70a08231",
    "totalSupply": "18160ddd",
    "decimals": "313ce567",
    "symbol": "95d89b41",
    "transfer": "a9059cbb",
}


def is_erc20_shaped(address: str, w3: Web3) -> bool:
    """
    True if the address's real bytecode contains at least three of the
    core ERC20 selectors. Structural, not a name/registry lookup — a
    contract either exposes these functions or it doesn't.
    """
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(address)).hex()
    except Exception:
        return False
    if not code or code == "0x":
        return False
    proxy_target = resolve_eip1167_target(code)
    if proxy_target:
        try:
            code = w3.eth.get_code(Web3.to_checksum_address(proxy_target)).hex()
        except Exception:
            return False
    hits = sum(1 for sel in ERC20_SELECTORS.values() if sel in code)
    return hits >= 3
