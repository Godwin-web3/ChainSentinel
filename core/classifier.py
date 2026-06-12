from typing import Optional
from utils.logger import log

# ERC20 function signatures
ERC20_SIGS = ["transfer", "transferFrom", "approve", "balanceOf", "totalSupply", "allowance"]
ERC721_SIGS = ["ownerOf", "safeTransferFrom", "tokenURI", "approve", "balanceOf"]
VAULT_SIGS = ["deposit", "withdraw", "totalAssets", "totalSupply", "convertToAssets"]
LENDING_SIGS = ["borrow", "repay", "liquidate", "getReserveData", "getUserAccountData"]
DEX_SIGS = ["swap", "addLiquidity", "removeLiquidity", "getAmountsOut", "token0", "token1"]
MULTISIG_SIGS = ["submitTransaction", "confirmTransaction", "executeTransaction", "getOwners"]
GOVERNANCE_SIGS = ["propose", "castVote", "execute", "queue", "state"]
BRIDGE_SIGS = ["deposit", "withdraw", "bridgeETH", "bridgeERC20", "sendMessage"]

def score_signatures(source: str, sigs: list) -> int:
    if not source:
        return 0
    return sum(1 for sig in sigs if sig in source)

def classify(resolved: dict) -> str:
    source_data = resolved.get("source")
    source_code = ""

    if source_data and source_data.get("verified"):
        raw = source_data.get("source", "")
        if isinstance(raw, str):
            source_code = raw
        elif isinstance(raw, dict):
            source_code = " ".join(raw.values())

    name = resolved.get("name", "").lower()
    contract_type = resolved.get("type", "")

    # Name-based hints
    name_hints = {
        "token": "token",
        "erc20": "token",
        "usdt": "token",
        "usdc": "token",
        "vault": "vault",
        "pool": "lending",
        "pair": "dex",
        "swap": "dex",
        "router": "dex",
        "lend": "lending",
        "borrow": "lending",
        "aave": "lending",
        "compound": "lending",
        "multisig": "multisig",
        "safe": "multisig",
        "govern": "governance",
        "bridge": "bridge",
        "proxy": "proxy",
    }

    for hint, category in name_hints.items():
        if hint in name:
            log.debug(f"Classified by name hint '{hint}' → {category}")
            return category

    # Signature scoring
    scores = {
        "token": score_signatures(source_code, ERC20_SIGS),
        "nft": score_signatures(source_code, ERC721_SIGS),
        "vault": score_signatures(source_code, VAULT_SIGS),
        "lending": score_signatures(source_code, LENDING_SIGS),
        "dex": score_signatures(source_code, DEX_SIGS),
        "multisig": score_signatures(source_code, MULTISIG_SIGS),
        "governance": score_signatures(source_code, GOVERNANCE_SIGS),
        "bridge": score_signatures(source_code, BRIDGE_SIGS),
    }

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        log.debug(f"Classified by signatures → {best} (score: {scores[best]})")
        return best

    if contract_type == "bytecode-only":
        return "unknown-bytecode"

    return "unknown"
