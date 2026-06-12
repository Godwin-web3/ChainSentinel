from utils.logger import log

# ── Signature banks ──────────────────────────────────────────────────────────

ERC20_SIGS       = ["transfer", "transferFrom", "approve", "balanceOf", "totalSupply", "allowance"]
ERC721_SIGS      = ["ownerOf", "safeTransferFrom", "tokenURI", "approve", "balanceOf", "setApprovalForAll"]
DEX_SIGS         = ["swap", "addLiquidity", "removeLiquidity", "getAmountsOut", "token0", "token1", "mint", "burn", "collect", "flash", "getReserves", "price0CumulativeLast"]
LENDING_SIGS     = ["borrow", "repay", "liquidate", "liquidationCall", "getReserveData", "getUserAccountData", "healthFactor", "collateral", "debtToken"]
VAULT_SIGS       = ["deposit", "withdraw", "totalAssets", "pricePerShare", "harvest", "earn", "strategy", "convertToAssets", "convertToShares"]
STAKING_SIGS     = ["stake", "unstake", "getReward", "earned", "notifyRewardAmount", "rewardPerToken", "exit", "rewardsDuration"]
STABILITY_SIGS   = ["openTrove", "closeTrove", "adjustTrove", "redeemCollateral", "liquidate", "troveManager", "stabilityPool", "cdp", "debtToken"]
INSURANCE_SIGS   = ["buyCover", "claimPayout", "underwrite", "premium", "coverage", "incident", "assessment"]
MULTISIG_SIGS    = ["submitTransaction", "confirmTransaction", "executeTransaction", "getOwners", "required", "isConfirmed"]
GOVERNANCE_SIGS  = ["propose", "castVote", "execute", "queue", "state", "quorum", "timelock", "votingPower"]
BRIDGE_SIGS      = ["bridgeETH", "bridgeERC20", "sendMessage", "relayMessage", "finalizeBridgeETH", "l1Token", "l2Token"]
REWARDS_SIGS     = ["claimRewards", "pendingRewards", "rewardDebt", "userInfo", "poolInfo", "massUpdatePools", "deposit", "withdraw"]

# ── Name hint tables ─────────────────────────────────────────────────────────

# Strong single-word matches → high confidence
STRONG_NAME_HINTS = {
    # tokens
    "erc20": "token",   "erc721": "nft",    "erc1155": "nft",
    "usdt": "token",    "usdc": "token",    "dai": "token",
    "weth": "token",    "wbtc": "token",

    # DEX
    "uniswap": "dex",   "sushiswap": "dex", "curve": "dex",
    "balancer": "dex",  "pancake": "dex",   "router": "dex",
    "factory": "dex",   "quoter": "dex",    "pair": "dex",

    # Lending
    "aave": "lending",  "compound": "lending", "morpho": "lending",
    "euler": "lending", "spark": "lending",

    # Vault
    "yearn": "vault",   "beefy": "vault",   "convex": "vault",

    # Staking
    "staking": "staking", "gauge": "staking",

    # Stability / CDP
    "trove": "stability", "cdp": "stability", "maker": "stability",
    "liquity": "stability",
    "stability": "stability",

    # Governance
    "governor": "governance", "timelock": "governance", "dao": "governance",

    # Bridge
    "bridge": "bridge", "portal": "bridge", "gateway": "bridge",

    # Multisig
    "multisig": "multisig", "gnosis": "multisig",

    # Insurance
    "cover": "insurance", "nexus": "insurance",
}

# Pool disambiguation — needs secondary signals
POOL_TYPES = {
    "dex":       ["swap", "token0", "token1", "liquidity", "reserve", "tick", "sqrtPrice", "getReserves"],
    "lending":   ["borrow", "repay", "collateral", "liquidat", "interestRate", "healthFactor", "debt"],
    "staking":   ["stake", "reward", "epoch", "emission", "vest", "lock", "boost"],
    "vault":     ["strategy", "harvest", "pricePerShare", "totalAssets", "earn"],
    "stability": ["trove", "cdp", "redemption", "stabilityPool", "debtToken", "offset", "liquidation", "collateralGain"],
    "rewards":   ["claimRewards", "pendingRewards", "rewardDebt", "userInfo", "poolInfo"],
    "insurance": ["premium", "coverage", "claim", "underwrite", "incident"],
}


def score_signatures(source: str, sigs: list) -> int:
    if not source:
        return 0
    return sum(1 for sig in sigs if sig in source)


def classify_pool(name: str, source: str) -> str:
    """Disambiguate pool type using secondary signals."""
    best_type = "dex"
    best_score = 0

    for pool_type, keywords in POOL_TYPES.items():
        score = sum(1 for kw in keywords if kw.lower() in source.lower())
        # Boost score if keyword appears in name too
        name_bonus = sum(1 for kw in keywords if kw.lower() in name.lower())
        total = score + (name_bonus * 2)
        if total > best_score:
            best_score = total
            best_type = pool_type

    log.debug(f"Pool disambiguation → {best_type} (score: {best_score})")
    return best_type


def classify(resolved: dict) -> str:
    source_data = resolved.get("source")
    source_code = ""

    if source_data and source_data.get("verified"):
        raw = source_data.get("source", "")
        if isinstance(raw, str):
            source_code = raw
        elif isinstance(raw, dict):
            source_code = " ".join(str(v) for v in raw.values())

    name = resolved.get("name", "").lower()

    # ── 1. Strong name hints (unambiguous protocol/token names) ───────────────
    for hint, category in STRONG_NAME_HINTS.items():
        if hint in name:
            log.debug(f"Classified by strong name hint '{hint}' → {category}")
            return category

    # ── 2. Pool disambiguation ────────────────────────────────────────────────
    pool_keywords = ["pool", "liquidity", "reserve"]
    if any(kw in name for kw in pool_keywords):
        return classify_pool(name, source_code)

    # ── 3. Signature scoring ──────────────────────────────────────────────────
    scores = {
        "token":      score_signatures(source_code, ERC20_SIGS),
        "nft":        score_signatures(source_code, ERC721_SIGS),
        "vault":      score_signatures(source_code, VAULT_SIGS),
        "lending":    score_signatures(source_code, LENDING_SIGS),
        "dex":        score_signatures(source_code, DEX_SIGS),
        "staking":    score_signatures(source_code, STAKING_SIGS),
        "stability":  score_signatures(source_code, STABILITY_SIGS),
        "insurance":  score_signatures(source_code, INSURANCE_SIGS),
        "multisig":   score_signatures(source_code, MULTISIG_SIGS),
        "governance": score_signatures(source_code, GOVERNANCE_SIGS),
        "bridge":     score_signatures(source_code, BRIDGE_SIGS),
        "rewards":    score_signatures(source_code, REWARDS_SIGS),
    }

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        log.debug(f"Classified by signatures → {best} (score: {scores[best]})")
        return best

    if resolved.get("type") == "bytecode-only":
        return "unknown-bytecode"

    return "unknown"
