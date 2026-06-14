import re
from utils.logger import log

# ═══════════════════════════════════════════════════════════════════════════════
# CLASSIFIER v3 — Behavior-first, multi-signal, import-aware
# Priority: exclusive signals → weighted scoring → hybrid resolution → name hints
# ═══════════════════════════════════════════════════════════════════════════════

# ── Step 0: Strip import noise before scoring ─────────────────────────────────
# Multi-file projects concatenate interfaces/imports — these inflate wrong scores
IMPORT_NOISE_RE = re.compile(
    r'^\s*(import\s+.*?;|interface\s+\w+\s*\{[^}]*\})',
    re.MULTILINE | re.DOTALL
)

def strip_imports(source: str) -> str:
    """Remove import statements and interface-only blocks to reduce noise."""
    # Remove single-line imports
    source = re.sub(r'^\s*import\s+[^\n]+', '', source, flags=re.MULTILINE)
    # Remove pure interface blocks (no function bodies)
    source = re.sub(r'interface\s+\w+\s*\{[^{}]*\}', '', source, flags=re.DOTALL)
    return source

# ── Step 1: Exclusive signals — single match overrides everything ─────────────
# These patterns are unique enough that false positives are near-zero
EXCLUSIVE_SIGNALS = [
    # Lending — Compound-style
    (re.compile(r'enterMarkets|exitMarket|borrowAllowed|mintAllowed|redeemAllowed|borrowRatePerBlock|supplyRatePerBlock|accrueInterest|borrowIndex|Comptroller', re.I), "lending"),
    # Lending — Aave-style
    (re.compile(r'liquidationCall|getUserAccountData|getReserveData|flashLoanSimple|FLASHLOAN_PREMIUM', re.I), "lending"),
    # Stability — Liquity/MakerDAO
    (re.compile(r'openTrove|closeTrove|adjustTrove|troveManager|NICR|TCR\b|ICR\b|CDPManager|ilk\b.*\bvat\b', re.I | re.DOTALL), "stability"),
    # Governance
    (re.compile(r'GovernorBravo|GovernorAlpha|proposalThreshold|votingDelay\(\)|votingPeriod\(\)|castVoteBySig', re.I), "governance"),
    # Multisig
    (re.compile(r'submitTransaction.*confirmTransaction|confirmTransaction.*executeTransaction|getOwners\(\).*isConfirmed', re.I | re.DOTALL), "multisig"),
    # Insurance
    (re.compile(r'buyCover|claimPayout|NXMToken|underwriterPool|coverAmount', re.I), "insurance"),
    # Bridge
    (re.compile(r'bridgeETH|finalizeBridgeETH|finalizeDeposit|l1Token.*l2Token|relayMessage.*sourceChain', re.I | re.DOTALL), "bridge"),
    # Rewards farm (MasterChef pattern)
    (re.compile(r'massUpdatePools|MasterChef|pendingSushi|pendingCake|rewardDebt.*userInfo|poolInfo.*allocPoint', re.I | re.DOTALL), "rewards"),
    # Oracle
    (re.compile(r'latestRoundData|latestAnswer|getRoundData|AggregatorV3Interface|updateAnswer|transmit\(', re.I), "oracle"),
    # Factory
    (re.compile(r'createPool\(|createPair\(|deployPool\(|allPairs\(|allPools\(|getPair\(|getPool\(.*fee', re.I), "factory"),
    # Flashloan receiver
    (re.compile(r'executeOperation\(.*assets.*amounts.*premiums|onFlashLoan\(.*initiator|uniswapV2Call\(|pancakeCall\(', re.I | re.DOTALL), "flashloan_receiver"),
    # Perpetuals
    (re.compile(r'increasePosition|decreasePosition|liquidatePosition|fundingRate|openInterest|markPrice|indexPrice', re.I), "perpetual"),
]

# ── Step 2: Weighted signature banks ─────────────────────────────────────────
# (pattern, weight) — higher weight = more diagnostic
# Patterns use exact substrings found in Solidity source

ERC20_SIGS = [
    ("function transfer(", 2), ("function transferFrom(", 3), ("function approve(", 1),
    ("function balanceOf(", 1), ("function totalSupply(", 2), ("function allowance(", 2),
    ("function decimals(", 2), ("function symbol(", 1), ("function name(", 1),
    ("emit Transfer(", 2), ("emit Approval(", 2), ("_mint(", 1), ("_burn(", 1),
    ("ERC20", 1), ("IERC20", 1),
]

ERC721_SIGS = [
    ("function ownerOf(", 4), ("function safeTransferFrom(", 4), ("function tokenURI(", 4),
    ("function setApprovalForAll(", 3), ("function getApproved(", 4), ("function isApprovedForAll(", 3),
    ("function tokenOfOwnerByIndex(", 4), ("ERC721", 3), ("IERC721", 2),
    ("emit Transfer(", 1), ("_safeMint(", 2),
]

ERC1155_SIGS = [
    ("function balanceOfBatch(", 5), ("function safeTransferFrom(", 2), ("function safeBatchTransferFrom(", 5),
    ("ERC1155", 4), ("uri(", 2),
]

DEX_SIGS = [
    ("function swap(", 4), ("function addLiquidity(", 4), ("function removeLiquidity(", 4),
    ("function getAmountsOut(", 4), ("token0()", 3), ("token1()", 3),
    ("function getReserves(", 4), ("price0CumulativeLast", 4), ("function flash(", 3),
    ("sqrtPriceX96", 4), ("function collect(", 2), ("tickSpacing", 3),
    ("function mint(", 1), ("function burn(", 1), ("PoolCreated", 3),
    ("addLiquidityETH(", 3), ("swapExactTokensForTokens(", 4),
]

LENDING_SIGS = [
    ("function borrow(", 5), ("function repay(", 4), ("function liquidate(", 3),
    ("function deposit(", 1), ("function withdraw(", 1),
    ("collateralFactor", 5), ("borrowIndex", 5), ("function accrueInterest(", 5),
    ("interestRateModel", 5), ("function redeemUnderlying(", 5),
    ("healthFactor", 4), ("debtToken", 3), ("function getAccountLiquidity(", 5),
    ("function markets(", 4), ("liquidationThreshold", 4),
]

VAULT_SIGS = [
    ("function deposit(", 1), ("function withdraw(", 1),
    ("function totalAssets(", 5), ("function pricePerShare(", 5),
    ("function harvest(", 5), ("function earn(", 4), ("function strategy(", 4),
    ("function convertToAssets(", 5), ("function convertToShares(", 5),
    ("function maxDeposit(", 4), ("totalDebt", 4), ("debtRatio", 5),
    ("performanceFee", 4), ("managementFee", 4), ("function report(", 3),
]

STAKING_SIGS = [
    ("function stake(", 4), ("function unstake(", 4), ("function getReward(", 4),
    ("function earned(", 4), ("function notifyRewardAmount(", 5),
    ("function rewardPerToken(", 5), ("rewardsDuration", 4), ("function exit(", 3),
    ("rewardRate", 4), ("lastUpdateTime", 3), ("function withdraw(", 1),
]

STABILITY_SIGS = [
    ("function openTrove(", 6), ("function closeTrove(", 6), ("function adjustTrove(", 6),
    ("function redeemCollateral(", 5), ("troveManager", 5), ("stabilityPool", 4),
    ("function openCDP(", 6), ("debtToken", 3), ("ICR", 3), ("MCR", 3),
    ("function frob(", 5), ("function bite(", 5),
]

INSURANCE_SIGS = [
    ("function buyCover(", 6), ("function claimPayout(", 6), ("function underwrite(", 5),
    ("premium", 3), ("coverage", 3), ("function submitClaim(", 5),
    ("function assessClaim(", 5), ("NXM", 4),
]

MULTISIG_SIGS = [
    ("function submitTransaction(", 6), ("function confirmTransaction(", 6),
    ("function executeTransaction(", 5), ("function getOwners(", 4),
    ("function isConfirmed(", 5), ("function revokeConfirmation(", 5),
    ("owners[]", 3), ("required", 2),
]

GOVERNANCE_SIGS = [
    ("function propose(", 4), ("function castVote(", 5), ("function execute(", 2),
    ("function queue(", 3), ("function quorum(", 5), ("function timelock(", 4),
    ("proposalCount", 4), ("function proposalThreshold(", 5),
    ("function votingDelay(", 5), ("function votingPeriod(", 5),
]

BRIDGE_SIGS = [
    ("function bridgeETH(", 6), ("function bridgeERC20(", 6), ("function sendMessage(", 4),
    ("function relayMessage(", 5), ("function finalizeBridgeETH(", 6),
    ("l1Token", 5), ("l2Token", 5), ("function finalizeDeposit(", 5),
]

REWARDS_SIGS = [
    ("function claimRewards(", 5), ("pendingRewards(", 5), ("rewardDebt", 5),
    ("userInfo(", 4), ("poolInfo(", 4), ("function massUpdatePools(", 6),
    ("function updatePool(", 4), ("allocPoint", 5), ("function deposit(", 1),
]

ORACLE_SIGS = [
    ("function latestRoundData(", 6), ("function latestAnswer(", 6),
    ("function getRoundData(", 5), ("function updateAnswer(", 5),
    ("AggregatorV3Interface", 5), ("function transmit(", 4),
    ("function getPrice(", 3), ("function consult(", 4),
    ("function observe(", 4), ("TWAP", 3),
]

FACTORY_SIGS = [
    ("function createPool(", 6), ("function createPair(", 6), ("function deployPool(", 6),
    ("function allPairs(", 5), ("function allPools(", 5), ("function getPair(", 5),
    ("function getPool(", 4), ("allPairsLength(", 5), ("function deploy(", 3),
    ("PoolCreated", 4), ("PairCreated", 4),
]

PERPETUAL_SIGS = [
    ("function increasePosition(", 6), ("function decreasePosition(", 6),
    ("function liquidatePosition(", 6), ("fundingRate", 5), ("openInterest", 5),
    ("markPrice", 5), ("indexPrice", 4), ("function updateCumulativeFundingRate(", 6),
    ("positionKey", 4), ("function validateLiquidation(", 5),
]

FLASHLOAN_SIGS = [
    ("function executeOperation(", 6), ("function onFlashLoan(", 6),
    ("function uniswapV2Call(", 6), ("function pancakeCall(", 6),
    ("function callbackFunction(", 4), ("function tokensToRepay(", 4),
]

# ── Step 3: Security metadata signals (not categories — cross-cutting flags) ──
SECURITY_FLAGS = {
    "pausable":         re.compile(r'function pause\(\)|whenNotPaused|Pausable', re.I),
    "ownable":          re.compile(r'onlyOwner|Ownable|transferOwnership', re.I),
    "access_control":   re.compile(r'hasRole|grantRole|revokeRole|AccessControl|onlyRole', re.I),
    "reentrancy_guard": re.compile(r'nonReentrant|ReentrancyGuard|_locked|_notEntered', re.I),
    "upgradeable":      re.compile(r'initializer|__gap|_initialized|UUPSUpgradeable|TransparentUpgradeable', re.I),
    "fee_on_transfer":  re.compile(r'_takeFee|_transferFee|feeOnTransfer|_taxFee', re.I),
    "rebasing":         re.compile(r'rebase\(|_rebase|gonsPerFragment|_totalSupply.*elastic', re.I),
    "flash_mintable":   re.compile(r'flashMint|flashLoan.*mint|onFlashMint', re.I),
    "timelock":         re.compile(r'TimelockController|queuedTransactions|eta\b.*delay', re.I),
}

# ── Step 4: Name hints — last resort only ────────────────────────────────────
NAME_HINTS = {
    "usdt": "token",      "usdc": "token",      "weth": "token",
    "wbtc": "token",      "dai": "token",        "frax": "token",
    "router": "dex",      "quoter": "dex",       "pair": "dex",
    "aave": "lending",    "compound": "lending", "morpho": "lending",
    "euler": "lending",   "spark": "lending",    "radiant": "lending",
    "yearn": "vault",     "beefy": "vault",      "convex": "vault",
    "staking": "staking", "gauge": "staking",    "locker": "staking",
    "trove": "stability", "liquity": "stability","maker": "stability",
    "governor": "governance", "dao": "governance",
    "bridge": "bridge",   "portal": "bridge",    "gateway": "bridge",
    "multisig": "multisig", "gnosis": "multisig",
    "nexus": "insurance", "cover": "insurance",
    "aggregator": "oracle", "pricefeed": "oracle",
    "factory": "factory", "deployer": "factory",
    "gmx": "perpetual",   "perpetual": "perpetual",
}

# ── Hybrid contract rules — contracts that intentionally score high on 2+ types
# When these conflicts arise, resolve with additional signals
HYBRID_RULES = [
    # cToken / aToken: scores token + lending — lending wins if borrowIndex present
    {
        "conflict": ("token", "lending"),
        "resolve_to": "lending",
        "condition": re.compile(r'borrowIndex|accrueInterest|interestRateModel|collateralFactor|Comptroller', re.I),
        "min_secondary_score": 6,
    },
    # ERC4626 vault: scores token + vault — vault wins if convertToAssets present
    {
        "conflict": ("token", "vault"),
        "resolve_to": "vault",
        "condition": re.compile(r'convertToAssets|convertToShares|totalAssets|pricePerShare', re.I),
        "min_secondary_score": 5,
    },
    # Staking rewards: scores staking + rewards — check which is higher
    {
        "conflict": ("staking", "rewards"),
        "resolve_to": None,  # None means use score comparison
        "condition": None,
        "min_secondary_score": 0,
    },
    # Curve pool: scores dex + staking — dex wins if swap present
    {
        "conflict": ("dex", "staking"),
        "resolve_to": "dex",
        "condition": re.compile(r'function swap\(|exchange\(|get_dy\(', re.I),
        "min_secondary_score": 3,
    },
]


def score_weighted(source: str, sigs: list) -> int:
    """Score source against weighted signature bank."""
    if not source:
        return 0
    return sum(weight for pattern, weight in sigs if pattern in source)


def get_security_flags(source: str) -> list:
    """Return list of security properties present in source."""
    return [flag for flag, pattern in SECURITY_FLAGS.items() if pattern.search(source)]


def resolve_hybrid(scores: dict, source: str) -> str:
    """Resolve conflicts where contract scores high on multiple categories."""
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best, best_score = sorted_scores[0]
    second, second_score = sorted_scores[1]

    for rule in HYBRID_RULES:
        c1, c2 = rule["conflict"]
        if (best == c1 and second == c2) or (best == c2 and second == c1):
            if rule["resolve_to"] is None:
                # Use score comparison
                return best
            if rule["condition"] and rule["condition"].search(source):
                if scores[rule["resolve_to"]] >= rule["min_secondary_score"]:
                    log.debug(f"Hybrid resolution: {c1}+{c2} → {rule['resolve_to']}")
                    return rule["resolve_to"]
    return best


def classify(resolved: dict) -> str:
    """
    Classify a contract into its primary category.
    Returns category string + attaches security_flags to resolved dict.
    """
    source_data = resolved.get("source")
    source_code = ""

    if source_data and source_data.get("verified"):
        raw = source_data.get("source", "")
        if isinstance(raw, str):
            source_code = raw
        elif isinstance(raw, dict):
            source_code = " ".join(str(v) for v in raw.values())

    name = resolved.get("name", "").lower()

    # Attach security flags to resolved for use by analyzers
    if source_code:
        resolved["security_flags"] = get_security_flags(source_code)
        log.debug(f"Security flags: {resolved['security_flags']}")

    # Strip import noise before scoring
    clean_source = strip_imports(source_code) if source_code else ""

    # ── 1. Exclusive signals — highest confidence ─────────────────────────────
    for pattern, category in EXCLUSIVE_SIGNALS:
        if pattern.search(clean_source):
            log.debug(f"Classified by exclusive signal → {category}")
            return category

    # ── 2. Weighted signature scoring ────────────────────────────────────────
    scores = {
        "token":             score_weighted(clean_source, ERC20_SIGS),
        "nft":               score_weighted(clean_source, ERC721_SIGS),
        "nft_multi":         score_weighted(clean_source, ERC1155_SIGS),
        "vault":             score_weighted(clean_source, VAULT_SIGS),
        "lending":           score_weighted(clean_source, LENDING_SIGS),
        "dex":               score_weighted(clean_source, DEX_SIGS),
        "staking":           score_weighted(clean_source, STAKING_SIGS),
        "stability":         score_weighted(clean_source, STABILITY_SIGS),
        "insurance":         score_weighted(clean_source, INSURANCE_SIGS),
        "multisig":          score_weighted(clean_source, MULTISIG_SIGS),
        "governance":        score_weighted(clean_source, GOVERNANCE_SIGS),
        "bridge":            score_weighted(clean_source, BRIDGE_SIGS),
        "rewards":           score_weighted(clean_source, REWARDS_SIGS),
        "oracle":            score_weighted(clean_source, ORACLE_SIGS),
        "factory":           score_weighted(clean_source, FACTORY_SIGS),
        "perpetual":         score_weighted(clean_source, PERPETUAL_SIGS),
        "flashloan_receiver": score_weighted(clean_source, FLASHLOAN_SIGS),
    }

    log.debug(f"Scores: { {k:v for k,v in sorted(scores.items(), key=lambda x: x[1], reverse=True) if v > 0} }")

    best = max(scores, key=scores.get)
    second = sorted(scores, key=scores.get, reverse=True)[1]

    # ── 3. Hybrid resolution ──────────────────────────────────────────────────
    if scores[best] > 0 and scores[second] > 0:
        ratio = scores[second] / scores[best]
        if ratio > 0.6:  # scores are close — potential hybrid
            best = resolve_hybrid(scores, clean_source)

    if scores[best] >= 3:
        log.debug(f"Classified by weighted signatures → {best} (score: {scores[best]})")
        return best

    # ── 4. Name hints — last resort ───────────────────────────────────────────
    for hint, category in NAME_HINTS.items():
        if hint in name:
            log.debug(f"Classified by name hint (fallback) '{hint}' → {category}")
            return category

    if resolved.get("type") == "bytecode-only":
        return "unknown-bytecode"

    return "unknown"
