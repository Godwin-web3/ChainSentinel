"""
core/market_risk.py — Protocol-agnostic market risk scoring

Takes a MarketConfig, scores it. No protocol names, no protocol-specific
fields. Any adapter that produces a MarketConfig gets scored the same way.
"""

from typing import Optional
from core.market_schema import MarketConfig
from core.token_volatility import get_volatility


def score_market_risk(market: MarketConfig, oracle_liquidity_usd: Optional[float] = None) -> dict:
    findings = []

    # Idle markets carry no collateral and no borrowing — nothing to
    # liquidate, nothing to manipulate. Not a risk surface.
    if market.liquidation_threshold == 0:
        return {"protocol": market.protocol, "market_id": market.market_id, "findings": []}

    if market.oracle_type == "spot":
        findings.append({
            "severity": "HIGH",
            "type": "MANIPULABLE_ORACLE",
            "reason": f"{market.market_id} uses a spot price oracle with no TWAP",
        })

    if market.oracle_type == "unguarded_mutable":
        findings.append({
            "severity": "CRITICAL",
            "type": "UNGUARDED_ORACLE",
            "reason": (
                f"{market.market_id} oracle can write to its own price storage "
                f"through a function with no caller-identity check (no CALLER/ORIGIN "
                f"opcode anywhere in its bytecode) — price is effectively settable "
                f"by anyone, no capital or flash loan required"
            ),
        })

    if oracle_liquidity_usd is not None and oracle_liquidity_usd < 500_000:
        findings.append({
            "severity": "HIGH",
            "type": "THIN_LIQUIDITY_ORACLE",
            "reason": f"Oracle pool depth ${oracle_liquidity_usd:,.0f} — cheap to manipulate",
        })

    collateral_volatility = get_volatility(market.collateral_asset)
    if collateral_volatility is not None:
        max_safe_lltv = max(0.50, 1.0 - (collateral_volatility * 0.6))
        if market.liquidation_threshold > max_safe_lltv:
            findings.append({
                "severity": "HIGH" if collateral_volatility > 0.5 else "MEDIUM",
                "type": "HIGH_LLTV",
                "reason": (
                    f"LLTV {market.liquidation_threshold:.0%} exceeds volatility-adjusted "
                    f"safe threshold {max_safe_lltv:.0%} for collateral with "
                    f"{collateral_volatility:.0%} annualized volatility"
                ),
            })
    else:
        if market.liquidation_threshold > 0.90:
            findings.append({
                "severity": "LOW",
                "type": "HIGH_LLTV_UNVERIFIED",
                "reason": (
                    f"LLTV {market.liquidation_threshold:.0%} — collateral volatility "
                    f"could not be resolved, risk unconfirmed"
                ),
            })

    return {
        "protocol": market.protocol,
        "market_id": market.market_id,
        "findings": findings,
    }
