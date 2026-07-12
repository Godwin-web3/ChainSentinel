"""
core/market_schema.py — Protocol-agnostic market config

Every lending protocol reduces to the same shape: an asset, an oracle,
a liquidation threshold. This is the shape every protocol adapter
writes into. Risk logic reads only this, never protocol-specific fields.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class MarketConfig:
    protocol: str                      # e.g. "morpho", "aave"
    market_id: str                     # protocol's own market/reserve id
    collateral_asset: str
    debt_asset: str
    oracle_address: str
    oracle_type: str                   # "spot", "twap", "chainlink", "unknown"
    liquidation_threshold: float        # 0.0 to 1.0
    irm_address: Optional[str] = None
