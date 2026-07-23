from dataclasses import dataclass
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

ALCHEMY_KEY = os.getenv("ALCHEMY_API_KEY", "PXbp5-4Rr858sQJlg7IIT")
ETHERSCAN_KEY = os.getenv("ETHERSCAN_API_KEY", "C9M3ZBEBTZNQ542MRHHW37C4DCMUG1SH58")

@dataclass
class Chain:
    name: str
    chain_id: int
    rpc_url: str
    explorer_api: str
    explorer_api_key: str
    native_symbol: str
    is_testnet: bool = False

CHAINS = {
    "mainnet": Chain(
        name="Ethereum Mainnet",
        chain_id=1,
        rpc_url=f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "arbitrum": Chain(
        name="Arbitrum One",
        chain_id=42161,
        rpc_url=f"https://arb-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "optimism": Chain(
        name="Optimism",
        chain_id=10,
        rpc_url=f"https://opt-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "base": Chain(
        name="Base",
        chain_id=8453,
        rpc_url=f"https://base-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "polygon": Chain(
        name="Polygon",
        chain_id=137,
        rpc_url=f"https://polygon-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="MATIC"
    ),
    "bsc": Chain(
        name="BNB Smart Chain",
        chain_id=56,
        rpc_url="https://bsc-dataseed1.binance.org",
        # Etherscan V2's unified /v2/api endpoint covers BSC under the
        # same ETHERSCAN_KEY as mainnet/arbitrum/optimism/base/polygon
        # (confirmed live: chainid=56 returns real verified source with
        # this exact key) — no separate BSCSCAN_API_KEY needed. Legacy
        # per-chain domains (bscscan.com/api) still work as a fallback
        # but require their own key, which most deployments don't have.
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="BNB"
    ),
    "avalanche": Chain(
        name="Avalanche C-Chain",
        chain_id=43114,
        rpc_url="https://api.avax.network/ext/bc/C/rpc",
        # Same unification as bsc above — confirmed live: chainid=43114
        # returns real verified source with the shared ETHERSCAN_KEY.
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_api_key=ETHERSCAN_KEY,
        native_symbol="AVAX"
    ),
    "fantom": Chain(
        name="Fantom",
        chain_id=250,
        rpc_url="https://rpc.ftm.tools",
        # NOT covered by Etherscan V2 (confirmed live: chainid=250 is
        # absent from https://api.etherscan.io/v2/chainlist entirely,
        # unlike bsc/avalanche above which ARE listed) — Fantom
        # genuinely needs its own FTMScan key, there's no unified
        # substitute for this one chain.
        explorer_api="https://api.ftmscan.com/api",
        explorer_api_key=os.getenv("FTMSCAN_API_KEY", ""),
        native_symbol="FTM"
    ),
}

def get_chain(name: str) -> Optional[Chain]:
    return CHAINS.get(name.lower())

def get_chain_by_id(chain_id: int) -> Optional[Chain]:
    for chain in CHAINS.values():
        if chain.chain_id == chain_id:
            return chain
    return None

def list_chains() -> list:
    return list(CHAINS.keys())
