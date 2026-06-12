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
        explorer_api="https://api.bscscan.com/api",
        explorer_api_key=os.getenv("BSCSCAN_API_KEY", ""),
        native_symbol="BNB"
    ),
    "avalanche": Chain(
        name="Avalanche C-Chain",
        chain_id=43114,
        rpc_url="https://api.avax.network/ext/bc/C/rpc",
        explorer_api="https://api.snowtrace.io/api",
        explorer_api_key=os.getenv("SNOWTRACE_API_KEY", ""),
        native_symbol="AVAX"
    ),
    "fantom": Chain(
        name="Fantom",
        chain_id=250,
        rpc_url="https://rpc.ftm.tools",
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
