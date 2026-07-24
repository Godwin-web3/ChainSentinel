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

    # ── Every remaining mainnet Etherscan V2's own chainlist
    # (https://api.etherscan.io/v2/chainlist) lists as online — all
    # share the same unified explorer endpoint + ETHERSCAN_KEY as
    # every chain above (no per-chain explorer key needed). RPC URLs
    # are Alchemy where Alchemy actually supports the network
    # (confirmed live: a real eth_chainId call against every Alchemy
    # URL below returned the exact chain_id listed), otherwise each
    # chain's own official public endpoint (also confirmed live the
    # same way). A handful (stable, plasma, megaeth) are newer/lower-
    # traffic chains whose only available public RPC is explicitly
    # rate-limited by its own operator — fine for this tool's
    # single-contract-at-a-time fetches, not meant for heavy use.
    "linea": Chain(
        name="Linea Mainnet", chain_id=59144,
        rpc_url=f"https://linea-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "blast": Chain(
        name="Blast Mainnet", chain_id=81457,
        rpc_url=f"https://blast-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "bittorrent": Chain(
        name="BitTorrent Chain", chain_id=199,
        rpc_url="https://rpc.bt.io",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="BTT"
    ),
    "celo": Chain(
        name="Celo Mainnet", chain_id=42220,
        rpc_url=f"https://celo-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="CELO"
    ),
    "fraxtal": Chain(
        name="Fraxtal Mainnet", chain_id=252,
        rpc_url="https://rpc.frax.com",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="frxETH"
    ),
    "gnosis": Chain(
        name="Gnosis", chain_id=100,
        rpc_url=f"https://gnosis-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="xDAI"
    ),
    "mantle": Chain(
        name="Mantle Mainnet", chain_id=5000,
        rpc_url=f"https://mantle-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="MNT"
    ),
    "memecore": Chain(
        name="Memecore Mainnet", chain_id=4352,
        rpc_url="https://rpc.memecore.net",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="M"
    ),
    "moonbeam": Chain(
        name="Moonbeam Mainnet", chain_id=1284,
        rpc_url=f"https://moonbeam-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="GLMR"
    ),
    "moonriver": Chain(
        name="Moonriver Mainnet", chain_id=1285,
        rpc_url="https://rpc.api.moonriver.moonbeam.network",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="MOVR"
    ),
    "opbnb": Chain(
        name="opBNB Mainnet", chain_id=204,
        rpc_url=f"https://opbnb-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="BNB"
    ),
    "taiko": Chain(
        name="Taiko Mainnet", chain_id=167000,
        rpc_url="https://rpc.mainnet.taiko.xyz",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "xdc": Chain(
        name="XDC Mainnet", chain_id=50,
        rpc_url="https://rpc.xinfin.network",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="XDC"
    ),
    "apechain": Chain(
        name="ApeChain Mainnet", chain_id=33139,
        rpc_url=f"https://apechain-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="APE"
    ),
    "worldchain": Chain(
        name="World Mainnet", chain_id=480,
        rpc_url=f"https://worldchain-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "sonic": Chain(
        name="Sonic Mainnet", chain_id=146,
        rpc_url=f"https://sonic-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="S"
    ),
    "unichain": Chain(
        name="Unichain Mainnet", chain_id=130,
        rpc_url=f"https://unichain-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "abstract": Chain(
        name="Abstract Mainnet", chain_id=2741,
        rpc_url=f"https://abstract-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "berachain": Chain(
        name="Berachain Mainnet", chain_id=80094,
        rpc_url=f"https://berachain-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="BERA"
    ),
    "monad": Chain(
        name="Monad Mainnet", chain_id=143,
        rpc_url=f"https://monad-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="MON"
    ),
    "hyperevm": Chain(
        name="HyperEVM Mainnet", chain_id=999,
        rpc_url=f"https://hyperliquid-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="HYPE"
    ),
    "katana": Chain(
        name="Katana Mainnet", chain_id=747474,
        rpc_url="https://rpc.katana.network",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    "sei": Chain(
        name="Sei Mainnet", chain_id=1329,
        rpc_url=f"https://sei-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="SEI"
    ),
    "stable": Chain(
        name="Stable Mainnet", chain_id=988,
        rpc_url="https://rpc.stable.xyz",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="USDT0"
    ),
    "plasma": Chain(
        name="Plasma Mainnet", chain_id=9745,
        rpc_url="https://rpc.plasma.to",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="XPL"
    ),
    "megaeth": Chain(
        name="MegaETH Mainnet", chain_id=4326,
        rpc_url="https://mainnet.megaeth.com/rpc",
        explorer_api="https://api.etherscan.io/v2/api", explorer_api_key=ETHERSCAN_KEY,
        native_symbol="ETH"
    ),
    # Robinhood Chain isn't on Etherscan V2's chainlist at all (confirmed
    # live: absent from https://api.etherscan.io/v2/chainlist) — its
    # official explorer is Blockscout, not Etherscan, at a dedicated
    # per-chain domain. Confirmed live: Blockscout's legacy `/api?module=
    # contract&action=getsourcecode` endpoint is wire-compatible with our
    # existing etherscan_request() (same status/result JSON shape, same
    # query params) and needs no API key at all — an empty
    # explorer_api_key still returns real verified source.
    "robinhood": Chain(
        name="Robinhood Chain Mainnet", chain_id=4663,
        rpc_url="https://rpc.mainnet.chain.robinhood.com",
        explorer_api="https://robinhoodchain.blockscout.com/api", explorer_api_key="",
        native_symbol="ETH"
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
