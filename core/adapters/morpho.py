"""
core/adapters/morpho.py — Morpho Blue market adapter

Reads CreateMarket events through Etherscan's log API. Decodes
MarketParams into the protocol-agnostic MarketConfig shape. This is
the only file that knows Morpho's own event schema — oracle
classification itself lives in core/oracle_detection.py since it was
never actually Morpho-specific.
"""

import requests
from eth_abi.abi import decode as abi_decode
from web3 import Web3
from core.market_schema import MarketConfig
from core.oracle_detection import detect_oracle_type
from utils.rpc import get_web3
from config.chains import Chain
from config.chains import ETHERSCAN_KEY as ETHERSCAN_API_KEY

MORPHO_ADDRESS = "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb"


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
                oracle_type=detect_oracle_type(oracle, w3),
                liquidation_threshold=lltv / 1e18,
                irm_address=irm,
            ))
        except Exception:
            continue

    return markets
