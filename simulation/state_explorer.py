from web3 import Web3
from typing import Optional
from simulation.fork_manager import ForkManager
from config.chains import Chain
from utils.logger import log

ERC20_ABI = [
    {"inputs": [{"name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "type": "function", "stateMutability": "view"},
    {"inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function", "stateMutability": "view"},
    {"inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function", "stateMutability": "view"},
    {"inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}], "name": "allowance", "outputs": [{"name": "", "type": "uint256"}], "type": "function", "stateMutability": "view"},
]

UNISWAP_V2_PAIR_ABI = [
    {"inputs": [], "name": "getReserves", "outputs": [{"name": "_reserve0", "type": "uint112"}, {"name": "_reserve1", "type": "uint112"}, {"name": "_blockTimestampLast", "type": "uint32"}], "type": "function", "stateMutability": "view"},
    {"inputs": [], "name": "token0", "outputs": [{"name": "", "type": "address"}], "type": "function", "stateMutability": "view"},
    {"inputs": [], "name": "token1", "outputs": [{"name": "", "type": "address"}], "type": "function", "stateMutability": "view"},
    {"inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function", "stateMutability": "view"},
    {"inputs": [], "name": "price0CumulativeLast", "outputs": [{"name": "", "type": "uint256"}], "type": "function", "stateMutability": "view"},
]

def explore_token(address: str, fork: ForkManager) -> dict:
    log.info(f"Exploring token state: {address}")
    w3 = fork.w3
    if not w3:
        return {}

    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(address),
            abi=ERC20_ABI
        )
        decimals = contract.functions.decimals().call()
        total_supply = contract.functions.totalSupply().call()

        return {
            "type": "token",
            "address": address,
            "total_supply_raw": total_supply,
            "total_supply": total_supply / (10 ** decimals),
            "decimals": decimals,
        }
    except Exception as e:
        log.error(f"Token exploration failed: {e}")
        return {}

def explore_dex_pair(address: str, fork: ForkManager) -> dict:
    log.info(f"Exploring DEX pair state: {address}")
    w3 = fork.w3
    if not w3:
        return {}

    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(address),
            abi=UNISWAP_V2_PAIR_ABI
        )

        reserves = contract.functions.getReserves().call()
        token0 = contract.functions.token0().call()
        token1 = contract.functions.token1().call()
        total_supply = contract.functions.totalSupply().call()

        reserve0, reserve1, ts = reserves

        log.success(f"Reserves: {reserve0} / {reserve1}")

        return {
            "type": "dex_pair",
            "address": address,
            "token0": token0,
            "token1": token1,
            "reserve0": reserve0,
            "reserve1": reserve1,
            "total_supply": total_supply,
            "price_ratio": reserve1 / reserve0 if reserve0 > 0 else 0,
        }
    except Exception as e:
        log.error(f"DEX pair exploration failed: {e}")
        return {}

def explore(address: str, category: str, fork: ForkManager) -> dict:
    if category == "token":
        return explore_token(address, fork)
    elif category == "dex":
        return explore_dex_pair(address, fork)
    else:
        log.warn(f"No explorer for category: {category}")
        return {"type": category, "address": address}
