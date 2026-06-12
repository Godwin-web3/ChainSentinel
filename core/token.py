from web3 import Web3
from utils.rpc import get_web3
from config.chains import Chain
from utils.logger import log

ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
]

def fetch_token_data(address: str, chain: Chain) -> dict:
    try:
        w3 = get_web3(chain)
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(address),
            abi=ERC20_ABI
        )

        name = symbol = decimals = supply = None

        try: name = contract.functions.name().call()
        except: pass

        try: symbol = contract.functions.symbol().call()
        except: pass

        try: decimals = contract.functions.decimals().call()
        except: pass

        try:
            raw_supply = contract.functions.totalSupply().call()
            if decimals is not None:
                supply = raw_supply / (10 ** decimals)
            else:
                supply = raw_supply
        except: pass

        log.success(f"Token data: {symbol} | decimals={decimals}")

        return {
            "symbol": symbol,
            "decimals": decimals,
            "total_supply": supply,
            "standard": "ERC20"
        }

    except Exception as e:
        log.error(f"Token fetch failed: {e}")
        return {}
