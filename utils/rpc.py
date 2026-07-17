import requests
import time
from web3 import Web3
from typing import Optional
from config.chains import Chain
from config.settings import HTTP_TIMEOUT, RPC_TIMEOUT
from utils.logger import log

def get_web3(chain: Chain) -> Web3:
    w3 = Web3(Web3.HTTPProvider(chain.rpc_url, request_kwargs={"timeout": RPC_TIMEOUT}))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to RPC: {chain.rpc_url}")
    return w3

def get_bytecode(address: str, chain: Chain) -> Optional[str]:
    try:
        w3 = get_web3(chain)
        code = w3.eth.get_code(Web3.to_checksum_address(address))
        result = code.hex()
        if result == "0x" or len(result) < 4:
            log.warn(f"No bytecode at {address} on {chain.name}")
            return None
        log.debug(f"Bytecode length: {len(result)} chars")
        return result
    except Exception as e:
        log.error(f"Bytecode fetch failed: {e}")
        return None

def get_storage_at(address: str, slot: str, chain: Chain, retries: int = 3) -> Optional[str]:
    for attempt in range(retries):
        try:
            w3 = get_web3(chain)
            value = w3.eth.get_storage_at(
            Web3.to_checksum_address(address),
            int(slot, 16)
        )
            return value.hex()
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
                continue
            log.error(f"Storage fetch failed: {e}")
            return None

def etherscan_request(params: dict, chain: Chain) -> Optional[dict]:
    try:
        params["apikey"] = chain.explorer_api_key
        params["chainid"] = chain.chain_id
        response = requests.get(
            chain.explorer_api,
            params=params,
            timeout=HTTP_TIMEOUT
        )
        data = response.json()
        if data.get("status") == "1":
            return data.get("result")
        log.warn(f"Etherscan error: {data.get('message')}")
        return None
    except Exception as e:
        log.error(f"Etherscan request failed: {e}")
        return None

def get_public_var_address(target_address: str, var_name: str, chain: Chain) -> Optional[str]:
    """
    Calls the auto-generated getter for a public state variable or immutable
    (e.g. ADDRESSES_PROVIDER()) on a deployed contract, and decodes the
    returned value as an address. Used to resolve cross-contract call
    destinations that are provably fixed at a specific deployed instance,
    not runtime-arbitrary (msg.sender, function parameters).
    """
    try:
        w3 = get_web3(chain)
        selector = w3.keccak(text=f"{var_name}()")[:4]
        result = w3.eth.call({
            "to": Web3.to_checksum_address(target_address),
            "data": selector,
        })
        if not result or len(result) < 32:
            return None
        addr = "0x" + result[-20:].hex()
        if addr == "0x" + "0" * 40:
            return None
        return Web3.to_checksum_address(addr)
    except Exception as e:
        log.error(f"get_public_var_address failed for {var_name} at {target_address}: {e}")
        return None


def get_address_array(target_address: str, function_signature: str, chain: Chain, limit: int = 5) -> Optional[list]:
    """
    Calls a no-argument view function that returns address[] (e.g.
    "getAllMarkets()") and decodes the ABI-encoded dynamic array.
    Returns up to `limit` addresses, or None on failure.
    """
    try:
        w3 = get_web3(chain)
        selector = w3.keccak(text=function_signature)[:4]
        result = w3.eth.call({
            "to": Web3.to_checksum_address(target_address),
            "data": selector,
        })
        if not result or len(result) < 64:
            return None
        length = int.from_bytes(result[32:64], "big")
        if length == 0:
            return None
        addresses = []
        for i in range(min(length, limit)):
            start = 64 + i * 32
            end = start + 32
            if end > len(result):
                break
            addr = "0x" + result[end - 20:end].hex()
            if addr != "0x" + "0" * 40:
                addresses.append(Web3.to_checksum_address(addr))
        return addresses or None
    except Exception as e:
        log.error(f"get_address_array failed for {function_signature} at {target_address}: {e}")
        return None
