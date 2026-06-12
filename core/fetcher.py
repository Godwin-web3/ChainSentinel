import requests
from typing import Optional
from config.chains import Chain
from config.settings import HTTP_TIMEOUT
from utils.rpc import etherscan_request, get_bytecode
from utils.logger import log

def fetch_source(address: str, chain: Chain) -> Optional[dict]:
    log.debug(f"Fetching source for {address} on {chain.name}")
    result = etherscan_request({
        "module": "contract",
        "action": "getsourcecode",
        "address": address
    }, chain)

    if not result or not isinstance(result, list):
        return None

    data = result[0]
    source = data.get("SourceCode", "")
    abi = data.get("ABI", "")
    name = data.get("ContractName", "")
    compiler = data.get("CompilerVersion", "")
    proxy = data.get("Proxy", "0")
    impl = data.get("Implementation", "")

    if not source or source == "" or abi == "Contract source code not verified":
        log.warn(f"No verified source for {address}")
        return {
            "verified": False,
            "name": name,
            "source": None,
            "abi": None,
            "compiler": compiler,
            "is_proxy": proxy == "1",
            "implementation": impl if impl else None
        }

    log.success(f"Source fetched: {name} ({compiler})")
    return {
        "verified": True,
        "name": name,
        "source": source,
        "abi": abi,
        "compiler": compiler,
        "is_proxy": proxy == "1",
        "implementation": impl if impl else None
    }

def fetch_abi(address: str, chain: Chain) -> Optional[list]:
    log.debug(f"Fetching ABI for {address}")
    result = etherscan_request({
        "module": "contract",
        "action": "getabi",
        "address": address
    }, chain)

    if not result:
        return None

    try:
        import json
        return json.loads(result)
    except Exception:
        return None

def fetch_contract(address: str, chain: Chain) -> dict:
    log.section(f"Fetching {address}")

    bytecode = get_bytecode(address, chain)
    source_data = fetch_source(address, chain)

    return {
        "address": address,
        "chain": chain.name,
        "chain_id": chain.chain_id,
        "bytecode": bytecode,
        "has_bytecode": bytecode is not None,
        "source": source_data,
        "verified": source_data.get("verified", False) if source_data else False,
        "name": source_data.get("name", "Unknown") if source_data else "Unknown",
    }
