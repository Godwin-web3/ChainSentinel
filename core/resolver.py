from web3 import Web3
from typing import Optional
from config.chains import Chain
from config.settings import PROXY_SLOTS, MAX_PROXY_DEPTH
from core.fetcher import fetch_contract
from utils.rpc import get_storage_at
from utils.logger import log

def extract_address_from_slot(slot_value: str) -> Optional[str]:
    try:
        if not slot_value or slot_value == "0x" + "0" * 64:
            return None
        addr = "0x" + slot_value[-40:]
        if addr == "0x" + "0" * 40:
            return None
        return Web3.to_checksum_address(addr)
    except Exception:
        return None

def detect_proxy(address: str, chain: Chain) -> Optional[str]:
    log.debug(f"Checking proxy slots for {address}")
    for proxy_type, slot in PROXY_SLOTS.items():
        value = get_storage_at(address, slot, chain)
        if value:
            impl = extract_address_from_slot(value)
            if impl:
                log.success(f"Proxy detected ({proxy_type}) → {impl}")
                return impl
    return None

def resolve(address: str, chain: Chain, depth: int = 0) -> dict:
    if depth > MAX_PROXY_DEPTH:
        log.warn(f"Max proxy depth reached at {address}")
        return None

    log.section(f"Resolving {address} on {chain.name}")

    contract = fetch_contract(address, chain)

    # Storage slot check first (most reliable)
    impl_address = detect_proxy(address, chain)

    # Etherscan fallback ONLY if storage check found nothing AND depth is 0
    if not impl_address and depth == 0 and contract["source"]:
        etherscan_impl = contract["source"].get("implementation")
        if etherscan_impl:
            log.success(f"Etherscan proxy impl → {etherscan_impl}")
            impl_address = etherscan_impl

    if impl_address:
        log.info(f"Resolving implementation at depth {depth + 1}")
        impl = resolve(impl_address, chain, depth + 1)
        return {
            "address": impl_address,
            "proxy_address": address,
            "chain": chain.name,
            "chain_id": chain.chain_id,
            "type": "proxy",
            "bytecode": impl["bytecode"] if impl else contract["bytecode"],
            "name": impl["name"] if impl else contract["name"],
            "verified": impl["verified"] if impl else contract["verified"],
            "source": impl["source"] if impl else contract["source"],
            "implementation": {
                "address": impl_address,
                "data": impl
            },
            "proxy_depth": depth + 1
        }

    contract_type = "verified" if contract["verified"] else "bytecode-only"

    return {
        "address": address,
        "chain": chain.name,
        "chain_id": chain.chain_id,
        "type": contract_type,
        "bytecode": contract["bytecode"],
        "name": contract["name"],
        "verified": contract["verified"],
        "source": contract["source"],
        "implementation": None,
        "proxy_depth": depth
    }
