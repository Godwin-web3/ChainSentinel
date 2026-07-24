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

    # Parse multi-file format — Etherscan wraps JSON in {{ }}
    parsed_source = source
    file_map = {}
    remappings = []
    if source.startswith("{{"):
        try:
            import json
            inner = source[1:-1]  # strip outer braces
            obj = json.loads(inner)
            sources = obj.get("sources", {})
            file_map = {path: data.get("content", "") for path, data in sources.items()}
            # Keep full source as concatenated string for pattern matching
            parsed_source = "\n".join(file_map.values())
            log.debug(f"Multi-file project: {len(file_map)} files parsed")
            # This is standard-json-input format (the shape `forge
            # verify-contract` submits) — it embeds the EXACT
            # remappings used at deploy-time compilation under
            # settings.remappings, e.g.
            # "@flaunch/=src/contracts/", "@optimism/=lib/optimism/
            # packages/contracts-bedrock/". Confirmed live against
            # Flaunch's real, currently-deployed PositionManager2
            # (Base): re-deriving remappings by walking the fetched
            # tree (the old/only approach) mapped `@optimism/interfaces/`
            # and `@optimism/src/` onto the wrong subdirectories and had
            # no rule at all for a bare `@flaunch/PositionManager.sol`
            # direct-file import, since no heuristic can invent
            # `@flaunch/=src/contracts/` — Slither exited 1 with silently
            # empty stdout/stderr (crytic-compile's real solc error
            # never surfaced past run_slither's "no output" catch-all),
            # skipping structural analysis entirely on a fully verified,
            # actively-used contract. These RHS paths are relative to
            # the project root exactly like the `sources` dict keys
            # written to disk by write_source_files, so no translation
            # is needed — join onto the real tmp project root and use
            # verbatim, ahead of any heuristic guessing.
            settings = obj.get("settings", {})
            raw_remaps = settings.get("remappings", [])
            if isinstance(raw_remaps, list):
                remappings = [r for r in raw_remaps if isinstance(r, str) and "=" in r]
        except Exception as e:
            log.debug(f"Multi-file parse failed: {e}")
    elif source.startswith("{"):
        try:
            import json
            obj = json.loads(source)
            # Etherscan has two shapes for single-brace JSON:
            # (a) {"language":..., "sources": {"File.sol": {"content":...}}}
            # (b) {"File.sol": {"content":...}, "Other.sol": {"content":...}}
            #     — a flat file map with NO "sources" wrapper, seen on
            #     older verified contracts (e.g. Compound-era, pre-2020
            #     compiler tooling). Detect which shape this is instead
            #     of assuming (a) and silently getting an empty map.
            if "sources" in obj and isinstance(obj.get("sources"), dict):
                sources = obj["sources"]
            else:
                sources = obj
            file_map = {
                path: data.get("content", "")
                for path, data in sources.items()
                if isinstance(data, dict) and "content" in data
            }
            parsed_source = "\n".join(file_map.values())
            log.debug(f"Multi-file project: {len(file_map)} files parsed")
        except Exception as e:
            log.debug(f"Single JSON parse failed: {e}")

    # Flat, non-JSON single-file source (older verified contracts, e.g.
    # pre-2020 compiler tooling) never enters either JSON branch above,
    # so file_map stays empty even though parsed_source has real content.
    # Fall back to a single synthetic file rather than silently writing
    # nothing to disk.
    if not file_map and parsed_source:
        synthetic_name = f"{name or 'Contract'}.sol"
        file_map = {synthetic_name: parsed_source}
        log.debug(f"Flat single-file source — wrote as synthetic file {synthetic_name}")

    log.success(f"Source fetched: {name} ({compiler})")
    return {
        "verified": True,
        "name": name,
        "source": parsed_source,
        "files": file_map,
        "abi": abi,
        "compiler": compiler,
        "is_proxy": proxy == "1",
        "implementation": impl if impl else None,
        "remappings": remappings
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
