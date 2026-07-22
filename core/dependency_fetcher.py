"""
Auto-fetch missing cross-contract dependencies during analysis.

Scope, by design: only fetches contracts behind calls whose destination is
provably fixed at THIS deployed instance (DestinationOrigin.STATE_VARIABLE
or IMMUTABLE, read via the real on-chain getter). Never fetches for
PARAMETER or MSG_SENDER origins — those are runtime-arbitrary by protocol
design (e.g. Morpho's pluggable IRM/oracle/callback), and fabricating a
destination for them would be worse than reporting UNRESOLVABLE.

Slither only compiles what's reachable via `import` from the entry file.
Writing a dependency's source to disk does nothing on its own — nothing
imports it. merge_dependency_source therefore also identifies which of the
newly-written files is the dependency's real top-level contract (using the
same entry-scoring heuristic write_source_files already uses), and returns
it as MergeResult.entry_file, so a wrapper compilation unit can import it
explicitly.
"""
import os
from dataclasses import dataclass
from typing import Optional, List
from config.chains import Chain
from core.resolver import resolve
from utils.rpc import get_public_var_address, get_address_array
from utils.logger import log


@dataclass
class MergeResult:
    wrote: bool
    entry_file: Optional[str] = None  # absolute path to the dependency's top-level contract
    address: Optional[str] = None
    name: Optional[str] = None


def _score_entry(filepath: str, contract_name: str) -> int:
    """Same heuristic as write_source_files: prefer exact name match, avoid interfaces/libraries."""
    stem = os.path.splitext(os.path.basename(filepath))[0].lower()
    name = contract_name.lower()
    if stem == name and "interfaces" not in filepath and "libraries" not in filepath:
        return 0
    if name in stem and "interfaces" not in filepath and "libraries" not in filepath:
        return 1
    if stem == name:
        return 2
    if name in stem:
        return 3
    return 99


def merge_dependency_source(address: str, chain: Chain, project_root: str) -> MergeResult:
    """
    Resolves (address, chain) — following proxies via the existing resolve()
    path — and writes its verified source files into project_root alongside
    the existing entry contract. Returns a MergeResult describing whether
    anything new was written and, if so, which file is the dependency's
    real top-level contract (for wrapper-import purposes).
    """
    resolved = resolve(address, chain)
    verified = bool(resolved) and (
        resolved.get("verified", False)
        or (resolved.get("source") and resolved["source"].get("verified"))
    )
    if not verified:
        log.warn(f"Dependency at {address} not verified — cannot merge source")
        return MergeResult(wrote=False)

    source_data = resolved.get("source") or {}
    file_map = source_data.get("files", {})
    contract_name = resolved.get("name", "dependency")

    wrote_any = False
    written_files: List[str] = []

    if file_map:
        for filepath, content in file_map.items():
            full_path = os.path.join(project_root, filepath)
            if os.path.exists(full_path):
                # Same relative path already present (e.g. shared OZ import) — skip, don't clobber
                written_files.append(full_path)  # still a candidate entry file even if pre-existing
                continue
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w") as f:
                f.write(content)
            written_files.append(full_path)
            wrote_any = True
    else:
        single_source = source_data.get("source", "")
        if single_source:
            full_path = os.path.join(project_root, f"{contract_name}.sol")
            if not os.path.exists(full_path):
                with open(full_path, "w") as f:
                    f.write(single_source)
                wrote_any = True
            written_files.append(full_path)

    if not written_files:
        return MergeResult(wrote=False)

    # Pick the real top-level contract file among everything we have on disk
    # for this dependency (freshly written or already present).
    written_files.sort(key=lambda fp: _score_entry(fp, contract_name))
    entry_file = written_files[0]

    if wrote_any:
        log.success(f"Merged dependency source: {contract_name} @ {address}")
    else:
        log.debug(f"Dependency {contract_name} @ {address} already present on disk — reusing")

    # Even if nothing NEW was written (already on disk from an earlier run),
    # we still return the entry file so the wrapper can import it — the
    # earlier bug was never "files missing", it was "nothing imports them".
    return MergeResult(wrote=True, entry_file=entry_file, address=address, name=contract_name)


def fetch_dependency_by_var(
    contract_address: str, var_name: str, chain: Chain, project_root: str
) -> Optional[MergeResult]:
    """
    Given the deployed address of a contract and the name of a public
    state variable / immutable on it (e.g. "ADDRESSES_PROVIDER"), reads
    its real on-chain value and merges that dependency's source into
    project_root. Returns a MergeResult on success, None if the on-chain
    read failed or the dependency isn't verified.
    """
    dep_address = get_public_var_address(contract_address, var_name, chain)
    if not dep_address:
        log.warn(f"Could not read {var_name} on {contract_address}")
        return None

    result = merge_dependency_source(dep_address, chain, project_root)
    if not result.wrote:
        return None
    return result


def fetch_dependency_by_enumeration(
    contract_address: str, getter_signature: str, chain: Chain, project_root: str
) -> Optional[MergeResult]:
    """
    For dependencies declared on a sibling contract TYPE rather than a
    single fixed address (e.g. CToken's interestRateModel, reached while
    walking Comptroller — there's no one "the" CToken, there are many
    markets). Calls a real no-arg getter on the entry contract that
    returns an array of that type (e.g. getAllMarkets() -> CToken[]),
    takes the first real on-chain address as a representative instance,
    and merges its source the same way fetch_dependency_by_var does.

    One representative instance is enough: this resolves the *shape* of
    calls into that contract type (so the graph can classify sinks reached
    through it), not per-market runtime values — markets sharing the same
    interface almost always share the same underlying implementation.
    """
    addresses = get_address_array(contract_address, getter_signature, chain, limit=1)
    if not addresses:
        log.warn(f"Could not read any addresses from {getter_signature} on {contract_address}")
        return None

    result = merge_dependency_source(addresses[0], chain, project_root)
    if not result.wrote:
        return None
    return result


def build_wrapper_entry(project_root: str, real_entry_file: str, dependency_entry_files: List[str]) -> str:
    """
    Slither compiles only what's reachable via import from the entry file.
    This writes a throwaway .sol file that imports both the real entry
    point and every newly-resolved dependency's top-level contract, so a
    single Slither compile pass includes all of them. This is purely a
    compilation-unit trick — nothing downstream (resolve_call, the DFS)
    should ever need to know this file exists.
    """
    rel_entry = os.path.relpath(real_entry_file, project_root)
    imports = [f'import "{rel_entry}";']
    seen = {rel_entry}
    for dep_file in dependency_entry_files:
        rel_dep = os.path.relpath(dep_file, project_root)
        if rel_dep in seen:
            continue
        seen.add(rel_dep)
        imports.append(f'import "{rel_dep}";')

    wrapper_path = os.path.join(project_root, "_chainsentinel_wrapper.sol")
    with open(wrapper_path, "w") as f:
        f.write("// SPDX-License-Identifier: MIT\n")
        f.write("pragma solidity >=0.4.0;\n\n")
        f.write("\n".join(imports) + "\n")
    return wrapper_path
