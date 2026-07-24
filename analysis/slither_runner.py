import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from config.settings import SLITHER_TIMEOUT
from utils.logger import log
from analysis.enricher import run_enricher

SEVERITY_MAP = {
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
    "Optimization": 0
}

def write_source_files(source_data: dict) -> Optional[tuple]:
    """
    Write source files to temp dir.
    Returns (root_dir, entry_file) or None.
    """
    try:
        tmpdir = tempfile.mkdtemp(prefix="chainsentinel-")

        # Use pre-parsed file_map from fetcher if available
        file_map = source_data.get("files", {})
        if file_map:
            entry_file = None
            contract_name = source_data.get("name", "contract")
            all_files = []
            for filepath, content in file_map.items():
                full_path = os.path.join(tmpdir, filepath)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w") as f:
                    f.write(content)
                all_files.append((filepath, full_path))
            # Pick entry: exact stem match first, then partial, skip interfaces/libraries
            def score_entry(fp):
                stem = os.path.splitext(os.path.basename(fp))[0].lower()
                name = contract_name.lower()
                if stem == name: return 0
                if stem == name and "interfaces" not in fp and "libraries" not in fp: return 1
                if name in stem and "interfaces" not in fp and "libraries" not in fp: return 2
                if name in stem: return 3
                return 99
            all_files.sort(key=lambda x: score_entry(x[0]))
            entry_file = all_files[0][1] if all_files else None
            log.debug(f"Entry file: {all_files[0][0] if all_files else None}")
            return (tmpdir, entry_file, len(all_files))

        # Single file fallback
        source = source_data.get("source", "")
        if not source:
            return None
        filepath = os.path.join(tmpdir, "contract.sol")
        with open(filepath, "w") as f:
            f.write(source)
        return (tmpdir, filepath)

    except Exception as e:
        log.error(f"Source write failed: {e}")
        return None

def parse_slither_output(output: dict) -> list:
    findings = []

    detectors = output.get("results", {}).get("detectors", [])

    for d in detectors:
        check = d.get("check", "unknown")
        impact = d.get("impact", "Informational")
        confidence = d.get("confidence", "Low")
        description = d.get("description", "").strip()

        # Extract affected elements
        elements = d.get("elements", [])
        affected = []
        for el in elements:
            name = el.get("name", "")
            el_type = el.get("type", "")
            if name:
                affected.append(f"{el_type}:{name}" if el_type else name)

        findings.append({
            "check": check,
            "impact": impact,
            "severity_score": SEVERITY_MAP.get(impact, 0),
            "confidence": confidence,
            "description": description[:300],
            "affected": affected[:5],
            "elements": elements
        })

    # Sort by severity
    findings.sort(key=lambda x: x["severity_score"], reverse=True)
    return findings

def _ensure_solc_installed(version: str) -> None:
    """
    Install this solc version via solc-select if it isn't already
    present, so solc-wrapper's `exec "$HOME/.solc-select/artifacts/
    solc-$VERSION/solc-$VERSION"` (see solc-wrapper) has a real binary
    to run. Without this, any contract pinned to a version this
    environment doesn't happen to have preinstalled fails outright —
    found live this session: real Berachain BEX Vault.sol (solc 0.7.1,
    a real, actively-used protocol) produced "Version '0.7.1' not
    installed" and zero analysis, purely because this specific patch
    version had never been installed here before, regardless of how
    common or well-formed the contract itself is. solc-select installs
    a missing version in a few seconds (confirmed live), so this is
    cheap insurance against ANY chain/protocol using a compiler patch
    version this environment hasn't seen yet.
    """
    try:
        installed = subprocess.run(
            ["solc-select", "versions"], capture_output=True, text=True, timeout=15
        )
        if version in (installed.stdout or ""):
            return
        log.info(f"solc {version} not installed — installing via solc-select")
        subprocess.run(
            ["solc-select", "install", version], capture_output=True, text=True, timeout=120
        )
    except Exception as e:
        log.warn(f"solc-select install {version} failed: {e}")


def run_slither(resolved: dict) -> dict:
    source_data = resolved.get("source")

    if not source_data or not source_data.get("verified"):
        log.warn("No verified source - skipping Slither")
        return {
            "success": False,
            "reason": "no_source",
            "findings": []
        }

    compiler = source_data.get("compiler", "")
    solc_version = ""
    if compiler:
        # Extract version like 0.8.19 from v0.8.19+commit.xxx
        parts = compiler.lstrip("v").split("+")[0]
        solc_version = parts

    log.info(f"Running Slither (solc: {solc_version})")

    result_tuple = write_source_files(source_data)
    if not result_tuple:
        return {
            "success": False,
            "reason": "source_write_failed",
            "findings": []
        }

    project_root, filepath, *_extra = result_tuple
    is_multifile = _extra[0] > 1 if _extra else False

    # Use relative path so Slither doesn't walk up and find foundry.toml
    import os as _os
    try:
        filepath = _os.path.relpath(filepath, project_root)
    except ValueError:
        pass  # Windows edge case — keep absolute

    # Guard against crytic-compile's upward-walking Foundry detection.
    # Even with a relative path, crytic-compile resolves it back to absolute
    # (using the cwd) and then walks every ancestor for foundry.toml. When
    # project_root has no foundry.toml of its own, the walk escapes past it
    # and finds the repo-root foundry.toml (pinned to 0.8.27), causing a
    # version mismatch against the contract's pragma. --foundry-ignore disables
    # the Foundry platform entirely and falls back to plain solc.
    _has_local_foundry = _os.path.isfile(_os.path.join(project_root, "foundry.toml"))

    # Build remappings, but ONLY for directories a real BARE (non-
    # relative) import somewhere in the project actually references —
    # not, as before, blindly for every directory in the tree.
    #
    # solc resolves a plain relative import (./, ../) purely by joining
    # it onto the IMPORTING file's own path — no remapping is supposed
    # to be involved. But once a remapping's LHS prefix happens to
    # match that JOINED/normalized path too, solc's resolver applies it
    # anyway, giving the file a SECOND, remapped-absolute identity
    # distinct from the first, relative one it already has as the
    # compile target or another relative import's target — and then
    # declares every contract in it twice ("Identifier already
    # declared"). Found live and reproduced down to a single-remap
    # solc-only repro: a real Solidly-fork Pair.sol (Velodrome on
    # Optimism, Lynex on Linea — same upstream code) entry file imports
    # `./factories/PairFactory.sol`, which imports `../Pair.sol` right
    # back — a real, safe, ordinary circular relative import solc
    # handles fine with ZERO remappings (confirmed live) — but adding
    # `contracts/factories/=<project_root>/contracts/factories/` (which
    # the old blanket "remap every directory" loop always generated)
    # collides with the FIRST import's own resolved path and triggers
    # exactly this crash, silently failing analysis for every such
    # protocol regardless of chain. Checked live: this real project's
    # imports are 100% relative — not one bare import anywhere — so the
    # old logic was generating remappings for it that were not just
    # unneeded but actively fatal.
    #
    # Remapping direct/bare imports (package-style
    # `@openzeppelin/contracts/...`, or a flattened multi-file fetch
    # using absolute-style `contracts/Foo.sol`) is still exactly as
    # important as before — those genuinely can't resolve without it —
    # so this keeps full coverage for THAT real need while eliminating
    # the case that can never legitimately require a remap: a directory
    # nothing in the project ever references via a bare import.
    import re as _re
    _IMPORT_RE = _re.compile(r'import\s+(?:[^"\';]*?\bfrom\s+)?["\']([^"\']+)["\']')
    bare_import_paths = set()
    for root, _dirs, files in os.walk(project_root):
        for fname in files:
            if not fname.endswith(".sol"):
                continue
            try:
                with open(os.path.join(root, fname), "r", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            for m in _IMPORT_RE.finditer(content):
                path = m.group(1)
                if path.startswith("./") or path.startswith("../"):
                    continue
                bare_import_paths.add(path)

    def _needed_by_bare_import(rel: str) -> bool:
        prefix = rel + "/"
        return any(p == rel or p.startswith(prefix) for p in bare_import_paths)

    # Package-alias fallback: a bare import's first segment (e.g.
    # `@openzeppelin`) frequently doesn't literally match ANY directory
    # name on disk, even though the real package IS present — a
    # Foundry-verified contract's multi-file bundle commonly preserves
    # the PHYSICAL vendored layout (e.g. `lib/openzeppelin-contracts/`)
    # rather than the import-alias path, relying on a separate
    # remappings.txt (not part of the bundle) to bridge them. Found
    # live: real Velodrome's Pool.sol imports
    # `@openzeppelin/contracts/token/ERC20/ERC20.sol` but the fetched
    # tree only has `lib/openzeppelin-contracts/contracts/...` — no
    # directory anywhere is literally named `@openzeppelin`, so the
    # exact-match logic above (correctly) finds nothing to remap, and
    # the import fails outright. Matches by checking whether a known
    # package directory's normalized name (strip non-alphanumerics,
    # lowercase) contains the import segment's own normalized form —
    # `openzeppelin` (from `@openzeppelin`) is a substring of
    # `openzeppelincontracts` (from `openzeppelin-contracts`).
    def _normalize(s: str) -> str:
        return _re.sub(r'[^a-z0-9]', '', s.lower())

    # Well-known historical package renames — the SAME real library
    # published under a different npm package name at different points
    # in time, so its normalized old name shares no substring with its
    # normalized new one. `openzeppelin-solidity` was OpenZeppelin's own
    # npm package name through v2.x (pre-2019), before the
    # `@openzeppelin/contracts` rename — real, still-live pre-Foundry
    # Solidity 0.4.x/0.5.x contracts (found live this session against
    # Mento Protocol's real Broker implementation on Celo, solc 0.5.17)
    # still import it by that name. "openzeppelinsolidity" is not a
    # substring of "openzeppelincontracts" (different second word), so
    # the plain substring match below can't bridge them — even when the
    # exact same vendored OZ tree is already sitting in the project,
    # fetched for a sibling dependency's own needs.
    _KNOWN_PACKAGE_SYNONYMS = {
        "openzeppelinsolidity": "openzeppelincontracts",
    }

    # Filler-word-stripped match — a second, independent alias check
    # alongside the plain character-substring one above. The character
    # check only catches a geometry where one FULL normalized name is a
    # contiguous run inside the other (`openzeppelin` inside
    # `openzeppelincontracts`). It can't bridge a real gap found live
    # this session against INIT Capital's real InitCore.sol (Blast):
    # imports `@openzeppelin-contracts-upgradeable/...`, but the
    # project's own Hardhat dependency cache vendors it at
    # `contracts/.cache/OpenZeppelin-Upgradeable/v4.9.3/...` — the
    # import's normalized form is "openzeppelincontractsupgradeable",
    # the directory's is "openzeppelinupgradeable"; neither is a
    # substring of the other, because "contracts" sits INSERTED between
    # "openzeppelin" and "upgradeable" in the import name, breaking
    # contiguity in both directions. Stripping the single, ubiquitous
    # filler word "contracts" (present in nearly every OZ-family
    # package/directory name and never itself distinguishing) from both
    # sides before comparing bridges exactly this.
    #
    # A naive "is either core string a substring of the other" check on
    # its own is unsafe two ways, both hit live against this exact
    # project: (1) it would match the top-level `contracts/` directory
    # itself, whose ENTIRE name is the filler word — stripped, its core
    # is empty, a substring of everything; guarded by a minimum core
    # length. (2) when the project vendors BOTH `OpenZeppelin/` and
    # `OpenZeppelin-Upgradeable/`, `@openzeppelin-contracts-upgradeable`
    # substring-matches EITHER one (its stripped core, "openzeppelin
    # upgradeable", contains plain "openzeppelin" too) — first-found-
    # wins (os.walk order) could silently pick the WRONG tree, which is
    # worse than no match at all (wrong files compiled, not just none).
    # Guarded by scoring every candidate directory by how close its own
    # core length is to the import segment's core length — an exact or
    # near-exact match (OpenZeppelin-Upgradeable, diff 0) always beats a
    # partial one (plain OpenZeppelin, diff 11) — and keeping only the
    # best-scoring directory per segment across the WHOLE tree, not the
    # first one encountered.
    _FILLER_WORDS = {"contracts", "contract"}
    _MIN_CORE_LEN = 4

    def _word_tokens(s: str) -> list:
        return [w for w in _re.split(r'[^a-z0-9]+', s.lower()) if w]

    def _core(s: str) -> str:
        return "".join(w for w in _word_tokens(s) if w not in _FILLER_WORDS)

    # For each bare import, match candidates are normally just the
    # first path segment — but for an npm-SCOPED package (a first
    # segment starting with "@", e.g. "@rari-capital"), ALSO consider
    # the second segment as an independent match candidate, keyed by
    # the FULL "scope/package" prefix. Found live this session against
    # real GoGoPool/Hypha's TokenggAVAX.sol (Avalanche): imports
    # `@rari-capital/solmate/src/mixins/ERC4626.sol`, but the fetched
    # tree only vendors it as `lib/solmate/` — no directory anywhere is
    # named "rari-capital" (Solmate's ORIGINAL npm scope, before the
    # package moved to the unscoped transmissions11/solmate), so
    # matching on the first segment alone can never succeed; "solmate"
    # (the second segment, the actual package name) does.
    # For a scoped import (`@openzeppelin/contracts/...`), the SECOND
    # segment alone ("contracts") is a catastrophically ambiguous
    # alias-match token on its own: "contracts" is the near-universal
    # top-level subdirectory name of virtually every vendored Solidity
    # package, so matching on it alone can silently pick a COMPLETELY
    # WRONG sibling package rather than failing to match at all — worse
    # than no match. Found live this session against Usual Protocol's
    # real, currently-deployed Eur0.sol: the project vendors BOTH
    # `lib/openzeppelin-contracts/` and
    # `lib/openzeppelin-contracts-upgradeable/`, each with its own
    # `contracts/` subfolder. Matching `@openzeppelin/contracts` on the
    # bare token "contracts" tied between both packages' `contracts/`
    # subfolders (both normalize to the same "contracts", diff 0) and
    # first-found-wins picked the UPGRADEABLE tree — so
    # `@openzeppelin/contracts/token/ERC20/IERC20.sol` (a NON-upgradeable
    # interface, genuinely absent from the upgradeable package) resolved
    # into the wrong tree and failed to compile, silently killing
    # structural analysis for the whole contract (Slither exits 1 with
    # no output, `success: False` with no error surfaced) even though
    # the real source is fully verified and compiles cleanly on its own.
    #
    # Fixed with a two-tier match: try the COMBINED scope+package token
    # first (`openzeppelin`+`contracts` -> "openzeppelincontracts",
    # which exact-matches ONLY the `openzeppelin-contracts` package
    # root, not its generic `contracts/` subfolder or any sibling
    # `-upgradeable` package). Only if NO directory in the whole tree
    # matches the combined token do we fall back to the package-name-
    # alone token — preserving the original real need this alias step
    # was built for (real GoGoPool/Hypha's TokenggAVAX.sol imports
    # `@rari-capital/solmate/...`, but no directory anywhere is named
    # "rari-capital", only "solmate" bare — the combined token
    # "raricapitalsolmate" matches nothing, so the fallback tier is
    # exactly what resolves that real case, unchanged from before).
    alias_simple: dict = {}           # lhs (single segment) -> itself, always full-matched, unchanged from before
    alias_combined: dict = {}         # lhs (two segments) -> combined scope+package token, tried first, strict-only
    alias_fallback: dict = {}         # same lhs as alias_combined -> package-name-alone token, tried only if the combined tier finds nothing
    for p in bare_import_paths:
        parts = p.split("/")
        alias_simple[parts[0]] = parts[0]
        if parts[0].startswith("@") and len(parts) > 1:
            combined_lhs = f"{parts[0]}/{parts[1]}"
            alias_combined[combined_lhs] = parts[0][1:] + parts[1]
            alias_fallback[combined_lhs] = parts[1]

    def _alias_match_pass(candidates_map: dict, strict: bool) -> None:
        # strict=True (the combined scope+package tier): ONLY the plain,
        # directional substring check (does the directory name contain
        # the WHOLE combined token) — skips the filler-stripped
        # bidirectional core-match fallback below. That fallback's
        # `core_d in core_seg` direction is exactly what let a short,
        # generic real subdirectory name (e.g. "token", "security" —
        # themselves genuine nested paths inside a vendored package,
        # not a package identity) spuriously substring-match INTO a
        # long synthetic combined token, causing this tier to claim a
        # match it shouldn't and pre-empt the (correct) fallback tier.
        # A real combined token is always long enough (concatenated
        # scope+package name) that the plain directional check alone is
        # sufficient — no directory can accidentally contain a ~20-char
        # combined identity as a substring by coincidence.
        for root, dirs, files in os.walk(project_root):
            for d in dirs:
                full = os.path.join(root, d)
                norm_d = _normalize(d)
                if not norm_d:
                    continue
                core_d = _core(d)
                for lhs, seg in candidates_map.items():
                    norm_seg = _normalize(seg)
                    if not norm_seg:
                        continue
                    candidates = {norm_seg}
                    if norm_seg in _KNOWN_PACKAGE_SYNONYMS:
                        candidates.add(_KNOWN_PACKAGE_SYNONYMS[norm_seg])
                    matched = any(c in norm_d for c in candidates)
                    diff = abs(len(norm_seg) - len(norm_d))
                    if not matched and not strict:
                        core_seg = _core(seg)
                        if (
                            len(core_seg) >= _MIN_CORE_LEN and len(core_d) >= _MIN_CORE_LEN
                            and (core_seg in core_d or core_d in core_seg)
                        ):
                            matched = True
                            diff = abs(len(core_seg) - len(core_d))
                    if matched and diff < alias_best_diff.get(lhs, float("inf")):
                        alias_targets[lhs] = full
                        alias_best_diff[lhs] = diff

    alias_targets: dict = {}
    alias_best_diff: dict = {}

    # A name-matched alias target may not be the real package ROOT —
    # some vendoring tools nest the fetched package one level deeper
    # inside a version folder. Found live this session against INIT
    # Capital's real InitCore.sol (Blast): Hardhat's dependency-compiler
    # cache lays out `contracts/.cache/OpenZeppelin/v4.9.3/token/ERC20/
    # IERC20.sol`, not `contracts/.cache/OpenZeppelin/token/ERC20/
    # IERC20.sol` — the name match correctly finds `.../OpenZeppelin/`,
    # but the import's own remainder path (`token/ERC20/IERC20.sol`)
    # doesn't exist directly under it, only one level further in.
    # Validate each matched target against a REAL bare import under
    # that exact segment (join the import's own remainder onto the
    # candidate and check the file actually exists); if it doesn't,
    # descend one level into each of the candidate's own subdirectories
    # and keep whichever one actually resolves a real file.
    def _deepen_aliases() -> None:
        for seg in list(alias_targets.keys()):
            candidate = alias_targets[seg]
            seg_prefix = seg + "/"
            remainders = [p[len(seg_prefix):] for p in bare_import_paths if p.startswith(seg_prefix)]
            if not remainders:
                continue

            def _validates(root: str) -> bool:
                return any(os.path.isfile(os.path.join(root, r)) for r in remainders)

            if _validates(candidate):
                continue
            try:
                for entry in sorted(os.listdir(candidate)):
                    sub = os.path.join(candidate, entry)
                    if os.path.isdir(sub) and _validates(sub):
                        alias_targets[seg] = sub
                        break
            except Exception:
                pass

    _alias_match_pass(alias_simple, strict=False)

    # Deepen the SIMPLE (1-segment, e.g. `@openzeppelin`) aliases
    # BEFORE Tier 0 below joins a second segment onto them — Tier 0's
    # own os.path.isdir() check needs the real, final package root
    # (e.g. `.../openzeppelin-contracts/contracts`, not the one-level-
    # too-shallow `.../openzeppelin-contracts`) to correctly find a
    # subdirectory like `utils`. Found live this session against
    # Robinhood Chain's real, currently-deployed Doppler Airlock.sol:
    # `@openzeppelin/utils/math/Math.sol` bare-imports through the
    # SAME `@openzeppelin` scope as `@openzeppelin/access/Ownable.sol`
    # (already correctly resolved to `openzeppelin-contracts/contracts`
    # elsewhere), but Tier 0 ran against the un-deepened, one-level-too-
    # shallow scope directory, found no `utils` subdirectory there, and
    # silently fell through to the fallback tier — which then matched
    # the bare basename "utils" against a COMPLETELY UNRELATED
    # vendored package's own `utils/` folder (solmate's), overriding
    # the correct base `@openzeppelin/` remap with a wrong, more-
    # specific one that solc's longest-prefix-wins resolution prefers.
    _deepen_aliases()

    # Tier 0 (tried before the combined-token / fallback tiers below):
    # if the bare SCOPE (parts[0], e.g. `@openzeppelin`) already resolved
    # to a real directory above, and that directory literally CONTAINS a
    # subdirectory named exactly `parts[1]` (e.g. `contracts`), that's an
    # unambiguous, direct answer — no fuzzy matching needed at all. This
    # is the common shape for BOTH an npm/node_modules-style scoped
    # package (`node_modules/@openzeppelin/contracts/`, a genuine nested
    # scope-dir/package-dir pair) and a Foundry-vendored flat package
    # (`lib/openzeppelin-contracts/contracts/`, where the scope alone
    # already fuzzy-resolved to the package root one level up).
    #
    # Found live this session against HLP0's real, currently-deployed
    # HLP0.sol (Arbitrum): the project vendors BOTH `@openzeppelin/...`
    # AND `@layerzerolabs/oapp-evm/...` under `node_modules/`, and
    # `@layerzerolabs/oapp-evm/` happens to ALSO have its own `contracts/`
    # subfolder. The fallback tier (package-name-alone, "contracts")
    # can't tell these apart — "contracts" substring-matches EITHER
    # package's subfolder — and picked the wrong one, sending
    # `@openzeppelin/contracts/...` imports into LayerZero's tree
    # instead. Resolving through the already-validated scope directory
    # first sidesteps the ambiguity entirely: only ONE directory named
    # `@openzeppelin` exists, and only its OWN `contracts/` subdirectory
    # can ever be the join target.
    for combined_lhs, package_seg in list(alias_fallback.items()):
        scope = combined_lhs.rsplit("/", 1)[0]
        scope_dir = alias_targets.get(scope)
        if not scope_dir:
            continue
        candidate = os.path.join(scope_dir, package_seg)
        if os.path.isdir(candidate):
            alias_targets[combined_lhs] = candidate
            alias_best_diff[combined_lhs] = 0

    remaining_combined = {k: v for k, v in alias_combined.items() if k not in alias_targets}
    if remaining_combined:
        _alias_match_pass(remaining_combined, strict=True)
    unmatched = set(alias_fallback) - set(alias_targets)
    if unmatched:
        _alias_match_pass({k: v for k, v in alias_fallback.items() if k in unmatched}, strict=False)

    # Deepen again, now covering the 2-segment (`@scope/package`)
    # entries Tier 0 / the combined / fallback tiers above may have
    # just added — idempotent for anything already correct (its own
    # _validates(candidate) check short-circuits immediately).
    _deepen_aliases()

    remappings = []
    for seg, full in alias_targets.items():
        remappings.append(f"{seg}/={full}/")

    # Skip any LHS this raw basename sweep would otherwise generate a
    # remap for if the alias-matching pass above (lines ~333-454)
    # already resolved and VALIDATED that exact same LHS — that pass
    # confirms its target against real file paths and self-corrects one
    # level deeper when the package's own root isn't the real import
    # root (see the "may not be the real package ROOT" validation
    # above). This blind walk has no such check: it appends a remap for
    # ANY directory whose bare basename happens to match a bare-import
    # prefix, unconditionally pointing at that directory itself. Found
    # live this session against Usual Protocol's real, currently-
    # deployed Eur0.sol: it bare-imports
    # `openzeppelin-contracts-upgradeable/token/ERC20/...` (package name
    # only, no `contracts/` suffix in the import path itself — the real
    # file lives one level deeper, under the package's own `contracts/`
    # subfolder). The alias pass already resolved+validated
    # `openzeppelin-contracts-upgradeable` correctly to
    # `.../lib/openzeppelin-contracts-upgradeable/contracts/`. This walk
    # ALSO matched the same LHS against the package's ROOT directory
    # (whose bare basename is literally "openzeppelin-contracts-
    # upgradeable") and appended a SECOND, conflicting, uncorrected
    # remap for the identical prefix pointing one level too shallow.
    # solc resolves a duplicate remapping prefix by taking whichever
    # was declared LAST, and this raw walk always runs after the alias
    # pass — so the wrong, unvalidated entry silently won, and a fully
    # verified, compilable-on-its-own contract failed to compile with
    # zero error output.
    already_resolved_lhs = set(alias_targets.keys())
    for root, dirs, files in os.walk(project_root):
        for d in dirs:
            full = os.path.join(root, d)
            rel = os.path.relpath(full, project_root)
            short = rel.split("/")[-1] if "/" in rel else None
            # Use relative left side, absolute right side
            if rel not in already_resolved_lhs and _needed_by_bare_import(rel):
                remappings.append(f"{rel}/={full}/")
            if short is not None and short not in already_resolved_lhs and _needed_by_bare_import(short):
                remappings.append(f"{short}/={full}/")

    remappings = list(dict.fromkeys(remappings))

    # Prioritize known packages that commonly fail remapping in deep lib trees
    PRIORITY_PACKAGES = {
        "openzeppelin-contracts", "@openzeppelin", "openzeppelin-solidity", "forge-std",
        "solmate", "solady", "ds-test", "prb-math",
    }
    priority = [r for r in remappings if any(p in r for p in PRIORITY_PACKAGES)]
    rest = [r for r in remappings if r not in priority]
    remappings = priority + rest

    # Prefer the AUTHORITATIVE remappings Etherscan embeds in
    # standard-json-verified sources (settings.remappings — the exact
    # list solc was invoked with at deploy-time compilation) over the
    # heuristic derivation above, when available. The heuristic exists
    # only to approximate this for verification formats that don't
    # carry it (flattened single-file sources, older non-standard-json
    # bundles) — for a project that DOES carry it, ground truth beats
    # any approximation. Confirmed live against Flaunch's real, currently-
    # deployed PositionManager2 (Base, 0xB4512b...): the heuristic maps
    # `@optimism/interfaces/` and `@optimism/src/` onto the wrong
    # subdirectories (there is no directory literally named "interfaces"
    # or "src" inside the vendored optimism package at those depths) and
    # has no rule that could ever invent `@flaunch/=src/contracts/` for a
    # bare `@flaunch/PositionManager.sol` DIRECT-FILE import (no
    # subdirectory segment to key off of at all) — Slither silently
    # exits 1 with empty stdout/stderr on a fully verified, actively-
    # used, ~$1.5M-TVL launchpad contract, and run_slither's "no output"
    # catch-all swallows the real crytic-compile error entirely. The
    # authoritative RHS values are relative to the project root in
    # exactly the same way the `sources` dict keys written to disk by
    # write_source_files are (both come from the same standard-json
    # `sources` object), so join verbatim onto project_root — no
    # translation needed.
    authoritative_remaps = source_data.get("remappings") or []
    if authoritative_remaps:
        resolved_remaps = []
        for entry in authoritative_remaps:
            lhs, _, rhs = entry.partition("=")
            lhs = lhs.strip()
            if not lhs:
                continue
            rhs = rhs.strip()
            full = os.path.join(project_root, rhs) if rhs else project_root
            resolved_remaps.append(f"{lhs}={full.rstrip('/')}/")
        if resolved_remaps:
            remappings = list(dict.fromkeys(resolved_remaps))
            log.debug(f"Using {len(remappings)} authoritative remappings from verified source metadata")

    log.debug(f"Remappings: {remappings[:5]}")

    # --via-ir only exists from solc 0.8.13 onward, but --optimize alone
    # has existed since Solidity's earliest releases and needs no such
    # gate. Real Aave V2-family lending pools (Aave itself, and forks:
    # Celo's Moola, Mantle's Lendle, and virtually every other chain's
    # AToken/LendingPool clone) are pinned to solc 0.6.x/0.7.x — too old
    # for --via-ir — and without ANY optimizer flag, solc's own legacy
    # codegen hits a hard "Stack too deep when compiling inline
    # assembly" compile error on LendingPool.sol's real complexity,
    # aborting analysis outright with no findings and no graph.
    # Confirmed live: the identical compile with nothing but --optimize
    # added (no --via-ir, since 0.7.6 doesn't support it) succeeds
    # cleanly. Splitting the two flags apart — always pass --optimize,
    # gate --via-ir separately — fixes this whole real, common protocol
    # family without changing behavior for anything already working.
    try:
        version_parts = tuple(int(x) for x in solc_version.split(".")[:3])
        major, minor, patch = version_parts
    except Exception:
        version_parts = None
        major = minor = patch = 0
    use_ir = version_parts is not None and (major, minor) >= (0, 8) and patch >= 13
    solc_extra = " --via-ir --optimize" if use_ir else " --optimize"

    # --allow-paths itself doesn't exist before solc 0.5.0 — passing it to
    # older compilers doesn't get ignored, it's a hard "unrecognised option"
    # compile error, which fails the ENTIRE run (no findings, no graph —
    # graph analysis is gated on this call succeeding). Found live: solc
    # 0.4.10 (Parity's 2017 WalletLibrary) crashed with exactly this,
    # silently, for every historically-old contract.
    supports_allow_paths = version_parts is not None and (major, minor) >= (0, 5)
    solc_args = f"--allow-paths {project_root}{solc_extra}" if supports_allow_paths else solc_extra.strip()
    cmd = ["slither", filepath, "--solc", "solc-wrapper", "--json", "-"]
    if solc_args:
        # `=`-joined, not two separate argv items: slither's own
        # argparse mis-parses `--solc-args --optimize` (a bare value
        # that itself looks like a flag) as "--solc-args got zero
        # arguments, --optimize is a separate unknown flag" and aborts
        # with "expected one argument" — confirmed live, this broke
        # EVERY pre-0.5.0 compiler (solc_args is a bare "--optimize"
        # there, no --allow-paths prefix to disguise it) the moment
        # --optimize started being passed unconditionally. The `=`
        # form sidesteps the ambiguity entirely and was verified live
        # to still work for the existing multi-word case too (e.g.
        # `--allow-paths /tmp/x --via-ir --optimize`).
        cmd.append(f"--solc-args={solc_args}")
    if not _has_local_foundry:
        cmd.append("--foundry-ignore")
    if remappings:
        cmd += ["--solc-remaps", " ".join(remappings[:50])]

    env = os.environ.copy()
    if solc_version:
        _ensure_solc_installed(solc_version)
        env["SOLC_VERSION"] = solc_version

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT,
            env=env,
            cwd=project_root
        )

        output_text = result.stdout.strip()
        log.debug(f"Slither return code: {result.returncode}")
        log.debug(f"Slither stderr: {result.stderr[:300]}")
        log.debug(f"Slither cmd: {cmd}")
        log.debug(f"Slither stdout: {result.stdout[:500]}")
        log.debug(f"Slither stderr FULL: {result.stderr[:1000]}")

        if not output_text:
            log.warn("Slither produced no output")
            return {
                "success": False,
                "reason": "no_output",
                "findings": []
            }

        try:
            output = json.loads(output_text)
        except json.JSONDecodeError:
            # Try to extract JSON from mixed output
            for line in output_text.split("\n"):
                if line.startswith("{"):
                    try:
                        output = json.loads(line)
                        break
                    except:
                        continue
            else:
                return {
                    "success": False,
                    "reason": "json_parse_failed",
                    "findings": []
                }

        findings = parse_slither_output(output)
        log.success(f"Slither complete: {len(findings)} findings")

        high = sum(1 for f in findings if f["impact"] == "High")
        medium = sum(1 for f in findings if f["impact"] == "Medium")
        low = sum(1 for f in findings if f["impact"] == "Low")

        resolved["remappings"] = remappings
        enrichment = run_enricher(resolved, project_root, os.path.join(project_root, filepath), solc_version)
        return {
            "success": True,
            "findings": findings,
            "slither_json": output,
            "enrichment": enrichment,
            "project_root": project_root,
            "entry_file": os.path.join(project_root, filepath),
            "solc_version": solc_version,
            "remappings": remappings,
            "summary": {
                "total": len(findings),
                "high": high,
                "medium": medium,
                "low": low
            }
        }

    except subprocess.TimeoutExpired:
        log.error("Slither timed out")
        return {"success": False, "reason": "timeout", "findings": []}
    except Exception as e:
        log.error(f"Slither failed: {e}")
        return {"success": False, "reason": str(e), "findings": []}
