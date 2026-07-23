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

    bare_first_segments = {p.split("/")[0] for p in bare_import_paths}
    alias_targets: dict = {}
    for root, dirs, files in os.walk(project_root):
        for d in dirs:
            full = os.path.join(root, d)
            norm_d = _normalize(d)
            if not norm_d:
                continue
            for seg in bare_first_segments:
                if seg in alias_targets:
                    continue
                norm_seg = _normalize(seg)
                if norm_seg and norm_seg in norm_d:
                    alias_targets[seg] = full

    remappings = []
    for seg, full in alias_targets.items():
        remappings.append(f"{seg}/={full}/")

    for root, dirs, files in os.walk(project_root):
        for d in dirs:
            full = os.path.join(root, d)
            rel = os.path.relpath(full, project_root)
            short = rel.split("/")[-1] if "/" in rel else None
            # Use relative left side, absolute right side
            if _needed_by_bare_import(rel):
                remappings.append(f"{rel}/={full}/")
            if short is not None and _needed_by_bare_import(short):
                remappings.append(f"{short}/={full}/")

    remappings = list(dict.fromkeys(remappings))

    # Prioritize known packages that commonly fail remapping in deep lib trees
    PRIORITY_PACKAGES = {
        "openzeppelin-contracts", "@openzeppelin", "forge-std",
        "solmate", "solady", "ds-test", "prb-math",
    }
    priority = [r for r in remappings if any(p in r for p in PRIORITY_PACKAGES)]
    rest = [r for r in remappings if r not in priority]
    remappings = priority + rest

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
