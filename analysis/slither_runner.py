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

    # Build remappings from directory structure
    remappings = []
    for root, dirs, files in os.walk(project_root):
        for d in dirs:
            full = os.path.join(root, d)
            rel = os.path.relpath(full, project_root)
            # Use relative left side, absolute right side
            remappings.append(f"{rel}/={full}/")
            if "/" in rel:
                short = rel.split("/")[-1]
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

    # --via-ir --optimize only supported in solc >= 0.8.13
    try:
        major, minor, patch = (int(x) for x in solc_version.split(".")[:3])
        use_ir = (major, minor) >= (0, 8) and patch >= 13
    except Exception:
        use_ir = False
    solc_extra = " --via-ir --optimize" if use_ir else ""
    cmd = ["slither", filepath, "--solc", "solc-wrapper",
           "--solc-args", f"--allow-paths {project_root}{solc_extra}",
           "--json", "-"]
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
