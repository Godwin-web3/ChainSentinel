import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from config.settings import SLITHER_TIMEOUT
from utils.logger import log

SEVERITY_MAP = {
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
    "Optimization": 0
}

def write_source_file(source_data: dict) -> Optional[str]:
    try:
        tmpdir = tempfile.mkdtemp(prefix="exploit-agent-")
        source = source_data.get("source", "")

        if not source:
            return None

        # Handle multi-file source (Etherscan JSON format)
        is_json = isinstance(source, str) and (source.startswith("{{") or source.startswith("{"))
        if is_json:
            try:
                raw = source[1:-1] if source.startswith("{{") else source
                inner = json.loads(raw)
                sources = inner.get("sources", {})
                if sources:
                    first_file = None
                    for filename, file_data in sources.items():
                        full_path = os.path.join(tmpdir, filename)
                        os.makedirs(os.path.dirname(full_path), exist_ok=True)
                        with open(full_path, "w") as f:
                            f.write(file_data.get("content", ""))
                        if first_file is None:
                            first_file = full_path
                    log.debug(f"Multi-file project: {len(sources)} files, root: {tmpdir}")
                    return first_file
            except Exception as e:
                log.warn(f"Multi-file parse failed: {e}")

        # Single file source
        filepath = os.path.join(tmpdir, "contract.sol")
        with open(filepath, "w") as f:
            f.write(source if isinstance(source, str) else json.dumps(source))

        return filepath

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
            "affected": affected[:5]
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

    filepath = write_source_file(source_data)
    if not filepath:
        return {
            "success": False,
            "reason": "source_write_failed",
            "findings": []
        }

    # Find tmpdir root (contains lib/ or src/)
    project_root = filepath
    for _ in range(15):
        parent = os.path.dirname(project_root)
        if parent == project_root:
            break
        project_root = parent
        if os.path.exists(os.path.join(project_root, "lib")) or "exploit-agent-" in os.path.basename(project_root):
            break
    # Build remappings for nested dependencies
    remappings = []
    for root, dirs, files in os.walk(project_root):
        for d in dirs:
            if d in ["openzeppelin-contracts", "openzeppelin-contracts-upgradeable", "solidity-utils", "aave-v3-origin"]:
                full = os.path.join(root, d)
                remappings.append(f"{d}/={full}/")
    
    cmd = ["slither", filepath, "--solc", "solc-wrapper",
           "--solc-args", f"--allow-paths {project_root}",
           "--json", "-"]
    if remappings:
        cmd += ["--solc-remaps", " ".join(remappings[:10])]
    log.debug(f"Remappings: {remappings[:3]}")

    env = os.environ.copy()
    if solc_version:
        env["SOLC_VERSION"] = solc_version

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT,
            env=env
        )

        output_text = result.stdout.strip()
        log.debug(f"Slither return code: {result.returncode}")
        log.debug(f"Slither stderr: {result.stderr[:300]}")
        log.debug(f"Slither cmd: {cmd}")

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

        return {
            "success": True,
            "findings": findings,
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
