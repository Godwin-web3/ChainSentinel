"""
Vyper analysis runner for ChainSentinel V2.
Combines: compiler CVE check + Semgrep + manual pattern engine.
"""

import json
import re
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent.parent
BUGS_DB = BASE_DIR / "knowledge" / "vyper_bugs.json"


def load_bugs_db() -> dict:
    with open(BUGS_DB) as f:
        return json.load(f)


def check_compiler_version(version: str, source: str = "") -> list:
    findings = []
    if not version:
        return findings
    db = load_bugs_db()
    for bug in db["compiler_bugs"]:
        if version not in bug["affected_versions"]:
            continue
        required = bug.get("required_pattern")
        min_implements = bug.get("min_implements", 0)
        if required and source:
            if not re.search(required, source, re.IGNORECASE | re.DOTALL):
                continue
        if min_implements and source:
            count = len(re.findall(r"implements\s*:", source, re.IGNORECASE))
            if count < min_implements:
                continue
        confidence = "HIGH" if (required and source and re.search(required, source, re.IGNORECASE)) else ("LOW" if not source else "INFORMATIONAL")
        findings.append({
            "id": bug["id"],
            "title": bug["title"],
            "severity": bug["severity"] if confidence == "HIGH" else "INFORMATIONAL",
            "type": "compiler_bug",
            "description": bug["description"],
            "exploit_template": bug["exploit_template"],
            "real_world": bug["real_world"],
            "immunefi_relevant": bug["immunefi_relevant"],
            "cwe": bug["cwe"],
            "references": bug["references"],
            "fixed_in": bug["fixed_in"],
            "compiler_version": version,
            "confidence": confidence,
            "source": "vyper_cve_db",
            "pattern_confirmed": bool(required and source and re.search(required, source, re.IGNORECASE))
        })
    return findings


def run_semgrep(source: str) -> list:
    findings = []
    if not source or len(source.strip()) < 10:
        return findings
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.vy', delete=False) as f:
            f.write(source)
            tmp_path = f.name
        cmd = ["semgrep", "--config", "auto", "--json", "--quiet", "--lang", "python", tmp_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        os.unlink(tmp_path)
        if result.returncode in (0, 1) and result.stdout:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                findings.append({
                    "id": "SEMGREP-" + r.get("check_id", "unknown").split(".")[-1].upper(),
                    "title": r.get("extra", {}).get("message", "Semgrep finding"),
                    "severity": r.get("extra", {}).get("severity", "WARNING").upper(),
                    "type": "semgrep",
                    "line": r.get("start", {}).get("line"),
                    "confidence": "MEDIUM",
                    "source": "semgrep"
                })
    except Exception:
        pass
    return findings


def run_manual_patterns(source: str) -> list:
    findings = []
    if not source:
        return findings

    lines = source.split('\n')

    def find_lines(pattern):
        result = []
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                result.append(i)
        return result[:5]

    def add(fid, title, severity, ftype, desc, pattern):
        findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "type": ftype,
            "description": desc,
            "lines": find_lines(pattern),
            "confidence": "MEDIUM",
            "source": "vyper_pattern_engine"
        })

    # PAT-001: external call without nonreentrant
    has_external_call = bool(re.search(r'raw_call|\.transfer\(|\.send\(', source))
    has_nonreentrant = bool(re.search(r'@nonreentrant', source))
    if has_external_call and not has_nonreentrant:
        add("VYPER-PAT-001",
            "Unsafe External Call Without Reentrancy Guard",
            "HIGH", "reentrancy",
            "External call detected without @nonreentrant decorator. Potential reentrancy vulnerability.",
            r'raw_call|\.transfer\(|\.send\(')

    # PAT-002: raw_call unchecked
    if re.search(r'raw_call\s*\(', source):
        add("VYPER-PAT-002",
            "Unchecked Return Value from raw_call",
            "MEDIUM", "unchecked_return",
            "raw_call return value not captured. Failed calls may go undetected.",
            r'raw_call\s*\(')

    # PAT-003: arithmetic in type cast
    if re.search(r'(uint256|int128)\s*\([^)]+[\+\-\*][^)]+\)', source):
        add("VYPER-PAT-003",
            "Integer Arithmetic Without Bounds Check",
            "MEDIUM", "arithmetic",
            "Arithmetic operation inside type cast. May overflow/underflow in older Vyper versions.",
            r'(uint256|int128)\s*\(')

    # PAT-004: delegatecall
    if re.search(r'delegatecall', source, re.IGNORECASE):
        add("VYPER-PAT-004",
            "Delegatecall Usage Detected",
            "CRITICAL", "delegatecall",
            "delegatecall detected. Can lead to storage corruption or privilege escalation.",
            r'delegatecall')

    # PAT-005: selfdestruct
    if re.search(r'selfdestruct\s*\(', source, re.IGNORECASE):
        add("VYPER-PAT-005",
            "Self Destruct Usage",
            "HIGH", "selfdestruct",
            "selfdestruct detected. Contract can be permanently destroyed.",
            r'selfdestruct')

    # PAT-006: admin function without access control
    admin_funcs = re.findall(
        r'@external\s*\ndef\s+(\w*(set_|update_|change_|add_|remove_|transfer_ownership)\w*)\s*\(',
        source, re.IGNORECASE
    )
    if admin_funcs:
        has_access_control = bool(re.search(
            r'assert\s+(msg\.sender|self\.owner|self\.admin)', source
        ))
        if not has_access_control:
            add("VYPER-PAT-006",
                "Unprotected Admin Function",
                "HIGH", "access_control",
                "Admin function detected without access control assertion.",
                r'@external\s*\ndef\s+\w*(set_|update_|change_|add_|remove_)')

    # PAT-007: tx.origin
    if re.search(r'tx\.origin', source):
        add("VYPER-PAT-007",
            "tx.origin Used for Authentication",
            "HIGH", "auth",
            "tx.origin used for authentication. Vulnerable to phishing attacks.",
            r'tx\.origin')

    # PAT-008: timestamp dependence
    if re.search(r'block\.timestamp', source):
        add("VYPER-PAT-008",
            "Timestamp Dependence",
            "LOW", "timestamp",
            "block.timestamp used. Miners can manipulate within ~15 second window.",
            r'block\.timestamp')

    # PAT-009: hardcoded address
    if re.search(r'0x[0-9a-fA-F]{40}', source):
        add("VYPER-PAT-009",
            "Hardcoded Address Detected",
            "LOW", "hardcoded",
            "Hardcoded address found. May be a centralization risk or deployment error.",
            r'0x[0-9a-fA-F]{40}')

    # PAT-010: uninitialized storage
    if re.search(r'^\w+\s*:\s*(address|uint256|int128)\s*$', source, re.MULTILINE):
        add("VYPER-PAT-010",
            "Uninitialized Storage Variable",
            "MEDIUM", "uninitialized",
            "Storage variable declared without initialization. Defaults to zero which may be unintended.",
            r'^\w+\s*:\s*(address|uint256|int128)\s*$')

    return findings


def analyze(source: str, version: str = "", use_semgrep: bool = True) -> dict:
    findings = []
    summary = {
        "language": "vyper",
        "compiler_version": version or "unknown",
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "total": 0,
        "immunefi_relevant": 0
    }

    findings.extend(check_compiler_version(version, source))

    if use_semgrep and source:
        findings.extend(run_semgrep(source))

    if source:
        findings.extend(run_manual_patterns(source))

    for f in findings:
        sev = f.get("severity", "").upper()
        if sev == "CRITICAL":
            summary["critical"] += 1
        elif sev == "HIGH":
            summary["high"] += 1
        elif sev == "MEDIUM":
            summary["medium"] += 1
        elif sev == "LOW":
            summary["low"] += 1
        if f.get("immunefi_relevant"):
            summary["immunefi_relevant"] += 1

    summary["total"] = len(findings)
    summary["severity_counts"] = {"HIGH": summary["high"], "MEDIUM": summary["medium"], "LOW": summary["low"], "CRITICAL": summary["critical"]}
    return {"summary": summary, "findings": findings}


if __name__ == "__main__":
    test_source = """
# @version 0.2.15

owner: address
balance: uint256

@external
def __init__():
    self.owner = msg.sender

@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    self.balance -= amount

@external
def set_owner(new_owner: address):
    self.owner = new_owner
"""
    result = analyze(test_source, version="0.2.15")
    print(f"\nVyper Analysis Results")
    print(f"======================")
    print(f"Version : {result['summary']['compiler_version']}")
    print(f"Total   : {result['summary']['total']} findings")
    print(f"CRITICAL: {result['summary']['critical']}")
    print(f"HIGH    : {result['summary']['high']}")
    print(f"MEDIUM  : {result['summary']['medium']}")
    print(f"LOW     : {result['summary']['low']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['id']} — {f['title']}")
