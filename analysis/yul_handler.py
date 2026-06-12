"""
Yul/inline assembly analysis for ChainSentinel V2.
Handles: pure Yul contracts + inline assembly blocks in Solidity.
"""

import re
from typing import Optional


def extract_assembly_blocks(source: str) -> list:
    """Extract all inline assembly blocks from Solidity source."""
    blocks = []
    pattern = re.compile(r'assembly\s*\{', re.MULTILINE)

    for match in pattern.finditer(source):
        start = match.start()
        brace_start = source.index('{', start)
        depth = 0
        i = brace_start

        while i < len(source):
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    blocks.append({
                        "start": start,
                        "end": i + 1,
                        "content": source[brace_start:i + 1],
                        "line": source[:start].count('\n') + 1
                    })
                    break
            i += 1

    return blocks


def analyze_assembly_block(block: dict) -> list:
    """Analyze a single assembly block for dangerous patterns."""
    findings = []
    content = block["content"]
    line_offset = block["line"]

    patterns = [
        {
            "id": "YUL-001",
            "title": "Delegatecall in Assembly",
            "severity": "CRITICAL",
            "pattern": re.compile(r'\bdelegatecall\b'),
            "description": "delegatecall in assembly bypasses Solidity safety checks. Can lead to storage corruption or privilege escalation.",
            "type": "delegatecall"
        },
        {
            "id": "YUL-002",
            "title": "Selfdestruct in Assembly",
            "severity": "CRITICAL",
            "pattern": re.compile(r'\bselfdestruct\b'),
            "description": "selfdestruct in assembly. Contract can be permanently destroyed, bypassing any Solidity-level guards.",
            "type": "selfdestruct"
        },
        {
            "id": "YUL-003",
            "title": "Unchecked Call in Assembly",
            "severity": "HIGH",
            "pattern": re.compile(r'\bcall\s*\('),
            "description": "Raw call in assembly. Return value must be manually checked — easy to miss failure.",
            "type": "unchecked_call"
        },
        {
            "id": "YUL-004",
            "title": "Staticcall in Assembly",
            "severity": "LOW",
            "pattern": re.compile(r'\bstaticcall\s*\('),
            "description": "staticcall in assembly. Ensure return data is properly validated.",
            "type": "staticcall"
        },
        {
            "id": "YUL-005",
            "title": "Direct Memory Write",
            "severity": "MEDIUM",
            "pattern": re.compile(r'\bmstore\s*\('),
            "description": "Direct memory write via mstore. Incorrect offset can corrupt adjacent memory slots.",
            "type": "memory_write"
        },
        {
            "id": "YUL-006",
            "title": "Calldata Manipulation",
            "severity": "MEDIUM",
            "pattern": re.compile(r'\bcalldatacopy\s*\('),
            "description": "calldatacopy in assembly. Ensure destination and length are bounds-checked.",
            "type": "calldata"
        },
        {
            "id": "YUL-007",
            "title": "Storage Slot Direct Write",
            "severity": "HIGH",
            "pattern": re.compile(r'\bsstore\s*\('),
            "description": "Direct storage write via sstore. Can overwrite critical state variables if slot calculation is wrong.",
            "type": "storage_write"
        },
        {
            "id": "YUL-008",
            "title": "Return Data Copy Without Length Check",
            "severity": "MEDIUM",
            "pattern": re.compile(r'\breturndatacopy\s*\('),
            "description": "returndatacopy without explicit length validation can read beyond return buffer.",
            "type": "returndata"
        },
        {
            "id": "YUL-009",
            "title": "Origin Used in Assembly",
            "severity": "HIGH",
            "pattern": re.compile(r'\borigin\b'),
            "description": "tx.origin equivalent in assembly. Vulnerable to phishing/relay attacks.",
            "type": "auth"
        },
        {
            "id": "YUL-010",
            "title": "Create2 in Assembly",
            "severity": "MEDIUM",
            "pattern": re.compile(r'\bcreate2\s*\('),
            "description": "create2 in assembly. Salt-based deployment can be front-run or predicted by attackers.",
            "type": "create2"
        }
    ]

    for p in patterns:
        matches = list(p["pattern"].finditer(content))
        if matches:
            lines = []
            for m in matches[:5]:
                line_num = line_offset + content[:m.start()].count('\n')
                lines.append(line_num)

            findings.append({
                "id": p["id"],
                "title": p["title"],
                "severity": p["severity"],
                "type": p["type"],
                "description": p["description"],
                "lines": lines,
                "assembly_block_line": line_offset,
                "confidence": "MEDIUM",
                "source": "yul_handler"
            })

    return findings


def analyze(source: str) -> dict:
    """
    Full Yul/assembly analysis.
    Works on both pure Yul and Solidity with inline assembly.
    """
    findings = []
    summary = {
        "language": "yul",
        "assembly_blocks": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "total": 0
    }

    if not source:
        return {"summary": summary, "findings": findings}

    # Pure Yul
    is_pure_yul = bool(
        re.search(r'\bobject\s+"\w+"\s*\{', source) or
        re.search(r'^\s*\{[\s\S]*\blet\b', source, re.MULTILINE)
    )

    if is_pure_yul:
        block = {"start": 0, "end": len(source), "content": source, "line": 1}
        findings.extend(analyze_assembly_block(block))
        summary["assembly_blocks"] = 1
    else:
        # Inline assembly in Solidity
        blocks = extract_assembly_blocks(source)
        summary["assembly_blocks"] = len(blocks)
        for block in blocks:
            findings.extend(analyze_assembly_block(block))

    # Count severities
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

    summary["total"] = len(findings)
    return {"summary": summary, "findings": findings}


if __name__ == "__main__":
    test_source = """
pragma solidity ^0.8.0;

contract YulTest {
    address owner;

    function dangerous(address target, bytes memory data) external {
        assembly {
            let result := delegatecall(gas(), target, add(data, 0x20), mload(data), 0, 0)
            if iszero(result) { revert(0, 0) }
        }
    }

    function store(uint256 slot, uint256 val) external {
        assembly {
            sstore(slot, val)
            let x := origin()
        }
    }

    function memOp(uint256 offset) external {
        assembly {
            mstore(offset, 0x1234)
            returndatacopy(0, 0, returndatasize())
        }
    }
}
"""
    result = analyze(test_source)
    print(f"\nYul Analysis Results")
    print(f"====================")
    print(f"Assembly blocks : {result['summary']['assembly_blocks']}")
    print(f"Total findings  : {result['summary']['total']}")
    print(f"CRITICAL: {result['summary']['critical']}")
    print(f"HIGH    : {result['summary']['high']}")
    print(f"MEDIUM  : {result['summary']['medium']}")
    print(f"LOW     : {result['summary']['low']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['id']} — {f['title']} (line {f['lines']})")
