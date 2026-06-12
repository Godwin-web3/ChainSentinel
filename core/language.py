"""
Language detection for ChainSentinel V2.
Detects: Solidity, Vyper, Yul from source + compiler metadata.
"""

import re
from typing import Optional

LANGUAGE_SOLIDITY = "solidity"
LANGUAGE_VYPER = "vyper"
LANGUAGE_YUL = "yul"
LANGUAGE_UNKNOWN = "unknown"


def detect_language(source: str = "", compiler: str = "", filename: str = "") -> dict:
    """
    Detect smart contract language from available signals.
    Returns dict with language, confidence, and signals.
    """
    signals = []
    language = LANGUAGE_UNKNOWN

    # 1. Compiler field (most reliable)
    if compiler:
        c = compiler.lower()
        if c.startswith("vyper") or "vyper" in c:
            language = LANGUAGE_VYPER
            signals.append(f"compiler field: {compiler}")
        elif c.startswith("v0.") or re.match(r"v?\d+\.\d+\.\d+", c):
            language = LANGUAGE_SOLIDITY
            signals.append(f"compiler field: {compiler}")

    # 2. Filename extension
    if filename:
        if filename.endswith(".vy"):
            language = LANGUAGE_VYPER
            signals.append("file extension: .vy")
        elif filename.endswith(".sol"):
            language = LANGUAGE_SOLIDITY
            signals.append("file extension: .sol")
        elif filename.endswith(".yul"):
            language = LANGUAGE_YUL
            signals.append("file extension: .yul")

    # 3. Source code patterns
    if source:
        # Vyper signals
        if re.search(r"#\s*@version", source) or re.search(r"#\s*pragma\s+version", source):
            language = LANGUAGE_VYPER
            signals.append("source: vyper version pragma")
        elif re.search(r"^@(external|internal|view|pure|payable)", source, re.MULTILINE):
            language = LANGUAGE_VYPER
            signals.append("source: vyper decorators")
        elif re.search(r"\bdef\s+\w+\(.*\).*:", source) and "pragma solidity" not in source.lower():
            language = LANGUAGE_VYPER
            signals.append("source: python-style function definitions")

        # Solidity signals
        elif re.search(r"pragma\s+solidity", source, re.IGNORECASE):
            language = LANGUAGE_SOLIDITY
            signals.append("source: solidity pragma")
        elif re.search(r"\bcontract\s+\w+", source):
            language = LANGUAGE_SOLIDITY
            signals.append("source: contract keyword")

        # Yul signals
        if re.search(r"\bassembly\s*\{", source):
            if language == LANGUAGE_SOLIDITY:
                signals.append("source: contains inline Yul assembly")
            else:
                language = LANGUAGE_YUL
                signals.append("source: pure Yul assembly")
        elif re.search(r"\bobject\s+\"\w+\"\s*\{", source):
            language = LANGUAGE_YUL
            signals.append("source: Yul object syntax")

    confidence = "high" if len(signals) >= 2 else "medium" if signals else "low"

    return {
        "language": language,
        "confidence": confidence,
        "signals": signals,
        "has_inline_yul": "source: contains inline Yul assembly" in signals
    }


def extract_vyper_version(source: str = "", compiler: str = "") -> Optional[str]:
    """Extract Vyper compiler version string."""
    # From compiler field e.g. "vyper:0.2.5"
    if compiler:
        m = re.search(r"(\d+\.\d+\.\d+)", compiler)
        if m:
            return m.group(1)

    # From source pragma e.g. "# @version 0.3.0"
    if source:
        m = re.search(r"#\s*@version\s+([\d.]+)", source)
        if m:
            return m.group(1)
        m = re.search(r"#\s*pragma\s+version\s+([\d.]+)", source)
        if m:
            return m.group(1)

    return None


if __name__ == "__main__":
    # Quick test
    test_cases = [
        {"compiler": "vyper:0.2.5", "source": "", "filename": ""},
        {"compiler": "v0.8.19+commit.7dd6d404", "source": "pragma solidity ^0.8.0;", "filename": "Token.sol"},
        {"compiler": "", "source": "# @version 0.3.0\n@external\ndef transfer():", "filename": ""},
        {"compiler": "", "source": "assembly { let x := mload(0x40) }", "filename": ""},
    ]

    for t in test_cases:
        result = detect_language(t["source"], t["compiler"], t["filename"])
        print(f"→ {result['language']} ({result['confidence']}) | {result['signals']}")
