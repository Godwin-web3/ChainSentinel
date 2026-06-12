from utils.logger import log

# Pattern map: slither check → enriched vulnerability data
PATTERNS = {
    # HIGH severity
    "reentrancy-eth": {
        "category": "reentrancy",
        "severity": "HIGH",
        "title": "ETH Reentrancy",
        "description": "Function sends ETH before updating state — classic reentrancy attack surface.",
        "impact": "Attacker can drain ETH by re-entering before balance updates.",
        "bounty_potential": "Critical on Immunefi if ETH at risk > $50k"
    },
    "reentrancy-no-eth": {
        "category": "reentrancy",
        "severity": "HIGH",
        "title": "Token Reentrancy",
        "description": "Reentrancy via token callbacks (ERC777, ERC1155, hooks).",
        "impact": "State manipulation via reentrant token transfers.",
        "bounty_potential": "High — common in lending/vault protocols"
    },
    "arbitrary-send-eth": {
        "category": "access_control",
        "severity": "HIGH",
        "title": "Arbitrary ETH Send",
        "description": "ETH can be sent to an arbitrary address controlled by caller.",
        "impact": "Direct theft of ETH from contract.",
        "bounty_potential": "Critical"
    },
    "controlled-delegatecall": {
        "category": "proxy",
        "severity": "HIGH",
        "title": "Controlled Delegatecall",
        "description": "Delegatecall target or data controlled by caller.",
        "impact": "Full storage takeover, ownership hijack.",
        "bounty_potential": "Critical"
    },
    "suicidal": {
        "category": "access_control",
        "severity": "HIGH",
        "title": "Self-Destruct Exposed",
        "description": "Contract can be destroyed by unauthorized caller.",
        "impact": "Protocol destruction, fund loss.",
        "bounty_potential": "Critical"
    },
    "unprotected-upgrade": {
        "category": "proxy",
        "severity": "HIGH",
        "title": "Unprotected Upgrade",
        "description": "Upgrade function lacks access control.",
        "impact": "Anyone can replace contract logic.",
        "bounty_potential": "Critical"
    },
    "incorrect-equality": {
        "category": "logic",
        "severity": "HIGH",
        "title": "Dangerous Equality Check",
        "description": "Strict equality on balances/timestamps — easily manipulated.",
        "impact": "Logic bypass via dust amounts or block manipulation.",
        "bounty_potential": "Medium-High"
    },

    # MEDIUM severity
    "oracle-manipulation": {
        "category": "oracle",
        "severity": "MEDIUM",
        "title": "Oracle Manipulation Risk",
        "description": "Price oracle can be manipulated via flash loans.",
        "impact": "Price manipulation leading to undercollateralized borrows or liquidation abuse.",
        "bounty_potential": "High on lending protocols"
    },
    "erc20-interface": {
        "category": "token",
        "severity": "MEDIUM",
        "title": "Non-Standard ERC20",
        "description": "ERC20 interface deviates from standard — missing return values.",
        "impact": "Integration failures, silent transfer failures.",
        "bounty_potential": "Low-Medium"
    },
    "divide-before-multiply": {
        "category": "arithmetic",
        "severity": "MEDIUM",
        "title": "Precision Loss",
        "description": "Division before multiplication causes precision loss.",
        "impact": "Rounding errors exploitable in high-value calculations.",
        "bounty_potential": "Medium on DeFi protocols"
    },
    "tainted-high-gas": {
        "category": "dos",
        "severity": "MEDIUM",
        "title": "Unbounded Gas Usage",
        "description": "Loop or operation with unbounded gas consumption.",
        "impact": "DoS via gas exhaustion.",
        "bounty_potential": "Medium"
    },
    "tx-origin": {
        "category": "access_control",
        "severity": "MEDIUM",
        "title": "tx.origin Authentication",
        "description": "Uses tx.origin for authentication instead of msg.sender.",
        "impact": "Phishing attack bypasses access control.",
        "bounty_potential": "Medium"
    },
    "unchecked-transfer": {
        "category": "token",
        "severity": "MEDIUM",
        "title": "Unchecked Transfer Return",
        "description": "ERC20 transfer return value not checked.",
        "impact": "Silent transfer failures — funds lost or accounting broken.",
        "bounty_potential": "Medium-High depending on context"
    },
    "locked-ether": {
        "category": "logic",
        "severity": "MEDIUM",
        "title": "Locked Ether",
        "description": "Contract receives ETH but has no withdrawal mechanism.",
        "impact": "ETH permanently locked.",
        "bounty_potential": "Medium"
    },
    "weak-prng": {
        "category": "randomness",
        "severity": "MEDIUM",
        "title": "Weak Randomness",
        "description": "Uses block.timestamp or blockhash as randomness source.",
        "impact": "Miner-manipulable randomness in games/lotteries.",
        "bounty_potential": "Medium-High in gaming protocols"
    },

    # LOW severity
    "missing-zero-check": {
        "category": "validation",
        "severity": "LOW",
        "title": "Missing Zero Address Check",
        "description": "Address parameter not checked for zero address.",
        "impact": "Funds or ownership sent to zero address permanently.",
        "bounty_potential": "Low-Medium"
    },
    "unimplemented-functions": {
        "category": "logic",
        "severity": "MEDIUM",
        "title": "Unimplemented Functions",
        "description": "Interface functions not fully implemented.",
        "impact": "Unexpected reverts or broken integrations.",
        "bounty_potential": "Medium"
    },
    "events-access": {
        "category": "code_quality",
        "severity": "LOW",
        "title": "Missing Events on Access Control",
        "description": "Access control changes not emitting events.",
        "impact": "Silent privilege escalation — undetectable off-chain.",
        "bounty_potential": "Low"
    },
    # INFORMATIONAL
    "solc-version": {
        "category": "code_quality",
        "severity": "INFORMATIONAL",
        "title": "Outdated Solidity Version",
        "description": "Contract uses old solc version with known bugs.",
        "impact": "Compiler bugs may affect contract behavior.",
        "bounty_potential": "Informational only"
    },
    "naming-convention": {
        "category": "code_quality",
        "severity": "INFORMATIONAL",
        "title": "Naming Convention",
        "description": "Variables or functions do not follow naming conventions.",
        "impact": "Code quality only.",
        "bounty_potential": "None"
    },
    "constable-states": {
        "category": "optimization",
        "severity": "OPTIMIZATION",
        "title": "State Variables as Constants",
        "description": "State variables that could be declared constant.",
        "impact": "Gas optimization only.",
        "bounty_potential": "None"
    },
    "unindexed-event-address": {
        "category": "code_quality",
        "severity": "INFORMATIONAL",
        "title": "Unindexed Event Parameters",
        "description": "Address parameters in events not indexed.",
        "impact": "Harder to filter events off-chain.",
        "bounty_potential": "None"
    },
    # LOW severity
    "calls-loop": {
        "category": "dos",
        "severity": "LOW",
        "title": "Calls Inside Loop",
        "description": "External calls inside loops — DoS if one reverts.",
        "impact": "Denial of service on batch operations.",
        "bounty_potential": "Low-Medium"
    },
    "reentrancy-benign": {
        "category": "reentrancy",
        "severity": "LOW",
        "title": "Benign Reentrancy",
        "description": "Reentrancy present but no direct exploit path identified.",
        "impact": "Low risk but worth monitoring.",
        "bounty_potential": "Low"
    },
    "shadowing-local": {
        "category": "code_quality",
        "severity": "LOW",
        "title": "Variable Shadowing",
        "description": "Local variable shadows state variable.",
        "impact": "Logic errors from unintended variable use.",
        "bounty_potential": "Low"
    },
}

def enrich_findings(slither_findings: list) -> list:
    enriched = []

    for finding in slither_findings:
        check = finding.get("check", "")
        pattern = PATTERNS.get(check)

        if pattern:
            enriched.append({
                **finding,
                "category": pattern["category"],
                "severity": pattern["severity"],
                "title": pattern["title"],
                "attack_description": pattern["description"],
                "impact": pattern["impact"],
                "bounty_potential": pattern["bounty_potential"],
                "known_pattern": True
            })
        else:
            # Unknown pattern — keep slither data, map severity
            enriched.append({
                **finding,
                "category": "unknown",
                "severity": finding.get("impact", "INFO").upper(),
                "title": check.replace("-", " ").title(),
                "attack_description": finding.get("description", ""),
                "impact": "Unknown — manual review required",
                "bounty_potential": "Unknown",
                "known_pattern": False
            })

    return enriched

def summarize(enriched: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "OPTIMIZATION": 0, "INFO": 0}
    categories = {}

    for f in enriched:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

        cat = f.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    high_value = [f for f in enriched if f.get("severity") in ["CRITICAL", "HIGH"] and f.get("known_pattern")]

    return {
        "severity_counts": counts,
        "categories": categories,
        "high_value_findings": high_value,
        "total": len(enriched)
    }
