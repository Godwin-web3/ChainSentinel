#!/usr/bin/env python3

import sys
import json
import argparse
from datetime import datetime, timezone
from config.chains import get_chain, list_chains
from core.resolver import resolve
from core.classifier import classify
from core.token import fetch_token_data
from analysis.slither_runner import run_slither
from analysis.pattern_engine import enrich_findings, summarize
from exploits.generator import generate_poc
from exploits.verifier import verify_exploit
from output.reporter import generate_report
from utils.logger import log

BANNER = """
+===================================================+
|        EXPLOIT AGENT  //  DeFi Security           |
|        Institutional Grade Analysis Engine        |
+===================================================+"""

def print_result(result):
    source = result.get("source") or {}
    impl = result.get("implementation")

    lines = [
        "",
        "=" * 55,
        "  Target     : " + result["address"],
        "  Chain      : " + result["chain"] + " (id: " + str(result["chain_id"]) + ")",
        "  Name       : " + result["name"],
        "  Category   : " + result["category"],
        "  Type       : " + result["type"],
        "  Verified   : " + ("yes" if result["verified"] else "no"),
        "  Proxy      : " + ("yes (depth " + str(result["proxy_depth"]) + ")" if result["proxy_depth"] > 0 else "no"),
        "  Bytecode   : " + str(len(result["bytecode"]) if result["bytecode"] else 0) + " chars",
    ]

    token = result.get("token") or {}
    if token.get("symbol"):
        lines.append("  Symbol     : " + token["symbol"])
    if token.get("decimals") is not None:
        lines.append("  Decimals   : " + str(token["decimals"]))
    if token.get("total_supply") is not None:
        supply = "{:,.2f}".format(token["total_supply"])
        lines.append("  Supply     : " + supply + " " + (token.get("symbol") or ""))
    if token.get("standard"):
        lines.append("  Standard   : " + token["standard"])

    if impl:
        lines.append("  Impl       : " + impl["address"])

    if source.get("compiler"):
        lines.append("  Compiler   : " + source["compiler"])

    analysis = result.get("analysis") or {}
    if analysis:
        sev = analysis.get("severity_counts", {})
        lines.append("" )
        lines.append("  --- Analysis Results ---")
        lines.append("  High       : " + str(sev.get("HIGH", 0)))
        lines.append("  Medium     : " + str(sev.get("MEDIUM", 0)))
        lines.append("  Low        : " + str(sev.get("LOW", 0)))
        lines.append("  Info       : " + str(sev.get("INFORMATIONAL", 0)))
        hv = analysis.get("high_value_findings", [])
        if hv:
            lines.append("  --- High Value Findings ---")
            for f in hv[:3]:
                lines.append("  [" + f["severity"] + "] " + f["title"])

    if result.get("poc_file"):
        lines.append("  PoC        : " + result["poc_file"])
    if result.get("report_file"):
        lines.append("  Report     : " + result["report_file"])

    lines += [
        "=" * 55,
        "  Status     : " + result["status"],
        "  Timestamp  : " + result["timestamp"],
        "=" * 55,
        ""
    ]

    print("\n".join(lines))

def analyze(address, chain_name, output_json=False):
    chain = get_chain(chain_name)
    if not chain:
        return {
            "success": False,
            "error": "Unknown chain: " + chain_name + ". Available: " + str(list_chains())
        }

    if not address.startswith("0x") or len(address) != 42:
        return {
            "success": False,
            "error": "Invalid address: " + address
        }

    try:
        resolved = resolve(address, chain)
        if not resolved:
            return {
                "success": False,
                "error": "Resolution failed"
            }

        category = classify(resolved)

        token_data = {}
        if category == "token":
            token_data = fetch_token_data(address, chain)

        slither_result = run_slither(resolved)
        analysis = {}
        if slither_result["success"]:
            enriched = enrich_findings(slither_result["findings"])
            analysis = summarize(enriched)
            analysis["findings"] = enriched

        poc_file = None
        report_file = None
        if analysis.get("findings"):
            report_file = generate_report({
                "address": address,
                "name": resolved["name"],
                "chain": resolved["chain"],
                "category": category,
                "verified": resolved["verified"],
                "proxy_depth": resolved["proxy_depth"],
                "implementation": resolved["implementation"],
                "token": token_data,
                "analysis": analysis
            })
            poc_file = generate_poc(
                address=address,
                name=resolved["name"],
                category=category,
                findings=analysis["findings"],
                block_number=0
            )

        return {
            "success": True,
            "address": address,
            "chain": resolved["chain"],
            "chain_id": resolved["chain_id"],
            "name": resolved["name"],
            "category": category,
            "type": resolved["type"],
            "verified": resolved["verified"],
            "proxy_depth": resolved["proxy_depth"],
            "bytecode": resolved["bytecode"],
            "source": resolved["source"],
            "implementation": resolved["implementation"],
            "token": token_data,
            "status": "RESOLVED - ready for analysis",
            "analysis": analysis,
            "poc_file": poc_file,
            "report_file": report_file,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
        }

    except Exception as e:
        log.error("Analysis failed: " + str(e))
        return {
            "success": False,
            "error": str(e)
        }

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Exploit Agent - Institutional Grade Smart Contract Security"
    )
    parser.add_argument("address", nargs="?", help="Contract address (0x...)")
    parser.add_argument("chain", nargs="?", default="mainnet", help="Chain name (default: mainnet)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--chains", action="store_true", help="List supported chains")

    args = parser.parse_args()

    if args.chains:
        print("Supported chains: " + ", ".join(list_chains()))
        return

    if not args.address:
        parser.print_help()
        return

    result = analyze(args.address, args.chain)

    if args.json:
        output = {k: v for k, v in result.items() if k not in ["bytecode", "source"]}
        print(json.dumps(output, indent=2))
        return

    if not result["success"]:
        print("\n  [ERROR] " + result["error"] + "\n")
        sys.exit(1)

    print_result(result)

if __name__ == "__main__":
    main()
