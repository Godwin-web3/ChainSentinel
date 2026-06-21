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
from analysis.vyper_runner import analyze as vyper_analyze
from analysis.yul_handler import analyze as yul_analyze
from core.language import detect_language, extract_vyper_version
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
        # Recount from all findings (handles mixed Slither+Yul+Vyper)
        all_findings = analysis.get("findings", [])
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in all_findings if f.get("severity") == "LOW")
        info = sum(1 for f in all_findings if f.get("severity") == "INFORMATIONAL")
        lang = analysis.get("language", "unknown")
        lines.append("")
        lines.append("  --- Analysis Results (" + lang + ") ---")
        if critical:
            lines.append("  Critical   : " + str(critical))
        lines.append("  High       : " + str(high))
        lines.append("  Medium     : " + str(medium))
        lines.append("  Low        : " + str(low))
        if info:
            lines.append("  Info       : " + str(info))
        hv = analysis.get("high_value_findings") or [
            f for f in analysis.get("findings", [])
            if f.get("severity") in ("CRITICAL", "HIGH")
        ]
        if hv:
            lines.append("  --- High Value Findings ---")
            for f in hv[:3]:
                lines.append("  [" + f["severity"] + "] " + f["title"])

        graph = analysis.get("graph")
        if graph:
            lines.append(f"  --- Graph Analysis: {graph.get('nodes',0)} nodes | {graph.get('sinks',0)} sinks ---")
            lines.append(f"  CONFIRMED:{graph.get('confirmed',0)} LIKELY:{graph.get('likely',0)} POSSIBLE:{graph.get('possible',0)} SUPPRESSED:{graph.get('suppressed',0)}")
            for r in graph.get("findings", []):
                lines.append(f"  [{r['verdict']}][{r['confidence']}%] {r['constraint_type']}")
                lines.append(f"    {r['entry']}")
                lines.append(f"    -> {r['sink']} | {r['immunefi_impact']}")

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

        # Detect language and route to correct analyzer
        raw_source = resolved.get("source", "") or ""
        source_code = raw_source.get("source", "") if isinstance(raw_source, dict) else raw_source
        compiler_str = resolved.get("compiler", "") or ""
        if not compiler_str and isinstance(raw_source, dict):
            compiler_str = raw_source.get("compiler", "") or ""
        lang_info = detect_language(source_code, compiler_str)
        language = lang_info["language"]

        analysis = {}
        enrichment = {}
        if language == "vyper":
            vyper_version = extract_vyper_version(source_code, compiler_str)
            vyper_result = vyper_analyze(source_code, version=vyper_version or "")
            if vyper_result["findings"]:
                analysis["findings"] = vyper_result["findings"]
                analysis["summary"] = vyper_result["summary"]
                analysis["severity_counts"] = vyper_result["summary"].get("severity_counts", {})
                analysis["language"] = "vyper"
        else:
            slither_result = run_slither(resolved)
            enrichment = slither_result.get("enrichment", {})
            if slither_result["success"]:
                enriched = enrich_findings(slither_result["findings"])
                analysis = summarize(enriched)
                analysis["findings"] = enriched
                analysis["language"] = "solidity"

                # Graph analysis — path enumeration
                try:
                    from core.graph import build_graph
                    from core.sinks import classify_sinks, top_sinks
                    from core.paths import enumerate_paths, top_paths

                    p_root = slither_result.get("project_root")
                    e_file = slither_result.get("entry_file")
                    s_ver  = slither_result.get("solc_version")

                    if p_root and e_file and s_ver:
                        remaps = slither_result.get("remappings", [])
                        nodes, graph_edges = build_graph(p_root, e_file, s_ver, enrichment, remaps)
                        sinks = classify_sinks(nodes, graph_edges)
                        paths = enumerate_paths(nodes, graph_edges, sinks)
                        high_paths = top_paths(paths, min_score=10)

                        from core.constraints import validate_paths
                        report = validate_paths(paths, nodes, graph_edges)

                        analysis["graph"] = {
                            "nodes": len(nodes),
                            "sinks": len(sinks),
                            "paths": len(paths),
                            "confirmed": len(report.confirmed),
                            "likely": len(report.likely),
                            "possible": len(report.possible),
                            "suppressed": len(report.suppressed),
                            "findings": [
                                {
                                    "verdict": r.verdict,
                                    "confidence": r.confidence,
                                    "constraint_type": r.constraint_type,
                                    "entry": r.path.entry,
                                    "sink": r.path.sink.node_id,
                                    "sink_category": r.path.sink.category,
                                    "flags": sorted(r.path.constraint_flags),
                                    "immunefi_impact": r.immunefi_impact,
                                    "reasoning": r.reasoning[:200],
                                    "final_score": r.final_score,
                                }
                                for r in report.all_findings()[:10]
                            ]
                        }
                        log.success(f"Graph: {len(nodes)} nodes | {len(sinks)} sinks | CONFIRMED:{len(report.confirmed)} LIKELY:{len(report.likely)} POSSIBLE:{len(report.possible)}")
                except Exception as ge:
                    log.warn(f"Graph analysis failed: {ge}")
            # Always run Yul handler on Solidity — catches inline assembly
            if source_code and lang_info.get("has_inline_yul"):
                yul_result = yul_analyze(source_code)
                if yul_result["findings"]:
                    existing = analysis.get("findings", [])
                    analysis["findings"] = existing + yul_result["findings"]
                    analysis["yul_summary"] = yul_result["summary"]
                    analysis["language"] = analysis.get("language", "solidity") + "+yul"
            if not analysis.get("language"):
                analysis["language"] = language

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
                "analysis": analysis,
                "enrichment": enrichment
            })
            poc_file = generate_poc(
                address=address,
                name=resolved["name"],
                category=category,
                findings=analysis["findings"],
                block_number=0,
                graph_findings=analysis.get("graph", {}).get("findings", [])
            )
            # Run PoC verification
            verify_result = None
            if poc_file:
                try:
                    verify_result = verify_exploit(poc_file, chain.rpc_url)
                    if verify_result.get("verified"):
                        log.info("✓ Exploit VERIFIED — profit: " + str(verify_result.get("profit_eth", 0)) + " ETH")
                    else:
                        log.info("PoC not yet exploitable — skeleton needs implementation")
                except Exception as ve:
                    log.warn("Verifier error: " + str(ve))
                    verify_result = {"verified": False, "reason": str(ve)}

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
        import traceback; traceback.print_exc()
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
