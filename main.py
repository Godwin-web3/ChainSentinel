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
from core.market_risk import score_market_risk
from core.adapters.morpho import fetch_markets as fetch_morpho_markets, MORPHO_ADDRESS
from utils.logger import log

# Protocol-level economic risk scan is keyed by known singleton contract
# addresses (a single deployed instance holds many markets — e.g. Morpho
# Blue), never by category/name guessing. Adding another protocol is one
# line here once it has an adapter under core/adapters/ producing
# MarketConfig objects; core/market_risk.py scores every adapter's output
# the same protocol-agnostic way.
MARKET_ADAPTERS = {
    MORPHO_ADDRESS.lower(): fetch_morpho_markets,
}

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

        market_risk = analysis.get("market_risk")
        if market_risk and market_risk.get("markets_scanned"):
            lines.append(
                f"  --- Market Risk: {market_risk['markets_scanned']} markets scanned | "
                f"{len(market_risk.get('findings', []))} with findings ---"
            )
            for mf in market_risk.get("findings", [])[:5]:
                for finding in mf.get("findings", []):
                    lines.append(
                        f"  [{finding['severity']}] {mf['market_id'][:10]}... "
                        f"{finding['type']}: {finding['reason']}"
                    )

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
                        nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps = build_graph(p_root, e_file, s_ver, enrichment, remaps)

                        # Auto-fetch missing sibling contracts. Only for calls whose
                        # destination is a fixed state variable / immutable on THIS
                        # deployed instance (never for runtime-arbitrary destinations
                        # like msg.sender or function parameters — those are correctly
                        # left unresolved by design).
                        #
                        # Writing a dependency's source to disk is not enough — Slither
                        # only compiles what's reachable via import from the entry file.
                        # So once any new dependency is merged, we compile via a small
                        # generated wrapper file that imports the real entry plus every
                        # resolved dependency's top-level contract, instead of e_file
                        # directly. This is purely a compilation-unit mechanism — it
                        # does not change how resolve_call or the DFS reason.
                        max_fetch_retries = 3
                        fetched_vars = set()
                        dependency_entry_files = []
                        # var_name -> entry_file, kept alongside the flat list above
                        # so the multi-version fallback knows which dependency file
                        # belongs to which unresolved variable.
                        dependency_map = {}
                        # var_name -> minimal resolved dict (address, chain_id), so the
                        # multi-version fallback can run REAL per-dependency enrichment
                        # instead of enrichment={} — see the fallback loop below.
                        dependency_resolved_info = {}
                        dependency_resolution_log = []
                        retry_count = 0
                        compile_entry = e_file
                        # Preserve the pre-retry build in case the wrapper attempt
                        # fails outright and we need a clean base to merge onto.
                        base_build = (nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps)

                        while unresolved_deps and retry_count < max_fetch_retries:
                            seen_names = set()
                            new_deps = []
                            for d in unresolved_deps:
                                vn = d["variable_name"]
                                if vn not in fetched_vars and vn not in seen_names:
                                    seen_names.add(vn)
                                    new_deps.append(d)
                            if not new_deps:
                                break
                            any_merged = False
                            for dep in new_deps:
                                var_name = dep["variable_name"]
                                declaring_contract = dep.get("declaring_contract")
                                fetched_vars.add(var_name)
                                # Variables declared on the entry contract itself have a
                                # single fixed address, fetchable via a direct getter read.
                                # Variables declared on an unrelated sibling contract TYPE
                                # (e.g. CToken's interestRateModel, seen while compiling
                                # Comptroller) don't — there's no one "the" CToken, there
                                # are many markets. For that case, look for a no-arg getter
                                # on the entry contract that enumerates real instances of
                                # that type (e.g. getAllMarkets() -> CToken[]) and use the
                                # first real on-chain address as a representative instance.
                                enumeration_getter = None
                                if declaring_contract and declaring_contract != resolved["name"]:
                                    from core.graph import find_enumeration_getter
                                    enumeration_getter = find_enumeration_getter(nodes, resolved["name"], declaring_contract)
                                    if not enumeration_getter:
                                        log.info(
                                            f"Skipping auto-fetch for {var_name} — declared on "
                                            f"{declaring_contract}, not entry contract {resolved['name']}, "
                                            f"and no enumeration getter found for {declaring_contract} "
                                            f"on {resolved['name']}"
                                        )
                                        dependency_resolution_log.append({
                                            "variable_name": var_name,
                                            "declaring_contract": declaring_contract,
                                            "status": "skipped",
                                            "reason": "declared on unrelated sibling contract — no enumeration getter found",
                                        })
                                        continue
                                try:
                                    if enumeration_getter:
                                        from core.dependency_fetcher import fetch_dependency_by_enumeration
                                        merge_result = fetch_dependency_by_enumeration(address, enumeration_getter, chain, p_root)
                                    else:
                                        from core.dependency_fetcher import fetch_dependency_by_var
                                        merge_result = fetch_dependency_by_var(address, var_name, chain, p_root)
                                    if merge_result and merge_result.entry_file:
                                        via = f" via {enumeration_getter}" if enumeration_getter else ""
                                        log.info(f"Auto-fetched dependency for {var_name}{via} -> {merge_result.address}")
                                        dependency_entry_files.append(merge_result.entry_file)
                                        dependency_map[var_name] = merge_result.entry_file
                                        dependency_resolved_info[var_name] = {
                                            "address": merge_result.address, "chain_id": chain.chain_id,
                                        }
                                        any_merged = True
                                        dependency_resolution_log.append({
                                            "variable_name": var_name,
                                            "declaring_contract": declaring_contract,
                                            "status": "fetched",
                                            "resolved_address": merge_result.address,
                                            "enumeration_getter": enumeration_getter,
                                        })
                                    else:
                                        dependency_resolution_log.append({
                                            "variable_name": var_name,
                                            "declaring_contract": declaring_contract,
                                            "status": "failed",
                                            "reason": "no entry file returned",
                                            "enumeration_getter": enumeration_getter,
                                        })
                                except Exception as fe:
                                    log.warn(f"Auto-fetch failed for {var_name}: {fe}")
                                    dependency_resolution_log.append({
                                        "variable_name": var_name,
                                        "declaring_contract": declaring_contract,
                                        "status": "failed",
                                        "reason": str(fe),
                                        "enumeration_getter": enumeration_getter,
                                    })
                            retry_count += 1
                            if not any_merged:
                                break

                            # Attempt 1: single-compile wrapper. Cheap, correct whenever
                            # the entry file and every dependency's pragma ranges overlap
                            # (the common case — most sibling contracts in an active
                            # protocol get redeployed against similar-ish solc versions).
                            wrapper_nodes = {}
                            try:
                                from core.dependency_fetcher import build_wrapper_entry
                                compile_entry = build_wrapper_entry(p_root, e_file, dependency_entry_files)
                                wrapper_nodes, wrapper_edges, wrapper_writers, wrapper_readers, wrapper_invariants, wrapper_unresolved = build_graph(p_root, compile_entry, s_ver, enrichment, remaps)
                            except Exception as we:
                                log.warn(f"Wrapper build failed: {we}")

                            if wrapper_nodes:
                                # Wrapper compiled successfully — use its output directly.
                                nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps = (
                                    wrapper_nodes, wrapper_edges, wrapper_writers, wrapper_readers, wrapper_invariants, wrapper_unresolved
                                )
                                continue

                            # Attempt 2: wrapper failed — almost certainly a genuine
                            # pragma conflict (e.g. an exact-pinned older sibling
                            # contract vs a newer entry file, proven case: Aave's
                            # Pool at 0.8.27 vs PoolAddressesProvider pinned to
                            # 0.8.10 exactly). Compile each dependency separately at
                            # its own real pragma, merge by canonical_id, then rewrite
                            # the synthetic external.{var}.{signature} labels using the
                            # dependency's real FunctionNodes — matched by EXACT full
                            # signature only (never bare name — see core/multi_compile.py).
                            log.info("Wrapper compile failed (likely pragma conflict) — falling back to separate multi-version compilation")
                            from core.multi_compile import extract_pragma_version, merge_build_results, rewrite_unresolved_edges

                            merged = base_build
                            for var_name, dep_entry in dependency_map.items():
                                dep_version = extract_pragma_version(dep_entry) or s_ver
                                # Real enrichment for THIS dependency's own compilation —
                                # see core/protocol_graph.py's identical fix for why
                                # enrichment={} makes CallEdge.trusted meaningless for
                                # every edge originating in a separately-compiled
                                # dependency (auth_lookup empty -> _resolve_trust always
                                # returns False, collapsing "protocol-fixed target" and
                                # "genuinely attacker-arbitrary target" into one bucket).
                                try:
                                    from analysis.enricher import run_enricher
                                    dep_resolved_info = dependency_resolved_info.get(
                                        var_name, {"address": dep_entry, "chain_id": chain.chain_id}
                                    )
                                    dep_enrichment = run_enricher(dep_resolved_info, p_root, dep_entry, dep_version)
                                except Exception as ee:
                                    log.warn(f"Enrichment failed for dependency of {var_name}: {ee}")
                                    dep_enrichment = {}
                                try:
                                    dep_result = build_graph(p_root, dep_entry, dep_version, dep_enrichment, remaps)
                                except Exception as de:
                                    log.warn(f"Separate compile failed for dependency of {var_name} at {dep_version}: {de}")
                                    dependency_resolution_log.append({
                                        "variable_name": var_name,
                                        "status": "compile_failed",
                                        "pragma_version": dep_version,
                                        "reason": str(de),
                                    })
                                    continue
                                if not dep_result[0]:
                                    log.warn(f"Separate compile for dependency of {var_name} produced no nodes at {dep_version}")
                                    dependency_resolution_log.append({
                                        "variable_name": var_name,
                                        "status": "compile_empty",
                                        "pragma_version": dep_version,
                                        "reason": "produced no nodes",
                                    })
                                    continue
                                merged = merge_build_results(merged, dep_result)
                                rewritten = rewrite_unresolved_edges(merged[1], dep_result[0], var_name)
                                log.info(f"Rewrote {rewritten} edges for {var_name} using separately-compiled dependency at {dep_version}")
                                dependency_resolution_log.append({
                                    "variable_name": var_name,
                                    "status": "cross_contract_resolved",
                                    "pragma_version": dep_version,
                                    "edges_rewritten": rewritten,
                                })

                            nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps = merged
                            base_build = merged
                            # unresolved_deps from the merge still reflects the
                            # original entry compile's list — recompute against
                            # what's actually still unresolved after rewriting.
                            still_unresolved = [
                                d for d in unresolved_deps
                                if any(str(e.dst).startswith(f"external.{d['variable_name']}.") for edges in graph_edges.values() for e in edges)
                            ]
                            unresolved_deps = still_unresolved
                        sinks = classify_sinks(nodes, graph_edges)
                        paths = enumerate_paths(nodes, graph_edges, sinks)
                        high_paths = top_paths(paths, min_score=10)

                        from core.constraints import validate_paths
                        report = validate_paths(paths, nodes, graph_edges, state_writers, state_readers, invariant_index)

                        analysis["graph"] = {
                            "nodes": len(nodes),
                            "sinks": len(sinks),
                            "paths": len(paths),
                            "confirmed": len(report.confirmed),
                            "likely": len(report.likely),
                            "possible": len(report.possible),
                            "suppressed": len(report.suppressed),
            "dependency_resolution": dependency_resolution_log,
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

                        # Cross-market reentrancy — a class of bug neither the
                        # single-contract REENTRANCY_CEI nor CROSS_FUNCTION_STATE_RACE
                        # checks can see even in principle: a CEI violation in one
                        # market, exploited by reentering a DIFFERENT market that
                        # reads the first market's stale state through a shared hub
                        # (the real root cause behind Cream Finance $18.8M, dForce
                        # $25M, Rari Fuse $80M). Only fires when the entry contract
                        # has a real, IR-grounded enumeration getter — most
                        # contracts don't, and this is a no-op for them.
                        try:
                            from core.protocol_graph import build_protocol_graph
                            from core.cross_market import check_cross_market_reentrancy

                            protocol_result = build_protocol_graph(
                                entry_address=address,
                                entry_name=resolved["name"],
                                chain=chain,
                                project_root=p_root,
                                entry_file=e_file,
                                solc_version=s_ver,
                                enrichment=enrichment,
                                base_build=(nodes, graph_edges, state_writers, state_readers, invariant_index, unresolved_deps),
                                remaps=remaps,
                            )
                            if protocol_result:
                                proto_nodes, proto_edges, proto_notes = protocol_result
                                cross_findings = check_cross_market_reentrancy(proto_nodes, proto_edges) if proto_edges else []
                                analysis["graph"]["cross_market"] = {
                                    "notes": proto_notes,
                                    "unified_nodes": len(proto_nodes),
                                    "findings": [
                                        {
                                            "vulnerable_entry": f.vulnerable_entry,
                                            "reentry_entry": f.reentry_entry,
                                            "shared_read_path": f.shared_read_path,
                                            "at_risk_keys": [
                                                f"{c}.{r}" + (f".{'.'.join(p)}" if p else "")
                                                for c, r, p in f.at_risk_keys
                                            ],
                                            "call_event": f.call_event.node_expr_str,
                                            "callback_target_known": f.callback_target_known,
                                        }
                                        for f in cross_findings
                                    ],
                                }
                                if cross_findings:
                                    log.success(f"Cross-market reentrancy: {len(cross_findings)} finding(s) across {len(proto_nodes)}-node unified graph")
                                else:
                                    log.info(f"Cross-market reentrancy: 0 findings across {len(proto_nodes)}-node unified graph ({len(proto_notes)} protocol notes)")
                        except Exception as pe:
                            log.warn(f"Cross-market protocol graph failed: {pe}")
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

        # Economic risk scan — independent of the code-flow analysis above.
        # Only runs when `address` is itself a registered protocol singleton
        # (e.g. Morpho Blue's own contract), since that's what holds many
        # markets; there's nothing to scan for an arbitrary contract.
        market_risk = {"markets_scanned": 0, "findings": []}
        adapter = MARKET_ADAPTERS.get(address.lower())
        if adapter:
            try:
                markets = adapter(chain, from_block=0)
                market_risk["markets_scanned"] = len(markets)
                for m in markets:
                    scored = score_market_risk(m)
                    if scored["findings"]:
                        market_risk["findings"].append(scored)
                log.success(
                    f"Market risk: {len(markets)} market(s) scanned, "
                    f"{len(market_risk['findings'])} with findings"
                )
            except Exception as me:
                log.warn(f"Market risk scan failed: {me}")
        analysis["market_risk"] = market_risk

        poc_file = None
        report_file = None
        has_code_findings = bool(analysis.get("findings"))
        has_market_findings = bool(market_risk["findings"])
        if has_code_findings or has_market_findings:
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
                "enrichment": enrichment,
                "graph": analysis.get("graph", {}),
                "market_risk": market_risk,
            })
        if has_code_findings:
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
