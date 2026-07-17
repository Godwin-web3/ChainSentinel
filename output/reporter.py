import json
import os
from datetime import datetime, timezone
from utils.logger import log

def generate_report(result: dict, output_dir: str = "output/reports") -> str:
    os.makedirs(output_dir, exist_ok=True)

    address = result.get("address", "unknown")
    name = result.get("name", "unknown")
    chain = result.get("chain", "unknown")
    category = result.get("category", "unknown")
    analysis = result.get("analysis") or {}
    findings = analysis.get("findings", [])
    severity = analysis.get("severity_counts", {})
    token = result.get("token") or {}
    impl = result.get("implementation")

    enrichment = result.get("enrichment", {})
    features = enrichment.get("features", {}) if enrichment else {}

    def get_auth_for_finding(finding):
        """Match a finding to enricher feature by function name."""
        fname = finding.get("function_name", "")
        if not fname:
            return None
        for k, v in features.items():
            if v.get("name", "").split("(")[0] == fname.split("(")[0]:
                return v
        return None

    high = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]

    # Dedup
    seen = set()
    deduped_high = []
    for f in high:
        if f.get("check", f.get("id", "unknown")) not in seen:
            seen.add(f.get("check", f.get("id", "unknown")))
            deduped_high.append(f)

    seen = set()
    deduped_medium = []
    for f in medium:
        if f.get("check", f.get("id", "unknown")) not in seen:
            seen.add(f.get("check", f.get("id", "unknown")))
            deduped_medium.append(f)

    timestamp = datetime.now(timezone.utc).isoformat()
    risk = "CRITICAL" if severity.get("CRITICAL", 0) > 0 else \
           "HIGH" if severity.get("HIGH", 0) > 0 else \
           "MEDIUM" if severity.get("MEDIUM", 0) > 0 else \
           "LOW"

    lines = [
        "# Exploit Agent — Security Report",
        f"> Generated: {timestamp}",
        "",
        "## Target",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Address | `{address}` |",
        f"| Name | {name} |",
        f"| Chain | {chain} |",
        f"| Category | {category} |",
        f"| Verified | {'Yes' if result.get('verified') else 'No'} |",
        f"| Proxy | {'Yes (depth ' + str(result.get('proxy_depth', 0)) + ')' if result.get('proxy_depth', 0) > 0 else 'No'} |",
        f"| Risk Level | **{risk}** |",
        "",
    ]

    if impl:
        lines += [
            f"| Implementation | `{impl['address']}` |",
            "",
        ]

    if token:
        lines += [
            "## Token Info",
            f"| Symbol | Decimals | Total Supply |",
            f"|--------|----------|-------------|",
            f"| {token.get('symbol', 'N/A')} | {token.get('decimals', 'N/A')} | {'{:,.2f}'.format(token.get('total_supply') or 0)} |",
            "",
        ]

    lines += [
        "## Analysis Summary",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 High/Critical | {severity.get('HIGH', 0) + severity.get('CRITICAL', 0)} |",
        f"| 🟡 Medium | {severity.get('MEDIUM', 0)} |",
        f"| 🟢 Low | {severity.get('LOW', 0)} |",
        f"| ℹ️ Informational | {severity.get('INFORMATIONAL', 0)} |",
        "",
    ]

    if deduped_high:
        lines += ["## 🔴 High / Critical Findings", ""]
        for f in deduped_high:
            lines += [
                f"### {f['title']}",
                f"- **Check:** `{f.get('check', f.get('id', 'N/A'))}`",
                f"- **Category:** {f.get('category', f.get('type', 'N/A'))}",
                f"- **Impact:** {f.get('impact', 'N/A')}",
                f"- **Bounty Potential:** {f.get('bounty_potential', 'N/A')}",
                f"- **Description:** {f.get('attack_description', f.get('description', 'N/A'))}",
            ]
            auth = get_auth_for_finding(f)
            if auth:
                lines += [
                    f"- **Auth State:** `{auth.get('auth_state', 'UNKNOWN')}`",
                    f"- **Auth Score:** {auth.get('auth_score', 0)}",
                    f"- **Auth Evidence:** {', '.join(e['type'] for e in auth.get('auth_evidence', []))}",
                ]
            lines += [""]

    if deduped_medium:
        lines += ["## 🟡 Medium Findings", ""]
        for f in deduped_medium:
            lines += [
                f"### {f['title']}",
                f"- **Impact:** {f.get('impact', 'N/A')}",
                f"- **Description:** {f.get('attack_description', f.get('description', 'N/A'))}",
            ]
            auth = get_auth_for_finding(f)
            if auth:
                lines += [
                    f"- **Auth State:** `{auth.get('auth_state', 'UNKNOWN')}`",
                    f"- **Auth Score:** {auth.get('auth_score', 0)}",
                    f"- **Auth Evidence:** {', '.join(e['type'] for e in auth.get('auth_evidence', []))}",
                ]
            lines += [""]

    # Enrichment section — high priority functions from auth analysis
    enrichment = result.get("enrichment", {})
    high_priority = enrichment.get("high_priority_functions", []) if enrichment else []
    features = enrichment.get("features", {}) if enrichment else {}

    if high_priority or features:
        lines += ["## 🔍 Auth Analysis", ""]
        lines += ["| Function | Auth State | Score | Evidence |"]
        lines += ["|----------|------------|-------|----------|"]
        for k, v in features.items():
            if v.get("is_entry_point") and not v.get("is_view"):
                evidence = ", ".join(e["type"] for e in v.get("auth_evidence", []))
                lines += [f"| `{v['name']}` | `{v.get('auth_state','?')}` | {v.get('auth_score',0)} | {evidence or '—'} |"]
        lines += [""]

    graph = result.get("graph", {})
    if graph:
        lines += ["## \U0001F578\uFE0F Graph Analysis", ""]
        lines += [
            f"| Nodes | Sinks | Confirmed | Likely | Possible | Suppressed |",
            f"|-------|-------|-----------|--------|----------|------------|",
            f"| {graph.get('nodes', 0)} | {graph.get('sinks', 0)} | {graph.get('confirmed', 0)} | "
            f"{graph.get('likely', 0)} | {graph.get('possible', 0)} | {graph.get('suppressed', 0)} |",
            "",
        ]
        graph_findings = graph.get("findings", [])
        if graph_findings:
            lines += ["### Constraint Engine Findings", ""]
            for gf in graph_findings:
                lines += [
                    f"- **{gf.get('verdict', 'UNKNOWN')}** ({gf.get('confidence', 0)}%) "
                    f"`{gf.get('constraint_type', 'N/A')}` \u2014 {gf.get('entry', '?')} \u2192 {gf.get('sink', '?')}",
                    f"  - {gf.get('reasoning', '')}",
                ]
            lines += [""]

        dep_log = graph.get("dependency_resolution", [])
        if dep_log:
            lines += ["### Cross-Contract Dependency Resolution", ""]
            lines += ["| Variable | Declaring Contract | Status | Detail |"]
            lines += ["|----------|--------------------|--------|--------|"]
            for d in dep_log:
                status = d.get("status", "unknown")
                detail = (
                    d.get("resolved_address")
                    or (f"{d.get('edges_rewritten', 0)} edges rewritten @ {d.get('pragma_version', '?')}" if status == "cross_contract_resolved" else None)
                    or d.get("reason", "")
                )
                lines += [
                    f"| `{d.get('variable_name', '?')}` | {d.get('declaring_contract', '—')} | "
                    f"{status} | {detail} |"
                ]
            lines += [""]

    safe_name = name.replace(" ", "_").replace("/", "_")
    filename = f"report_{safe_name}_{address[:8]}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    log.success(f"Report saved: {filepath}")
    return filepath
