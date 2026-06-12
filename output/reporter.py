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
                "",
            ]

    if deduped_medium:
        lines += ["## 🟡 Medium Findings", ""]
        for f in deduped_medium:
            lines += [
                f"### {f['title']}",
                f"- **Impact:** {f.get('impact', 'N/A')}",
                f"- **Description:** {f.get('attack_description', f.get('description', 'N/A'))}",
                "",
            ]

    safe_name = name.replace(" ", "_").replace("/", "_")
    filename = f"report_{safe_name}_{address[:8]}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write("\n".join(lines))

    log.success(f"Report saved: {filepath}")
    return filepath
