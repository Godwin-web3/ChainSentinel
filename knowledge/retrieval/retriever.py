import json
import logging
from knowledge.storage.db.database import get_connection

log = logging.getLogger(__name__)

# Maps sink categories from paths.py to attack pattern names in DB
SINK_TO_PATTERNS = {
    "ASSET_DRAIN":        ["reentrancy-eth", "reentrancy-token", "read-only-reentrancy", "price-manipulation", "flash-loan-attack"],
    "CALLBACK_SINK":      ["reentrancy-eth", "reentrancy-token", "read-only-reentrancy"],
    "DELEGATION_SINK":    ["controlled-delegatecall"],
    "STORAGE_CORRUPTION": ["storage-collision", "controlled-delegatecall"],
    "SELFDESTRUCT_SINK":  ["controlled-delegatecall"],
}

# Maps constraint flags to pattern names that match
FLAG_TO_PATTERNS = {
    "AUTH_GAP":           ["access-control-bypass"],
    "STATE_BEFORE_CALL":  ["reentrancy-eth", "reentrancy-token"],
    "DELEGATION":         ["controlled-delegatecall"],
    "UNCERTAIN_TARGET":   ["reentrancy-eth", "price-manipulation"],
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _query(sql: str, params: tuple = ()) -> list:
    try:
        conn = get_connection()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"DB query failed: {e}")
        return []


def get_patterns_for_sink(sink_category: str) -> list:
    """Return attack pattern rows matching a sink category."""
    names = SINK_TO_PATTERNS.get(sink_category, [])
    if not names:
        return []
    placeholders = ",".join("?" * len(names))
    return _query(
        f"SELECT * FROM attack_patterns WHERE name IN ({placeholders})",
        tuple(names)
    )


def get_findings_for_patterns(pattern_names: list, limit: int = 10) -> list:
    """Return real audit findings linked to given pattern names."""
    if not pattern_names:
        return []
    pattern_rows = _query(
        f"SELECT id, name FROM attack_patterns WHERE name IN ({','.join('?'*len(pattern_names))})",
        tuple(pattern_names)
    )
    if not pattern_rows:
        return []
    pattern_ids = [r["id"] for r in pattern_rows]
    placeholders = ",".join("?" * len(pattern_ids))
    findings = _query(
        f"""SELECT f.*, ap.name as pattern_name
            FROM findings f
            LEFT JOIN attack_patterns ap ON f.pattern_id = ap.id
            WHERE f.pattern_id IN ({placeholders})
            ORDER BY f.severity, f.id
            LIMIT ?""",
        tuple(pattern_ids) + (limit,)
    )
    return sorted(findings, key=lambda x: SEVERITY_RANK.get(x.get("severity", "low"), 3))


def get_findings_for_category(category: str, limit: int = 10) -> list:
    """Return findings by vulnerability category string."""
    return _query(
        """SELECT * FROM findings
           WHERE category = ?
           ORDER BY severity, id
           LIMIT ?""",
        (category, limit)
    )


def get_attack_priorities(protocol_category: str) -> list:
    """Return ordered attack patterns for a protocol category."""
    return _query(
        """SELECT ap.name, ap.display_name, ap.description, cam.priority
           FROM category_attack_map cam
           JOIN attack_patterns ap ON cam.pattern_id = ap.id
           WHERE cam.protocol_category = ?
           ORDER BY cam.priority ASC""",
        (protocol_category,)
    )


def query_for_exploit_path(
    sink_category: str,
    constraint_flags: set,
    protocol_category: str = "lending",
    max_findings: int = 5,
) -> dict:
    """
    Main entry point for the PoC generator.

    Given an ExploitPath's sink + flags + protocol context,
    returns relevant patterns and real findings to use as context.
    """
    # Gather pattern names from sink and flags
    pattern_names = list(set(SINK_TO_PATTERNS.get(sink_category, [])))
    for flag in constraint_flags:
        pattern_names += FLAG_TO_PATTERNS.get(flag, [])
    pattern_names = list(set(pattern_names))

    patterns = get_patterns_for_sink(sink_category)
    findings = get_findings_for_patterns(pattern_names, limit=max_findings)

    # Fallback: pull by protocol priority if no pattern findings found
    if not findings:
        priorities = get_attack_priorities(protocol_category)
        priority_names = [p["name"] for p in priorities[:3]]
        findings = get_findings_for_patterns(priority_names, limit=max_findings)

    return {
        "sink_category":      sink_category,
        "constraint_flags":   list(constraint_flags),
        "protocol_category":  protocol_category,
        "matched_patterns":   [p["name"] for p in patterns],
        "findings":           findings,
        "finding_count":      len(findings),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("\n--- Test: ASSET_DRAIN + STATE_BEFORE_CALL (lending) ---")
    result = query_for_exploit_path(
        sink_category="ASSET_DRAIN",
        constraint_flags={"STATE_BEFORE_CALL", "EXTERNAL_CALL", "AUTH_GAP"},
        protocol_category="lending",
    )
    print(f"Matched patterns: {result['matched_patterns']}")
    print(f"Findings retrieved: {result['finding_count']}")
    for f in result["findings"]:
        print(f"  [{f['severity'].upper()}] {f['title']} ({f.get('pattern_name', 'unlinked')})")

    print("\n--- Test: DELEGATION_SINK (proxy) ---")
    result2 = query_for_exploit_path(
        sink_category="DELEGATION_SINK",
        constraint_flags={"DELEGATION", "UNCERTAIN_TARGET"},
        protocol_category="proxy",
    )
    print(f"Matched patterns: {result2['matched_patterns']}")
    print(f"Findings retrieved: {result2['finding_count']}")
    for f in result2["findings"]:
        print(f"  [{f['severity'].upper()}] {f['title']} ({f.get('pattern_name', 'unlinked')})")
