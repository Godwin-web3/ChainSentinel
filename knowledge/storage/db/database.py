"""
knowledge/storage/db/database.py
SQLite connection + all queries the agent needs.
"""

import sqlite3
import json
import os
from typing import Optional
from utils.logger import log

DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "chainsentinel.db"
)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# ── Reports ──────────────────────────────────────────────────────

def insert_report(
    source: str,
    protocol: str,
    protocol_category: str,
    date: str,
    url: str,
    raw_path: str,
    file_format: str,
    total_findings: int = 0,
    critical_count: int = 0,
    high_count: int = 0,
    medium_count: int = 0,
) -> Optional[int]:
    try:
        conn = get_connection()
        cur = conn.execute("""
            INSERT OR IGNORE INTO reports
            (source, protocol, protocol_category, date, url,
             raw_path, file_format, total_findings,
             critical_count, high_count, medium_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (source, protocol, protocol_category, date, url,
              raw_path, file_format, total_findings,
              critical_count, high_count, medium_count))
        conn.commit()
        report_id = cur.lastrowid
        conn.close()
        return report_id
    except Exception as e:
        log.error(f"insert_report failed: {e}")
        return None


def get_report_by_url(url: str) -> Optional[dict]:
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM reports WHERE url = ?", (url,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error(f"get_report_by_url failed: {e}")
        return None


# ── Attack Patterns ───────────────────────────────────────────────

def insert_pattern(
    name: str,
    display_name: str,
    category: str,
    subcategory: str,
    description: str,
    indicators: list,
    requirements: list,
    impact: str,
    affected_categories: list,
    mitigations: list,
    confidence_base: float = 0.5,
    avg_severity: str = "high",
) -> Optional[int]:
    try:
        conn = get_connection()
        cur = conn.execute("""
            INSERT OR IGNORE INTO attack_patterns
            (name, display_name, category, subcategory, description,
             indicators, requirements, impact, affected_categories,
             mitigations, confidence_base, avg_severity)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            name, display_name, category, subcategory, description,
            json.dumps(indicators), json.dumps(requirements),
            impact, json.dumps(affected_categories),
            json.dumps(mitigations), confidence_base, avg_severity
        ))
        conn.commit()
        pattern_id = cur.lastrowid
        conn.close()
        return pattern_id
    except Exception as e:
        log.error(f"insert_pattern failed: {e}")
        return None


def get_patterns_for_category(protocol_category: str) -> list:
    """
    Returns attack patterns ranked by priority for a given
    protocol category. This is what the agent queries first
    when it starts investigating a new contract.
    """
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT ap.*, cam.priority, cam.historical_hits
            FROM attack_patterns ap
            JOIN category_attack_map cam ON ap.id = cam.pattern_id
            WHERE cam.protocol_category = ?
            ORDER BY cam.priority ASC, cam.historical_hits DESC
        """, (protocol_category,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"get_patterns_for_category failed: {e}")
        return []


def get_pattern_by_name(name: str) -> Optional[dict]:
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM attack_patterns WHERE name = ?", (name,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        log.error(f"get_pattern_by_name failed: {e}")
        return None


def increment_pattern_occurrence(pattern_id: int):
    try:
        conn = get_connection()
        conn.execute("""
            UPDATE attack_patterns
            SET occurrence_count = occurrence_count + 1,
                updated_at = datetime('now')
            WHERE id = ?
        """, (pattern_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"increment_pattern_occurrence failed: {e}")


# ── Findings ──────────────────────────────────────────────────────

def insert_finding(
    report_id: int,
    title: str,
    severity: str,
    category: str,
    description: str,
    impact: str,
    recommendation: str,
    protocol: str,
    protocol_category: str,
    source: str,
    url: str = "",
    pattern_id: int = None,
    affected_functions: list = None,
    indicators_found: list = None,
    bounty_paid: float = None,
) -> Optional[int]:
    try:
        conn = get_connection()
        cur = conn.execute("""
            INSERT INTO findings
            (report_id, pattern_id, title, severity, category,
             description, impact, recommendation, affected_functions,
             indicators_found, protocol, protocol_category,
             source, url, bounty_paid)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            report_id, pattern_id, title, severity, category,
            description, impact, recommendation,
            json.dumps(affected_functions or []),
            json.dumps(indicators_found or []),
            protocol, protocol_category, source, url, bounty_paid
        ))
        conn.commit()
        finding_id = cur.lastrowid
        conn.close()
        return finding_id
    except Exception as e:
        log.error(f"insert_finding failed: {e}")
        return None


def get_findings_by_pattern(
    pattern_id: int,
    severity: str = None,
    limit: int = 10
) -> list:
    """
    Get real audit findings matching a pattern.
    The agent calls this to get examples before generating a PoC.
    """
    try:
        conn = get_connection()
        if severity:
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE pattern_id = ? AND severity = ?
                ORDER BY bounty_paid DESC NULLS LAST
                LIMIT ?
            """, (pattern_id, severity, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE pattern_id = ?
                ORDER BY bounty_paid DESC NULLS LAST
                LIMIT ?
            """, (pattern_id, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"get_findings_by_pattern failed: {e}")
        return []


def get_findings_by_category(
    protocol_category: str,
    severity: str = None,
    limit: int = 20
) -> list:
    try:
        conn = get_connection()
        if severity:
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE protocol_category = ? AND severity = ?
                ORDER BY bounty_paid DESC NULLS LAST
                LIMIT ?
            """, (protocol_category, severity, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE protocol_category = ?
                ORDER BY bounty_paid DESC NULLS LAST
                LIMIT ?
            """, (protocol_category, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"get_findings_by_category failed: {e}")
        return []


# ── Category Attack Map ───────────────────────────────────────────

def insert_category_map(
    protocol_category: str,
    pattern_id: int,
    priority: int = 5,
    historical_hits: int = 0,
    notes: str = ""
):
    try:
        conn = get_connection()
        conn.execute("""
            INSERT OR IGNORE INTO category_attack_map
            (protocol_category, pattern_id, priority, historical_hits, notes)
            VALUES (?,?,?,?,?)
        """, (protocol_category, pattern_id, priority, historical_hits, notes))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"insert_category_map failed: {e}")


def increment_category_hit(protocol_category: str, pattern_id: int):
    try:
        conn = get_connection()
        conn.execute("""
            UPDATE category_attack_map
            SET historical_hits = historical_hits + 1
            WHERE protocol_category = ? AND pattern_id = ?
        """, (protocol_category, pattern_id))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"increment_category_hit failed: {e}")


# ── Postmortems ───────────────────────────────────────────────────

def insert_postmortem(
    protocol: str,
    protocol_category: str,
    date: str,
    loss_usd: float,
    attack_summary: str,
    root_cause: str,
    entry_point: str,
    chain: str,
    url: str,
    tx_hash: str = "",
    pattern_id: int = None,
) -> Optional[int]:
    try:
        conn = get_connection()
        cur = conn.execute("""
            INSERT INTO postmortems
            (protocol, protocol_category, date, loss_usd, pattern_id,
             attack_summary, root_cause, entry_point, tx_hash, chain, url)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            protocol, protocol_category, date, loss_usd, pattern_id,
            attack_summary, root_cause, entry_point, tx_hash, chain, url
        ))
        conn.commit()
        pm_id = cur.lastrowid
        conn.close()
        return pm_id
    except Exception as e:
        log.error(f"insert_postmortem failed: {e}")
        return None


def get_postmortems_by_pattern(pattern_id: int, limit: int = 5) -> list:
    try:
        conn = get_connection()
        rows = conn.execute("""
            SELECT * FROM postmortems
            WHERE pattern_id = ?
            ORDER BY loss_usd DESC
            LIMIT ?
        """, (pattern_id, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"get_postmortems_by_pattern failed: {e}")
        return []


# ── Ingestion Log ─────────────────────────────────────────────────

def log_ingestion(
    source: str,
    identifier: str,
    status: str,
    findings_added: int = 0,
    error: str = ""
):
    try:
        conn = get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO ingestion_log
            (source, identifier, status, findings_added, error)
            VALUES (?,?,?,?,?)
        """, (source, identifier, status, findings_added, error))
        conn.commit()
        conn.close()
    except Exception as e:
        log.error(f"log_ingestion failed: {e}")


def already_ingested(source: str, identifier: str) -> bool:
    try:
        conn = get_connection()
        row = conn.execute("""
            SELECT id FROM ingestion_log
            WHERE source = ? AND identifier = ? AND status = 'success'
        """, (source, identifier)).fetchone()
        conn.close()
        return row is not None
    except Exception as e:
        log.error(f"already_ingested check failed: {e}")
        return False


# ── Stats ─────────────────────────────────────────────────────────

def get_stats() -> dict:
    try:
        conn = get_connection()
        stats = {
            "reports":   conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
            "patterns":  conn.execute("SELECT COUNT(*) FROM attack_patterns").fetchone()[0],
            "findings":  conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "postmortems": conn.execute("SELECT COUNT(*) FROM postmortems").fetchone()[0],
        }
        conn.close()
        return stats
    except Exception as e:
        log.error(f"get_stats failed: {e}")
        return {}

