import os
import logging
from knowledge.ingestion.parsers.markdown_parser import parse_directory
from knowledge.storage.db.database import insert_report, insert_finding, get_connection

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

RAW_MD_DIR = "knowledge/storage/raw/markdown"


def _extract_protocol(source_file: str) -> str:
    name = source_file.replace("code4rena_", "").replace(".md", "")
    parts = name.split("_")
    return parts[0] if parts else "unknown"


def _count_severities(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _get_report_id_by_path(raw_path: str):
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT id FROM reports WHERE raw_path = ?", (raw_path,)
        ).fetchone()
        conn.close()
        return row["id"] if row else None
    except Exception as e:
        log.error(f"_get_report_id_by_path failed: {e}")
        return None


def _findings_exist(report_id: int) -> bool:
    try:
        conn = get_connection()
        count = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE report_id = ?", (report_id,)
        ).fetchone()[0]
        conn.close()
        return count > 0
    except Exception as e:
        log.error(f"_findings_exist failed: {e}")
        return False


def run():
    log.info(f"Starting pipeline on {RAW_MD_DIR}")
    findings = parse_directory(RAW_MD_DIR)
    log.info(f"{len(findings)} findings parsed")

    grouped = {}
    for f in findings:
        src = f.get("source_file", "unknown")
        grouped.setdefault(src, []).append(f)

    total_inserted = 0

    for source_file, file_findings in grouped.items():
        protocol = _extract_protocol(source_file)
        counts = _count_severities(file_findings)
        raw_path = os.path.join(RAW_MD_DIR, source_file)

        report_id = insert_report(
            source="code4rena",
            protocol=protocol,
            protocol_category="defi",
            date="",
            url=raw_path,
            raw_path=raw_path,
            file_format="markdown",
            total_findings=len(file_findings),
            critical_count=counts["critical"],
            high_count=counts["high"],
            medium_count=counts["medium"],
        )

        if not report_id:
            report_id = _get_report_id_by_path(raw_path)

        if not report_id:
            log.warning(f"Could not resolve report_id for {source_file}, skipping")
            continue

        if _findings_exist(report_id):
            log.info(f"Findings already exist for report {report_id}, skipping")
            continue

        for f in file_findings:
            fid = insert_finding(
                report_id=report_id,
                title=f.get("title", ""),
                severity=f.get("severity", ""),
                category=f.get("category", ""),
                description=f.get("description", ""),
                impact=f.get("impact", ""),
                recommendation=f.get("recommendation", ""),
                protocol=protocol,
                protocol_category="defi",
                source="code4rena",
                url="",
                affected_functions=f.get("affected_functions", []),
            )
            if fid:
                total_inserted += 1

    log.info(f"Done. {total_inserted} findings written to DB.")


if __name__ == "__main__":
    run()
