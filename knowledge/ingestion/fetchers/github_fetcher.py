"""
knowledge/ingestion/fetchers/github_fetcher.py
Pulls audit reports from GitHub repos: Code4rena, Sherlock, Spearbit, others.
Saves raw markdown/PDF to knowledge/storage/raw/
Logs every fetch to ingestion_log to avoid duplicates.
"""

import os
import time
import requests
from utils.logger import log
from knowledge.storage.db.database import already_ingested, log_ingestion

RAW_MD_DIR  = "knowledge/storage/raw/markdown"
RAW_PDF_DIR = "knowledge/storage/raw/pdfs"

GITHUB_API   = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "ChainSentinel-KB/1.0",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

# Orgs where every repo is an audit contest
CONTEST_ORGS = [
    {"source": "code4rena",  "org": "code-423n4"},
    {"source": "sherlock",   "org": "sherlock-audit"},
]

# Orgs with a single portfolio repo
PORTFOLIO_REPOS = [
    {
        "source":    "spearbit",
        "org":       "spearbit",
        "repo":      "portfolio",
        "exts":      [".pdf", ".md"],
        "max_files": 100,
    },
    {
        "source":    "openzeppelin",
        "org":       "OpenZeppelin",
        "repo":      "security-audits",
        "exts":      [".md", ".pdf"],
        "max_files": 100,
    },
]


def _api_get(url: str):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 403:
            log.warn("Rate limited. Waiting 60s...")
            time.sleep(60)
            resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 404:
            log.warn(f"Not found: {url}")
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.error(f"API request failed: {e}")
        return None


def _list_org_repos(org: str, max_repos: int = 500) -> list:
    """List all repos in an org, paginated."""
    repos = []
    page = 1
    while len(repos) < max_repos:
        url = f"{GITHUB_API}/orgs/{org}/repos?per_page=100&page={page}&sort=updated"
        data = _api_get(url)
        if not data or not isinstance(data, list) or len(data) == 0:
            break
        repos.extend(data)
        page += 1
        time.sleep(0.5)
    return repos[:max_repos]


def _list_repo_tree(org: str, repo: str) -> list:
    """Get full file tree via Git Trees API."""
    repo_data = _api_get(f"{GITHUB_API}/repos/{org}/{repo}")
    if not repo_data:
        return []
    branch = repo_data.get("default_branch", "main")
    result = _api_get(
        f"{GITHUB_API}/repos/{org}/{repo}/git/trees/{branch}?recursive=1"
    )
    if not result:
        return []
    return result.get("tree", [])


def _download_file(
    org: str,
    repo: str,
    file_path: str,
    source: str,
) -> str | None:
    identifier = f"{org}/{repo}/{file_path}"

    if already_ingested(source, identifier):
        return None

    for branch in ["main", "master"]:
        raw_url = f"https://raw.githubusercontent.com/{org}/{repo}/{branch}/{file_path}"
        try:
            resp = requests.get(raw_url, headers=HEADERS, timeout=30)
            if resp.status_code == 200:
                break
        except Exception:
            continue
    else:
        log_ingestion(source, identifier, "failed", error="not found on main or master")
        return None

    try:
        safe_name = (
            f"{source}_{repo}_{file_path}"
            .replace("/", "_")
            .replace(" ", "_")
        )[:200]

        if file_path.endswith(".pdf"):
            dest_path = os.path.join(RAW_PDF_DIR, safe_name)
        else:
            dest_path = os.path.join(RAW_MD_DIR, safe_name)

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(resp.content)

        log_ingestion(source, identifier, "success")
        log.success(f"Saved: {safe_name[:80]}")
        return dest_path

    except Exception as e:
        log_ingestion(source, identifier, "failed", error=str(e))
        log.error(f"Save failed {identifier}: {e}")
        return None


def fetch_contest_org(source: str, org: str, max_repos: int = 200) -> dict:
    """
    Fetch findings from all contest repos in an org.
    Each repo is one audit contest.
    """
    log.section(f"Fetching contest org: {source} ({org})")

    repos = _list_org_repos(org, max_repos)
    log.info(f"Found {len(repos)} repos in {org}")

    total = 0
    for repo_data in repos:
        repo = repo_data["name"]

        # Skip non-audit repos
        if repo in ["code423n4.com", ".github", "website"]:
            continue

        tree = _list_repo_tree(org, repo)
        if not tree:
            continue

        # Only grab markdown findings files
        files = [
            item["path"] for item in tree
            if item.get("type") == "blob"
            and (item["path"].endswith(".md") or item["path"].endswith(".pdf"))
            and any(kw in item["path"].lower() for kw in [
                "finding", "report", "audit", "vuln", "bug", "issue", "high", "medium"
            ])
        ]

        if not files:
            # Fallback: grab all .md files in repo root
            files = [
                item["path"] for item in tree
                if item.get("type") == "blob"
                and item["path"].endswith(".md")
                and "/" not in item["path"]
            ][:5]

        for file_path in files[:20]:
            result = _download_file(org, repo, file_path, source)
            if result:
                total += 1
            time.sleep(0.3)

        time.sleep(0.5)

    log.success(f"{source}: {total} files downloaded")
    return {source: total}


def fetch_portfolio_repo(config: dict) -> dict:
    """Fetch from a single portfolio-style repo."""
    source = config["source"]
    org    = config["org"]
    repo   = config["repo"]
    exts   = config.get("exts", [".md"])
    max_f  = config.get("max_files", 100)

    log.section(f"Fetching portfolio: {source} ({org}/{repo})")

    tree = _list_repo_tree(org, repo)
    if not tree:
        return {source: 0}

    files = [
        item["path"] for item in tree
        if item.get("type") == "blob"
        and any(item["path"].endswith(e) for e in exts)
    ][:max_f]

    log.info(f"Found {len(files)} files in {org}/{repo}")

    total = 0
    for file_path in files:
        result = _download_file(org, repo, file_path, source)
        if result:
            total += 1
        time.sleep(0.3)

    log.success(f"{source}: {total} files downloaded")
    return {source: total}


def fetch_all() -> dict:
    summary = {}

    for cfg in CONTEST_ORGS:
        result = fetch_contest_org(cfg["source"], cfg["org"])
        summary.update(result)
        time.sleep(2)

    for cfg in PORTFOLIO_REPOS:
        result = fetch_portfolio_repo(cfg)
        summary.update(result)
        time.sleep(2)

    log.section("Fetch Complete")
    for source, count in summary.items():
        log.info(f"  {source}: {count} files")

    return summary


def fetch_single(source_name: str):
    for cfg in CONTEST_ORGS:
        if cfg["source"] == source_name:
            return fetch_contest_org(cfg["source"], cfg["org"])
    for cfg in PORTFOLIO_REPOS:
        if cfg["source"] == source_name:
            return fetch_portfolio_repo(cfg)
    log.error(f"Unknown source: {source_name}")
    log.info(f"Available: {[c['source'] for c in CONTEST_ORGS + PORTFOLIO_REPOS]}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        fetch_single(sys.argv[1])
    else:
        fetch_all()
