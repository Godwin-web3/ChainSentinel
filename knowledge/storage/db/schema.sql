-- ============================================================
-- ChainSentinel Knowledge Base Schema
-- ============================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ── Reports: source audit documents ─────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,        -- "code4rena", "sherlock", "spearbit", etc
    protocol        TEXT,                 -- "Aave", "Uniswap", etc
    protocol_category TEXT,              -- "lending", "dex", "bridge", etc
    date            TEXT,                 -- ISO date string
    url             TEXT,                 -- original URL or GitHub link
    raw_path        TEXT,                 -- local path to raw file
    file_format     TEXT,                 -- "markdown", "pdf", "html"
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    ingested_at     TEXT DEFAULT (datetime('now')),
    UNIQUE(url)
);

-- ── Attack patterns: reusable exploit primitives ─────────────
CREATE TABLE IF NOT EXISTS attack_patterns (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE, -- "cross-function-reentrancy"
    display_name     TEXT NOT NULL,        -- "Cross-Function Reentrancy"
    category         TEXT NOT NULL,        -- "reentrancy", "oracle", "access_control"
    subcategory      TEXT,                 -- "read-only-reentrancy", "price-manipulation"
    description      TEXT,
    indicators       TEXT NOT NULL,        -- JSON array of code signals
    requirements     TEXT,                 -- JSON array of conditions needed
    impact           TEXT,                 -- "drain funds", "price manipulation"
    affected_categories TEXT,             -- JSON array: ["lending", "vault", "dex"]
    mitigations      TEXT,                -- JSON array of fixes
    confidence_base  REAL DEFAULT 0.5,    -- base confidence 0.0-1.0
    occurrence_count INTEGER DEFAULT 0,   -- how many times seen in audits
    avg_severity     TEXT,                -- most common severity
    created_at       TEXT DEFAULT (datetime('now')),
    updated_at       TEXT DEFAULT (datetime('now'))
);

-- ── Findings: individual vulnerabilities from reports ────────
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id        INTEGER NOT NULL,
    pattern_id       INTEGER,             -- NULL if novel/unclassified
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,       -- "critical", "high", "medium", "low"
    category         TEXT,               -- "reentrancy", "oracle", etc
    description      TEXT,
    impact           TEXT,
    recommendation   TEXT,
    affected_functions TEXT,             -- JSON array of function names
    indicators_found TEXT,              -- JSON array of signals found in this finding
    protocol         TEXT,
    protocol_category TEXT,
    source           TEXT,              -- which audit firm / platform
    url              TEXT,              -- direct link to finding
    bounty_paid      REAL,             -- USD if known
    created_at       TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (report_id) REFERENCES reports(id),
    FOREIGN KEY (pattern_id) REFERENCES attack_patterns(id)
);

-- ── Exploit primitives: atomic building blocks ───────────────
CREATE TABLE IF NOT EXISTS exploit_primitives (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id       INTEGER NOT NULL,
    primitive        TEXT NOT NULL,       -- "external_call_before_state_update"
    description      TEXT,
    code_signal      TEXT,               -- what to look for in source
    slither_check    TEXT,               -- matching slither detector if any
    context          TEXT,               -- when this primitive applies
    FOREIGN KEY (pattern_id) REFERENCES attack_patterns(id)
);

-- ── Category attack map: what to hunt per protocol type ──────
CREATE TABLE IF NOT EXISTS category_attack_map (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol_category TEXT NOT NULL,     -- "lending", "bridge", "dex"
    pattern_id       INTEGER NOT NULL,
    priority         INTEGER DEFAULT 5,  -- 1=highest, 10=lowest
    historical_hits  INTEGER DEFAULT 0,  -- confirmed bugs found via this pattern
    notes            TEXT,
    FOREIGN KEY (pattern_id) REFERENCES attack_patterns(id),
    UNIQUE(protocol_category, pattern_id)
);

-- ── Postmortems: real exploit analyses ───────────────────────
CREATE TABLE IF NOT EXISTS postmortems (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol         TEXT NOT NULL,
    protocol_category TEXT,
    date             TEXT,
    loss_usd         REAL,
    pattern_id       INTEGER,
    attack_summary   TEXT,
    root_cause       TEXT,
    entry_point      TEXT,              -- function that was exploited
    tx_hash          TEXT,             -- onchain proof
    chain            TEXT,
    url              TEXT,
    FOREIGN KEY (pattern_id) REFERENCES attack_patterns(id)
);

-- ── Ingestion log: track what has been processed ─────────────
CREATE TABLE IF NOT EXISTS ingestion_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source           TEXT NOT NULL,
    identifier       TEXT NOT NULL,     -- repo name, URL, filename
    status           TEXT NOT NULL,     -- "success", "failed", "skipped"
    findings_added   INTEGER DEFAULT 0,
    error            TEXT,
    processed_at     TEXT DEFAULT (datetime('now')),
    UNIQUE(source, identifier)
);

-- ── Indexes ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_findings_pattern    ON findings(pattern_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category   ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_protocol_cat ON findings(protocol_category);
CREATE INDEX IF NOT EXISTS idx_category_map_cat    ON category_attack_map(protocol_category);
CREATE INDEX IF NOT EXISTS idx_category_map_priority ON category_attack_map(priority);
CREATE INDEX IF NOT EXISTS idx_patterns_category   ON attack_patterns(category);
CREATE INDEX IF NOT EXISTS idx_postmortems_pattern ON postmortems(pattern_id);


-- ── Exploit sequences: step-by-step attack chains ────────────
CREATE TABLE IF NOT EXISTS exploit_sequences (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id       INTEGER NOT NULL,
    step_order       INTEGER NOT NULL,   -- 1, 2, 3...
    step_name        TEXT NOT NULL,      -- "Borrow Flash Loan"
    step_description TEXT,              -- what happens at this step
    code_signal      TEXT,              -- what to look for in source
    slither_check    TEXT,              -- matching slither detector if any
    is_optional      INTEGER DEFAULT 0, -- 1 if step can be skipped
    FOREIGN KEY (pattern_id) REFERENCES attack_patterns(id)
);

CREATE INDEX IF NOT EXISTS idx_sequences_pattern ON exploit_sequences(pattern_id);
CREATE INDEX IF NOT EXISTS idx_sequences_order   ON exploit_sequences(pattern_id, step_order);
