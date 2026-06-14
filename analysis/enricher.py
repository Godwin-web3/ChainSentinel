import os
import re
import subprocess
from utils.logger import log

# ─── Auth evidence types (ordered by strength) ────────────────────────────────
# Score: 3=strong, 2=medium, 1=weak
AUTH_MODIFIER_PATTERNS = [
    "onlyOwner", "onlyAdmin", "onlyRole", "onlyGov", "onlyGuardian",
    "onlyOperator", "onlyMinter", "onlyBurner", "onlyVault", "onlyKeeper",
    "onlyExecutor", "onlyTimelock", "onlyDAO", "onlyWhitelisted",
    "nonReentrant", "whenNotPaused", "whenPaused",
]

AUTH_REQUIRE_RE = re.compile(
    r'require\s*\(\s*msg\.sender|msg\.sender\s*==|hasRole|isOwner|_onlyOwner|_checkRole',
    re.I
)

ASSET_TRANSFER_RE = re.compile(
    r'transfer\(|transferFrom\(|safeTransfer\(|safeTransferFrom\(|call\{value|send\(',
    re.I
)

STATE_WRITE_RE = re.compile(r'\w+\s*=\s*(?!.*==)', re.I)

# ─── Parser: function-summary printer output ──────────────────────────────────
def parse_function_summary(text: str) -> dict:
    """
    Parse Slither function-summary printer output.
    Returns dict keyed by 'ContractName.function_name'
    """
    functions = {}
    current_contract = None

    for line in text.splitlines():
        # Detect contract header
        contract_match = re.match(r'^Contract\s+(\w+)', line)
        if contract_match:
            current_contract = contract_match.group(1)
            continue

        # Parse table rows (skip headers and separators)
        if not current_contract:
            continue
        if line.startswith('+') or line.startswith('|  Function') or line.startswith('| Function'):
            continue

        # Match data rows
        row_match = re.match(r'\|\s*(.+?)\s*\|\s*(\w+)\s*\|\s*\[([^\]]*)\]\s*\|\s*\[([^\]]*)\]\s*\|\s*\[([^\]]*)\]\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|', line)
        if row_match:
            func_name = row_match.group(1).strip()
            visibility = row_match.group(2).strip()
            modifiers_raw = row_match.group(3).strip()
            reads_raw = row_match.group(4).strip()
            writes_raw = row_match.group(5).strip()
            internal_calls_raw = row_match.group(6).strip()
            external_calls_raw = row_match.group(7).strip()

            modifiers = [m.strip().strip("'") for m in modifiers_raw.split(',') if m.strip()]
            reads = [r.strip().strip("'") for r in reads_raw.split(',') if r.strip()]
            writes = [w.strip().strip("'") for w in writes_raw.split(',') if w.strip()]

            key = f"{current_contract}.{func_name}"
            functions[key] = {
                "contract": current_contract,
                "name": func_name,
                "visibility": visibility,
                "modifiers": modifiers,
                "reads": reads,
                "writes": writes,
                "internal_calls": internal_calls_raw,
                "external_calls": external_calls_raw,
                "is_entry_point": visibility in ("public", "external"),
                "is_view": False,  # refined below
            }

    return functions

# ─── Parser: vars-and-auth printer output ────────────────────────────────────
def parse_vars_and_auth(text: str) -> dict:
    """
    Parse Slither vars-and-auth printer output.
    Returns dict keyed by 'ContractName.function_name' with auth evidence.
    """
    auth_data = {}
    current_contract = None

    for line in text.splitlines():
        contract_match = re.match(r'^Contract\s+(\w+)', line)
        if contract_match:
            current_contract = contract_match.group(1)
            continue

        if not current_contract:
            continue
        if line.startswith('+') or 'State variables' in line:
            continue

        row_match = re.match(r'\|\s*(.+?)\s*\|\s*\[([^\]]*)\]\s*\|\s*\[([^\]]*)\]\s*\|', line)
        if row_match:
            func_name = row_match.group(1).strip()
            state_written = row_match.group(2).strip()
            msg_sender_conditions = row_match.group(3).strip()

            key = f"{current_contract}.{func_name}"
            auth_data[key] = {
                "state_written": [s.strip().strip("'") for s in state_written.split(',') if s.strip()],
                "msg_sender_conditions": [c.strip() for c in msg_sender_conditions.split(',') if c.strip()],
            }

    return auth_data

# ─── Auth scorer ──────────────────────────────────────────────────────────────
def score_auth(func: dict, auth: dict) -> dict:
    """
    Build auth_evidence list and auth_score for a function.
    Score: 0=none, 1=weak, 2=medium, 3=strong
    """
    evidence = []
    score = 0

    # Strong: explicit auth modifiers
    for mod in func.get("modifiers", []):
        for pattern in AUTH_MODIFIER_PATTERNS:
            if pattern.lower() in mod.lower():
                if mod.lower() in ("nonreentrant", "whennotpaused", "whenpaused"):
                    evidence.append({"type": "guard_modifier", "value": mod, "strength": 2})
                    score = max(score, 2)
                else:
                    evidence.append({"type": "auth_modifier", "value": mod, "strength": 3})
                    score = max(score, 3)
                break

    # Strong: msg.sender conditions from vars-and-auth
    for cond in auth.get("msg_sender_conditions", []):
        if cond:
            evidence.append({"type": "msg_sender_check", "value": cond, "strength": 3})
            score = max(score, 3)

    # Medium: internal calls that look like auth gates
    internal = func.get("internal_calls", "")
    if re.search(r'onlyOwner|onlyAdmin|_checkRole|_onlyOwner|require.*owner', internal, re.I):
        evidence.append({"type": "internal_auth_call", "value": "internal auth gate detected", "strength": 2})
        score = max(score, 2)

    # Auth signal: layered heuristics
    reads = func.get("reads", [])
    internal = func.get("internal_calls", "")
    PRIV_VARS = {"admin", "owner", "guardian", "operator", "governance",
                 "pendingadmin", "pauseguardian", "timelock", "dao"}
    priv_reads = [r for r in reads if r.lower().split('.')[-1] in PRIV_VARS]
    has_sender = "msg.sender" in reads
    has_fail_path = bool(re.search(
        r'\bfail\(', internal, re.I
    ))

    if has_sender and priv_reads:
        # Strong: explicit msg.sender + privileged var co-read
        evidence.append({"type": "inline_sender_check",
                         "value": f"reads msg.sender + {priv_reads}", "strength": 3})
        score = max(score, 3)
    elif priv_reads and has_fail_path:
        # Medium: privileged var read + failure/revert path (Compound early-return style)
        evidence.append({"type": "priv_var_fail_path",
                         "value": f"reads {priv_reads} + failure path in internal calls",
                         "strength": 2})
        score = max(score, 2)
    elif priv_reads:
        # Weak: privileged var read only (may be for config, not auth)
        evidence.append({"type": "priv_var_read",
                         "value": f"reads privileged var {priv_reads}", "strength": 0})
    elif has_sender and score == 0:
        # Weak: msg.sender read only (may be logging or fee routing)
        evidence.append({"type": "sender_read",
                         "value": "msg.sender read present", "strength": 1})
        score = max(score, 1)

    if score >= 2:
        auth_state = "AUTHENTICATED"
    elif score >= 1 or evidence:
        auth_state = "UNKNOWN"
    else:
        auth_state = "UNAUTHENTICATED"

    return {
        "auth_evidence": evidence,
        "auth_score": score,
        "auth_state": auth_state,
        "has_auth": score >= 2,  # kept for backwards compat
    }

# ─── Asset flow detector ─────────────────────────────────────────────────────
def detect_asset_flow(func: dict) -> list:
    """Detect token/ETH transfer patterns in external calls."""
    flows = []
    external = func.get("external_calls", "")

    if re.search(r'transfer\(|safeTransfer\(', external, re.I):
        flows.append("ERC20_TRANSFER")
    if re.search(r'transferFrom\(|safeTransferFrom\(', external, re.I):
        flows.append("ERC20_TRANSFER_FROM")
    if re.search(r'call\{value|\.send\(|\.transfer\(', external, re.I):
        flows.append("ETH_SEND")

    return flows

# ─── Dangerous ordering detector ─────────────────────────────────────────────
def detect_dangerous_ordering(func: dict) -> bool:
    """
    Detect external call before state write pattern.
    This is a structural signal, not a confirmed exploit.
    Requires manual verification of call trust.
    """
    ext = func.get("external_calls", "[]")
    if isinstance(ext, str):
        ext = ext.strip()
        has_external = ext not in ("", "[]", "['']")
    else:
        has_external = bool(ext)
    has_write = bool(func.get("writes", []))
    return has_external and has_write

# ─── Main enricher ────────────────────────────────────────────────────────────
def run_enricher(resolved: dict, project_root: str, entry_file: str, solc_version: str) -> dict:
    """
    Run Slither printers and build function feature table.
    Returns structured enrichment data keyed by function.
    """
    env = os.environ.copy()
    if solc_version:
        env["SOLC_VERSION"] = solc_version

    try:
        entry_rel = os.path.relpath(entry_file, project_root)
    except ValueError:
        entry_rel = entry_file

    base_cmd = [
        "slither", entry_rel,
        "--solc", "solc-wrapper",
        "--solc-args", f"--allow-paths {project_root}",
    ]
    remappings = resolved.get("remappings", [])
    if remappings:
        base_cmd += ["--solc-remaps", " ".join(remappings)]

    # Run function-summary
    log.debug("Enricher: running function-summary printer")
    try:
        r1 = subprocess.run(
            base_cmd + ["--print", "function-summary"],
            capture_output=True, text=True, timeout=360,
            env=env, cwd=project_root
        )
        func_data = parse_function_summary(r1.stderr + r1.stdout)
        log.debug(f"Enricher: parsed {len(func_data)} functions")
    except Exception as e:
        log.warn(f"Enricher function-summary failed: {e}")
        func_data = {}

    # Run vars-and-auth
    log.debug("Enricher: running vars-and-auth printer")
    try:
        r2 = subprocess.run(
            base_cmd + ["--print", "vars-and-auth"],
            capture_output=True, text=True, timeout=360,
            env=env, cwd=project_root
        )
        auth_data = parse_vars_and_auth(r2.stderr + r2.stdout)
        log.debug(f"Enricher: parsed {len(auth_data)} auth entries")
    except Exception as e:
        log.warn(f"Enricher vars-and-auth failed: {e}")
        auth_data = {}

    # Merge into feature table
    features = {}
    for key, func in func_data.items():
        auth = auth_data.get(key, {})
        auth_result = score_auth(func, auth)
        asset_flows = detect_asset_flow(func)
        dangerous_order = detect_dangerous_ordering(func)

        features[key] = {
            **func,
            **auth_result,
            "asset_flows": asset_flows,
            "dangerous_ordering": dangerous_order,
            "state_written": auth.get("state_written", []),
            "msg_sender_conditions": auth.get("msg_sender_conditions", []),
        }

    # Fix vars. prefix -- real contract name from resolved or first non-vars key
    for k, v in features.items():
        if v.get("contract") == "vars":
            v["contract"] = "unknown"

    # Entry points with no auth and asset movement -- highest priority
    # Exclude constructors (not attacker-reachable post-deploy)
    high_priority = [
        v for k, v in features.items()
        if v["is_entry_point"]
        and v.get("auth_state", "UNAUTHENTICATED") == "UNAUTHENTICATED"
        and (v["asset_flows"] or v["dangerous_ordering"])
        and v.get("visibility") not in ("view", "pure")
        and not v["name"].startswith("constructor")
        and not v["name"].startswith("initialize")
    ]

    log.debug(f"Enricher: {len(high_priority)} high-priority functions")

    return {
        "success": True,
        "features": features,
        "high_priority_functions": high_priority,
        "total_functions": len(features),
        "entry_points": [k for k, v in features.items() if v["is_entry_point"]],
    }
