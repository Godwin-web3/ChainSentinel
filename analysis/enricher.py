import os
import re
import subprocess
from utils.logger import log

# ─── Auth evidence types (ordered by strength) ────────────────────────────────
# Score: 3=strong, 2=medium, 1=weak
import hashlib

_CACHE_DIR = os.path.expanduser("~/.chainsentinel-cache/printers")

def _cache_key(resolved: dict) -> str:
    addr = resolved.get("address", "unknown").lower()
    chain = str(resolved.get("chain_id", "1"))
    bytecode = resolved.get("bytecode", "")
    bhash = hashlib.md5(bytecode.encode()).hexdigest()[:8]
    return f"{chain}_{addr}_{bhash}"

def _load_printer_cache(key: str, printer: str):
    path = os.path.join(_CACHE_DIR, f"{key}_{printer}.txt")
    if os.path.exists(path):
        return open(path, "r").read()
    return None

def _save_printer_cache(key: str, printer: str, text: str):
    os.makedirs(_CACHE_DIR, exist_ok=True)
    path = os.path.join(_CACHE_DIR, f"{key}_{printer}.txt")
    with open(path, "w") as f:
        f.write(text)

AUTH_MODIFIER_PATTERNS = [
    "onlyOwner", "onlyAdmin", "onlyRole", "onlyGov", "onlyGuardian", "auth",
    "onlyFactoryOwner", "onlyFactory", "onlyPool", "onlyVault", "onlyMinter",
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
            new_entry = {
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
            # Keep richer entry on duplicate keys
            if key not in functions or len(reads) + len(writes) + len(modifiers) >                len(functions[key]["reads"]) + len(functions[key]["writes"]) + len(functions[key]["modifiers"]):
                functions[key] = new_entry

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

    # Strong: require with auth-indicating error string (catches TMP-collapsed comparisons)
    if re.search(r'require.*only.*(admin|owner|gov|guardian|operator)', internal, re.I):
        evidence.append({"type": "require_auth_string", "value": "require with auth error message", "strength": 3})
        score = max(score, 3)

    # Auth signal: layered heuristics
    reads = func.get("reads", [])
    internal = func.get("internal_calls", "")
    PRIV_VARS = {"admin", "owner", "guardian", "operator", "governance",
                 "pendingadmin", "pauseguardian", "timelock", "dao", "wards"}
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
                         "strength": 3})
        score = max(score, 3)
    elif priv_reads:
        # Weak: privileged var read only (may be for config, not auth)
        evidence.append({"type": "priv_var_read",
                         "value": f"reads privileged var {priv_reads}", "strength": 0})
    elif has_sender and score == 0:
        # Neutral: msg.sender read only — not auth evidence alone
        evidence.append({"type": "sender_read",
                         "value": "msg.sender read present", "strength": 0})
        # score unchanged

    NOISE = {"sender_read", "priv_var_read"}
    filtered = [e for e in evidence if e["type"] not in NOISE]
    has_auth_gate = score >= 3
    has_partial_signal = score >= 2
    conflict = len(filtered) > 1 and has_partial_signal and not has_auth_gate

    if has_auth_gate:
        auth_state = "AUTHENTICATED"
    elif conflict:
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
    CRYPTO_PRIMITIVES = {"abi.encode", "abi.encodepacked", "keccak256", "ecrecover", "sha256", "ripemd160", "fullmath", "safemath", "math", "safeerc20", "address(", "fixedpoint128", "fixedpoint96", "tickmath", "liquiditymath", "swapmath", "bitmath"}
    ext = func.get("external_calls", "[]")
    if isinstance(ext, str):
        ext = ext.strip()
        if ext in ("", "[]", "['']"):
            real_ext = []
        else:
            import ast
            try:
                parsed = ast.literal_eval(ext)
                real_ext = [e for e in parsed if not any(p in e.lower() for p in CRYPTO_PRIMITIVES)]
            except:
                real_ext = [] if any(p in ext.lower() for p in CRYPTO_PRIMITIVES) else [ext]
    elif isinstance(ext, list):
        real_ext = [e for e in ext if not any(p in e.lower() for p in CRYPTO_PRIMITIVES)]
    else:
        real_ext = []
    has_write = bool(func.get("writes", []))
    return bool(real_ext) and has_write

# ─── Main enricher ────────────────────────────────────────────────────────────

def extract_source_auth(project_root: str, func_name: str) -> list:
    """
    Scan source files for require(msg.sender == X) patterns.
    Fallback for when vars-and-auth printer loses comparisons to TMP variables.
    Returns list of condition strings like ["msg.sender == owner"].
    """
    import glob
    bare_name = func_name.split("(")[0].strip()
    patterns = [
        re.compile(r'require\s*\(\s*msg\.sender\s*==\s*(\w+)', re.I),
        re.compile(r'require\s*\(\s*(\w+)\s*==\s*msg\.sender', re.I),
    ]
    conditions = []
    in_func = False
    brace_depth = 0

    sol_files = glob.glob(os.path.join(project_root, "**", "*.sol"), recursive=True)
    for filepath in sol_files:
        try:
            with open(filepath, "r", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue

        for i, line in enumerate(lines):
            # Detect function start
            if re.search(rf'\bfunction\s+{re.escape(bare_name)}\b', line):
                in_func = True
                brace_depth = 0

            if in_func:
                brace_depth += line.count("{") - line.count("}")
                for pat in patterns:
                    m = pat.search(line)
                    if m:
                        var = m.group(1)
                        cond = f"msg.sender == {var}"
                        if cond not in conditions:
                            conditions.append(cond)
                if brace_depth <= 0 and "{" in "".join(lines[max(0,i-5):i+1]):
                    in_func = False

    return conditions


def _detect_framework(project_root):
    if os.path.exists(os.path.join(project_root, "foundry.toml")):
        return "foundry"
    if os.path.exists(os.path.join(project_root, "hardhat.config.js")) or \
       os.path.exists(os.path.join(project_root, "hardhat.config.ts")):
        return "hardhat"
    if os.path.exists(os.path.join(project_root, "truffle-config.js")):
        return "truffle"
    return "solc"

def run_enricher(resolved: dict, project_root: str, entry_file: str, solc_version: str) -> dict:
    """
    Run Slither printers and build function feature table.
    Returns structured enrichment data keyed by function.
    """
    env = os.environ.copy()
    if solc_version:
        env["SOLC_VERSION"] = solc_version

    try:
        entry_rel = os.path.relpath(entry_file, os.path.dirname(project_root))
    except ValueError:
        entry_rel = entry_file

    # Match solc args exactly with slither_runner.py
    try:
        major, minor, patch = (int(x) for x in solc_version.split(".")[:3])
        use_ir = (major, minor) >= (0, 8) and patch >= 13
    except Exception:
        use_ir = False
    solc_extra = " --via-ir --optimize" if use_ir else ""

    remappings = resolved.get("remappings", [])
    base_cmd = [
        "slither", entry_rel,
        "--solc", "solc-wrapper",
        "--solc-args", f"--allow-paths {project_root}{solc_extra}",
    ]
    base_cmd += ["--compile-force-framework", _detect_framework(project_root)]
    if remappings:
        base_cmd += ["--solc-remaps", " ".join(remappings[:50])]

    # Run function-summary
        log.debug(f"Enricher: project_root={project_root} dirname={os.path.dirname(project_root)}")
        log.debug(f"Enricher: base_cmd={base_cmd}")
    log.debug("Enricher: running function-summary printer")
    _ckey = _cache_key(resolved)
    _summary_cached = _load_printer_cache(_ckey, "function-summary")
    try:
        if _summary_cached is not None:
            log.debug("Enricher: function-summary cache hit")
            _summary_text = _summary_cached
        else:
            r1 = subprocess.run(
                base_cmd + ["--print", "function-summary"],
                capture_output=True, text=True, timeout=900,
                env=env, cwd=os.path.dirname(project_root)
            )
            _summary_text = r1.stderr + r1.stdout
            log.debug(f"Enricher: returncode={r1.returncode}")
            log.debug(f"Enricher: printer full output:\n{_summary_text}")
            _save_printer_cache(_ckey, "function-summary", _summary_text)
        func_data = parse_function_summary(_summary_text)
        log.debug(f"Enricher: parsed {len(func_data)} functions")
    except Exception as e:
        log.warn(f"Enricher function-summary failed: {e}")
        func_data = {}

    # Run vars-and-auth
    log.debug("Enricher: running vars-and-auth printer")
    _auth_cached = _load_printer_cache(_ckey, "vars-and-auth")
    try:
        if _auth_cached is not None:
            log.debug("Enricher: vars-and-auth cache hit")
            _auth_text = _auth_cached
        else:
            r2 = subprocess.run(
                base_cmd + ["--print", "vars-and-auth"],
                capture_output=True, text=True, timeout=900,
                env=env, cwd=os.path.dirname(project_root)
            )
            _auth_text = r2.stderr + r2.stdout
            _save_printer_cache(_ckey, "vars-and-auth", _auth_text)
        auth_data = parse_vars_and_auth(_auth_text)
        log.debug(f"Enricher: parsed {len(auth_data)} auth entries")
    except Exception as e:
        log.warn(f"Enricher vars-and-auth failed: {e}")
        auth_data = {}

    # Merge into feature table
    features = {}
    for key, func in func_data.items():
        auth = auth_data.get(key, {})

        # Source fallback: recover lost msg.sender comparisons
        # Only triggers when printer saw msg.sender but lost the comparison to TMP
        if (not auth.get("msg_sender_conditions") and
                "msg.sender" in func.get("reads", [])):
            recovered = extract_source_auth(project_root, func.get("name", ""))
            if recovered:
                # Filter: only accept if variable is a known priv var
                PRIV_VARS = {"admin", "owner", "guardian", "operator",
                             "governance", "pendingadmin", "pauseguardian",
                             "timelock", "dao"}
                filtered = [c for c in recovered
                            if c.split("== ")[-1].lower() in PRIV_VARS]
                if filtered:
                    auth = dict(auth)
                    auth["msg_sender_conditions"] = filtered
                    auth["source_auth_fallback"] = True

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


    # DEBUG DUMP
    import json as _json
    with open('/root/enricher_debug.json', 'w') as _f:
        _json.dump({"features": features, "high_priority": high_priority}, _f, indent=2)

    return {
        "success": True,
        "features": features,
        "high_priority_functions": high_priority,
        "total_functions": len(features),
        "entry_points": [k for k, v in features.items() if v["is_entry_point"]],
    }
