import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "storage" / "db" / "chainsentinel.db"

CATEGORY_MAP = {
    "reentrancy": ["reentrancy-eth", "reentrancy-token", "read-only-reentrancy"],
    "oracle": ["flash-loan-oracle-manipulation", "price-manipulation-twap"],
    "access_control": ["access-control-missing"],
    "access control": ["access-control-missing"],
    "proxy": ["controlled-delegatecall"],
    "delegatecall": ["controlled-delegatecall"],
    "arithmetic": ["integer-overflow", "precision-loss"],
    "overflow": ["integer-overflow"],
    "precision": ["precision-loss"],
    "flash_loan": ["flash-loan-attack", "flash-loan-oracle-manipulation"],
    "flash loan": ["flash-loan-attack", "flash-loan-oracle-manipulation"],
    "bridge": ["bridge-message-replay"],
    "governance": ["governance-flash-loan"],
    "vault": ["vault-inflation-attack"],
    "erc4626": ["vault-inflation-attack"],
    "liquidation": ["liquidation-manipulation"],
    "token": ["unchecked-return-value"],
    "return value": ["unchecked-return-value"],
}

INDICATOR_MAP = {
    "call.value": "reentrancy-eth",
    "receive()": "reentrancy-eth",
    "fallback()": "reentrancy-eth",
    "balance before": "reentrancy-eth",
    "erc777": "reentrancy-token",
    "tokensreceived": "reentrancy-token",
    "onerc1155received": "reentrancy-token",
    "get_virtual_price": "read-only-reentrancy",
    "read-only": "read-only-reentrancy",
    "getreserves": "flash-loan-oracle-manipulation",
    "spot price": "flash-loan-oracle-manipulation",
    "twap": "price-manipulation-twap",
    "consult(": "price-manipulation-twap",
    "onlyowner": "access-control-missing",
    "no access control": "access-control-missing",
    "unprotected": "access-control-missing",
    "initialize": "access-control-missing",
    "delegatecall": "controlled-delegatecall",
    "unchecked": "integer-overflow",
    "safeMath": "integer-overflow",
    "divide-before-multiply": "precision-loss",
    "rounding": "precision-loss",
    "flashloan": "flash-loan-attack",
    "flash loan": "flash-loan-attack",
    "replay": "bridge-message-replay",
    "nonce": "bridge-message-replay",
    "processedmessages": "bridge-message-replay",
    "snapshot": "governance-flash-loan",
    "voting power": "governance-flash-loan",
    "timelock": "governance-flash-loan",
    "totalassets": "vault-inflation-attack",
    "first depositor": "vault-inflation-attack",
    "virtual shares": "vault-inflation-attack",
    "liquidation bonus": "liquidation-manipulation",
    "collateral price": "liquidation-manipulation",
    "transfer(": "unchecked-return-value",
    "transferfrom(": "unchecked-return-value",
    "safeerc20": "unchecked-return-value",
    "return value": "unchecked-return-value",
}

def get_pattern_id(cur, name):
    cur.execute("SELECT id FROM attack_patterns WHERE name = ?", (name,))
    row = cur.fetchone()
    return row[0] if row else None

def match_pattern(finding):
    scores = {}

    category = (finding.get("category") or "").lower()
    for key, patterns in CATEGORY_MAP.items():
        if key in category:
            for p in patterns:
                scores[p] = scores.get(p, 0) + 3

    text = " ".join([
        finding.get("title") or "",
        finding.get("description") or "",
        finding.get("impact") or "",
        finding.get("recommendation") or "",
    ]).lower()

    for signal, pattern in INDICATOR_MAP.items():
        if signal.lower() in text:
            scores[pattern] = scores.get(pattern, 0) + 1

    if not scores:
        return None

    return max(scores, key=scores.get)

def extract_entities():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM findings WHERE pattern_id IS NULL")
    findings = cur.fetchall()

    if not findings:
        print("No unclassified findings.")
        conn.close()
        return

    matched = 0
    unmatched = 0

    for finding in findings:
        finding = dict(finding)
        pattern_name = match_pattern(finding)

        if pattern_name:
            pattern_id = get_pattern_id(cur, pattern_name)
            if pattern_id:
                cur.execute(
                    "UPDATE findings SET pattern_id = ? WHERE id = ?",
                    (pattern_id, finding["id"])
                )
                cur.execute(
                    "UPDATE attack_patterns SET occurrence_count = occurrence_count + 1, updated_at = datetime('now') WHERE id = ?",
                    (pattern_id,)
                )
                matched += 1
            else:
                unmatched += 1
        else:
            unmatched += 1

    conn.commit()
    conn.close()
    print(f"Done. {matched} findings matched, {unmatched} unmatched.")

if __name__ == "__main__":
    extract_entities()
