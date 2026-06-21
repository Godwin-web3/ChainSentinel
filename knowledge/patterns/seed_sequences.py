import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "storage" / "db" / "chainsentinel.db"
SEQUENCES_PATH = Path(__file__).parent / "seed_sequences.json"

def load_sequences():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    with open(SEQUENCES_PATH) as f:
        data = json.load(f)

    inserted = 0
    skipped = 0

    for entry in data["sequences"]:
        cur.execute("SELECT id FROM attack_patterns WHERE name = ?", (entry["pattern_name"],))
        row = cur.fetchone()

        if not row:
            print(f"[SKIP] Pattern not found: {entry['pattern_name']}")
            skipped += 1
            continue

        pattern_id = row[0]

        for step in entry["steps"]:
            cur.execute("""
                INSERT OR IGNORE INTO exploit_sequences
                    (pattern_id, step_order, step_name, step_description, code_signal, slither_check, is_optional)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern_id,
                step["step_order"],
                step["step_name"],
                step["step_description"],
                step["code_signal"],
                step.get("slither_check"),
                step["is_optional"]
            ))
            inserted += 1

    conn.commit()
    conn.close()
    print(f"Done. {inserted} steps inserted, {skipped} patterns skipped.")

if __name__ == "__main__":
    load_sequences()
