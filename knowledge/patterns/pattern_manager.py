"""
knowledge/patterns/pattern_manager.py
Loads seed_patterns.json into SQLite and builds category_attack_map.
"""

import json
import os
from knowledge.storage.db.database import (
    insert_pattern,
    insert_category_map,
    get_pattern_by_name,
    get_stats,
)
from utils.logger import log

SEED_PATH = os.path.join(os.path.dirname(__file__), "seed_patterns.json")

# Priority map: how urgently the agent investigates each pattern
# per protocol category. 1 = investigate first, 10 = investigate last.
CATEGORY_ATTACK_MAP = {
    "lending": [
        ("flash-loan-oracle-manipulation", 1),
        ("read-only-reentrancy",           2),
        ("liquidation-manipulation",       2),
        ("price-manipulation-twap",        3),
        ("reentrancy-token",               3),
        ("reentrancy-eth",                 4),
        ("access-control-missing",         4),
        ("flash-loan-attack",              5),
        ("unchecked-return-value",         5),
        ("precision-loss",                 6),
        ("integer-overflow",               7),
    ],
    "vault": [
        ("vault-inflation-attack",         1),
        ("reentrancy-eth",                 2),
        ("reentrancy-token",               2),
        ("read-only-reentrancy",           3),
        ("access-control-missing",         3),
        ("controlled-delegatecall",        4),
        ("flash-loan-oracle-manipulation", 5),
        ("precision-loss",                 5),
        ("unchecked-return-value",         6),
        ("integer-overflow",               7),
    ],
    "dex": [
        ("flash-loan-oracle-manipulation", 1),
        ("reentrancy-eth",                 2),
        ("reentrancy-token",               2),
        ("read-only-reentrancy",           3),
        ("flash-loan-attack",              3),
        ("unchecked-return-value",         4),
        ("precision-loss",                 4),
        ("integer-overflow",               5),
        ("access-control-missing",         6),
    ],
    "bridge": [
        ("bridge-message-replay",          1),
        ("access-control-missing",         2),
        ("controlled-delegatecall",        3),
        ("integer-overflow",               4),
        ("reentrancy-eth",                 5),
        ("unchecked-return-value",         5),
    ],
    "governance": [
        ("governance-flash-loan",          1),
        ("access-control-missing",         2),
        ("flash-loan-attack",              3),
        ("integer-overflow",               4),
    ],
    "stability": [
        ("flash-loan-oracle-manipulation", 1),
        ("liquidation-manipulation",       2),
        ("price-manipulation-twap",        2),
        ("flash-loan-attack",              3),
        ("reentrancy-eth",                 4),
        ("access-control-missing",         5),
        ("precision-loss",                 6),
    ],
    "staking": [
        ("reentrancy-token",               1),
        ("reentrancy-eth",                 2),
        ("flash-loan-attack",              3),
        ("precision-loss",                 4),
        ("unchecked-return-value",         4),
        ("access-control-missing",         5),
        ("integer-overflow",               6),
    ],
    "perpetual": [
        ("flash-loan-oracle-manipulation", 1),
        ("liquidation-manipulation",       2),
        ("price-manipulation-twap",        2),
        ("access-control-missing",         3),
        ("precision-loss",                 4),
        ("reentrancy-token",               5),
        ("integer-overflow",               6),
    ],
    "token": [
        ("integer-overflow",               1),
        ("unchecked-return-value",         2),
        ("access-control-missing",         3),
        ("precision-loss",                 4),
        ("reentrancy-token",               5),
    ],
    "oracle": [
        ("flash-loan-oracle-manipulation", 1),
        ("price-manipulation-twap",        2),
        ("access-control-missing",         3),
    ],
    "factory": [
        ("access-control-missing",         1),
        ("controlled-delegatecall",        2),
        ("reentrancy-eth",                 3),
    ],
    "multisig": [
        ("access-control-missing",         1),
        ("controlled-delegatecall",        2),
        ("reentrancy-eth",                 3),
        ("integer-overflow",               4),
    ],
    "rewards": [
        ("reentrancy-token",               1),
        ("flash-loan-attack",              2),
        ("precision-loss",                 3),
        ("unchecked-return-value",         4),
        ("access-control-missing",         5),
        ("integer-overflow",               6),
    ],
    "flashloan_receiver": [
        ("reentrancy-eth",                 1),
        ("reentrancy-token",               2),
        ("unchecked-return-value",         3),
        ("access-control-missing",         4),
    ],
}


def load_seeds() -> int:
    """
    Load seed_patterns.json into SQLite.
    Returns number of patterns inserted.
    """
    if not os.path.exists(SEED_PATH):
        log.error(f"Seed file not found: {SEED_PATH}")
        return 0

    with open(SEED_PATH) as f:
        data = json.load(f)

    patterns = data.get("patterns", [])
    inserted = 0

    for p in patterns:
        pattern_id = insert_pattern(
            name=p["name"],
            display_name=p["display_name"],
            category=p["category"],
            subcategory=p.get("subcategory", ""),
            description=p["description"],
            indicators=p["indicators"],
            requirements=p["requirements"],
            impact=p["impact"],
            affected_categories=p["affected_categories"],
            mitigations=p["mitigations"],
            confidence_base=p.get("confidence_base", 0.5),
            avg_severity=p.get("avg_severity", "high"),
        )
        if pattern_id:
            inserted += 1
            log.success(f"Loaded pattern: {p['name']}")
        else:
            log.warn(f"Pattern already exists or failed: {p['name']}")

    return inserted


def build_category_map():
    """
    Wire attack patterns to protocol categories with priority scores.
    This is what the agent queries when it starts investigating a contract.
    """
    mapped = 0

    for protocol_category, patterns in CATEGORY_ATTACK_MAP.items():
        for pattern_name, priority in patterns:
            pattern = get_pattern_by_name(pattern_name)
            if not pattern:
                log.warn(f"Pattern not found for map: {pattern_name}")
                continue
            insert_category_map(
                protocol_category=protocol_category,
                pattern_id=pattern["id"],
                priority=priority,
            )
            mapped += 1

    log.success(f"Category attack map built: {mapped} entries")
    return mapped


def init_knowledge_base():
    """
    Full initialization. Run once to seed the knowledge base.
    Safe to re-run — INSERT OR IGNORE prevents duplicates.
    """
    log.section("Initializing ChainSentinel Knowledge Base")

    stats_before = get_stats()
    log.info(f"Before: {stats_before}")

    inserted = load_seeds()
    log.info(f"Patterns loaded: {inserted}")

    mapped = build_category_map()
    log.info(f"Category mappings created: {mapped}")

    stats_after = get_stats()
    log.info(f"After: {stats_after}")

    log.success("Knowledge base initialized")
    return stats_after


def get_attack_priorities(protocol_category: str) -> list:
    """
    Returns ordered attack patterns for a protocol category.
    The agent calls this at the start of every investigation.
    """
    from knowledge.storage.db.database import get_patterns_for_category
    return get_patterns_for_category(protocol_category)


if __name__ == "__main__":
    init_knowledge_base()
