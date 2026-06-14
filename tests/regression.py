#!/usr/bin/env python3
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config.chains import get_chain
from core.resolver import resolve
from core.classifier import classify
from analysis.slither_runner import run_slither

SUITE_DIR = os.path.join(os.path.dirname(__file__), "regression")

def run_suite():
    files = sorted(f for f in os.listdir(SUITE_DIR) if f.endswith(".json"))
    total_pass = 0
    total_fail = 0

    for fname in files:
        path = os.path.join(SUITE_DIR, fname)
        with open(path) as f:
            spec = json.load(f)

        address = spec["address"]
        name = spec["name"]
        chain_id = spec.get("chain", "mainnet")
        expectations = spec["expect"]

        print(f"\n{'='*50}")
        print(f"  {name} ({address[:10]}...)")
        print(f"{'='*50}")

        try:
            chain = get_chain(chain_id)
            resolved = resolve(address, chain)
            classify(resolved)
            result = run_slither(resolved)

            if not result.get("success"):
                print(f"  [ERROR] Slither failed")
                total_fail += len(expectations)
                continue

            features = result.get("enrichment", {}).get("features", {})

            # Build lookup by function name
            by_name = {}
            for k, v in features.items():
                by_name[v["name"]] = v

            for func_name, expected_state in expectations.items():
                feature = by_name.get(func_name)
                if not feature:
                    print(f"  [MISS]  {func_name}")
                    print(f"          expected: {expected_state}")
                    print(f"          actual:   NOT FOUND")
                    total_fail += 1
                    continue

                actual = feature.get("auth_state", "UNKNOWN")
                if actual == expected_state:
                    print(f"  [PASS]  {func_name}: {actual}")
                    total_pass += 1
                else:
                    print(f"  [FAIL]  {func_name}")
                    print(f"          expected: {expected_state}")
                    print(f"          actual:   {actual}")
                    print(f"          evidence: {[e['type'] for e in feature.get('auth_evidence',[])]}")
                    total_fail += 1

        except Exception as e:
            print(f"  [ERROR] {e}")
            import traceback; traceback.print_exc()
            total_fail += len(expectations)

    print(f"\n{'='*50}")
    print(f"  RESULTS: {total_pass} passed, {total_fail} failed")
    print(f"{'='*50}\n")
    return total_fail == 0

if __name__ == "__main__":
    ok = run_suite()
    sys.exit(0 if ok else 1)
