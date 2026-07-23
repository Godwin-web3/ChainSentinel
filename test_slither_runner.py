"""
Regression tests for analysis/slither_runner.py's remapping generation.

Reproduces the real "Slither produced no output" failure found live
this session against Mento Protocol's real Broker implementation on
Celo (0x1B78f6acD05e7BcB00f74863bfd8a7C264143e37, solc 0.5.17): its
verified source bundle imports `openzeppelin-solidity/contracts/...`
(OpenZeppelin's own npm package name through v2.x, pre-2019, before the
`@openzeppelin/contracts` rename) but has no local copy of its own —
only a SIBLING dependency's own vendored tree, at
`lib/mento-core-2.0.0/lib/openzeppelin-contracts/`, has a matching v2.x
directory layout. The existing package-alias fallback (built for the
`@openzeppelin` vs `openzeppelin-contracts` mismatch) couldn't bridge
this: normalized "openzeppelinsolidity" is not a substring of
normalized "openzeppelincontracts" — a different second word, not a
punctuation/prefix difference.
"""
import os

from analysis.slither_runner import run_slither

FIXTURE_DIR = os.path.abspath("fixture/legacy_oz_package_name")


def _resolved(entry_rel: str, name: str, solc_version: str = "0.5.17") -> dict:
    files = {}
    for root, _dirs, fnames in os.walk(FIXTURE_DIR):
        for fname in fnames:
            if not fname.endswith(".sol"):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, FIXTURE_DIR)
            with open(full, "r") as fh:
                files[rel] = fh.read()
    return {
        "source": {
            "verified": True,
            "compiler": f"v{solc_version}+commit.d19bba13",
            "name": name,
            "files": files,
        }
    }


def test_legacy_openzeppelin_solidity_package_name_resolves_via_sibling_alias():
    result = run_slither(_resolved("consumer/Broker.sol", "Broker"))
    assert result.get("success"), f"expected successful analysis, got: {result}"
    print("test_legacy_openzeppelin_solidity_package_name_resolves_via_sibling_alias: PASS —",
          "Broker.sol compiled with the legacy openzeppelin-solidity import resolved via a sibling's vendored tree")


if __name__ == "__main__":
    test_legacy_openzeppelin_solidity_package_name_resolves_via_sibling_alias()
    print("\nAll slither_runner tests passed.")
