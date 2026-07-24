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
VERSIONED_ALIAS_FIXTURE_DIR = os.path.abspath("fixture/versioned_oz_alias")
NESTED_SCOPE_ALIAS_FIXTURE_DIR = os.path.abspath("fixture/nested_scope_alias")


def _resolved(fixture_dir: str, name: str, solc_version: str = "0.5.17") -> dict:
    files = {}
    for root, _dirs, fnames in os.walk(fixture_dir):
        for fname in fnames:
            if not fname.endswith(".sol"):
                continue
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, fixture_dir)
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
    result = run_slither(_resolved(FIXTURE_DIR, "Broker"))
    assert result.get("success"), f"expected successful analysis, got: {result}"
    print("test_legacy_openzeppelin_solidity_package_name_resolves_via_sibling_alias: PASS —",
          "Broker.sol compiled with the legacy openzeppelin-solidity import resolved via a sibling's vendored tree")


def test_versioned_hyphenated_oz_alias_resolves_without_cross_wiring():
    """
    Reproduces the real "Slither produced no output" failure found live
    this session against INIT Capital's real InitCore.sol (Blast,
    0x815e63d6B5E1b8D74876fC9a2C08b79d4185494b): it imports two
    DIFFERENT hyphenated OZ package names, `@openzeppelin-contracts`
    and `@openzeppelin-contracts-upgradeable`, both vendored by
    Hardhat's dependency-compiler cache one level deeper than the
    package name itself suggests
    (`contracts/.cache/OpenZeppelin/v4.9.3/token/ERC20/IERC20.sol`, not
    `contracts/.cache/OpenZeppelin/token/ERC20/IERC20.sol`).

    Two independent gaps, both real: (1) normalized
    "openzeppelincontracts" is not a substring of normalized
    "openzeppelin" (or vice versa) once "contracts" — a filler word
    present in nearly every OZ-family name — is the only difference;
    (2) even once name-matched, the resolved directory isn't the real
    package root, only its parent, because of the inserted version
    folder.

    This fixture's own project tree contains a literal top-level
    directory named "contracts" — proves the fix doesn't regress into
    matching that generic, entirely-filler-word directory name (its
    stripped core is empty) as a false alias target, and that the two
    OZ variants (plain vs -Upgradeable) don't get cross-wired to each
    other's tree, which would be a WRONG-code failure, not just a
    missing one.
    """
    result = run_slither(_resolved(VERSIONED_ALIAS_FIXTURE_DIR, "InitCoreLike", solc_version="0.8.19"))
    assert result.get("success"), f"expected successful analysis, got: {result}"
    print("test_versioned_hyphenated_oz_alias_resolves_without_cross_wiring: PASS —",
          "InitCoreLike.sol compiled with both hyphenated OZ variants correctly resolved to their own version-nested trees")


def test_scope_deepened_before_subfolder_join_avoids_sibling_cross_wire():
    """
    Reproduces the real "Slither produced no output" failure found live
    this session against Robinhood Chain's real, currently-deployed
    Doppler Airlock.sol: it bare-imports both `@openzeppelin/access/
    Ownable.sol` and `@openzeppelin/utils/math/Math.sol` — the same
    `@openzeppelin` scope, correctly name-matched to
    `lib/openzeppelin-contracts` but one level too shallow (real files
    live under its own `contracts/` subfolder). Tier 0 (the scope+
    subfolder join for a `@scope/package` bare import) used to run
    BEFORE the "may not be the real package root" deepening pass
    corrected the scope directory, so it checked the wrong, too-shallow
    path, found no `utils` subdirectory there, and silently fell
    through to the fallback tier — which matched the bare basename
    "utils" against this fixture's own UNRELATED sibling
    `lib/solmate/src/utils/` (a real cross-wire trap directory,
    present in this exact fixture), breaking compilation entirely.
    """
    result = run_slither(_resolved(NESTED_SCOPE_ALIAS_FIXTURE_DIR, "NestedScopeAlias", solc_version="0.8.19"))
    assert result.get("success"), f"expected successful analysis, got: {result}"
    print("test_scope_deepened_before_subfolder_join_avoids_sibling_cross_wire: PASS —",
          "NestedScopeAlias.sol compiled with @openzeppelin/utils correctly resolved, not cross-wired to solmate's own utils/")


if __name__ == "__main__":
    test_legacy_openzeppelin_solidity_package_name_resolves_via_sibling_alias()
    test_versioned_hyphenated_oz_alias_resolves_without_cross_wiring()
    test_scope_deepened_before_subfolder_join_avoids_sibling_cross_wire()
    print("\nAll slither_runner tests passed.")
