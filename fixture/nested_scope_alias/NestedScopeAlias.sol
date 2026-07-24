// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests analysis/slither_runner.py's alias-deepening ORDER — the fix
// for the real "Slither produced no output" failure found live this
// session against Robinhood Chain's real, currently-deployed Doppler
// Airlock.sol: it bare-imports BOTH `@openzeppelin/access/Ownable.sol`
// and `@openzeppelin/utils/math/Math.sol` — the SAME `@openzeppelin`
// scope, resolved correctly to `lib/openzeppelin-contracts` (the
// package ROOT, one level too shallow — the real files live one level
// deeper, under its own `contracts/` subfolder).
//
// Tier 0 (core/analysis/slither_runner.py's scope+subfolder join) is
// supposed to join the deepened `@openzeppelin` scope directory onto
// the second segment ("utils") to resolve `@openzeppelin/utils`
// directly and unambiguously — but it used to run BEFORE the
// "may not be the real package root" deepening pass corrected the
// scope directory, so it checked or the wrong not-yet-deepened
// directory, found no `utils` subdirectory there, and silently fell
// through to the fallback tier — which matches the bare basename
// "utils" against ANY directory in the whole project tree, including
// this fixture's own UNRELATED sibling `lib/solmate/src/utils/`
// (SafeTransferLib.sol's own home) — cross-wiring `@openzeppelin/utils/`
// to a completely different package and breaking compilation.
import { Ownable } from "@openzeppelin/access/Ownable.sol";
import { Math } from "@openzeppelin/utils/math/Math.sol";

contract NestedScopeAlias is Ownable {
    constructor() Ownable(msg.sender) {}

    function bigger(uint256 a, uint256 b) external pure returns (uint256) {
        return Math.max(a, b);
    }
}
