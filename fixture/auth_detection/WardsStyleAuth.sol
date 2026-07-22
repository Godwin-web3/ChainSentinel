// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_role_mapping_ir's equality-against-
// constant branch — the fix for the real regression found live this
// session against MakerDAO's Vat.sol: `wards[msg.sender] == 1` is a
// numeric (uint, not bool) membership flag used by the `auth` modifier
// across the ENTIRE DSS ecosystem (Vat, Jug, Pot, Spot, Cat, Dog, Vow,
// Flap, Flop, End, every Join). It stopped scoring as auth evidence at
// all once _role_mapping_ir was gated to bool-typed Index results only
// (the earlier fix for Dai's `allowance[src][msg.sender] >= wad` false-
// AUTHENTICATED bug) — silently losing BOTH auth_score for rely()/deny()
// AND wards' STORAGE_CORRUPTION "privileged" classification entirely
// (confirmed live: Vat.sol's sink count dropped from 2 to 0).
contract WardsStyleAuth {
    mapping(address => uint256) public wards;
    mapping(address => uint256) public spendLimit;

    modifier auth() {
        require(wards[msg.sender] == 1, "not-authorized");
        _;
    }

    constructor() {
        wards[msg.sender] = 1;
    }

    // Safe: gated by the auth modifier's wards[msg.sender] == 1 check —
    // a real MakerDAO rely()/deny() shape.
    function rely(address usr) external auth {
        wards[usr] = 1;
    }

    function deny(address usr) external auth {
        wards[usr] = 0;
    }

    // DANGEROUS: an equality check against a caller-supplied VARIABLE
    // (spendLimit[msg.sender] == amt, amt is a parameter, not a
    // constant) is a numeric exact-match check — structurally the same
    // shape as Dai's allowance guard, not a permission flag. Must NOT
    // be treated as role-mapping evidence: this function has no real
    // auth gate on the wards write, and must still be flagged.
    function corruptWards(address victim, uint256 amt) external {
        require(spendLimit[msg.sender] == amt, "mismatch");
        wards[victim] = 1;
    }
}
