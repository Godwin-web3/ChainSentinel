// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_outermost_index_key — the fix for the
// real MakerDAO Vat.hope()/nope() false positive found live this
// session: `can[msg.sender][usr] = 1` writes a NESTED mapping where the
// OUTER key is msg.sender and the INNER key (usr) is an arbitrary,
// caller-chosen parameter — the opposite shape from
// AccessControl.renounceRole's `_roles[role].members[account]` (where
// the OUTER key `role` is attacker-irrelevant and the INNER key
// `account` is what must be msg.sender). find_self_scoped_writes
// previously only ever checked the INNERMOST index, so this real,
// common "delegation/approval" pattern (identical in shape to ERC20's
// allowances[owner][spender]) was never recognized as self-scoped.
contract NestedMappingSelfScope {
    mapping(address => mapping(address => uint256)) public can;
    mapping(address => mapping(address => uint256)) public allowances;

    // Makes both mappings structurally "privileged" for classify_sinks
    // (core/sinks.py::_privileged_vars_by_contract) — a real
    // msg.sender-keyed lookup gating a revert, the same real shape
    // used elsewhere this session. Without this, writes to `can`/
    // `allowances` never become STORAGE_CORRUPTION sinks at all and
    // this fixture wouldn't exercise the check under test.
    modifier onlyPermitted(address usr) {
        require(can[msg.sender][usr] > 0, "not permitted");
        _;
    }

    modifier onlyApproved(address spender) {
        require(allowances[msg.sender][spender] > 0, "not approved");
        _;
    }

    function privilegedGrant(address usr) external onlyPermitted(usr) {}
    function privilegedSpend(address spender) external onlyApproved(spender) {}

    // Safe (real Vat.hope() shape): the OUTER key is msg.sender — the
    // write can only ever land inside the caller's own subtree,
    // regardless of what `usr` is chosen. Must be self-scoped.
    function hope(address usr) external {
        can[msg.sender][usr] = 1;
    }

    function nope(address usr) external {
        can[msg.sender][usr] = 0;
    }

    // DANGEROUS: neither the outer key (victim) nor the inner key
    // (spender) is msg.sender — an attacker can corrupt an arbitrary
    // victim's allowance row for an arbitrary spender. Must NOT be
    // self-scoped.
    function corruptAllowance(address victim, address spender, uint256 amount) external {
        allowances[victim][spender] = amount;
    }
}
