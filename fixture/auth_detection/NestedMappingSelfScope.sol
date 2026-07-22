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
    address public constant ADMIN = address(0xdead);
    mapping(address => mapping(address => bool)) public can;
    mapping(address => mapping(address => bool)) public allowances;

    // Makes both mappings structurally "privileged" for classify_sinks
    // (core/sinks.py::_privileged_vars_by_contract): a real
    // msg.sender-keyed BOOLEAN lookup gating a revert, with msg.sender
    // as the INNERMOST (bool-valued) key — can[ADMIN][msg.sender] —
    // matching the real AccessControl.hasRole shape
    // (_role_mapping_ir requires msg.sender to be the key of the
    // FINAL, bool-typed Index; can[msg.sender][usr]'s OUTER index
    // result is an intermediate mapping reference, not bool, so that
    // shape alone can't double as its own auth gate — a real,
    // structural distinction, not a fixture quirk). Deliberately a
    // DIFFERENT read shape on the SAME root variable than hope()/
    // nope()'s write, mirroring a real bidirectional permission
    // mapping (can[grantor][grantee]): ADMIN pre-approving specific
    // callers here, separate from any caller granting/revoking their
    // own delegates via hope()/nope().
    modifier onlyAdminApproved() {
        require(can[ADMIN][msg.sender], "not approved by admin");
        _;
    }

    modifier onlyPreApproved() {
        require(allowances[ADMIN][msg.sender], "not pre-approved");
        _;
    }

    function privilegedGrant() external onlyAdminApproved() {}
    function privilegedSpend() external onlyPreApproved() {}

    // Safe (real Vat.hope() shape): the OUTER key is msg.sender — the
    // write can only ever land inside the caller's own subtree,
    // regardless of what `usr` is chosen. Must be self-scoped.
    function hope(address usr) external {
        can[msg.sender][usr] = true;
    }

    function nope(address usr) external {
        can[msg.sender][usr] = false;
    }

    // DANGEROUS: neither the outer key (victim) nor the inner key
    // (spender) is msg.sender — an attacker can corrupt an arbitrary
    // victim's allowance row for an arbitrary spender. Must NOT be
    // self-scoped.
    function corruptAllowance(address victim, address spender, bool approved) external {
        allowances[victim][spender] = approved;
    }
}
