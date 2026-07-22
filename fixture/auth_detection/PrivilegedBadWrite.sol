// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::find_self_scoped_writes and its
// constraints.py wiring — the fix for the real renounceRole() false
// positive found against Aave's ACLManager (require(param == msg.sender)
// before a privileged write, self-only by construction) WITHOUT
// weakening detection of a structurally identical but genuinely
// dangerous shape: checking one parameter against msg.sender while
// writing storage keyed by a DIFFERENT, unconstrained parameter.
// `operators` is "privileged" because it's the real target of the
// onlyOperator auth check (governance_gated / structural_auth_var).
contract PrivilegedBadWrite {
    mapping(address => bool) public operators;

    modifier onlyOperator() {
        require(operators[msg.sender], "not operator");
        _;
    }

    function privilegedAction() external onlyOperator {}

    // Safe: caller can only ever set/unset THEIR OWN operator flag.
    function setOperatorForSelf(bool enabled) external {
        _setOperator(msg.sender, enabled);
    }

    // DANGEROUS: checks caller==msg.sender but corrupts a DIFFERENT,
    // attacker-chosen target's operator flag. Must still fire.
    function corruptOperator(address caller, address target, bool enabled) external {
        require(caller == msg.sender, "not caller");
        _setOperator(target, enabled);
    }

    function _setOperator(address who, bool enabled) internal {
        operators[who] = enabled;
    }
}
