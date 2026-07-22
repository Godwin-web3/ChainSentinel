// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Reproduces real OpenZeppelin AccessControl's ACTUAL structural shape
// (not the simplified flat-mapping version in AccessControlRoles.sol) —
// found live against Aave's real ACLManager (0xc2aaCf655...) this
// session. Two things a naive Index-chain-only, msg.sender-only detector
// misses:
//   1. Role storage is struct-wrapped: _roles[role].members[account] is
//      an Index -> Member -> Index chain, not a flat nested mapping.
//   2. The actual auth check goes through _msgSender() (Context-style
//      indirection), and the account being checked is a PARAMETER
//      (`account`) whose msg.sender-ness is only provable by tracing
//      the call site (onlyRole -> _checkRole(role, _msgSender()) ->
//      hasRole(role, account)) — not from _checkRole's or hasRole's own
//      body in isolation.
contract RealAccessControlShape {
    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    uint256 public criticalParam;

    function _msgSender() internal view returns (address) {
        return msg.sender;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members[account];
    }

    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) {
            revert("missing role");
        }
    }

    modifier onlyRole(bytes32 role) {
        _checkRole(role, _msgSender());
        _;
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role].members[account] = true;
    }

    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }

    function setCriticalParam(uint256 v) external onlyRole(ADMIN_ROLE) {
        criticalParam = v;
    }
}
