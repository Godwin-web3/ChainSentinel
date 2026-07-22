// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// OpenZeppelin AccessControl-shaped role check via nested mapping lookup
// (_roles[role][msg.sender]) rather than a direct msg.sender comparison.
// Proves the role/mapping-lookup detector fires on the real structural
// shape, with zero reliance on the "hasRole"/"_checkRole" name.
contract AccessControlRoles {
    mapping(bytes32 => mapping(address => bool)) private _roles;
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN");
    uint256 public criticalParam;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "no role");
        _;
    }

    function setCriticalParam(uint256 v) external onlyRole(ADMIN_ROLE) {
        criticalParam = v;
    }
}
