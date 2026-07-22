// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// A deliberately non-standard-named auth modifier — does NOT match any
// entry in the old AUTH_MODIFIER_PATTERNS name list (onlyOwner, onlyAdmin,
// etc.). Proves the structural detector catches it via real evidence
// (require(msg.sender == pendingOwner)) instead of a name guess.
contract CustomAuthModifier {
    address public pendingOwner;
    address public owner;

    modifier gatekept() {
        require(msg.sender == pendingOwner, "no");
        _;
    }

    function acceptOwnership() external gatekept {
        owner = pendingOwner;
    }
}
