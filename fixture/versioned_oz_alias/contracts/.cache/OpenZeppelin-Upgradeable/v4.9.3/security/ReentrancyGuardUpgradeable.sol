// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Minimal stand-in for OpenZeppelin v4.9.3's real
// ReentrancyGuardUpgradeable.sol — same physical Hardhat dependency-
// compiler cache layout real vendored trees use (.cache/OpenZeppelin-
// Upgradeable/<version>/security/ReentrancyGuardUpgradeable.sol).
// Deliberately named/shaped so it CANNOT compile as a stand-in for
// plain OpenZeppelin/IERC20.sol above — proves the two OZ variants
// (plain vs -Upgradeable) don't get cross-wired.
abstract contract ReentrancyGuardUpgradeable {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _status;

    function __ReentrancyGuard_init() internal {
        _status = NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != ENTERED, "ReentrancyGuard: reentrant call");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }
}
