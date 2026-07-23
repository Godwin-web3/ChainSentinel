// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC20} from '@openzeppelin-contracts/token/ERC20/IERC20.sol';
import {ReentrancyGuardUpgradeable} from '@openzeppelin-contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol';

// The real INIT Capital InitCore.sol shape (Blast,
// 0x815e63d6B5E1b8D74876fC9a2C08b79d4185494b): imports two DIFFERENT
// hyphenated OZ package names, `@openzeppelin-contracts` and
// `@openzeppelin-contracts-upgradeable`, both vendored by Hardhat's
// dependency-compiler cache one level deeper than the package name
// itself suggests — under a version folder
// (.cache/OpenZeppelin/v4.9.3/... and
// .cache/OpenZeppelin-Upgradeable/v4.9.3/...).
contract InitCoreLike is ReentrancyGuardUpgradeable {
    IERC20 public token;

    function sweep(address to, uint256 amount) external nonReentrant {
        token.transfer(to, amount);
    }
}
