// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Minimal stand-in for OpenZeppelin v4.9.3's real IERC20.sol — same
// physical Hardhat dependency-compiler cache layout real vendored
// trees use (.cache/OpenZeppelin/<version>/token/ERC20/IERC20.sol),
// deliberately NOT a full copy since only import resolution is under
// test here.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
