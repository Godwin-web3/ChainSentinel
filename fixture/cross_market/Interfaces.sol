// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IMarketAReader {
    function accountBorrowsOf(address user) external view returns (uint256);
}

interface IMarketBReader {
    function accountBorrowsOf(address user) external view returns (uint256);
}

interface IHub {
    function totalBorrowed(address user) external view returns (uint256);
}
