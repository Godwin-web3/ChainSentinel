// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Interfaces.sol";

// Mirrors the real Cream Finance shape: borrowFresh() sends the underlying
// out BEFORE recording the debt. Its own nonReentrant guard only locks
// MarketA — it cannot and does not protect any other deployed contract.
contract MarketA is IMarketAReader {
    mapping(address => uint256) public accountBorrows;
    IToken public immutable underlying;
    bool internal _notEntered = true;

    modifier nonReentrant() {
        require(_notEntered, "reentrant");
        _notEntered = false;
        _;
        _notEntered = true;
    }

    constructor(address _underlying) {
        underlying = IToken(_underlying);
    }

    function borrow(uint256 amount) external nonReentrant {
        underlying.transfer(msg.sender, amount);
        accountBorrows[msg.sender] += amount;
    }

    function accountBorrowsOf(address user) external view returns (uint256) {
        return accountBorrows[user];
    }
}
