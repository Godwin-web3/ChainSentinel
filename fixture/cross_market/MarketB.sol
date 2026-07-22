// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Interfaces.sol";

// Mirrors crETH: its OWN nonReentrant guard is fully engaged and correct
// in isolation. The vulnerability isn't here — it's that this function's
// health check trusts Hub.totalBorrowed(), which trusts MarketA's
// self-reported debt, which MarketA has not written yet if this call
// happens during MarketA.borrow()'s external-call window.
contract MarketB is IMarketBReader {
    mapping(address => uint256) public accountBorrows;
    IHub public immutable hub;
    IToken public immutable underlying;
    bool internal _notEntered = true;

    modifier nonReentrant() {
        require(_notEntered, "reentrant");
        _notEntered = false;
        _;
        _notEntered = true;
    }

    constructor(address _hub, address _underlying) {
        hub = IHub(_hub);
        underlying = IToken(_underlying);
    }

    function borrow(uint256 amount) external nonReentrant {
        uint256 existing = hub.totalBorrowed(msg.sender);
        require(existing < 1000e18, "insufficient collateral");
        accountBorrows[msg.sender] += amount;
        underlying.transfer(msg.sender, amount);
    }

    function accountBorrowsOf(address user) external view returns (uint256) {
        return accountBorrows[user];
    }
}
