// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Interfaces.sol";

// Mirrors Comptroller's cross-market liquidity aggregation: reads every
// market's own reported debt for a user, unaware that one of those
// markets may not have finished recording a borrow yet.
contract Hub is IHub {
    IMarketAReader public immutable marketA;
    IMarketBReader public immutable marketB;

    constructor(address _marketA, address _marketB) {
        marketA = IMarketAReader(_marketA);
        marketB = IMarketBReader(_marketB);
    }

    function totalBorrowed(address user) external view returns (uint256) {
        return marketA.accountBorrowsOf(user) + marketB.accountBorrowsOf(user);
    }
}
