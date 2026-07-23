pragma solidity ^0.5.13;

import { Ownable } from "openzeppelin-solidity/contracts/ownership/Ownable.sol";

// The real Mento Protocol Broker.sol shape (Celo,
// 0x1B78f6acD05e7BcB00f74863bfd8a7C264143e37): imports the legacy
// `openzeppelin-solidity` package name, with no local copy of its own
// — only a sibling dependency's vendored tree has a matching layout.
contract Broker is Ownable {
    uint256 public tradingLimit;

    function setTradingLimit(uint256 newLimit) external onlyOwner {
        tradingLimit = newLimit;
    }
}
