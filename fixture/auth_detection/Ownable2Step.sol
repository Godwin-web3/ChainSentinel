// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Ownable2Step {
    address public owner;
    address public pendingOwner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        address sender = msg.sender;
        require(sender == pendingOwner, "not pending owner");
        _transferOwnership(sender);
    }

    function _transferOwnership(address newOwner) internal {
        owner = newOwner;
        pendingOwner = address(0);
    }
}
