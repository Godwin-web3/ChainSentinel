// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IOracle {
    function getPrice() external view returns (uint256);
}

contract Oracle is IOracle {
    uint256 public price = 100;

    function getPrice() external view override returns (uint256) {
        return price;
    }

    function setPrice(uint256 _price) external {
        price = _price;
    }
}

contract Vault {
    IOracle public oracle;
    mapping(address => uint256) public balances;

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
    }

    // direct external call, resolved via constructor-assigned storage
    function getValue(address user) external view returns (uint256) {
        uint256 bal = balances[user];
        uint256 price = oracle.getPrice();
        return bal * price;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
