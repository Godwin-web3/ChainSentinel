pragma solidity ^0.5.0;

// Minimal stand-in for OpenZeppelin v2.x's real Ownable.sol — same
// physical layout (contracts/ownership/Ownable.sol) real pre-2019
// vendored trees use, deliberately NOT a full copy since only the
// import-resolution path is under test here.
contract Ownable {
    address private _owner;

    constructor () internal {
        _owner = msg.sender;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }

    function isOwner() public view returns (bool) {
        return msg.sender == _owner;
    }
}
