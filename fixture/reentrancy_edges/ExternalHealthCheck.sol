// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/constraints.py::_guard_constrains_sink_state's extension
// for health-check guards derived from a trusted EXTERNAL dependency
// rather than local storage — the real Liquity StabilityPool false
// positive found live this session.
//
// Real withdrawFromSP() calls _requireNoUnderCollateralizedTroves() as
// a sibling guard before reaching _sendETHGainToDepositor(), which
// writes `ETH` then sends ETH. _requireNoUnderCollateralizedTroves()
// never reads any of StabilityPool's OWN state — its entire condition
// comes from priceFeed.fetchPrice()/sortedTroves.getLast()/
// troveManager.getCurrentICR(...), all fixed, protocol-governed
// contracts. The old local-storage-overlap-only check couldn't see it
// at all: node.reads never intersects the sink's writes when the guard
// reads nothing local.
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract ExternalHealthCheck {
    IPriceOracle public immutable oracle;
    mapping(address => uint256) public totalDebt;
    address public owner;

    constructor(IPriceOracle _oracle, address _owner) {
        oracle = _oracle;
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Gives the contract a real auth-scored function that reads
    // totalDebt, so core/constraints.py's early "no guard in the
    // contract could possibly validate this state" suppression doesn't
    // short-circuit before reaching the check under test.
    function adminForgiveDebt(address user) external onlyOwner {
        require(totalDebt[user] > 0, "no debt");
        totalDebt[user] = 0;
    }

    // Safe (real): the sibling guard's condition comes entirely from a
    // TRUSTED (immutable), read-only external oracle — never touching
    // totalDebt locally. The real Liquity
    // _requireNoUnderCollateralizedTroves() shape. Must NOT fire
    // MISSING_HEALTH_CHECK.
    function withdraw(uint256 amount) external {
        _requireHealthySystem();
        _withdraw(amount);
    }

    function _withdraw(uint256 amount) internal {
        totalDebt[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function _requireHealthySystem() internal view {
        require(oracle.getPrice() > 0, "bad price");
    }

    // DANGEROUS: the "guard" queries an ATTACKER-SUPPLIED oracle
    // address, not the fixed, immutable one — must NOT be treated as a
    // valid health check even though it has the identical shape.
    // MISSING_HEALTH_CHECK must still fire.
    function withdrawUnsafe(uint256 amount, IPriceOracle fakeOracle) external {
        require(fakeOracle.getPrice() > 0, "bad price");
        _withdraw(amount);
    }
}
