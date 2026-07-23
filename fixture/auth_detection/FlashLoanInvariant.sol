// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::has_balance_invariant_after_external_call
// — the fix for the real false positive found live this session against
// Uniswap V3's real UniswapV3Pool.flash()/swap():
//   uint256 balance0Before = balance0();
//   ...external callback...
//   uint256 balance0After = balance0();
//   require(balance0Before.add(fee0) <= balance0After, 'F0');
// core/constraints.py::_check_flashloan_window's own docstring already
// promised "no invariant enforced after" as part of its structural
// signal, but the code never actually checked for it — flagging this
// real, safe pattern as a 99%-confidence flash-loan vulnerability.
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IFlashCallback {
    function onFlashLoan(uint256 amount) external;
}

contract FlashLoanInvariant {
    IERC20Like public token0;
    uint256 public reserve0;

    // Safe: reserve0 is written before the callback (structural
    // trigger for the check under test), but balance0() is
    // snapshotted before the callback and re-verified after via a
    // revert-capable invariant — the real Uniswap V3 flash() shape.
    // Must NOT fire FLASHLOAN_WINDOW.
    function flash(address recipient, uint256 amount) external {
        uint256 balance0Before = token0.balanceOf(address(this));
        reserve0 -= amount;
        token0.transfer(recipient, amount);
        IFlashCallback(msg.sender).onFlashLoan(amount);
        uint256 balance0After = token0.balanceOf(address(this));
        require(balance0Before <= balance0After, "not repaid");
        reserve0 = balance0After;
    }

    // DANGEROUS: the real PancakeBunny-style shape — reserve0 is
    // written before the callback, and there is NO re-verification of
    // any snapshotted quantity afterward. Must still fire
    // FLASHLOAN_WINDOW.
    function flashUnsafe(address recipient, uint256 amount) external {
        reserve0 -= amount;
        token0.transfer(recipient, amount);
        IFlashCallback(msg.sender).onFlashLoan(amount);
    }
}
