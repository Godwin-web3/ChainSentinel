// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_is_self_scoped_getter_ref /
// _amount_is_self_funded_decrement — the fix for the real Uniswap V3
// UniswapV3Pool.collect() false positive found live this session:
//   Position.Info storage position = positions.get(msg.sender, tickLower, tickUpper);
//   amount0 = amount0Requested > position.tokensOwed0 ? position.tokensOwed0 : amount0Requested;
//   position.tokensOwed0 -= amount0;
//   TransferHelper.safeTransfer(token0, recipient, amount0);
// `recipient` is arbitrary (a legitimate "send to any address"
// pattern), but the AMOUNT sent is bounded by, and simultaneously
// debited from, the CALLER's own accrued position — looked up via a
// getter whose owner argument is hardcoded to msg.sender, hashed
// together with attacker-chosen (but immaterial) tick bounds. An
// attacker can only ever drain their OWN accrued fees, never another
// position holder's.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library Position {
    struct Info {
        uint128 tokensOwed0;
    }
    function get(
        mapping(bytes32 => Info) storage self,
        address owner,
        int24 tickLower,
        int24 tickUpper
    ) internal view returns (Position.Info storage position) {
        position = self[keccak256(abi.encodePacked(owner, tickLower, tickUpper))];
    }
}

contract SelfScopedGetterCollect {
    using Position for mapping(bytes32 => Position.Info);

    mapping(bytes32 => Position.Info) public positions;
    IERC20 public token0;

    // Safe: `position` is proven self-scoped (owner==msg.sender at the
    // getter call site), and the transferred amount is exactly what's
    // debited from that same position in this call. Recipient is
    // arbitrary — fine, since the AMOUNT is what's proven safe here.
    // Must NOT fire ACCESS_CONTROL_GAP/ASSET_DRAIN.
    function collect(
        address recipient, int24 tickLower, int24 tickUpper, uint128 amount0Requested
    ) external returns (uint128 amount0) {
        Position.Info storage position = positions.get(msg.sender, tickLower, tickUpper);
        amount0 = amount0Requested > position.tokensOwed0 ? position.tokensOwed0 : amount0Requested;
        if (amount0 > 0) {
            position.tokensOwed0 -= amount0;
            token0.transfer(recipient, amount0);
        }
    }

    // DANGEROUS: the getter is called with an attacker-chosen `owner`
    // parameter instead of msg.sender — an attacker can drain ANY
    // position's accrued fees to themselves. Must still fire.
    function collectFor(
        address owner, address recipient, int24 tickLower, int24 tickUpper, uint128 amount0Requested
    ) external returns (uint128 amount0) {
        Position.Info storage position = positions.get(owner, tickLower, tickUpper);
        amount0 = amount0Requested > position.tokensOwed0 ? position.tokensOwed0 : amount0Requested;
        if (amount0 > 0) {
            position.tokensOwed0 -= amount0;
            token0.transfer(recipient, amount0);
        }
    }

    // DANGEROUS: `position` is legitimately self-scoped (owner ==
    // msg.sender), but the TRANSFERRED amount is a caller-chosen
    // parameter completely decoupled from the debited amount — an
    // attacker can debit 1 wei from their own position while
    // instructing the token to send an arbitrary, unrelated amount.
    // Must still fire — this is exactly the shape a naive "any
    // self-scoped getter decrement exists somewhere" fix would wrongly
    // suppress.
    function collectDecoupled(
        address recipient, int24 tickLower, int24 tickUpper, uint128 debitAmount, uint128 sendAmount
    ) external {
        Position.Info storage position = positions.get(msg.sender, tickLower, tickUpper);
        position.tokensOwed0 -= debitAmount;
        token0.transfer(recipient, sendAmount);
    }
}
