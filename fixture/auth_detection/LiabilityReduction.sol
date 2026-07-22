// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::find_self_scoped_liability_reductions —
// the fix for the real repayAsset/liquidate ACCESS_CONTROL_GAP false
// positive found live against Fraxlend's FraxlendPairCore this session.
// Mirrors Fraxlend's real two-hop structure exactly: a public entry
// (repayAsset) calls an internal function (_repayAsset) that does BOTH
// the privileged decrease-write AND the msg.sender-funded payment.
// core/paths.py's DFS only classifies a sink at depth > 0 (never the
// entry itself), so it's the INTERNAL function that becomes the
// STORAGE_CORRUPTION sink here, same as the real _repayAsset() /
// _repayAsset() reused by liquidate().
//
// Payment is made via `using SafeERCLib for IERC20; token.safeTransferFrom(...)`
// — a LibraryCall, matching real Fraxlend's `using SafeERC20 for IERC20`
// exactly. This matters structurally, not just cosmetically: a
// LibraryCall's raw_type is "library", not "highlevel", so it is NOT
// counted into the function's own node.asset_flows (core/edges.py's
// is_token_transfer is only computed for raw_type=="highlevel") — which
// is WHY the internal function classifies as STORAGE_CORRUPTION rather
// than being eclipsed by ASSET_DRAIN, exactly like real _repayAsset().
//
// _badReduce() reproduces the exact shape a naive "any self-scoped
// payment exists somewhere in this function" fix would wrongly
// suppress: a real payment from msg.sender, but for a completely
// decoupled, attacker-chosen amount — letting an attacker wipe out an
// arbitrary borrower's real debt for 1 wei. Must still fire.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERCLib {
    // Mirrors real OpenZeppelin SafeERC20's actual internals: an
    // encoded low-level .call(), not a literal interface HighLevelCall
    // — real Fraxlend's own SafeERC20 dependency never produces a
    // resolvable/unresolvable `token.transferFrom(...)` interface call
    // node of its own, only this. Matters structurally: a literal
    // interface call here would let core/paths.py's DFS walk one hop
    // further into a synthetic "unresolved external call" ASSET_DRAIN
    // terminal that real Fraxlend's repayAsset/liquidate never produces
    // either (confirmed live — those paths are STORAGE_CORRUPTION only).
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }
}

contract LiabilityReduction {
    using SafeERCLib for IERC20;

    IERC20 public token;
    mapping(address => uint256) public userBorrowShares;

    // Makes userBorrowShares structurally "privileged" for
    // classify_sinks (core/sinks.py::_privileged_vars_by_contract): a
    // real msg.sender-keyed mapping lookup gating a revert, the same
    // way real Fraxlend code checks a caller's own borrow position
    // elsewhere in the contract. Without this, the write below never
    // becomes a STORAGE_CORRUPTION sink at all and this fixture
    // wouldn't exercise the check under test.
    function myDebt() external view returns (uint256) {
        require(userBorrowShares[msg.sender] > 0, "no debt");
        return userBorrowShares[msg.sender];
    }

    // Safe: the write-amount (shares) and the payment-amount are the
    // SAME value — repaying an arbitrary borrower's debt still costs
    // the caller the full, correlated amount. No auth gate needed.
    function repayFor(address borrower, uint256 shares) external {
        uint256 amount = _toAmount(shares);
        _repayFor(borrower, shares, amount, msg.sender);
    }

    function _repayFor(address borrower, uint256 shares, uint256 amount, address payer) internal {
        userBorrowShares[borrower] -= shares;
        token.safeTransferFrom(payer, address(this), amount);
    }

    function _toAmount(uint256 shares) internal pure returns (uint256) {
        return shares * 2;
    }

    // DANGEROUS: reduces an arbitrary borrower's debt by `shares`, but
    // the payment pulled from msg.sender is a completely separate,
    // caller-chosen `paidAmount` — decoupled from `shares`. An attacker
    // can pass a huge `shares` and a tiny `paidAmount` (even 1 wei) to
    // erase real debt for almost nothing. Must still fire.
    function badReduce(address borrower, uint256 shares, uint256 paidAmount) external {
        _badReduce(borrower, shares, paidAmount, msg.sender);
    }

    function _badReduce(address borrower, uint256 shares, uint256 paidAmount, address payer) internal {
        userBorrowShares[borrower] -= shares;
        token.safeTransferFrom(payer, address(this), paidAmount);
    }
}
