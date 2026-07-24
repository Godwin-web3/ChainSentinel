// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::has_state_write_after_external_call's
// loop-back-edge fix — the real REENTRANCY_CEI false positive found
// live this session against Flaunch's real, currently-deployed
// ReferralEscrow.sol (Base, PositionManager2's referral-fee escrow
// contract, ~$1.5M TVL, PositionManager2 = 0xB4512b...): claimTokens()
// zeroes `allocations[msg.sender][token]` BEFORE its external transfer
// on EVERY loop iteration (the real source even comments "Update
// allocation before transferring to prevent reentrancy attacks" —
// textbook-correct CEI), but core/auth_detection.py::
// has_state_write_after_external_call's forward CFG walk from the
// external call reached that SAME write node again only by crossing
// the loop's own back-edge (`++i;` -> loop condition -> ... -> the
// write) — misreporting a 99%-confidence "REENTRANCY_CEI +
// MISSING_HEALTH_CHECK + ACCESS_CONTROL_GAP + FLASHLOAN_WINDOW /
// direct theft of user funds" finding on fully CEI-compliant,
// currently-deployed, actively-used code.
//
// Fixed by refusing to cross an edge (node -> son) where `son` is one
// of `node`'s own dominators (Slither's real dominator-tree data,
// node.dominators) — the standard graph-theory definition of a loop
// back-edge, confirmed live: node 12 (the write) IS a dominator of
// node 16 (the call) in the real ReferralEscrow.claimTokens() CFG.
contract LoopBackEdgeCEI {
    mapping(address => mapping(address => uint256)) public allocations;

    // Safe: real ReferralEscrow.claimTokens() shape. Zeroes the
    // caller's own allocation for THIS token BEFORE the external
    // transfer, every iteration — must NOT fire REENTRANCY_CEI.
    function claimTokens(address[] calldata tokens, address payable recipient) external {
        for (uint256 i; i < tokens.length; ++i) {
            address token = tokens[i];
            uint256 amount = allocations[msg.sender][token];
            if (amount == 0) continue;

            // Update allocation before transferring to prevent reentrancy attacks
            allocations[msg.sender][token] = 0;

            (bool sent, ) = recipient.call{value: amount}("");
            require(sent, "ETH Transfer Failed");
        }
    }

    // DANGEROUS: adversarial regression proving the back-edge fix
    // doesn't blanket-suppress every loop-shaped external call. The
    // write happens AFTER the call WITHIN THE SAME iteration — an
    // ordinary forward edge, not a back-edge, reproducing the classic
    // Fei/Cream-style violation. Must still fire REENTRANCY_CEI.
    function claimTokensUnsafe(address[] calldata tokens, address payable recipient) external {
        for (uint256 i; i < tokens.length; ++i) {
            address token = tokens[i];
            uint256 amount = allocations[msg.sender][token];
            if (amount == 0) continue;

            (bool sent, ) = recipient.call{value: amount}("");
            require(sent, "ETH Transfer Failed");

            // Write happens AFTER the call, inside the SAME iteration
            allocations[msg.sender][token] = 0;
        }
    }
}
