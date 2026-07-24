// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_amount_is_self_scoped_balance_read —
// the fix for the real ACCESS_CONTROL_GAP false positive found live
// this session against Flaunch's real, currently-deployed
// FeeEscrow.withdrawFees() and ReferralEscrow.claimTokens()/
// claimAndSwap() (Base): both read the caller's own msg.sender-keyed
// balance into a local, zero the slot, then send that local value to a
// CALLER-CHOSEN recipient (not necessarily msg.sender itself):
//     uint amount = balances[msg.sender];
//     balances[msg.sender] = 0;
//     recipient.call{value: amount}('');
// find_self_scoped_asset_moves previously only recognized a self-scoped
// DESTINATION (to == msg.sender) or a self-funded DECREMENT via a
// getter-function call (the real Uniswap V3 collect() shape) — neither
// matches this simpler, arguably more common "read your own balance,
// zero it, send it wherever you like" pattern with a PLAIN mapping.
contract SelfScopedBalanceWithdraw {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allocations;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Safe (real FeeEscrow.withdrawFees shape): amount is read directly
    // from the caller's own single-level mapping slot, which is then
    // zeroed. Must NOT fire ACCESS_CONTROL_GAP even though `recipient`
    // is an arbitrary parameter, not msg.sender.
    function withdrawTo(address payable recipient) external {
        uint256 amount = balances[msg.sender];
        if (amount == 0) return;
        balances[msg.sender] = 0;
        (bool sent, ) = recipient.call{value: amount}("");
        require(sent, "ETH transfer failed");
    }

    // Safe (real ReferralEscrow.claimTokens shape): same proof, but
    // through a NESTED mapping — the OUTER key (msg.sender) is what
    // must resolve self-scoped, matching _outermost_index_key's own
    // inner/outer bar for a write. Must NOT fire.
    function withdrawTokenTo(address token, address payable recipient) external {
        uint256 amount = allocations[msg.sender][token];
        if (amount == 0) return;
        allocations[msg.sender][token] = 0;
        (bool sent, ) = recipient.call{value: amount}("");
        require(sent, "ETH transfer failed");
    }

    // DANGEROUS: adversarial regression proving the fix doesn't
    // over-suppress. `amount` here is a genuine caller-supplied
    // parameter, never read from any self-scoped balance — the
    // attacker can drain arbitrary ETH held by this contract to any
    // recipient. Must still fire ACCESS_CONTROL_GAP.
    function withdrawArbitrary(address payable recipient, uint256 amount) external {
        (bool sent, ) = recipient.call{value: amount}("");
        require(sent, "ETH transfer failed");
    }

    // DANGEROUS: adversarial regression proving the read must be keyed
    // by msg.sender, not an arbitrary caller-supplied account. `amount`
    // is read from an Index (so it superficially matches the read
    // shape), but the key is a free parameter — any caller can drain
    // any OTHER account's balance to themselves. Must still fire.
    function withdrawFromAccount(address account, address payable recipient) external {
        uint256 amount = balances[account];
        if (amount == 0) return;
        balances[account] = 0;
        (bool sent, ) = recipient.call{value: amount}("");
        require(sent, "ETH transfer failed");
    }
}
