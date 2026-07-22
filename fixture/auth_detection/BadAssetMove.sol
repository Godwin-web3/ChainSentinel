// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::find_self_scoped_asset_moves and its
// constraints.py wiring — the replacement for ECONOMIC_INTERFACES (a
// hardcoded name list of common DeFi verbs like swap/deposit/withdraw/
// supply used to blanket-suppress ACCESS_CONTROL_GAP on ASSET_DRAIN
// sinks). Found live: Liquity's real withdrawFromSP() ->
// _sendETHGainToDepositor() sends ETH to msg.sender directly, no
// admin gate, correctly permissionless — but ECONOMIC_INTERFACES'
// exact-name-match missed "withdrawFromSP" (only "withdraw" was
// listed), producing a false positive on a real, audited, currently-
// live protocol. drainTo/stealApproved reproduce the exact shape a
// naive removal-without-replacement, OR a naive "any caller==msg.sender
// check counts" fix, would get wrong in either direction.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract BadAssetMove {
    IERC20 public token;
    mapping(address => uint256) public gains;

    // DANGEROUS: checks caller==msg.sender but sends ETH to an
    // ARBITRARY attacker-chosen recipient. Must fire.
    function drainTo(address caller, address payable recipient) external {
        require(caller == msg.sender, "not caller");
        recipient.call{value: gains[msg.sender]}("");
    }

    // Safe: caller can only ever receive their OWN gain.
    function claimGain() external {
        payable(msg.sender).call{value: gains[msg.sender]}("");
    }

    // DANGEROUS: pulls tokens FROM an arbitrary victim (whatever they
    // approved) TO the attacker. Must fire.
    function stealApproved(address victim, address attacker, uint256 amount) external {
        token.transferFrom(victim, attacker, amount);
    }

    // Safe: caller only ever moves their OWN approved tokens in.
    function depositMine(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }
}
