// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/edges.py::_self_gated_branches/_dominating_gate_requirements/
// _self_bound_call_args + core/paths.py's DFS pruning — the fix for the
// real ASSET_DRAIN false positive found live this session against
// Flaunch's real, currently-deployed PositionManager (Base,
// 0xf785Bb58059fab6fb19bdDa2Cb9078D9E546EFDc): the shared V4-core
// library `CurrencySettler.settle(currency, manager, payer, amount, burn)`
// has
//     if (payer != address(this)) { token.transferFrom(payer, manager, amount); }
//     else                         { token.transfer(manager, amount); }
// Every real call site in the project passes `payer = address(this)`
// literally — the transferFrom branch is dead code there — but the old
// flat, branch-unaware edge extraction walked into it regardless of
// which argument was actually passed, reporting a 99%-confidence
// "direct theft of user funds" finding on fully dead code. This is a
// faithful, simplified reproduction of that exact shape (not the real
// V4 CurrencySettler itself, to keep the fixture self-contained), kept
// structurally identical: a library with a payer-vs-self gate, called
// once with a literal `address(this)` argument and once with a
// genuinely caller-controlled argument.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library Settler {
    function settle(IERC20 token, address manager, address payer, uint256 amount) internal {
        if (payer != address(this)) {
            token.transferFrom(payer, manager, amount);
        } else {
            token.transfer(manager, amount);
        }
    }
}

// Safe (real Flaunch PositionManager._settleDelta shape): payer is
// ALWAYS passed as the literal `address(this)` — the transferFrom
// branch is genuinely unreachable from this call site. Must NOT
// register an ASSET_DRAIN finding for the transferFrom branch.
contract SafeSettler {
    IERC20 public token;
    address public manager;

    function settleOwnFunds(uint256 amount) external {
        Settler.settle(token, manager, address(this), amount);
    }
}

// DANGEROUS: adversarial regression proving the pruning doesn't
// over-suppress. `payer` here is a genuine, caller-supplied parameter —
// never proven to be address(this) — so the transferFrom branch IS
// really reachable and must still be reported.
contract UnsafeSettler {
    IERC20 public token;
    address public manager;

    function settleArbitraryFunds(address payer, uint256 amount) external {
        Settler.settle(token, manager, payer, amount);
    }
}
