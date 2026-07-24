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

// Tests the SECOND real false positive this session: even once the
// dead transferFrom branch above is pruned, the surviving `.transfer`
// branch's own destination (settle's `manager` PARAMETER — the actual
// RECIPIENT argument of transfer/transferFrom, not the call's own
// target, which is the TOKEN contract) was never checked for trust at
// all. Confirmed live against Flaunch's real, currently-deployed
// PositionManager (Base): CurrencySettler.settle's `manager` parameter
// is always PositionManager's own `poolManager` IMMUTABLE — a fixed,
// non-attacker-redirectable settlement layer, not a real theft target.

// Safe: `manager` is THIS contract's own immutable, passed directly.
// The `.transfer` branch's destination is fixed — must NOT fire.
contract TrustedDestinationSettler {
    IERC20 public token;
    address public immutable manager;

    constructor(address _manager) {
        manager = _manager;
    }

    function settleOwnFunds(uint256 amount) external {
        Settler.settle(token, manager, address(this), amount);
    }
}

// DANGEROUS: adversarial regression proving the trust check doesn't
// over-suppress. `manager` here is a genuine, caller-supplied
// parameter — never proven immutable/constant — so the recipient IS
// really attacker-redirectable and `.transfer` must still fire.
contract UntrustedDestinationSettler {
    IERC20 public token;

    function settleToArbitraryManager(address manager, uint256 amount) external {
        Settler.settle(token, manager, address(this), amount);
    }
}

// Tests TRANSITIVE propagation across TWO hops — the exact real
// Flaunch shape: beforeSwap passes its own `poolManager` immutable
// into _internalSwap's `_poolManager` PARAMETER, and _internalSwap
// passes THAT parameter into CurrencySettler.settle's `manager`
// parameter two hops later. Proving `manager` trusted here requires
// chaining both hops, not just looking at settle's direct caller.

// Safe: manager reaches settle only after being passed THROUGH an
// intermediate internal function's own parameter, but originates from
// a real immutable at the top of the chain. Must NOT fire.
contract TransitiveTrustSettler {
    IERC20 public token;
    address public immutable manager;

    constructor(address _manager) {
        manager = _manager;
    }

    function _relay(address _manager, uint256 amount) internal {
        Settler.settle(token, _manager, address(this), amount);
    }

    function settleViaRelay(uint256 amount) external {
        _relay(manager, amount);
    }
}

// DANGEROUS: adversarial regression for the transitive case. Same
// two-hop shape as TransitiveTrustSettler, but the value threaded
// through _relay originates from a genuine, caller-supplied parameter,
// never proven immutable/constant at any hop — must still fire.
contract TransitiveUntrustedSettler {
    IERC20 public token;

    function _relay(address _manager, uint256 amount) internal {
        Settler.settle(token, _manager, address(this), amount);
    }

    function settleViaRelay(address manager, uint256 amount) external {
        _relay(manager, amount);
    }
}
