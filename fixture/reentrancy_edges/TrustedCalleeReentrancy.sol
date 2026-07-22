// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/edges.py's trust-resolution fix, found live re-verifying
// Convex Booster's admin-only functions (setFeeInfo/shutdownPool/
// shutdownSystem) this session. Two compounding bugs made every
// interface-cast call destination (IFoo(stateVar).bar() — the standard
// pattern for virtually all external calls in Solidity) score
// trusted=False regardless of how fixed the destination actually was:
//
// 1. _resolve_trust's TypeConversion-wrapped destination resolution
//    (`_trace_temp_to_source`, and _resolve_trust's own fallback) both
//    imported TemporaryVariable from
//    slither.core.variables.temporary_variable — a module that doesn't
//    exist (the real path is slither.slithir.variables.temporary) —
//    raising ModuleNotFoundError on every call, silently caught,
//    making temp-var backward-slicing a permanent no-op.
//
// 2. Even once (1) was fixed, a real `constant` state variable's own
//    "writer" (Slither's synthetic slitherConstructorConstantVariables()
//    initializer, FunctionType.CONSTRUCTOR_CONSTANT_VARIABLES /
//    is_constructor_variables=True) isn't the REAL constructor
//    (w.is_constructor is False for it), so _writers_are_trusted fell
//    through to treating it as an unscored, untrusted writer.
//
// Both together meant `registry`/`staker`-style destinations (a
// constant and a constructor-set immutable, both genuinely trusted)
// scored trusted=False, so their external calls were never excluded
// from CALLBACK_SINK classification — a false-positive REENTRANCY_CEI
// on functions where reentrancy would require compromising the
// protocol's own fixed dependency, not an independent external attack.
interface IRegistry {
    function notify() external;
}

interface ITarget {
    function withdrawAll() external;
}

contract TrustedCalleeReentrancy {
    address public constant registry = address(0xDEAD);
    address public immutable staker;
    uint256 public balance;

    constructor(address _staker) {
        staker = _staker;
    }

    // Safe: registry is a constant (compile-time fixed) and staker is
    // set only in the constructor — both genuinely trusted, never
    // attacker-substitutable. An external call + state write in the
    // same function is not a real reentrancy surface when the callee
    // can't be swapped out. Must NOT classify CALLBACK_SINK or fire
    // REENTRANCY_CEI.
    function adminOnlyAction() external {
        IRegistry(registry).notify();
        ITarget(staker).withdrawAll();
        balance = 0;
    }

    // DANGEROUS: destination is an arbitrary, caller-supplied address —
    // a real reentrancy surface. Must still classify CALLBACK_SINK and
    // fire REENTRANCY_CEI.
    function attackerControlled(address target) external {
        ITarget(target).withdrawAll();
        balance = 0;
    }
}
