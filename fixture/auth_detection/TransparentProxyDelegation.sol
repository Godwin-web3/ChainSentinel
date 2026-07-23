// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/edges.py::_resolve_trust (extended to delegatecall/
// codecall) and core/sinks.py's fallback/receive proxy-dispatcher
// carve-out — the fix for the real false positive found live this
// session against Takara Lend, a real Compound V2 fork deployed on
// Sei (Comptroller at 0x56A171Acb1bBa46D4fdF21AfBE89377574B8D9BD):
// `Unitroller.fallback()` unconditionally delegatecalls
// `comptrollerImplementation.delegatecall(msg.data)` with no auth
// check of its own — the standard transparent-proxy pattern. That's
// correct: the actual privilege enforcement happens inside each of
// the implementation's own functions (`require(msg.sender ==
// admin)`), re-checked against the SAME shared storage the
// delegatecall preserves. But core/edges.py hardcoded trusted=False
// for EVERY delegatecall regardless of destination, and core/sinks.py's
// carve-out for exactly this pattern checked `not e.uncertain` — a
// flag ALSO hardcoded True for every delegatecall — so the carve-out
// could never actually fire, and every real transparent proxy in the
// codebase (a hugely common DeFi pattern) scored a false
// ACCESS_CONTROL_GAP / DELEGATION_SINK on its own fallback().
//
// Deliberately does NOT share a common storage base between the safe
// and unsafe contracts below — Slither's StateVariable.written
// aggregates ALL writers of a given declaration across every
// inheriting contract, so a shared base would let the safe contract's
// real admin-gated setter accidentally "prove" the unsafe contract's
// unguarded one governance_gated too, defeating the counter-example.
//
// Also tests a second, related fix: a SELF-delegatecall
// (`address(this).delegatecall(...)`, the real OpenZeppelin-style
// Multicall batching pattern) — found live this session, ALSO against
// INIT Capital's real InitCore.sol on Blast. `address(this)` lowers to
// a TypeConversion producing a TemporaryVariable, so it never matched
// the state-variable trust path at all; and core/sinks.py's carve-out
// was gated to functions literally named "fallback"/"receive", which
// "multicall" isn't. See SelfMulticall / UnsafeDelegateToParam below.

// Safe: the real Compound V2 Unitroller pattern. comptrollerImpl is
// only ever settable via a real 2-step admin handoff
// (_setPendingImplementation -> _acceptImplementation, each
// independently msg.sender-gated against shared storage) — a REAL,
// ongoing, non-constructor auth-gated setter, not merely an immutable
// value. fallback() itself has no auth check by design. Must NOT fire
// ACCESS_CONTROL_GAP and must NOT classify as DELEGATION_SINK.
contract SafeUnitroller {
    address public admin;
    address public pendingAdmin;
    address public comptrollerImpl;
    address public pendingComptrollerImpl;

    constructor() {
        admin = msg.sender;
    }

    function _setPendingImplementation(address newPendingImplementation) public returns (bool) {
        require(msg.sender == admin, "not admin");
        pendingComptrollerImpl = newPendingImplementation;
        return true;
    }

    function _acceptImplementation() public returns (bool) {
        require(msg.sender == pendingComptrollerImpl, "not pending impl");
        comptrollerImpl = pendingComptrollerImpl;
        pendingComptrollerImpl = address(0);
        return true;
    }

    fallback() external {
        (bool success, ) = comptrollerImpl.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
}

// DANGEROUS: structurally identical fallback() shape — but the
// implementation slot is set by a completely UNGUARDED function, so
// anyone can repoint the proxy to an arbitrary malicious contract and
// then drive it through fallback(). Must still fire ACCESS_CONTROL_GAP
// / classify as DELEGATION_SINK.
contract UnsafeProxy {
    address public implementation;

    function setImplementation(address newImplementation) external {
        implementation = newImplementation;
    }

    fallback() external {
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "delegatecall failed");
    }
}

// Safe: the real OpenZeppelin-style Multicall batching pattern, found
// live this session against INIT Capital's real InitCore.sol on
// Blast — a SELF-delegatecall (`address(this).delegatecall(...)`),
// not a proxy dispatching to a separate implementation. Not gated on
// a function name like "fallback"/"receive" at all — a batching
// helper delegating to its OWN address is exactly as safe as a real
// proxy's governance-gated implementation slot, since the destination
// can never be attacker-redirected: it IS this exact contract,
// definitionally. Must NOT fire ACCESS_CONTROL_GAP and must NOT
// classify as DELEGATION_SINK.
contract SelfMulticall {
    uint256 public counter;

    function bump() external {
        counter += 1;
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            require(success, "MC");
            results[i] = result;
        }
    }
}

// DANGEROUS: structurally similar to SelfMulticall (a delegatecall
// inside a loop, no fallback()/receive() name) — but the destination
// is an ATTACKER-SUPPLIED PARAMETER, not `address(this)`. Must NOT be
// misdetected as a safe self-delegation just because it superficially
// resembles a multicall helper. Must still fire ACCESS_CONTROL_GAP /
// classify as DELEGATION_SINK.
contract UnsafeDelegateToParam {
    function batchCall(address target, bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = target.delegatecall(data[i]);
            require(success, "MC");
            results[i] = result;
        }
    }
}
