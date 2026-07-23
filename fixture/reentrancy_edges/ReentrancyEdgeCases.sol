// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests three real, structural bugs found live this session while
// investigating why Uniswap V3's swap()/flash() produced zero findings
// despite being genuine, textbook CEI-violation shapes:
//
// 1. core/paths.py's _dfs gated the sink-check to depth > 0, so a
//    function that is its OWN sink (state write + external call in the
//    same function, no intermediate hop — exactly Uniswap's
//    swap()/flash()) never registered a path at all.
//
// 2. core/edges.py::_raw_type_from_ir called .lower() directly on
//    LowLevelCall.function_name, which is a Slither Constant object,
//    not a str — raising AttributeError, silently swallowed by
//    extract_edges' broad except, dropping the edge entirely. This
//    meant EVERY raw low-level call (.call(...), .call{value}(...)) in
//    the ENTIRE codebase never produced a graph edge, at any depth —
//    confirmed with a synthetic withdraw() -> _doWithdraw() CEI
//    violation that produced zero edges, let alone findings.
//
// 3. Once (2) was fixed, a real Uniswap-shaped bug was exposed:
//    .staticcall(...) (used for balanceOf()-style reads, e.g. Uniswap's
//    balance0()/balance1()) was bucketed into the same "lowlevel_call"
//    semantic profile as a value-carrying .call(...), so it was
//    misclassified as is_value_transfer=True (ASSET_DRAIN) and as a
//    reentrancy surface (CALLBACK_SINK) — both structurally impossible,
//    since the EVM propagates the static context transitively to every
//    call reachable from a STATICCALL: nothing downstream, including a
//    callback into the calling function, can ever write state or move
//    value.
//
// 4. core/constraints.py::_check_unchecked_return fired on ANY
//    low-level call on a path, never actually checking whether the
//    return value was validated — a false positive on virtually any
//    competently-written contract (TransferHelper.safeTransfer, OZ's
//    Address.functionCall, Liquity's _sendETHGainToDepositor all check
//    their own return). Fixed with real dataflow tracing (core/
//    edges.py::_low_level_return_checked): does the call's own `bool
//    success` unpack to a variable later read by a revert-capable node
//    in the same function?
//
// 5. core/paths.py's STATE_BEFORE_CALL flag was pure co-occurrence —
//    "does this function have both a state write and an external call
//    ANYWHERE, regardless of order" — which can't distinguish a real
//    violation from real Liquity's _sendETHGainToDepositor, which
//    writes `ETH = newETH` BEFORE its ETH send (CEI-compliant for that
//    variable, confirmed via real node order). Fixed with
//    core/auth_detection.py::has_state_write_after_external_call: is a
//    state-write node CFG-reachable FROM the external call, not merely
//    present somewhere in the same function.
//
// 6. core/edges.py::_semantic_properties gave every "highlevel" call
//    (Foo(addr).bar()-style Solidity call syntax) is_state_crossing=
//    True unconditionally, regardless of whether bar() itself is
//    declared view/pure — even though a view/pure call compiles to
//    STATICCALL under the hood, the exact same EVM guarantee already
//    carved out for an explicit .staticcall(...) above. Found live
//    against real Velodrome's setName(), whose only external
//    interaction is `IVoter(_voter).emergencyCouncil()` (a view call):
//    REENTRANCY_CEI and FLASHLOAN_WINDOW both fired purely because the
//    call was external and non-static-syntax, never checking the
//    resolved callee's own mutability.
interface IVoterLike {
    function emergencyCouncil() external view returns (address);
    function notifyRewardAmount(uint256 amount) external;
}

contract ReentrancyEdgeCases {
    uint256 public balance;
    address public token0;
    bool public locked;
    uint256 public counter;
    address public voter;
    string public name_;

    // Unguarded on purpose: makes `voter` structurally untrusted
    // (core/edges.py's trust resolution — a state var written by an
    // unauthenticated function is never treated as a fixed, trusted
    // destination), so the edges below are evaluated purely on
    // is_state_crossing, the actual property this fixture tests.
    function setVoter(address _voter) external {
        voter = _voter;
    }

    // DANGEROUS: entry IS its own sink — a direct, unguarded low-level
    // call with a state write in the SAME function, no intermediate
    // hop. The real Uniswap V3 swap()/flash() shape (untrusted callback
    // with open state writes). Must fire REENTRANCY_CEI.
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        balance = 0;
    }

    // Safe: the low-level call is a .staticcall(...) — the EVM
    // guarantees it (and everything reachable from it) cannot transfer
    // value or mutate state, so a co-located state write is not a real
    // reentrancy surface. Must NOT fire REENTRANCY_CEI, and must NOT be
    // classified ASSET_DRAIN or CALLBACK_SINK at all.
    function checkBalance() external returns (uint256) {
        (bool ok, bytes memory data) = token0.staticcall(
            abi.encodeWithSignature("balanceOf(address)", address(this))
        );
        require(ok, "staticcall failed");
        balance = abi.decode(data, (uint256));
        return balance;
    }

    // Safe: an inline reentrancy guard flattened directly into this
    // function's own body instead of expressed as a modifier — the
    // real Uniswap V3 swap() shape (require(!locked); locked = true;
    // ...; locked = false;), a gas optimization on a hot path. Must
    // NOT fire REENTRANCY_CEI — see
    // core/auth_detection.py::has_inline_reentrancy_guard.
    function withdrawLocked() external {
        require(!locked, "locked");
        locked = true;
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        balance = 0;
        locked = false;
    }

    // DANGEROUS: a state variable written twice around the external
    // call, structurally similar to withdrawLocked() at a glance, but
    // `counter` is never READ or revert-checked before its first
    // write — not a real guard, just an unrelated counter bump. Must
    // NOT be misdetected as an inline guard; REENTRANCY_CEI must still
    // fire.
    function withdrawFakeInline() external {
        counter += 1;
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        balance = 0;
        counter += 1;
    }

    // DANGEROUS: the low-level call's return value is completely
    // discarded — never captured, never checked. The real
    // King-of-Ether-style unchecked-return bug. Must fire
    // UNCHECKED_RETURN.
    function withdrawUnchecked() external {
        msg.sender.call{value: 0}("");
        balance = 0;
    }

    // Safe: the state write happens BEFORE the external call — the
    // real Liquity _sendETHGainToDepositor shape. No guard needed;
    // safety comes from ORDER, not a lock. Must NOT fire
    // REENTRANCY_CEI.
    function withdrawOrdered() external {
        balance = 0;
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
    }

    // Safe: the real Velodrome setName() shape — a state write with
    // an external call right next to it, but that call
    // (emergencyCouncil()) is view-only. STATICCALL semantics make it
    // structurally impossible for this call to reenter or mutate
    // state, regardless of write order or the absence of a lock. Must
    // NOT fire REENTRANCY_CEI or FLASHLOAN_WINDOW.
    function setNameLikeVelodrome(string calldata newName) external {
        require(msg.sender == IVoterLike(voter).emergencyCouncil(), "not council");
        name_ = newName;
    }

    // DANGEROUS: structurally identical to setNameLikeVelodrome() —
    // same auth-check shape, same state write — except the external
    // call is to a NON-view function (notifyRewardAmount is a real
    // state-mutating call on the callee side). A naive "any highlevel
    // call is safe" fix would wrongly suppress this too. Must still
    // fire REENTRANCY_CEI/FLASHLOAN_WINDOW.
    function setNameViaMutatingCall(string calldata newName) external {
        IVoterLike(voter).notifyRewardAmount(0);
        name_ = newName;
    }
}
