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
contract ReentrancyEdgeCases {
    uint256 public balance;
    address public token0;
    bool public locked;
    uint256 public counter;

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
}
