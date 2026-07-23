// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// A reentrancy guard modifier with a deliberately non-standard name
// (xyzzy) — does not match any entry/prefix in the old REENTRANCY_GUARDS/
// REENTRANCY_GUARD_PREFIXES name lists. Proves is_reentrancy_guard()
// detects it via real structural evidence (status read-check, write
// "entered" before the placeholder, write "not entered" after) instead
// of a name guess.
//
// fakeGuard is a negative control: writes a variable once (no real
// entered/not-entered pair straddling the placeholder) — must NOT be
// classified as a guard.
contract CustomReentrancyGuard {
    uint256 private _status;
    uint256 constant NOT_ENTERED = 1;
    uint256 constant ENTERED = 2;
    address public target;
    uint256 public counter;

    modifier xyzzy() {
        require(_status != ENTERED, "reentrant");
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }

    modifier fakeGuard() {
        counter += 1;
        _;
    }

    // Reproduces modern OpenZeppelin's real nonReentrant shape (v4.8+,
    // the current standard): the modifier itself is just two
    // InternalCalls straddling the placeholder — the actual
    // check/set/reset logic lives in the two private helpers, not
    // inlined in the modifier body. Found live this session: this
    // exact shape scored is_reentrancy_guard=False before the fix,
    // producing false-positive REENTRANCY_CEI on every real
    // nonReentrant-protected function in Fraxlend (borrowAsset,
    // liquidate, removeCollateral, etc.).
    modifier delegatedGuard() {
        _delegatedBefore();
        _;
        _delegatedAfter();
    }

    function _delegatedBefore() private {
        require(_status != ENTERED, "reentrant");
        _status = ENTERED;
    }

    function _delegatedAfter() private {
        _status = NOT_ENTERED;
    }

    // Negative control: ALSO delegates to helper functions before/after
    // the placeholder (same shape as delegatedGuard at a glance), but
    // the two helpers don't share a written+read state variable — must
    // NOT be misdetected as a guard just because internal calls are
    // now followed.
    modifier fakeDelegatedGuard() {
        _fakeBefore();
        _;
        _fakeAfter();
    }

    function _fakeBefore() private {
        counter += 1;
    }

    function _fakeAfter() private {
        target = msg.sender;
    }

    function withdraw() external xyzzy {
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        target = msg.sender;
    }

    function notReallyGuarded() external fakeGuard {
        target = msg.sender;
    }

    function withdrawDelegated() external delegatedGuard {
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        target = msg.sender;
    }

    function notReallyGuardedDelegated() external fakeDelegatedGuard {
        target = msg.sender;
    }

    uint256 private _guardCounter = 1;

    // Reproduces OpenZeppelin's own v2.x-era ReentrancyGuard shape
    // (before the boolean `_status` sentinel that later replaced it),
    // found live this session in real, currently-deployed Mento
    // Protocol's Broker on Celo: a monotonic counter fence instead of
    // a boolean lock — the guard variable is written ONLY before the
    // placeholder (incremented), never reset after it; the "already
    // entered" check instead lives AFTER the placeholder, comparing a
    // pre-call snapshot against the counter's current value. A
    // reentrant call would also increment the counter, breaking the
    // equality and reverting. _guard_shape_from_before_after requires
    // the SAME variable written on BOTH sides of the placeholder (the
    // boolean lock's set/reset idiom) and its revert-capable check
    // BEFORE the placeholder — neither holds here, so this scored
    // is_reentrancy_guard=False before the fix.
    modifier counterFenceGuard() {
        _guardCounter += 1;
        uint256 localCounter = _guardCounter;
        _;
        require(localCounter == _guardCounter, "reentrant call");
    }

    // Negative control: ALSO increments a counter before the
    // placeholder and snapshots it into a local — same shape at a
    // glance — but the after-side check compares the snapshot against
    // an UNRELATED variable, not the counter itself, so a reentrant
    // call that only mutates _guardCounter (not counter) would sail
    // right through. Must NOT be misdetected as a guard.
    modifier fakeCounterFenceGuard() {
        counter += 1;
        uint256 localCounter = counter;
        _;
        require(localCounter == _guardCounter, "not actually checking the right variable");
    }

    function withdrawCounterFenced() external counterFenceGuard {
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        target = msg.sender;
    }

    function notReallyGuardedCounterFence() external fakeCounterFenceGuard {
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        target = msg.sender;
    }
}
