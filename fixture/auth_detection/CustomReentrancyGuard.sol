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

    function withdraw() external xyzzy {
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "call failed");
        target = msg.sender;
    }

    function notReallyGuarded() external fakeGuard {
        target = msg.sender;
    }
}
