// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_external_view_comparison_ir — the fix
// for the real Uniswap V3 onlyFactoryOwner() false positive found live
// this session: require(msg.sender == IUniswapV3Factory(factory).owner())
// compares msg.sender against the RETURN VALUE of an external view
// call, not a plain state variable, which the existing direct-
// comparison detector (state-variable/immutable only) couldn't see.
//
// badAuthCallerSuppliedFactory and badAuthStateChangingCall reproduce
// the two ways a naive "any external call's return counts" fix would
// get wrong: an attacker-supplied call destination, and a call that
// isn't provably side-effect-free. Both must NOT be treated as auth
// evidence.
interface IFactory {
    function owner() external view returns (address);
    function reportCaller() external returns (address);
}

contract ExternalViewAuth {
    IFactory public immutable factory;
    uint256 public criticalParam;

    constructor(IFactory _factory) {
        factory = _factory;
    }

    // Safe (real): destination (factory) is immutable — never
    // caller-controlled — and owner() is a view call, provably
    // side-effect-free. The real Uniswap V3 shape.
    modifier onlyFactoryOwner() {
        require(msg.sender == factory.owner(), "not factory owner");
        _;
    }

    function setCriticalParam(uint256 _value) external onlyFactoryOwner {
        criticalParam = _value;
    }

    // DANGEROUS: the call destination is an attacker-supplied
    // PARAMETER, not a fixed state variable — msg.sender is being
    // compared against whatever the CALLER chooses to report as
    // "owner". Must NOT be treated as auth evidence.
    function badAuthCallerSuppliedFactory(IFactory _fakeFactory, uint256 _value) external {
        require(msg.sender == _fakeFactory.owner(), "not owner");
        criticalParam = _value;
    }

    // DANGEROUS: the call is NOT view/pure (reportCaller() can have
    // side effects) — even though the destination is fixed, the call
    // itself isn't provably side-effect-free. Must NOT be treated as
    // auth evidence.
    function badAuthStateChangingCall(uint256 _value) external {
        require(msg.sender == factory.reportCaller(), "not caller");
        criticalParam = _value;
    }
}
