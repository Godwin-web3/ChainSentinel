// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_external_view_return_verdict_ir and
// core/edges.py::_function_can_revert — the fix for the real Balancer/
// Berachain BEX Authorizer false positive found live this session on
// ProtocolFeesCollector.withdrawCollectedFees() (deployed on Berachain
// at 0x4Be03f781C497A489E3cB0287833452cA9B9E80B):
//
//   function _canPerform(bytes32 actionId, address account)
//       internal view override returns (bool)
//   {
//       return _getAuthorizer().canPerform(actionId, account, address(this));
//   }
//   function _getAuthorizer() internal view returns (IAuthorizer) {
//       return vault.getAuthorizer();  // vault is IVault public immutable
//   }
//   modifier authenticate() {
//       _authenticateCaller();
//       _;
//   }
//   function _authenticateCaller() internal view {
//       _require(_canPerform(getActionId(msg.sig), msg.sender), 401);
//   }
//
// Two structural gaps, both real and independent:
//  1. Balancer's real revert path is a free-function wrapper,
//     `_require(bool, uint256) { if (!condition) _revert(errorCode); }`,
//     where `_revert` itself reverts via raw `assembly { revert(...) }`
//     — invisible to the old _node_can_revert, which only recognized a
//     DIRECT SolidityCall to the require()/assert() builtins in the
//     SAME node. Fixed via _function_can_revert (core/edges.py):
//     recognizes Slither's own assembly-decoded `SolidityCall ...
//     revert(...)` IR op, and recurses through internal revert-wrapper
//     calls.
//  2. _canPerform's own body has NO `==`/`!=` comparison at all — the
//     external call's raw boolean return IS the verdict, forwarded
//     unchanged. The existing _external_view_comparison_ir requires a
//     Binary comparison and can't see this. Fixed via
//     _external_view_return_verdict_ir (core/auth_detection.py).
//
// badAuthCallerSuppliedAuthorizer, badAuthNoCallerArgument, and
// badAuthMutatingCall reproduce the ways a naive fix could weaken real
// detection; fakeRequireNeverReverts proves _function_can_revert checks
// for a REAL revert path, not just "looks like a wrapper."
interface IAuthorizer {
    function canPerform(bytes32 actionId, address account, address where) external view returns (bool);
    function reportAndApprove(bytes32 actionId, address account, address where) external returns (bool);
}

function _require(bool condition, uint256 errorCode) pure {
    if (!condition) _revert(errorCode);
}

function _revert(uint256 errorCode) pure {
    assembly {
        let scratch := mload(0x40)
        mstore(scratch, errorCode)
        revert(scratch, 0x20)
    }
}

// Superficially identical wrapper shape, but the inner "revert" call
// never actually reverts (it's a no-op) — must NOT be treated as
// revert-capable, proving the fix checks for a real revert path rather
// than pattern-matching "a function named like a revert wrapper."
function _fakeRequire(bool /* condition */, uint256 /* errorCode */) pure {
    _fakeRevert();
}

function _fakeRevert() pure {
    assembly {
        let scratch := mload(0x40)
        mstore(scratch, 0)
        // Deliberately NOT a revert — pop discards the value instead.
        pop(scratch)
    }
}

contract AuthorizerReturnVerdict {
    IAuthorizer public immutable authorizer;
    uint256 public criticalParam;

    constructor(IAuthorizer _authorizer) {
        authorizer = _authorizer;
    }

    // Safe (real): the real Balancer/Berachain BEX shape. `authorizer`
    // is immutable (never caller-controlled), canPerform() is view
    // (provably side-effect-free), and `msg.sender` is passed straight
    // through as the `account` argument — the raw bool return IS the
    // auth verdict, gated by a real revert (via the assembly-based
    // _revert wrapper).
    function _canPerform(bytes32 actionId, address account) internal view returns (bool) {
        return authorizer.canPerform(actionId, account, address(this));
    }

    modifier authenticate() {
        _require(_canPerform(bytes32(0), msg.sender), 401);
        _;
    }

    function withdrawCollectedFees(uint256 amount) external authenticate {
        criticalParam = amount;
    }

    // DANGEROUS: the authorizer destination is an attacker-supplied
    // PARAMETER, not the fixed immutable `authorizer` — msg.sender is
    // being checked against whatever the caller chooses to report as
    // permission. Must NOT be treated as auth evidence.
    function badAuthCallerSuppliedAuthorizer(IAuthorizer fakeAuthorizer, uint256 amount) external {
        _require(fakeAuthorizer.canPerform(bytes32(0), msg.sender, address(this)), 401);
        criticalParam = amount;
    }

    // DANGEROUS: the fixed-destination view call's boolean return is
    // used directly as the verdict, but msg.sender is NEVER passed as
    // one of its arguments — nothing ties the permission check to the
    // actual caller's identity (e.g. it always checks a hardcoded
    // address). Must NOT be treated as auth evidence.
    function badAuthNoCallerArgument(uint256 amount) external {
        _require(authorizer.canPerform(bytes32(0), address(0xdead), address(this)), 401);
        criticalParam = amount;
    }

    // DANGEROUS: the call is NOT view/pure (reportAndApprove can have
    // side effects) — even though the destination is fixed and
    // msg.sender is passed through, the call itself isn't provably
    // side-effect-free. Must NOT be treated as auth evidence.
    function badAuthMutatingCall(uint256 amount) external {
        _require(authorizer.reportAndApprove(bytes32(0), msg.sender, address(this)), 401);
        criticalParam = amount;
    }

    // DANGEROUS: structurally mimics the real wrapper (a "_require"-
    // shaped call around a fixed-destination/msg.sender-bound verdict)
    // but the wrapper never actually reverts on failure — a fake gate.
    // Must NOT be treated as auth evidence.
    function fakeRequireNeverReverts(uint256 amount) external {
        _fakeRequire(_canPerform(bytes32(0), msg.sender), 401);
        criticalParam = amount;
    }
}
