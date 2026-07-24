// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_signer_comparison_ir — the fix for the
// real false positive found live this session against set.wtf's real,
// currently-deployed LiquidityPool (0x2506CB864df6336d93A87C4af2b644fd61cF4d81):
//   address signer1 = ethSignedMessageHash.recover(ownerSig);
//   require(signer1 == owner() && signer2 == secondOwner, "Invalid signatures");
// OpenZeppelin's ECDSA.recover() (via `using ECDSA for bytes32`) compiles
// to a LibraryCall, not a direct ecrecover(...) SolidityCall — neither
// the msg.sender-only _direct_comparison_ir nor the direct-SolidityCall-
// only _params_proven_ecrecover_signer (built earlier this session for
// Dai.permit()/Morpho's setAuthorizationWithSig()) recognized this as
// real access-control evidence for the WHOLE FUNCTION's compute_own_auth
// score, so batchProcessWithdrawals/batchProcessRewardClaims (both
// gated only by this pattern) false-positived ACCESS_CONTROL_GAP.
//
// The library below is a faithful reproduction of the REAL, currently-
// deployed @openzeppelin/contracts v4.9.x ECDSA.sol shape (pulled live
// this session as part of set.wtf's own dependency tree) — not a
// simplified invention. The first version of this fix used a single-
// hop recover() that called ecrecover directly, and it passed this
// fixture while still false-positiving on the real contract: OZ's real
// recover(bytes32,bytes) never calls ecrecover itself — it forwards
// through tryRecover(hash, signature) -> tryRecover(hash, v, r, s) ->
// ecrecover(...), three internal-call hops deep. Reproducing that exact
// depth here is what makes this fixture an honest regression guard
// against _is_ecrecover_derived_call's recursion depth, rather than a
// shape that happens to pass a shallower, unrealistic version of the
// check.
library ECDSA {
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(hash, v, r, s);
    }

    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return tryRecover(hash, v, r, s);
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return tryRecover(hash, signature);
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}

contract LiquidityPool {
    using ECDSA for bytes32;

    address private owner_;
    address public secondOwner;
    mapping(address => uint256) public pendingWithdrawals;

    constructor(address _owner, address _secondOwner) {
        owner_ = _owner;
        secondOwner = _secondOwner;
    }

    // Makes `pendingWithdrawals` structurally "privileged" for
    // classify_sinks — a real msg.sender-keyed numeric threshold check,
    // same shape as EcrecoverPermit.sol's spendAllowance().
    function claim() external view returns (bool) {
        return pendingWithdrawals[msg.sender] >= 0;
    }

    // Real set.wtf _validateBatchSignatures() shape: the signature check
    // lives in a SEPARATE internal function, delegated to via an
    // internal call, and the comparison target is owner() — an
    // INTERNAL GETTER call, not a bare state-variable read (same
    // indirection OwnableGetterAuth.sol already covers for msg.sender,
    // here composed with the signer-recovery indirection too) — plus a
    // compound `&&` with a second signer against a second fixed
    // variable, the real two-signature-required shape.
    function _validateBatchSignatures(
        address[] calldata recipients, bytes calldata ownerSig, bytes calldata secondSig
    ) internal view {
        bytes32 hash = keccak256(abi.encode(recipients, block.chainid));
        bytes32 ethSignedMessageHash = hash.toEthSignedMessageHash();
        address signer1 = ethSignedMessageHash.recover(ownerSig);
        address signer2 = ethSignedMessageHash.recover(secondSig);
        require(signer1 == owner() && signer2 == secondOwner, "Invalid signatures");
    }

    function owner() public view returns (address) {
        return owner_;
    }

    // Real set.wtf shape: the whole function's auth evidence lives
    // entirely in a signer-recovered-via-library-call comparison against
    // a fixed state variable, reached through a delegated internal
    // function AND an internal getter, no msg.sender comparison
    // anywhere. Must be AUTHENTICATED.
    function batchProcessWithdrawals(
        address[] calldata recipients, uint256[] calldata amounts, bytes calldata ownerSig, bytes calldata secondSig
    ) external {
        _validateBatchSignatures(recipients, ownerSig, secondSig);
        for (uint256 i = 0; i < recipients.length; i++) {
            pendingWithdrawals[recipients[i]] = amounts[i];
        }
    }

    // DANGEROUS: no signature check, no msg.sender check, nothing —
    // must stay UNAUTHENTICATED.
    function batchProcessWithdrawalsUnsafe(
        address[] calldata recipients, uint256[] calldata amounts
    ) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            pendingWithdrawals[recipients[i]] = amounts[i];
        }
    }

    // DANGEROUS: the critical adversarial regression case. The only
    // "check" here is the common defensive null-check
    // `signer != address(0)` — comparing a recovered signer against the
    // literal zero address is NOT evidence of a genuine trust anchor,
    // it's a sanity check that ANY recovered signer (attacker's own
    // valid signature included) trivially passes. A fix that added
    // CONSTANT to _FIXED_ORIGINS without excluding literal zero would
    // wrongly treat this as real access control. Must stay
    // UNAUTHENTICATED — ACCESS_CONTROL_GAP must still fire.
    function batchProcessWithdrawalsZeroCheckOnly(
        address[] calldata recipients, uint256[] calldata amounts, bytes calldata anySig
    ) external {
        bytes32 hash = keccak256(abi.encode(recipients, amounts, block.chainid));
        address signer = hash.toEthSignedMessageHash().recover(anySig);
        require(signer != address(0), "invalid signature");
        for (uint256 i = 0; i < recipients.length; i++) {
            pendingWithdrawals[recipients[i]] = amounts[i];
        }
    }
}
