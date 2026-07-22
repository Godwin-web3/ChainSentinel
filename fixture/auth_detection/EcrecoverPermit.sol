// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_params_proven_ecrecover_signer — the
// fix for the real Dai.permit() false positive found live this session
// against MakerDAO's Dai.sol:
//   require(holder == ecrecover(digest, v, r, s), "Dai/invalid-permit");
//   allowance[holder][spender] = wad;
// `holder` isn't caller-chosen — an attacker can't forge a valid ECDSA
// signature recovering to an arbitrary address — so the write is exactly
// as safe as Dai.approve()'s `allowance[msg.sender][usr] = wad`, just
// authenticated by a signature instead of the transaction sender.
contract EcrecoverPermit {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    bytes32 public constant DOMAIN_SEPARATOR = bytes32(uint256(1));

    // Makes `allowance` structurally "privileged" for classify_sinks
    // (core/sinks.py::_privileged_vars_by_contract): a real
    // msg.sender-keyed NUMERIC threshold check, the same real Dai
    // transferFrom() shape (find_economic_threshold_vars). Without
    // this, writes to `allowance` never become STORAGE_CORRUPTION
    // sinks at all and this fixture wouldn't exercise the check under
    // test.
    function spendAllowance(address src, uint256 wad) external view returns (bool) {
        return allowance[src][msg.sender] >= wad;
    }

    // Safe: the write's outer key (holder) is the SAME parameter
    // ecrecover proved is the real signer. Must be self-scoped.
    function permit(
        address holder, address spender, uint256 wad, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(holder, spender, wad, nonces[holder]++, deadline))
        ));
        require(holder != address(0), "invalid-address-0");
        require(holder == ecrecover(digest, v, r, s), "invalid-permit");
        require(block.timestamp <= deadline, "permit-expired");
        allowance[holder][spender] = wad;
    }

    // DANGEROUS: the ecrecover check proves `signer` is a real signature
    // holder, but the write is keyed by `victim` — a totally separate,
    // attacker-chosen parameter never constrained by the signature at
    // all. An attacker can supply their OWN valid signature (signer ==
    // themselves) while corrupting an arbitrary victim's allowance row.
    // Must NOT be self-scoped — ACCESS_CONTROL_GAP must still fire.
    function corruptViaUnrelatedSignature(
        address signer, address victim, address spender, uint256 wad,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(signer, spender, wad));
        require(signer == ecrecover(digest, v, r, s), "invalid-signature");
        allowance[victim][spender] = wad;
    }
}
