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

    // ── Real Morpho Blue setAuthorizationWithSig() shape ────────────
    //
    // Found live this session against Morpho Blue's real, currently-
    // deployed setAuthorizationWithSig(): permit()'s fully-inlined
    // `require(holder == ecrecover(...))` above is NOT the only real
    // idiom. Morpho's actual code names the recovered signer in a
    // LOCAL VARIABLE first:
    //   address signatory = ecrecover(digest, v, r, s);
    //   require(authorization.authorizer == signatory, "...");
    // and the value proven signer-bound is a STRUCT FIELD
    // (authorization.authorizer), not a bare parameter.
    // _params_proven_ecrecover_signer previously only matched the
    // fully-inlined form (one hop from the comparison to the
    // SolidityCall) — the local-variable indirection made it miss the
    // ecrecover call entirely, so known_signer stayed empty and this
    // exact real function false-positived MISSING_HEALTH_CHECK.
    struct Authorization {
        address authorizer;
        address authorized;
        bool isAuthorized;
    }

    mapping(address => mapping(address => bool)) public isAuthorized;
    mapping(address => uint256) public authNonce;
    mapping(address => uint256) public credit;

    // Makes `isAuthorized` structurally "privileged" — the real Morpho
    // Blue onBehalf-authorization gate shape.
    modifier onlyAuthorized(address onBehalf) {
        require(onBehalf == msg.sender || isAuthorized[onBehalf][msg.sender], "unauthorized");
        _;
    }

    function protectedAction(address onBehalf) external onlyAuthorized(onBehalf) {}

    // Makes `credit` structurally "privileged" — a plain msg.sender-
    // keyed numeric threshold gate, same shape as spendAllowance()
    // above but single-level (no nested mapping).
    modifier onlyCredited() {
        require(credit[msg.sender] > 0, "no credit");
        _;
    }

    function useCredit() external onlyCredited {}

    // Safe: the real Morpho Blue shape. The write's OUTER key
    // (authorization.authorizer) is the struct field ecrecover proved
    // is the real signer (via the local-variable `signatory`
    // indirection) — the INNER key (authorization.authorized) is
    // attacker-chosen, but that's fine: the write can only ever land
    // inside the signer's own subtree, exactly like Vat.hope()'s
    // `can[msg.sender][usr]`. Must be self-scoped.
    function setAuthorizationWithSig(
        Authorization calldata authorization, uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(
            authorization.authorizer, authorization.authorized, authNonce[authorization.authorizer]++
        ));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0) && authorization.authorizer == signatory, "invalid signature");
        isAuthorized[authorization.authorizer][authorization.authorized] = authorization.isAuthorized;
    }

    // DANGEROUS: the critical adversarial regression case proving
    // field-precision, not just "some ecrecover check exists in this
    // function". Reuses the SAME struct type and the SAME local-
    // variable-signatory idiom to prove authorization.authorizer is
    // signer-bound, but the actual write here is keyed SOLELY by
    // authorization.authorized — a completely different, unconstrained
    // struct field never touched by the signature check. A field-BLIND
    // fix (one that resolved any Member access on `authorization` to
    // the same coarse base-object identity — exactly what
    // core/destination_origin.py's ReferenceVariable resolution does
    // on its own) would wrongly treat this as self-scoped too, since
    // .authorizer and .authorized share the same base pointer. Must
    // NOT be self-scoped — ACCESS_CONTROL_GAP must still fire: an
    // attacker can sign a valid authorization for themselves (as
    // .authorizer) while naming an arbitrary victim as .authorized,
    // crediting ONLY the arbitrary victim's row.
    function corruptViaWrongStructField(
        Authorization calldata authorization, uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(
            authorization.authorizer, authorization.authorized, authNonce[authorization.authorizer]++
        ));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0) && authorization.authorizer == signatory, "invalid signature");
        credit[authorization.authorized] += 1;
    }
}
