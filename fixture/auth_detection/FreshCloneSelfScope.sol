// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_is_fresh_clone_call — the fix for the
// real ACCESS_CONTROL_GAP + UNPROTECTED_INITIALIZER + MISSING_HEALTH_CHECK
// false positive found live this session against NUVA's real, currently-
// deployed DedicatedVaultRouter.sol:
//   address redemptionProxyAddress = Clones.clone(redemptionProxyImplementation);
//   ...
//   redemptionProxyToFunds[redemptionProxyAddress] = UserFunds({user: msg.sender, ...});
// A mapping key that IS the address of a contract just deployed this
// same transaction can't have any prior owner — nothing else in
// existence could have any claim on it. The library below is a
// faithful reproduction of the real, currently-deployed
// @openzeppelin/contracts v5.4.0 Clones.sol shape (pulled live this
// session as part of NUVA's own dependency tree) — including the real
// TWO-hop forwarding (clone(address) -> clone(address,uint256)) and
// the real inline-assembly `create` opcode — not a simplified
// invention, since a shallower version previously passed a simplified
// fixture while still missing the real, deployed shape.
library Clones {
    function clone(address implementation) internal returns (address instance) {
        return clone(implementation, 0);
    }

    function clone(address implementation, uint256 value) internal returns (address instance) {
        assembly {
            mstore(0x00, or(shr(0xe8, shl(0x60, implementation)), 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000))
            mstore(0x20, or(shl(0x78, implementation), 0x5af43d82803e903d91602b57fd5bf3))
            instance := create(value, 0x09, 0x37)
        }
    }
}

contract FreshCloneSelfScope {
    address public implementation;

    mapping(address => address) public cloneToOwner;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    // Makes cloneToOwner structurally "privileged" for classify_sinks
    // (core/sinks.py::_privileged_vars_by_contract) — a real
    // revert-gated msg.sender-keyed comparison on the SAME variable
    // the write under test targets, matching the real NUVA use of this
    // mapping to gate "am I the owner of this redemption proxy".
    function onlyMyClone(address instance) external view {
        require(cloneToOwner[instance] == msg.sender, "not my clone");
    }

    // Safe (real NUVA DedicatedVaultRouter shape): the write's key is
    // the address of an EIP-1167 minimal-proxy clone deployed THIS
    // SAME call — nothing else in existence could have any prior claim
    // on it. Must be self-scoped.
    function requestAction() external returns (address) {
        address instance = Clones.clone(implementation);
        cloneToOwner[instance] = msg.sender;
        return instance;
    }

    // DANGEROUS: writes the SAME mapping keyed by a caller-supplied
    // address, never a freshly deployed clone. Must NOT be self-scoped
    // — ACCESS_CONTROL_GAP must still fire.
    function corruptCloneOwner(address instance, address owner) external {
        cloneToOwner[instance] = owner;
    }
}
