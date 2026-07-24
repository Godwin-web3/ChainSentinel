// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_params_proven_fresh_key — the fix for
// the real ACCESS_CONTROL_GAP + UNPROTECTED_INITIALIZER false positive
// found live this session against Asymmetry USDaf's real, currently-
// deployed BorrowerOperations.sol (a Liquity V2 fork):
//   troveId = keccak256(msg.sender, owner, ownerIndex);
//   _requireTroveDoesNotExists(troveManager, troveId);   // reverts if it exists
//   ...
//   _setAddManager(troveId, addManager);                 // addManagerOf[troveId] = addManager
// `troveId` is neither msg.sender nor a fresh CREATE2/clone address —
// it's a plain computed key — but the explicit revert-gated existence
// check PROVES no prior write could have touched it, exactly the same
// "nothing else could have a claim on this yet" guarantee msg.sender-
// keying already gets credit for. The check and the write live in TWO
// DIFFERENT internal calls, both made from the SAME entry function
// (_openTrove calls _requireTroveDoesNotExists, then separately calls
// _setAddManager) — not a direct caller/callee relationship, which is
// what previously made this invisible to find_self_scoped_writes.
interface IRegistry {
    function getStatus(uint256 id) external view returns (Status);
}

enum Status { nonExistent, active, closed }

contract FreshKeyRegistry is IRegistry {
    mapping(uint256 => Status) public statusOf;

    function getStatus(uint256 id) external view returns (Status) {
        return statusOf[id];
    }

    function setStatus(uint256 id, Status s) external {
        statusOf[id] = s;
    }
}

contract FreshKeySelfScope {
    IRegistry public immutable registry;

    struct ManagerReceiver {
        address manager;
        address receiver;
    }

    mapping(uint256 => address) public addManagerOf;
    mapping(uint256 => ManagerReceiver) public removeManagerReceiverOf;

    constructor(IRegistry _registry) {
        registry = _registry;
    }

    // Makes addManagerOf/removeManagerReceiverOf structurally
    // "privileged" for classify_sinks (core/sinks.py::
    // _privileged_vars_by_contract) — a real revert-gated
    // msg.sender-keyed comparison on the SAME variables the writes
    // under test target, matching the real Liquity V2 use of these
    // mappings to gate "am I authorized to act on this position".
    function onlyMyAddManager(uint256 id) external view {
        require(addManagerOf[id] == msg.sender, "not my manager");
    }

    function onlyMyRemoveManager(uint256 id) external view {
        require(removeManagerReceiverOf[id].manager == msg.sender, "not my remove manager");
    }

    function _requireDoesNotExist(uint256 id) internal view {
        Status status = registry.getStatus(id);
        if (status != Status.nonExistent) revert("exists");
    }

    function _setAddManager(uint256 id, address manager) internal {
        addManagerOf[id] = manager;
    }

    function _setRemoveManagerAndReceiver(uint256 id, address manager, address receiver) internal {
        removeManagerReceiverOf[id].manager = manager;
        removeManagerReceiverOf[id].receiver = receiver;
    }

    // Safe (real Liquity V2 openTrove shape): id is a fresh, computed
    // key, explicitly proven via a revert-gated existence check made
    // from a SIBLING internal call before either write happens. Must
    // be self-scoped — both the plain-mapping write (addManagerOf) and
    // the struct-field write on an indexed entry
    // (removeManagerReceiverOf[id].manager/.receiver).
    function openPosition(
        address owner, uint256 ownerIndex, address manager, address removeManager, address receiver
    ) external returns (uint256) {
        uint256 id = uint256(keccak256(abi.encode(msg.sender, owner, ownerIndex)));
        _requireDoesNotExist(id);
        _setAddManager(id, manager);
        _setRemoveManagerAndReceiver(id, removeManager, receiver);
        return id;
    }

    // DANGEROUS: writes the SAME mappings with a caller-supplied id
    // that is NEVER checked for freshness anywhere. Must NOT be
    // self-scoped — ACCESS_CONTROL_GAP must still fire.
    function corruptExistingManager(uint256 id, address manager) external {
        _setAddManager(id, manager);
    }

    // DANGEROUS: the critical adversarial regression case proving
    // POLARITY-precision, not just "some status check exists nearby".
    // This check proves the record DOES exist (the opposite claim of
    // freshness) — a real "must already be registered" guard, not a
    // "must not exist yet" one. Must NOT be treated as a freshness
    // proof — ACCESS_CONTROL_GAP must still fire.
    function updateExistingManager(uint256 id, address manager) external {
        Status status = registry.getStatus(id);
        if (status == Status.nonExistent) revert("does not exist");
        _setAddManager(id, manager);
    }
}
