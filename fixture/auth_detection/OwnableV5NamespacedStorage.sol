// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_resolve_operand's InternalCall-unwrap
// fix — the real false positive found live this session against Acre's
// real, currently-deployed acreBTC vault (0x74B5E703bc31FC70B4bA50e7807f
// 9dAd013E338C): every onlyOwner-gated function (updateDispatcher,
// WithdrawalQueue.initialize, ...) scored UNAUTHENTICATED because
// OpenZeppelin v5.x's OwnableUpgradeable — the current default for new
// upgradeable deployments — stores `_owner` via ERC-7201 namespaced
// storage instead of a plain state variable:
//   function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
//       assembly { $.slot := OwnableStorageLocation }
//   }
//   function owner() public view returns (address) {
//       OwnableStorage storage $ = _getOwnableStorage();
//       return $._owner;
//   }
// Root cause: resolve_variable_origin($._owner, owner()) correctly
// reports origin=RETURN_VALUE with `resolved` pointing at the TEMP
// holding _getOwnableStorage()'s call result — but _resolve_operand's
// subsequent "unwrap this internal call" step looked up the defining IR
// keyed on the ORIGINAL variable ($._owner, a Member op — never an
// InternalCall), not on `resolved` (the actual call), so it always
// found the wrong IR and gave up before ever reaching
// _getOwnableStorage()'s own body. Fixed by keying that lookup on
// `resolved`. That body's own Return is `$.slot := <a bytes32 constant
// slot literal>` — a compile-time-fixed, non-attacker-influenced
// location exactly as trustworthy as a plain state variable, which is
// why DestinationOrigin.CONSTANT was added to _FIXED_ORIGINS alongside
// STATE_VARIABLE/IMMUTABLE.
contract OwnableUpgradeableV5Shape {
    struct OwnableStorage {
        address _owner;
    }

    bytes32 private constant OwnableStorageLocation =
        0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := OwnableStorageLocation
        }
    }

    error OwnableUnauthorizedAccount(address account);

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view virtual returns (address) {
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    function _checkOwner() internal view virtual {
        if (owner() != msg.sender) {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
    }

    function _transferOwnership(address newOwner) internal virtual {
        OwnableStorage storage $ = _getOwnableStorage();
        $._owner = newOwner;
    }

    function _initOwner(address initialOwner) internal {
        _transferOwnership(initialOwner);
    }
}

// Safe: the real Acre acreBTC shape. Must be recognized as auth-gated —
// score 3, AUTHENTICATED.
contract Treasury is OwnableUpgradeableV5Shape {
    uint256 public balance;

    constructor(address initialOwner) {
        _initOwner(initialOwner);
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }

    // DANGEROUS: the critical adversarial regression case — no guard at
    // all. Must NOT be recognized as auth-gated — proves the fix
    // doesn't blanket-trust anything merely for existing alongside a
    // real onlyOwner elsewhere in the same contract.
    function withdrawUnsafe(uint256 amount) external {
        balance -= amount;
    }
}

// DANGEROUS: the critical adversarial regression case proving the fix
// checks the storage slot's actual PROVENANCE, not just "some assembly
// computes a slot and a struct field off it" — here the slot is a
// CALLER-CHOSEN parameter, not a compile-time constant, so `$._owner`
// reads/writes an ARBITRARY storage slot the caller picked. This is the
// real "arbitrary storage location" vulnerability class the fix must
// NOT be fooled into trusting. Must NOT be recognized as auth-gated.
contract ArbitrarySlotIsNotConstant {
    struct OwnableStorage {
        address _owner;
    }

    error OwnableUnauthorizedAccount(address account);

    function _getOwnableStorageAt(bytes32 slot) private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := slot
        }
    }

    // `attackerSlot` is fully caller-controlled — reading `$._owner`
    // through it can land on ANY storage slot the caller names, so
    // comparing against it proves nothing about real ownership. Must
    // NOT score as real auth evidence.
    function checkOwnerAtArbitrarySlot(bytes32 attackerSlot) external view returns (bool) {
        OwnableStorage storage $ = _getOwnableStorageAt(attackerSlot);
        return $._owner == msg.sender;
    }
}

// Safe: the complementary real-world shape this fix also covers — a
// plain, direct comparison against a hardcoded `constant` address
// (e.g. a baked-in multisig), never previously recognized because
// DestinationOrigin.CONSTANT wasn't in _FIXED_ORIGINS at all. Must be
// recognized as auth-gated — score 3, AUTHENTICATED.
contract HardcodedConstantAdmin {
    address public constant ADMIN = 0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD;
    uint256 public balance;

    modifier onlyAdmin() {
        require(msg.sender == ADMIN, "not admin");
        _;
    }

    function withdraw(uint256 amount) external onlyAdmin {
        balance -= amount;
    }

    // DANGEROUS: no guard at all. Must NOT be recognized as auth-gated.
    function withdrawUnsafe(uint256 amount) external {
        balance -= amount;
    }
}
