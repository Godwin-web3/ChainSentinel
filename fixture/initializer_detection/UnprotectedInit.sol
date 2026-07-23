// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/initializer_detection.py::find_unprotected_initializer —
// detects a "logical constructor" (a plain function moved out of a
// real constructor for proxy-compatibility) that sets privileged
// state with no guard against being invoked more than once, or by
// anyone.
//
// Real precedent: the Parity Multisig Wallet Library (Nov 2017) — its
// real initWallet() set `owner` with zero re-invocation guard. An
// attacker called it directly on the shared library contract (never
// meant to be initialized on its own), became its owner, then called
// the library's own kill() — selfdestructing it and permanently
// freezing ~513,774 ETH (~$280M) across 587 dependent wallets. The
// same root cause recurs constantly in modern proxy-based upgradeable
// contracts under "missing initializer modifier" /
// "front-runnable initialize()" — one of the most common real
// Code4rena/Sherlock findings for proxy-based protocols.

// Faithful minimal reproduction of the real, widely-deployed OZ v4.9
// Initializable.sol shape (buttonwood/aave/compound-v3-upgradeable and
// most of currently-deployed DeFi TVL still uses this exact shape;
// v5's ERC-7201 namespaced-storage rewrite is deliberately out of
// scope — assembly-based storage access, not a plain state variable).
contract Initializable {
    uint8 private _initialized;
    bool private _initializing;

    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) {
            _initializing = true;
        }
        _;
        if (isTopLevelCall) {
            _initializing = false;
        }
    }
}

// DANGEROUS: faithful minimal reproduction of the real Parity
// WalletLibrary shape — initWallet sets `owner` with ZERO guard
// against being called more than once, or by anyone. Must fire
// evidence.
contract ParityStyleWallet {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initWallet(address _owner) external {
        owner = _owner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }

    function kill() external onlyOwner {
        selfdestruct(payable(owner));
    }
}

// Safe: protected via the real OZ initializer modifier — a genuine
// one-time latch. Must NOT fire.
contract ProtectedInitializable is Initializable {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// Safe: protected via an inline self-referential guard — checks the
// auth variable itself is still at its zero-value sentinel before
// setting it. Must NOT fire.
contract InlineGuardedInit {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address _owner) external {
        require(owner == address(0), "already initialized");
        owner = _owner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// DANGEROUS: the critical adversarial regression case — a real
// nonReentrant-style guard is attached, but nonReentrant only TOGGLES
// its flag (set before, reset after) — it provides no protection
// whatsoever against being called again in a SEPARATE later
// transaction, only against reentrant calls DURING the same one. Must
// still fire — a reentrancy guard is not a substitute for a one-time
// latch.
contract NonReentrantIsNotAnInitializerGuard {
    address public owner;
    uint256 public balance;
    bool private _status;

    modifier nonReentrant() {
        require(!_status, "reentrant call");
        _status = true;
        _;
        _status = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address _owner) external nonReentrant {
        owner = _owner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// Negative control: owner is set ONLY in the real Solidity constructor
// — EVM-enforced single-invocation already, runs once at the
// implementation's own deployment. Must NOT fire.
contract ConstructorOnly {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// Negative control: the unprotected owner-setting logic lives in an
// INTERNAL helper, never externally callable on its own — an attacker
// cannot invoke it directly regardless of guard status. Must NOT fire.
contract InternalHelperOnly {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _setupOwner(address _owner) internal {
        owner = _owner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// Negative control (the critical adversarial regression case found
// live this session): the real OpenZeppelin Ownable2Step shape.
// acceptOwnership() writes owner/pendingOwner (privileged) with NO
// one-time latch — by design, since it's a REPEATABLE acceptance step,
// not a single-use initializer — but IS genuinely protected by a real
// msg.sender comparison against pendingOwner, a value only the CURRENT
// owner could have set (via transferOwnership's own onlyOwner gate).
// Must NOT fire — a one-time latch is not the ONLY valid protection;
// genuine msg.sender-based auth is equally valid and must be
// recognized.
contract Ownable2StepStyleAccept {
    address public owner;
    address public pendingOwner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        address sender = msg.sender;
        require(pendingOwner == sender, "not pending owner");
        owner = sender;
        pendingOwner = address(0);
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}
