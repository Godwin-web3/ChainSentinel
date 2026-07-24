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

// Negative control (the critical adversarial regression case found
// live this session against Morpho Labs' real, currently-deployed
// MetaMorpho.sol): a genuinely permissionless "finalize" function,
// protected by NEITHER a one-time latch NOR an msg.sender check, but
// gated by a real elapsed-time delay since an EARLIER, privileged
// call scheduled it — the actual MetaMorpho
// `afterTimelock(pendingGuardian.validAt)` / `submitGuardian()` /
// `acceptGuardian()` shape, confirmed live via direct verification
// against the real fetched source. acceptOwner() can only ever
// finalize an ownership change the CURRENT owner already approved and
// scheduled via submitOwner's own onlyOwner gate. Must NOT fire — a
// time-delay gate against an externally-sourced deadline is a third,
// equally valid protection mechanism, distinct from a one-time latch
// or a direct msg.sender comparison.
contract TimelockGatedAccept {
    struct Pending { address value; uint256 validAt; }

    address public owner;
    Pending public pendingOwner;
    uint256 public timelock;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier afterTimelock(uint256 validAt) {
        require(validAt != 0, "no pending value");
        require(block.timestamp >= validAt, "timelock not elapsed");
        _;
    }

    function submitOwner(address newOwner) external onlyOwner {
        pendingOwner = Pending(newOwner, block.timestamp + timelock);
    }

    function acceptOwner() external afterTimelock(pendingOwner.validAt) {
        owner = pendingOwner.value;
        delete pendingOwner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// DANGEROUS: the critical adversarial regression case proving the fix
// checks the deadline's actual PROVENANCE, not just "some elapsed-time
// comparison exists" — the deadline here is freshly computed WITHIN
// this same call, from the current block.timestamp, so the check is
// pure theater and provides zero protection. Must still fire.
contract FakeTimelockDoesNotSuppressFinding {
    address public owner;
    uint256 public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function acceptOwner(address newOwner) external {
        uint256 fakeValidAt = block.timestamp;
        require(block.timestamp >= fakeValidAt, "timelock not elapsed");
        owner = newOwner;
    }

    function withdraw(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}

// Negative control (the critical adversarial regression case found
// live this session verifying against the real, currently-deployed
// MakerDAO Vat.sol — one of the most important, highest-TVL contracts
// in all of DeFi): hope(usr)/nope(usr) write `can[msg.sender][usr]` —
// a per-CALLER delegate-permission mapping (the exact same real
// pattern already proven self-scoped for ACCESS_CONTROL_GAP in
// fixture/auth_detection/NestedMappingSelfScope.sol) — with NO
// one-time-latch guard and no msg.sender-based own-auth check, since
// there's genuinely no identity check needed: the write can only ever
// land inside the CALLER's own subtree of `can`, never anyone else's,
// regardless of what `usr` is chosen. Previously false-positived
// UNPROTECTED_INITIALIZER with a reasoning string that was flatly
// wrong for this shape ("attacker can... become owner/admin"). Must
// NOT fire — core/constraints.py::_check_unprotected_initializer now
// applies the same self-scoped-write exemption ACCESS_CONTROL_GAP
// already had.
contract VatStyleSelfScopedPermission {
    address public constant ADMIN = address(0xdead);
    mapping(address => mapping(address => bool)) public can;

    // Makes `can` structurally "privileged" for classify_sinks — a
    // real msg.sender-keyed boolean lookup gating a revert, matching
    // the real AccessControl.hasRole shape.
    modifier onlyAdminApproved() {
        require(can[ADMIN][msg.sender], "not approved by admin");
        _;
    }

    function privilegedAction() external onlyAdminApproved {}

    function hope(address usr) external {
        can[msg.sender][usr] = true;
    }

    function nope(address usr) external {
        can[msg.sender][usr] = false;
    }

    // DANGEROUS: structurally identical shape (writes the SAME
    // privileged mapping, same lack of any guard), but neither the
    // outer key (victim) nor the inner key (usr) is msg.sender — an
    // attacker can corrupt an ARBITRARY victim's permission row. Must
    // still fire — proves the exemption requires genuine self-scoping,
    // not just "this privileged var has SOME self-scoped write
    // somewhere in the contract".
    function corruptGrant(address victim, address usr) external {
        can[victim][usr] = true;
    }
}

// Negative control (the critical adversarial regression case found live
// this session verifying against MatrixDock's real, currently-deployed
// STBTv2 — a real, currently-deployed RWA stablecoin): the real
// OpenZeppelin AccessControl.grantRole()/revokeRole() shape —
// `onlyRole(getRoleAdmin(role))`, a modifier invoked with a COMPUTED
// argument. The function's OWN body (just `_grantRole(role, account);`)
// carries zero auth evidence of its own — the real check lives entirely
// inside the attached modifier — so core/graph.py's
// structural_auth_score (own body only) was 0, and
// find_unprotected_initializer's own-auth exemption never applied even
// though the function genuinely is protected. Must NOT fire — grantRole/
// revokeRole are correctly, structurally auth-gated.
contract RoleBasedAccessControl {
    mapping(bytes32 => mapping(address => bool)) private _roles;
    mapping(bytes32 => bytes32) private _roleAdmin;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    // Makes `_roles` structurally "privileged" for classify_sinks — the
    // real AccessControl.hasRole shape: a msg.sender-keyed boolean
    // lookup gating a revert.
    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "missing role");
        _;
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roleAdmin[role];
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }

    function _revokeRole(bytes32 role, address account) internal {
        _roles[role][account] = false;
    }

    function grantRole(bytes32 role, address account) external onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }
}

// DANGEROUS: the critical adversarial regression case proving the fix
// checks the attached modifier's OWN genuine auth evidence, not merely
// "some modifier that takes an argument is attached" — a naive fix
// that just exempted any function with an argument-taking modifier
// would wrongly suppress this too. fakeGate takes an argument
// (superficially resembling the real onlyRole(getRoleAdmin(role))
// shape) but its body performs no real check at all. Must still fire
// UNPROTECTED_INITIALIZER.
contract FakeArgumentModifierIsNotRealAuth {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    mapping(bytes32 => mapping(address => bool)) private _roles;

    // Makes `_roles` structurally "privileged" — the same real
    // AccessControl.hasRole shape used in RoleBasedAccessControl above.
    modifier onlyRealRole(bytes32 role) {
        require(_roles[role][msg.sender], "missing role");
        _;
    }

    modifier fakeGate(bytes32) {
        _;
    }

    function privilegedAction() external onlyRealRole(DEFAULT_ADMIN_ROLE) {}

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }

    function grantRoleUnsafe(bytes32 role, address account) external fakeGate(role) {
        _grantRole(role, account);
    }
}

// Tests core/initializer_detection.py::_nodes_before_after_placeholder
// — the fix for the real false positive found live this session
// against SPOT Cash's real, currently-deployed Tranche.init(): OZ
// v4.5.0's real Initializable.sol guards with a TERNARY inside its
// require():
//   require(_initializing ? _isConstructor() : !_initialized, "...");
// Solidity lowers that ternary to actual IF/branch/ENDIF control flow
// — confirmed live via direct IR probe, Slither's own flat .nodes list
// places those lowered nodes AFTER the modifier's PLACEHOLDER in list
// order, even though they execute BEFORE it. Splitting before/after by
// list index (instead of real .sons-edge graph reachability) put the
// require()'s _initialized read in the WRONG (after) set, so the
// one-time latch was never recognized despite being genuine and
// correctly implemented.
contract InitializableV45 {
    bool private _initialized;
    bool private _initializing;

    modifier initializer() {
        require(_initializing ? _isConstructor() : !_initialized, "Initializable: contract is already initialized");
        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }
        _;
        if (isTopLevelCall) {
            _initializing = false;
        }
    }

    function _isConstructor() private view returns (bool) {
        return address(this).code.length == 0;
    }
}

// Safe: the real SPOT Cash Tranche.init() shape. Must NOT fire.
contract TrancheStyleTernaryLatch is InitializableV45 {
    address public bond;
    address public owner;

    // Makes `owner` structurally "privileged" for classify_sinks.
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function init(address _bond) public initializer {
        bond = _bond;
        owner = msg.sender;
    }

    function withdraw() external onlyOwner {}
}

// DANGEROUS: the critical adversarial regression case proving the fix
// doesn't just "notice a ternary/branch shape near the placeholder and
// assume it's a real check" — it must find a revert-capable read of
// the SPECIFIC variable being latched. fakeInitializer's ternary
// condition reads a completely unrelated flag (_unrelatedFlag, always
// true either way) — `_initialized` itself is set with no guarding
// check on it at all. Must still fire UNPROTECTED_INITIALIZER.
contract UnrelatedTernaryDoesNotSuppressFinding {
    bool private _initialized;
    bool private _unrelatedFlag;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier fakeInitializer() {
        require(_unrelatedFlag ? true : true, "always passes, checks the wrong flag");
        _initialized = true;
        _;
    }

    function init(address _owner) public fakeInitializer {
        owner = _owner;
    }

    function withdraw() external onlyOwner {}
}
