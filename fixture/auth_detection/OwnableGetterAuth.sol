// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/auth_detection.py::_resolve_operand's INTERNAL-call
// return-value unwrap toward a FIXED_ORIGIN (state variable/
// immutable), not just toward MSG_SENDER.
//
// Live-verification finding: the real, currently-deployed OpenZeppelin
// v4.9.3 Ownable.sol shape —
//   modifier onlyOwner() { _checkOwner(); _; }
//   function _checkOwner() internal view virtual {
//       require(owner() == _msgSender(), "Ownable: caller is not the owner");
//   }
//   function owner() public view virtual returns (address) { return _owner; }
// — scored auth_score 0 everywhere before this fix: owner() is an
// INTERNAL call (same contract/inheritance chain), so
// _external_view_comparison_ir's EXTERNAL-call-only handling never
// applied, and _resolve_operand's existing internal-call unwrap only
// ever checked "does the callee return msg.sender", never "does the
// callee return a fixed state variable". This is the single most
// widely-deployed access-control pattern on Ethereum — virtually every
// Ownable-based contract in existence uses exactly this shape.

contract OwnableGetterAuth {
    address private _owner;
    uint256 public criticalParam;

    constructor() {
        _owner = msg.sender;
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    function _msgSender() internal view returns (address) {
        return msg.sender;
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    // Safe: the real OZ Ownable shape. Must score as structural auth
    // evidence (auth_score >= 3), with _owner as the matched state var.
    function setCriticalParam(uint256 v) external onlyOwner {
        criticalParam = v;
    }

    // DANGEROUS: the real backdoor shape — bypasses onlyOwner entirely
    // by writing the privileged state directly. Proves the fix doesn't
    // just blanket-trust every function in a contract that HAS an
    // Ownable-style getter somewhere; only functions actually GATED by
    // the real check count. Must NOT score as auth-protected.
    function backdoorSetOwner(address newOwner) external {
        _owner = newOwner;
    }

    // Adversarial: a function that superficially LOOKS like the same
    // getter-comparison shape (same call pattern:
    // require(fakeOwner(x) == msg.sender)) but fakeOwner() just echoes
    // back a CALLER-SUPPLIED parameter, not a fixed state variable —
    // trivially bypassable by passing your own address. Proves the fix
    // checks the callee's ACTUAL return provenance (state variable/
    // immutable only), not merely "some internal call's result is
    // compared against msg.sender". Must NOT score as auth.
    function fakeOwner(address suppliedOwner) public pure returns (address) {
        return suppliedOwner;
    }

    modifier onlyFakeOwner(address suppliedOwner) {
        require(fakeOwner(suppliedOwner) == msg.sender, "not fake owner");
        _;
    }

    function setCriticalParamBad(uint256 v, address suppliedOwner) external onlyFakeOwner(suppliedOwner) {
        criticalParam = v;
    }
}
