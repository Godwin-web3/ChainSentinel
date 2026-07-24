// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// An UNRELATED sibling package that also happens to have its own
// `utils/` subdirectory — the cross-wire trap. If `@openzeppelin/utils`
// incorrectly resolves here instead of into the real openzeppelin-contracts
// tree, the entry file's `@openzeppelin/utils/math/Math.sol` import fails
// to find a matching file (this package has no `utils/math/` at all),
// and the whole project fails to compile.
library SafeTransferLib {
    function safeTransfer(address, address, uint256) internal pure {}
}
