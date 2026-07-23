// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/vault_detection.py::find_unsafe_share_price_divisor — the
// replacement for core/constraints.py's old _check_share_inflation /
// _rate_is_balance_derived, which grepped CallEdge.function_name
// strings for words like "totalassets", "converttoshares", "offset",
// "virtual", "dead", "minimum" — unable to verify a balanceOf() call's
// ARGUMENT is actually address(this), unable to verify a "virtual
// offset" is a real additive term on the actual divisor rather than a
// coincidentally-named function anywhere on the path.
//
// Real precedent for the vulnerable shape: Sherlock's real
// 2024-01-napier-judging#125 finding against Napier's
// BaseLSTAdapter.totalAssets() (`withdrawalQueueEth + bufferEth +
// STETH.balanceOf(address(this))`, no offset), and Zellic's real
// Perennial audit finding of the identical shape. Real precedent for
// the protected shape: OpenZeppelin's actual ERC4626 v4.9+/v5
// _convertToShares (`assets.mulDiv(totalSupply() + 10 **
// _decimalsOffset(), totalAssets() + 1, rounding)`) — confirmed live
// via IR probe against the real library source that even the
// "protected" implementation still calls balanceOf(address(this))
// unconditionally in totalAssets() itself; the real protection is the
// additive virtual-offset term on the divisor, not avoiding
// balanceOf(this) altogether.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

// Faithful minimal reproduction of the real Solmate mulDivDown shape
// (transmissions11/solmate FixedPointMathLib.sol), used verbatim by a
// huge fraction of real ERC4626 vaults.
library FixedPointMathLib {
    function mulDivDown(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 z) {
        assembly {
            if iszero(mul(denominator, iszero(mul(x, gt(x, div(not(0), y)))))) { revert(0, 0) }
            z := div(mul(x, y), denominator)
        }
    }
}

// DANGEROUS: the real, unprotected Solmate ERC4626 shape — raw
// balanceOf(this) as totalAssets, no virtual offset in the ratio. Must
// fire SHARE_INFLATION (CONFIRMED).
contract VulnerableVault {
    using FixedPointMathLib for uint256;
    IERC20 public asset;
    uint256 public totalSupply;

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares != 0, "ZERO_SHARES");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
    }
}

// Safe: the real OpenZeppelin v4.9+/v5 shape — same raw
// balanceOf(this)-derived totalAssets, but the ratio itself includes
// virtual offset constants (+1 asset, +10**decimalsOffset shares),
// making the attack economically unprofitable regardless of donation
// size. Must NOT fire.
contract ProtectedVaultVirtualOffset {
    using FixedPointMathLib for uint256;
    IERC20 public asset;
    uint256 public totalSupply;

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets.mulDivDown(totalSupply + 10 ** 3, totalAssets() + 1);
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares != 0, "ZERO_SHARES");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
    }
}

// Safe: totalAssets is INTERNALLY TRACKED (only ever changes via this
// contract's own deposit/withdraw bookkeeping), not a raw balanceOf
// read — a direct token donation to this contract is invisible to the
// ratio entirely, so the classic attack simply doesn't apply,
// regardless of any virtual offset. The real Aave/Compound-style
// accounting shape. Must NOT fire.
contract ProtectedVaultInternalAccounting {
    using FixedPointMathLib for uint256;
    IERC20 public asset;
    uint256 public totalSupply;
    uint256 public totalAssetsTracked;

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : assets.mulDivDown(supply, totalAssetsTracked);
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares != 0, "ZERO_SHARES");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        totalAssetsTracked += assets;
    }
}

// Negative control: a decoy contract whose function/variable NAMES are
// deliberately chosen to match every keyword the OLD name-matching
// heuristic grepped for ("totalAssets", "convertToShares",
// "previewDeposit", "virtualOffset", "decimalsOffset", "deposit",
// "donate") — but NONE of it actually computes a balanceOf(this)-
// derived share-price ratio at all; "totalAssets" here is an unrelated
// counter, and "convertToShares" just doubles a number. Proves the
// fix isn't just a different set of names that happens to work on the
// obvious cases — it requires the real structural shape. Must NOT
// fire under any circumstance.
contract NameDecoyOnly {
    uint256 public totalAssets;
    uint256 public totalSupply;
    uint256 public virtualOffset;
    uint256 public decimalsOffset;

    function convertToShares(uint256 assets) public pure returns (uint256) {
        return assets * 2;
    }

    function previewDeposit(uint256 assets) public pure returns (uint256) {
        return assets;
    }

    function donate(uint256 amount) external {
        totalAssets += amount;
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = convertToShares(assets);
        totalSupply += shares;
    }
}

// Negative control: reads balanceOf(address(this)) for a completely
// unrelated purpose (an informational view getter) — never used as
// the divisor of any share-price ratio at all. Proves the fix doesn't
// flag every balanceOf(this) read on sight, only ones actually feeding
// a share-conversion divisor. Must NOT fire.
contract BalanceOfUnrelatedUse {
    using FixedPointMathLib for uint256;
    IERC20 public asset;
    uint256 public totalSupply;
    uint256 public fixedPrice = 1e18;

    function currentReserves() external view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        // Divisor is a fixed, constructor-set price — never
        // balanceOf(this)-derived at all.
        return assets.mulDivDown(totalSupply, fixedPrice);
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares != 0, "ZERO_SHARES");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
    }
}
