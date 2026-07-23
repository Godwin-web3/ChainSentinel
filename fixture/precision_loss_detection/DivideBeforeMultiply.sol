// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/precision_loss_detection.py::find_unsafe_divide_before_multiply
// — detects a raw division whose (already-truncated) result later
// becomes an operand of a multiplication feeding critical accounting
// state.
//
// Real precedent for the vulnerable shape: Code4rena's real
// 2022-05-cally-findings#280 — Cally.sol's real
// getDutchAuctionStrike(): each line individually LOOKS like the safe
// "multiply, then divide" shape, but the first line's division result
// (`progress`) gets squared in a SECOND multiplication, compounding
// its truncation error into the option's strike price. Real precedent
// for the protected shapes: the real Cally fix (eliminate the
// intermediate division, multiply everything first, divide once at
// the end) and Solmate's actual FixedPointMathLib.mulDivDown
// (`div(mul(x, y), denominator)`, fully fused in one assembly
// instruction), confirmed live via IR probe against both real
// reference sources.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

// DANGEROUS: faithful minimal reproduction of the real Cally
// getDutchAuctionStrike() shape, immediately used to charge the caller
// (a realistic Dutch-auction-exercise flow). Must fire evidence.
contract VulnerableAuction {
    uint256 public constant AUCTION_DURATION = 1 days;
    mapping(uint256 => uint256) public auctionStrike;
    IERC20 public paymentToken;

    function exercise(uint256 id, uint256 delta, uint256 startingStrike) external {
        uint256 progress = (1e18 * delta) / AUCTION_DURATION;
        auctionStrike[id] = (progress * progress * startingStrike) / (1e18 * 1e18);
        paymentToken.transferFrom(msg.sender, address(this), auctionStrike[id]);
    }
}

// Safe: the real recommended fix — eliminate the intermediate
// division entirely, multiply everything first, divide once at the
// very end. Must NOT fire.
contract ProtectedAuction {
    uint256 public constant AUCTION_DURATION = 1 days;
    mapping(uint256 => uint256) public auctionStrike;
    IERC20 public paymentToken;

    function exercise(uint256 id, uint256 delta, uint256 startingStrike) external {
        auctionStrike[id] = (delta * delta * startingStrike) / (AUCTION_DURATION * AUCTION_DURATION);
        paymentToken.transferFrom(msg.sender, address(this), auctionStrike[id]);
    }
}

// Faithful minimal reproduction of Solmate's real
// FixedPointMathLib.mulDivDown.
library FixedPointMathLib {
    function mulDivDown(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 z) {
        assembly {
            if iszero(mul(denominator, iszero(mul(x, gt(x, div(not(0), y)))))) { revert(0, 0) }
            z := div(mul(x, y), denominator)
        }
    }
}

// Safe: the real mulDiv-family fused pattern — the intermediate
// division (necessarily present to compute a ratio at all) is fully
// opaque, full-precision, and lives inside an assembly block that
// never lowers to a visible Binary DIVISION op at this level. Must
// NOT fire.
contract ProtectedMulDivLibrary {
    using FixedPointMathLib for uint256;
    mapping(uint256 => uint256) public auctionStrike;
    IERC20 public paymentToken;

    function exercise(uint256 id, uint256 delta, uint256 startingStrike) external {
        uint256 progress = delta.mulDivDown(1e18, 1 days);
        auctionStrike[id] = progress.mulDivDown(progress, 1e18).mulDivDown(startingStrike, 1e18);
        paymentToken.transferFrom(msg.sender, address(this), auctionStrike[id]);
    }
}

// Negative control: an UNRELATED division and an UNRELATED
// multiplication both exist in the same function, but the division's
// OWN result never flows into the multiplication at all — proves the
// detector requires the actual dataflow link, not mere co-occurrence.
// Must NOT fire.
contract UnrelatedDivisionAndMultiplicationDoNotFalsePositive {
    mapping(uint256 => uint256) public auctionStrike;
    mapping(uint256 => uint256) public cooldownRemaining;
    IERC20 public paymentToken;

    function exercise(uint256 id, uint256 delta, uint256 startingStrike) external {
        uint256 cooldownFraction = delta / 100;
        cooldownRemaining[id] = cooldownFraction;

        auctionStrike[id] = delta * startingStrike;
        paymentToken.transferFrom(msg.sender, address(this), auctionStrike[id]);
    }
}

// Negative control: names deliberately chosen to match every keyword a
// name-matching heuristic would grep for ("price", "shares",
// "strike") but none of it actually performs a division whose result
// later feeds a multiplication. Must NOT fire.
contract NameDecoyOnly {
    uint256 public sharePrice;
    uint256 public strikeValue = 1e18;
    IERC20 public paymentToken;

    function exercise(uint256 delta) external {
        sharePrice = delta * strikeValue;
        paymentToken.transferFrom(msg.sender, address(this), sharePrice);
    }
}
