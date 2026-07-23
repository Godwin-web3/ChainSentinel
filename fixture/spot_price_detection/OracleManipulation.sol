// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/spot_price_detection.py::find_unsafe_spot_price_dependency —
// the replacement for core/constraints.py's old _check_oracle_dependency,
// which grepped CallEdge.function_name strings for substrings like
// "oracle", "pricefeed", "twap", "getreserves" — unable to verify the
// value was ever used in a price computation at all, let alone
// distinguish a raw single-block spot read from a fully time-weighted
// average that happens to also call getReserves() somewhere upstream.
//
// Real precedent for the vulnerable shape: Harvest Finance's real $24M
// loss (Oct 2020, priced vault shares from a live Curve pool reserve
// ratio with no time-weighting), Warp Finance's real $8M loss (Dec
// 2020, priced collateral directly from a Uniswap V2 pair's
// getReserves()). Real precedent for the protected shape: Uniswap's own
// real v2-periphery ExampleOracleSimple.sol — confirmed live via IR
// probe against the actual reference source — dividing by REAL ELAPSED
// TIME (blockTimestamp - blockTimestampLast).

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint256);
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

// DANGEROUS: the real Warp Finance shape — collateral value computed
// DIRECTLY from getReserves(), a raw single-block spot read, with no
// time-elapsed division anywhere. An attacker can flash-loan-swap to
// skew reserve0/reserve1 within one transaction, inflate
// collateralValue, and borrow against phantom collateral. Must fire
// ORACLE_DEPENDENCY (CONFIRMED).
contract VulnerableLendingPool {
    IUniswapV2Pair public pair;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function borrow(uint256 lpAmount) external {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        uint256 price = (uint256(reserve1) * 1e18) / uint256(reserve0);
        collateralValue[msg.sender] = (lpAmount * price) / 1e18;
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// Safe: the real Uniswap V2 TWAP shape (ExampleOracleSimple.sol) —
// updatePrice() maintains price0Average via a genuine elapsed-time
// division; borrow() only ever reads the cached average and never
// calls getReserves() itself, so the accessor-evidence never appears
// on this entry's own reachable scope at all. Must NOT fire.
contract ProtectedLendingPoolTWAP {
    IUniswapV2Pair public pair;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    uint256 public price0CumulativeLast;
    uint32 public blockTimestampLast;
    uint256 public price0Average;

    function updatePrice() external {
        uint256 price0Cumulative = pair.price0CumulativeLast();
        uint32 blockTimestamp = uint32(block.timestamp);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;
        price0Average = (price0Cumulative - price0CumulativeLast) / timeElapsed;
        price0CumulativeLast = price0Cumulative;
        blockTimestampLast = blockTimestamp;
    }

    function borrow(uint256 lpAmount) external {
        collateralValue[msg.sender] = (lpAmount * price0Average) / 1e18;
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// Safe: getReserves() IS read directly inside the SAME function that
// writes collateralValue, but the raw reserve-derived price is itself
// divided by a real elapsed-time value (blockTimestamp - lastUpdate)
// before it ever reaches collateralValue — the SPECIFIC value that
// traced back to the spot-price accessor is genuinely diluted, not
// merely co-located with an unrelated division elsewhere in scope.
// Must NOT fire.
contract ProtectedInlineElapsedDivision {
    IUniswapV2Pair public pair;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;
    uint32 public lastUpdate;

    function borrow(uint256 lpAmount) external {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        uint256 rawPrice = (uint256(reserve1) * 1e18) / uint256(reserve0);
        uint32 timeElapsed = uint32(block.timestamp) - lastUpdate;
        uint256 dilutedPrice = rawPrice / timeElapsed;
        collateralValue[msg.sender] = (lpAmount * dilutedPrice) / 1e18;
        lastUpdate = uint32(block.timestamp);
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// DANGEROUS: false-suppression regression case — a genuinely unsafe
// direct-reserve collateral computation coexists in the SAME function
// with an entirely UNRELATED elapsed-time division (a staking cooldown
// multiplier applied to a completely different value, rewardBoost).
// A scope-wide "any elapsed-time division anywhere" check would
// wrongly suppress this; the unrelated division must NOT suppress the
// real vulnerability, since collateralValue is still derived straight
// from raw reserves with zero dilution. Must fire ORACLE_DEPENDENCY
// (CONFIRMED).
contract VulnerableWithUnrelatedElapsedDivision {
    IUniswapV2Pair public pair;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;
    mapping(address => uint256) public rewardBoost;
    mapping(address => uint32) public stakeStart;

    function borrow(uint256 lpAmount) external {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        uint256 price = (uint256(reserve1) * 1e18) / uint256(reserve0);
        collateralValue[msg.sender] = (lpAmount * price) / 1e18;

        uint32 stakeDuration = uint32(block.timestamp) - stakeStart[msg.sender];
        rewardBoost[msg.sender] = 1000 / stakeDuration;

        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// Negative control: a decoy contract whose function/variable NAMES are
// deliberately chosen to match every keyword an old name-matching
// heuristic would grep for ("oracle", "priceFeed", "twap", "consult")
// — but NONE of it actually reads a real Uniswap V2/V3 spot-price
// accessor at all; the "price" is just a fixed constant dressed up in
// oracle-shaped names. Must NOT fire under any circumstance.
contract NameDecoyOnly {
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;
    uint256 public oraclePriceFeedTwap = 1e18;

    function consult() public view returns (uint256) {
        return oraclePriceFeedTwap;
    }

    function borrow(uint256 lpAmount) external {
        collateralValue[msg.sender] = (lpAmount * consult()) / 1e18;
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// Negative control: reads getReserves() for a completely unrelated,
// non-price purpose (an informational view getter reporting pool
// depth) — never used in any collateral/price computation at all.
// Proves the fix doesn't flag every getReserves() read on sight, only
// ones actually feeding a price/value computation. Must NOT fire.
contract ReservesUnrelatedUse {
    IUniswapV2Pair public pair;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;
    uint256 public fixedPrice = 1e18;

    function poolDepth() external view returns (uint112, uint112) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return (reserve0, reserve1);
    }

    function borrow(uint256 lpAmount) external {
        collateralValue[msg.sender] = (lpAmount * fixedPrice) / 1e18;
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// DANGEROUS (the real Warp Finance shape, cross-contract): faithful
// minimal reproduction of the actual exploited UniswapLPOracleFactory.sol
// + a TWAP consult() oracle instance, confirmed live via cmichel.io's
// real writeup of the actual $8M Dec 2020 exploit. The factory reads
// raw getReserves() and passes the RAW reserve AMOUNT as an ARGUMENT
// into a SEPARATE oracle contract's own consult()-style function,
// which internally multiplies a real TWAP-protected average price by
// that unprotected amount. Neither contract's own function body alone
// looks unsafe in isolation — the vulnerability only exists across the
// call boundary, via parameter binding. Must fire ORACLE_DEPENDENCY
// (CONFIRMED).
contract WarpStyleTWAPOracle {
    uint256 public price0Average;

    function consult(address token, uint256 amountIn) external view returns (uint256) {
        return price0Average * amountIn;
    }
}

contract WarpStyleLPOracleFactory {
    IUniswapV2Pair public pair;
    WarpStyleTWAPOracle public oracle;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function borrow(address token) external {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        uint256 value0 = oracle.consult(token, uint256(reserve0));
        collateralValue[msg.sender] = value0;
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}

// Safe cross-contract counterpart: the factory calls consult() with a
// FIXED unit amount (1e18), never the raw reserve itself — the
// TWAP-protected price is used as a genuine per-unit price, not
// multiplied by an unprotected pool-size-dependent amount. Must NOT
// fire — this contract never reads getReserves() at all.
contract SafeCrossContractOracleFactory {
    WarpStyleTWAPOracle public oracle;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function borrow(address token, uint256 lpAmount) external {
        uint256 unitPrice = oracle.consult(token, 1e18);
        collateralValue[msg.sender] = (lpAmount * unitPrice) / 1e18;
        borrowToken.transfer(msg.sender, collateralValue[msg.sender]);
    }
}
