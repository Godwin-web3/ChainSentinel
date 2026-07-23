// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/staleness_detection.py::find_unstaled_latest_round_data_dependency
// — detects Chainlink latestRoundData() calls whose returned price is
// consumed without a genuine elapsed-time freshness check on updatedAt.
// One of the single most common high-severity findings in real
// Code4rena/Sherlock audits (2024-07-loopfi#494/#521, 2024-05-predy#69,
// 2024-08-sentiment-v2#51, 2023-12-the-standard#438).

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

// DANGEROUS: faithful minimal reproduction of the real LoopFi
// AuraVault.sol shape (code-423n4/2024-07-loopfi-findings#494/#521):
// updatedAt is destructured with a blank comma — never bound to any
// variable at all — inside a private helper called via an internal
// call. Must fire evidence.
contract LoopFiStyleVault {
    address public BAL_CHAINLINK_FEED;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function _chainlinkSpot() private view returns (uint256 price) {
        bool isValid;
        try AggregatorV3Interface(BAL_CHAINLINK_FEED).latestRoundData() returns (
            uint80,
            int256 answer,
            uint256,
            uint256,
            uint80
        ) {
            price = uint256(answer);
            isValid = (price > 0);
        } catch {
            isValid = false;
        }
    }

    function updateCollateralValue(address user, uint256 amount) external {
        uint256 price = _chainlinkSpot();
        collateralValue[user] = amount * price;
        borrowToken.transfer(user, collateralValue[user]);
    }
}

// DANGEROUS: faithful minimal reproduction of the real Cryptex Finance
// ChainlinkOracle.sol (cryptexfinance/contracts) — a subtler real case.
// getLatestAnswer() DOES check round completeness (timeStamp != 0) and
// round staleness (answeredInRound >= roundID), but NEVER checks
// elapsed real time. A real, deployed, "seemingly careful" shape that
// is still genuinely vulnerable — Chainlink itself documents
// answeredInRound as an unreliable staleness indicator on newer
// aggregator versions. Must fire evidence.
contract CryptexStyleOracle {
    AggregatorV3Interface public aggregatorContract;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function getLatestAnswer() public view returns (int256) {
        (uint80 roundID, int256 price, , uint256 timeStamp, uint80 answeredInRound) = aggregatorContract.latestRoundData();
        require(timeStamp != 0, "round is not complete");
        require(answeredInRound >= roundID, "stale data");
        return price;
    }

    function updateCollateralValue(address user, uint256 amount) external {
        int256 price = getLatestAnswer();
        collateralValue[user] = amount * uint256(price);
        borrowToken.transfer(user, collateralValue[user]);
    }
}

// Safe: faithful minimal reproduction of the real ButtonWood Protocol
// ChainlinkOracle.sol (buttonwood-protocol/button-wrappers) — a genuine
// elapsed-time staleness check, PROPAGATED as a return-value bool for
// the caller to check (never reverts inline). Must NOT fire.
contract ButtonWoodStyleOracle {
    AggregatorV3Interface public oracle;
    uint256 public stalenessThresholdSecs;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function getData() public view returns (uint256, bool) {
        (, int256 answer, , uint256 updatedAt, ) = oracle.latestRoundData();
        uint256 diff = block.timestamp - updatedAt;
        return (uint256(answer), diff <= stalenessThresholdSecs);
    }

    function updateCollateralValue(address user, uint256 amount) external {
        (uint256 price, bool valid) = getData();
        require(valid, "stale price");
        collateralValue[user] = amount * price;
        borrowToken.transfer(user, collateralValue[user]);
    }
}

// Safe: the common textbook require()-based single-step staleness
// check — require(updatedAt >= block.timestamp - MAX_DELAY). Must NOT
// fire.
contract RequireStyleOracle {
    AggregatorV3Interface public oracle;
    uint256 public constant MAX_DELAY = 3600;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function updateCollateralValue(address user, uint256 amount) external {
        (, int256 answer, , uint256 updatedAt, ) = oracle.latestRoundData();
        require(updatedAt >= block.timestamp - MAX_DELAY, "stale price feed");
        collateralValue[user] = amount * uint256(answer);
        borrowToken.transfer(user, collateralValue[user]);
    }
}

// Negative control: names deliberately chosen to match every keyword a
// name-matching heuristic would grep for ("oracle", "stale",
// "updatedAt", "freshness") but none of it actually calls
// latestRoundData() at all. Must NOT fire.
contract NameDecoyOnly {
    uint256 public updatedAt;
    uint256 public stalenessThreshold = 3600;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralValue;

    function checkFreshness() public view returns (bool) {
        return block.timestamp - updatedAt <= stalenessThreshold;
    }

    function updateCollateralValue(address user, uint256 amount) external {
        collateralValue[user] = amount * 1e18;
        borrowToken.transfer(user, collateralValue[user]);
    }
}

// Negative control: calls latestRoundData() and even discards
// updatedAt (the same unsafe shape as LoopFiStyleVault), but the
// answer is only ever written to a purely informational state variable
// — never a collateral/debt/borrow/liquidation/health/price/value-
// shaped one. Proves the fix doesn't flag every unstaled
// latestRoundData() call on sight, only ones actually feeding
// consequential state. Must NOT fire.
contract InformationalPriceDecoy {
    AggregatorV3Interface public oracle;
    int256 public lastReading;

    function observeFeed() external {
        (, int256 answer, , , ) = oracle.latestRoundData();
        lastReading = answer;
    }
}
