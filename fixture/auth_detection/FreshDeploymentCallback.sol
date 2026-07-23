// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/invariants.py::_classify_call's fresh-deployment
// exception — the fix for the real false positive found live this
// session against QuickSwap/UniswapV2Factory.createPair() on Polygon:
//   bytes memory bytecode = type(UniswapV2Pair).creationCode;
//   assembly { pair := create2(0, add(bytecode, 32), mload(bytecode), salt) }
//   IUniswapV2Pair(pair).initialize(token0, token1);
//   getPair[token0][token1] = pair;
// `pair` isn't an attacker-substitutable address — it's CREATE2'd two
// lines earlier from this SAME factory's own, fully-known bytecode
// (`type(KnownPair).creationCode`). CROSS_FUNCTION_STATE_RACE
// previously treated the initialize() call as CALLBACK_CAPABLE purely
// because it's a non-view function, regardless of destination — a
// false positive on one of DeFi's most heavily audited, unexploited
// patterns.
interface ICallback {
    function hook() external;
}

contract KnownPair {
    address public token0;
    address public token1;
    address public factory;

    constructor() {
        factory = msg.sender;
    }

    // Safe: a plain two-field setter, no external call of its own.
    function initialize(address _token0, address _token1) external {
        require(msg.sender == factory, "FORBIDDEN");
        token0 = _token0;
        token1 = _token1;
    }
}

contract KnownFactory {
    mapping(address => mapping(address => address)) public getPair;

    function createPair(address tokenA, address tokenB) external returns (address pair) {
        require(getPair[tokenA][tokenB] == address(0), "PAIR_EXISTS");
        bytes memory bytecode = type(KnownPair).creationCode;
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        assembly {
            pair := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        KnownPair(pair).initialize(tokenA, tokenB);
        getPair[tokenA][tokenB] = pair;
        getPair[tokenB][tokenA] = pair;
    }
}

// DANGEROUS: the deployed contract's own matching function (also
// named `initialize`, same freshly-CREATE2'd-destination shape) makes
// a REAL external call to an attacker-supplied address. A "trust
// anything freshly deployed" fix would wrongly suppress this — the
// destination being known/fresh says nothing about what that known
// code itself goes on to call. Must still fire.
contract UnsafeKnownPair {
    address public token0;
    address public token1;

    function initialize(address _token0, address _token1, address hookTarget) external {
        token0 = _token0;
        token1 = _token1;
        ICallback(hookTarget).hook();
    }
}

contract UnsafeFactory {
    mapping(address => mapping(address => address)) public getPair;

    function createPair(address tokenA, address tokenB, address hookTarget) external returns (address pair) {
        require(getPair[tokenA][tokenB] == address(0), "PAIR_EXISTS");
        bytes memory bytecode = type(UnsafeKnownPair).creationCode;
        bytes32 salt = keccak256(abi.encodePacked(tokenA, tokenB));
        assembly {
            pair := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        UnsafeKnownPair(pair).initialize(tokenA, tokenB, hookTarget);
        getPair[tokenA][tokenB] = pair;
        getPair[tokenB][tokenA] = pair;
    }
}
