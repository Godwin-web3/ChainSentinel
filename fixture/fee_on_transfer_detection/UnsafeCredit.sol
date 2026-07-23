// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Tests core/fee_on_transfer_detection.py::find_unsafe_fee_on_transfer_credit
// — detects a deposit/lock path that pulls tokens via transferFrom and
// directly credits the nominal `amount` argument to accounting, never
// checking what the contract actually received.
//
// Real precedent for the vulnerable shape: Balancer's real $500K loss
// (June 2020) — a pool holding Statera (STA), a deflationary token
// that burns 1% per transfer, assumed each swap's IN amount was fully
// received; the discrepancy compounded across 24 flash-loaned swaps
// until the attacker drained the pool's other real assets. Also the
// real code-423n4/2023-01-popcorn-findings#503 (MultiRewardEscrow.
// lock()) — one of dozens of near-identical real Code4rena/Sherlock
// findings whose recommended fix appears near-verbatim across audits.
// Real precedent for the protected shape: the balance-before/after
// delta pattern from those same audit fixes, and Uniswap V2's own
// canonical pull-based accounting (UniswapV2Pair.mint():
// `amount0 = balance0.sub(_reserve0)`), confirmed live via IR probe.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

// DANGEROUS: faithful minimal reproduction of the real Popcorn
// MultiRewardEscrow.lock() shape — credits the SAME nominal `amount`
// argument directly into accounting with no check on what was
// actually received. Must fire evidence.
contract VulnerableEscrow {
    struct Escrow { uint256 balance; }
    mapping(uint256 => Escrow) public escrows;
    uint256 public nextId;

    function lock(IERC20 token, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 id = nextId++;
        escrows[id].balance = amount;
    }
}

// Safe: the real recommended fix across dozens of real audits —
// balance-before/after delta. Must NOT fire.
contract ProtectedEscrow {
    struct Escrow { uint256 balance; }
    mapping(uint256 => Escrow) public escrows;
    uint256 public nextId;

    function lock(IERC20 token, uint256 amount) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 actualAmount = balanceAfter - balanceBefore;
        uint256 id = nextId++;
        escrows[id].balance = actualAmount;
    }
}

// Safe: the real Uniswap V2 pull-based accounting pattern — no
// explicit "amount" argument is ever distrusted in the first place;
// the actually-received amount is derived purely from
// balanceOf(address(this)) against a tracked reserve. Must NOT fire.
contract UniswapV2StylePullAccounting {
    IERC20 public token;
    uint256 public reserve;
    mapping(address => uint256) public balances;

    function deposit() external {
        uint256 balance = token.balanceOf(address(this));
        uint256 amountIn = balance - reserve;
        balances[msg.sender] += amountIn;
        reserve = balance;
    }
}

// DANGEROUS: the critical adversarial regression case — an unrelated
// balanceOf() call exists in the SAME function (an informational
// observation), but it does NOT bracket the transfer at all; the
// critical write still directly credits the raw nominal `amount`.
// Proves "any balanceOf call somewhere in scope" doesn't suppress —
// the delta must actually feed the write. Must fire evidence.
contract UnrelatedBalanceCheckDoesNotSuppress {
    struct Escrow { uint256 balance; }
    mapping(uint256 => Escrow) public escrows;
    uint256 public nextId;
    uint256 public lastObservedContractBalance;

    function lock(IERC20 token, uint256 amount) external {
        lastObservedContractBalance = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 id = nextId++;
        escrows[id].balance = amount;
    }
}

// Negative control: names deliberately chosen to match every keyword a
// name-matching heuristic would grep for ("balance", "deposit",
// "escrow") but none of it actually pulls tokens via transferFrom at
// all — the "deposit" is just a fixed constant. Must NOT fire.
contract NameDecoyOnly {
    mapping(address => uint256) public balances;
    uint256 public escrowedTotal;

    function deposit() external {
        balances[msg.sender] += 1e18;
        escrowedTotal += 1e18;
    }
}

// Negative control: pulls tokens via transferFrom, but the destination
// is NOT this contract (a third-party relay/forwarding pattern) — an
// attacker-supplied fee-on-transfer token here doesn't corrupt THIS
// contract's own accounting, since it never claims to have received
// anything. Must NOT fire.
contract ThirdPartyRelayDoesNotFalsePositive {
    struct Escrow { uint256 balance; }
    mapping(uint256 => Escrow) public escrows;
    uint256 public nextId;

    function relay(IERC20 token, address to, uint256 amount) external {
        token.transferFrom(msg.sender, to, amount);
        uint256 id = nextId++;
        escrows[id].balance = amount;
    }
}
