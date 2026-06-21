# Revert Lend Mitigation Review details
- Total Prize Pool: $23,500 in USDC
  - HM awards: $21,150
  - Judge awards: $2,350
- [Warden guidelines for C4 mitigation reviews](https://code4rena.notion.site/Guidelines-for-C4-mitigation-reviews-ed10fc5cfbf640bd8dcec66f38b343c4)
- Submit findings [using the C4 form](https://code4rena.com/contests/2024-04-revert-lend-mitigation-review/submit)
- Starts April 19, 2024 20:00 UTC
- Ends April 29, 2024 20:00 UTC

## Important note 

Each warden must submit a mitigation review for *every* individual PR listed in the `Scope` section below. **Incomplete mitigation reviews will not be eligible for awards.**

## Findings being mitigated

Mitigations of all High and Medium issues will be considered in-scope and listed here.

- [H-01: V3Vault.sol permit signature does not check receiving token address is USDC](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/368)
- [H-02: Risk of reentrancy onERC721Received function to manipulate collateral token configs shares](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/323)
- [H-03: V3Vault::transform does not validate the data input and allows a depositor to exploit any position approved on the transformer](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/214)
- [H-04: V3Utils.execute() does not have caller validation, leading to stolen NFT positions from users](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/141)
- [H-05: _getReferencePoolPriceX96() will show incorrect price for negative tick deltas in current implementation cause it doesn't round up for them](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/127)
- [H-06: Owner of a position can prevent liquidation due to the 'onERC721Received' callback](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/54)

- [M-01: An attacker can easily bypass the collateral value limit factor checks](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/466)
- [M-02: Protocol can be repeatedly gas griefed in AutoRange external call](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/459)
- [M-03: No minLoanSize means liquidators will have no incentive to liquidate small positions](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/455)
- [M-04: Due to interest rates update method, Interest-Free Loans are possible and the Cost of DoS are reduced](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/435)
- [M-05: setReserveFactor fails to update global interest before updating reserve factor](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/427)
- [M-06: Users can lend and borrow above allowed limitations](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/415)
- [M-07: Large decimal of referenceToken causes overflow at oracle price calculation](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/409)
- [M-08: DailyLendIncreaseLimitLeft and dailyDebtIncreaseLimitLeft are not adjusted accurately.](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/400)
- [M-09: Liquidation reward sent to msg.sender instead of recipient](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/389)
- [M-10: Users's tokens stuck in AutoCompound after Vault is deactivated.](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/365)
- [M-11: Lack of safety buffer in _checkLoanIsHealthy could subject users who take out the max loan into a forced liquidation](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/363)
- [M-12: Wrong global lending limit check in _deposit function](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/324)
- [M-13: User might execute PositionToken of token set by previous token owner.](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/256)
- [M-14: V3Vault is not ERC-4626 compliant](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/249)
- [M-15: Users' newly created positions can be prematurely closed and removed from the vault directly after they are created](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/232)
- [M-16: Repayments and liquidations can be forced to revert by an attacker that repays miniscule amount of shares](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/222)
- [M-17: AutoExit could receive a reward calculated from the entire position's fund even if onlyFee is true in AutoExit.execute().](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/216e)
- [M-18: Users cannot stop loss in AutoRange and AutoExit](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/202)
- [M-19: V3Oracle susceptible to price manipulation](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/175)
- [M-20: Tokens can't be removed as a collateral without breaking liquidations and other core functions](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/158)
- [M-21: Dangerous use of deadline parameter](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/147)
- [M-22: dailyDebtIncreaseLimitLeft is not updated in liquidate().](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/140)
- [M-23: AutoRange execution can be front-ran to avoid protocol fee, causing loss for protocol](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/110)
- [M-24: Incorrect liquidation fee calculation during underwater liquidation, disincentivizing liquidators to participate](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/53)
- [M-25: Asymmetric calculation of price difference](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/10)

## Scope

### Branch
https://github.com/revert-finance/lend/tree/audit

### Mitigation of High & Medium Severity Issues

Wherever possible, mitigations should be provided in separate pull requests, one per issue. If that is not possible (e.g. because several audit findings stem from the same core problem), then please link the PR to all relevant issues in your findings repo. 

| URL | Mitigation of | Purpose | 
| ----------- | ------------- | ----------- |
| https://github.com/revert-finance/lend/pull/19 | H-01 | Checks token in permit | 
| https://github.com/revert-finance/lend/pull/8 https://github.com/revert-finance/lend/pull/32 | H-02 | Removed sending of NFT to avoid reentrancy | 
| https://github.com/revert-finance/lend/pull/29 | H-03 | Refactoring to make all transformers properly check caller permission | 
| https://github.com/revert-finance/lend/pull/29 | H-04 | Refactoring to make all transformers properly check caller permission | 
| https://github.com/revert-finance/lend/pull/10 | H-05 | Fixed calculation | 
| https://github.com/revert-finance/lend/pull/8 https://github.com/revert-finance/lend/pull/32 | H-06 | Removed sending of NFT to avoid reentrancy | 
| https://github.com/revert-finance/lend/pull/23 | M-05 | Fixed | 
| https://github.com/revert-finance/lend/pull/22 | M-06 | Fixed | 
| https://github.com/revert-finance/lend/pull/21 | M-07 | Fixed | 
| https://github.com/revert-finance/lend/pull/11 | M-08 | Fixed | 
| https://github.com/revert-finance/lend/pull/20 | M-09 | Fixed | 
| https://github.com/revert-finance/lend/pull/18 | M-10 | Fixed | 
| https://github.com/revert-finance/lend/pull/17 | M-11 | Added safety buffer for borrow and decreaseLiquidity (not for transformers) | 
| https://github.com/revert-finance/lend/pull/16 | M-12 | Fixed | 
| https://github.com/revert-finance/lend/pull/15 | M-14 | Fixed | 
| https://github.com/revert-finance/lend/pull/8 https://github.com/revert-finance/lend/pull/32 | M-15 | Fixed | 
| https://github.com/revert-finance/lend/pull/14 https://github.com/revert-finance/lend/pull/30 | M-16 | Fixed | 
| https://github.com/revert-finance/lend/pull/12 | M-18 | Fixed | 
| https://github.com/revert-finance/lend/pull/26 | M-19 | Fixed | 
| https://github.com/revert-finance/lend/pull/25 | M-20 | Fixed | 
| https://github.com/revert-finance/lend/pull/24 | M-21 | Added deadline where missing | 
| https://github.com/revert-finance/lend/pull/11 | M-22 | Fixed | 
| https://github.com/revert-finance/lend/pull/7 | M-24 | Fixed calculation | 
| https://github.com/revert-finance/lend/pull/5 | M-25 | Fixed calculation | 

### Additional scope to be reviewed

These are additional changes that will be in scope.

| URL | Mitigation of | Purpose | 
| ----------- | ------------- | ----------- |
| https://github.com/revert-finance/lend/pull/13 | ADD-01 - https://github.com/code-423n4/2024-03-revert-lend-findings/issues/220 | Improper return of chainlinkReferencePriceX96 | 
| https://github.com/revert-finance/lend/pull/27 | ADD-02 - https://github.com/code-423n4/2024-03-revert-lend-findings/issues/12 | Missing L2 sequencer checks for Chainlink oracle | 
| https://github.com/revert-finance/lend/pull/28 | ADD-03 - https://github.com/code-423n4/2024-03-revert-lend-findings/issues/14 | Some ERC20 can revert on a zero value transfer | 
| https://github.com/revert-finance/lend/pull/31 | ADD-04 - QA, GAS | Several small changes to address QA and GAS optimization issues | 
| https://github.com/revert-finance/lend/pull/33 | ADD-05 - QA, GAS | Several small changes to address QA and GAS optimization issues | 
| https://github.com/revert-finance/lend/pull/34 | ADD-06 - QA, GAS | Several small changes to address QA and GAS optimization issues | 

## Out of Scope

Please list any High and Medium issues that were judged as valid but you have chosen not to fix.

| Issue | Comments | 
| ----------- | ----------- |
| M-01 | Acknowlegded, see comments in https://github.com/code-423n4/2024-03-revert-lend-findings/issues/466 | 
| M-02 | Acknowlegded, this is solved off-chain by the operator bots, see discussion in https://github.com/code-423n4/2024-03-revert-lend-findings/issues/459 | 
| M-03 | Acknowlegded, at deployment a resonable value will be set for minLoanSize | 
| M-04 | Acknowlegded, we will monitor for this behaviour and adjust config if needed, see discussion in https://github.com/code-423n4/2024-03-revert-lend-findings/issues/435 | 
| M-13 | Acknowlegded, see comment in https://github.com/code-423n4/2024-03-revert-lend-findings/issues/256 | 
| M-17 | Acknowlegded, see comment in https://github.com/code-423n4/2024-03-revert-lend-findings/issues/216 | 
| M-23 | Acknowlegded, this is solved off-chain by the operator bots | 
