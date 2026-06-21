
# Predict.fun contest details

- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the issue page in your private contest repo (label issues as med or high)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)

# Q&A

### Q: On what chains are the smart contracts going to be deployed?
Blast and potentially any EVM chains with a prediction market that uses Polymarket’s CTF exchange and neg risk protocol

predict.fun on Blast
BlastConditionalTokens	0x8F9C9f888A4268Ab0E2DDa03A291769479bAc285	
BlastUmaCtfAdapter	0x0C1331E4a4bBD59B7aae2902290506bf8fbE3e6c	
BlastCTFExchange	0x739f0331594029064C252559436eDce0E468E37a	
BlastNegRiskAdapter	0xc55687812285D05b74815EE2716D046fAF61B003	
BlastNegRiskCtfExchange	0x6a3796C21e733a3016Bc0bA41edF763016247e72	
BlastUmaCtfAdapter (Neg Risk)	0xB0c308abeC5d321A7B6a8E3ce43A368276178F7A	
___

### Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of [weird tokens](https://github.com/d-xo/weird-erc20) you want to integrate?
Each lending contract will only interact with one conditional token (ERC-1155) and one collateral token (ERC-20). The collateral token should match the integrated prediction market’s collateral token. On Blast it will be USDB and USDC on other prediction markets.
___

### Q: Are there any limitations on values set by admins (or other roles) in the codebase, including restrictions on array lengths?
PredictDotLoan::protocolFeeBasisPoints
-  Between 0 and 200


We have a feature that allows borrowers to use borrowed funds to buy shares on the prediction market. The order struct has a field called feeRateBps, the value must be >= the minimumOrderFeeRate defined in the lending contract. minimumOrderFeeRate is settable by the admin.

___

### Q: Are there any limitations on values set by admins (or other roles) in protocols you integrate with, including restrictions on array lengths?
Exchange - Fees::getMaxFeeRate()
- 1,000
___

### Q: For permissioned functions, please list all checks and requirements that will be made before calling the function.
- refinance (batch) can only be called by callers with the role REFINANCIER_ROLE

- updateMinimumOrderFeeRate, updateProtocolFeeRecipient, updateProtocolFeeBasisPoints, togglePaused can only be called by callers with the role DEFAULT_ADMIN_ROLE

___

### Q: Is the codebase expected to comply with any EIPs? Can there be/are there any deviations from the specification?
The contract is expected to strictly comply with EIP-712 and EIP-1271.
___

### Q: Are there any off-chain mechanisms for the protocol (keeper bots, arbitrage bots, etc.)? We assume they won't misbehave, delay, or go offline unless specified otherwise.
We have a bot that auto-refinances loans for borrowers. There is a potential issue of “over-refinancing” if the bot refinances the same loan over and over. We charge a protocol fee on each refinance as it creates a new loan, so in theory we can completely drain a loan. Contestants can assume the bot to be correctly implemented so that loans are not over-refinanced. We also don’t perform auto-refinancing for borrowers that did not opt into the feature.
___

### Q: If the codebase is to be deployed on an L2, what should be the behavior of the protocol in case of sequencer issues (if applicable)? Should Sherlock assume that the Sequencer won't misbehave, including going offline?
Sherlock should assume that the Sequencer won’t misbehave, including going offline.
___

### Q: What properties/invariants do you want to hold even if breaking them has a low/unknown impact?
The invariants can be found in the PredictDotLoan_Invariants contract (PredictDotLoan.Invariants.t.sol).
___

### Q: Please discuss any design choices you made.
- Off-chain proposals are used instead of asking our users to create proposals on-chain in order to allow users that need to make many loan offers and borrow requests to do it more easily.

- Proposals can be matched against each other, instead of just asking the takers to accept the offers so that the best deals can be made.

- We only allow one loan token because we believe the primary use of the protocol is leverage. It only makes sense for the borrowers to borrow the token that can be used to buy more conditional tokens on the exchange. If we allow another loan token, borrowers would have to swap the loan token for the exchange’s collateral token.

- Each loan must take up at least 10% of the proposal’s loan amount. It would be a nightmare for both sides if they have to manage tens of thousands of loans. The last loan does not have to be 10% as long as it completely fills the proposal. If it’s not done this way then a proposal cannot be fully filled. Also the last loan created will end up making the borrower put up with slightly more collateral because of precision loss (it shouldn’t be more than a few weis). We accept this trade-off in order to maintain the collateral ratio.

- Loans must be repaid in their entirety for simplicity. Most loans will be very short-term and borrowers will likely either just repay or default rather than repaying the loan partially.

- We don’t allow the new lender to set the interest rate per second in an auction as we believe they will always aim for the highest allowed interest rate. Also, the minimum duration of the new loan is 0 seconds because the new lender is taking on a lot of risk by taking over an already defaulting loan. It’s quite likely that the borrower will not repay since he already has defaulted once.

- We don’t ask for positionId in the proposal and rather derive it because we need the question ID to verify the current question status and also the position belongs to the question. We can just use the derived position IDs directly. There is no point requiring it in the Proposal struct.

- We copied some code directly from the ConditionalTokens contract (_getConditionalId and _getPositionId) because they are just simple keccak256 calls. It’s cheaper than making multiple external calls.

- interest rate per second and minimum duration aren't included in the emitted events as we are hitting stack too deep and they can be retrieved by calling ``loans`

___

### Q: Please list any known issues and explicitly state the acceptable risks for each known issue.
- Any ERC1155 that does not call checkOnERC1155Received or onERC1155BatchReceived can still be sent to the lending contract.

- Auctioned loans have a minimumDuration of zero and can be called any time by the new lender. This can be used to increase the debt of a borrower by auctioning an auctioned loan multiple times, increasing the debt by the protocol fee each time. This has no benefit for the lender as it is very likely that an auction loan will not be repaid.

- It is possible to use up a lend offer by matching the proposal against a borrower offer with a duration of zero, and then repaying the loan immediately in the same block. The borrower does not have to pay any interest, only the protocol fee.

- By default, users are not opted in to auto refinancing. If they opt in, their loans can be refinanced as many times as the refinancer deems fit, and the protocol fee will be charged on each refinance, increasing the loan’s debt. Refinancing logic is permissioned and implemented off chain and not considered in the scope of this competition.

- Exchange (not lending) fee calculation is done based on the logic documented here https://github.com/Polymarket/ctf-exchange/blob/main/docs/Overview.md#fees. Depending on the price of the trade, there will be cases where the fee charged is not X basis points even though the feeBps used is X to preserve market symmetry.

- The last borrower of a partially fulfilled loan offer will end up depositing slightly more collateral (a few weis) in order to get a loan. We implemented it this way in order to uphold the loan offer’s collateral ratio and it’s not an issue unless you can show that the last borrower’s collateral ratio is significantly higher than previous borrowers’.

- acceptLoanOfferAndFillOrder only works with predict.fun’s exchanges because fillOrder requires admin role.

___

### Q: We will report issues where the core protocol functionality is inaccessible for at least 7 days. Would you like to override this value?
No
___

### Q: Please provide links to previous audits (if any).
N/A
___

### Q: Please list any relevant protocol resources.
https://docs.gnosis.io/conditionaltokens/
https://docs.uma.xyz/
https://docs.predict.fun/

https://github.com/polymarket/ctf-exchange
https://github.com/Polymarket/exchange-fee-module
https://github.com/polymarket/neg-risk-ctf-adapter
https://github.com/Polymarket/uma-ctf-adapter
https://github.com/Polymarket/conditional-tokens-contracts

___



# Audit scope


[predict-dot-loan @ a0e47f025761691fbbe174745faf61b966d77880](https://github.com/PredictDotFun/predict-dot-loan/tree/a0e47f025761691fbbe174745faf61b966d77880)
- [predict-dot-loan/contracts/BlastPredictDotLoan.sol](predict-dot-loan/contracts/BlastPredictDotLoan.sol)
- [predict-dot-loan/contracts/PredictDotLoan.sol](predict-dot-loan/contracts/PredictDotLoan.sol)
- [predict-dot-loan/contracts/interfaces/IPredictDotLoan.sol](predict-dot-loan/contracts/interfaces/IPredictDotLoan.sol)
- [predict-dot-loan/contracts/libraries/InterestLib.sol](predict-dot-loan/contracts/libraries/InterestLib.sol)
- [predict-dot-loan/contracts/libraries/NegRiskIdLib.sol](predict-dot-loan/contracts/libraries/NegRiskIdLib.sol)

