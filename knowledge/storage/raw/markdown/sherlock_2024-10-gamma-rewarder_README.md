
# Gamma Rewarder contest details

- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the issue page in your private contest repo (label issues as med or high)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)

# Q&A

### Q: On what chains are the smart contracts going to be deployed?
Optimism
___

### Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of [weird tokens](https://github.com/d-xo/weird-erc20) you want to integrate?
Yes, we are only allowing whitelisted tokens to work with the codebase.  These will be standard ERC-20 tokens.  We won't be allowing any fee-on-transfer  or non-standard ERC-20 tokens. We will also integrate USDC and USDT.
___

### Q: Are there any limitations on values set by admins (or other roles) in the codebase, including restrictions on array lengths?
    function setBlocksPerEpoch(uint64 _blocksPerEpoch) external onlyOwner {
        blocksPerEpoch = _blocksPerEpoch;
        emit BlocksPerEpochUpdated(_blocksPerEpoch);
    }

blocksPerEpoch will not be set as something excessively large so as to make the zk proof computation too expensive per user.  6 hours - 1 day worth of blocks would be reasonable.  This would be computed in blocks however.  
___

### Q: Are there any limitations on values set by admins (or other roles) in protocols you integrate with, including restrictions on array lengths?
No
___

### Q: For permissioned functions, please list all checks and requirements that will be made before calling the function.
1. createDistribution Function
Modifiers:

nonReentrant: Prevents reentrancy attacks.

Checks and Requirements:

Start Block Number: _startBlockNum > block.number
Distribution Duration: (_endBlockNum - _startBlockNum) <= MAX_DISTRIBUTION_BLOCKS
Distribution Amount: _amount > 0
Multiples of Blocks per Epoch: (_endBlockNum - _startBlockNum) % blocksPerEpoch == 0
Whitelisted Reward Token: isWhitelistedRewardToken[_rewardToken] == 1
Sufficient Token Allowance: IERC20(_rewardToken).allowance(msg.sender, address(this)) >= _amount
Protocol Fee Recipient: protocolFeeRecipient != address(0)

2. claimTest and handleProofResult Functions
Modifiers: None
Checks and Requirements:

Valid Verification Key Hash: vkHashes[_vkHash]
Valid Claim Period: startBlock < endBlock && (endBlock - startBlock) % blocksPerEpoch == 0
Claim Period Within Distribution Range: startBlock >= params.startBlockNumber && endBlock <= params.endBlockNumber
Matching Distribution Parameters:

lpTokenAddress == params.hypervisor
rewardTokenAddress == params.rewardToken
distributionAmountPerEpoch == params.distributionAmountPerEpoch


Non-Zero Reward: totalRewardAmount > 0
No Double Claiming: claim.amount == 0

3. Governance Functions (OnlyOwner)
Modifiers:

onlyOwner: Restricts function execution to the contract owner

Functions and Requirements:

addVkHash/removeVkHash: No additional checks
setBlocksPerEpoch: No additional checks
setProtocolFee: _protocolFee < BASE_9
toggleTokenWhitelist: No additional checks
setProtocolFeeRecipient: No additional checks


Situations Where Functions May Not Be Used:
claimTest: This function may be used for testing purposes.  In production, handleProofResult would likely be the primary function, with claimTest being removed.  claimTest was made external just for the purposes of testing.
___

### Q: Is the codebase expected to comply with any EIPs? Can there be/are there any deviations from the specification?
ERC20 (for safe token transfers and approvals via SafeERC20)
___

### Q: Are there any off-chain mechanisms for the protocol (keeper bots, arbitrage bots, etc.)? We assume they won't misbehave, delay, or go offline unless specified otherwise.
Yes

A prover system that generates Brevis proofs, as indicated by:

Use of BrevisApp and IBrevisProof interfaces
handleProofResult and vkHash verification functionality
Proof validation for claiming rewards
___

### Q: If the codebase is to be deployed on an L2, what should be the behavior of the protocol in case of sequencer issues (if applicable)? Should Sherlock assume that the Sequencer won't misbehave, including going offline?
Assumption should be that Sequencer won't misbehave
___

### Q: What properties/invariants do you want to hold even if breaking them has a low/unknown impact?
Key invariants from the contract code:

Total distributed rewards must match initial deposit minus protocol fees
Users cannot claim more rewards than allocated per distribution period
Same rewards cannot be claimed twice (enforced by claim tracking)
Distribution parameters (hypervisor, token, amounts) must remain immutable once set
___

### Q: Please discuss any design choices you made.
1.  Epoch-based distributions
- uses block numbers instead of timestamps for precision
- block times could be inconsistent with actual times, but we're using blocks for precision


2. Proofs can only prove valid participation/eligibility but cannot prove non-participation. This means:
- Valid rewards can be proven and claimed
- System cannot prevent omission of eligible addresses from rewards
- Relies on off-chain prover to include all eligible addresses

Flow  from the user perspective:
1.)  Via offchain calls on frontend, the user calls initiates a zk-proof and sends an onchain request to Brevis App
2.)  Brevis will call the callback function "handleProofResult" (claimTest is a public function which simulates this just for testing purposes, and would not be called by Brevis in production)
___

### Q: Please list any known issues and explicitly state the acceptable risks for each known issue.
- System cannot prevent omission of eligible addresses from rewards
- Relies on off-chain prover to include all eligible addresses (any rpc issues are deemed acceptable)
___

### Q: We will report issues where the core protocol functionality is inaccessible for at least 7 days. Would you like to override this value?
No
___

### Q: Please provide links to previous audits (if any).
NA
___

### Q: Please list any relevant protocol resources.
https://docs.brevis.network/developer-guide/brevis-app-workflow
___

### Q: Additional audit information.
NA.
___



# Audit scope


[GammaRewarder @ 50b9775d9fb5a44ec53638acd3eaf694ed7e7417](https://github.com/GammaStrategies/GammaRewarder/tree/50b9775d9fb5a44ec53638acd3eaf694ed7e7417)
- [GammaRewarder/contracts/GammaRewarder.sol](GammaRewarder/contracts/GammaRewarder.sol)
- [GammaRewarder/contracts/brevis/lib/BrevisApp.sol](GammaRewarder/contracts/brevis/lib/BrevisApp.sol)
- [GammaRewarder/contracts/brevis/lib/Lib.sol](GammaRewarder/contracts/brevis/lib/Lib.sol)

