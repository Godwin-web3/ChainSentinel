
# AXION contest details

- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the issue page in your private contest repo (label issues as med or high)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)

# Q&A

### Q: On what chains are the smart contracts going to be deployed?
The smart contracts can potentially be implemented on any full-EVM chain. 
Currently: Sonic, Base, Blast, Thena, Scroll —— Optimism, Mantle, X Layer and Bera are also close to our ecosystem thus possible.

The AMO implementation is Dex-specific more than chain-specific.
The Solidity Utils contract are simple wrappers around escrow/coding contrats, which also need Dex-specific implementations


___

### Q: If you are integrating tokens, are you allowing only whitelisted tokens to work with the codebase or any complying with the standard? Are they assumed to have certain properties, e.g. be non-reentrant? Are there any types of [weird tokens](https://github.com/d-xo/weird-erc20) you want to integrate?
Yes, the AMO are deployed by the team, with a specific stablecoin as a pair! 
In the the scope of this audit would be any USD-pegged token, beside fee-on-transfer ones.

The BOOST token itself can potentially be paired on any Dex ( eg Uniswap ) with any token —— this is out of our control.
___

### Q: Are there any limitations on values set by admins (or other roles) in the codebase, including restrictions on array lengths?
No, there are no off-chain limitations!
There are, however, some hard-coded limitations —— mainly to ensure that even admins can only buyback BOOST below peg and sell it above peg. These are doctsringed.

___

### Q: Are there any limitations on values set by admins (or other roles) in protocols you integrate with, including restrictions on array lengths?
No.
___

### Q: For permissioned functions, please list all checks and requirements that will be made before calling the function.
There are three levels of permissions:
- any critical permission is given to the multisig —— note that any ERC withdrawals are only to the multisig adress
- the manager may change some parameters
- AMO role is given to the automation bot
___

### Q: Is the codebase expected to comply with any EIPs? Can there be/are there any deviations from the specification?
Strictly compliant: ERC-1504: Upgradable Smart Contract
___

### Q: Are there any off-chain mechanisms for the protocol (keeper bots, arbitrage bots, etc.)? We assume they won't misbehave, delay, or go offline unless specified otherwise.
The BOOST peg can be rebalanced permissionlessly by interactive with the publicAMO contract.
Our bots will also ensure continuos rebalancing ( typically every 10 seconds under normal conditions ) but they are not necessary to maintain peg. since users can rebalance through the contract or run their own bots.
___

### Q: If the codebase is to be deployed on an L2, what should be the behavior of the protocol in case of sequencer issues (if applicable)? Should Sherlock assume that the Sequencer won't misbehave, including going offline?
Yes, let's assume that the sequencer doesn't misbehave. If the sequencer goes offline, funds are stuck on the layer 2.

___

### Q: What properties/invariants do you want to hold even if breaking them has a low/unknown impact?
No
___

### Q: Please discuss any design choices you made.
Design choices are documented in the code and readme.
The only significant difference in design choices between implementation is regarding the trading price of BOOST.
___

### Q: Please list any known issues and explicitly state the acceptable risks for each known issue.
The acceptable risk is that the paired USD token itself depegs. This will cause a local depeg of BOOST.
___

### Q: We will report issues where the core protocol functionality is inaccessible for at least 7 days. Would you like to override this value?
Yes, 3 days

___

### Q: Please provide links to previous audits (if any).
This is the first audit
___

### Q: Please list any relevant protocol resources.
The website is not officially live.
Here's two threads though:
* One about our approach to security:
https://typefully.com/t/2Ea9o1T
* One about how the project fits for DEFI
https://x.com/omazett/status/1838629900259070244


### Q: Additional audit information.

Additional info about the Axion protocol can be found here https://sticky-yarrow-52e.notion.site/AXION-Audit-Documentation-11bb3e443073802c949bd3700abad968?pvs=4



___



# Audit scope


[liquidity-amo @ 9a9adab905878a3a8c4fbe7c0851354185d8466a](https://github.com/AXION-MONEY/liquidity-amo/tree/9a9adab905878a3a8c4fbe7c0851354185d8466a)
- [liquidity-amo/contracts/BoostStablecoin.sol](liquidity-amo/contracts/BoostStablecoin.sol)
- [liquidity-amo/contracts/MasterAMO.sol](liquidity-amo/contracts/MasterAMO.sol)
- [liquidity-amo/contracts/Minter.sol](liquidity-amo/contracts/Minter.sol)
- [liquidity-amo/contracts/SolidlyV2AMO.sol](liquidity-amo/contracts/SolidlyV2AMO.sol)
- [liquidity-amo/contracts/SolidlyV3AMO.sol](liquidity-amo/contracts/SolidlyV3AMO.sol)

[solidly-utils @ 7946d226cc2c14159a6a2bda01ede157e2199f21](https://github.com/AXION-MONEY/solidly-utils/tree/7946d226cc2c14159a6a2bda01ede157e2199f21)
- [solidly-utils/contracts/AerodromeUtils.sol](solidly-utils/contracts/AerodromeUtils.sol)
- [solidly-utils/contracts/EqualizerUtils.sol](solidly-utils/contracts/EqualizerUtils.sol)
- [solidly-utils/contracts/MasterUtils.sol](solidly-utils/contracts/MasterUtils.sol)
- [solidly-utils/contracts/RamsesUtils.sol](solidly-utils/contracts/RamsesUtils.sol)
- [solidly-utils/contracts/ThenaUtils.sol](solidly-utils/contracts/ThenaUtils.sol)




[liquidity-amo @ 9a9adab905878a3a8c4fbe7c0851354185d8466a](https://github.com/AXION-MONEY/liquidity-amo/tree/9a9adab905878a3a8c4fbe7c0851354185d8466a)
- [liquidity-amo/contracts/BoostStablecoin.sol](liquidity-amo/contracts/BoostStablecoin.sol)
- [liquidity-amo/contracts/MasterAMO.sol](liquidity-amo/contracts/MasterAMO.sol)
- [liquidity-amo/contracts/Minter.sol](liquidity-amo/contracts/Minter.sol)
- [liquidity-amo/contracts/SolidlyV2AMO.sol](liquidity-amo/contracts/SolidlyV2AMO.sol)
- [liquidity-amo/contracts/SolidlyV3AMO.sol](liquidity-amo/contracts/SolidlyV3AMO.sol)


