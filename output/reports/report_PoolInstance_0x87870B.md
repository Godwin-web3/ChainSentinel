# Exploit Agent — Security Report
> Generated: 2026-07-23T19:27:16.923248+00:00

## Target
| Field | Value |
|-------|-------|
| Address | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` |
| Name | PoolInstance |
| Chain | Ethereum Mainnet |
| Category | lending |
| Verified | Yes |
| Proxy | Yes (depth 1) |
| Risk Level | **HIGH** |

| Implementation | `0x728a138A4823392C2EFA55e028d434F526fE03CF` |

## Analysis Summary
| Severity | Count |
|----------|-------|
| 🔴 High/Critical | 9 |
| 🟡 Medium | 23 |
| 🟢 Low | 20 |
| ℹ️ Informational | 94 |

## 🔴 High / Critical Findings

### Arbitrary Send Erc20
- **Check:** `arbitrary-send-erc20`
- **Category:** unknown
- **Impact:** Unknown — manual review required
- **Bounty Potential:** Unknown
- **Description:** BorrowLogic.executeRepay(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,DataTypes.ExecuteRepayParams) (lib/aave-v3-origin-private/src/contracts/protocol/libraries/logic/BorrowLogic.sol#126-223) uses arbit

### Unprotected Upgrade
- **Check:** `unprotected-upgrade`
- **Category:** proxy
- **Impact:** Anyone can replace contract logic.
- **Bounty Potential:** Critical
- **Description:** Upgrade function lacks access control.

### Dangerous Equality Check
- **Check:** `incorrect-equality`
- **Category:** logic
- **Impact:** Logic bypass via dust amounts or block manipulation.
- **Bounty Potential:** Medium-High
- **Description:** Strict equality on balances/timestamps — easily manipulated.

### Delegatecall in Assembly
- **Check:** `YUL-001`
- **Category:** delegatecall
- **Impact:** N/A
- **Bounty Potential:** N/A
- **Description:** delegatecall in assembly bypasses Solidity safety checks. Can lead to storage corruption or privilege escalation.

### Unchecked Call in Assembly
- **Check:** `YUL-003`
- **Category:** unchecked_call
- **Impact:** N/A
- **Bounty Potential:** N/A
- **Description:** Raw call in assembly. Return value must be manually checked — easy to miss failure.

## 🟡 Medium Findings

### Uninitialized Local
- **Impact:** Unknown — manual review required
- **Description:** ValidationLogic.validateLiquidationCall(DataTypes.UserConfigurationMap,DataTypes.ReserveData,DataTypes.ReserveData,DataTypes.ValidateLiquidationCallParams).vars (lib/aave-v3-origin-private/src/contracts/protocol/libraries/logic/ValidationLogic.sol#259) is a local variable never initialized

### Unused Return
- **Impact:** Unknown — manual review required
- **Description:** Pool.getUserAccountData(address) (lib/aave-v3-origin-private/src/contracts/protocol/pool/Pool.sol#470-498) ignores return value by PoolLogic.executeGetUserAccountData(_reserves,_reservesList,_eModeCategories,DataTypes.CalculateUserAccountDataParams({userConfig:_usersConfig[user],user:user,oracle:ADD

### Direct Memory Write
- **Impact:** N/A
- **Description:** Direct memory write via mstore. Incorrect offset can corrupt adjacent memory slots.

### Return Data Copy Without Length Check
- **Impact:** N/A
- **Description:** returndatacopy without explicit length validation can read beyond return buffer.

## 🔍 Auth Analysis

| Function | Auth State | Score | Evidence |
|----------|------------|-------|----------|
| `totalSupply()` | `UNAUTHENTICATED` | 0 | — |
| `balanceOf(address)` | `UNAUTHENTICATED` | 0 | — |
| `transfer(address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `allowance(address,address)` | `UNAUTHENTICATED` | 0 | — |
| `approve(address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `transferFrom(address,address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `multicall(bytes[])` | `UNAUTHENTICATED` | 0 | — |
| `initialize(IPoolAddressesProvider)` | `UNAUTHENTICATED` | 0 | — |
| `supply(address,uint256,address,uint16)` | `UNAUTHENTICATED` | 0 | — |
| `supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)` | `UNAUTHENTICATED` | 0 | — |
| `withdraw(address,uint256,address)` | `UNAUTHENTICATED` | 0 | — |
| `borrow(address,uint256,uint256,uint16,address)` | `UNAUTHENTICATED` | 0 | — |
| `repay(address,uint256,uint256,address)` | `UNAUTHENTICATED` | 0 | — |
| `repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)` | `UNAUTHENTICATED` | 0 | — |
| `repayWithATokens(address,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `setUserUseReserveAsCollateral(address,bool)` | `UNAUTHENTICATED` | 0 | — |
| `liquidationCall(address,address,address,uint256,bool)` | `UNAUTHENTICATED` | 0 | — |
| `flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)` | `UNAUTHENTICATED` | 0 | — |
| `flashLoanSimple(address,address,uint256,bytes,uint16)` | `UNAUTHENTICATED` | 0 | — |
| `mintToTreasury(address[])` | `UNAUTHENTICATED` | 0 | — |
| `getReserveData(address)` | `UNAUTHENTICATED` | 0 | — |
| `getVirtualUnderlyingBalance(address)` | `UNAUTHENTICATED` | 0 | — |
| `getUserAccountData(address)` | `UNAUTHENTICATED` | 0 | — |
| `getConfiguration(address)` | `UNAUTHENTICATED` | 0 | — |
| `getUserConfiguration(address)` | `UNAUTHENTICATED` | 0 | — |
| `getReserveNormalizedIncome(address)` | `UNAUTHENTICATED` | 0 | — |
| `getReserveNormalizedVariableDebt(address)` | `UNAUTHENTICATED` | 0 | — |
| `getReservesList()` | `UNAUTHENTICATED` | 0 | — |
| `getReservesCount()` | `UNAUTHENTICATED` | 0 | — |
| `getReserveAddressById(uint16)` | `UNAUTHENTICATED` | 0 | — |
| `FLASHLOAN_PREMIUM_TOTAL()` | `UNAUTHENTICATED` | 0 | — |
| `FLASHLOAN_PREMIUM_TO_PROTOCOL()` | `UNAUTHENTICATED` | 0 | — |
| `MAX_NUMBER_RESERVES()` | `UNAUTHENTICATED` | 0 | — |
| `finalizeTransfer(address,address,address,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `initReserve(address,address,address)` | `UNAUTHENTICATED` | 0 | — |
| `syncIndexesState(address)` | `UNAUTHENTICATED` | 0 | — |
| `syncRatesState(address)` | `UNAUTHENTICATED` | 0 | — |
| `setConfiguration(address,DataTypes.ReserveConfigurationMap)` | `UNAUTHENTICATED` | 0 | — |
| `updateFlashloanPremium(uint128)` | `UNAUTHENTICATED` | 0 | — |
| `configureEModeCategory(uint8,DataTypes.EModeCategoryBaseConfiguration)` | `UNAUTHENTICATED` | 0 | — |
| `configureEModeCategoryCollateralBitmap(uint8,uint128)` | `UNAUTHENTICATED` | 0 | — |
| `configureEModeCategoryBorrowableBitmap(uint8,uint128)` | `UNAUTHENTICATED` | 0 | — |
| `configureEModeCategoryLtvzeroBitmap(uint8,uint128)` | `UNAUTHENTICATED` | 0 | — |
| `configureEModeCategoryIsolated(uint8,bool)` | `UNAUTHENTICATED` | 0 | — |
| `getEModeCategoryData(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getEModeCategoryCollateralConfig(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getEModeCategoryLabel(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getEModeCategoryCollateralBitmap(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getEModeCategoryBorrowableBitmap(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getEModeCategoryLtvzeroBitmap(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getIsEModeCategoryIsolated(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `setUserEMode(uint8)` | `UNAUTHENTICATED` | 0 | — |
| `getUserEMode(address)` | `UNAUTHENTICATED` | 0 | — |
| `getLiquidationGracePeriod(address)` | `UNAUTHENTICATED` | 0 | — |
| `setLiquidationGracePeriod(address,uint40)` | `UNAUTHENTICATED` | 0 | — |
| `rescueTokens(address,address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `deposit(address,uint256,address,uint16)` | `UNAUTHENTICATED` | 0 | — |
| `eliminateReserveDeficit(address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `approvePositionManager(address,bool)` | `UNAUTHENTICATED` | 0 | — |
| `renouncePositionManagerRole(address)` | `UNAUTHENTICATED` | 0 | — |
| `setUserUseReserveAsCollateralOnBehalfOf(address,bool,address)` | `UNAUTHENTICATED` | 0 | — |
| `setUserEModeOnBehalfOf(uint8,address)` | `UNAUTHENTICATED` | 0 | — |
| `isApprovedPositionManager(address,address)` | `UNAUTHENTICATED` | 0 | — |
| `getReserveDeficit(address)` | `UNAUTHENTICATED` | 0 | — |
| `getReserveAToken(address)` | `UNAUTHENTICATED` | 0 | — |
| `getReserveVariableDebtToken(address)` | `UNAUTHENTICATED` | 0 | — |
| `getFlashLoanLogic()` | `UNAUTHENTICATED` | 0 | — |
| `getBorrowLogic()` | `UNAUTHENTICATED` | 0 | — |
| `getLiquidationLogic()` | `UNAUTHENTICATED` | 0 | — |
| `getPoolLogic()` | `UNAUTHENTICATED` | 0 | — |
| `getSupplyLogic()` | `UNAUTHENTICATED` | 0 | — |
| `ADDRESSES_PROVIDER()` | `UNAUTHENTICATED` | 0 | — |
| `RESERVE_INTEREST_RATE_STRATEGY()` | `UNAUTHENTICATED` | 0 | — |
| `POOL_ADMIN_ROLE()` | `UNAUTHENTICATED` | 0 | — |
| `EMERGENCY_ADMIN_ROLE()` | `UNAUTHENTICATED` | 0 | — |
| `RISK_ADMIN_ROLE()` | `UNAUTHENTICATED` | 0 | — |
| `FLASH_BORROWER_ROLE()` | `UNAUTHENTICATED` | 0 | — |
| `BRIDGE_ROLE()` | `UNAUTHENTICATED` | 0 | — |
| `ASSET_LISTING_ADMIN_ROLE()` | `UNAUTHENTICATED` | 0 | — |
| `setRoleAdmin(bytes32,bytes32)` | `UNAUTHENTICATED` | 0 | — |
| `addPoolAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `removePoolAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `isPoolAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `addEmergencyAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `removeEmergencyAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `isEmergencyAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `addRiskAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `removeRiskAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `isRiskAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `addFlashBorrower(address)` | `UNAUTHENTICATED` | 0 | — |
| `removeFlashBorrower(address)` | `UNAUTHENTICATED` | 0 | — |
| `isFlashBorrower(address)` | `UNAUTHENTICATED` | 0 | — |
| `addBridge(address)` | `UNAUTHENTICATED` | 0 | — |
| `removeBridge(address)` | `UNAUTHENTICATED` | 0 | — |
| `isBridge(address)` | `UNAUTHENTICATED` | 0 | — |
| `addAssetListingAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `removeAssetListingAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `isAssetListingAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `initialize(IPool,address,uint8,string,string,bytes)` | `UNAUTHENTICATED` | 0 | — |
| `scaledBalanceOf(address)` | `UNAUTHENTICATED` | 0 | — |
| `getScaledUserBalanceAndSupply(address)` | `UNAUTHENTICATED` | 0 | — |
| `scaledTotalSupply()` | `UNAUTHENTICATED` | 0 | — |
| `getPreviousIndex(address)` | `UNAUTHENTICATED` | 0 | — |
| `mint(address,address,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `burn(address,address,uint256,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `mintToTreasury(uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `transferOnLiquidation(address,address,uint256,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `transferUnderlyingTo(address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` | `UNAUTHENTICATED` | 0 | — |
| `UNDERLYING_ASSET_ADDRESS()` | `UNAUTHENTICATED` | 0 | — |
| `RESERVE_TREASURY_ADDRESS()` | `UNAUTHENTICATED` | 0 | — |
| `DOMAIN_SEPARATOR()` | `UNAUTHENTICATED` | 0 | — |
| `nonces(address)` | `UNAUTHENTICATED` | 0 | — |
| `getMarketId()` | `UNAUTHENTICATED` | 0 | — |
| `setMarketId(string)` | `UNAUTHENTICATED` | 0 | — |
| `getAddress(bytes32)` | `UNAUTHENTICATED` | 0 | — |
| `setAddressAsProxy(bytes32,address)` | `UNAUTHENTICATED` | 0 | — |
| `setAddress(bytes32,address)` | `UNAUTHENTICATED` | 0 | — |
| `getPool()` | `UNAUTHENTICATED` | 0 | — |
| `setPoolImpl(address)` | `UNAUTHENTICATED` | 0 | — |
| `getPoolConfigurator()` | `UNAUTHENTICATED` | 0 | — |
| `setPoolConfiguratorImpl(address)` | `UNAUTHENTICATED` | 0 | — |
| `getPriceOracle()` | `UNAUTHENTICATED` | 0 | — |
| `setPriceOracle(address)` | `UNAUTHENTICATED` | 0 | — |
| `getACLManager()` | `UNAUTHENTICATED` | 0 | — |
| `setACLManager(address)` | `UNAUTHENTICATED` | 0 | — |
| `getACLAdmin()` | `UNAUTHENTICATED` | 0 | — |
| `setACLAdmin(address)` | `UNAUTHENTICATED` | 0 | — |
| `getPriceOracleSentinel()` | `UNAUTHENTICATED` | 0 | — |
| `setPriceOracleSentinel(address)` | `UNAUTHENTICATED` | 0 | — |
| `getPoolDataProvider()` | `UNAUTHENTICATED` | 0 | — |
| `setPoolDataProvider(address)` | `UNAUTHENTICATED` | 0 | — |
| `BASE_CURRENCY()` | `UNAUTHENTICATED` | 0 | — |
| `BASE_CURRENCY_UNIT()` | `UNAUTHENTICATED` | 0 | — |
| `getAssetPrice(address)` | `UNAUTHENTICATED` | 0 | — |
| `setInterestRateParams(address,bytes)` | `UNAUTHENTICATED` | 0 | — |
| `calculateInterestRates(DataTypes.CalculateInterestRatesParams)` | `UNAUTHENTICATED` | 0 | — |
| `mint(address,address,uint256,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `burn(address,uint256,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `executeOperation(address[],uint256[],uint256[],address,bytes)` | `UNAUTHENTICATED` | 0 | — |
| `POOL()` | `UNAUTHENTICATED` | 0 | — |
| `executeOperation(address,uint256,uint256,address,bytes)` | `UNAUTHENTICATED` | 0 | — |
| `executeBorrow(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,DataTypes.ExecuteBorrowParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeRepay(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,DataTypes.ExecuteRepayParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeFlashLoan(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,DataTypes.FlashloanParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeFlashLoanSimple(DataTypes.ReserveData,DataTypes.FlashloanSimpleParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeEliminateDeficit(mapping(address => DataTypes.ReserveData),DataTypes.UserConfigurationMap,DataTypes.ExecuteEliminateDeficitParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeLiquidationCall(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(address => DataTypes.UserConfigurationMap),mapping(uint8 => DataTypes.EModeCategory),DataTypes.ExecuteLiquidationCallParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeInitReserve(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),DataTypes.InitReserveParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeSyncIndexesState(DataTypes.ReserveData)` | `UNAUTHENTICATED` | 0 | — |
| `executeSyncRatesState(DataTypes.ReserveData,address,address)` | `UNAUTHENTICATED` | 0 | — |
| `executeRescueTokens(address,address,uint256)` | `UNAUTHENTICATED` | 0 | — |
| `executeMintToTreasury(mapping(address => DataTypes.ReserveData),address[])` | `UNAUTHENTICATED` | 0 | — |
| `executeSetLiquidationGracePeriod(mapping(address => DataTypes.ReserveData),address,uint40)` | `UNAUTHENTICATED` | 0 | — |
| `executeGetUserAccountData(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.CalculateUserAccountDataParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeSupply(mapping(address => DataTypes.ReserveData),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,DataTypes.ExecuteSupplyParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeWithdraw(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,DataTypes.ExecuteWithdrawParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeFinalizeTransfer(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),mapping(address => DataTypes.UserConfigurationMap),DataTypes.FinalizeTransferParams)` | `UNAUTHENTICATED` | 0 | — |
| `executeUseReserveAsCollateral(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),DataTypes.UserConfigurationMap,address,address,bool,address,uint8)` | `UNAUTHENTICATED` | 0 | — |
| `executeSetUserEMode(mapping(address => DataTypes.ReserveData),mapping(uint256 => address),mapping(uint8 => DataTypes.EModeCategory),mapping(address => uint8),DataTypes.UserConfigurationMap,address,address,uint8)` | `UNAUTHENTICATED` | 0 | — |

## 🕸️ Graph Analysis

| Nodes | Sinks | Confirmed | Likely | Possible | Suppressed |
|-------|-------|-----------|--------|----------|------------|
| 388 | 3 | 2 | 0 | 0 | 1 |

### Constraint Engine Findings

- **CONFIRMED** (90%) `UNPROTECTED_INITIALIZER` — Pool.approvePositionManager(address,bool) → Pool.approvePositionManager(address,bool)
  - Entry Pool.approvePositionManager(address,bool) writes privileged state (_positionManager) with NO guard against being invoked more than once, or by anyone — neither a one-time-latch modifier (the rea
- **CONFIRMED** (90%) `UNPROTECTED_INITIALIZER` — Pool.renouncePositionManagerRole(address) → Pool.renouncePositionManagerRole(address)
  - Entry Pool.renouncePositionManagerRole(address) writes privileged state (_positionManager) with NO guard against being invoked more than once, or by anyone — neither a one-time-latch modifier (the rea

### Cross-Contract Dependency Resolution

| Variable | Declaring Contract | Status | Detail |
|----------|--------------------|--------|--------|
| `ADDRESSES_PROVIDER` | Pool | skipped | declared on unrelated sibling contract — no enumeration getter found |
