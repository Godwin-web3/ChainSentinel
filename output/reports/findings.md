# Exploit Agent — Findings Report

## Summary
- High/Critical: 4
- Medium: 1
- Low/Info: 27

## High / Critical Findings

### [HIGH] Dangerous Equality Check
**Check:** `incorrect-equality`
**Category:** logic
**Impact:** Logic bypass via dust amounts or block manipulation.
**Bounty Potential:** Medium-High
**Description:** Strict equality on balances/timestamps — easily manipulated.

### [HIGH] Dangerous Equality Check
**Check:** `incorrect-equality`
**Category:** logic
**Impact:** Logic bypass via dust amounts or block manipulation.
**Bounty Potential:** Medium-High
**Description:** Strict equality on balances/timestamps — easily manipulated.

### [HIGH] Token Reentrancy
**Check:** `reentrancy-no-eth`
**Category:** reentrancy
**Impact:** State manipulation via reentrant token transfers.
**Bounty Potential:** High — common in lending/vault protocols
**Description:** Reentrancy via token callbacks (ERC777, ERC1155, hooks).

### [HIGH] Token Reentrancy
**Check:** `reentrancy-no-eth`
**Category:** reentrancy
**Impact:** State manipulation via reentrant token transfers.
**Bounty Potential:** High — common in lending/vault protocols
**Description:** Reentrancy via token callbacks (ERC777, ERC1155, hooks).

## Medium Findings

### [MEDIUM] Weak Randomness
**Impact:** Miner-manipulable randomness in games/lotteries.
