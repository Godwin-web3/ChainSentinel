# Exploit Agent — Security Report
> Generated: 2026-07-22T17:55:15.565981+00:00

## Target
| Field | Value |
|-------|-------|
| Address | `0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2` |
| Name | PoolInstance |
| Chain | Ethereum Mainnet |
| Category | lending |
| Verified | Yes |
| Proxy | Yes (depth 1) |
| Risk Level | **LOW** |

| Implementation | `0x728a138A4823392C2EFA55e028d434F526fE03CF` |

## Analysis Summary
| Severity | Count |
|----------|-------|
| 🔴 High/Critical | 0 |
| 🟡 Medium | 0 |
| 🟢 Low | 0 |
| ℹ️ Informational | 0 |

## 🔴 High / Critical Findings

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

### Direct Memory Write
- **Impact:** N/A
- **Description:** Direct memory write via mstore. Incorrect offset can corrupt adjacent memory slots.

### Return Data Copy Without Length Check
- **Impact:** N/A
- **Description:** returndatacopy without explicit length validation can read beyond return buffer.
