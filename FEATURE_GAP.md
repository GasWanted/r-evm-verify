# r-evm-verify — Feature Gap Analysis

## Current Position

Fast Rust prototype with 6 detectors, Z3 + Rayon parallelism, 3 CLI modes (scan, prove, invariant). 3-7x faster than Halmos on equivalent properties. But missing fundamental features that competitors ship out of the box.

## Gap 1: Taint Tracking (CRITICAL — eliminates 80%+ of false positives)

**Problem:** Our oracle detector flags every SLOAD→SSTORE flow, including OpenZeppelin AccessControl role reads. We can't distinguish attacker-controlled inputs from trusted internal storage. This caused 86% false positive rate on Alchemix.

**What competitors do:** Slither tracks data flow from sources (msg.sender, msg.value, calldata) through operations to sinks (CALL value, SSTORE). Only flags flows from untrusted sources.

**Implementation:**
- Tag each Expr with a taint: `Untrusted` (calldata, msg.value), `Trusted` (constants, admin-set storage), `Unknown`
- Propagate taint through arithmetic: `Untrusted + Trusted = Untrusted`
- Only flag findings where the sink expression has `Untrusted` taint
- SLOAD defaults to `Unknown`; known patterns (AccessControl roles, owner slot) get `Trusted`

**Impact:** Would have prevented the 15 AccessControl false positives on Alchemix and the vault() false positive on Boring Vault.

## Gap 2: Storage Layout Import (HIGH — enables precise findings)

**Problem:** We see `SLOAD(slot)` but don't know what variable it is. Is slot 0 the `owner`? Is the keccak of slot 5 a `balances` mapping? Without this, findings say "at offset 0x1667" instead of "writing to balances[msg.sender]".

**What competitors do:** Slither and Certora read the solc `storageLayout` JSON output which maps every variable name to its slot number and type.

**Implementation:**
- Parse solc `--storage-layout` output: `{slot: 0, label: "owner", type: "address"}`
- Map known slot hashes to variable names
- For mappings: `keccak256(key . baseSlot)` → `variableName[key]`
- Annotate findings with variable names instead of raw offsets

**Impact:** Findings become human-readable. "Writing to owner without access control" vs "SSTORE at offset 0x1667".

## Gap 3: More Detectors (HIGH — coverage parity with Slither)

**Problem:** We have 6 detectors. Slither has 90+. The top Immunefi bounties involve vulnerability classes we don't check.

**Priority detectors to add (top 20):**

| # | Detector | Slither equiv | Effort |
|---|----------|--------------|--------|
| 1 | Uninitialized storage (proxy) | uninitialized-state | 1 day |
| 2 | Unchecked return value | unchecked-transfer | 1 day |
| 3 | Arbitrary external call | arbitrary-send-eth | 1 day |
| 4 | Shadowed variables | shadowing-state | 1 day |
| 5 | Unused return value | unused-return | 1 day |
| 6 | Suicidal contract | suicidal | Already have |
| 7 | Missing zero-address check | missing-zero-check | 1 day |
| 8 | Locked ether | locked-ether | 1 day |
| 9 | Incorrect ERC20 interface | erc20-interface | 2 days |
| 10 | Dangerous strict equality | incorrect-equality | 1 day |
| 11 | Unprotected upgrade | unprotected-upgrade | 1 day |
| 12 | Storage collision in proxy | domain-separator-collision | 2 days |
| 13 | Msg.value in loop | msg-value-loop | 1 day |
| 14 | Divide before multiply | divide-before-multiply | 1 day |
| 15 | Unchecked low-level call | low-level-calls | Already partial |
| 16 | Block timestamp manipulation | timestamp | 1 day |
| 17 | Weak PRNG | weak-prng | 1 day |
| 18 | Missing events for critical ops | events-access | 1 day |
| 19 | Front-running vulnerability | front-running | 2 days |
| 20 | Token approval race | approval-race | 1 day |

## Gap 4: Working Prove Mode (HIGH — Halmos parity)

**Problem:** We scaffolded the prove command but never successfully proved a real property. The SVM doesn't dispatch CALLs into target contract bytecode — it pushes symbolic returns. So a check_ function that calls `token.transfer()` doesn't actually execute the transfer logic.

**Implementation:**
- When SVM hits CALL with a known target address (from state.contracts), save current frame and start executing target bytecode
- On RETURN from target, restore caller frame and push return data
- Need call stack depth tracking (max 1024 per EVM spec)
- Handle msg.sender/msg.value context switching

**Impact:** Would make prove mode actually work on real contracts. Currently it's dead code.

## Gap 5: Documentation and UX (MEDIUM — adoption)

**Problem:** Zero documentation. No README explaining how to use each command. No examples. No error messages that guide users.

**What's needed:**
- Usage examples for scan, prove, invariant
- Explanation of each detector and what it catches
- Guide for writing check_ properties
- CI integration guide (GitHub Actions example)
- Comparison with Slither/Halmos showing when to use which

## Implementation Priority

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | Taint tracking | 3-4 days | Eliminates 80%+ false positives |
| 2 | Top 10 new detectors | 5-7 days | 2x detection coverage |
| 3 | Storage layout import | 2-3 days | Human-readable findings |
| 4 | Working CALL dispatch in prove mode | 3-4 days | Halmos parity |
| 5 | Documentation | 2 days | Adoption |

Total: ~3 weeks to production-competitive quality.
