# Renegade Darkpool — r-evm-verify Analysis

## Summary

9 contracts scanned. 7/9 clean, 2 flagged.

| Contract | Bytes | Scan | Invariant | Notes |
|----------|-------|------|-----------|-------|
| Darkpool | 22,683 | CLEAN | CLEAN | Main darkpool v1 — no findings |
| DarkpoolV2 | 12,317 | CLEAN | CLEAN | Main darkpool v2 — no findings |
| TransferExecutor | 7,243 | CLEAN | CLEAN | Token transfer handler |
| GasSponsor | 9,134 | CLEAN | CLEAN | Gas sponsorship |
| GasSponsorV2 | 6,279 | CLEAN | CLEAN | Gas sponsorship v2 |
| Verifier | 12,271 | CLEAN | CLEAN | ZK proof verifier |
| VKeys | 6,964 | OVFL | TIMEOUT | Verification keys storage |
| DarkpoolUniswapExecutor | 9,835 | REENT+OVFL+ORACLE | 3158 ordering deps | Uniswap integration |
| MalleableMatchConnector | 4,115 | CLEAN | CLEAN | Match connector |

## Detailed Findings

### DarkpoolUniswapExecutor — 28 findings

**Interesting finding #1:** Reentrancy + Oracle dependency in `transferOwnership()` path
- SLOAD value flows into external call/storage write
- This is likely the OpenZeppelin AccessControl SLOAD pattern (false positive)

**Interesting finding #2:** 27 overflow findings with counterexamples showing `calldatasize = 0x8000...` or `calldatasize = 0xe000...`
- These trigger on calldatasize being unrealistically large
- The overflow is in ABI decoding (memory allocation for calldata copy)
- **Likely false positives** — Solidity 0.8 checked arithmetic would revert, and realistic calldatasize is bounded by block gas limit

**Invariant findings:** 3,158 ordering dependencies
- The Uniswap executor has many functions that read/write overlapping storage slots
- This is expected for a DEX integration contract

### VKeys — 1 overflow finding

- Overflow in verification key storage operations
- VKeys timeout on invariant mode (large constant data)

### Core Darkpool Contracts — All Clean

The main Darkpool, DarkpoolV2, TransferExecutor, GasSponsor, GasSponsorV2, Verifier, and MalleableMatchConnector all passed both scan and invariant modes with **zero findings**. This suggests:

1. The core darkpool logic is well-written with proper access control
2. ZK verification contracts don't trigger our detectors (expected — they're pure math)
3. The transfer executor properly follows CEI pattern
4. Gas sponsorship contracts have proper access control

## Assessment

The Renegade darkpool contracts appear well-secured from the patterns our tool can detect. The only findings are in the Uniswap integration layer (DarkpoolUniswapExecutor), which is the bridge between the ZK darkpool and external DEX liquidity. This makes sense — the integration point is where the most risk exists.

The core darkpool security comes from ZK proofs (state transitions are only valid with a valid proof), which is a fundamentally different security model than what our tool checks. Our tool verifies EVM-level patterns (reentrancy, access control, overflow); the darkpool's security relies on cryptographic guarantees that are verified by the on-chain Verifier contract.

**What we CAN'T check on this codebase:**
- ZK proof soundness (is the verifier correct?)
- Merkle tree integrity (are insertions/deletions consistent?)
- Nullifier set completeness (can a note be double-spent?)
- Proof linking correctness (are cross-proof constraints enforced?)

These are the types of bugs that would be Critical for Renegade, and they require domain-specific formal verification (like KEVM or Circom verification tools), not general EVM symbolic execution.
