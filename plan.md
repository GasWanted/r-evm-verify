# r-evm-verify — Roadmap

## Current State
- 6 vulnerability detectors + cross-contract callback modeling
- Halmos-mode `prove` command: symbolically verify check_ functions with Z3 counterexamples
- RV-tier `invariant` command: compositional analysis via function summaries
- Symbolic VM with Z3 (incremental + fast-path) + Rayon parallelism
- Function-level scanning, loop bounding, ABI-aware
- 6/6 DeFiVulnLabs, flash loan reentrancy in DVDeFi detected
- 14/15 DVDeFi contracts show invariant violations
- 0 false positives on Compound/Uniswap/Lido mainnet contracts
- 3.6-7.6x faster than Halmos on equivalent properties
- 108 tests passing

## Completed

### P0-P2
- [x] Function selector parsing, loop bounding, function-level scanning
- [x] Complete EVM opcodes (25+), counterexamples, ABI-aware scanning
- [x] 6 detectors: reentrancy, overflow, access control, delegatecall, tx.origin, selfdestruct

### P3 — Benchmarks
- [x] DeFiVulnLabs: 6/6 detection
- [x] Immunefi CTF: 2/2 core vulns detected
- [x] Mainnet: Compound cETH, Uniswap V2 Router, Lido stETH — clean scans
- [x] Damn Vulnerable DeFi v4.1.0: 15 contracts scanned

### P4 — Advanced
- [x] Incremental Z3 solving (push/pop)
- [x] Cross-contract callback modeling (flash loan reentrancy)

### P5 — Halmos-mode (prove command)
- [x] Multi-contract SVM state for cross-contract calls
- [x] Prover engine: symbolically verify check_ functions
- [x] CLI `prove` subcommand with Z3 counterexamples
- [x] Test property compilation and verification

### P6 — RV-tier (invariant command)
- [x] Function summary extraction via symbolic execution
- [x] Built-in invariants: access_control, cei_compliance, ordering_dependency
- [x] CLI `invariant` subcommand with compositional analysis
- [x] DVDeFi benchmark: 14/15 contracts show invariant violations
- [x] DeFiVulnLabs benchmark: 3/7 contracts show invariant violations

### Benchmark results (108 tests passing)
- DVDeFi: 14 contracts with violations (401,204 ordering_dependency, 21 cei_compliance, 13 access_control)
- DeFiVulnLabs: EtherStore (6), UncheckedOverflow (4), SafeVault (6) violations detected
- 0 test failures across workspace

## Next Steps

### Performance (handle big contracts)
- [x] **Expression simplification** — reduce symbolic expression size before Z3 queries. Constant folding on Expr trees, identity elimination (x + 0 = x), dead branch pruning.
- [ ] **Parallel branch checking** — rayon::join for both JUMPI branches simultaneously
- [x] **Constraint budget** — limit total Z3 queries per function (not just steps/paths). Skip overflow checks after N findings per function.
- [x] **Pre-0.8 Solidity** — detect legacy dispatchers (CALLDATALOAD + AND + EQ pattern)

### Solver
- [ ] **GPU constraint fuzzer** — CUDA parallel random evaluation for fast SAT
- [ ] **Native Rust BV solver** — bit-blast + cube-and-conquer, eliminate Z3

### Features
- [ ] **Specification annotations** — `/// @verify invariant` for custom properties
- [ ] **Foundry test output** — reproducer tests from counterexamples
- [x] **Oracle manipulation detector** — flag SLOAD values used in price calculations without TWAP
- [ ] **Flash loan detector** — flag functions that receive and return tokens in same tx
