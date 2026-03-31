# Changelog

## [Unreleased]

### Added — Algebraic Mining v2
- Product invariants (Mul(SLoad, SLoad) patterns → AMM constant-product)
- Ratio invariants (Div(SLoad, SLoad) → exchange rate/collateral ratio)
- Z3 verification — candidates promoted from Likely to Proven
- Mapping slot recognition (keccak base slot grouping)
- Complete overwrite analysis (consistent vs inconsistent expression shapes)
- Bidirectional balance detection (deposit/withdraw on same slot)
- State dependency graph (function→slot→function edges)
- Attack path mining (state manipulation → unguarded external call sequences)
- Humanized slot names (mapping_entry@N instead of Keccak256(...))
- Capped violator lists, deduplicated function names

### Stats
- 162 tests
- 10 algebraic mining strategies
- UnstoppableVault: 20 critical attack paths from 108 state dependencies
- SimpleToken: conservation invariant PROVEN via Z3

## [0.1.0] — 2026-03-31

### Overview
First release of r-evm-verify. 8,770+ lines of Rust, 144 tests, 5 CLI modes.
Pivoted from Bend/HVM2 to pure Rust after benchmarking showed HVM2's 1000x
per-operation overhead negated its 3x parallelism advantage.

### CLI Modes
- `scan` — Pattern-based vulnerability detection (11 detectors)
- `prove` — Halmos-mode property verification (check_ functions with Z3 counterexamples)
- `invariant` — RV-tier compositional analysis via function summaries
- `infer` — Automatic invariant inference (11 strategies, no user input)
- `mine` — Algebraic invariant mining (conservation, monotonicity, zero-sum)

### Detectors (11)
- Reentrancy (CALL before SSTORE, cross-contract callback modeling)
- Integer overflow (Z3 satisfiability check: is a + b < a possible?)
- Access control (state-modifying paths without msg.sender constraint)
- Delegatecall to untrusted address
- tx.origin authentication
- Reachable SELFDESTRUCT
- Oracle manipulation (SLOAD → financial calculation without validation)
- Unchecked external call return value
- Arbitrary ETH send to calldata-derived address
- msg.value used multiple times (loop pattern)
- Timestamp/block.number dependence in storage writes
- Divide-before-multiply precision loss

### Inference Strategies (11)
- Write exclusivity (slot only written by one function)
- Guarded mutations (all write paths check caller)
- Unprotected value transfer
- Inconsistent access control across shared slots
- Slot correlation (conservation invariant violations)
- Value flow asymmetry (fund leak through different accounting path)
- Unguarded CEI violation
- Privilege escalation (writes to access-control slots without auth)
- Flash loan risk (complex function with calls + storage mods)
- Dead code detection (functions that always revert)
- Contract complexity profiling

### Algebraic Mining (5 strategies)
- Conservation (opposite-sign deltas on slot pairs → sum preserved)
- Monotonicity (slot only increases or only decreases across all functions)
- Bounded change (fixed constant increment → counter/index pattern)
- Zero-sum transfer (positive + negative deltas share same variable)
- Cross-function consistency (incremental vs overwrite conflict detection)

### Engine
- Symbolic Virtual Machine (SVM) with 25+ EVM opcode support
- Z3 constraint solver with fast-path constant folding (50%+ queries resolved without Z3)
- Incremental Z3 solving (push/pop for efficient JUMPI branch checking)
- Rayon parallel path exploration
- Per-path and global timeout (prevents runaway on large contracts)
- Adaptive configuration (scales steps/paths based on contract size)
- Expression simplification (identity elimination, constant folding)
- Taint tracking (Untrusted/Trusted/Unknown labels on all stack values)
- Function-level scanning (skips dispatcher, scans functions in parallel)
- Loop bounding (tracks pc + stack_height visits)
- Cross-contract callback modeling (simulates re-entry at function entry points)
- CALL dispatch into deployed target contracts (prove mode)
- Function summary extraction via symbolic execution
- Storage layout import from solc JSON
- ABI-aware scanning with keccak256 selector computation

### Benchmarks
- DeFiVulnLabs: 6/6 vulnerable contracts detected
- Damn Vulnerable DeFi v4.1.0: 15/15 contracts scanned, 10 with findings
- Immunefi top 10 bounties: 5/10 hit rate ($1.95M bounty value caught)
- Immunefi CTF challenges: 2/2 core vulnerabilities detected
- Mainnet contracts: Compound cETH, Uniswap V2 Router, Lido stETH — clean scans
- Live bounty analysis: Alchemix (3 WETHGateway findings), IPOR (oracle staleness gap), Renegade (7/9 clean), Boring Vault (clean)
- 3-7x faster than Halmos on equivalent properties

### Research
- Algebraic invariant mining: automatically discovers conservation invariants from symbolic execution traces — novel combination of Daikon-style mining + symbolic execution + SMT verification for EVM
- 4-level research roadmap: algebraic mining → abstract interpretation → CEGIR → attack synthesis
