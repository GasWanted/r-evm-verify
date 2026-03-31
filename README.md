# r-evm-verify

Parallel formal verification engine for EVM smart contracts. Pure Rust + Z3 + Rayon.

**Status:** Early development

## What it does

Symbolic execution engine that mathematically proves contract properties or finds concrete counterexamples:

- **Reentrancy** — proves no execution path has an external call before a state update
- **Integer overflow** — proves arithmetic cannot overflow (via Z3 constraint solving)
- **Access control** — detects state-modifying functions without authorization checks

## Why it's fast

- **Rust** — 20-50x faster symbolic execution loop vs Halmos (Python)
- **Rayon** — parallel path exploration across all CPU cores
- **Z3** — industry-standard SMT solver for constraint checking

## Quick start

```bash
# Install
cargo install --path crates/cli

# Scan a contract
r-evm-verify scan contract.hex

# Scan solc JSON output
r-evm-verify scan out/MyContract.json
```

## Architecture

```
Solidity → solc → bytecode → [Lifter] → Symbolic IR → [SVM + Rayon] → [Z3] → Report
                                (Rust)                    (parallel)   (C lib)  (Rust)
```

- **Lifter**: Disassembles EVM bytecode, extracts CFG, builds symbolic IR
- **SVM**: Symbolic Virtual Machine — executes bytecode with symbolic stack/memory/storage
- **Solver**: Z3 wrapper for constraint satisfiability and counterexample generation
- **Engine**: Rayon-parallelized path exploration orchestrator

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

## License

MIT OR Apache-2.0
