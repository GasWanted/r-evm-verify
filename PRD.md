# r-evm-verify — Parallel EVM Formal Verification Engine

## Overview

r-evm-verify is an open-source formal verification engine for EVM smart contracts. It performs symbolic execution with Z3 constraint solving and Rayon-parallelized path exploration to prove contract invariants or find violations with concrete counterexamples.

## Problem

Smart contract exploits caused over $3.6B in losses in 2023 alone. Formal verification can prevent these by proving correctness before deployment, but current tools are:

- **Slow** — Halmos (Python + Z3) takes minutes to hours per property
- **Expensive** — Certora charges $500K-$2M/year
- **Hard to use** — Certora requires learning CVL

## Solution

A Rust-native symbolic execution engine that is:

- **20-50x faster** than Halmos on the symbolic execution loop (Rust vs Python)
- **10-14x additional speedup** from Rayon parallel path exploration
- **Free and open source** — MIT/Apache-2.0 licensed
- **Zero config** — built-in analyses run without annotations

## Architecture

```
bytecode → [Lifter] → SymbolicProgram → [SVM + Rayon] → [Z3] → Report
             (Rust)                       (parallel)    (C lib)  (Rust)
```

### Components

| Component | Role |
|-----------|------|
| Lifter | Bytecode → CFG → Symbolic IR |
| SVM | Symbolic Virtual Machine — executes with symbolic state, forks at JUMPI |
| Solver | Z3 wrapper — sat checking, counterexample extraction |
| Engine | Rayon parallel path exploration |
| Synthesizer | Report formatting, Foundry test generation |
| CLI | `r-evm-verify scan <file>` |

## Built-in Analyses

| Analysis | Method | Z3 required? |
|----------|--------|-------------|
| Reentrancy | Call/storage ordering in execution trace | No |
| Integer overflow | Is `a + b < a` satisfiable? | Yes |
| Access control | No `msg.sender` constraint on state-modifying paths | No |
| Self-destruct reachability | Is there a satisfiable path to SELFDESTRUCT? | Yes |

## Goals

1. **10x faster** than Halmos on equivalent properties
2. **Sub-30s** for single-contract scan on 16-core machine
3. **Concrete counterexamples** for every finding
4. **Zero false negatives** on overflow detection vs Halmos

## Non-Goals (v1)

- Custom specification language
- Cross-contract analysis
- GUI / web interface
- Non-EVM chains

## License

MIT OR Apache-2.0
