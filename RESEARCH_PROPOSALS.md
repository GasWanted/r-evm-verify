# r-evm-verify — Research Proposals

Research directions that would expand r-evm-verify's detection capabilities and performance beyond the current symbolic execution engine. Ordered by impact.

## 1. Function Summaries for Known Standards

**Impact:** High — enables cross-contract analysis for real DeFi
**Effort:** 1-2 weeks for ERC20/ERC721 coverage
**Dependencies:** None

### Problem

When our SVM encounters a CALL to an external contract (e.g., a token transfer), it pushes a symbolic return value and moves on. It doesn't know that `token.transfer(to, amount)` decreases `balances[from]` and increases `balances[to]`. This means:

- PuppetPool's oracle manipulation goes undetected (we don't model that Uniswap swaps change reserves)
- Flash loan attacks that rely on token balance changes can't be fully analyzed
- Any vulnerability that depends on the behavior of a called contract is invisible

### Approach

Pre-compute summaries for standard contract interfaces:

```
ERC20.transfer(to, amount):
  requires: balanceOf[msg.sender] >= amount
  effects:  balanceOf[msg.sender] -= amount
            balanceOf[to] += amount
  returns:  true
  reverts:  if balance insufficient

ERC20.balanceOf(addr):
  returns:  symbolic value (storage read)
  effects:  none

UniswapV2Pair.swap(amount0Out, amount1Out, to, data):
  requires: k invariant maintained (reserve0 * reserve1 >= k)
  effects:  reserve0 changes, reserve1 changes, tokens transferred
  returns:  void
```

When the SVM encounters a CALL, check if the target address matches a known contract or the function selector matches a known interface. If yes, apply the summary instead of pushing a blind symbolic return.

### What it enables

- Oracle manipulation detection: model that `getPrice()` reads from a pool whose reserves an attacker can change
- Flash loan analysis: model that borrowed tokens must be returned
- Token flow tracking: prove balance conservation across multi-contract interactions

### References

- Certora's manual summaries: https://docs.certora.com/en/latest/docs/cvl/methods.html
- HEVM's symbolic storage model for external contracts

---

## 2. Abstract Interpretation Pre-Pass

**Impact:** High — makes all analysis 10-100x faster on large contracts
**Effort:** 3-4 weeks
**Dependencies:** None

### Problem

Symbolic execution explores every feasible path. A contract with 20 JUMPI branches has up to 2^20 = 1M paths. Even with Z3 pruning and timeouts, large contracts (UnstoppableVault with 45 functions) take 20+ seconds. Abstract interpretation computes a sound over-approximation of ALL paths in a single pass.

### Approach

Define an abstract domain for EVM values:

```
Concrete:    x = 0xa9059cbb (exact value)
Interval:    x ∈ [0, 2^256)  (range)
Sign:        x > 0, x == 0, x < 0 (signed)
Bitwidth:    x fits in 160 bits (address-sized)
Taint:       x depends on calldata (attacker-controlled)
```

Execute the bytecode once using abstract values instead of symbolic expressions. At each JUMPI, take BOTH branches but merge the abstract states at join points (where control flow reconverges). No Z3 queries needed — all operations are on ranges/intervals.

```
Abstract execution of: require(x < 100); y = x + 50;
  Before: x ∈ [0, 2^256)
  After require: x ∈ [0, 99]
  After add: y ∈ [50, 149]
  Overflow possible? 149 < 2^256, so NO.
```

### What it enables

- 100ms pre-scan that flags suspicious functions (narrows symbolic execution scope)
- Taint analysis: which storage writes depend on attacker-controlled inputs?
- Value range analysis: prove that arithmetic cannot overflow without Z3
- Scales to any contract size (no path explosion)

### Tradeoff

Abstract interpretation is sound (no false negatives for the abstract domain) but imprecise (false positives when intervals are too wide). It cannot produce counterexamples. Use it as a fast filter, not a replacement for symbolic execution.

### References

- Mythril's abstract interpretation for EVM: https://github.com/Consensys/mythril
- EtherTrust: https://www.netidee.at/ethertrust
- The lattice theory: Cousot & Cousot, "Abstract Interpretation: A Unified Lattice Model" (1977)

---

## 3. Native Rust Bitvector SAT Solver

**Impact:** Medium — 2-5x faster Z3 queries, eliminates C++ dependency
**Effort:** 4-6 weeks
**Dependencies:** None (can be built incrementally)

### Problem

Z3 is our performance bottleneck. Each Z3 query:
- Crosses Rust→C++ FFI boundary (marshaling overhead)
- Creates a fresh solver context (no sharing across queries)
- Uses a general-purpose CDCL algorithm (not optimized for our query patterns)

90% of our queries are simple bitvector comparisons (`x + y < x`, `x == 0xa9059cbb`). These don't need a full SMT solver.

### Approach

**Layer 1 — Fast-path (already implemented):**
Constant folding, interval analysis, pattern matching. Resolves ~50% of queries in nanoseconds.

**Layer 2 — Bit-blasting + Parallel SAT:**
Convert bitvector operations to boolean circuits (mechanical translation). For 256-bit ADD, this produces ~1,500 boolean variables and ~5,000 clauses. Solve using a Rust-native CDCL SAT solver (build on `varisat` crate or write a minimal one).

Parallelize via cube-and-conquer: split the boolean search space into independent cubes, solve each on a separate Rayon thread.

```
Query: is (a + b < a) satisfiable?

Bit-blast → 1,500 boolean vars, 5,000 clauses
Split on top 5 vars → 32 cubes
Rayon: 24 cores solve 32 cubes
First SAT → return SAT (overflow possible)
All UNSAT → return UNSAT (safe)
```

**Layer 3 — Z3 fallback:**
For queries that Layer 2 can't solve within 1ms (complex keccak constraints, array theory), fall back to Z3.

### What it enables

- Eliminates Z3 C++ dependency (pure Rust binary, easier distribution)
- 2-5x faster per query from zero FFI overhead + parallel SAT
- GPU acceleration possible in the future (bit-blasted SAT maps well to CUDA)

### References

- Varisat (Rust SAT solver): https://github.com/jix/varisat
- Bitwuzla (state-of-art BV solver): https://bitwuzla.github.io/
- Cube-and-Conquer: Heule et al., "Cube and Conquer: Guiding CDCL SAT Solvers by Lookaheads" (2012)

---

## 4. Compositional Verification

**Impact:** Medium — enables multi-transaction attack detection
**Effort:** 6-8 weeks
**Dependencies:** Function summaries (#1)

### Problem

Our SVM verifies one function execution at a time. Flash loan attacks involve multiple function calls in sequence: `flashLoan() → attacker.callback() → deposit() → withdraw()`. The vulnerability only exists in the COMPOSITION of these calls, not in any single one.

### Approach

Verify each function independently, producing a summary of its effects (preconditions, postconditions, state changes). Then check if there exists a SEQUENCE of function calls that violates a global invariant.

```
deposit() summary:
  pre:  true
  post: balances[caller] += msg.value
        address(this).balance += msg.value

withdraw() summary:
  pre:  balances[caller] > 0
  post: balances[caller] = 0
        caller.transfer(old_balances[caller])

Global invariant: address(this).balance >= sum(balances)

Check: is there a sequence [f1, f2, ...] such that
       starting from valid state,
       applying summaries in order,
       the invariant is violated?
```

This reduces to a constraint satisfaction problem over function summaries — solvable by Z3 without symbolic execution.

### What it enables

- Flash loan attack detection: find sequences where borrow→manipulate→repay violates invariants
- Governance attacks: find sequences where propose→vote→execute bypasses intended controls
- Multi-step exploits that no single-function analysis can detect

### Tradeoff

Requires defining global invariants (what does "safe" mean for this protocol?). Manual for now, could be inferred from common patterns (balance conservation, monotonic state variables) in future work.

### References

- Move Prover's compositional approach: https://github.com/move-language/move
- Certora's rule-based verification
- Hoare Logic composition: "An Axiomatic Basis for Computer Programming" (1969)

---

## 5. GPU-Accelerated Constraint Fuzzing

**Impact:** Low-Medium — fast SAT finding, not proving
**Effort:** 2-3 weeks
**Dependencies:** None

### Problem

Z3 proves both SAT (found a counterexample) and UNSAT (property holds). For vulnerability detection, we mainly need SAT — finding ONE input that triggers the bug. UNSAT proofs are nice but not strictly necessary for a security scanner.

### Approach

Instead of symbolic reasoning, launch 100,000 GPU threads that each evaluate the constraint with random concrete inputs. If any thread finds a satisfying assignment, return SAT immediately.

```
GPU kernel (per thread):
  1. Generate random 256-bit values for all symbolic variables
  2. Evaluate the concrete bitvector circuit
  3. Check all constraints
  4. If satisfied → write to output buffer (SAT found)

Launch: 100,000 threads on RTX 4090
Time: ~10μs for 100K evaluations
```

This is massively parallel random testing (fuzzing) on GPU. No branch divergence because every thread runs the same circuit with different inputs.

### What it enables

- Near-instant SAT finding for simple constraints
- Counterexample generation without Z3
- Probabilistic: may miss SAT for highly constrained problems, but fast for common cases
- Pairs with Z3: GPU finds SAT fast, Z3 proves UNSAT when GPU fails

### Tradeoff

Cannot prove UNSAT (can't exhaustively check 2^512 inputs). Only useful for finding violations, not proving safety. Best used as Layer 2 in the tiered solver (after fast-path, before Z3).

### References

- ParaFrost: GPU-accelerated SAT solving
- KLEE's random path selection: similar concept on CPU
- GPU fuzzing: "Full-speed Fuzzing" (2019)
