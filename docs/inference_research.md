# Automatic Invariant Inference — Research Notes

## Current State (Template-Based)

r-evm-verify has 11 inference strategies. All follow the same pattern:

```
1. Extract features from function summaries (slots, constraints, calls)
2. Compare against a hardcoded template ("if X and Y then suspicious")
3. Report matches
```

### What the templates catch

| Strategy | Logic | What it finds |
|----------|-------|--------------|
| Write exclusivity | Count writers per slot | Slot written by unexpected function |
| Guarded mutations | Check if Expr::Caller in path constraints | Missing access control |
| Unprotected external call | Call without caller constraint | Unauthorized ETH transfer |
| Inconsistent access control | Compare guard patterns across functions sharing a slot | One writer protected, another not |
| Slot correlation | Count slot pair co-occurrences | Conservation invariant violation |
| Value flow asymmetry | Compare deposit slots vs withdraw slots | Fund leak through different accounting path |
| CEI violation | Function has both CALL and SSTORE without guard | Reentrancy |
| Privilege escalation | Find auth-check slots, check if written without auth | Ownership takeover |
| Flash loan risk | Complex function with calls + storage | Attack surface |
| Dead code | Function with 0 success paths | Broken logic |
| Contract profile | Count function categories | Risk overview |

### What the templates CANNOT catch

```solidity
// Uniswap: reserve0 * reserve1 >= k
// → No template for "product of two slots is monotonically non-decreasing"

// ERC20: sum(balanceOf[all addresses]) == totalSupply
// → Can't reason about aggregate properties over mappings

// Lending: collateralValue >= debtValue * collateralFactor
// → No template for "weighted ratio between storage values"

// Flash loan: borrowed amount must be returned in same tx
// → Can't track value conservation across call boundaries

// Exchange rate: rate should never decrease by more than 1% per update
// → No template for bounded rate-of-change properties
```

These are the $100K-$10M bug classes. Template matching can't find them because the invariant SHAPE is protocol-specific — you can't hardcode "product of reserves" as a template because you don't know which contract is Uniswap.

---

## Level 1: Algebraic Invariant Mining (Daikon-style)

### Approach

Instead of predefined templates, generate ALL possible mathematical relationships between storage slots up to a complexity bound, then test which ones hold.

```
Given a contract with storage slots S0, S1, S2, S3:

Phase 1 — Generate candidates (offline, combinatorial):
    Unary:   S0 > 0, S0 == 0, S1 > 0, ...
    Binary:  S0 == S1, S0 < S1, S0 + S1 == S2, S0 - S1 >= 0, ...
    Ternary: S0 + S1 == S2, S0 * S1 == S2, S0 * S1 >= S2, ...
    Bounded: S0 <= constant, S0 >= constant, ...

Phase 2 — Test candidates against function summaries:
    For each function F and each candidate invariant I:
        Symbolically check: if I holds BEFORE F, does I hold AFTER F?
        If not → discard candidate
        If yes for all F → I is a likely invariant

Phase 3 — Report surviving candidates as inferred properties
```

### What it would catch

- `totalSupply == sum(deposits) - sum(burns)` → from observing that deposit() increases S0 and S2 by the same amount
- `reserve0 * reserve1 >= k` → from observing that swap() maintains the product
- `balanceOf[x] >= 0 for all x` → from observing no function makes a balance negative (in checked arithmetic)

### Implementation in Rust

```rust
/// A candidate invariant expressed as a relationship between slot values.
enum CandidateInvariant {
    // Unary
    NonZero(SlotId),
    NonNegative(SlotId),

    // Binary relationships
    Equal(SlotId, SlotId),              // S_a == S_b
    LessEqual(SlotId, SlotId),          // S_a <= S_b
    Sum(SlotId, SlotId, SlotId),        // S_a + S_b == S_c

    // Conservation
    SumConserved(Vec<SlotId>),          // sum(S_i) == constant across calls
    ProductBound(SlotId, SlotId),       // S_a * S_b >= initial_product

    // Rate-of-change
    BoundedChange(SlotId, u64),         // |S_new - S_old| <= bound per call
}

/// For each candidate, check if any function's summary can violate it.
fn verify_candidate(
    candidate: &CandidateInvariant,
    summaries: &[FunctionSummary],
    solver: &SolverContext,
) -> bool {
    // Encode: "invariant holds before function AND function executes
    //          IMPLIES invariant holds after function"
    // Ask Z3: is the negation satisfiable? If UNSAT → invariant holds.
    // ...
}
```

### Complexity

For N storage slots:
- Unary candidates: O(N)
- Binary candidates: O(N²)
- Ternary candidates: O(N³)
- Each candidate requires one Z3 query per function

A contract with 10 slots and 20 functions: ~1000 candidates × 20 functions = 20,000 Z3 queries. At 1ms each = 20 seconds. Feasible.

A contract with 50 slots: ~125,000 ternary candidates × 50 functions = 6.25M queries. Not feasible without pruning.

### Pruning strategies

1. **Type-directed:** Only generate `S_a + S_b == S_c` when all three slots are uint256 (not address or bool)
2. **Write-set guided:** Only relate slots that are written by the same function (they're likely in the same accounting system)
3. **Access-pattern guided:** Slots read together are more likely to be related than slots read independently
4. **Early termination:** If a candidate is violated by the first function checked, skip it
5. **Incremental:** Start with unary, only promote to binary/ternary if unary candidates survive

### References

- Ernst et al., "Dynamically Discovering Likely Program Invariants to Support Program Evolution" (Daikon, 2001)
- Nguyen et al., "Using Dynamic Analysis to Discover Polynomial and Array Invariants" (DIG, 2012)

### Effort estimate: 2-3 weeks

---

## Level 2: Abstract Interpretation with Widening

### Approach

Instead of concrete symbolic values, track abstract properties:

```
Abstract domain for a storage slot:
    Interval:  [lo, hi]          — value is between lo and hi
    Sign:      {pos, neg, zero}  — sign of the value
    Parity:    {even, odd}       — parity
    Taint:     {trusted, untrusted}  — data origin

Abstract state = one abstract value per storage slot

For each function, compute the abstract transfer function:
    deposit(amount):
        balances[caller] → [old_lo + 0, old_hi + MAX]  (increases by 0..MAX)
        totalSupply      → [old_lo + 0, old_hi + MAX]  (increases by same)

    transfer(to, amount):
        balances[caller] → [old_lo - MAX, old_hi - 0]  (decreases)
        balances[to]     → [old_lo + 0, old_hi + MAX]  (increases)
        totalSupply      → [old, old]                    (UNCHANGED)

Fixed point: after applying all functions repeatedly:
    totalSupply ∈ [initial, initial + sum_of_all_deposits]

    Invariant discovered: totalSupply is bounded and monotonically non-decreasing.
```

### What it would catch

- Value range violations ("balance should never exceed total supply")
- Monotonicity ("total supply only increases via mint, decreases via burn")
- Boundedness ("exchange rate stays within [0.95, 1.05] of initial")

### The hard part: widening

When a loop or recursive call creates an unbounded sequence of abstract states, widening forces convergence by over-approximating:

```
Iteration 1: x ∈ [0, 1]
Iteration 2: x ∈ [0, 2]
Iteration 3: x ∈ [0, 3]
...
Widening:    x ∈ [0, +∞)  ← jump to infinity to force convergence
```

This is sound (no false negatives in the abstract domain) but imprecise (false positives from over-approximation). The research question is designing a widening operator that's precise enough for DeFi accounting.

### Abstract domains for DeFi

| Domain | Tracks | Cost | Precision |
|--------|--------|------|-----------|
| Intervals [lo, hi] | Value ranges | O(1) per slot | Low — loses relationships |
| Octagons ±x ± y ≤ c | Pairwise relationships | O(N²) | Medium — catches x + y == z |
| Polyhedra ax + by + cz ≤ d | Arbitrary linear | O(N^exponential) | High — too expensive |
| Symbolic | Exact expressions | O(expression size) | Exact — but doesn't converge |

**Best fit for DeFi:** Octagons. They can express `balanceOf[from] + balanceOf[to] == constant` (conservation) and `totalSupply >= balanceOf[x]` (dominance) at reasonable cost.

### References

- Cousot & Cousot, "Abstract Interpretation: A Unified Lattice Model for Static Analysis of Programs by Construction or Approximation of Fixpoints" (1977)
- Miné, "The Octagon Abstract Domain" (2006)
- Grech et al., "MadMax: Surviving Out-of-Gas Conditions in Ethereum Smart Contracts" (2018) — abstract interpretation for EVM

### Effort estimate: 4-6 weeks

---

## Level 3: Counterexample-Guided Invariant Refinement (CEGIR)

### Approach

Combine invariant mining with Z3 verification in a refinement loop:

```
1. GUESS: Start with a strong candidate invariant
   e.g., "totalSupply == sum(balanceOf)"

2. VERIFY: Ask Z3 — "given this invariant holds before function F,
   can F violate it?"

3a. If UNSAT (no violation possible) → invariant is PROVED for F
    Move to next function.

3b. If SAT (counterexample found) → REFINE the invariant
    - The counterexample tells us WHICH input breaks it
    - Weaken the invariant: "totalSupply == sum(balanceOf)
      EXCEPT during mint() where totalSupply increases first"
    - Or: add precondition: "totalSupply == sum(balanceOf)
      IF no mint is in progress"

4. REPEAT until invariant holds for ALL functions or is too weak to be useful.
```

### What it would catch

Everything in Level 1 + Level 2, PLUS:
- **Conditional invariants:** "X == Y UNLESS function F is executing" (reentrancy guards)
- **Transactional invariants:** "X + Y == constant BEFORE and AFTER any complete transaction"
- **Temporal invariants:** "if X was true at block N, X is still true at block N+1"

### The hard part: refinement convergence

The refinement loop may not converge:
- Each counterexample weakens the invariant
- Too many refinements → invariant becomes trivially true (useless)
- Need a "interestingness" metric to stop refining when the invariant becomes too weak

### The research contribution

The novel part for DeFi: **domain-specific refinement strategies.**

When Z3 returns a counterexample for `totalSupply == sum(balanceOf)`:
- If the counterexample involves `mint()` → refine with "except during mint"
- If the counterexample involves reentrancy → refine with "assuming no reentrant call"
- If the counterexample involves overflow → refine with "assuming no overflow"

These refinement strategies encode DeFi knowledge: minting changes supply, reentrancy breaks mid-transaction invariants, overflow breaks accounting. A general CEGIR loop doesn't know this; a DeFi-specialized one does.

### References

- Garg et al., "ICE: A Robust Framework for Learning Invariants" (2014)
- Padhi et al., "Data-Driven Precondition Inference with Learned Features" (2016)
- Champion et al., "CoStar: Concurrency-Aware Inference of Invariants" (2023)

### Effort estimate: 2-3 months

---

## Level 4: Game-Theoretic Attack Synthesis

### The ultimate goal

Not just finding invariant violations, but synthesizing **profitable attack strategies**:

```
Given: Contract C with functions F1, F2, ..., Fn
       External state (token prices, pool reserves)
       Attacker budget (flash loan capacity)

Find: A sequence of transactions T1, T2, ..., Tk such that:
       1. Each Ti is a valid function call
       2. The attacker's balance increases
       3. The sequence is executable in one transaction (flash loan)
```

This is fundamentally different from invariant checking — it's **strategy synthesis.** The tool would output:
```
Attack found:
  1. Flash loan 1M USDC from Aave
  2. Deposit 1M USDC into Vault (get 1M shares)
  3. Donate 1M USDC to Vault directly (inflates share price)
  4. Redeem shares (get 1.5M USDC due to inflated price)
  5. Repay 1M USDC flash loan
  6. Profit: 500K USDC
```

### Why this is genuinely hard

- **State space explosion:** N functions × K transaction steps × infinite parameter space
- **Economic modeling:** Need token prices, DEX reserves, lending rates — external to the contract
- **Multi-agent reasoning:** Other users' transactions can help or hinder the attack
- **Partial observability:** The attacker doesn't know other pending transactions (unless MEV)

### Existing work

- Qin et al., "Attacking the DeFi Ecosystem with Flash Loans for Fun and Profit" (2021)
- Zhou et al., "High-Frequency Trading on Decentralized On-Chain Exchanges" (2021)
- Wang et al., "Towards Automated Security Analysis of Smart Contracts based on Execution Property Graph" (2022)
- Babel et al., "ClockWork Finance: Automated Analysis of Economic Security in Smart Contracts" (2023)

### Effort estimate: 6-12 months (genuine research)

---

## Recommended Path

```
NOW        → Level 1 (algebraic mining)      → 2-3 weeks  → catches reserve*reserve, sum==total
NEXT       → Level 3 (CEGIR with DeFi hints) → 2-3 months → proves invariants with Z3
LATER      → Level 2 (abstract interpretation)→ 4-6 weeks  → fast pre-pass for large contracts
RESEARCH   → Level 4 (attack synthesis)       → 6-12 months → finds profitable exploits
```

Level 1 is the highest ROI. It catches the same bugs as Level 3 for simple cases (conservation, monotonicity) without the complexity of a refinement loop. Level 3 is needed for conditional and transactional invariants.

Level 4 is the endgame — a tool that finds exploits, not just properties. But it requires solving the economic modeling problem first.
