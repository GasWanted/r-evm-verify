# Temporal Equilibrium Analysis — Design Document

## Core Idea

Smart contracts maintain an "equilibrium" — a set of relationships between storage slots that hold true under normal operation. Every function was designed to maintain this equilibrium.

A vulnerability is when a specific execution path pushes the system OUT of equilibrium at a point where an attacker has control (an external CALL). The attacker observes or exploits the broken state through a callback before the equilibrium is restored.

## The Key Insight

Classic reentrancy detection asks:
```
Is there a SLOAD(X) → CALL → SSTORE(X) conflict on slot X?
```

Temporal equilibrium detection asks:
```
Are slots {A, B, C} that should change TOGETHER all updated
before the CALL, or is the update PARTIAL?
```

The second catches bugs the first misses. A flash loan callback sees `balanceA` updated but `balanceB` not yet updated — the equilibrium is broken — but there's no single-slot SLOAD→CALL→SSTORE conflict on either slot individually.

## Algorithm

### Step 1: Cluster — Find co-modification groups (no Z3, O(functions × slots))

From function summaries, identify which storage slots are always modified together.

```
transfer(): writes {balanceOf[from], balanceOf[to]}  → cluster {A, B}
deposit():  writes {balanceOf[user], totalSupply}     → cluster {C, D}
withdraw(): writes {balanceOf[user], totalSupply}     → cluster {C, D} (same)
```

Slots that always appear together in writes are a cluster. The cluster represents a piece of the contract's accounting that must change atomically.

### Step 2: Characterize — Find the equilibrium (cheap pattern matching)

For each cluster, determine what relationship the majority of functions maintain.

```
Cluster {A, B}: transfer() does A -= x, B += x → equilibrium: A + B = constant
Cluster {C, D}: deposit() does C += x, D += x  → equilibrium: C and D change in same direction
```

This uses the delta extraction from algebraic mining — the same infrastructure.

### Step 3: Track — During symbolic execution, monitor the dirty set (O(1) per instruction)

During each function's symbolic execution, track which slots from each cluster have been written so far.

```
At function entry:          dirty = {}
After SSTORE(slot_A, val):  dirty = {A}
After SSTORE(slot_B, val):  dirty = {A, B}
```

At each CALL, DELEGATECALL, or STATICCALL instruction, check:

```
For each cluster {A, B, C}:
    written = dirty ∩ {A, B, C}
    if written ≠ {} AND written ≠ {A, B, C}:
        → PARTIAL UPDATE at external call
        → Equilibrium is broken at this point
        → Attacker callback could observe inconsistent state
```

### Step 4: Report — The vulnerability window

```
Function: flashLoan()
  Cluster: {available, borrowed} (equilibrium: available + borrowed = constant)

  Instruction 42: SSTORE(available, old - amount)    ← available updated
  Instruction 67: CALL(borrower, ...)                ← ATTACKER GETS CONTROL HERE
  Instruction 89: SSTORE(borrowed, old + amount)     ← borrowed updated

  VULNERABILITY WINDOW: instructions 42-89
  At instruction 67, cluster {available, borrowed} is partially updated.
  available has changed but borrowed has not.
  A re-entrant call at this point sees available + borrowed ≠ constant.
```

## Cost Analysis

| Step | Cost | Z3 needed? |
|------|------|-----------|
| Clustering | O(functions × slots) | No |
| Characterization | O(clusters × functions) | No (delta pattern matching) |
| Temporal tracking | O(1) per instruction | No (set membership) |
| Reporting | O(clusters × call_points) | No |
| **Total** | **O(instructions)** — same cost as symbolic execution itself | **No additional Z3** |

The temporal analysis adds effectively zero overhead to the existing symbolic execution pass. It's just maintaining a set of "which slots have been written" alongside the existing SVM state.

## What It Catches

### Flash Loan Callbacks
```
flashLoan() sends tokens → CALL(borrower.callback()) → restores tokens
At CALL: token balance is reduced but accounting not updated
Callback can exploit: borrow against inflated collateral, manipulate price
```

### Classic Reentrancy (multi-slot)
```
withdraw() sends ETH → CALL(msg.sender) → updates balance
At CALL: ETH is sent but balance not yet decreased
Callback can: re-enter withdraw(), double-spend
```

### Cross-Function Reentrancy
```
functionA() updates slotX → CALL → updates slotY
functionB() reads both slotX and slotY
At CALL: slotX is new but slotY is old
If callback calls functionB(), it sees inconsistent state
```

### Read-Only Reentrancy
```
functionA() updates reserves → CALL → updates price
At CALL: reserves are new but cached price is old
If callback reads price via STATICCALL, it gets stale value
```

## What It Doesn't Catch

- **Deployment bugs** (uninitialized proxy) — no execution to analyze
- **Rounding direction** — not visible in symbolic structure
- **Economic attacks** (oracle manipulation via DEX trades) — external state not modeled
- **Logic errors** (wrong formula, off-by-one) — the equilibrium IS the wrong formula
- **Single-function bugs** (no external call involved) — no vulnerability window

## Comparison with Existing Tools

| Tool | What it detects | Our advantage |
|------|----------------|---------------|
| **Sereum (2019)** | Single-slot SLOAD→CALL→SSTORE conflicts at runtime | We detect MULTI-SLOT partial updates at static analysis time |
| **Sailfish (2022)** | Storage dependency graph conflicts between functions | We track TEMPORAL ordering within a function's execution |
| **Slither** | Basic reentrancy pattern (external call before state change) | We identify WHICH specific equilibrium is broken and WHY |
| **Mythril** | Symbolic execution + reentrancy detector | We use co-modification clusters to find partial updates, not just single-slot conflicts |

## Novel Contribution

1. **Co-modification clusters** as the unit of analysis — no existing tool groups storage slots by "which functions always modify them together"

2. **Temporal equilibrium tracking** — checking cluster completeness at each external call point during symbolic execution

3. **Vulnerability window identification** — pinpointing the exact instruction range where the state is inconsistent and an attacker has control

4. **Zero additional cost** — set tracking adds O(1) per instruction to existing SVM execution

## Immunefi Hack Coverage

| Hack | Bounty | Caught? | Why |
|------|--------|---------|-----|
| Fei Protocol (flash loan) | $800K | **Yes** | Partial cluster update at CALL |
| O3 Swap (ERC777) | $500 | **Yes** | Token callback during partial update |
| DFX Finance (reentrancy) | $100K | **Yes** | Curve state partial update |
| BeanStalk (flash loan) | $1.28M | **Yes** | Governance state partial update during callback |
| Belt Finance (strategy) | $1.05M | **Maybe** | Depends on harvest mid-execution state |
| Redacted Cartel | $560K | **Yes** (existing) | Access control outlier |
| Sense Finance | $50K | **Yes** (existing) | Access control outlier |
| Wormhole | $10M | No | Deployment bug |
| Notional | $1M | No | Logic error in formula |
| DFX rounding | $100K | No | Rounding direction |

**Estimated additional catch: 4-5 hacks worth $2-3M in bounty value, on top of existing detectors.**

## Implementation Plan

### Phase 1: Co-modification clustering
- From existing function summaries, group slots by co-occurrence in writes
- Output: list of clusters with member slots and supporting functions

### Phase 2: SVM dirty set tracking
- Add `dirty_slots: HashSet<String>` to SvmState
- At each SSTORE, add the slot to dirty_slots
- At each CALL/DELEGATECALL/STATICCALL, check cluster completeness

### Phase 3: Vulnerability window reporting
- When a partial update is detected at a CALL, record:
  - Which cluster
  - Which slots are updated vs missing
  - The instruction offset of the CALL
  - The instruction offset of the first and last SSTORE in the cluster
- Format as a finding with the vulnerability window

### Phase 4: Integration with equilibrium mining
- Combine with algebraic invariant mining to identify WHAT the equilibrium is (not just that it's broken)
- Report: "Cluster {A, B} has conservation invariant A + B = constant. At CALL in flashLoan(), A is updated but B is not. A re-entrant call sees A + B ≠ constant."
