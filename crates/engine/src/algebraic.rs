use r_evm_verify_lifter::ir::{Expr, Prop};
use r_evm_verify_svm::summary::FunctionSummary;
use std::collections::{HashMap, HashSet};

/// A storage slot identified by its expression (stringified for comparison).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SlotId(pub String);

/// How a function modifies a storage slot.
#[derive(Debug, Clone)]
pub struct SlotDelta {
    pub slot: SlotId,
    /// The old value expression (typically SLoad(slot))
    pub old_value: Expr,
    /// The new value expression (what gets SSTOREd)
    pub new_value: Expr,
    /// The delta: new_value - old_value (simplified)
    pub delta: Option<Expr>,
}

/// A mined algebraic invariant.
#[derive(Debug, Clone)]
pub struct AlgebraicInvariant {
    pub name: String,
    pub description: String,
    /// The invariant expressed as a Prop (for Z3 verification).
    pub property: Option<Prop>,
    /// How confident we are.
    pub confidence: AlgebraicConfidence,
    /// Functions that potentially violate it.
    pub violators: Vec<String>,
    /// Evidence: which functions support this invariant.
    pub supporting_functions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgebraicConfidence {
    Proven,    // Z3 verified for all functions
    Likely,    // Holds for all observed paths
    Candidate, // Pattern detected, not fully verified
}

// ---------------------------------------------------------------------------
// Step 1: Extract Slot Deltas
// ---------------------------------------------------------------------------

/// Extract slot deltas from a function's writes.
pub fn extract_deltas(summary: &FunctionSummary) -> Vec<SlotDelta> {
    let mut deltas = Vec::new();

    for (slot_expr, new_value) in &summary.writes {
        let slot_id = SlotId(format!("{:?}", slot_expr));

        // The old value is SLoad(slot_expr)
        let old_value = Expr::SLoad(Box::new(slot_expr.clone()));

        // Try to compute delta = new_value - old_value symbolically
        let delta = try_extract_delta(new_value, &old_value);

        deltas.push(SlotDelta {
            slot: slot_id,
            old_value,
            new_value: new_value.clone(),
            delta,
        });
    }

    deltas
}

/// Try to extract the delta from a new_value expression.
/// If new_value = Add(SLoad(slot), X), delta = X
/// If new_value = Sub(SLoad(slot), X), delta = -X (represented as Sub(Lit(0), X))
/// Otherwise delta is None (can't determine).
fn try_extract_delta(new_value: &Expr, old_sload: &Expr) -> Option<Expr> {
    match new_value {
        Expr::Add(a, b) => {
            if exprs_match(a, old_sload) {
                Some((**b).clone()) // delta = b
            } else if exprs_match(b, old_sload) {
                Some((**a).clone()) // delta = a
            } else {
                None
            }
        }
        Expr::Sub(a, b) => {
            if exprs_match(a, old_sload) {
                // new = old - b, delta = -b
                Some(Expr::Sub(
                    Box::new(Expr::Lit([0; 32])),
                    Box::new((**b).clone()),
                ))
            } else {
                None
            }
        }
        _ => {
            // new_value doesn't reference old value — it's a complete overwrite
            None
        }
    }
}

/// Check if two expressions are structurally equal (for matching SLoad(slot) patterns).
fn exprs_match(a: &Expr, b: &Expr) -> bool {
    format!("{:?}", a) == format!("{:?}", b)
}

// ---------------------------------------------------------------------------
// Step 2: Generate Candidate Invariants
// ---------------------------------------------------------------------------

/// Mine algebraic invariants from function summaries.
pub fn mine_invariants(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    invariants.extend(mine_conservation(summaries));
    invariants.extend(mine_monotonicity(summaries));
    invariants.extend(mine_bounded_change(summaries));
    invariants.extend(mine_zero_sum(summaries));

    invariants
}

/// Conservation: if two slots always change by opposite deltas, their sum is constant.
/// This catches: balanceOf[from] + balanceOf[to] = constant during transfer()
fn mine_conservation(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        let deltas = extract_deltas(summary);

        // Look for pairs where delta_a = -delta_b (opposite changes)
        for i in 0..deltas.len() {
            for j in (i + 1)..deltas.len() {
                let da = &deltas[i];
                let db = &deltas[j];

                // Check if deltas are opposite
                if let (Some(delta_a), Some(delta_b)) = (&da.delta, &db.delta) {
                    if are_opposite_deltas(delta_a, delta_b) {
                        invariants.push(AlgebraicInvariant {
                            name: "conservation".to_string(),
                            description: format!(
                                "Slots {} and {} change by opposite amounts in {} \
                                 — their sum is conserved.",
                                da.slot.0, db.slot.0, summary.name
                            ),
                            property: None,
                            confidence: AlgebraicConfidence::Likely,
                            violators: vec![],
                            supporting_functions: vec![summary.name.clone()],
                        });
                    }
                }
            }
        }
    }

    // Deduplicate by slot pair
    dedup_invariants(&mut invariants);
    invariants
}

/// Check if two deltas are negations of each other.
fn are_opposite_deltas(a: &Expr, b: &Expr) -> bool {
    // Case 1: a = X, b = Sub(0, X) -> a = -b
    if let Expr::Sub(zero, inner) = b {
        if matches!(**zero, Expr::Lit(z) if z == [0u8; 32]) {
            return exprs_match(a, inner);
        }
    }
    // Case 2: b = X, a = Sub(0, X) -> b = -a
    if let Expr::Sub(zero, inner) = a {
        if matches!(**zero, Expr::Lit(z) if z == [0u8; 32]) {
            return exprs_match(b, inner);
        }
    }
    // Case 3: a and b are the same variable (both sides of a transfer use the same `amount`)
    if let (Expr::Var(va), Expr::Sub(zero, inner)) = (a, b) {
        if matches!(**zero, Expr::Lit(z) if z == [0u8; 32]) {
            if let Expr::Var(vb) = &**inner {
                return va == vb;
            }
        }
    }
    if let (Expr::Sub(zero, inner), Expr::Var(vb)) = (a, b) {
        if matches!(**zero, Expr::Lit(z) if z == [0u8; 32]) {
            if let Expr::Var(va) = &**inner {
                return va == vb;
            }
        }
    }
    false
}

/// Monotonicity: a slot that only increases (or only decreases) across all functions.
fn mine_monotonicity(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    // For each slot, track whether it only increases, only decreases, or both
    // (ever_increases, ever_decreases, functions)
    let mut slot_directions: HashMap<String, (bool, bool, Vec<String>)> = HashMap::new();

    for summary in summaries {
        let deltas = extract_deltas(summary);
        for delta in &deltas {
            let entry =
                slot_directions
                    .entry(delta.slot.0.clone())
                    .or_insert((false, false, Vec::new()));
            entry.2.push(summary.name.clone());

            match &delta.delta {
                Some(Expr::Sub(zero, _)) if matches!(**zero, Expr::Lit(z) if z == [0u8; 32]) => {
                    entry.1 = true; // decreases
                }
                Some(_) => {
                    entry.0 = true; // increases (or unknown direction)
                }
                None => {
                    // Complete overwrite — both directions possible
                    entry.0 = true;
                    entry.1 = true;
                }
            }
        }
    }

    for (slot, (increases, decreases, functions)) in &slot_directions {
        if *increases && !*decreases {
            invariants.push(AlgebraicInvariant {
                name: "monotonic_increase".to_string(),
                description: format!(
                    "Slot {} only increases (never decreases) across functions: {}",
                    truncate(slot),
                    functions.join(", ")
                ),
                property: None,
                confidence: AlgebraicConfidence::Likely,
                violators: vec![],
                supporting_functions: functions.clone(),
            });
        } else if *decreases && !*increases {
            invariants.push(AlgebraicInvariant {
                name: "monotonic_decrease".to_string(),
                description: format!(
                    "Slot {} only decreases (never increases) across functions: {}",
                    truncate(slot),
                    functions.join(", ")
                ),
                property: None,
                confidence: AlgebraicConfidence::Likely,
                violators: vec![],
                supporting_functions: functions.clone(),
            });
        }
    }

    invariants
}

/// Bounded change: a slot that always changes by at most a bounded amount.
fn mine_bounded_change(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        let deltas = extract_deltas(summary);
        for delta in &deltas {
            if let Some(delta_expr) = &delta.delta {
                // If the delta is a concrete literal, it's bounded
                if let Expr::Lit(bytes) = delta_expr {
                    if *bytes != [0u8; 32] {
                        let val = u64::from_be_bytes({
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(&bytes[24..32]);
                            buf
                        });
                        if val > 0 && val < 1_000_000 {
                            invariants.push(AlgebraicInvariant {
                                name: "fixed_increment".to_string(),
                                description: format!(
                                    "Slot {} always changes by exactly {} in {}. \
                                     Counter or index pattern.",
                                    truncate(&delta.slot.0),
                                    val,
                                    summary.name
                                ),
                                property: None,
                                confidence: AlgebraicConfidence::Likely,
                                violators: vec![],
                                supporting_functions: vec![summary.name.clone()],
                            });
                        }
                    }
                }
            }
        }
    }

    invariants
}

/// Zero-sum: across ALL writes in a function, the total delta sums to zero.
/// This is a stronger conservation invariant: not just pairs, but the entire function.
fn mine_zero_sum(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        let deltas = extract_deltas(summary);
        let known_deltas: Vec<&SlotDelta> = deltas.iter().filter(|d| d.delta.is_some()).collect();

        if known_deltas.len() < 2 {
            continue;
        }

        // Count positive and negative deltas
        let mut positives = 0;
        let mut negatives = 0;

        let mut positive_vars: HashSet<String> = HashSet::new();
        let mut negative_vars: HashSet<String> = HashSet::new();

        for d in &known_deltas {
            match d.delta.as_ref().unwrap() {
                Expr::Sub(zero, inner) if matches!(**zero, Expr::Lit(z) if z == [0u8; 32]) => {
                    negatives += 1;
                    if let Expr::Var(v) = &**inner {
                        negative_vars.insert(v.clone());
                    }
                }
                Expr::Var(v) => {
                    positives += 1;
                    positive_vars.insert(v.clone());
                }
                _ => {
                    positives += 1;
                }
            }
        }

        // If positive and negative deltas reference the same variable, it's zero-sum
        let shared_vars: HashSet<_> = positive_vars.intersection(&negative_vars).collect();
        if !shared_vars.is_empty() {
            invariants.push(AlgebraicInvariant {
                name: "zero_sum_transfer".to_string(),
                description: format!(
                    "{} performs a zero-sum transfer: {} slots increase and {} decrease \
                     by the same variable. Total value is conserved.",
                    summary.name, positives, negatives
                ),
                property: None,
                confidence: AlgebraicConfidence::Likely,
                violators: vec![],
                supporting_functions: vec![summary.name.clone()],
            });
        }

        // If equal number of positive and negative deltas, it might be zero-sum
        if positives == negatives && positives > 0 && shared_vars.is_empty() {
            invariants.push(AlgebraicInvariant {
                name: "potential_conservation".to_string(),
                description: format!(
                    "{} has {} positive and {} negative deltas \
                     — potentially conserved quantity. Needs deeper analysis.",
                    summary.name, positives, negatives
                ),
                property: None,
                confidence: AlgebraicConfidence::Candidate,
                violators: vec![],
                supporting_functions: vec![summary.name.clone()],
            });
        }
    }

    invariants
}

/// Cross-function conservation: if every function that writes to slot set S
/// preserves some relationship, it's a protocol invariant.
pub fn mine_cross_function_conservation(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    // Group slot deltas by slot across all functions
    let mut slot_all_deltas: HashMap<String, Vec<(String, Option<Expr>)>> = HashMap::new();

    for summary in summaries {
        let deltas = extract_deltas(summary);
        for d in deltas {
            slot_all_deltas
                .entry(d.slot.0.clone())
                .or_default()
                .push((summary.name.clone(), d.delta));
        }
    }

    // A slot that is always overwritten (no delta extraction possible) by multiple functions
    // without consistency is suspicious
    for (slot, all_deltas) in &slot_all_deltas {
        let has_delta: Vec<&str> = all_deltas
            .iter()
            .filter(|(_, d)| d.is_some())
            .map(|(f, _)| f.as_str())
            .collect();
        let no_delta: Vec<&str> = all_deltas
            .iter()
            .filter(|(_, d)| d.is_none())
            .map(|(f, _)| f.as_str())
            .collect();

        if !has_delta.is_empty() && !no_delta.is_empty() {
            invariants.push(AlgebraicInvariant {
                name: "inconsistent_slot_update".to_string(),
                description: format!(
                    "Slot {} is incrementally updated by {} but completely \
                     overwritten by {}. The overwriters may break an accumulator invariant.",
                    truncate(slot),
                    has_delta.join(", "),
                    no_delta.join(", ")
                ),
                property: None,
                confidence: AlgebraicConfidence::Candidate,
                violators: no_delta.iter().map(|s| s.to_string()).collect(),
                supporting_functions: has_delta.iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    invariants
}

fn dedup_invariants(invariants: &mut Vec<AlgebraicInvariant>) {
    let mut seen = HashSet::new();
    invariants.retain(|inv| {
        let key = format!("{}:{}", inv.name, inv.description);
        seen.insert(key)
    });
}

fn truncate(s: &str) -> String {
    if s.len() > 50 {
        format!("{}...", &s[..47])
    } else {
        s.to_string()
    }
}

/// Format algebraic invariants for display.
pub fn format_algebraic_invariants(invariants: &[AlgebraicInvariant]) -> String {
    let mut out = String::new();

    let proven = invariants
        .iter()
        .filter(|i| i.confidence == AlgebraicConfidence::Proven)
        .count();
    let likely = invariants
        .iter()
        .filter(|i| i.confidence == AlgebraicConfidence::Likely)
        .count();
    let candidate = invariants
        .iter()
        .filter(|i| i.confidence == AlgebraicConfidence::Candidate)
        .count();
    let with_violators: Vec<_> = invariants
        .iter()
        .filter(|i| !i.violators.is_empty())
        .collect();

    out.push_str(&format!(
        "Mined {} algebraic invariants ({} proven, {} likely, {} candidate)\n",
        invariants.len(),
        proven,
        likely,
        candidate
    ));
    out.push_str(&format!(
        "{} potential violations\n\n",
        with_violators.len()
    ));

    // Group by type
    let mut by_name: HashMap<&str, Vec<&AlgebraicInvariant>> = HashMap::new();
    for inv in invariants {
        by_name.entry(&inv.name).or_default().push(inv);
    }

    // Sort keys for deterministic output
    let mut names: Vec<&&str> = by_name.keys().collect();
    names.sort();

    for name in names {
        let invs = &by_name[*name];
        out.push_str(&format!("--- {} ({}) ---\n", name, invs.len()));
        for inv in invs {
            let conf = match inv.confidence {
                AlgebraicConfidence::Proven => "PROVEN",
                AlgebraicConfidence::Likely => "LIKELY",
                AlgebraicConfidence::Candidate => "CANDIDATE",
            };
            out.push_str(&format!("  [{}] {}\n", conf, inv.description));
            if !inv.violators.is_empty() {
                out.push_str(&format!(
                    "    ! Potential violators: {}\n",
                    inv.violators.join(", ")
                ));
            }
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_evm_verify_lifter::ir::Expr;
    use r_evm_verify_svm::summary::FunctionSummary;

    fn make_summary(name: &str, writes: Vec<(Expr, Expr)>) -> FunctionSummary {
        let modifies_storage = !writes.is_empty();
        FunctionSummary {
            name: name.to_string(),
            preconditions: vec![],
            reads: vec![],
            writes,
            has_external_call: false,
            modifies_storage,
            revert_conditions: vec![],
            success_conditions: vec![],
        }
    }

    #[test]
    fn test_extract_delta_add() {
        let slot = Expr::Var("slot_0".into());
        let old = Expr::SLoad(Box::new(slot.clone()));
        let amount = Expr::Var("amount".into());
        let new_val = Expr::Add(Box::new(old.clone()), Box::new(amount.clone()));

        let summary = make_summary("test_fn", vec![(slot, new_val)]);
        let deltas = extract_deltas(&summary);

        assert_eq!(deltas.len(), 1);
        assert!(deltas[0].delta.is_some());
        assert_eq!(deltas[0].delta.as_ref().unwrap(), &amount);
    }

    #[test]
    fn test_extract_delta_sub() {
        let slot = Expr::Var("slot_0".into());
        let old = Expr::SLoad(Box::new(slot.clone()));
        let amount = Expr::Var("amount".into());
        let new_val = Expr::Sub(Box::new(old.clone()), Box::new(amount.clone()));

        let summary = make_summary("test_fn", vec![(slot, new_val)]);
        let deltas = extract_deltas(&summary);

        assert_eq!(deltas.len(), 1);
        assert!(deltas[0].delta.is_some());
        // delta should be Sub(Lit(0), amount) i.e. -amount
        match deltas[0].delta.as_ref().unwrap() {
            Expr::Sub(zero, inner) => {
                assert_eq!(**zero, Expr::Lit([0; 32]));
                assert_eq!(**inner, amount);
            }
            other => panic!("Expected Sub(0, amount), got {:?}", other),
        }
    }

    #[test]
    fn test_conservation_detection() {
        let slot_a = Expr::Var("slot_a".into());
        let slot_b = Expr::Var("slot_b".into());
        let amount = Expr::Var("amount".into());

        // slot_a gets old + amount
        let new_a = Expr::Add(
            Box::new(Expr::SLoad(Box::new(slot_a.clone()))),
            Box::new(amount.clone()),
        );
        // slot_b gets old - amount
        let new_b = Expr::Sub(
            Box::new(Expr::SLoad(Box::new(slot_b.clone()))),
            Box::new(amount.clone()),
        );

        let summary = make_summary("transfer", vec![(slot_a, new_a), (slot_b, new_b)]);
        let invariants = mine_conservation(&[summary]);

        assert!(
            !invariants.is_empty(),
            "Should detect conservation invariant"
        );
        assert_eq!(invariants[0].name, "conservation");
    }

    #[test]
    fn test_monotonicity_detection() {
        let slot = Expr::Var("counter".into());
        let amount = Expr::Var("x".into());

        let new_val = Expr::Add(
            Box::new(Expr::SLoad(Box::new(slot.clone()))),
            Box::new(amount.clone()),
        );

        let s1 = make_summary("increment_a", vec![(slot.clone(), new_val.clone())]);
        let s2 = make_summary("increment_b", vec![(slot.clone(), new_val)]);

        let invariants = mine_monotonicity(&[s1, s2]);

        assert!(
            !invariants.is_empty(),
            "Should detect monotonic increase invariant"
        );
        assert_eq!(invariants[0].name, "monotonic_increase");
    }

    #[test]
    fn test_zero_sum_detection() {
        let slot_a = Expr::Var("balance_from".into());
        let slot_b = Expr::Var("balance_to".into());
        let amount = Expr::Var("amount".into());

        let new_a = Expr::Sub(
            Box::new(Expr::SLoad(Box::new(slot_a.clone()))),
            Box::new(amount.clone()),
        );
        let new_b = Expr::Add(
            Box::new(Expr::SLoad(Box::new(slot_b.clone()))),
            Box::new(amount.clone()),
        );

        let summary = make_summary("transfer", vec![(slot_a, new_a), (slot_b, new_b)]);
        let invariants = mine_zero_sum(&[summary]);

        assert!(
            !invariants.is_empty(),
            "Should detect zero-sum transfer invariant"
        );
        assert!(invariants.iter().any(|i| i.name == "zero_sum_transfer"));
    }

    #[test]
    fn test_complete_overwrite_no_delta() {
        let slot = Expr::Var("state".into());
        // Complete overwrite: new_value = Lit(42), doesn't reference old value
        let mut val = [0u8; 32];
        val[31] = 42;
        let new_val = Expr::Lit(val);

        let summary = make_summary("set_state", vec![(slot, new_val)]);
        let deltas = extract_deltas(&summary);

        assert_eq!(deltas.len(), 1);
        assert!(
            deltas[0].delta.is_none(),
            "Complete overwrite should have no delta"
        );
    }

    #[test]
    fn test_cross_function_inconsistency() {
        let slot = Expr::Var("counter".into());
        let amount = Expr::Var("x".into());

        // Function 1: incremental update (slot += x)
        let new_inc = Expr::Add(
            Box::new(Expr::SLoad(Box::new(slot.clone()))),
            Box::new(amount.clone()),
        );
        let s1 = make_summary("increment", vec![(slot.clone(), new_inc)]);

        // Function 2: complete overwrite (slot = 42)
        let mut val = [0u8; 32];
        val[31] = 42;
        let s2 = make_summary("reset", vec![(slot, Expr::Lit(val))]);

        let invariants = mine_cross_function_conservation(&[s1, s2]);

        assert!(
            !invariants.is_empty(),
            "Should detect inconsistent slot update"
        );
        assert_eq!(invariants[0].name, "inconsistent_slot_update");
        assert!(invariants[0].violators.contains(&"reset".to_string()));
    }
}
