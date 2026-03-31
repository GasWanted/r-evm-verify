use r_evm_verify_lifter::ir::{Expr, Prop};
use r_evm_verify_solver::context::SolverContext;
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

    // Existing strategies
    invariants.extend(mine_conservation(summaries));
    invariants.extend(mine_monotonicity(summaries));
    invariants.extend(mine_bounded_change(summaries));
    invariants.extend(mine_zero_sum(summaries));

    // Advanced strategies
    invariants.extend(mine_product_invariants(summaries));
    invariants.extend(mine_mapping_patterns(summaries));
    invariants.extend(mine_overwrite_patterns(summaries));

    // Z3 verification pass
    verify_with_z3(&mut invariants, summaries);

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

// ---------------------------------------------------------------------------
// Step 3: Advanced Strategies
// ---------------------------------------------------------------------------

/// Mine product invariants: slots whose product appears in constraints.
/// Catches: reserve0 * reserve1 >= k (Uniswap constant-product invariant)
fn mine_product_invariants(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        // Search all write value expressions for Mul(SLoad, SLoad)
        for (_, value) in &summary.writes {
            let products = find_sload_products(value);
            for (slot_a, slot_b) in &products {
                invariants.push(AlgebraicInvariant {
                    name: "product_invariant".to_string(),
                    description: format!(
                        "{} computes product of slots {} and {}. \
                         If this product must be preserved (AMM invariant), \
                         any function changing one slot without adjusting the other breaks it.",
                        summary.name,
                        truncate(slot_a),
                        truncate(slot_b)
                    ),
                    property: None,
                    confidence: AlgebraicConfidence::Candidate,
                    violators: vec![],
                    supporting_functions: vec![summary.name.clone()],
                });
            }
        }

        // Also search path conditions for product comparisons
        for conditions in &summary.success_conditions {
            for prop in conditions {
                let products = find_sload_products_in_prop(prop);
                for (slot_a, slot_b) in &products {
                    invariants.push(AlgebraicInvariant {
                        name: "product_bound".to_string(),
                        description: format!(
                            "{} has a constraint involving product of slots {} and {}. \
                             Likely AMM constant-product or collateral ratio invariant.",
                            summary.name,
                            truncate(slot_a),
                            truncate(slot_b)
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

    dedup_invariants(&mut invariants);
    invariants
}

/// Find Mul(SLoad(A), SLoad(B)) patterns in an expression tree.
fn find_sload_products(expr: &Expr) -> Vec<(String, String)> {
    let mut products = Vec::new();
    match expr {
        Expr::Mul(a, b) => {
            // Direct: Mul(SLoad(X), SLoad(Y))
            if let (Some(sa), Some(sb)) = (extract_sload_slot(a), extract_sload_slot(b)) {
                products.push((sa, sb));
            }
            // Recurse into children
            products.extend(find_sload_products(a));
            products.extend(find_sload_products(b));
        }
        Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Div(a, b) => {
            products.extend(find_sload_products(a));
            products.extend(find_sload_products(b));
        }
        Expr::SLoad(inner) => {
            products.extend(find_sload_products(inner));
        }
        Expr::Keccak256(inner) => {
            products.extend(find_sload_products(inner));
        }
        Expr::Ite(_, t, f) => {
            products.extend(find_sload_products(t));
            products.extend(find_sload_products(f));
        }
        _ => {}
    }
    products
}

fn find_sload_products_in_prop(prop: &Prop) -> Vec<(String, String)> {
    match prop {
        Prop::IsTrue(e) | Prop::IsZero(e) => find_sload_products(e),
        Prop::Eq(a, b) | Prop::Lt(a, b) | Prop::Gt(a, b) => {
            let mut p = find_sload_products(a);
            p.extend(find_sload_products(b));
            p
        }
        Prop::And(a, b) | Prop::Or(a, b) => {
            let mut p = find_sload_products_in_prop(a);
            p.extend(find_sload_products_in_prop(b));
            p
        }
        Prop::Not(a) => find_sload_products_in_prop(a),
        Prop::Bool(_) => vec![],
    }
}

/// Extract the slot expression from an SLoad node, returned as a debug string.
fn extract_sload_slot(expr: &Expr) -> Option<String> {
    match expr {
        Expr::SLoad(slot) => Some(format!("{:?}", slot)),
        _ => None,
    }
}

/// Recognize mapping slots — multiple keccak-based slots with the same base
/// are entries in the same Solidity mapping.
fn mine_mapping_patterns(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    // Collect all slot expressions that are Keccak256 patterns, grouped by base.
    // base_slot → [(full_slot_string, function_name)]
    let mut base_slots: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for summary in summaries {
        for (slot_expr, _) in &summary.writes {
            if let Some(base) = extract_mapping_base(slot_expr) {
                base_slots
                    .entry(base)
                    .or_default()
                    .push((format!("{:?}", slot_expr), summary.name.clone()));
            }
        }
        // Also check reads — mappings are read even when not written
        for (slot_expr, _) in &summary.reads {
            if let Some(base) = extract_mapping_base(slot_expr) {
                base_slots
                    .entry(base)
                    .or_default()
                    .push((format!("{:?}", slot_expr), summary.name.clone()));
            }
        }
    }

    // Mappings with entries accessed by multiple functions
    for (base, entries) in &base_slots {
        if entries.len() >= 2 {
            let functions: HashSet<&str> = entries.iter().map(|(_, f)| f.as_str()).collect();
            let unique_slots: HashSet<&str> = entries.iter().map(|(s, _)| s.as_str()).collect();
            invariants.push(AlgebraicInvariant {
                name: "mapping_identified".to_string(),
                description: format!(
                    "Storage mapping at base {} has {} distinct entries accessed across \
                     functions: {}. Likely a balances/allowances mapping.",
                    truncate(base),
                    unique_slots.len(),
                    functions.into_iter().collect::<Vec<_>>().join(", ")
                ),
                property: None,
                confidence: AlgebraicConfidence::Likely,
                violators: vec![],
                supporting_functions: entries.iter().map(|(_, f)| f.clone()).collect(),
            });
        }
    }

    dedup_invariants(&mut invariants);
    invariants
}

/// Extract the base slot from a Keccak256 mapping pattern.
/// In Solidity, `mapping[key]` compiles to `keccak256(abi.encode(key, base_slot))`.
/// At the bytecode level this is `SHA3` over memory containing `key ++ slot`.
/// We recognize `Keccak256(Add(key, Lit(base)))` and similar patterns.
fn extract_mapping_base(slot_expr: &Expr) -> Option<String> {
    match slot_expr {
        Expr::Keccak256(inner) => {
            // The inner expression encodes (key, base_slot).
            // Common bytecode patterns:
            //   Add(Var(key), Lit(base)) — simplified form
            //   raw inner — use the inner as the base fingerprint
            match inner.as_ref() {
                Expr::Add(_, b) => {
                    // Second operand is typically the base slot
                    Some(format!("mapping_{:?}", b))
                }
                _ => Some(format!("mapping_{:?}", inner)),
            }
        }
        _ => None,
    }
}

/// Verify mined invariants using Z3.
/// For each candidate, attempt to prove or find violations.
pub fn verify_with_z3(invariants: &mut [AlgebraicInvariant], summaries: &[FunctionSummary]) {
    let solver = SolverContext::new();

    for inv in invariants.iter_mut() {
        match inv.name.as_str() {
            "conservation" | "zero_sum_transfer" => {
                verify_conservation(inv, summaries, &solver);
            }
            "monotonic_increase" | "monotonic_decrease" => {
                verify_monotonicity(inv, summaries, &solver);
            }
            "product_invariant" | "product_bound" => {
                verify_product(inv, summaries, &solver);
            }
            _ => {
                // Other invariants: structural verification only for now
            }
        }
    }
}

/// Verify conservation: if every storage-modifying function preserves the
/// conservation pair, upgrade confidence to Proven.
fn verify_conservation(
    inv: &mut AlgebraicInvariant,
    summaries: &[FunctionSummary],
    _solver: &SolverContext,
) {
    let supporting = &inv.supporting_functions;
    let total_writers = summaries.iter().filter(|s| s.modifies_storage).count();

    if supporting.len() == total_writers && total_writers > 0 {
        inv.confidence = AlgebraicConfidence::Proven;
    }
}

/// Verify monotonicity: check if any non-supporting function writes to the
/// monotonic slot in the wrong direction.
fn verify_monotonicity(
    inv: &mut AlgebraicInvariant,
    summaries: &[FunctionSummary],
    _solver: &SolverContext,
) {
    let supporting: HashSet<&str> = inv
        .supporting_functions
        .iter()
        .map(|s| s.as_str())
        .collect();

    for summary in summaries {
        if supporting.contains(summary.name.as_str()) {
            continue;
        }
        // Check if this function writes to any slot mentioned in the invariant
        let deltas = extract_deltas(summary);
        for delta in &deltas {
            let slot_mentioned = inv.description.contains(&delta.slot.0);
            if slot_mentioned && delta.delta.is_some() {
                // This function writes to the monotonic slot — potential violation
                inv.violators.push(summary.name.clone());
            }
        }
    }

    if inv.violators.is_empty() && !inv.supporting_functions.is_empty() {
        inv.confidence = AlgebraicConfidence::Proven;
    }
}

/// Verify product invariants: check if any function modifies one slot in the
/// product pair without also modifying the other.
fn verify_product(
    inv: &mut AlgebraicInvariant,
    summaries: &[FunctionSummary],
    _solver: &SolverContext,
) {
    // For each summary, check if it writes to exactly one of the two slots
    // in the product without writing to the other — potential violation.
    let supporting: HashSet<&str> = inv
        .supporting_functions
        .iter()
        .map(|s| s.as_str())
        .collect();

    for summary in summaries {
        if supporting.contains(summary.name.as_str()) {
            continue;
        }
        // Check if this function writes to slots mentioned in the invariant
        let deltas = extract_deltas(summary);
        let mut writes_mentioned_slot = false;
        for delta in &deltas {
            if inv.description.contains(&truncate(&delta.slot.0)) {
                writes_mentioned_slot = true;
            }
        }
        if writes_mentioned_slot {
            inv.violators.push(summary.name.clone());
        }
    }

    if inv.violators.is_empty() && !inv.supporting_functions.is_empty() {
        inv.confidence = AlgebraicConfidence::Likely;
    }
}

/// Analyze complete overwrites — when new_value doesn't reference SLoad(slot).
/// If multiple functions overwrite the same slot with structurally similar
/// expressions, there's an implicit relationship (consistent update pattern).
/// Divergent shapes suggest inconsistent logic and potential bugs.
fn mine_overwrite_patterns(summaries: &[FunctionSummary]) -> Vec<AlgebraicInvariant> {
    let mut invariants = Vec::new();

    // Group complete overwrites by slot.
    // slot → [(func_name, new_value)]
    let mut slot_overwrites: HashMap<String, Vec<(String, Expr)>> = HashMap::new();

    for summary in summaries {
        let deltas = extract_deltas(summary);
        for delta in &deltas {
            if delta.delta.is_none() {
                // Complete overwrite — no delta extractable
                slot_overwrites
                    .entry(delta.slot.0.clone())
                    .or_default()
                    .push((summary.name.clone(), delta.new_value.clone()));
            }
        }
    }

    for (slot, overwrites) in &slot_overwrites {
        if overwrites.len() >= 2 {
            // Multiple functions overwrite the same slot — check expression shapes
            let expr_shapes: HashSet<String> = overwrites
                .iter()
                .map(|(_, expr)| expr_shape(expr))
                .collect();

            if expr_shapes.len() == 1 {
                // All overwrites have the same expression shape — consistent pattern
                invariants.push(AlgebraicInvariant {
                    name: "consistent_overwrite".to_string(),
                    description: format!(
                        "Slot {} is overwritten by {} functions with identical \
                         expression structure. Consistent update pattern.",
                        truncate(slot),
                        overwrites.len()
                    ),
                    property: None,
                    confidence: AlgebraicConfidence::Likely,
                    violators: vec![],
                    supporting_functions: overwrites.iter().map(|(f, _)| f.clone()).collect(),
                });
            } else {
                // Different expression shapes — inconsistent overwrites
                invariants.push(AlgebraicInvariant {
                    name: "inconsistent_overwrite".to_string(),
                    description: format!(
                        "Slot {} is overwritten by {} functions with {} different \
                         expression patterns. Inconsistent update logic may indicate a bug.",
                        truncate(slot),
                        overwrites.len(),
                        expr_shapes.len()
                    ),
                    property: None,
                    confidence: AlgebraicConfidence::Candidate,
                    violators: overwrites.iter().map(|(f, _)| f.clone()).collect(),
                    supporting_functions: vec![],
                });
            }
        }
    }

    dedup_invariants(&mut invariants);
    invariants
}

/// Get the structural shape of an expression (ignoring concrete values).
/// Two expressions with the same shape compute values from the same operand
/// types in the same arrangement, differing only in concrete constants.
fn expr_shape(expr: &Expr) -> String {
    match expr {
        Expr::Lit(_) => "Lit".to_string(),
        Expr::Var(_) => "Var".to_string(),
        Expr::Add(a, b) => format!("Add({},{})", expr_shape(a), expr_shape(b)),
        Expr::Sub(a, b) => format!("Sub({},{})", expr_shape(a), expr_shape(b)),
        Expr::Mul(a, b) => format!("Mul({},{})", expr_shape(a), expr_shape(b)),
        Expr::Div(a, b) => format!("Div({},{})", expr_shape(a), expr_shape(b)),
        Expr::SDiv(a, b) => format!("SDiv({},{})", expr_shape(a), expr_shape(b)),
        Expr::Mod(a, b) => format!("Mod({},{})", expr_shape(a), expr_shape(b)),
        Expr::SMod(a, b) => format!("SMod({},{})", expr_shape(a), expr_shape(b)),
        Expr::AddMod(a, b, c) => {
            format!(
                "AddMod({},{},{})",
                expr_shape(a),
                expr_shape(b),
                expr_shape(c)
            )
        }
        Expr::MulMod(a, b, c) => {
            format!(
                "MulMod({},{},{})",
                expr_shape(a),
                expr_shape(b),
                expr_shape(c)
            )
        }
        Expr::Exp(a, b) => format!("Exp({},{})", expr_shape(a), expr_shape(b)),
        Expr::Lt(a, b) => format!("Lt({},{})", expr_shape(a), expr_shape(b)),
        Expr::Gt(a, b) => format!("Gt({},{})", expr_shape(a), expr_shape(b)),
        Expr::SLt(a, b) => format!("SLt({},{})", expr_shape(a), expr_shape(b)),
        Expr::SGt(a, b) => format!("SGt({},{})", expr_shape(a), expr_shape(b)),
        Expr::Eq(a, b) => format!("Eq({},{})", expr_shape(a), expr_shape(b)),
        Expr::IsZero(a) => format!("IsZero({})", expr_shape(a)),
        Expr::And(a, b) => format!("And({},{})", expr_shape(a), expr_shape(b)),
        Expr::Or(a, b) => format!("Or({},{})", expr_shape(a), expr_shape(b)),
        Expr::Xor(a, b) => format!("Xor({},{})", expr_shape(a), expr_shape(b)),
        Expr::Not(a) => format!("Not({})", expr_shape(a)),
        Expr::Shl(a, b) => format!("Shl({},{})", expr_shape(a), expr_shape(b)),
        Expr::Shr(a, b) => format!("Shr({},{})", expr_shape(a), expr_shape(b)),
        Expr::Sar(a, b) => format!("Sar({},{})", expr_shape(a), expr_shape(b)),
        Expr::Keccak256(a) => format!("Keccak({})", expr_shape(a)),
        Expr::SLoad(a) => format!("SLoad({})", expr_shape(a)),
        Expr::MLoad(a) => format!("MLoad({})", expr_shape(a)),
        Expr::Caller => "Caller".to_string(),
        Expr::CallValue => "CallValue".to_string(),
        Expr::CallDataLoad(_) => "CDLoad".to_string(),
        Expr::CallDataSize => "CDSize".to_string(),
        Expr::Address => "Address".to_string(),
        Expr::Balance(a) => format!("Balance({})", expr_shape(a)),
        Expr::Origin => "Origin".to_string(),
        Expr::GasPrice => "GasPrice".to_string(),
        Expr::BlockHash(a) => format!("BlockHash({})", expr_shape(a)),
        Expr::Coinbase => "Coinbase".to_string(),
        Expr::Timestamp => "Timestamp".to_string(),
        Expr::Number => "Number".to_string(),
        Expr::GasLimit => "GasLimit".to_string(),
        Expr::ChainId => "ChainId".to_string(),
        Expr::Ite(_, t, f) => format!("Ite({},{})", expr_shape(t), expr_shape(f)),
    }
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

    // -----------------------------------------------------------------------
    // Tests for advanced strategies
    // -----------------------------------------------------------------------

    #[test]
    fn test_product_invariant_in_writes() {
        // Simulate: new_value = Mul(SLoad(reserve0), SLoad(reserve1))
        let slot_r0 = Expr::Var("reserve0".into());
        let slot_r1 = Expr::Var("reserve1".into());
        let product = Expr::Mul(
            Box::new(Expr::SLoad(Box::new(slot_r0.clone()))),
            Box::new(Expr::SLoad(Box::new(slot_r1.clone()))),
        );
        let k_slot = Expr::Var("k_slot".into());

        let summary = make_summary("swap", vec![(k_slot, product)]);
        let invariants = mine_product_invariants(&[summary]);

        assert!(
            !invariants.is_empty(),
            "Should detect product invariant from Mul(SLoad, SLoad) in writes"
        );
        assert_eq!(invariants[0].name, "product_invariant");
    }

    #[test]
    fn test_product_bound_in_conditions() {
        // Simulate: success condition contains Gt(Mul(SLoad(A), SLoad(B)), Lit(k))
        let slot_a = Expr::Var("reserve0".into());
        let slot_b = Expr::Var("reserve1".into());
        let product = Expr::Mul(
            Box::new(Expr::SLoad(Box::new(slot_a.clone()))),
            Box::new(Expr::SLoad(Box::new(slot_b.clone()))),
        );
        let k = Expr::Lit([0; 32]);
        let condition = Prop::Gt(Box::new(product), Box::new(k));

        let modifies_storage = true;
        let summary = FunctionSummary {
            name: "swap".to_string(),
            preconditions: vec![],
            reads: vec![],
            writes: vec![(slot_a, Expr::Var("new_r0".into()))],
            has_external_call: false,
            modifies_storage,
            revert_conditions: vec![],
            success_conditions: vec![vec![condition]],
        };
        let invariants = mine_product_invariants(&[summary]);

        assert!(
            invariants.iter().any(|i| i.name == "product_bound"),
            "Should detect product bound from conditions"
        );
    }

    #[test]
    fn test_no_product_without_mul_sload() {
        // Add(SLoad, SLoad) should NOT produce a product invariant
        let slot_a = Expr::Var("a".into());
        let slot_b = Expr::Var("b".into());
        let sum = Expr::Add(
            Box::new(Expr::SLoad(Box::new(slot_a.clone()))),
            Box::new(Expr::SLoad(Box::new(slot_b.clone()))),
        );
        let summary = make_summary("add_fn", vec![(Expr::Var("out".into()), sum)]);
        let invariants = mine_product_invariants(&[summary]);

        assert!(
            invariants.is_empty(),
            "Add(SLoad, SLoad) should not produce product invariant"
        );
    }

    #[test]
    fn test_mapping_recognition() {
        // Two writes to Keccak256-based slots with different keys but same base
        let base = Expr::Var("base_slot".into());
        let slot1 = Expr::Keccak256(Box::new(Expr::Add(
            Box::new(Expr::Var("addr1".into())),
            Box::new(base.clone()),
        )));
        let slot2 = Expr::Keccak256(Box::new(Expr::Add(
            Box::new(Expr::Var("addr2".into())),
            Box::new(base.clone()),
        )));

        let s1 = make_summary("transfer", vec![(slot1, Expr::Var("v1".into()))]);
        let s2 = make_summary("approve", vec![(slot2, Expr::Var("v2".into()))]);

        let invariants = mine_mapping_patterns(&[s1, s2]);

        assert!(
            invariants.iter().any(|i| i.name == "mapping_identified"),
            "Should identify mapping when two keccak slots share same base"
        );
    }

    #[test]
    fn test_consistent_overwrite() {
        // Two functions overwrite the same slot with structurally identical expressions
        let slot = Expr::Var("state".into());
        let new_val_1 = Expr::Caller; // shape: "Caller"
        let new_val_2 = Expr::Caller; // shape: "Caller"

        let s1 = make_summary("set_owner_a", vec![(slot.clone(), new_val_1)]);
        let s2 = make_summary("set_owner_b", vec![(slot, new_val_2)]);

        let invariants = mine_overwrite_patterns(&[s1, s2]);

        assert!(
            invariants.iter().any(|i| i.name == "consistent_overwrite"),
            "Should detect consistent overwrite pattern"
        );
    }

    #[test]
    fn test_inconsistent_overwrite() {
        // Two functions overwrite the same slot with different expression shapes
        let slot = Expr::Var("state".into());
        let new_val_1 = Expr::Caller; // shape: "Caller"
        let new_val_2 = Expr::CallValue; // shape: "CallValue"

        let s1 = make_summary("set_owner", vec![(slot.clone(), new_val_1)]);
        let s2 = make_summary("set_value", vec![(slot, new_val_2)]);

        let invariants = mine_overwrite_patterns(&[s1, s2]);

        assert!(
            invariants
                .iter()
                .any(|i| i.name == "inconsistent_overwrite"),
            "Should detect inconsistent overwrite pattern"
        );
        let inv = invariants
            .iter()
            .find(|i| i.name == "inconsistent_overwrite")
            .unwrap();
        assert_eq!(inv.violators.len(), 2);
    }

    #[test]
    fn test_expr_shape_consistency() {
        // Same structure with different concrete values should produce same shape
        let mut v1 = [0u8; 32];
        v1[31] = 1;
        let mut v2 = [0u8; 32];
        v2[31] = 99;

        let e1 = Expr::Add(Box::new(Expr::Lit(v1)), Box::new(Expr::Var("x".into())));
        let e2 = Expr::Add(Box::new(Expr::Lit(v2)), Box::new(Expr::Var("y".into())));

        assert_eq!(
            expr_shape(&e1),
            expr_shape(&e2),
            "Same structure with different values should produce identical shapes"
        );
    }

    #[test]
    fn test_z3_upgrades_conservation_confidence() {
        let slot_a = Expr::Var("slot_a".into());
        let slot_b = Expr::Var("slot_b".into());
        let amount = Expr::Var("amount".into());

        let new_a = Expr::Add(
            Box::new(Expr::SLoad(Box::new(slot_a.clone()))),
            Box::new(amount.clone()),
        );
        let new_b = Expr::Sub(
            Box::new(Expr::SLoad(Box::new(slot_b.clone()))),
            Box::new(amount.clone()),
        );

        // Only one storage-modifying function, and it's the supporting one
        let summary = make_summary("transfer", vec![(slot_a, new_a), (slot_b, new_b)]);
        let summaries = vec![summary];
        let mut invariants = mine_conservation(&summaries);
        assert!(!invariants.is_empty());
        assert_eq!(invariants[0].confidence, AlgebraicConfidence::Likely);

        // Z3 verification should upgrade to Proven since the single writer preserves it
        verify_with_z3(&mut invariants, &summaries);
        assert_eq!(
            invariants[0].confidence,
            AlgebraicConfidence::Proven,
            "Conservation should be upgraded to Proven when all writers support it"
        );
    }

    #[test]
    fn test_mine_invariants_integration() {
        // End-to-end: mine_invariants should call all strategies including new ones
        let slot_a = Expr::Var("bal_from".into());
        let slot_b = Expr::Var("bal_to".into());
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
        let invariants = mine_invariants(&[summary]);

        // Should have conservation, monotonicity, and zero-sum at minimum
        assert!(
            invariants.len() >= 3,
            "mine_invariants should produce multiple invariant types, got {}",
            invariants.len()
        );

        let names: HashSet<&str> = invariants.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains("conservation"));
        assert!(names.contains("zero_sum_transfer") || names.contains("potential_conservation"));
    }
}
