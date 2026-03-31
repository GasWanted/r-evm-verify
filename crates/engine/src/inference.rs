use r_evm_verify_lifter::ir::{Expr, Prop};
use r_evm_verify_svm::summary::FunctionSummary;
use std::collections::{HashMap, HashSet};

/// An automatically inferred invariant.
#[derive(Debug, Clone)]
pub struct InferredInvariant {
    pub name: String,
    pub description: String,
    pub confidence: Confidence,
    /// Functions that could potentially violate this invariant.
    pub potential_violators: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,   // Invariant holds across all observed paths
    Medium, // Invariant holds for most paths, some exceptions
    Low,    // Candidate only -- limited evidence
}

/// Infer invariants from function summaries.
pub fn infer_invariants(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    invariants.extend(infer_write_exclusivity(summaries));
    invariants.extend(infer_guarded_mutations(summaries));
    invariants.extend(infer_no_unprotected_value_transfer(summaries));
    invariants.extend(infer_paired_operations(summaries));
    invariants.extend(infer_storage_slot_patterns(summaries));

    // Advanced strategies for economic/logic bug detection
    invariants.extend(infer_slot_correlation(summaries));
    invariants.extend(infer_value_flow(summaries));
    invariants.extend(infer_cei_violation(summaries));
    invariants.extend(infer_privilege_escalation(summaries));
    invariants.extend(infer_flash_loan_risk(summaries));
    invariants.extend(infer_dead_functions(summaries));

    invariants
}

/// Invariant: certain storage slots are only written by specific functions.
/// If slot X is only ever written by function "withdraw", then any other
/// function writing to X is suspicious.
fn infer_write_exclusivity(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    // Build map: slot expression (stringified) -> set of functions that write to it
    let mut slot_writers: HashMap<String, Vec<String>> = HashMap::new();

    for summary in summaries {
        for (slot, _value) in &summary.writes {
            let slot_key = format!("{:?}", slot);
            slot_writers
                .entry(slot_key)
                .or_default()
                .push(summary.name.clone());
        }
    }

    let mut invariants = Vec::new();

    // Find slots written by only 1 function -- these are likely access-controlled
    for (slot_key, writers) in &slot_writers {
        let unique_writers: HashSet<&String> = writers.iter().collect();
        if unique_writers.len() == 1 {
            let writer = unique_writers.into_iter().next().unwrap();
            invariants.push(InferredInvariant {
                name: "exclusive_write".to_string(),
                description: format!(
                    "Storage slot {} is only written by {}. Any other writer is suspicious.",
                    truncate_slot(slot_key),
                    writer
                ),
                confidence: Confidence::High,
                potential_violators: vec![],
            });
        }
    }

    invariants
}

/// Invariant: storage mutations that are always guarded by caller checks.
/// If function X always has a caller constraint when it writes to storage,
/// then that is an access control invariant.
fn infer_guarded_mutations(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        if !summary.modifies_storage {
            continue;
        }

        // Check if ALL success paths have caller-dependent constraints
        let all_paths_check_caller = !summary.success_conditions.is_empty()
            && summary
                .success_conditions
                .iter()
                .all(|conditions| conditions.iter().any(|prop| prop_references_caller(prop)));

        if all_paths_check_caller {
            invariants.push(InferredInvariant {
                name: "caller_guarded".to_string(),
                description: format!(
                    "{} always checks msg.sender before modifying storage. \
                     This is an access control invariant.",
                    summary.name
                ),
                confidence: Confidence::High,
                potential_violators: vec![],
            });
        }

        // Check if function has BOTH guarded and unguarded paths (partial access control)
        let some_paths_check = summary
            .success_conditions
            .iter()
            .any(|conditions| conditions.iter().any(|prop| prop_references_caller(prop)));
        let some_paths_dont = summary
            .success_conditions
            .iter()
            .any(|conditions| !conditions.iter().any(|prop| prop_references_caller(prop)));

        if some_paths_check && some_paths_dont {
            invariants.push(InferredInvariant {
                name: "partial_access_control".to_string(),
                description: format!(
                    "{} has some paths that check msg.sender and some that don't. \
                     Potential access control bypass.",
                    summary.name
                ),
                confidence: Confidence::Medium,
                potential_violators: vec![summary.name.clone()],
            });
        }
    }

    invariants
}

/// Invariant: no function should make external calls without access control.
fn infer_no_unprotected_value_transfer(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        if !summary.has_external_call {
            continue;
        }

        let has_caller_guard = summary
            .success_conditions
            .iter()
            .any(|conditions| conditions.iter().any(|prop| prop_references_caller(prop)));

        let has_revert_on_unauthorized = summary
            .revert_conditions
            .iter()
            .any(|conditions| conditions.iter().any(|prop| prop_references_caller(prop)));

        if !has_caller_guard && !has_revert_on_unauthorized {
            invariants.push(InferredInvariant {
                name: "unprotected_external_call".to_string(),
                description: format!(
                    "{} makes external calls without any msg.sender check. \
                     Potential unauthorized access.",
                    summary.name
                ),
                confidence: Confidence::High,
                potential_violators: vec![summary.name.clone()],
            });
        }
    }

    invariants
}

/// Invariant: functions that write to the same storage slots should have
/// consistent preconditions (they are likely related operations).
fn infer_paired_operations(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    // Find functions that write to the same slots
    let mut slot_writers: HashMap<String, Vec<&FunctionSummary>> = HashMap::new();
    for summary in summaries {
        for (slot, _) in &summary.writes {
            let key = format!("{:?}", slot);
            slot_writers.entry(key).or_default().push(summary);
        }
    }

    for (slot_key, writers) in &slot_writers {
        if writers.len() < 2 {
            continue;
        }

        // Check if some writers have access control and others don't
        let guarded: Vec<_> = writers
            .iter()
            .filter(|w| {
                w.success_conditions
                    .iter()
                    .any(|c| c.iter().any(|p| prop_references_caller(p)))
                    || w.revert_conditions
                        .iter()
                        .any(|c| c.iter().any(|p| prop_references_caller(p)))
            })
            .collect();

        let unguarded: Vec<_> = writers
            .iter()
            .filter(|w| {
                !w.success_conditions
                    .iter()
                    .any(|c| c.iter().any(|p| prop_references_caller(p)))
                    && !w
                        .revert_conditions
                        .iter()
                        .any(|c| c.iter().any(|p| prop_references_caller(p)))
            })
            .collect();

        if !guarded.is_empty() && !unguarded.is_empty() {
            invariants.push(InferredInvariant {
                name: "inconsistent_access_control".to_string(),
                description: format!(
                    "Storage slot {} is written by both access-controlled functions ({}) \
                     and uncontrolled functions ({}). The uncontrolled writers may be a vulnerability.",
                    truncate_slot(slot_key),
                    guarded
                        .iter()
                        .map(|w| w.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    unguarded
                        .iter()
                        .map(|w| w.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                confidence: Confidence::High,
                potential_violators: unguarded.iter().map(|w| w.name.clone()).collect(),
            });
        }
    }

    invariants
}

/// Invariant: detect common storage patterns.
/// - Functions that only read storage (view functions) should be safe
/// - Functions that write without reading first may be initializers
fn infer_storage_slot_patterns(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    let total_functions = summaries.len();
    let state_changing = summaries.iter().filter(|s| s.modifies_storage).count();
    let with_external_calls = summaries.iter().filter(|s| s.has_external_call).count();
    let with_both = summaries
        .iter()
        .filter(|s| s.modifies_storage && s.has_external_call)
        .count();

    invariants.push(InferredInvariant {
        name: "contract_profile".to_string(),
        description: format!(
            "Contract has {} functions: {} modify storage, {} make external calls, {} do both. \
             Functions that both modify storage and make external calls are highest risk.",
            total_functions, state_changing, with_external_calls, with_both
        ),
        confidence: Confidence::High,
        potential_violators: summaries
            .iter()
            .filter(|s| s.modifies_storage && s.has_external_call)
            .map(|s| s.name.clone())
            .collect(),
    });

    // Flag functions with many success paths (complex logic = higher risk)
    for summary in summaries {
        if summary.success_conditions.len() > 10 {
            invariants.push(InferredInvariant {
                name: "complex_function".to_string(),
                description: format!(
                    "{} has {} distinct execution paths. \
                     High complexity increases risk of logic errors.",
                    summary.name,
                    summary.success_conditions.len()
                ),
                confidence: Confidence::Low,
                potential_violators: vec![summary.name.clone()],
            });
        }
    }

    invariants
}

/// Detect correlated storage slots — slots that always change together.
/// If slot A and B always change in the same function, any function
/// changing A without B (or vice versa) may break a conservation invariant.
fn infer_slot_correlation(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    // Build map: which slots does each function write?
    let mut func_slots: HashMap<String, HashSet<String>> = HashMap::new();
    for summary in summaries {
        let slots: HashSet<String> = summary
            .writes
            .iter()
            .map(|(slot, _)| format!("{:?}", slot))
            .collect();
        if !slots.is_empty() {
            func_slots.insert(summary.name.clone(), slots);
        }
    }

    // Find slot pairs that appear together in multiple functions
    let mut pair_counts: HashMap<(String, String), usize> = HashMap::new();
    let mut slot_total_appearances: HashMap<String, usize> = HashMap::new();

    for (_func, slots) in &func_slots {
        let slot_vec: Vec<&String> = slots.iter().collect();
        for slot in &slot_vec {
            *slot_total_appearances.entry((*slot).clone()).or_insert(0) += 1;
        }
        for i in 0..slot_vec.len() {
            for j in (i + 1)..slot_vec.len() {
                let pair = if slot_vec[i] < slot_vec[j] {
                    (slot_vec[i].clone(), slot_vec[j].clone())
                } else {
                    (slot_vec[j].clone(), slot_vec[i].clone())
                };
                *pair_counts.entry(pair).or_insert(0) += 1;
            }
        }
    }

    // For pairs that ALWAYS appear together, check if any function breaks the pattern
    for ((slot_a, slot_b), count) in &pair_counts {
        let a_total = slot_total_appearances.get(slot_a).copied().unwrap_or(0);
        let b_total = slot_total_appearances.get(slot_b).copied().unwrap_or(0);

        // If they appear together most of the time but sometimes one changes without the other
        if *count >= 2 && (a_total > *count || b_total > *count) {
            let violators: Vec<String> = func_slots
                .iter()
                .filter(|(_, slots)| {
                    let has_a = slots.contains(slot_a);
                    let has_b = slots.contains(slot_b);
                    (has_a && !has_b) || (!has_a && has_b)
                })
                .map(|(name, _)| name.clone())
                .collect();

            if !violators.is_empty() {
                invariants.push(InferredInvariant {
                    name: "broken_slot_correlation".to_string(),
                    description: format!(
                        "Slots {} and {} usually change together ({} times), but {} change only one. Possible conservation invariant violation.",
                        truncate_slot(slot_a),
                        truncate_slot(slot_b),
                        count,
                        violators.join(", ")
                    ),
                    confidence: Confidence::Medium,
                    potential_violators: violators,
                });
            }
        }
    }

    invariants
}

/// Detect value flow asymmetry: functions that send ETH without reading
/// the same storage slots that receiving functions write to.
fn infer_value_flow(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    // Functions that write storage (potential "deposit" functions)
    let depositors: Vec<&FunctionSummary> = summaries
        .iter()
        .filter(|s| s.modifies_storage && !s.has_external_call)
        .collect();

    // Functions that make external calls (potential "withdraw" functions)
    let withdrawers: Vec<&FunctionSummary> =
        summaries.iter().filter(|s| s.has_external_call).collect();

    // Get slots written by depositors
    let deposit_slots: HashSet<String> = depositors
        .iter()
        .flat_map(|s| s.writes.iter().map(|(slot, _)| format!("{:?}", slot)))
        .collect();

    // Check: do withdrawers read/write the same slots?
    for w in &withdrawers {
        let w_slots: HashSet<String> = w
            .writes
            .iter()
            .map(|(slot, _)| format!("{:?}", slot))
            .collect();

        let overlap = deposit_slots.intersection(&w_slots).count();

        if overlap == 0 && !deposit_slots.is_empty() {
            invariants.push(InferredInvariant {
                name: "disconnected_value_flow".to_string(),
                description: format!(
                    "{} makes external calls but writes to NONE of the same storage slots as deposit functions. Funds may flow out without proper accounting.",
                    w.name
                ),
                confidence: Confidence::Medium,
                potential_violators: vec![w.name.clone()],
            });
        }
    }

    invariants
}

/// Detect precise CEI violations by analyzing operation ordering per slot.
fn infer_cei_violation(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        if !summary.has_external_call || !summary.modifies_storage {
            continue;
        }

        // This function both calls out AND modifies storage.
        // Without precise ordering info (which our summaries don't have),
        // flag it as a CEI risk. But give higher confidence if there's
        // no caller guard (unprotected CEI violation is worse).
        let has_guard = summary
            .success_conditions
            .iter()
            .any(|c| c.iter().any(|p| prop_references_caller(p)))
            || summary
                .revert_conditions
                .iter()
                .any(|c| c.iter().any(|p| prop_references_caller(p)));

        if !has_guard {
            invariants.push(InferredInvariant {
                name: "unguarded_cei_violation".to_string(),
                description: format!(
                    "{} modifies storage AND makes external calls WITHOUT access control. High-risk reentrancy vector — anyone can trigger the external call.",
                    summary.name
                ),
                confidence: Confidence::High,
                potential_violators: vec![summary.name.clone()],
            });
        }
    }

    invariants
}

/// Detect potential privilege escalation: functions that write to
/// slots that appear in access control checks.
fn infer_privilege_escalation(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    // Collect slots that appear in caller-dependent revert conditions.
    // These are likely access control storage (owner, roles, etc.)
    let mut access_control_slots: HashSet<String> = HashSet::new();

    for summary in summaries {
        for conditions in &summary.revert_conditions {
            if conditions.iter().any(|p| prop_references_caller(p)) {
                // This revert path checks caller — find any SLOAD in the conditions
                for prop in conditions {
                    collect_sload_slots(prop, &mut access_control_slots);
                }
            }
        }
    }

    if access_control_slots.is_empty() {
        return invariants;
    }

    // Now check: does any function write to these access control slots?
    for summary in summaries {
        for (slot, _) in &summary.writes {
            let slot_key = format!("{:?}", slot);
            if access_control_slots.contains(&slot_key) {
                // This function writes to an access control slot
                let has_strong_guard = summary
                    .revert_conditions
                    .iter()
                    .any(|c| c.iter().any(|p| prop_references_caller(p)));

                if !has_strong_guard {
                    invariants.push(InferredInvariant {
                        name: "privilege_escalation".to_string(),
                        description: format!(
                            "{} can modify access control storage without authorization. Potential ownership takeover.",
                            summary.name
                        ),
                        confidence: Confidence::High,
                        potential_violators: vec![summary.name.clone()],
                    });
                }
            }
        }
    }

    invariants
}

fn collect_sload_slots(prop: &Prop, slots: &mut HashSet<String>) {
    match prop {
        Prop::IsTrue(e) | Prop::IsZero(e) => collect_sload_slots_expr(e, slots),
        Prop::Eq(a, b) | Prop::Lt(a, b) | Prop::Gt(a, b) => {
            collect_sload_slots_expr(a, slots);
            collect_sload_slots_expr(b, slots);
        }
        Prop::And(a, b) | Prop::Or(a, b) => {
            collect_sload_slots(a, slots);
            collect_sload_slots(b, slots);
        }
        Prop::Not(a) => collect_sload_slots(a, slots),
        Prop::Bool(_) => {}
    }
}

fn collect_sload_slots_expr(expr: &Expr, slots: &mut HashSet<String>) {
    match expr {
        Expr::SLoad(slot) => {
            slots.insert(format!("{:?}", slot));
        }

        // Binary ops
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::SDiv(a, b)
        | Expr::Mod(a, b)
        | Expr::SMod(a, b)
        | Expr::Exp(a, b)
        | Expr::Lt(a, b)
        | Expr::Gt(a, b)
        | Expr::SLt(a, b)
        | Expr::SGt(a, b)
        | Expr::Eq(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Shr(a, b)
        | Expr::Sar(a, b) => {
            collect_sload_slots_expr(a, slots);
            collect_sload_slots_expr(b, slots);
        }

        // Ternary ops
        Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
            collect_sload_slots_expr(a, slots);
            collect_sload_slots_expr(b, slots);
            collect_sload_slots_expr(c, slots);
        }

        // Unary ops
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::Keccak256(a)
        | Expr::MLoad(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => {
            collect_sload_slots_expr(a, slots);
        }

        // Conditional
        Expr::Ite(cond, t, f) => {
            collect_sload_slots(cond, slots);
            collect_sload_slots_expr(t, slots);
            collect_sload_slots_expr(f, slots);
        }

        // Leaves that don't contain sub-expressions
        Expr::Lit(_)
        | Expr::Var(_)
        | Expr::Caller
        | Expr::CallValue
        | Expr::CallDataSize
        | Expr::Address
        | Expr::Origin
        | Expr::GasPrice
        | Expr::Coinbase
        | Expr::Timestamp
        | Expr::Number
        | Expr::GasLimit
        | Expr::ChainId => {}
    }
}

/// Detect flash loan receiver patterns: functions with callback-like behavior
/// that both receive and send external calls.
fn infer_flash_loan_risk(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    // Functions with many success paths AND external calls AND storage modifications
    // are likely complex financial operations (flash loan receivers, liquidation, etc.)
    for summary in summaries {
        if summary.has_external_call
            && summary.modifies_storage
            && summary.success_conditions.len() > 3
        {
            let has_guard = summary
                .revert_conditions
                .iter()
                .any(|c| c.iter().any(|p| prop_references_caller(p)));

            invariants.push(InferredInvariant {
                name: "complex_financial_operation".to_string(),
                description: format!(
                    "{} is a complex function ({} paths) with external calls and storage modifications. \
                     {}. Potential flash loan or arbitrage attack surface.",
                    summary.name,
                    summary.success_conditions.len(),
                    if has_guard {
                        "Has caller check"
                    } else {
                        "NO caller check — HIGH RISK"
                    }
                ),
                confidence: if has_guard {
                    Confidence::Low
                } else {
                    Confidence::High
                },
                potential_violators: if has_guard {
                    vec![]
                } else {
                    vec![summary.name.clone()]
                },
            });
        }
    }

    invariants
}

/// Detect functions that always revert (dead code or broken logic).
fn infer_dead_functions(summaries: &[FunctionSummary]) -> Vec<InferredInvariant> {
    let mut invariants = Vec::new();

    for summary in summaries {
        if summary.success_conditions.is_empty() && !summary.revert_conditions.is_empty() {
            invariants.push(InferredInvariant {
                name: "always_reverts".to_string(),
                description: format!(
                    "{} appears to always revert ({} revert paths, 0 success paths). \
                     Either intentionally disabled or has a logic error preventing normal execution.",
                    summary.name,
                    summary.revert_conditions.len()
                ),
                confidence: Confidence::Medium,
                potential_violators: vec![summary.name.clone()],
            });
        }

        // Also flag functions with no paths at all (unreachable or timeout)
        if summary.success_conditions.is_empty()
            && summary.revert_conditions.is_empty()
            && summary.modifies_storage
        {
            invariants.push(InferredInvariant {
                name: "unreachable_function".to_string(),
                description: format!(
                    "{} has no explored execution paths but is expected to modify storage. \
                     May be unreachable or too complex to analyze.",
                    summary.name
                ),
                confidence: Confidence::Low,
                potential_violators: vec![summary.name.clone()],
            });
        }
    }

    invariants
}

fn prop_references_caller(prop: &Prop) -> bool {
    match prop {
        Prop::Bool(_) => false,
        Prop::IsTrue(e) | Prop::IsZero(e) => expr_references_caller(e),
        Prop::Eq(a, b) | Prop::Lt(a, b) | Prop::Gt(a, b) => {
            expr_references_caller(a) || expr_references_caller(b)
        }
        Prop::And(a, b) | Prop::Or(a, b) => prop_references_caller(a) || prop_references_caller(b),
        Prop::Not(a) => prop_references_caller(a),
    }
}

fn expr_references_caller(expr: &Expr) -> bool {
    match expr {
        Expr::Caller => true,

        // Binary ops
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::SDiv(a, b)
        | Expr::Mod(a, b)
        | Expr::SMod(a, b)
        | Expr::Exp(a, b)
        | Expr::Lt(a, b)
        | Expr::Gt(a, b)
        | Expr::SLt(a, b)
        | Expr::SGt(a, b)
        | Expr::Eq(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Shr(a, b)
        | Expr::Sar(a, b) => expr_references_caller(a) || expr_references_caller(b),

        // Ternary ops
        Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
            expr_references_caller(a) || expr_references_caller(b) || expr_references_caller(c)
        }

        // Unary ops
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::SLoad(a)
        | Expr::Keccak256(a)
        | Expr::MLoad(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => expr_references_caller(a),

        // Conditional
        Expr::Ite(cond, t, f) => {
            prop_references_caller(cond) || expr_references_caller(t) || expr_references_caller(f)
        }

        // Leaves that don't reference caller
        Expr::Lit(_)
        | Expr::Var(_)
        | Expr::CallValue
        | Expr::CallDataSize
        | Expr::Address
        | Expr::Origin
        | Expr::GasPrice
        | Expr::Coinbase
        | Expr::Timestamp
        | Expr::Number
        | Expr::GasLimit
        | Expr::ChainId => false,
    }
}

fn truncate_slot(slot_key: &str) -> String {
    if slot_key.len() > 40 {
        format!("{}...", &slot_key[..37])
    } else {
        slot_key.to_string()
    }
}

/// Format inferred invariants for display.
pub fn format_inferred_invariants(invariants: &[InferredInvariant]) -> String {
    let mut out = String::new();

    let high = invariants
        .iter()
        .filter(|i| i.confidence == Confidence::High)
        .count();
    let medium = invariants
        .iter()
        .filter(|i| i.confidence == Confidence::Medium)
        .count();
    let low = invariants
        .iter()
        .filter(|i| i.confidence == Confidence::Low)
        .count();
    let with_violators: Vec<_> = invariants
        .iter()
        .filter(|i| !i.potential_violators.is_empty())
        .collect();

    out.push_str(&format!(
        "Inferred {} invariants ({} high, {} medium, {} low confidence)\n",
        invariants.len(),
        high,
        medium,
        low
    ));
    out.push_str(&format!(
        "{} potential issues found\n\n",
        with_violators.len()
    ));

    // Show potential issues first
    if !with_violators.is_empty() {
        out.push_str("=== Potential Issues ===\n\n");
        for inv in &with_violators {
            let conf = match inv.confidence {
                Confidence::High => "HIGH",
                Confidence::Medium => "MED",
                Confidence::Low => "LOW",
            };
            out.push_str(&format!("  [{}] {}\n", conf, inv.name));
            out.push_str(&format!("    {}\n", inv.description));
            out.push_str(&format!(
                "    Suspects: {}\n\n",
                inv.potential_violators.join(", ")
            ));
        }
    }

    // Then show confirmed invariants (no violators)
    let confirmed: Vec<_> = invariants
        .iter()
        .filter(|i| i.potential_violators.is_empty())
        .collect();
    if !confirmed.is_empty() {
        out.push_str("=== Confirmed Properties ===\n\n");
        for inv in &confirmed {
            out.push_str(&format!(
                "  [{}] {}\n",
                match inv.confidence {
                    Confidence::High => "OK",
                    Confidence::Medium => "~",
                    Confidence::Low => "?",
                },
                inv.description
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_evm_verify_lifter::ir::{Expr, Prop};
    use r_evm_verify_svm::summary::FunctionSummary;

    fn make_summary(
        name: &str,
        writes: Vec<(Expr, Expr)>,
        has_external_call: bool,
        success_conditions: Vec<Vec<Prop>>,
        revert_conditions: Vec<Vec<Prop>>,
    ) -> FunctionSummary {
        let modifies_storage = !writes.is_empty();
        FunctionSummary {
            name: name.to_string(),
            preconditions: Vec::new(),
            reads: Vec::new(),
            writes,
            has_external_call,
            modifies_storage,
            revert_conditions,
            success_conditions,
        }
    }

    fn slot_zero() -> Expr {
        Expr::Lit([0; 32])
    }

    fn value_one() -> Expr {
        let mut v = [0u8; 32];
        v[31] = 1;
        Expr::Lit(v)
    }

    fn caller_eq_check() -> Prop {
        Prop::Eq(
            Box::new(Expr::Caller),
            Box::new(Expr::SLoad(Box::new(slot_zero()))),
        )
    }

    #[test]
    fn test_write_exclusivity_single_writer() {
        let summaries = vec![make_summary(
            "withdraw",
            vec![(slot_zero(), value_one())],
            false,
            vec![],
            vec![],
        )];
        let invariants = infer_write_exclusivity(&summaries);
        assert_eq!(invariants.len(), 1);
        assert_eq!(invariants[0].name, "exclusive_write");
        assert!(invariants[0].potential_violators.is_empty());
    }

    #[test]
    fn test_write_exclusivity_multiple_writers() {
        let summaries = vec![
            make_summary(
                "withdraw",
                vec![(slot_zero(), value_one())],
                false,
                vec![],
                vec![],
            ),
            make_summary(
                "deposit",
                vec![(slot_zero(), value_one())],
                false,
                vec![],
                vec![],
            ),
        ];
        let invariants = infer_write_exclusivity(&summaries);
        // Two writers means no exclusive_write invariant
        assert!(invariants.is_empty());
    }

    #[test]
    fn test_guarded_mutations() {
        let summaries = vec![make_summary(
            "setOwner",
            vec![(slot_zero(), value_one())],
            false,
            vec![vec![caller_eq_check()]],
            vec![],
        )];
        let invariants = infer_guarded_mutations(&summaries);
        assert!(invariants.iter().any(|i| i.name == "caller_guarded"));
    }

    #[test]
    fn test_unprotected_external_call() {
        let summaries = vec![make_summary(
            "transfer",
            vec![],
            true,
            vec![vec![Prop::Bool(true)]],
            vec![],
        )];
        let invariants = infer_no_unprotected_value_transfer(&summaries);
        assert_eq!(invariants.len(), 1);
        assert_eq!(invariants[0].name, "unprotected_external_call");
        assert_eq!(invariants[0].potential_violators, vec!["transfer"]);
    }

    #[test]
    fn test_protected_external_call() {
        let summaries = vec![make_summary(
            "transfer",
            vec![],
            true,
            vec![vec![caller_eq_check()]],
            vec![],
        )];
        let invariants = infer_no_unprotected_value_transfer(&summaries);
        assert!(invariants.is_empty());
    }

    #[test]
    fn test_inconsistent_access_control() {
        let summaries = vec![
            make_summary(
                "admin_set",
                vec![(slot_zero(), value_one())],
                false,
                vec![vec![caller_eq_check()]],
                vec![],
            ),
            make_summary(
                "public_set",
                vec![(slot_zero(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
        ];
        let invariants = infer_paired_operations(&summaries);
        assert!(invariants
            .iter()
            .any(|i| i.name == "inconsistent_access_control"));
        let inv = invariants
            .iter()
            .find(|i| i.name == "inconsistent_access_control")
            .unwrap();
        assert!(inv.potential_violators.contains(&"public_set".to_string()));
    }

    #[test]
    fn test_infer_invariants_integration() {
        let summaries = vec![
            make_summary(
                "withdraw",
                vec![(slot_zero(), value_one())],
                true,
                vec![vec![caller_eq_check()]],
                vec![],
            ),
            make_summary(
                "deposit",
                vec![(slot_zero(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
        ];
        let invariants = infer_invariants(&summaries);
        assert!(!invariants.is_empty());

        let output = format_inferred_invariants(&invariants);
        assert!(output.contains("Inferred"));
        assert!(output.contains("invariants"));
    }

    #[test]
    fn test_expr_references_caller() {
        assert!(expr_references_caller(&Expr::Caller));
        assert!(!expr_references_caller(&Expr::CallValue));
        assert!(expr_references_caller(&Expr::Add(
            Box::new(Expr::Caller),
            Box::new(Expr::Lit([0; 32]))
        )));
        assert!(expr_references_caller(&Expr::Keccak256(Box::new(
            Expr::Caller
        ))));
        assert!(!expr_references_caller(&Expr::Keccak256(Box::new(
            Expr::Lit([0; 32])
        ))));
    }

    fn slot_one() -> Expr {
        let mut v = [0u8; 32];
        v[31] = 1;
        Expr::Lit(v)
    }

    fn slot_two() -> Expr {
        let mut v = [0u8; 32];
        v[31] = 2;
        Expr::Lit(v)
    }

    #[test]
    fn test_slot_correlation_violation() {
        // Three functions: two write slots 0+1 together, one writes only slot 0
        let summaries = vec![
            make_summary(
                "transfer",
                vec![(slot_zero(), value_one()), (slot_one(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
            make_summary(
                "transferFrom",
                vec![(slot_zero(), value_one()), (slot_one(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
            make_summary(
                "mint",
                vec![(slot_zero(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
        ];
        let invariants = infer_slot_correlation(&summaries);
        assert!(
            invariants
                .iter()
                .any(|i| i.name == "broken_slot_correlation"),
            "Expected broken_slot_correlation invariant"
        );
        let inv = invariants
            .iter()
            .find(|i| i.name == "broken_slot_correlation")
            .unwrap();
        assert!(inv.potential_violators.contains(&"mint".to_string()));
    }

    #[test]
    fn test_slot_correlation_no_violation() {
        // Two functions both write slots 0+1 — no violation
        let summaries = vec![
            make_summary(
                "transfer",
                vec![(slot_zero(), value_one()), (slot_one(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
            make_summary(
                "transferFrom",
                vec![(slot_zero(), value_one()), (slot_one(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
        ];
        let invariants = infer_slot_correlation(&summaries);
        assert!(
            invariants.is_empty(),
            "No violation expected when all funcs write both slots"
        );
    }

    #[test]
    fn test_value_flow_disconnected() {
        // Deposit writes slot 0, withdraw makes external call but writes slot 1
        let summaries = vec![
            make_summary(
                "deposit",
                vec![(slot_zero(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
            make_summary(
                "withdraw",
                vec![(slot_one(), value_one())],
                true,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
        ];
        let invariants = infer_value_flow(&summaries);
        assert!(invariants
            .iter()
            .any(|i| i.name == "disconnected_value_flow"));
        let inv = invariants
            .iter()
            .find(|i| i.name == "disconnected_value_flow")
            .unwrap();
        assert!(inv.potential_violators.contains(&"withdraw".to_string()));
    }

    #[test]
    fn test_value_flow_connected() {
        // Both deposit and withdraw write to the same slot — OK
        let summaries = vec![
            make_summary(
                "deposit",
                vec![(slot_zero(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
            make_summary(
                "withdraw",
                vec![(slot_zero(), value_one())],
                true,
                vec![vec![Prop::Bool(true)]],
                vec![],
            ),
        ];
        let invariants = infer_value_flow(&summaries);
        assert!(invariants.is_empty());
    }

    #[test]
    fn test_cei_violation_unguarded() {
        // Function modifies storage + external call + no access control
        let summaries = vec![make_summary(
            "withdraw",
            vec![(slot_zero(), value_one())],
            true,
            vec![vec![Prop::Bool(true)]],
            vec![],
        )];
        let invariants = infer_cei_violation(&summaries);
        assert!(invariants
            .iter()
            .any(|i| i.name == "unguarded_cei_violation"));
    }

    #[test]
    fn test_cei_violation_guarded_ok() {
        // Function modifies storage + external call + HAS access control
        let summaries = vec![make_summary(
            "withdraw",
            vec![(slot_zero(), value_one())],
            true,
            vec![vec![caller_eq_check()]],
            vec![],
        )];
        let invariants = infer_cei_violation(&summaries);
        assert!(invariants.is_empty());
    }

    #[test]
    fn test_privilege_escalation() {
        // One function uses caller check on slot 0 (access control).
        // Another function writes to slot 0 WITHOUT caller check.
        let summaries = vec![
            make_summary(
                "protected_fn",
                vec![(slot_one(), value_one())],
                false,
                vec![vec![Prop::Bool(true)]],
                vec![vec![caller_eq_check()]], // reverts if caller != sload(slot0)
            ),
            make_summary(
                "set_owner",
                vec![(slot_zero(), value_one())], // writes to access control slot!
                false,
                vec![vec![Prop::Bool(true)]],
                vec![], // no caller check
            ),
        ];
        let invariants = infer_privilege_escalation(&summaries);
        assert!(invariants.iter().any(|i| i.name == "privilege_escalation"));
        let inv = invariants
            .iter()
            .find(|i| i.name == "privilege_escalation")
            .unwrap();
        assert!(inv.potential_violators.contains(&"set_owner".to_string()));
    }

    #[test]
    fn test_flash_loan_risk() {
        // Complex function with external calls, storage mods, and many paths
        let summaries = vec![make_summary(
            "executeOperation",
            vec![(slot_zero(), value_one())],
            true,
            vec![
                vec![Prop::Bool(true)],
                vec![Prop::Bool(true)],
                vec![Prop::Bool(true)],
                vec![Prop::Bool(true)],
            ],
            vec![],
        )];
        let invariants = infer_flash_loan_risk(&summaries);
        assert!(invariants
            .iter()
            .any(|i| i.name == "complex_financial_operation"));
    }

    #[test]
    fn test_dead_functions_always_reverts() {
        let summaries = vec![make_summary(
            "broken",
            vec![],
            false,
            vec![],                       // no success paths
            vec![vec![Prop::Bool(true)]], // has revert paths
        )];
        let invariants = infer_dead_functions(&summaries);
        assert!(invariants.iter().any(|i| i.name == "always_reverts"));
        assert!(invariants[0]
            .potential_violators
            .contains(&"broken".to_string()));
    }

    #[test]
    fn test_dead_functions_unreachable() {
        let mut summary = make_summary("ghost", vec![], false, vec![], vec![]);
        summary.modifies_storage = true; // manually set since make_summary derives from writes
        let summaries = vec![summary];
        let invariants = infer_dead_functions(&summaries);
        assert!(invariants.iter().any(|i| i.name == "unreachable_function"));
    }

    #[test]
    fn test_collect_sload_slots() {
        let mut slots = HashSet::new();
        let prop = Prop::Eq(
            Box::new(Expr::Caller),
            Box::new(Expr::SLoad(Box::new(slot_zero()))),
        );
        collect_sload_slots(&prop, &mut slots);
        assert_eq!(slots.len(), 1);
        assert!(slots.contains(&format!("{:?}", slot_zero())));
    }
}
