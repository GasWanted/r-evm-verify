use crate::algebraic::extract_deltas;
use r_evm_verify_lifter::ir::Expr;
use r_evm_verify_solver::translate::expr_to_z3;
use r_evm_verify_svm::summary::FunctionSummary;
use z3::ast::{Ast, BV as BitVec};

/// Result of inductive verification for one invariant against one function.
#[derive(Debug, Clone)]
pub struct InductiveResult {
    pub invariant_name: String,
    pub function_name: String,
    pub verified: bool,
    /// If not verified, the Z3 counterexample showing how the function breaks it.
    pub counterexample: Option<String>,
}

/// Inductively verify conservation invariants.
///
/// For each conservation invariant (slot_A + slot_B == constant):
///   For each function that writes to A or B:
///     Prove that if A_pre + B_pre == C, then A_post + B_post == C.
///
/// The method: assert the NEGATION (pre_sum != post_sum).
/// If Z3 returns UNSAT, the negation is impossible, so conservation is PROVEN.
pub fn verify_conservation_inductive(summaries: &[FunctionSummary]) -> Vec<InductiveResult> {
    let mut results = Vec::new();
    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);

    // Find all conservation pairs: functions where two slots have opposite deltas
    for summary in summaries {
        let deltas = extract_deltas(summary);

        for i in 0..deltas.len() {
            for j in (i + 1)..deltas.len() {
                let da = &deltas[i];
                let db = &deltas[j];

                // Both must have extractable deltas
                let (Some(_delta_a), Some(_delta_b)) = (&da.delta, &db.delta) else {
                    continue;
                };

                // Try to verify: pre_A + pre_B == post_A + post_B
                let result = verify_additive_conservation(
                    &ctx,
                    &da.old_value,
                    &da.new_value,
                    &db.old_value,
                    &db.new_value,
                    &summary.name,
                    &da.slot.0,
                    &db.slot.0,
                );
                results.push(result);
            }
        }
    }

    results
}

/// Verify that slot_A + slot_B is conserved by one function's writes.
///
/// Translates the pre- and post-state expressions to Z3 bitvectors, then
/// asserts the negation of conservation (pre_sum != post_sum).
/// UNSAT means conservation is mathematically proven for this function.
fn verify_additive_conservation(
    ctx: &z3::Context,
    old_a: &Expr,
    new_a: &Expr,
    old_b: &Expr,
    new_b: &Expr,
    func_name: &str,
    slot_a_name: &str,
    slot_b_name: &str,
) -> InductiveResult {
    let inv_name = format!("conservation({}, {})", slot_a_name, slot_b_name);

    let solver = z3::Solver::new(ctx);

    // Set timeout to avoid hanging on complex expressions
    let mut params = z3::Params::new(ctx);
    params.set_u32("timeout", 5000);
    solver.set_params(&params);

    // Translate pre-state and post-state expressions to Z3 bitvectors
    let pre_a = match expr_to_z3(ctx, old_a) {
        Ok(bv) => bv,
        Err(e) => {
            return InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(format!("Failed to translate pre_A to Z3: {}", e)),
            };
        }
    };

    let pre_b = match expr_to_z3(ctx, old_b) {
        Ok(bv) => bv,
        Err(e) => {
            return InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(format!("Failed to translate pre_B to Z3: {}", e)),
            };
        }
    };

    let post_a = match expr_to_z3(ctx, new_a) {
        Ok(bv) => bv,
        Err(e) => {
            return InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(format!("Failed to translate post_A to Z3: {}", e)),
            };
        }
    };

    let post_b = match expr_to_z3(ctx, new_b) {
        Ok(bv) => bv,
        Err(e) => {
            return InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(format!("Failed to translate post_B to Z3: {}", e)),
            };
        }
    };

    // Conservation: pre_A + pre_B == post_A + post_B
    // Assert the NEGATION: pre_A + pre_B != post_A + post_B
    // If UNSAT -> the negation is impossible -> conservation is PROVEN
    let pre_sum = pre_a.bvadd(&pre_b);
    let post_sum = post_a.bvadd(&post_b);

    let not_conserved = pre_sum._eq(&post_sum).not();
    solver.assert(&not_conserved);

    match solver.check() {
        z3::SatResult::Unsat => {
            // UNSAT means the negation is impossible -> conservation PROVEN
            InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: true,
                counterexample: None,
            }
        }
        z3::SatResult::Sat => {
            // SAT means there exist inputs that break conservation
            let model_str = solver
                .get_model()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "no model".to_string());
            InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(format!(
                    "Z3 found inputs that break conservation: {}",
                    if model_str.len() > 200 {
                        &model_str[..200]
                    } else {
                        &model_str
                    }
                )),
            }
        }
        z3::SatResult::Unknown => InductiveResult {
            invariant_name: inv_name,
            function_name: func_name.to_string(),
            verified: false,
            counterexample: Some("Z3 returned Unknown (timeout or too complex)".to_string()),
        },
    }
}

/// Verify monotonicity: a slot's post-value is always >= (or <=) its pre-value.
///
/// For each function's delta expression, we check if the delta can ever be
/// "negative" (in unsigned 256-bit arithmetic: >= 2^255). If Z3 returns UNSAT,
/// the delta is always non-negative, proving monotonic increase.
pub fn verify_monotonicity_inductive(summaries: &[FunctionSummary]) -> Vec<InductiveResult> {
    let mut results = Vec::new();
    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);

    for summary in summaries {
        let deltas = extract_deltas(summary);

        for delta in &deltas {
            let Some(delta_expr) = &delta.delta else {
                continue;
            };

            // Check if delta is always non-negative (monotonic increase)
            let result = verify_delta_sign(&ctx, delta_expr, &summary.name, &delta.slot.0);
            results.push(result);
        }
    }

    results
}

/// Verify that a delta expression is always non-negative (monotonic increase).
///
/// In unsigned 256-bit arithmetic, a "negative" delta wraps to a very large number
/// (>= 2^255). We ask Z3 whether such a value is possible. If UNSAT, the delta is
/// provably always non-negative.
fn verify_delta_sign(
    ctx: &z3::Context,
    delta: &Expr,
    func_name: &str,
    slot_name: &str,
) -> InductiveResult {
    let inv_name = format!("monotonic_increase({})", slot_name);

    let solver = z3::Solver::new(ctx);
    let mut params = z3::Params::new(ctx);
    params.set_u32("timeout", 5000);
    solver.set_params(&params);

    let delta_z3 = match expr_to_z3(ctx, delta) {
        Ok(bv) => bv,
        Err(e) => {
            return InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(format!("Failed to translate delta to Z3: {}", e)),
            };
        }
    };

    // Check: is delta ever "negative"?
    // In unsigned 256-bit arithmetic, "negative" means >= 2^255.
    // Build 2^255 as: 1 << 255
    let one = BitVec::from_u64(ctx, 1, 256);
    let shift = BitVec::from_u64(ctx, 255, 256);
    let half = one.bvshl(&shift);
    let is_negative = delta_z3.bvuge(&half); // unsigned >= 2^255 means "negative" in signed

    solver.assert(&is_negative);

    match solver.check() {
        z3::SatResult::Unsat => {
            // Delta is ALWAYS non-negative -> monotonic increase proven
            InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: true,
                counterexample: None,
            }
        }
        z3::SatResult::Sat => {
            // Delta CAN be negative
            InductiveResult {
                invariant_name: inv_name,
                function_name: func_name.to_string(),
                verified: false,
                counterexample: Some(
                    "Delta can be negative -- not monotonically increasing".to_string(),
                ),
            }
        }
        z3::SatResult::Unknown => InductiveResult {
            invariant_name: inv_name,
            function_name: func_name.to_string(),
            verified: false,
            counterexample: Some("Z3 timeout".to_string()),
        },
    }
}

/// Run all inductive verifications and return results.
pub fn run_inductive_verification(summaries: &[FunctionSummary]) -> Vec<InductiveResult> {
    let mut all_results = Vec::new();
    all_results.extend(verify_conservation_inductive(summaries));
    all_results.extend(verify_monotonicity_inductive(summaries));
    all_results
}

/// Format inductive verification results for display.
pub fn format_inductive_results(results: &[InductiveResult]) -> String {
    let mut out = String::new();

    let proven = results.iter().filter(|r| r.verified).count();
    let failed = results.len() - proven;

    out.push_str(&format!(
        "\n=== Inductive Z3 Verification ===\n{} checks: {} PROVEN, {} failed/unknown\n\n",
        results.len(),
        proven,
        failed
    ));

    // Show proven first
    for r in results.iter().filter(|r| r.verified) {
        out.push_str(&format!(
            "  [PROVEN] {} preserved by {}\n",
            r.invariant_name, r.function_name
        ));
    }

    // Then failures
    for r in results.iter().filter(|r| !r.verified) {
        out.push_str(&format!(
            "  [FAILED] {} in {}: {}\n",
            r.invariant_name,
            r.function_name,
            r.counterexample.as_deref().unwrap_or("unknown reason")
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_evm_verify_lifter::ir::Expr;
    use r_evm_verify_svm::summary::FunctionSummary;

    fn make_u256(val: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let val_bytes = val.to_be_bytes();
        bytes[24..32].copy_from_slice(&val_bytes);
        bytes
    }

    fn slot_lit(n: u64) -> Expr {
        Expr::Lit(make_u256(n))
    }

    /// A transfer function: slot 0 gets old - amount, slot 1 gets old + amount.
    /// Conservation should be PROVEN.
    #[test]
    fn test_conservation_proven_for_transfer() {
        let slot0 = slot_lit(0);
        let slot1 = slot_lit(1);
        let amount = Expr::Var("amount".into());

        let summary = FunctionSummary {
            name: "transfer".to_string(),
            preconditions: vec![],
            reads: vec![],
            writes: vec![
                (
                    slot0.clone(),
                    Expr::Sub(
                        Box::new(Expr::SLoad(Box::new(slot0.clone()))),
                        Box::new(amount.clone()),
                    ),
                ),
                (
                    slot1.clone(),
                    Expr::Add(
                        Box::new(Expr::SLoad(Box::new(slot1.clone()))),
                        Box::new(amount.clone()),
                    ),
                ),
            ],
            has_external_call: false,
            modifies_storage: true,
            revert_conditions: vec![],
            success_conditions: vec![],
        };

        let results = verify_conservation_inductive(&[summary]);
        assert!(
            !results.is_empty(),
            "Expected at least one conservation result"
        );

        let proven_count = results.iter().filter(|r| r.verified).count();
        assert!(
            proven_count > 0,
            "Expected at least one PROVEN conservation, got: {:?}",
            results
        );
    }

    /// A function that adds to both slots by unrelated amounts should NOT be proven.
    #[test]
    fn test_conservation_fails_for_unbalanced_writes() {
        let slot0 = slot_lit(0);
        let slot1 = slot_lit(1);
        let amount_a = Expr::Var("amount_a".into());
        let amount_b = Expr::Var("amount_b".into());

        let summary = FunctionSummary {
            name: "unbalanced".to_string(),
            preconditions: vec![],
            reads: vec![],
            writes: vec![
                (
                    slot0.clone(),
                    Expr::Add(
                        Box::new(Expr::SLoad(Box::new(slot0.clone()))),
                        Box::new(amount_a),
                    ),
                ),
                (
                    slot1.clone(),
                    Expr::Add(
                        Box::new(Expr::SLoad(Box::new(slot1.clone()))),
                        Box::new(amount_b),
                    ),
                ),
            ],
            has_external_call: false,
            modifies_storage: true,
            revert_conditions: vec![],
            success_conditions: vec![],
        };

        let results = verify_conservation_inductive(&[summary]);
        assert!(!results.is_empty());

        // The conservation check should FAIL (SAT = counterexample found)
        let proven_count = results.iter().filter(|r| r.verified).count();
        assert_eq!(
            proven_count, 0,
            "Unbalanced writes should not be proven conserved"
        );
    }

    /// Monotonicity: a constant positive delta should be proven.
    #[test]
    fn test_monotonicity_proven_for_constant_increment() {
        let slot0 = slot_lit(0);

        let summary = FunctionSummary {
            name: "increment".to_string(),
            preconditions: vec![],
            reads: vec![],
            writes: vec![(
                slot0.clone(),
                Expr::Add(
                    Box::new(Expr::SLoad(Box::new(slot0.clone()))),
                    Box::new(Expr::Lit(make_u256(1))),
                ),
            )],
            has_external_call: false,
            modifies_storage: true,
            revert_conditions: vec![],
            success_conditions: vec![],
        };

        let results = verify_monotonicity_inductive(&[summary]);
        assert!(!results.is_empty());

        let proven = results.iter().filter(|r| r.verified).count();
        assert!(
            proven > 0,
            "Constant increment should be proven monotonically increasing"
        );
    }
}
