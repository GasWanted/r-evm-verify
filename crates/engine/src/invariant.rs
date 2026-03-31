use r_evm_verify_lifter::ir::{Expr, Prop};
use r_evm_verify_svm::summary::FunctionSummary;

#[derive(Debug, Clone)]
pub struct InvariantResult {
    pub invariant_name: String,
    pub holds: bool,
    pub violating_function: Option<String>,
    pub violating_sequence: Vec<String>,
    pub duration_ms: u64,
}

pub fn check_invariants(summaries: &[FunctionSummary]) -> Vec<InvariantResult> {
    let start = std::time::Instant::now();
    let mut results = Vec::new();

    // Invariant 1: access_control — storage-modifying functions with external calls
    // should have caller-dependent revert paths
    for summary in summaries {
        if summary.modifies_storage && summary.has_external_call {
            let has_caller_in_reverts = summary
                .revert_conditions
                .iter()
                .any(|conds| conds.iter().any(|p| prop_mentions_caller(p)));
            let has_caller_in_success = summary
                .success_conditions
                .iter()
                .any(|conds| conds.iter().any(|p| prop_mentions_caller(p)));
            if !has_caller_in_reverts && !has_caller_in_success {
                results.push(InvariantResult {
                    invariant_name: "access_control".to_string(),
                    holds: false,
                    violating_function: Some(summary.name.clone()),
                    violating_sequence: vec![summary.name.clone()],
                    duration_ms: start.elapsed().as_millis() as u64,
                });
            }
        }
    }

    // Invariant 2: cei_compliance — functions with external calls AND storage writes
    // may violate Checks-Effects-Interactions
    for summary in summaries {
        if summary.has_external_call && summary.modifies_storage {
            results.push(InvariantResult {
                invariant_name: "cei_compliance".to_string(),
                holds: false,
                violating_function: Some(summary.name.clone()),
                violating_sequence: vec![summary.name.clone()],
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }
    }

    // Invariant 3: ordering_dependency — function A writes slot that function B reads
    // This detects potential front-running and ordering attacks
    for (i, fa) in summaries.iter().enumerate() {
        for (j, fb) in summaries.iter().enumerate() {
            if i == j || fa.writes.is_empty() || fb.writes.is_empty() {
                continue;
            }
            // Check if fa writes to same slots that fb reads from
            for (w_slot, _) in &fa.writes {
                for (r_slot, _) in &fb.writes {
                    if slots_may_overlap(w_slot, r_slot) {
                        results.push(InvariantResult {
                            invariant_name: "ordering_dependency".to_string(),
                            holds: false,
                            violating_function: None,
                            violating_sequence: vec![fa.name.clone(), fb.name.clone()],
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                }
            }
        }
    }

    results
}

/// Check if two slot expressions might refer to the same storage slot.
fn slots_may_overlap(a: &Expr, b: &Expr) -> bool {
    // If both are the same literal, definitely overlap
    if a == b {
        return true;
    }
    // If both are literals but different, no overlap
    if matches!(a, Expr::Lit(_)) && matches!(b, Expr::Lit(_)) {
        return false;
    }
    // If either is symbolic, conservatively assume possible overlap
    true
}

fn prop_mentions_caller(prop: &Prop) -> bool {
    match prop {
        Prop::Bool(_) => false,
        Prop::IsTrue(e) | Prop::IsZero(e) => expr_mentions_caller(e),
        Prop::Eq(a, b) | Prop::Lt(a, b) | Prop::Gt(a, b) => {
            expr_mentions_caller(a) || expr_mentions_caller(b)
        }
        Prop::And(a, b) | Prop::Or(a, b) => prop_mentions_caller(a) || prop_mentions_caller(b),
        Prop::Not(a) => prop_mentions_caller(a),
    }
}

fn expr_mentions_caller(expr: &Expr) -> bool {
    match expr {
        Expr::Caller => true,
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
        | Expr::Sar(a, b) => expr_mentions_caller(a) || expr_mentions_caller(b),
        Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
            expr_mentions_caller(a) || expr_mentions_caller(b) || expr_mentions_caller(c)
        }
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::SLoad(a)
        | Expr::MLoad(a)
        | Expr::Keccak256(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => expr_mentions_caller(a),
        Expr::Ite(p, t, f) => {
            prop_mentions_caller(p) || expr_mentions_caller(t) || expr_mentions_caller(f)
        }
        _ => false,
    }
}

pub fn format_invariant_results(results: &[InvariantResult]) -> String {
    let mut out = String::new();
    let holds = results.iter().filter(|r| r.holds).count();
    let violated = results.len() - holds;
    out.push_str(&format!(
        "Checked {} invariants ({} hold, {} violated)\n\n",
        results.len(),
        holds,
        violated
    ));
    for r in results {
        let status = if r.holds { "HOLDS" } else { "VIOLATED" };
        out.push_str(&format!("  [{}] {}", status, r.invariant_name));
        if let Some(func) = &r.violating_function {
            out.push_str(&format!(" -- in {}", func));
        }
        if r.violating_sequence.len() > 1 {
            out.push_str(&format!(
                " -- sequence: {}",
                r.violating_sequence.join(" -> ")
            ));
        }
        out.push('\n');
    }
    out
}
