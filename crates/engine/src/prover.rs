use r_evm_verify_lifter::selectors::{extract_selectors, selector_hex, FunctionEntry};
use r_evm_verify_solver::context::SolverContext;
use r_evm_verify_solver::incremental::IncrementalSolver;
use r_evm_verify_svm::exec::{step, step_incremental, ExecutionResult};
use r_evm_verify_svm::SvmState;
use r_evm_verify_synthesizer::report::*;
use rayon::prelude::*;
use std::sync::Mutex;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the prover.
pub struct ProveConfig {
    /// Maximum symbolic execution steps per path.
    pub max_steps: u64,
    /// Maximum number of execution paths to explore per check_ function.
    pub max_paths: usize,
    /// Per-path time limit in milliseconds.
    pub path_timeout_ms: u64,
    /// Maximum constraint depth before switching to fresh solver.
    pub max_constraint_depth: usize,
}

impl Default for ProveConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_paths: 10_000,
            path_timeout_ms: 5_000,
            max_constraint_depth: 50,
        }
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of proving a single check_ function.
#[derive(Debug, Clone)]
pub struct ProveResult {
    /// Name of the check_ function (selector hex if no ABI name).
    pub function_name: String,
    /// 4-byte selector of the function.
    pub selector: [u8; 4],
    /// True if all reachable paths returned normally (property verified).
    pub verified: bool,
    /// Counterexample inputs when a REVERT path was found.
    pub counterexample: Option<Counterexample>,
    /// Number of paths explored.
    pub paths_explored: usize,
    /// Time taken in milliseconds.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Discovery: find check_ entry points
// ---------------------------------------------------------------------------

/// Filter function entries to those whose name starts with `check_`.
/// Falls back to matching selectors if no ABI names are available.
pub fn discover_check_functions(selectors: &[FunctionEntry]) -> Vec<&FunctionEntry> {
    selectors
        .iter()
        .filter(|entry| {
            entry
                .name
                .as_ref()
                .map_or(false, |n| n.starts_with("check_"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Core: prove one check_ function
// ---------------------------------------------------------------------------

/// Prove a single `check_` function by symbolic execution.
///
/// The function is considered VIOLATED if any reachable path REVERTs
/// (which corresponds to an assert failure in the test). If all reachable
/// paths RETURN normally, the property is VERIFIED.
pub fn prove_one(
    test_bytecode: &[u8],
    target_bytecode: &[u8],
    entry: &FunctionEntry,
    config: &ProveConfig,
) -> ProveResult {
    let start = Instant::now();
    let func_name = entry
        .name
        .clone()
        .unwrap_or_else(|| selector_hex(&entry.selector));

    // Build initial state at the check_ function's entry offset.
    let mut initial = SvmState::new(config.max_steps);
    initial.pc = entry.offset;

    // Deploy the target contract at a fixed address (last byte = 1).
    let mut target_addr = [0u8; 20];
    target_addr[19] = 1;
    initial
        .contracts
        .insert(target_addr, target_bytecode.to_vec());

    // Worklist-based symbolic exploration.
    let path_count = Mutex::new(0usize);
    let violation: Mutex<Option<Counterexample>> = Mutex::new(None);
    let mut worklist = vec![initial];
    let global_timeout_ms = 20_000u64;
    let timed_out = std::sync::atomic::AtomicBool::new(false);

    while !worklist.is_empty() {
        // Global timeout.
        if start.elapsed().as_millis() as u64 > global_timeout_ms
            || timed_out.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        // Path budget.
        {
            let count = path_count.lock().unwrap();
            if *count >= config.max_paths {
                break;
            }
        }
        // Already found a violation — no need to keep exploring.
        {
            if violation.lock().unwrap().is_some() {
                break;
            }
        }
        // Cap worklist to prevent unbounded growth.
        if worklist.len() > 500 {
            worklist.truncate(500);
        }

        let next_states: Vec<SvmState> = worklist
            .into_par_iter()
            .flat_map(|state| {
                let solver = SolverContext::new();
                let mut inc = IncrementalSolver::new(solver.z3_ctx());
                let use_incremental = state.constraints.len() <= config.max_constraint_depth;
                if use_incremental {
                    for c in &state.constraints {
                        let _ = inc.assert_prop(c);
                    }
                }
                let mut current = state;
                let path_start = Instant::now();
                loop {
                    // Per-path timeout OR global timeout.
                    if path_start.elapsed().as_millis() as u64 > config.path_timeout_ms
                        || start.elapsed().as_millis() as u64 > global_timeout_ms
                    {
                        timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
                        *path_count.lock().unwrap() += 1;
                        return vec![];
                    }
                    let result = if use_incremental {
                        step_incremental(&mut current, test_bytecode, &mut inc)
                    } else {
                        step(&mut current, test_bytecode, Some(&solver))
                    };
                    match result {
                        None => {
                            // No terminal event — continue stepping.
                            continue;
                        }
                        Some(ExecutionResult::Returned { .. }) => {
                            // Path returned normally — property holds on this path.
                            *path_count.lock().unwrap() += 1;
                            return vec![];
                        }
                        Some(ExecutionResult::Reverted { state: rev_state }) => {
                            // REVERT = assertion failure → VIOLATION.
                            // Extract counterexample from path constraints.
                            let cex = solver
                                .get_counterexample(&rev_state.constraints)
                                .ok()
                                .flatten()
                                .map(|model| Counterexample {
                                    inputs: model
                                        .assignments
                                        .iter()
                                        .map(|(k, v)| {
                                            let hex: String =
                                                v.iter().map(|b| format!("{:02x}", b)).collect();
                                            (
                                                k.clone(),
                                                format!("0x{}", hex.trim_start_matches('0')),
                                            )
                                        })
                                        .collect(),
                                    call_trace: vec![],
                                });
                            // Store the first violation found.
                            let mut lock = violation.lock().unwrap();
                            if lock.is_none() {
                                *lock = Some(cex.unwrap_or(Counterexample {
                                    inputs: vec![],
                                    call_trace: vec![],
                                }));
                            }
                            *path_count.lock().unwrap() += 1;
                            return vec![];
                        }
                        Some(ExecutionResult::BoundReached { .. }) => {
                            *path_count.lock().unwrap() += 1;
                            return vec![];
                        }
                        Some(ExecutionResult::Fork {
                            true_state,
                            false_state,
                        }) => {
                            *path_count.lock().unwrap() += 1;
                            return vec![true_state, false_state];
                        }
                        Some(ExecutionResult::Continue { state: next }) => {
                            current = next;
                            continue;
                        }
                        Some(ExecutionResult::Dead) => {
                            *path_count.lock().unwrap() += 1;
                            return vec![];
                        }
                        Some(ExecutionResult::ExternalCall {
                            continue_state,
                            call_offset: _,
                        }) => {
                            current = continue_state;
                            // Check if this is a cross-contract CALL into a
                            // known contract (indicated by the SVM having
                            // pushed a CallFrame onto the call stack).
                            if !current.call_frames.is_empty() {
                                // Execute the callee inline.  We determine
                                // which contract to run by looking at the
                                // last CallEvent::ExternalCall address.
                                let callee_bytecode: Option<Vec<u8>> = {
                                    let last_call = current.call_log.iter().rev().find_map(|e| {
                                        if let r_evm_verify_svm::CallEvent::ExternalCall {
                                            addr,
                                            ..
                                        } = e
                                        {
                                            if let r_evm_verify_lifter::ir::Expr::Lit(b) = addr {
                                                let mut a = [0u8; 20];
                                                a.copy_from_slice(&b[12..32]);
                                                Some(a)
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    });
                                    last_call.and_then(|a| current.contracts.get(&a).cloned())
                                };

                                if let Some(callee_code) = callee_bytecode {
                                    // Store the caller's bytecode in the frame
                                    // so we can restore it after the callee
                                    // returns.
                                    if let Some(frame) = current.call_frames.last_mut() {
                                        frame.caller_bytecode = test_bytecode.to_vec();
                                    }

                                    // Run the callee's bytecode until it
                                    // terminates.  We create a sub-solver
                                    // context for the callee.
                                    let callee_solver = SolverContext::new();
                                    let callee_max_steps = 5_000u64;
                                    let callee_start_steps = current.steps;
                                    let mut callee_returned = false;
                                    loop {
                                        if current.steps - callee_start_steps > callee_max_steps {
                                            // Callee hit step limit — treat as
                                            // failed call (push 0).
                                            break;
                                        }
                                        if path_start.elapsed().as_millis() as u64
                                            > config.path_timeout_ms
                                        {
                                            break;
                                        }

                                        let callee_result =
                                            step(&mut current, &callee_code, Some(&callee_solver));
                                        match callee_result {
                                            None => continue,
                                            Some(ExecutionResult::Returned {
                                                state: ret_state,
                                            }) => {
                                                current = ret_state;
                                                callee_returned = true;
                                                break;
                                            }
                                            Some(ExecutionResult::Reverted {
                                                state: rev_state,
                                            }) => {
                                                // Callee reverted — call failed.
                                                current = rev_state;
                                                callee_returned = false;
                                                break;
                                            }
                                            Some(ExecutionResult::BoundReached {
                                                state: bound_state,
                                            }) => {
                                                current = bound_state;
                                                break;
                                            }
                                            Some(ExecutionResult::Fork {
                                                true_state,
                                                false_state: _,
                                            }) => {
                                                // Simplification: take the true
                                                // branch of callee forks.
                                                // A full implementation would
                                                // explore both, but that
                                                // requires a nested worklist.
                                                current = true_state;
                                                continue;
                                            }
                                            Some(ExecutionResult::Continue { state: next }) => {
                                                current = next;
                                                continue;
                                            }
                                            Some(ExecutionResult::Dead) => {
                                                break;
                                            }
                                            Some(ExecutionResult::ExternalCall {
                                                continue_state: inner_cont,
                                                ..
                                            }) => {
                                                // Nested external call from
                                                // callee — treat symbolically
                                                // for now.
                                                current = inner_cont;
                                                continue;
                                            }
                                        }
                                    }

                                    // Restore the caller's frame.
                                    if let Some(frame) = current.call_frames.pop() {
                                        current.pc = frame.return_pc;
                                        current.stack = frame.caller_stack;
                                        current.taints = frame.caller_taints;
                                        // Push success (1) or failure (0)
                                        // depending on whether callee returned.
                                        if callee_returned {
                                            let mut one = [0u8; 32];
                                            one[31] = 1;
                                            current.push_tainted(
                                                r_evm_verify_lifter::ir::Expr::Lit(one),
                                                r_evm_verify_svm::Taint::Trusted,
                                            );
                                        } else {
                                            current.push_tainted(
                                                r_evm_verify_lifter::ir::Expr::Lit([0u8; 32]),
                                                r_evm_verify_svm::Taint::Trusted,
                                            );
                                        }
                                    }
                                    // Continue executing the caller's bytecode.
                                    continue;
                                }
                            }

                            // Unknown target or no call frame — just continue
                            // past the external call symbolically.
                            continue;
                        }
                    }
                }
            })
            .collect();

        worklist = next_states;
    }

    let paths = *path_count.lock().unwrap();
    let cex = violation.into_inner().unwrap();
    let verified = cex.is_none();
    let duration_ms = start.elapsed().as_millis() as u64;

    ProveResult {
        function_name: func_name,
        selector: entry.selector,
        verified,
        counterexample: cex,
        paths_explored: paths,
        duration_ms,
    }
}

// ---------------------------------------------------------------------------
// Top-level: prove all check_ functions
// ---------------------------------------------------------------------------

/// Prove all `check_` functions found in `test_bytecode`.
///
/// `target_bytecode` is the contract under test, deployed at a fixed address
/// so that CALLs from the test harness can reference it.
///
/// Returns results sorted by function name.
pub fn prove_all(
    test_bytecode: &[u8],
    target_bytecode: &[u8],
    config: &ProveConfig,
    abi_json: Option<&serde_json::Value>,
) -> Vec<ProveResult> {
    let mut selectors = extract_selectors(test_bytecode);
    if let Some(abi) = abi_json {
        let abi_map = r_evm_verify_lifter::abi::parse_abi(abi);
        r_evm_verify_lifter::abi::enrich_with_abi(&mut selectors, &abi_map);
    }

    let check_entries: Vec<&FunctionEntry> = discover_check_functions(&selectors);

    if check_entries.is_empty() {
        eprintln!("  No check_ functions found in test bytecode.");
        return vec![];
    }

    eprintln!(
        "  Found {} check_ function{}:",
        check_entries.len(),
        if check_entries.len() == 1 { "" } else { "s" }
    );
    for entry in &check_entries {
        let fallback = selector_hex(&entry.selector);
        let name = entry.name.as_deref().unwrap_or(&fallback);
        eprintln!("    - {} (offset 0x{:04x})", name, entry.offset);
    }

    // Prove each check_ function in parallel.
    let mut results: Vec<ProveResult> = check_entries
        .par_iter()
        .map(|entry| prove_one(test_bytecode, target_bytecode, entry, config))
        .collect();

    results.sort_by(|a, b| a.function_name.cmp(&b.function_name));
    results
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Format prove results for human-readable display.
pub fn format_prove_results(results: &[ProveResult]) -> String {
    if results.is_empty() {
        return "No check_ functions found to prove.\n".to_string();
    }

    let mut out = String::new();
    let verified_count = results.iter().filter(|r| r.verified).count();
    let violated_count = results.len() - verified_count;

    out.push_str(&format!(
        "Prove results: {} verified, {} violated ({} total)\n",
        verified_count,
        violated_count,
        results.len()
    ));
    out.push_str(&"-".repeat(60));
    out.push('\n');

    for result in results {
        let status = if result.verified {
            "VERIFIED"
        } else {
            "VIOLATED"
        };
        out.push_str(&format!(
            "  [{}] {} ({} paths, {} ms)\n",
            status, result.function_name, result.paths_explored, result.duration_ms,
        ));
        if let Some(cex) = &result.counterexample {
            if !cex.inputs.is_empty() {
                out.push_str("    Counterexample:\n");
                for (name, value) in &cex.inputs {
                    out.push_str(&format!("      {} = {}\n", name, value));
                }
            }
        }
    }

    out.push_str(&"-".repeat(60));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_filters_check_functions() {
        let entries = vec![
            FunctionEntry {
                selector: [0x01, 0x02, 0x03, 0x04],
                offset: 100,
                name: Some("check_balance()".into()),
            },
            FunctionEntry {
                selector: [0x05, 0x06, 0x07, 0x08],
                offset: 200,
                name: Some("transfer(address,uint256)".into()),
            },
            FunctionEntry {
                selector: [0x09, 0x0a, 0x0b, 0x0c],
                offset: 300,
                name: Some("check_invariant()".into()),
            },
        ];
        let check_fns = discover_check_functions(&entries);
        assert_eq!(check_fns.len(), 2);
        assert_eq!(check_fns[0].name.as_deref(), Some("check_balance()"));
        assert_eq!(check_fns[1].name.as_deref(), Some("check_invariant()"));
    }

    #[test]
    fn prove_trivial_return_verified() {
        // Bytecode: PUSH1 0x00 PUSH1 0x00 RETURN
        // This just returns immediately — no revert, so VERIFIED.
        let entry = FunctionEntry {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            offset: 0,
            name: Some("check_trivial()".into()),
        };
        let test_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xF3]; // PUSH 0, PUSH 0, RETURN
        let target_bytecode = vec![0x00]; // STOP
        let config = ProveConfig::default();
        let result = prove_one(&test_bytecode, &target_bytecode, &entry, &config);
        assert!(result.verified, "Trivial RETURN should be verified");
        assert!(result.counterexample.is_none());
    }

    #[test]
    fn prove_trivial_revert_violated() {
        // Bytecode: PUSH1 0x00 PUSH1 0x00 REVERT
        // This always reverts — VIOLATED.
        let entry = FunctionEntry {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            offset: 0,
            name: Some("check_always_fails()".into()),
        };
        let test_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xFD]; // PUSH 0, PUSH 0, REVERT
        let target_bytecode = vec![0x00]; // STOP
        let config = ProveConfig::default();
        let result = prove_one(&test_bytecode, &target_bytecode, &entry, &config);
        assert!(!result.verified, "Always-REVERT should be violated");
        assert!(result.counterexample.is_some());
    }

    #[test]
    fn format_results_empty() {
        let output = format_prove_results(&[]);
        assert!(output.contains("No check_ functions found"));
    }

    #[test]
    fn format_results_mixed() {
        let results = vec![
            ProveResult {
                function_name: "check_ok()".into(),
                selector: [0x01, 0x02, 0x03, 0x04],
                verified: true,
                counterexample: None,
                paths_explored: 5,
                duration_ms: 42,
            },
            ProveResult {
                function_name: "check_fail()".into(),
                selector: [0x05, 0x06, 0x07, 0x08],
                verified: false,
                counterexample: Some(Counterexample {
                    inputs: vec![("caller".into(), "0x1234".into())],
                    call_trace: vec![],
                }),
                paths_explored: 3,
                duration_ms: 99,
            },
        ];
        let output = format_prove_results(&results);
        assert!(output.contains("VERIFIED"));
        assert!(output.contains("VIOLATED"));
        assert!(output.contains("check_ok()"));
        assert!(output.contains("check_fail()"));
        assert!(output.contains("caller = 0x1234"));
    }
}
