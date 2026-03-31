use r_evm_verify_lifter::abi::{enrich_with_abi, parse_abi};
use r_evm_verify_lifter::ir::Expr;
use r_evm_verify_lifter::selectors::{
    extract_selectors, offset_to_function, selector_hex, FunctionEntry,
};
use r_evm_verify_solver::context::SolverContext;
use r_evm_verify_solver::incremental::IncrementalSolver;
use r_evm_verify_svm::exec::{step, step_incremental, ExecutionResult};
use r_evm_verify_svm::properties::{
    check_access_control, check_add_overflow, check_arbitrary_send, check_delegatecall,
    check_divide_before_multiply, check_msg_value_in_loop, check_mul_overflow,
    check_oracle_manipulation, check_reentrancy, check_selfdestruct, check_timestamp_dependence,
    check_tx_origin, check_unchecked_call_return, check_unprotected_call,
};
use r_evm_verify_svm::SvmState;
use r_evm_verify_synthesizer::report::*;
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

/// Configuration for a scan.
pub struct ScanConfig {
    pub max_steps: u64,
    pub max_paths: usize,
    pub max_overflow_checks: usize,
    pub max_constraint_depth: usize,
    /// Per-path time limit in milliseconds.
    pub path_timeout_ms: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000,
            max_paths: 10_000,
            max_overflow_checks: 5,
            max_constraint_depth: 30,
            path_timeout_ms: 5_000,
        }
    }
}

/// Create adaptive config based on contract size.
pub fn adaptive_config(bytecode_len: usize, num_functions: usize) -> ScanConfig {
    // Bigger contracts get fewer steps per function to stay within total budget.
    let steps_per_func = if num_functions > 30 {
        1_000
    } else if num_functions > 20 {
        2_000
    } else if num_functions > 10 {
        5_000
    } else {
        10_000
    };
    let max_paths = if num_functions > 30 {
        200
    } else if num_functions > 20 {
        500
    } else if num_functions > 10 {
        2_000
    } else {
        10_000
    };
    ScanConfig {
        max_steps: steps_per_func,
        max_paths,
        max_overflow_checks: 3,
        max_constraint_depth: 20,
        path_timeout_ms: 3_000,
    }
}

/// Scan raw bytecode for vulnerabilities using symbolic execution.
pub fn scan_bytecode(bytecode: &[u8]) -> Report {
    scan_bytecode_with_abi(bytecode, None)
}

/// Scan with ABI information for better function name resolution.
pub fn scan_bytecode_with_abi(bytecode: &[u8], abi_json: Option<&serde_json::Value>) -> Report {
    // Use adaptive config based on contract size.
    let num_funcs = extract_selectors(bytecode).len();
    let config = if num_funcs > 10 {
        adaptive_config(bytecode.len(), num_funcs)
    } else {
        ScanConfig::default()
    };
    scan_bytecode_full(bytecode, &config, abi_json)
}

/// Scan with custom configuration and optional ABI.
pub fn scan_bytecode_full(
    bytecode: &[u8],
    config: &ScanConfig,
    abi_json: Option<&serde_json::Value>,
) -> Report {
    let start = Instant::now();

    // Extract function selectors and enrich with ABI if available.
    let mut selectors = extract_selectors(bytecode);
    if let Some(abi) = abi_json {
        let abi_map = parse_abi(abi);
        enrich_with_abi(&mut selectors, &abi_map);
    }

    let findings = Mutex::new(Vec::new());

    let callback_offsets: Vec<usize> = selectors
        .iter()
        .filter(|s| s.offset > 0)
        .map(|s| s.offset)
        .collect();

    if selectors.is_empty() {
        // No standard dispatcher found — tight budget for full exploration
        let mut initial = SvmState::new(config.max_steps.min(3000));
        initial.max_callbacks = 0; // No callbacks for full-contract scan
        let tight_config = ScanConfig {
            max_steps: config.max_steps.min(3000),
            max_paths: config.max_paths.min(500),
            max_overflow_checks: 3,
            max_constraint_depth: 15,
            path_timeout_ms: 2_000,
        };
        run_exploration(
            bytecode,
            vec![initial],
            &tight_config,
            &findings,
            &callback_offsets,
        );
    } else {
        // Function-level scanning: one SVM per function, starting at each
        // function's entry offset. Skips the dispatcher entirely.
        let initial_states: Vec<SvmState> = selectors
            .iter()
            .filter(|s| s.offset > 0)
            .map(|entry| {
                let mut state = SvmState::new(config.max_steps);
                state.pc = entry.offset;
                state
            })
            .collect();

        let func_count = initial_states.len();
        eprintln!(
            "  Scanning {} function{} in parallel...",
            func_count,
            if func_count == 1 { "" } else { "s" }
        );

        run_exploration(
            bytecode,
            initial_states,
            config,
            &findings,
            &callback_offsets,
        );
    }

    let mut all_findings = findings.into_inner().unwrap();

    // Annotate findings with function names from selector table.
    for finding in &mut all_findings {
        if let Some(entry) = offset_to_function(&selectors, finding.location.offset) {
            finding.location.function_selector = Some(entry.selector);
            finding.location.function_name = entry
                .name
                .clone()
                .or_else(|| Some(selector_hex(&entry.selector)));
        }
    }

    all_findings.sort_by_key(|f| (f.location.offset, format!("{:?}", f.category)));
    all_findings.dedup_by(|a, b| {
        a.category == b.category
            && (a.location.offset == b.location.offset
                || (a.location.function_name.is_some()
                    && a.location.function_name == b.location.function_name))
    });

    let duration_ms = start.elapsed().as_millis() as u64;
    Report {
        findings: all_findings,
        duration_ms,
    }
}

/// Run parallel symbolic exploration from a set of initial states.
fn run_exploration(
    bytecode: &[u8],
    initial_states: Vec<SvmState>,
    config: &ScanConfig,
    findings: &Mutex<Vec<Finding>>,
    callback_offsets: &[usize],
) {
    let path_count = Mutex::new(0usize);
    let mut worklist = initial_states;
    let scan_start = Instant::now();
    let global_timeout_ms = 20_000u64;
    let timed_out = std::sync::atomic::AtomicBool::new(false);

    while !worklist.is_empty() {
        if scan_start.elapsed().as_millis() as u64 > global_timeout_ms
            || timed_out.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        {
            let count = path_count.lock().unwrap();
            if *count >= config.max_paths {
                break;
            }
        }
        // Cap worklist size to prevent unbounded growth
        if worklist.len() > 500 {
            worklist.truncate(500);
        }

        let next_states: Vec<SvmState> = worklist
            .into_par_iter()
            .flat_map(|state| {
                let solver = SolverContext::new();
                // Incremental solver for this path — load existing constraints once.
                let mut inc = IncrementalSolver::new(solver.z3_ctx());
                // Only load constraints if the path has them (forked paths do).
                if state.constraints.len() <= 50 {
                    // Small constraint set: use incremental solver
                    for c in &state.constraints {
                        let _ = inc.assert_prop(c);
                    }
                }
                let use_incremental = state.constraints.len() <= 50;
                let mut current = state;
                let mut reported_overflow_pcs: HashSet<usize> = HashSet::new();
                let path_start = Instant::now();
                loop {
                    // Per-path timeout OR global timeout
                    if path_start.elapsed().as_millis() as u64 > config.path_timeout_ms
                        || scan_start.elapsed().as_millis() as u64 > global_timeout_ms
                    {
                        timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
                        *path_count.lock().unwrap() += 1;
                        return vec![];
                    }
                    let pc_before = current.pc;
                    let result = if use_incremental {
                        step_incremental(&mut current, bytecode, &mut inc)
                    } else {
                        step(&mut current, bytecode, Some(&solver))
                    };
                    match result {
                        None => {
                            // Check for overflow — skip if budget exhausted or constraints too deep
                            let overflow_budget_ok = config.max_overflow_checks == 0
                                || reported_overflow_pcs.len() < config.max_overflow_checks;
                            let constraint_depth_ok = current.constraints.len() <= config.max_constraint_depth;

                            if overflow_budget_ok && constraint_depth_ok {
                                if let Some(top) = current.stack.last() {
                                let model = match top {
                                    Expr::Add(a, b) => {
                                        check_add_overflow(a, b, &current.constraints, &solver)
                                    }
                                    Expr::Mul(a, b) => {
                                        check_mul_overflow(a, b, &current.constraints, &solver)
                                    }
                                    _ => None,
                                };
                                if let Some(cex_model) = model {
                                    if reported_overflow_pcs.insert(pc_before) {
                                        let title = match top {
                                            Expr::Add(_, _) => "Integer overflow in ADD",
                                            Expr::Mul(_, _) => "Integer overflow in MUL",
                                            _ => "Integer overflow",
                                        };
                                        let cex = if cex_model.assignments.is_empty() {
                                            None
                                        } else {
                                            Some(Counterexample {
                                                inputs: cex_model
                                                    .assignments
                                                    .iter()
                                                    .map(|(k, v)| {
                                                        let hex: String = v
                                                            .iter()
                                                            .map(|b| format!("{:02x}", b))
                                                            .collect();
                                                        (
                                                            k.clone(),
                                                            format!(
                                                                "0x{}",
                                                                hex.trim_start_matches('0')
                                                            ),
                                                        )
                                                    })
                                                    .collect(),
                                                call_trace: vec![],
                                            })
                                        };
                                        findings.lock().unwrap().push(Finding {
                                            severity: Severity::Medium,
                                            category: Category::Overflow,
                                            title: title.to_string(),
                                            description:
                                                "Arithmetic operation can overflow under satisfiable path constraints"
                                                    .to_string(),
                                            location: Location {
                                                offset: pc_before,
                                                function_selector: None,
                                                function_name: None,
                                            },
                                            counterexample: cex,
                                        });
                                    }
                                }
                            }
                            } // overflow_budget_ok && constraint_depth_ok
                            continue;
                        }
                        Some(ExecutionResult::Returned { state }) => {
                            let path_findings = check_all_properties(&state);
                            if !path_findings.is_empty() {
                                findings.lock().unwrap().extend(path_findings);
                            }
                            *path_count.lock().unwrap() += 1;
                            return vec![];
                        }
                        Some(ExecutionResult::Reverted { .. }) => {
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
                            current = continue_state.clone();

                            // Only simulate callback if this path hasn't exceeded its callback budget.
                            if current.callback_count < current.max_callbacks {
                                let mut callback_states: Vec<SvmState> = callback_offsets
                                    .iter()
                                    .take(2) // Max 2 callback targets
                                    .map(|&entry| {
                                        let mut cb_state = continue_state.clone();
                                        cb_state.pc = entry;
                                        cb_state.stack.clear();
                                        cb_state.callback_count += 1;
                                        cb_state.max_steps = 3000; // Short budget for callbacks
                                        cb_state
                                    })
                                    .collect();

                                if !callback_states.is_empty() {
                                    *path_count.lock().unwrap() += callback_states.len();
                                    callback_states.push(current);
                                    return callback_states;
                                }
                            }
                            continue;
                        }
                    }
                }
            })
            .collect();

        worklist = next_states;
    }
}

/// Check all property detectors on a completed path.
fn check_all_properties(state: &SvmState) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(reentrancy) = check_reentrancy(state) {
        findings.push(Finding {
            severity: Severity::High,
            category: Category::Reentrancy,
            title: "Reentrancy vulnerability".to_string(),
            description: format!(
                "External call at offset 0x{:04x} followed by storage write at 0x{:04x}",
                reentrancy.call_offset, reentrancy.sstore_offset
            ),
            location: Location {
                offset: reentrancy.call_offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(access) = check_access_control(state) {
        findings.push(Finding {
            severity: Severity::Medium,
            category: Category::AccessControl,
            title: "Missing access control".to_string(),
            description: "State-modifying path with no constraint on msg.sender".to_string(),
            location: Location {
                offset: access.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(ucall) = check_unprotected_call(state) {
        findings.push(Finding {
            severity: Severity::High,
            category: Category::AccessControl,
            title: "Unprotected ETH transfer".to_string(),
            description: "External call sending value without msg.sender check".to_string(),
            location: Location {
                offset: ucall.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(dc) = check_delegatecall(state) {
        findings.push(Finding {
            severity: Severity::High,
            category: Category::AccessControl,
            title: "Delegatecall to untrusted address".to_string(),
            description: "DELEGATECALL with user-controlled target address".to_string(),
            location: Location {
                offset: dc.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(txo) = check_tx_origin(state) {
        findings.push(Finding {
            severity: Severity::Medium,
            category: Category::AccessControl,
            title: "tx.origin used for authentication".to_string(),
            description: "ORIGIN opcode used — vulnerable to phishing attacks, use CALLER instead"
                .to_string(),
            location: Location {
                offset: txo.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(sd) = check_selfdestruct(state) {
        findings.push(Finding {
            severity: Severity::Critical,
            category: Category::AccessControl,
            title: "Reachable SELFDESTRUCT".to_string(),
            description: "SELFDESTRUCT opcode is reachable on this execution path".to_string(),
            location: Location {
                offset: sd.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(oracle) = check_oracle_manipulation(state) {
        findings.push(Finding {
            severity: Severity::High,
            category: Category::Reentrancy, // reuse category for now
            title: "Potential oracle manipulation".to_string(),
            description: "External call value or storage write depends on SLOAD (price oracle) without validation".to_string(),
            location: Location {
                offset: oracle.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(ucr) = check_unchecked_call_return(state) {
        findings.push(Finding {
            severity: Severity::Medium,
            category: Category::AccessControl,
            title: "Unchecked low-level call return value".to_string(),
            description: "Return value of external call is not checked — silent failures possible"
                .to_string(),
            location: Location {
                offset: ucr.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(arb) = check_arbitrary_send(state) {
        findings.push(Finding {
            severity: Severity::High,
            category: Category::AccessControl,
            title: "Arbitrary ETH send to user-controlled address".to_string(),
            description: "ETH sent to an address derived from calldata without validation"
                .to_string(),
            location: Location {
                offset: arb.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(mvl) = check_msg_value_in_loop(state) {
        findings.push(Finding {
            severity: Severity::High,
            category: Category::Reentrancy,
            title: "msg.value used in a loop".to_string(),
            description: format!(
                "msg.value referenced in {} external calls — may be double-counted",
                mvl.count
            ),
            location: Location {
                offset: 0,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if let Some(ts) = check_timestamp_dependence(state) {
        findings.push(Finding {
            severity: Severity::Low,
            category: Category::Reentrancy,
            title: "Block timestamp dependence".to_string(),
            description:
                "Block timestamp or block number used in storage write — miner-manipulable"
                    .to_string(),
            location: Location {
                offset: ts.offset,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }
    if check_divide_before_multiply(state).is_some() {
        findings.push(Finding {
            severity: Severity::Medium,
            category: Category::Overflow,
            title: "Divide before multiply — precision loss".to_string(),
            description:
                "Division performed before multiplication causes precision loss due to integer truncation"
                    .to_string(),
            location: Location {
                offset: 0,
                function_selector: None,
                function_name: None,
            },
            counterexample: None,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_trivial_stop() {
        let report = scan_bytecode(&[0x60, 0x00, 0x00]);
        assert!(report.is_clean());
    }

    #[test]
    fn scan_call_then_sstore_reentrancy() {
        let mut bytecode = Vec::new();
        for _ in 0..7 {
            bytecode.extend_from_slice(&[0x60, 0x00]);
        }
        bytecode.push(0xF1); // CALL
        bytecode.extend_from_slice(&[0x60, 0x42]); // PUSH val
        bytecode.extend_from_slice(&[0x60, 0x00]); // PUSH slot
        bytecode.push(0x55); // SSTORE
        bytecode.push(0x00); // STOP

        let report = scan_bytecode(&bytecode);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == Category::Reentrancy),
            "Should detect reentrancy: CALL before SSTORE"
        );
    }

    #[test]
    fn scan_sstore_before_call_safe() {
        let mut bytecode = Vec::new();
        bytecode.extend_from_slice(&[0x60, 0x42]); // PUSH val
        bytecode.extend_from_slice(&[0x60, 0x00]); // PUSH slot
        bytecode.push(0x55); // SSTORE
        for _ in 0..7 {
            bytecode.extend_from_slice(&[0x60, 0x00]);
        }
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // STOP

        let report = scan_bytecode(&bytecode);
        let reentrancy = report
            .findings
            .iter()
            .any(|f| f.category == Category::Reentrancy);
        assert!(
            !reentrancy,
            "SSTORE before CALL should NOT be flagged as reentrancy"
        );
    }

    #[test]
    fn scan_handles_jumpi_fork() {
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1 (cond)
            0x60, 0x06, // PUSH1 6 (dest)
            0x57, // JUMPI
            0x00, // STOP (fallthrough)
            0x5B, // JUMPDEST
            0x00, // STOP (target)
        ];
        let report = scan_bytecode(&bytecode);
        assert!(report.is_clean());
    }
}
