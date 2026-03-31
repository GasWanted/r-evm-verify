use r_evm_verify_lifter::selectors::FunctionEntry;
use r_evm_verify_solver::context::SolverContext;
use r_evm_verify_svm::exec::step;
use r_evm_verify_svm::state::CallEvent;
use r_evm_verify_svm::summary::FunctionSummary;
use r_evm_verify_svm::ExecutionResult;
use r_evm_verify_svm::SvmState;
use std::time::Instant;

/// Symbolically execute a single function and collect a summary of its behavior.
pub fn summarize_function(
    bytecode: &[u8],
    entry: &FunctionEntry,
    max_steps: u64,
) -> FunctionSummary {
    let func_name = entry.name.clone().unwrap_or_else(|| {
        format!(
            "0x{:02x}{:02x}{:02x}{:02x}",
            entry.selector[0], entry.selector[1], entry.selector[2], entry.selector[3]
        )
    });

    let mut initial = SvmState::new(max_steps);
    initial.pc = entry.offset;

    let solver = SolverContext::new();
    let mut worklist = vec![initial];
    let mut success_conditions = Vec::new();
    let mut revert_conditions = Vec::new();
    let mut all_writes = Vec::new();
    let all_reads = Vec::new();
    let mut has_external_call = false;
    let scan_start = Instant::now();

    while let Some(state) = worklist.pop() {
        if scan_start.elapsed().as_millis() > 5000 {
            break;
        }
        let mut current = state;
        loop {
            if scan_start.elapsed().as_millis() > 5000 {
                break;
            }
            match step(&mut current, bytecode, Some(&solver)) {
                None => continue,
                Some(ExecutionResult::Returned { state: final_state }) => {
                    success_conditions.push(final_state.constraints.clone());
                    for event in &final_state.call_log {
                        match event {
                            CallEvent::StorageWrite { slot, value, .. } => {
                                all_writes.push((slot.clone(), value.clone()));
                            }
                            CallEvent::ExternalCall { .. } | CallEvent::DelegateCall { .. } => {
                                has_external_call = true;
                            }
                            _ => {}
                        }
                    }
                    break;
                }
                Some(ExecutionResult::Reverted { state: rev_state }) => {
                    revert_conditions.push(rev_state.constraints.clone());
                    break;
                }
                Some(ExecutionResult::Fork {
                    true_state,
                    false_state,
                }) => {
                    worklist.push(false_state);
                    current = true_state;
                    continue;
                }
                Some(ExecutionResult::BoundReached { .. }) | Some(ExecutionResult::Dead) => break,
                Some(ExecutionResult::Continue { state: next }) => {
                    current = next;
                    continue;
                }
                Some(ExecutionResult::ExternalCall { continue_state, .. }) => {
                    has_external_call = true;
                    current = continue_state;
                    continue;
                }
            }
        }
    }

    let modifies_storage = !all_writes.is_empty();

    FunctionSummary {
        name: func_name,
        preconditions: Vec::new(),
        reads: all_reads,
        writes: all_writes,
        has_external_call,
        modifies_storage,
        revert_conditions,
        success_conditions,
    }
}

/// Summarize all functions in a contract by symbolically executing each one.
pub fn summarize_contract(
    bytecode: &[u8],
    functions: &[FunctionEntry],
    max_steps: u64,
) -> Vec<FunctionSummary> {
    functions
        .iter()
        .filter(|f| f.offset > 0)
        .map(|f| summarize_function(bytecode, f, max_steps))
        .collect()
}
