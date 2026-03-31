use crate::state::{CallEvent, SvmState};
use crate::taint::Taint;
use r_evm_verify_lifter::ir::Expr;
use r_evm_verify_lifter::opcodes::Opcode;
use r_evm_verify_solver::context::SolverContext;
use r_evm_verify_solver::incremental::IncrementalSolver;
use r_evm_verify_solver::SatResult;

/// Result of executing one path to completion.
#[derive(Debug, Clone)]
pub enum ExecutionResult {
    /// Path reached STOP/RETURN normally.
    Returned { state: SvmState },
    /// Path reached REVERT.
    Reverted { state: SvmState },
    /// Path hit step limit.
    BoundReached { state: SvmState },
    /// Path needs to fork at JUMPI — returns both feasible branches.
    Fork {
        true_state: SvmState,
        false_state: SvmState,
    },
    /// Only one JUMPI branch is feasible — continue on it.
    Continue { state: SvmState },
    /// Both JUMPI branches are infeasible — dead path.
    Dead,
    /// External CALL encountered — engine may simulate callback re-entry.
    /// `continue_state` has the symbolic call return, `callback_state` has
    /// storage/constraints for simulating re-entry at function entry points.
    ExternalCall {
        continue_state: SvmState,
        call_offset: usize,
    },
}

/// Execute a single step of the SVM. Returns None if execution should continue,
/// or Some(result) if the path has terminated or needs to fork.
///
/// If `solver` is Some, Z3 is used to prune infeasible JUMPI branches.
/// If None, both branches are taken (no pruning).
pub fn step(
    state: &mut SvmState,
    bytecode: &[u8],
    solver: Option<&SolverContext>,
) -> Option<ExecutionResult> {
    step_inner(state, bytecode, solver, &mut None)
}

/// Step with an incremental solver for efficient push/pop at JUMPI branches.
pub fn step_incremental<'ctx>(
    state: &mut SvmState,
    bytecode: &[u8],
    inc_solver: &mut IncrementalSolver<'ctx>,
) -> Option<ExecutionResult> {
    step_inner(state, bytecode, None, &mut Some(inc_solver))
}

fn step_inner<'a, 'ctx>(
    state: &mut SvmState,
    bytecode: &[u8],
    solver: Option<&SolverContext>,
    inc_solver_ref: &mut Option<&mut IncrementalSolver<'ctx>>,
) -> Option<ExecutionResult> {
    if state.steps >= state.max_steps {
        return Some(ExecutionResult::BoundReached {
            state: state.clone(),
        });
    }
    // Loop detection: if we've visited this (pc, stack_height) too many times, stop.
    if state.check_loop_bound() {
        return Some(ExecutionResult::BoundReached {
            state: state.clone(),
        });
    }
    if state.pc >= bytecode.len() {
        return Some(ExecutionResult::Returned {
            state: state.clone(),
        });
    }

    state.steps += 1;
    let opcode = Opcode::from_byte(bytecode[state.pc]);
    let imm_size = opcode.immediate_size();

    match opcode {
        // Arithmetic
        Opcode::Add => binary_op(state, |a, b| Expr::Add(Box::new(a), Box::new(b))),
        Opcode::Sub => binary_op(state, |a, b| Expr::Sub(Box::new(a), Box::new(b))),
        Opcode::Mul => binary_op(state, |a, b| Expr::Mul(Box::new(a), Box::new(b))),
        Opcode::Div => binary_op(state, |a, b| Expr::Div(Box::new(a), Box::new(b))),
        Opcode::SDiv => binary_op(state, |a, b| Expr::SDiv(Box::new(a), Box::new(b))),
        Opcode::Mod => binary_op(state, |a, b| Expr::Mod(Box::new(a), Box::new(b))),
        Opcode::SMod => binary_op(state, |a, b| Expr::SMod(Box::new(a), Box::new(b))),
        Opcode::Exp => binary_op(state, |a, b| Expr::Exp(Box::new(a), Box::new(b))),

        // Comparison
        Opcode::Lt => binary_op(state, |a, b| Expr::Lt(Box::new(a), Box::new(b))),
        Opcode::Gt => binary_op(state, |a, b| Expr::Gt(Box::new(a), Box::new(b))),
        Opcode::SLt => binary_op(state, |a, b| Expr::SLt(Box::new(a), Box::new(b))),
        Opcode::SGt => binary_op(state, |a, b| Expr::SGt(Box::new(a), Box::new(b))),
        Opcode::Eq => binary_op(state, |a, b| Expr::Eq(Box::new(a), Box::new(b))),
        Opcode::IsZero => unary_op(state, |a| Expr::IsZero(Box::new(a))),

        // Bitwise
        Opcode::And => binary_op(state, |a, b| Expr::And(Box::new(a), Box::new(b))),
        Opcode::Or => binary_op(state, |a, b| Expr::Or(Box::new(a), Box::new(b))),
        Opcode::Xor => binary_op(state, |a, b| Expr::Xor(Box::new(a), Box::new(b))),
        Opcode::Not => unary_op(state, |a| Expr::Not(Box::new(a))),
        Opcode::Shl => binary_op(state, |a, b| Expr::Shl(Box::new(a), Box::new(b))),
        Opcode::Shr => binary_op(state, |a, b| Expr::Shr(Box::new(a), Box::new(b))),
        Opcode::Sar => binary_op(state, |a, b| Expr::Sar(Box::new(a), Box::new(b))),

        // Stack
        Opcode::Push(n) => {
            let mut bytes = [0u8; 32];
            let start = state.pc + 1;
            let end = (start + n as usize).min(bytecode.len());
            let data = &bytecode[start..end];
            // Right-align in 32-byte array (big-endian)
            bytes[32 - data.len()..].copy_from_slice(data);
            state.push_tainted(Expr::Lit(bytes), Taint::Trusted);
        }
        Opcode::Pop => {
            state.pop();
        }
        Opcode::Dup(n) => {
            if let Some(val) = state.peek(n as usize - 1).cloned() {
                let taint = state.peek_taint(n as usize - 1);
                state.push_tainted(val, taint);
            }
        }
        Opcode::Swap(n) => {
            let len = state.stack.len();
            if len > n as usize {
                state.stack.swap(len - 1, len - 1 - n as usize);
                state.taints.swap(len - 1, len - 1 - n as usize);
            }
        }

        // Memory
        Opcode::MLoad => {
            if let Some(offset) = state.pop() {
                if let Expr::Lit(bytes) = &offset {
                    let off = u256_to_usize(bytes);
                    let val = state.memory.load(off);
                    state.push(val);
                } else {
                    state.push(Expr::MLoad(Box::new(offset)));
                }
            }
        }
        Opcode::MStore => {
            if let (Some(offset), Some(value)) = (state.pop(), state.pop()) {
                if let Expr::Lit(bytes) = &offset {
                    let off = u256_to_usize(bytes);
                    state.memory.store(off, value);
                }
                // Symbolic offset: skip (lossy but avoids explosion)
            }
        }

        // Storage
        Opcode::SLoad => {
            if let Some(slot) = state.pop() {
                let val = state.storage.sload(&slot);
                state.push_tainted(val, Taint::Unknown);
            }
        }
        Opcode::SStore => {
            if let (Some((slot, _slot_taint)), Some((value, val_taint))) =
                (state.pop_tainted(), state.pop_tainted())
            {
                state.call_log.push(CallEvent::StorageWrite {
                    offset: state.pc,
                    slot: slot.clone(),
                    value: value.clone(),
                    value_taint: val_taint,
                });
                state.storage.sstore(slot, value);
            }
        }

        // Environment
        Opcode::Caller => state.push_tainted(Expr::Caller, Taint::Untrusted),
        Opcode::CallValue => state.push_tainted(Expr::CallValue, Taint::Untrusted),
        Opcode::CallDataLoad => {
            if let Some(offset) = state.pop() {
                state.push_tainted(Expr::CallDataLoad(Box::new(offset)), Taint::Untrusted);
            }
        }
        Opcode::CallDataSize => state.push_tainted(Expr::CallDataSize, Taint::Untrusted),
        Opcode::Address => state.push_tainted(Expr::Address, Taint::Trusted),
        Opcode::Origin => {
            state
                .call_log
                .push(CallEvent::TxOriginCheck { offset: state.pc });
            state.push_tainted(Expr::Origin, Taint::Untrusted);
        }
        Opcode::GasPrice => state.push_tainted(Expr::GasPrice, Taint::Unknown),
        Opcode::Coinbase => state.push_tainted(Expr::Coinbase, Taint::Unknown),
        Opcode::Timestamp => state.push_tainted(Expr::Timestamp, Taint::Unknown),
        Opcode::Number => state.push_tainted(Expr::Number, Taint::Unknown),
        Opcode::GasLimit => state.push_tainted(Expr::GasLimit, Taint::Unknown),
        Opcode::ChainId => state.push_tainted(Expr::ChainId, Taint::Trusted),
        Opcode::Balance => {
            if let Some(addr) = state.pop() {
                state.push(Expr::Balance(Box::new(addr)));
            }
        }
        Opcode::BlockHash => {
            if let Some(num) = state.pop() {
                state.push(Expr::BlockHash(Box::new(num)));
            }
        }

        // Calls
        Opcode::Call => {
            let call_pc = state.pc;
            let _gas = state.pop().unwrap_or(Expr::Lit([0; 32]));
            let addr_expr = state.pop().unwrap_or(Expr::Lit([0; 32]));
            let (value_expr, value_taint) = state
                .pop_tainted()
                .unwrap_or((Expr::Lit([0; 32]), Taint::Unknown));
            let args_offset = state.pop();
            let args_size = state.pop();
            let ret_offset_expr = state.pop();
            let ret_size_expr = state.pop();

            // Try to resolve a concrete target address for cross-contract dispatch.
            let target_addr = crate::call_dispatch::resolve_address(&addr_expr);
            let is_known_contract = target_addr
                .as_ref()
                .map_or(false, |a| crate::call_dispatch::has_contract(state, a));

            if is_known_contract {
                let _target_addr = target_addr.unwrap();

                // Parse ret_offset and ret_size for later RETURNDATACOPY.
                let ret_off = match &ret_offset_expr {
                    Some(Expr::Lit(b)) => u256_to_usize(b),
                    _ => 0,
                };
                let ret_sz = match &ret_size_expr {
                    Some(Expr::Lit(b)) => u256_to_usize(b),
                    _ => 0,
                };

                // Copy calldata from caller's memory into the callee's memory
                // so the callee's CALLDATALOAD can read it. We approximate this
                // by extracting the 4-byte selector from memory at args_offset
                // and making it available as calldata. For now we pass memory
                // through since both contracts share state.memory in this model.
                let _args_off = match &args_offset {
                    Some(Expr::Lit(b)) => u256_to_usize(b),
                    _ => 0,
                };
                let _args_sz = match &args_size {
                    Some(Expr::Lit(b)) => u256_to_usize(b),
                    _ => 0,
                };

                // Save the caller's frame so we can restore after callee returns.
                let frame = crate::call_dispatch::CallFrame {
                    return_pc: state.pc + 1, // PC after this CALL opcode
                    caller_bytecode: vec![], // Filled in by the engine
                    caller_stack: state.stack.clone(),
                    caller_taints: state.taints.clone(),
                    ret_offset: ret_off,
                    ret_size: ret_sz,
                };
                state.call_frames.push(frame);

                // Prepare state for executing the target contract's bytecode.
                state.pc = 0;
                state.stack.clear();
                state.taints.clear();
                // Memory and storage are shared (same EVM transaction context).

                // Log the external call.
                state.call_log.push(CallEvent::ExternalCall {
                    offset: call_pc,
                    addr: addr_expr,
                    value: value_expr,
                    value_taint,
                });

                // Signal to the engine to switch bytecode to the target contract.
                return Some(ExecutionResult::ExternalCall {
                    continue_state: state.clone(),
                    call_offset: call_pc,
                });
            }

            // Unknown/symbolic target — fall back to symbolic return value.
            state.call_log.push(CallEvent::ExternalCall {
                offset: call_pc,
                addr: addr_expr,
                value: value_expr,
                value_taint,
            });

            // Push symbolic success and advance PC
            state.push(Expr::Var(format!("call_success@{}", call_pc)));
            state.pc += 1;

            // Signal to the engine that a callback might occur
            return Some(ExecutionResult::ExternalCall {
                continue_state: state.clone(),
                call_offset: call_pc,
            });
        }
        Opcode::StaticCall => {
            let _gas = state.pop();
            let addr = state.pop().unwrap_or(Expr::Lit([0; 32]));
            let _args_offset = state.pop();
            let _args_size = state.pop();
            let _ret_offset = state.pop();
            let _ret_size = state.pop();

            state.call_log.push(CallEvent::ExternalCall {
                offset: state.pc,
                addr,
                value: Expr::Lit([0; 32]),
                value_taint: Taint::Trusted,
            });
            state.push(Expr::Var(format!("call_success@{}", state.pc)));
        }
        Opcode::DelegateCall => {
            let _gas = state.pop();
            let addr = state.pop().unwrap_or(Expr::Lit([0; 32]));
            let _args_offset = state.pop();
            let _args_size = state.pop();
            let _ret_offset = state.pop();
            let _ret_size = state.pop();

            state.call_log.push(CallEvent::DelegateCall {
                offset: state.pc,
                addr: addr.clone(),
            });
            state.call_log.push(CallEvent::ExternalCall {
                offset: state.pc,
                addr,
                value: Expr::Lit([0; 32]),
                value_taint: Taint::Trusted,
            });
            state.push(Expr::Var(format!("call_success@{}", state.pc)));
        }

        // Control flow
        Opcode::Jump => {
            if let Some(dest) = state.pop() {
                if let Expr::Lit(bytes) = &dest {
                    state.pc = u256_to_usize(bytes);
                    return None; // Don't advance PC
                }
            }
            // Dynamic jump target — can't resolve, terminate path
            return Some(ExecutionResult::Returned {
                state: state.clone(),
            });
        }
        Opcode::JumpI => {
            let dest = state.pop().unwrap_or(Expr::Lit([0; 32]));
            let cond = state.pop().unwrap_or(Expr::Lit([0; 32]));

            if let Expr::Lit(bytes) = &dest {
                let target = u256_to_usize(bytes);
                let fallthrough = state.pc + 1;

                let true_prop = r_evm_verify_lifter::ir::Prop::IsTrue(Box::new(cond.clone()));
                let false_prop = r_evm_verify_lifter::ir::Prop::IsZero(Box::new(cond.clone()));

                // Check feasibility of both branches.
                // Prefer incremental solver (push/pop) over fresh solver.
                let (true_feasible, false_feasible) = if let Some(inc) = &mut *inc_solver_ref {
                    inc.check_branch(&true_prop, &false_prop)
                        .unwrap_or((true, true))
                } else if let Some(s) = solver {
                    let mut true_constraints = state.constraints.clone();
                    true_constraints.push(true_prop.clone());
                    let true_sat = s.check_sat(&true_constraints).unwrap_or(SatResult::Unknown);

                    let mut false_constraints = state.constraints.clone();
                    false_constraints.push(false_prop.clone());
                    let false_sat = s
                        .check_sat(&false_constraints)
                        .unwrap_or(SatResult::Unknown);

                    (true_sat != SatResult::Unsat, false_sat != SatResult::Unsat)
                } else {
                    (true, true)
                };

                match (true_feasible, false_feasible) {
                    (true, true) => {
                        let mut true_state = state.fork();
                        true_state.constraints.push(true_prop);
                        true_state.pc = target;

                        let mut false_state = state.fork();
                        false_state.constraints.push(false_prop);
                        false_state.pc = fallthrough;

                        return Some(ExecutionResult::Fork {
                            true_state,
                            false_state,
                        });
                    }
                    (true, false) => {
                        // Only true branch feasible
                        state.constraints.push(true_prop);
                        state.pc = target;
                        return None; // Continue on this path
                    }
                    (false, true) => {
                        // Only false branch feasible
                        state.constraints.push(false_prop);
                        state.pc = fallthrough;
                        return None; // Continue on this path
                    }
                    (false, false) => {
                        return Some(ExecutionResult::Dead);
                    }
                }
            }
            // Dynamic dest — take fallthrough only
            state
                .constraints
                .push(r_evm_verify_lifter::ir::Prop::IsZero(Box::new(cond)));
        }
        Opcode::JumpDest => { /* no-op */ }
        Opcode::Pc => {
            let mut bytes = [0u8; 32];
            let pc = state.pc;
            bytes[24..].copy_from_slice(&(pc as u64).to_be_bytes());
            state.push_tainted(Expr::Lit(bytes), Taint::Trusted);
        }

        // Terminal
        Opcode::Stop => {
            return Some(ExecutionResult::Returned {
                state: state.clone(),
            });
        }
        Opcode::Return => {
            let _offset = state.pop();
            let _size = state.pop();
            return Some(ExecutionResult::Returned {
                state: state.clone(),
            });
        }
        Opcode::Revert => {
            let _offset = state.pop();
            let _size = state.pop();
            return Some(ExecutionResult::Reverted {
                state: state.clone(),
            });
        }
        Opcode::Invalid => {
            return Some(ExecutionResult::Reverted {
                state: state.clone(),
            });
        }
        Opcode::SelfDestruct => {
            let _addr = state.pop();
            state
                .call_log
                .push(CallEvent::SelfDestruct { offset: state.pc });
            return Some(ExecutionResult::Returned {
                state: state.clone(),
            });
        }

        // Additional arithmetic
        Opcode::SignExtend => {
            let pc = state.pc;
            binary_op(state, |_a, _b| Expr::Var(format!("signextend@{}", pc)));
        }
        Opcode::Byte => {
            let pc = state.pc;
            binary_op(state, |_a, _b| Expr::Var(format!("byte@{}", pc)));
        }
        Opcode::AddMod => {
            // ADDMOD(a, b, N): (a + b) % N
            if let (Some(_a), Some(_b), Some(_n)) = (state.pop(), state.pop(), state.pop()) {
                state.push(Expr::Var(format!("addmod@{}", state.pc)));
            }
        }
        Opcode::MulMod => {
            // MULMOD(a, b, N): (a * b) % N
            if let (Some(_a), Some(_b), Some(_n)) = (state.pop(), state.pop(), state.pop()) {
                state.push(Expr::Var(format!("mulmod@{}", state.pc)));
            }
        }

        // Memory
        Opcode::MStore8 => {
            if let (Some(offset), Some(value)) = (state.pop(), state.pop()) {
                if let Expr::Lit(bytes) = &offset {
                    let off = u256_to_usize(bytes);
                    state.memory.store(off, value);
                }
            }
        }

        // Calldata
        Opcode::CallDataCopy => {
            // CALLDATACOPY(destOffset, offset, size) — copies calldata to memory
            let _dest = state.pop();
            let _offset = state.pop();
            let _size = state.pop();
            // Symbolic: we don't model the actual copy, just consume args
        }

        // Code
        Opcode::CodeSize => {
            let mut bytes = [0u8; 32];
            let size = bytecode.len();
            bytes[24..].copy_from_slice(&(size as u64).to_be_bytes());
            state.push_tainted(Expr::Lit(bytes), Taint::Trusted);
        }
        Opcode::CodeCopy => {
            let _dest = state.pop();
            let _offset = state.pop();
            let _size = state.pop();
        }
        Opcode::ExtCodeSize => {
            let _addr = state.pop();
            state.push(Expr::Var(format!("extcodesize@{}", state.pc)));
        }
        Opcode::ExtCodeCopy => {
            let _addr = state.pop();
            let _dest = state.pop();
            let _offset = state.pop();
            let _size = state.pop();
        }
        Opcode::ExtCodeHash => {
            let _addr = state.pop();
            state.push(Expr::Var(format!("extcodehash@{}", state.pc)));
        }

        // Return data
        Opcode::ReturnDataSize => {
            state.push(Expr::Var(format!("returndatasize@{}", state.pc)));
        }
        Opcode::ReturnDataCopy => {
            let _dest = state.pop();
            let _offset = state.pop();
            let _size = state.pop();
        }

        // Environment
        Opcode::SelfBalance => state.push(Expr::Var(format!("selfbalance@{}", state.pc))),
        Opcode::BaseFee => state.push(Expr::Var(format!("basefee@{}", state.pc))),
        Opcode::PrevRandao => state.push(Expr::Var(format!("prevrandao@{}", state.pc))),

        // Logging — consume args, no stack output
        Opcode::Log(n) => {
            let _offset = state.pop();
            let _size = state.pop();
            for _ in 0..n {
                let _topic = state.pop();
            }
        }

        // Create
        Opcode::Create => {
            let _value = state.pop();
            let _offset = state.pop();
            let _size = state.pop();
            state.push(Expr::Var(format!("create@{}", state.pc)));
        }
        Opcode::Create2 => {
            let _value = state.pop();
            let _offset = state.pop();
            let _size = state.pop();
            let _salt = state.pop();
            state.push(Expr::Var(format!("create2@{}", state.pc)));
        }
        Opcode::CallCode => {
            let _gas = state.pop();
            let addr = state.pop().unwrap_or(Expr::Lit([0; 32]));
            let (value, val_taint) = state
                .pop_tainted()
                .unwrap_or((Expr::Lit([0; 32]), Taint::Unknown));
            let _args_offset = state.pop();
            let _args_size = state.pop();
            let _ret_offset = state.pop();
            let _ret_size = state.pop();
            state.call_log.push(CallEvent::ExternalCall {
                offset: state.pc,
                addr,
                value,
                value_taint: val_taint,
            });
            state.push(Expr::Var(format!("call_success@{}", state.pc)));
        }

        // Sha3/Keccak
        Opcode::Sha3 => {
            let _offset = state.pop();
            let _size = state.pop();
            state.push(Expr::Keccak256(Box::new(Expr::Var(format!(
                "sha3_input@{}",
                state.pc
            )))));
        }

        // Gas / misc
        Opcode::Gas | Opcode::MSize => {
            state.push(Expr::Var(format!("{:?}@{}", opcode, state.pc)));
        }

        // Unhandled — push symbolic placeholder
        _ => {
            // Pop expected inputs and push symbolic output
            state.push(Expr::Var(format!("unhandled_{:?}@{}", opcode, state.pc)));
        }
    }

    // Advance PC past opcode + immediate bytes
    state.pc += 1 + imm_size;
    None
}

fn binary_op(state: &mut SvmState, f: impl FnOnce(Expr, Expr) -> Expr) {
    if let (Some((a, ta)), Some((b, tb))) = (state.pop_tainted(), state.pop_tainted()) {
        let combined = ta.combine(tb);
        state.push_tainted(f(a, b), combined);
    }
}

fn unary_op(state: &mut SvmState, f: impl FnOnce(Expr) -> Expr) {
    if let Some((a, ta)) = state.pop_tainted() {
        state.push_tainted(f(a), ta);
    }
}

fn u256_to_usize(bytes: &[u8; 32]) -> usize {
    // Take last 8 bytes as u64, truncate to usize
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    u64::from_be_bytes(buf) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_push_stop() {
        let bytecode = vec![0x60, 0x42, 0x00]; // PUSH1 0x42, STOP
        let mut state = SvmState::new(1000);
        // Step 1: PUSH1
        assert!(step(&mut state, &bytecode, None).is_none());
        assert_eq!(state.stack_len(), 1);
        // Step 2: STOP
        let result = step(&mut state, &bytecode, None);
        assert!(matches!(result, Some(ExecutionResult::Returned { .. })));
    }

    #[test]
    fn execute_add() {
        let bytecode = vec![0x60, 0x03, 0x60, 0x05, 0x01, 0x00]; // PUSH 3, PUSH 5, ADD, STOP
        let mut state = SvmState::new(1000);
        step(&mut state, &bytecode, None); // PUSH 3
        step(&mut state, &bytecode, None); // PUSH 5
        step(&mut state, &bytecode, None); // ADD
        assert_eq!(state.stack_len(), 1);
        // With expression simplification, 3 + 5 folds to Lit(8)
        let mut expected = [0u8; 32];
        expected[31] = 8;
        assert_eq!(state.stack[0], Expr::Lit(expected));
    }

    #[test]
    fn execute_sstore_logged() {
        // PUSH1 0x42, PUSH1 0x00, SSTORE, STOP
        let bytecode = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];
        let mut state = SvmState::new(1000);
        step(&mut state, &bytecode, None); // PUSH 0x42
        step(&mut state, &bytecode, None); // PUSH 0x00
        step(&mut state, &bytecode, None); // SSTORE
        assert_eq!(state.call_log.len(), 1);
        assert!(matches!(state.call_log[0], CallEvent::StorageWrite { .. }));
    }

    #[test]
    fn execute_jumpi_forks() {
        // PUSH1 0x01 (cond), PUSH1 0x06 (dest), JUMPI, STOP, JUMPDEST, STOP
        let bytecode = vec![0x60, 0x01, 0x60, 0x06, 0x57, 0x00, 0x5B, 0x00];
        let mut state = SvmState::new(1000);
        step(&mut state, &bytecode, None); // PUSH 0x01
        step(&mut state, &bytecode, None); // PUSH 0x06
        let result = step(&mut state, &bytecode, None); // JUMPI
        assert!(matches!(result, Some(ExecutionResult::Fork { .. })));
        if let Some(ExecutionResult::Fork {
            true_state,
            false_state,
        }) = result
        {
            assert_eq!(true_state.pc, 6); // jump target
            assert_eq!(false_state.pc, 5); // fallthrough
            assert_eq!(true_state.constraints.len(), 1);
            assert_eq!(false_state.constraints.len(), 1);
        }
    }

    #[test]
    fn execute_call_logged() {
        // 7x PUSH1 0 + CALL + STOP
        let mut bytecode = Vec::new();
        for _ in 0..7 {
            bytecode.extend_from_slice(&[0x60, 0x00]);
        }
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // STOP

        let mut state = SvmState::new(1000);
        for _ in 0..7 {
            step(&mut state, &bytecode, None);
        }
        step(&mut state, &bytecode, None); // CALL
        assert_eq!(state.call_log.len(), 1);
        assert!(matches!(state.call_log[0], CallEvent::ExternalCall { .. }));
        assert_eq!(state.stack_len(), 1); // success value pushed
    }

    #[test]
    fn jumpi_z3_prunes_infeasible_branch() {
        // Push ISZERO(0) = 1 as condition, then JUMPI.
        // With Z3: condition is concrete 1, so only true branch is feasible.
        // PUSH1 0x00, ISZERO, PUSH1 0x07 (dest), JUMPI, STOP, JUMPDEST, STOP
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0x00
            0x15, // ISZERO → pushes 1
            0x60, 0x07, // PUSH1 0x07 (dest)
            0x57, // JUMPI
            0x00, // STOP (fallthrough, offset 6)
            0x5B, // JUMPDEST (offset 7)
            0x00, // STOP
        ];
        let solver = SolverContext::new();
        let mut state = SvmState::new(1000);
        step(&mut state, &bytecode, Some(&solver)); // PUSH 0
        step(&mut state, &bytecode, Some(&solver)); // ISZERO
        step(&mut state, &bytecode, Some(&solver)); // PUSH 7
        let result = step(&mut state, &bytecode, Some(&solver)); // JUMPI

        // With a concrete condition (IsZero(Lit(0)) = always true),
        // Z3 should prune the false branch and continue on true.
        // The result should be None (continue) with pc = 7.
        assert!(
            result.is_none(),
            "Z3 should prune infeasible branch and continue, got {:?}",
            result
        );
        assert_eq!(
            state.pc, 7,
            "Should jump to target since condition is always true"
        );
    }

    #[test]
    fn jumpi_z3_both_feasible_for_symbolic() {
        // Symbolic condition: CALLDATALOAD(0) is unknown, so both branches are feasible.
        // PUSH1 0, CALLDATALOAD, PUSH1 0x07, JUMPI, STOP, JUMPDEST, STOP
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x35, // CALLDATALOAD → symbolic
            0x60, 0x07, // PUSH1 0x07 (dest)
            0x57, // JUMPI
            0x00, // STOP
            0x5B, // JUMPDEST
            0x00, // STOP
        ];
        let solver = SolverContext::new();
        let mut state = SvmState::new(1000);
        step(&mut state, &bytecode, Some(&solver)); // PUSH 0
        step(&mut state, &bytecode, Some(&solver)); // CALLDATALOAD
        step(&mut state, &bytecode, Some(&solver)); // PUSH 7
        let result = step(&mut state, &bytecode, Some(&solver)); // JUMPI

        assert!(
            matches!(result, Some(ExecutionResult::Fork { .. })),
            "Symbolic condition should fork both branches"
        );
    }
}
