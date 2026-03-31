use crate::state::{CallEvent, SvmState};
use crate::taint::Taint;
use r_evm_verify_lifter::ir::{Expr, Prop};
use r_evm_verify_solver::context::SolverContext;

/// Check the execution state for reentrancy: CALL before SSTORE.
pub fn check_reentrancy(state: &SvmState) -> Option<ReentrancyFinding> {
    let mut last_call_offset = None;

    for event in &state.call_log {
        match event {
            CallEvent::ExternalCall { offset, .. } | CallEvent::DelegateCall { offset, .. } => {
                last_call_offset = Some(*offset);
            }
            CallEvent::StorageWrite { offset, .. } => {
                if let Some(call_off) = last_call_offset {
                    return Some(ReentrancyFinding {
                        call_offset: call_off,
                        sstore_offset: *offset,
                    });
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct ReentrancyFinding {
    pub call_offset: usize,
    pub sstore_offset: usize,
}

/// Check if an ADD expression can overflow given path constraints.
/// Returns a counterexample Model if overflow is possible, None if safe.
pub fn check_add_overflow(
    a: &Expr,
    b: &Expr,
    constraints: &[Prop],
    solver: &SolverContext,
) -> Option<r_evm_verify_solver::Model> {
    let sum = Expr::Add(Box::new(a.clone()), Box::new(b.clone()));
    let overflow_prop = Prop::Lt(Box::new(sum), Box::new(a.clone()));

    let mut all_constraints = constraints.to_vec();
    all_constraints.push(overflow_prop);

    solver.get_counterexample(&all_constraints).ok().flatten()
}

/// Check if a MUL expression can overflow given path constraints.
/// Returns a counterexample Model if overflow is possible, None if safe.
pub fn check_mul_overflow(
    a: &Expr,
    b: &Expr,
    constraints: &[Prop],
    solver: &SolverContext,
) -> Option<r_evm_verify_solver::Model> {
    let product = Expr::Mul(Box::new(a.clone()), Box::new(b.clone()));
    let div_back = Expr::Div(Box::new(product), Box::new(a.clone()));
    let not_equal = Prop::Not(Box::new(Prop::Eq(Box::new(div_back), Box::new(b.clone()))));
    let a_nonzero = Prop::Not(Box::new(Prop::IsZero(Box::new(a.clone()))));

    let mut all_constraints = constraints.to_vec();
    all_constraints.push(a_nonzero);
    all_constraints.push(not_equal);

    solver.get_counterexample(&all_constraints).ok().flatten()
}

/// Check if a completed path modifies state without any constraint on msg.sender.
/// Returns Some if the path has SSTORE but no CALLER-dependent constraint.
pub fn check_access_control(state: &SvmState) -> Option<AccessControlFinding> {
    // Collect all storage writes.
    let sstores: Vec<_> = state
        .call_log
        .iter()
        .filter_map(|e| match e {
            CallEvent::StorageWrite {
                offset,
                slot,
                value,
                value_taint,
            } => Some((*offset, slot, value, *value_taint)),
            _ => None,
        })
        .collect();

    if sstores.is_empty() {
        return None;
    }

    // Does any path constraint reference CALLER (msg.sender)?
    let has_caller_check = state.constraints.iter().any(prop_references_caller);
    if has_caller_check {
        return None;
    }

    // If ALL storage writes target slots derived from CALLER
    // (e.g., mapping(address => uint) writes to keccak256(caller, base_slot)),
    // this is a self-modifying pattern (deposit/transfer) — not an access control issue.
    let all_slots_use_caller = sstores
        .iter()
        .all(|(_, slot, _, _)| expr_references_caller(slot));
    if all_slots_use_caller {
        return None;
    }

    // Also skip if the storage slot computation involves caller anywhere
    // in the write value (e.g., balances[msg.sender] += msg.value).
    // Check: does the slot expression contain any keccak that references caller?
    let all_values_use_caller = sstores
        .iter()
        .all(|(_, _, value, _)| expr_references_caller(value));
    if all_values_use_caller {
        return None;
    }

    // If the path has no external call and no selfdestruct, it's likely
    // a benign state update (deposit, transfer). Only flag paths that
    // have dangerous operations (CALL with value, SELFDESTRUCT) without auth.
    let has_dangerous_op = state.call_log.iter().any(|e| {
        matches!(
            e,
            CallEvent::ExternalCall { .. }
                | CallEvent::DelegateCall { .. }
                | CallEvent::SelfDestruct { .. }
        )
    });
    if !has_dangerous_op {
        return None;
    }

    let sstore_offset = sstores.first().map(|(off, _, _, _)| *off).unwrap_or(0);
    Some(AccessControlFinding {
        offset: sstore_offset,
    })
}

/// Check for unprotected ETH transfers — external calls sending value without auth.
pub fn check_unprotected_call(state: &SvmState) -> Option<AccessControlFinding> {
    // Does any path constraint reference CALLER?
    let has_caller_check = state.constraints.iter().any(prop_references_caller);
    if has_caller_check {
        return None;
    }

    // Is there an external call that could send ETH?
    for event in &state.call_log {
        if let CallEvent::ExternalCall { offset, value, .. } = event {
            // If value is not zero (or symbolic), flag it
            if !matches!(value, Expr::Lit(b) if *b == [0u8; 32]) {
                return Some(AccessControlFinding { offset: *offset });
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct AccessControlFinding {
    pub offset: usize,
}

/// Check for delegatecall to an address that could be attacker-controlled.
/// Returns Some if the path contains a DELEGATECALL with a symbolic (non-constant) address.
pub fn check_delegatecall(state: &SvmState) -> Option<DelegatecallFinding> {
    for event in &state.call_log {
        if let CallEvent::DelegateCall { offset, addr } = event {
            // If addr is not a literal (i.e., it's symbolic/user-controlled), flag it
            if !matches!(addr, Expr::Lit(_)) {
                return Some(DelegatecallFinding { offset: *offset });
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct DelegatecallFinding {
    pub offset: usize,
}

/// Check for tx.origin usage in authentication.
/// Only flag when ORIGIN is actually used in a path constraint (comparison/require).
pub fn check_tx_origin(state: &SvmState) -> Option<TxOriginFinding> {
    // Check if any constraint references Origin (not just that ORIGIN was pushed)
    let origin_in_constraints = state.constraints.iter().any(|p| prop_references_origin(p));
    if !origin_in_constraints {
        return None;
    }

    for event in &state.call_log {
        if let CallEvent::TxOriginCheck { offset } = event {
            return Some(TxOriginFinding { offset: *offset });
        }
    }
    None
}

fn prop_references_origin(prop: &Prop) -> bool {
    match prop {
        Prop::Bool(_) => false,
        Prop::IsTrue(e) | Prop::IsZero(e) => expr_references_origin(e),
        Prop::Eq(a, b) | Prop::Lt(a, b) | Prop::Gt(a, b) => {
            expr_references_origin(a) || expr_references_origin(b)
        }
        Prop::And(a, b) | Prop::Or(a, b) => prop_references_origin(a) || prop_references_origin(b),
        Prop::Not(a) => prop_references_origin(a),
    }
}

fn expr_references_origin(expr: &Expr) -> bool {
    match expr {
        Expr::Origin => true,
        Expr::Lit(_)
        | Expr::Var(_)
        | Expr::Caller
        | Expr::CallValue
        | Expr::CallDataSize
        | Expr::Address
        | Expr::GasPrice
        | Expr::Coinbase
        | Expr::Timestamp
        | Expr::Number
        | Expr::GasLimit
        | Expr::ChainId => false,
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
        | Expr::Sar(a, b) => expr_references_origin(a) || expr_references_origin(b),
        Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
            expr_references_origin(a) || expr_references_origin(b) || expr_references_origin(c)
        }
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::Keccak256(a)
        | Expr::SLoad(a)
        | Expr::MLoad(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => expr_references_origin(a),
        Expr::Ite(_, a, b) => expr_references_origin(a) || expr_references_origin(b),
    }
}

#[derive(Debug, Clone)]
pub struct TxOriginFinding {
    pub offset: usize,
}

/// Check if SELFDESTRUCT is reachable on this path.
pub fn check_selfdestruct(state: &SvmState) -> Option<SelfDestructFinding> {
    for event in &state.call_log {
        if let CallEvent::SelfDestruct { offset } = event {
            return Some(SelfDestructFinding { offset: *offset });
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct SelfDestructFinding {
    pub offset: usize,
}

/// Check for potential oracle manipulation: SLOAD values used in arithmetic
/// that determines CALL value or SSTORE amount without bounds checking.
/// This flags paths where an externally-controlled storage value (price oracle)
/// flows into a transfer amount.
pub fn check_oracle_manipulation(state: &SvmState) -> Option<OracleManipulationFinding> {
    // Look for external calls where the value sent depends on an SLOAD
    // and the value taint is Untrusted or Unknown (skip Trusted internal flows).
    for event in &state.call_log {
        if let CallEvent::ExternalCall {
            offset,
            value,
            value_taint,
            ..
        } = event
        {
            if expr_depends_on_sload(value) && *value_taint != Taint::Trusted {
                return Some(OracleManipulationFinding { offset: *offset });
            }
        }
    }
    // Also check storage writes where the value depends on SLOAD (price-based logic)
    // Only flag when the value has untrusted or unknown taint (not pure Trusted→SSTORE).
    for event in &state.call_log {
        if let CallEvent::StorageWrite {
            offset,
            value,
            value_taint,
            ..
        } = event
        {
            if expr_depends_on_sload(value)
                && expr_depends_on_sload_and_calldata(value)
                && *value_taint != Taint::Trusted
            {
                return Some(OracleManipulationFinding { offset: *offset });
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct OracleManipulationFinding {
    pub offset: usize,
}

/// Check if an expression tree contains SLOAD (reads from storage = external data).
fn expr_depends_on_sload(expr: &Expr) -> bool {
    match expr {
        Expr::SLoad(_) => true,
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::SDiv(a, b)
        | Expr::Mod(a, b)
        | Expr::SMod(a, b)
        | Expr::Exp(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Shr(a, b)
        | Expr::Sar(a, b)
        | Expr::Lt(a, b)
        | Expr::Gt(a, b)
        | Expr::SLt(a, b)
        | Expr::SGt(a, b)
        | Expr::Eq(a, b) => expr_depends_on_sload(a) || expr_depends_on_sload(b),
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::Keccak256(a)
        | Expr::MLoad(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => expr_depends_on_sload(a),
        _ => false,
    }
}

/// Check if expression depends on both SLOAD and calldata (attacker-influenced price * amount).
fn expr_depends_on_sload_and_calldata(expr: &Expr) -> bool {
    expr_depends_on_sload(expr) && expr_depends_on_calldata(expr)
}

fn expr_depends_on_calldata(expr: &Expr) -> bool {
    match expr {
        Expr::CallDataLoad(_) | Expr::CallDataSize => true,
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::SDiv(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Shl(a, b)
        | Expr::Shr(a, b)
        | Expr::Lt(a, b)
        | Expr::Gt(a, b)
        | Expr::Eq(a, b) => expr_depends_on_calldata(a) || expr_depends_on_calldata(b),
        Expr::Not(a) | Expr::IsZero(a) | Expr::Keccak256(a) | Expr::MLoad(a) | Expr::Balance(a) => {
            expr_depends_on_calldata(a)
        }
        _ => false,
    }
}

/// Check if a Prop references Expr::Caller anywhere in its tree.
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

/// Check if an Expr contains Expr::Caller.
fn expr_references_caller(expr: &Expr) -> bool {
    match expr {
        Expr::Caller => true,
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
        Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
            expr_references_caller(a) || expr_references_caller(b) || expr_references_caller(c)
        }
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::Keccak256(a)
        | Expr::SLoad(a)
        | Expr::MLoad(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => expr_references_caller(a),
        Expr::Ite(_, a, b) => expr_references_caller(a) || expr_references_caller(b),
    }
}

// ---------------------------------------------------------------------------
// New detectors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UncheckedReturnFinding {
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct ArbitrarySendFinding {
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct MsgValueLoopFinding {
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct TimestampFinding {
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct PrecisionLossFinding;

/// A low-level CALL return value that is never checked (popped and ignored).
/// The SVM tracks this: if a CALL result is on the stack and gets POPped without
/// being in a JUMPI condition, it's unchecked.
pub fn check_unchecked_call_return(state: &SvmState) -> Option<UncheckedReturnFinding> {
    // Check if any external call happened but the path doesn't have a constraint
    // that references a call_success variable (meaning the return was checked)
    for event in &state.call_log {
        if let CallEvent::ExternalCall { offset, .. } = event {
            let call_var = format!("call_success@{}", offset);
            let return_checked = state
                .constraints
                .iter()
                .any(|p| prop_mentions_var(p, &call_var));
            if !return_checked {
                return Some(UncheckedReturnFinding { offset: *offset });
            }
        }
    }
    None
}

/// External call sends ETH to an address derived from calldata without validation.
pub fn check_arbitrary_send(state: &SvmState) -> Option<ArbitrarySendFinding> {
    for event in &state.call_log {
        if let CallEvent::ExternalCall {
            offset,
            addr,
            value,
            ..
        } = event
        {
            // Skip zero-value calls
            if matches!(value, Expr::Lit(b) if *b == [0u8; 32]) {
                continue;
            }
            // Flag if addr depends on calldata (attacker-controlled destination)
            if expr_depends_on_calldata(addr) {
                return Some(ArbitrarySendFinding { offset: *offset });
            }
        }
    }
    None
}

/// If msg.value is read multiple times in a path with loop-like patterns,
/// it may be counted multiple times.
pub fn check_msg_value_in_loop(state: &SvmState) -> Option<MsgValueLoopFinding> {
    // Count how many times CallValue appears in the call_log values
    let mut callvalue_count = 0;
    for event in &state.call_log {
        if let CallEvent::ExternalCall { value, .. } = event {
            if expr_references_callvalue(value) {
                callvalue_count += 1;
            }
        }
    }
    if callvalue_count > 1 {
        return Some(MsgValueLoopFinding {
            count: callvalue_count,
        });
    }
    None
}

/// Block timestamp or block number used in financial calculations.
pub fn check_timestamp_dependence(state: &SvmState) -> Option<TimestampFinding> {
    for event in &state.call_log {
        if let CallEvent::StorageWrite { offset, value, .. } = event {
            if expr_references_timestamp(value) {
                return Some(TimestampFinding { offset: *offset });
            }
        }
    }
    None
}

/// Detects patterns like (a / b) * c where precision is lost.
pub fn check_divide_before_multiply(state: &SvmState) -> Option<PrecisionLossFinding> {
    // Check expressions on the stack for Mul(Div(...), ...)
    for expr in &state.stack {
        if has_divide_before_multiply(expr) {
            return Some(PrecisionLossFinding);
        }
    }
    // Also check values being written to storage
    for event in &state.call_log {
        if let CallEvent::StorageWrite { value, .. } = event {
            if has_divide_before_multiply(value) {
                return Some(PrecisionLossFinding);
            }
        }
    }
    None
}

fn has_divide_before_multiply(expr: &Expr) -> bool {
    match expr {
        Expr::Mul(a, b) => {
            matches!(**a, Expr::Div(_, _))
                || matches!(**b, Expr::Div(_, _))
                || has_divide_before_multiply(a)
                || has_divide_before_multiply(b)
        }
        Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Div(a, b) => {
            has_divide_before_multiply(a) || has_divide_before_multiply(b)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Helper functions for new detectors
// ---------------------------------------------------------------------------

fn prop_mentions_var(prop: &Prop, var_name: &str) -> bool {
    match prop {
        Prop::Bool(_) => false,
        Prop::IsTrue(e) | Prop::IsZero(e) => expr_mentions_var(e, var_name),
        Prop::Eq(a, b) | Prop::Lt(a, b) | Prop::Gt(a, b) => {
            expr_mentions_var(a, var_name) || expr_mentions_var(b, var_name)
        }
        Prop::And(a, b) | Prop::Or(a, b) => {
            prop_mentions_var(a, var_name) || prop_mentions_var(b, var_name)
        }
        Prop::Not(a) => prop_mentions_var(a, var_name),
    }
}

fn expr_mentions_var(expr: &Expr, var_name: &str) -> bool {
    match expr {
        Expr::Var(name) => name == var_name,
        Expr::Add(a, b)
        | Expr::Sub(a, b)
        | Expr::Mul(a, b)
        | Expr::Div(a, b)
        | Expr::SDiv(a, b)
        | Expr::Mod(a, b)
        | Expr::SMod(a, b)
        | Expr::Exp(a, b)
        | Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Xor(a, b)
        | Expr::Eq(a, b)
        | Expr::Lt(a, b)
        | Expr::Gt(a, b)
        | Expr::SLt(a, b)
        | Expr::SGt(a, b)
        | Expr::Shl(a, b)
        | Expr::Shr(a, b)
        | Expr::Sar(a, b) => expr_mentions_var(a, var_name) || expr_mentions_var(b, var_name),
        Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
            expr_mentions_var(a, var_name)
                || expr_mentions_var(b, var_name)
                || expr_mentions_var(c, var_name)
        }
        Expr::Not(a)
        | Expr::IsZero(a)
        | Expr::SLoad(a)
        | Expr::Keccak256(a)
        | Expr::MLoad(a)
        | Expr::CallDataLoad(a)
        | Expr::Balance(a)
        | Expr::BlockHash(a) => expr_mentions_var(a, var_name),
        Expr::Ite(_, a, b) => expr_mentions_var(a, var_name) || expr_mentions_var(b, var_name),
        _ => false,
    }
}

fn expr_references_callvalue(expr: &Expr) -> bool {
    match expr {
        Expr::CallValue => true,
        Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b) | Expr::Div(a, b) => {
            expr_references_callvalue(a) || expr_references_callvalue(b)
        }
        _ => false,
    }
}

fn expr_references_timestamp(expr: &Expr) -> bool {
    match expr {
        Expr::Timestamp | Expr::Number => true,
        Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b) | Expr::Div(a, b) => {
            expr_references_timestamp(a) || expr_references_timestamp(b)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reentrancy_detected() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::ExternalCall {
            offset: 10,
            addr: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        state.call_log.push(CallEvent::StorageWrite {
            offset: 20,
            slot: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        let finding = check_reentrancy(&state);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.call_offset, 10);
        assert_eq!(f.sstore_offset, 20);
    }

    #[test]
    fn no_reentrancy_sstore_before_call() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::StorageWrite {
            offset: 10,
            slot: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        state.call_log.push(CallEvent::ExternalCall {
            offset: 20,
            addr: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        assert!(check_reentrancy(&state).is_none());
    }

    #[test]
    fn no_reentrancy_no_call() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::StorageWrite {
            offset: 10,
            slot: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        assert!(check_reentrancy(&state).is_none());
    }

    #[test]
    fn add_overflow_symbolic() {
        let solver = SolverContext::new();
        let a = Expr::Var("a".into());
        let b = Expr::Var("b".into());
        // No constraints — overflow is possible for unconstrained inputs
        let result = check_add_overflow(&a, &b, &[], &solver);
        assert!(result.is_some(), "Should find overflow counterexample");
    }

    #[test]
    fn add_overflow_small_constants() {
        let solver = SolverContext::new();
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 1;
        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 2;
        let a = Expr::Lit(a_bytes);
        let b = Expr::Lit(b_bytes);
        // 1 + 2 cannot overflow
        assert!(check_add_overflow(&a, &b, &[], &solver).is_none());
    }

    #[test]
    fn add_overflow_constrained_safe() {
        let solver = SolverContext::new();
        let a = Expr::Var("a".into());
        let b = Expr::Var("b".into());
        let mut hundred = [0u8; 32];
        hundred[31] = 100;
        let constraints = vec![
            Prop::Lt(Box::new(a.clone()), Box::new(Expr::Lit(hundred))),
            Prop::Lt(Box::new(b.clone()), Box::new(Expr::Lit(hundred))),
        ];
        assert!(check_add_overflow(&a, &b, &constraints, &solver).is_none());
    }

    #[test]
    fn mul_overflow_symbolic() {
        let solver = SolverContext::new();
        let mut large = [0u8; 32];
        large[0] = 0xFF; // Large but concrete values — Z3 can solve this quickly
        let mut two = [0u8; 32];
        two[31] = 2;
        let a = Expr::Lit(large);
        let b = Expr::Lit(two);
        // 0xFF00..00 * 2 overflows
        assert!(check_mul_overflow(&a, &b, &[], &solver).is_some());
    }

    #[test]
    fn access_control_missing() {
        let mut state = SvmState::new(1000);
        // SSTORE + CALL without any CALLER constraint → access control issue
        state.call_log.push(CallEvent::ExternalCall {
            offset: 5,
            addr: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        state.call_log.push(CallEvent::StorageWrite {
            offset: 10,
            slot: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Untrusted,
        });
        assert!(check_access_control(&state).is_some());
    }

    #[test]
    fn access_control_present() {
        let mut state = SvmState::new(1000);
        // SSTORE with a CALLER constraint in path conditions
        state.constraints.push(Prop::Eq(
            Box::new(Expr::Caller),
            Box::new(Expr::Var("owner".into())),
        ));
        state.call_log.push(CallEvent::StorageWrite {
            offset: 10,
            slot: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        assert!(check_access_control(&state).is_none());
    }

    #[test]
    fn access_control_no_sstore() {
        let state = SvmState::new(1000);
        // No SSTORE → no access control issue
        assert!(check_access_control(&state).is_none());
    }

    #[test]
    fn unchecked_return_detected() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::ExternalCall {
            offset: 42,
            addr: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        // No constraint referencing call_success@42 → unchecked
        let finding = check_unchecked_call_return(&state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().offset, 42);
    }

    #[test]
    fn unchecked_return_safe_when_checked() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::ExternalCall {
            offset: 42,
            addr: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        // Constraint references the call return variable
        state
            .constraints
            .push(Prop::IsTrue(Box::new(Expr::Var("call_success@42".into()))));
        assert!(check_unchecked_call_return(&state).is_none());
    }

    #[test]
    fn arbitrary_send_detected() {
        let mut state = SvmState::new(1000);
        let mut one = [0u8; 32];
        one[31] = 1;
        state.call_log.push(CallEvent::ExternalCall {
            offset: 50,
            addr: Expr::CallDataLoad(Box::new(Expr::Lit([0; 32]))),
            value: Expr::Lit(one),
            value_taint: Taint::Untrusted,
        });
        let finding = check_arbitrary_send(&state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().offset, 50);
    }

    #[test]
    fn arbitrary_send_zero_value_safe() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::ExternalCall {
            offset: 50,
            addr: Expr::CallDataLoad(Box::new(Expr::Lit([0; 32]))),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        assert!(check_arbitrary_send(&state).is_none());
    }

    #[test]
    fn msg_value_loop_detected() {
        let mut state = SvmState::new(1000);
        // Two external calls both referencing CallValue → loop pattern
        state.call_log.push(CallEvent::ExternalCall {
            offset: 10,
            addr: Expr::Lit([0; 32]),
            value: Expr::CallValue,
            value_taint: Taint::Untrusted,
        });
        state.call_log.push(CallEvent::ExternalCall {
            offset: 20,
            addr: Expr::Lit([0; 32]),
            value: Expr::CallValue,
            value_taint: Taint::Untrusted,
        });
        let finding = check_msg_value_in_loop(&state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().count, 2);
    }

    #[test]
    fn msg_value_loop_single_safe() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::ExternalCall {
            offset: 10,
            addr: Expr::Lit([0; 32]),
            value: Expr::CallValue,
            value_taint: Taint::Untrusted,
        });
        assert!(check_msg_value_in_loop(&state).is_none());
    }

    #[test]
    fn timestamp_dependence_detected() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::StorageWrite {
            offset: 30,
            slot: Expr::Lit([0; 32]),
            value: Expr::Add(Box::new(Expr::Timestamp), Box::new(Expr::Lit([0; 32]))),
            value_taint: Taint::Unknown,
        });
        let finding = check_timestamp_dependence(&state);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().offset, 30);
    }

    #[test]
    fn timestamp_dependence_safe() {
        let mut state = SvmState::new(1000);
        state.call_log.push(CallEvent::StorageWrite {
            offset: 30,
            slot: Expr::Lit([0; 32]),
            value: Expr::Lit([0; 32]),
            value_taint: Taint::Unknown,
        });
        assert!(check_timestamp_dependence(&state).is_none());
    }

    #[test]
    fn divide_before_multiply_detected() {
        let mut state = SvmState::new(1000);
        // (a / b) * c on the stack
        let expr = Expr::Mul(
            Box::new(Expr::Div(
                Box::new(Expr::Var("a".into())),
                Box::new(Expr::Var("b".into())),
            )),
            Box::new(Expr::Var("c".into())),
        );
        state.stack.push(expr);
        state.taints.push(Taint::Unknown);
        assert!(check_divide_before_multiply(&state).is_some());
    }

    #[test]
    fn divide_before_multiply_safe() {
        let mut state = SvmState::new(1000);
        // a * b / c — multiply first, safe
        let expr = Expr::Div(
            Box::new(Expr::Mul(
                Box::new(Expr::Var("a".into())),
                Box::new(Expr::Var("b".into())),
            )),
            Box::new(Expr::Var("c".into())),
        );
        state.stack.push(expr);
        state.taints.push(Taint::Unknown);
        assert!(check_divide_before_multiply(&state).is_none());
    }
}
