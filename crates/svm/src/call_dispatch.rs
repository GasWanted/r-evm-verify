use crate::state::SvmState;
use crate::taint::Taint;
use r_evm_verify_lifter::ir::Expr;

/// Saved execution frame for cross-contract CALL dispatch.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// PC to resume at in the caller after the callee returns.
    pub return_pc: usize,
    /// The bytecode the caller was executing (so the engine can switch back).
    pub caller_bytecode: Vec<u8>,
    /// Caller's stack at the point of the CALL (before pushing the return value).
    pub caller_stack: Vec<Expr>,
    /// Caller's taint vector, parallel to caller_stack.
    pub caller_taints: Vec<Taint>,
    /// Memory offset where callee return data should be copied.
    pub ret_offset: usize,
    /// Size of return data to copy.
    pub ret_size: usize,
}

pub fn resolve_address(addr_expr: &Expr) -> Option<[u8; 20]> {
    if let Expr::Lit(bytes) = addr_expr {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes[12..32]);
        Some(addr)
    } else {
        None
    }
}

pub fn has_contract(state: &SvmState, addr: &[u8; 20]) -> bool {
    state.contracts.contains_key(addr)
}

pub fn get_bytecode<'a>(state: &'a SvmState, addr: &[u8; 20]) -> Option<&'a Vec<u8>> {
    state.contracts.get(addr)
}
