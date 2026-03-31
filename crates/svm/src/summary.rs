use r_evm_verify_lifter::ir::{Expr, Prop};

/// Summary of a single function's behavior across all explored paths.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    pub name: String,
    pub preconditions: Vec<Prop>,
    pub reads: Vec<(Expr, Expr)>,
    pub writes: Vec<(Expr, Expr)>,
    pub has_external_call: bool,
    pub modifies_storage: bool,
    pub revert_conditions: Vec<Vec<Prop>>,
    pub success_conditions: Vec<Vec<Prop>>,
}

/// Invariant that must hold before and after every function call.
#[derive(Debug, Clone)]
pub struct Invariant {
    pub name: String,
    pub property: Prop,
}
