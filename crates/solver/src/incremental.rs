use crate::{SatResult, SolverError};
use r_evm_verify_lifter::ir::Prop;

/// Incremental solver that maintains state across JUMPI branches.
/// Uses Z3's push/pop to efficiently add/remove constraints
/// while keeping learned clauses.
pub struct IncrementalSolver<'ctx> {
    solver: z3::Solver<'ctx>,
    ctx: &'ctx z3::Context,
    /// Number of constraints currently asserted (for debugging).
    depth: usize,
}

impl<'ctx> IncrementalSolver<'ctx> {
    pub fn new(ctx: &'ctx z3::Context) -> Self {
        let solver = z3::Solver::new(ctx);
        // Set per-query timeout
        let mut params = z3::Params::new(ctx);
        params.set_u32("timeout", 5000);
        solver.set_params(&params);
        Self {
            solver,
            ctx,
            depth: 0,
        }
    }

    /// Push a scope (before branching). Allows pop() to undo.
    pub fn push(&mut self) {
        self.solver.push();
        self.depth += 1;
    }

    /// Pop a scope (after returning from a branch).
    pub fn pop(&mut self) {
        if self.depth > 0 {
            self.solver.pop(1);
            self.depth -= 1;
        }
    }

    /// Assert a constraint (adds to current scope).
    pub fn assert_prop(&mut self, prop: &Prop) -> Result<(), SolverError> {
        let z3_ast = crate::translate::prop_to_z3(self.ctx, prop)?;
        self.solver.assert(&z3_ast);
        Ok(())
    }

    /// Assert multiple constraints.
    pub fn assert_all(&mut self, props: &[Prop]) -> Result<(), SolverError> {
        for p in props {
            self.assert_prop(p)?;
        }
        Ok(())
    }

    /// Check satisfiability of current constraints.
    pub fn check_sat(&self) -> SatResult {
        match self.solver.check() {
            z3::SatResult::Sat => SatResult::Sat,
            z3::SatResult::Unsat => SatResult::Unsat,
            z3::SatResult::Unknown => SatResult::Unknown,
        }
    }

    /// Check if adding a new constraint would be satisfiable,
    /// without permanently adding it.
    pub fn check_sat_assuming(&mut self, prop: &Prop) -> Result<SatResult, SolverError> {
        self.push();
        self.assert_prop(prop)?;
        let result = self.check_sat();
        self.pop();
        Ok(result)
    }

    /// Check both branches of a JUMPI: returns (true_feasible, false_feasible).
    /// Uses push/pop to avoid rebuilding constraints.
    pub fn check_branch(
        &mut self,
        true_prop: &Prop,
        false_prop: &Prop,
    ) -> Result<(bool, bool), SolverError> {
        // Check true branch
        self.push();
        self.assert_prop(true_prop)?;
        let true_sat = self.check_sat();
        self.pop();

        // Check false branch
        self.push();
        self.assert_prop(false_prop)?;
        let false_sat = self.check_sat();
        self.pop();

        Ok((true_sat != SatResult::Unsat, false_sat != SatResult::Unsat))
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_evm_verify_lifter::ir::Expr;

    #[test]
    fn incremental_push_pop() {
        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut solver = IncrementalSolver::new(&ctx);

        // x > 5
        let x = Expr::Var("x".into());
        let mut five = [0u8; 32];
        five[31] = 5;
        solver
            .assert_prop(&Prop::Gt(Box::new(x.clone()), Box::new(Expr::Lit(five))))
            .unwrap();
        assert_eq!(solver.check_sat(), SatResult::Sat);

        // Push, add x < 3 (should be UNSAT with x > 5)
        solver.push();
        let mut three = [0u8; 32];
        three[31] = 3;
        solver
            .assert_prop(&Prop::Lt(Box::new(x.clone()), Box::new(Expr::Lit(three))))
            .unwrap();
        assert_eq!(solver.check_sat(), SatResult::Unsat);

        // Pop — back to just x > 5
        solver.pop();
        assert_eq!(solver.check_sat(), SatResult::Sat);
    }

    #[test]
    fn check_branch_both_feasible() {
        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut solver = IncrementalSolver::new(&ctx);

        let x = Expr::Var("x".into());
        let zero = Expr::Lit([0; 32]);

        let true_prop = Prop::IsTrue(Box::new(x.clone()));
        let false_prop = Prop::IsZero(Box::new(x));

        let (t, f) = solver.check_branch(&true_prop, &false_prop).unwrap();
        assert!(t, "x != 0 should be feasible");
        assert!(f, "x == 0 should be feasible");
    }

    #[test]
    fn check_branch_one_infeasible() {
        let cfg = z3::Config::new();
        let ctx = z3::Context::new(&cfg);
        let mut solver = IncrementalSolver::new(&ctx);

        // Assert x == 0
        let x = Expr::Var("x".into());
        let zero = Expr::Lit([0; 32]);
        solver
            .assert_prop(&Prop::Eq(Box::new(x.clone()), Box::new(zero)))
            .unwrap();

        let true_prop = Prop::IsTrue(Box::new(x.clone()));
        let false_prop = Prop::IsZero(Box::new(x));

        let (t, f) = solver.check_branch(&true_prop, &false_prop).unwrap();
        assert!(!t, "x != 0 should be infeasible when x == 0");
        assert!(f, "x == 0 should be feasible when x == 0");
    }
}
