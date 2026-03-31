use crate::fastpath::{try_fast_check, FastResult};
use crate::{Model, SatResult, SolverError};
use r_evm_verify_lifter::ir::Prop;

/// Per-thread solver context. Tries fast-path Rust evaluation first,
/// falls back to Z3 for constraints that can't be resolved statically.
pub struct SolverContext {
    ctx: z3::Context,
    /// Number of queries resolved by fast path (for stats).
    pub fast_hits: std::cell::Cell<u64>,
    /// Number of queries that required Z3.
    pub z3_calls: std::cell::Cell<u64>,
}

impl SolverContext {
    pub fn new() -> Self {
        let mut cfg = z3::Config::new();
        cfg.set_param_value("timeout", "5000"); // 2 second Z3 query timeout
        let ctx = z3::Context::new(&cfg);
        Self {
            ctx,
            fast_hits: std::cell::Cell::new(0),
            z3_calls: std::cell::Cell::new(0),
        }
    }

    /// Check if a set of constraints is satisfiable.
    /// Tries fast-path evaluation first, falls back to Z3.
    pub fn check_sat(&self, constraints: &[Prop]) -> Result<SatResult, SolverError> {
        // Fast path: try to resolve without Z3.
        match try_fast_check(constraints) {
            FastResult::Sat => {
                self.fast_hits.set(self.fast_hits.get() + 1);
                return Ok(SatResult::Sat);
            }
            FastResult::Unsat => {
                self.fast_hits.set(self.fast_hits.get() + 1);
                return Ok(SatResult::Unsat);
            }
            FastResult::Unknown => {
                // Fall through to Z3.
            }
        }

        // Z3 path.
        self.z3_calls.set(self.z3_calls.get() + 1);
        let solver = z3::Solver::new(&self.ctx);
        for c in constraints {
            let z3_ast = crate::translate::prop_to_z3(&self.ctx, c)?;
            solver.assert(&z3_ast);
        }
        match solver.check() {
            z3::SatResult::Sat => Ok(SatResult::Sat),
            z3::SatResult::Unsat => Ok(SatResult::Unsat),
            z3::SatResult::Unknown => Ok(SatResult::Unknown),
        }
    }

    /// Check satisfiability and extract a model if SAT.
    pub fn check_sat_model(
        &self,
        constraints: &[Prop],
    ) -> Result<(SatResult, Option<Model>), SolverError> {
        // Fast path for definite UNSAT.
        if let FastResult::Unsat = try_fast_check(constraints) {
            self.fast_hits.set(self.fast_hits.get() + 1);
            return Ok((SatResult::Unsat, None));
        }

        // Need Z3 for model extraction.
        self.z3_calls.set(self.z3_calls.get() + 1);
        let solver = z3::Solver::new(&self.ctx);
        for c in constraints {
            let z3_ast = crate::translate::prop_to_z3(&self.ctx, c)?;
            solver.assert(&z3_ast);
        }
        match solver.check() {
            z3::SatResult::Sat => {
                let model = solver.get_model().map(|m| self.extract_model(&m));
                Ok((SatResult::Sat, model))
            }
            z3::SatResult::Unsat => Ok((SatResult::Unsat, None)),
            z3::SatResult::Unknown => Ok((SatResult::Unknown, None)),
        }
    }

    /// Extract a Model from a Z3 model by evaluating well-known symbolic variables.
    fn extract_model(&self, z3_model: &z3::Model) -> Model {
        let well_known = [
            "caller",
            "callvalue",
            "calldatasize",
            "origin",
            "timestamp",
            "blocknumber",
            "chainid",
        ];

        let mut assignments = Vec::new();

        for name in &well_known {
            let bv = z3::ast::BV::new_const(&self.ctx, *name, 256);
            if let Some(val) = z3_model.eval(&bv, true) {
                let val_str = val.to_string();
                // Z3 outputs "#x..." for bitvectors — extract the hex
                if let Some(hex) = val_str.strip_prefix("#x") {
                    if let Ok(bytes) = hex_to_bytes(hex) {
                        assignments.push((name.to_string(), bytes));
                    }
                } else if let Some(_hex) = val_str.strip_prefix("#b") {
                    // Binary format — just store the string
                    assignments.push((name.to_string(), val_str.into_bytes()));
                } else {
                    assignments.push((name.to_string(), val_str.into_bytes()));
                }
            }
        }

        // Also extract calldataload values (calldataload@0, calldataload@4, etc.)
        // These are uninterpreted function applications, harder to enumerate.
        // For now, try common offsets.
        for offset in [0u64, 4, 36, 68, 100] {
            let _name = format!("cd_{}", offset);
            let func = z3::FuncDecl::new(
                &self.ctx,
                "calldataload",
                &[&z3::Sort::bitvector(&self.ctx, 256)],
                &z3::Sort::bitvector(&self.ctx, 256),
            );
            let offset_bv = z3::ast::BV::from_u64(&self.ctx, offset, 256);
            let app = func.apply(&[&offset_bv]);
            if let Some(val) = z3_model.eval(&app, true) {
                let val_str = val.to_string();
                if let Some(hex) = val_str.strip_prefix("#x") {
                    if let Ok(bytes) = hex_to_bytes(hex) {
                        if bytes != vec![0u8; 32] {
                            // Only include non-zero values
                            assignments.push((format!("calldata[{}]", offset), bytes));
                        }
                    }
                }
            }
        }

        Model { assignments }
    }

    /// Get a reference to the Z3 context.
    pub fn z3_ctx(&self) -> &z3::Context {
        &self.ctx
    }

    /// Check constraints and return a counterexample if SAT.
    /// Convenience method for property checking.
    pub fn get_counterexample(&self, constraints: &[Prop]) -> Result<Option<Model>, SolverError> {
        match self.check_sat_model(constraints)? {
            (SatResult::Sat, Some(model)) => Ok(Some(model)),
            _ => Ok(None),
        }
    }

    /// Return (fast_hits, z3_calls) stats.
    pub fn stats(&self) -> (u64, u64) {
        (self.fast_hits.get(), self.z3_calls.get())
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i.min(hex.len()).max(i + 2)], 16))
        .collect()
}

impl Default for SolverContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r_evm_verify_lifter::ir::{Expr, Prop};

    #[test]
    fn trivially_sat_uses_fast_path() {
        let ctx = SolverContext::new();
        let result = ctx.check_sat(&[Prop::Bool(true)]).unwrap();
        assert_eq!(result, SatResult::Sat);
        assert_eq!(ctx.fast_hits.get(), 1);
        assert_eq!(ctx.z3_calls.get(), 0);
    }

    #[test]
    fn trivially_unsat_uses_fast_path() {
        let ctx = SolverContext::new();
        let result = ctx.check_sat(&[Prop::Bool(false)]).unwrap();
        assert_eq!(result, SatResult::Unsat);
        assert_eq!(ctx.fast_hits.get(), 1);
        assert_eq!(ctx.z3_calls.get(), 0);
    }

    #[test]
    fn symbolic_falls_through_to_z3() {
        let ctx = SolverContext::new();
        let x = Expr::Var("x".into());
        let zero = Expr::Lit([0; 32]);
        let mut ten = [0u8; 32];
        ten[31] = 10;
        let ten_expr = Expr::Lit(ten);
        let constraints = vec![
            Prop::Gt(Box::new(x.clone()), Box::new(zero)),
            Prop::Lt(Box::new(x), Box::new(ten_expr)),
        ];
        let result = ctx.check_sat(&constraints).unwrap();
        assert_eq!(result, SatResult::Sat);
        assert_eq!(ctx.fast_hits.get(), 0);
        assert_eq!(ctx.z3_calls.get(), 1);
    }

    #[test]
    fn concrete_comparison_uses_fast_path() {
        let ctx = SolverContext::new();
        let mut five = [0u8; 32];
        five[31] = 5;
        let mut ten = [0u8; 32];
        ten[31] = 10;
        // 5 < 10 → Sat, resolved by fast path
        let constraints = vec![Prop::Lt(
            Box::new(Expr::Lit(five)),
            Box::new(Expr::Lit(ten)),
        )];
        let result = ctx.check_sat(&constraints).unwrap();
        assert_eq!(result, SatResult::Sat);
        assert_eq!(ctx.fast_hits.get(), 1);
        assert_eq!(ctx.z3_calls.get(), 0);
    }
}
