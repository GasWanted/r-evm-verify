pub mod context;
pub mod fastpath;
pub mod incremental;
pub mod translate;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolverError {
    #[error("Z3 returned unknown")]
    Unknown,
    #[error("Z3 timeout")]
    Timeout,
    #[error("unsupported expression: {0}")]
    Unsupported(String),
}

/// Result of a satisfiability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SatResult {
    Sat,
    Unsat,
    Unknown,
}

/// A concrete assignment for symbolic variables (counterexample).
#[derive(Debug, Clone)]
pub struct Model {
    pub assignments: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Display for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (name, value) in &self.assignments {
            let hex: String = value.iter().map(|b| format!("{:02x}", b)).collect();
            // Trim leading zeros for readability
            let trimmed = hex.trim_start_matches('0');
            let display = if trimmed.is_empty() { "0" } else { trimmed };
            writeln!(f, "  {} = 0x{}", name, display)?;
        }
        Ok(())
    }
}
