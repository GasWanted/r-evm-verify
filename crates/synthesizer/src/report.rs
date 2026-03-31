use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Reentrancy,
    Overflow,
    AccessControl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Byte offset in the bytecode.
    pub offset: usize,
    /// 4-byte function selector if identifiable.
    pub function_selector: Option<[u8; 4]>,
    /// Human-readable function name if resolved.
    pub function_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterexample {
    /// Concrete values that trigger the violation.
    pub inputs: Vec<(String, String)>,
    /// Sequence of calls leading to the violation.
    pub call_trace: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,
    pub location: Location,
    pub counterexample: Option<Counterexample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub duration_ms: u64,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Informational => write!(f, "INFO"),
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Reentrancy => write!(f, "Reentrancy"),
            Category::Overflow => write!(f, "Integer Overflow"),
            Category::AccessControl => write!(f, "Access Control"),
        }
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_clean() {
            writeln!(f, "No issues found ({} ms)", self.duration_ms)?;
        } else {
            writeln!(
                f,
                "Found {} issue(s) ({} ms):",
                self.findings.len(),
                self.duration_ms
            )?;
            for (i, finding) in self.findings.iter().enumerate() {
                writeln!(
                    f,
                    "\n  {}. [{}] {} — {}",
                    i + 1,
                    finding.severity,
                    finding.category,
                    finding.title
                )?;
                writeln!(f, "     {}", finding.description)?;
                if let Some(name) = &finding.location.function_name {
                    writeln!(
                        f,
                        "     in {} (offset 0x{:04x})",
                        name, finding.location.offset
                    )?;
                } else {
                    writeln!(
                        f,
                        "     at bytecode offset 0x{:04x}",
                        finding.location.offset
                    )?;
                }
                if let Some(cex) = &finding.counterexample {
                    if !cex.inputs.is_empty() {
                        writeln!(f, "     Counterexample:")?;
                        for (name, value) in &cex.inputs {
                            writeln!(f, "       {} = {}", name, value)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_severity() {
        let finding = Finding {
            severity: Severity::High,
            category: Category::Reentrancy,
            title: "Reentrancy in withdraw()".to_string(),
            description: "External call before state update".to_string(),
            location: Location {
                offset: 42,
                function_selector: Some([0xa9, 0x05, 0x9c, 0xbb]),
                function_name: Some("transfer(address,uint256)".into()),
            },
            counterexample: None,
        };
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn report_empty() {
        let report = Report {
            findings: vec![],
            duration_ms: 123,
        };
        assert!(report.is_clean());
    }

    #[test]
    fn report_with_finding() {
        let report = Report {
            findings: vec![Finding {
                severity: Severity::Medium,
                category: Category::Overflow,
                title: "Overflow in add()".to_string(),
                description: "Unchecked addition".to_string(),
                location: Location {
                    offset: 10,
                    function_selector: None,
                    function_name: None,
                },
                counterexample: None,
            }],
            duration_ms: 50,
        };
        assert!(!report.is_clean());
    }
}
