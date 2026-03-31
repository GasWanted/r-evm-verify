use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "r-evm-verify",
    version,
    about = "Parallel formal verification for EVM smart contracts"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run built-in analyses (reentrancy, overflow, access control) on a contract
    Scan {
        /// Path to raw bytecode hex file or solc JSON output
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    /// Check compositional invariants across all functions
    Invariant {
        /// Path to contract bytecode hex or solc JSON
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    /// Automatically infer protocol invariants (no user input needed)
    Infer {
        /// Path to contract bytecode hex or solc JSON
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    /// Prove user-defined properties (check_ functions) from Foundry test contracts
    Prove {
        /// Path to compiled test contract JSON (solc combined-json or forge output)
        #[arg(value_name = "TEST_JSON")]
        test_path: PathBuf,
        /// Path to compiled target contract JSON
        #[arg(long, value_name = "TARGET_JSON")]
        target: PathBuf,
    },
    /// Mine algebraic invariants from symbolic execution (research mode)
    Mine {
        /// Path to contract bytecode hex or solc JSON
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path } => cmd_scan(path),
        Commands::Infer { path } => cmd_infer(path),
        Commands::Invariant { path } => cmd_invariant(path),
        Commands::Prove { test_path, target } => cmd_prove(test_path, target),
        Commands::Mine { path } => cmd_mine(path),
    }
}

fn cmd_scan(path: PathBuf) -> Result<()> {
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let (bytecode, abi_json) = parse_input(&contents)?;

    eprintln!(
        "Scanning {} ({} bytes of bytecode{})",
        path.display(),
        bytecode.len(),
        if abi_json.is_some() { ", with ABI" } else { "" }
    );

    let report =
        r_evm_verify_engine::pipeline::scan_bytecode_with_abi(&bytecode, abi_json.as_ref());
    println!("{report}");

    if report.is_clean() {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn cmd_infer(path: PathBuf) -> Result<()> {
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let (bytecode, abi_json) = parse_input(&contents)?;

    let mut selectors = r_evm_verify_lifter::selectors::extract_selectors(&bytecode);
    if let Some(abi) = &abi_json {
        let abi_map = r_evm_verify_lifter::abi::parse_abi(abi);
        r_evm_verify_lifter::abi::enrich_with_abi(&mut selectors, &abi_map);
    }

    eprintln!("Extracting function summaries...");
    let summaries =
        r_evm_verify_engine::summarizer::summarize_contract(&bytecode, &selectors, 5000);
    eprintln!("  {} functions summarized", summaries.len());

    eprintln!("Inferring invariants...");
    let invariants = r_evm_verify_engine::inference::infer_invariants(&summaries);

    let output = r_evm_verify_engine::inference::format_inferred_invariants(&invariants);
    println!("{}", output);

    let issues = invariants
        .iter()
        .filter(|i| !i.potential_violators.is_empty())
        .count();
    if issues > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_invariant(path: PathBuf) -> Result<()> {
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let (bytecode, abi_json) = parse_input(&contents)?;

    let mut selectors = r_evm_verify_lifter::selectors::extract_selectors(&bytecode);
    if let Some(abi) = &abi_json {
        let abi_map = r_evm_verify_lifter::abi::parse_abi(abi);
        r_evm_verify_lifter::abi::enrich_with_abi(&mut selectors, &abi_map);
    }

    eprintln!("Extracting function summaries...");
    let summaries =
        r_evm_verify_engine::summarizer::summarize_contract(&bytecode, &selectors, 5000);
    eprintln!("  {} functions summarized", summaries.len());

    eprintln!("Checking invariants...");
    let results = r_evm_verify_engine::invariant::check_invariants(&summaries);

    let output = r_evm_verify_engine::invariant::format_invariant_results(&results);
    println!("{}", output);

    let any_violated = results.iter().any(|r| !r.holds);
    if any_violated {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_prove(test_path: PathBuf, target_path: PathBuf) -> Result<()> {
    let test_contents = std::fs::read_to_string(&test_path)
        .with_context(|| format!("Failed to read {}", test_path.display()))?;
    let target_contents = std::fs::read_to_string(&target_path)
        .with_context(|| format!("Failed to read {}", target_path.display()))?;

    let (test_bytecode, test_abi) = parse_input(&test_contents)?;
    let (target_bytecode, _) = parse_input(&target_contents)?;

    eprintln!(
        "Test contract: {} ({} bytes)",
        test_path.display(),
        test_bytecode.len()
    );
    eprintln!(
        "Target contract: {} ({} bytes)",
        target_path.display(),
        target_bytecode.len()
    );

    let config = r_evm_verify_engine::prover::ProveConfig::default();
    let results = r_evm_verify_engine::prover::prove_all(
        &test_bytecode,
        &target_bytecode,
        &config,
        test_abi.as_ref(),
    );

    if results.is_empty() {
        eprintln!("No check_ functions found in test contract.");
        eprintln!("Write functions prefixed with 'check_' that contain assert() statements.");
        std::process::exit(1);
    }

    let output = r_evm_verify_engine::prover::format_prove_results(&results);
    println!("{}", output);

    let any_violated = results.iter().any(|r| !r.verified);
    if any_violated {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_mine(path: PathBuf) -> Result<()> {
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let (bytecode, abi_json) = parse_input(&contents)?;

    let mut selectors = r_evm_verify_lifter::selectors::extract_selectors(&bytecode);
    if let Some(abi) = &abi_json {
        let abi_map = r_evm_verify_lifter::abi::parse_abi(abi);
        r_evm_verify_lifter::abi::enrich_with_abi(&mut selectors, &abi_map);
    }

    eprintln!("Extracting function summaries...");
    let summaries =
        r_evm_verify_engine::summarizer::summarize_contract(&bytecode, &selectors, 5000);
    eprintln!("  {} functions summarized", summaries.len());

    eprintln!("Mining algebraic invariants...");
    let mut invariants = r_evm_verify_engine::algebraic::mine_invariants(&summaries);
    invariants.extend(r_evm_verify_engine::algebraic::mine_cross_function_conservation(&summaries));

    let output = r_evm_verify_engine::algebraic::format_algebraic_invariants(&invariants);
    println!("{}", output);

    Ok(())
}

/// Parse input file: returns bytecode and optional ABI JSON.
fn parse_input(contents: &str) -> Result<(Vec<u8>, Option<serde_json::Value>)> {
    let trimmed = contents.trim();

    // Try as solc JSON output.
    if trimmed.starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(trimmed).context("Invalid JSON")?;

        // Standard JSON output paths
        let bytecode_hex = json
            .pointer("/evm/deployedBytecode/object")
            .or_else(|| json.pointer("/deployedBytecode/object"))
            .or_else(|| json.pointer("/bytecode/object"))
            .or_else(|| json.pointer("/evm/bytecode/object"))
            .and_then(|v| v.as_str());

        if let Some(hex) = bytecode_hex {
            let bytecode = hex_decode(hex)?;
            let abi = r_evm_verify_lifter::abi::extract_abi_from_solc_json(&json);
            return Ok((bytecode, abi));
        }

        // Combined JSON format: contracts/<file:name>/bin-runtime
        if let Some(contracts) = json.get("contracts").and_then(|c| c.as_object()) {
            for (_key, contract) in contracts {
                if let Some(hex) = contract.get("bin-runtime").and_then(|v| v.as_str()) {
                    if !hex.is_empty() {
                        let bytecode = hex_decode(hex)?;
                        let abi = contract.get("abi").cloned();
                        return Ok((bytecode, abi));
                    }
                }
            }
        }

        bail!("Could not find bytecode in JSON — expected solc standard or combined output format");
    }

    // Raw hex.
    Ok((hex_decode(trimmed)?, None))
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes: Result<Vec<u8>, _> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect();
    bytes.context("Invalid hex string")
}
