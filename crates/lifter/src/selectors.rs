use crate::disasm::disassemble;
use crate::opcodes::Opcode;
use std::collections::HashMap;

/// A detected function selector with its jump target in the bytecode.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    /// 4-byte selector (e.g., 0xa9059cbb for transfer)
    pub selector: [u8; 4],
    /// Bytecode offset of the function body
    pub offset: usize,
    /// Human-readable name if known
    pub name: Option<String>,
}

/// Well-known function selectors (keccak256 of signature, first 4 bytes).
fn known_selectors() -> HashMap<[u8; 4], &'static str> {
    let mut m = HashMap::new();
    // ERC20
    m.insert([0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)");
    m.insert(
        [0x23, 0xb8, 0x72, 0xdd],
        "transferFrom(address,address,uint256)",
    );
    m.insert([0x09, 0x5e, 0xa7, 0xb3], "approve(address,uint256)");
    m.insert([0x70, 0xa0, 0x82, 0x31], "balanceOf(address)");
    m.insert([0xdd, 0x62, 0xed, 0x3e], "allowance(address,address)");
    m.insert([0x18, 0x16, 0x0d, 0xdd], "totalSupply()");
    // Common
    m.insert([0xd0, 0xe3, 0x0d, 0xb0], "deposit()");
    m.insert([0x3c, 0xcf, 0xd6, 0x0b], "withdraw()");
    m.insert([0x2e, 0x1a, 0x7d, 0x4d], "withdraw(uint256)");
    m.insert([0x8d, 0xa5, 0xcb, 0x5b], "renounceOwnership()");
    m.insert([0xf2, 0xfd, 0xe3, 0x8b], "transferOwnership(address)");
    m.insert([0x8d, 0xa5, 0xcb, 0x5b], "renounceOwnership()");
    m.insert([0x71, 0x5b, 0x45, 0x42], "mint(address,uint256)");
    m.insert([0x42, 0x96, 0x6c, 0x68], "burn(uint256)");
    m.insert([0x27, 0xe2, 0x35, 0xe3], "balances(address)");
    // Fallback/receive
    m
}

/// Extract function selectors from compiled Solidity bytecode.
///
/// Looks for the dispatcher pattern:
/// ```text
/// PUSH4 <selector> EQ PUSH1/2 <offset> JUMPI
/// ```
pub fn extract_selectors(bytecode: &[u8]) -> Vec<FunctionEntry> {
    let instructions = disassemble(bytecode);
    let known = known_selectors();
    let mut entries = Vec::new();

    // Scan for PUSH4 <selector> ... EQ ... PUSH <offset> JUMPI pattern
    for (i, instr) in instructions.iter().enumerate() {
        // Look for PUSH4 with exactly 4 bytes
        if let Opcode::Push(4) = instr.opcode {
            if instr.immediate.len() != 4 {
                continue;
            }

            let mut selector = [0u8; 4];
            selector.copy_from_slice(&instr.immediate);

            // Look ahead for EQ followed by PUSH+JUMPI within next 6 instructions
            // (wider window for pre-0.8 patterns with DUP/SWAP between PUSH4 and EQ)
            let window = &instructions[i + 1..(i + 7).min(instructions.len())];

            let has_eq = window.iter().any(|w| w.opcode == Opcode::Eq);
            let _jumpi_target: Option<usize> = window.iter().find_map(|w| {
                if w.opcode == Opcode::JumpI {
                    None
                } else {
                    None
                }
            });

            // Find the PUSH right before the JUMPI in the window
            let mut target_offset = None;
            for j in 0..window.len() {
                if window[j].opcode == Opcode::JumpI && j > 0 {
                    if let Opcode::Push(_) = window[j - 1].opcode {
                        let imm = &window[j - 1].immediate;
                        let mut val = 0usize;
                        for &b in imm {
                            val = (val << 8) | (b as usize);
                        }
                        target_offset = Some(val);
                    }
                }
            }

            if has_eq {
                let name = known.get(&selector).map(|s| s.to_string());
                entries.push(FunctionEntry {
                    selector,
                    offset: target_offset.unwrap_or(0),
                    name,
                });
            }
        }
    }

    entries
}

/// Given a bytecode offset, find which function it belongs to.
pub fn offset_to_function(entries: &[FunctionEntry], offset: usize) -> Option<&FunctionEntry> {
    // Find the function whose body offset is closest to (but not exceeding) the given offset.
    entries
        .iter()
        .filter(|e| e.offset <= offset)
        .max_by_key(|e| e.offset)
}

/// Format a selector as a hex string.
pub fn selector_hex(selector: &[u8; 4]) -> String {
    format!(
        "0x{:02x}{:02x}{:02x}{:02x}",
        selector[0], selector[1], selector[2], selector[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_simple_overflow() {
        let hex = std::fs::read_to_string("../../bench/r-evm-verify/SimpleOverflow.hex")
            .unwrap_or_default();
        let hex = hex.trim();
        if hex.is_empty() {
            return; // skip if fixture not available
        }
        let bytecode: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();

        let entries = extract_selectors(&bytecode);
        assert!(
            !entries.is_empty(),
            "Should find at least one function selector"
        );

        // SimpleOverflow has: total() and unsafeAdd(uint256,uint256)
        let selectors: Vec<String> = entries.iter().map(|e| selector_hex(&e.selector)).collect();
        eprintln!("Found selectors: {:?}", selectors);
        assert!(entries.len() >= 2, "Expected at least 2 selectors");
    }

    #[test]
    fn extract_from_reentrancy() {
        let hex =
            std::fs::read_to_string("../../bench/r-evm-verify/Reentrancy.hex").unwrap_or_default();
        let hex = hex.trim();
        if hex.is_empty() {
            return;
        }
        let bytecode: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();

        let entries = extract_selectors(&bytecode);
        let names: Vec<Option<&str>> = entries.iter().map(|e| e.name.as_deref()).collect();
        eprintln!("Reentrancy selectors: {:?}", names);

        // VulnerableVault has: deposit(), withdraw(), balances(address)
        let has_withdraw = entries
            .iter()
            .any(|e| e.name.as_deref().map_or(false, |n| n.contains("withdraw")));
        let has_deposit = entries
            .iter()
            .any(|e| e.name.as_deref().map_or(false, |n| n.contains("deposit")));
        assert!(
            has_withdraw || has_deposit,
            "Should find deposit or withdraw"
        );
    }

    #[test]
    fn known_selectors_lookup() {
        let known = known_selectors();
        assert_eq!(
            known.get(&[0xa9, 0x05, 0x9c, 0xbb]),
            Some(&"transfer(address,uint256)")
        );
    }

    #[test]
    fn offset_to_function_finds_closest() {
        let entries = vec![
            FunctionEntry {
                selector: [0x01, 0x02, 0x03, 0x04],
                offset: 100,
                name: Some("foo()".into()),
            },
            FunctionEntry {
                selector: [0x05, 0x06, 0x07, 0x08],
                offset: 200,
                name: Some("bar()".into()),
            },
        ];
        let result = offset_to_function(&entries, 150);
        assert_eq!(result.unwrap().name.as_deref(), Some("foo()"));

        let result = offset_to_function(&entries, 250);
        assert_eq!(result.unwrap().name.as_deref(), Some("bar()"));
    }
}
