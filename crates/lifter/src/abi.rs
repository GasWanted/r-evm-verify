use crate::selectors::FunctionEntry;
use serde::Deserialize;
use std::collections::HashMap;

/// Minimal ABI function entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AbiEntry {
    #[serde(rename = "type")]
    pub entry_type: Option<String>,
    pub name: Option<String>,
    pub inputs: Option<Vec<AbiInput>>,
    #[serde(rename = "stateMutability")]
    pub state_mutability: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiInput {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
}

/// Parse a solc ABI JSON array into a map of selector → function signature.
pub fn parse_abi(abi_json: &serde_json::Value) -> HashMap<[u8; 4], String> {
    let mut selectors = HashMap::new();

    let entries: Vec<AbiEntry> = match serde_json::from_value(abi_json.clone()) {
        Ok(e) => e,
        Err(_) => return selectors,
    };

    for entry in entries {
        if entry.entry_type.as_deref() != Some("function") {
            continue;
        }
        let Some(name) = &entry.name else { continue };
        let inputs = entry.inputs.as_deref().unwrap_or(&[]);

        // Build canonical signature: "functionName(type1,type2,...)"
        let param_types: Vec<&str> = inputs.iter().map(|i| i.input_type.as_str()).collect();
        let signature = format!("{}({})", name, param_types.join(","));

        // Compute selector: first 4 bytes of keccak256(signature)
        let selector = compute_selector(&signature);
        selectors.insert(selector, signature);
    }

    selectors
}

/// Compute the 4-byte function selector from a canonical signature.
fn compute_selector(signature: &str) -> [u8; 4] {
    use alloy_primitives::keccak256;
    let hash = keccak256(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

/// Enrich function entries from bytecode analysis with names from ABI.
pub fn enrich_with_abi(entries: &mut [FunctionEntry], abi_selectors: &HashMap<[u8; 4], String>) {
    for entry in entries {
        if entry.name.is_none() {
            if let Some(sig) = abi_selectors.get(&entry.selector) {
                entry.name = Some(sig.clone());
            }
        }
    }
}

/// Try to extract ABI from a solc standard JSON output.
pub fn extract_abi_from_solc_json(json: &serde_json::Value) -> Option<serde_json::Value> {
    // Standard JSON: contracts/<file>/<contract>/abi
    if let Some(contracts) = json.get("contracts").and_then(|c| c.as_object()) {
        for (_file, file_contracts) in contracts {
            if let Some(file_obj) = file_contracts.as_object() {
                for (_name, contract) in file_obj {
                    if let Some(abi) = contract.get("abi") {
                        return Some(abi.clone());
                    }
                }
            }
        }
    }
    // Simple format: just "abi" at root
    json.get("abi").cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_abi() {
        let abi_json = serde_json::json!([
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "balanceOf",
                "inputs": [
                    {"name": "account", "type": "address"}
                ],
                "stateMutability": "view"
            }
        ]);
        let selectors = parse_abi(&abi_json);
        assert_eq!(selectors.len(), 2);
        // transfer(address,uint256) selector = 0xa9059cbb
        assert!(selectors.contains_key(&[0xa9, 0x05, 0x9c, 0xbb]));
        assert_eq!(
            selectors.get(&[0xa9, 0x05, 0x9c, 0xbb]),
            Some(&"transfer(address,uint256)".to_string())
        );
    }

    #[test]
    fn compute_known_selector() {
        let sel = compute_selector("transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn compute_deposit_selector() {
        let sel = compute_selector("deposit()");
        assert_eq!(sel, [0xd0, 0xe3, 0x0d, 0xb0]);
    }

    #[test]
    fn enrich_entries() {
        let mut entries = vec![FunctionEntry {
            selector: [0xa9, 0x05, 0x9c, 0xbb],
            offset: 100,
            name: None,
        }];
        let mut abi_map = HashMap::new();
        abi_map.insert(
            [0xa9, 0x05, 0x9c, 0xbb],
            "transfer(address,uint256)".to_string(),
        );
        enrich_with_abi(&mut entries, &abi_map);
        assert_eq!(
            entries[0].name.as_deref(),
            Some("transfer(address,uint256)")
        );
    }
}
