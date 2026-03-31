use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct StorageLayout {
    pub storage: Vec<StorageEntry>,
    #[serde(default)]
    pub types: HashMap<String, StorageType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageEntry {
    pub label: String,
    pub slot: String,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub offset: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageType {
    pub encoding: String,
    pub label: String,
    #[serde(rename = "numberOfBytes")]
    pub number_of_bytes: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

/// Parsed storage layout with slot-to-variable-name mapping.
#[derive(Debug, Clone, Default)]
pub struct StorageMap {
    /// Direct slot to variable name.
    pub slots: HashMap<[u8; 32], String>,
    /// Base slots for mappings: slot to (variable name, key type label).
    pub mapping_bases: HashMap<[u8; 32], (String, String)>,
}

/// Parse a solc `storageLayout` JSON into a [`StorageMap`].
pub fn parse_storage_layout(json: &serde_json::Value) -> Option<StorageMap> {
    let layout: StorageLayout = serde_json::from_value(json.clone()).ok()?;
    let mut map = StorageMap::default();

    for entry in &layout.storage {
        let slot_num: u64 = entry.slot.parse().ok()?;
        let mut slot_bytes = [0u8; 32];
        slot_bytes[24..32].copy_from_slice(&slot_num.to_be_bytes());

        if let Some(type_info) = layout.types.get(&entry.type_name) {
            if type_info.encoding == "mapping" {
                let key_label = type_info.key.as_deref().unwrap_or("unknown");
                let key_type = layout
                    .types
                    .get(key_label)
                    .map(|t| t.label.clone())
                    .unwrap_or_else(|| key_label.to_string());
                map.mapping_bases
                    .insert(slot_bytes, (entry.label.clone(), key_type));
            } else {
                map.slots.insert(slot_bytes, entry.label.clone());
            }
        } else {
            map.slots.insert(slot_bytes, entry.label.clone());
        }
    }

    Some(map)
}

/// Try to extract a storage layout from a solc combined-json or standard-json output.
pub fn extract_storage_layout(json: &serde_json::Value) -> Option<StorageMap> {
    // Standard JSON: contracts/<file>/<contract>/storageLayout
    if let Some(contracts) = json.get("contracts").and_then(|c| c.as_object()) {
        for (_file, file_contracts) in contracts {
            if let Some(file_obj) = file_contracts.as_object() {
                for (_name, contract) in file_obj {
                    if let Some(layout) = contract.get("storageLayout") {
                        return parse_storage_layout(layout);
                    }
                }
            }
            // Combined JSON format
            if let Some(layout) = file_contracts.get("storage-layout") {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(layout.as_str()?) {
                    return parse_storage_layout(&parsed);
                }
            }
        }
    }
    // Direct storageLayout at root
    if let Some(layout) = json.get("storageLayout") {
        return parse_storage_layout(layout);
    }
    None
}

/// Look up a variable name for a given slot.
pub fn resolve_slot_name(map: &StorageMap, slot_bytes: &[u8; 32]) -> Option<String> {
    // Direct slot match
    if let Some(name) = map.slots.get(slot_bytes) {
        return Some(name.clone());
    }
    // For mappings, we would need to match keccak256(key . base_slot)
    // which requires knowing the key -- for now return None.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_layout() {
        let json = serde_json::json!({
            "storage": [
                {"label": "owner", "slot": "0", "type": "t_address", "offset": 0},
                {"label": "balances", "slot": "1", "type": "t_mapping", "offset": 0},
                {"label": "totalSupply", "slot": "2", "type": "t_uint256", "offset": 0}
            ],
            "types": {
                "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
                "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                "t_mapping": {"encoding": "mapping", "label": "mapping(address => uint256)", "numberOfBytes": "32", "key": "t_address", "value": "t_uint256"}
            }
        });
        let map = parse_storage_layout(&json).unwrap();

        let slot0 = [0u8; 32];
        assert_eq!(map.slots.get(&slot0), Some(&"owner".to_string()));

        let mut slot2 = [0u8; 32];
        slot2[31] = 2;
        assert_eq!(map.slots.get(&slot2), Some(&"totalSupply".to_string()));

        let mut slot1 = [0u8; 32];
        slot1[31] = 1;
        assert!(map.mapping_bases.contains_key(&slot1));
    }
}
