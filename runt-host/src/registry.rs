use std::collections::HashMap;

use crate::types::VerifierMetadata;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CapabilityKey {
    pub category: String,
    pub value: String,
}

pub struct VerifierRegistry {
    entries: HashMap<String, VerifierMetadata>,
    capability_index: HashMap<CapabilityKey, Vec<String>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            capability_index: HashMap::new(),
        }
    }

    pub fn register(&mut self, metadata: VerifierMetadata) {
        let type_id = metadata.proof_type_id.clone();

        if !metadata.curve.is_empty() {
            self.index_capability(
                &type_id,
                CapabilityKey {
                    category: "curve".into(),
                    value: metadata.curve.clone(),
                },
            );
        }
        if !metadata.scheme.is_empty() {
            self.index_capability(
                &type_id,
                CapabilityKey {
                    category: "scheme".into(),
                    value: metadata.scheme.clone(),
                },
            );
        }

        self.entries.insert(type_id, metadata);
    }

    fn index_capability(&mut self, type_id: &str, key: CapabilityKey) {
        self.capability_index
            .entry(key)
            .or_default()
            .push(type_id.to_string());
    }

    pub fn get(&self, proof_type_id: &str) -> Option<&VerifierMetadata> {
        self.entries.get(proof_type_id)
    }

    pub fn list(&self) -> Vec<&VerifierMetadata> {
        self.entries.values().collect()
    }

    pub fn find_by_capability(&self, category: &str, value: &str) -> Vec<&VerifierMetadata> {
        let key = CapabilityKey {
            category: category.to_string(),
            value: value.to_string(),
        };
        self.capability_index
            .get(&key)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}
