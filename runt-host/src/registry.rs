use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub proof_type_id: String,
    pub version: String,
    pub curve: String,
    pub scheme: String,
    pub supports_recursion: bool,
    pub trusted_setup_required: bool,
    pub max_proof_size: u64,
    pub description: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CapabilityKey {
    pub category: String,
    pub value: String,
}

pub struct VerifierRegistry {
    metadata: HashMap<String, VerifierMetadata>,
    capability_index: HashMap<CapabilityKey, Vec<String>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new(),
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

        self.metadata.insert(type_id, metadata);
    }

    fn index_capability(&mut self, type_id: &str, key: CapabilityKey) {
        self.capability_index
            .entry(key)
            .or_default()
            .push(type_id.to_string());
    }

    pub fn get(&self, proof_type_id: &str) -> Option<&VerifierMetadata> {
        self.metadata.get(proof_type_id)
    }

    pub fn list(&self) -> Vec<&VerifierMetadata> {
        self.metadata.values().collect()
    }

    pub fn find_by_capability(&self, category: &str, value: &str) -> Vec<&VerifierMetadata> {
        let key = CapabilityKey {
            category: category.to_string(),
            value: value.to_string(),
        };
        self.capability_index
            .get(&key)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.metadata.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.metadata.len()
    }

    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}
