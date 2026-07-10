use std::collections::HashMap;

pub trait StorageProvider: Send + Sync {
    fn get_verification_key(&self, key_id: &str) -> Result<Vec<u8>, String>;
    fn get_public_params(&self, params_id: &str) -> Result<Vec<u8>, String>;
}

pub struct InMemoryStorage {
    verification_keys: HashMap<String, Vec<u8>>,
    public_params: HashMap<String, Vec<u8>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            verification_keys: HashMap::new(),
            public_params: HashMap::new(),
        }
    }

    pub fn insert_verification_key(&mut self, key_id: String, key: Vec<u8>) {
        self.verification_keys.insert(key_id, key);
    }

    pub fn insert_public_params(&mut self, params_id: String, params: Vec<u8>) {
        self.public_params.insert(params_id, params);
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageProvider for InMemoryStorage {
    fn get_verification_key(&self, key_id: &str) -> Result<Vec<u8>, String> {
        self.verification_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| format!("verification key not found: {key_id}"))
    }

    fn get_public_params(&self, params_id: &str) -> Result<Vec<u8>, String> {
        self.public_params
            .get(params_id)
            .cloned()
            .ok_or_else(|| format!("public params not found: {params_id}"))
    }
}
