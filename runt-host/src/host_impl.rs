use crate::bindings::runt::verifier::host_crypto;
use crate::bindings::runt::verifier::host_storage;
use crate::crypto::CryptoProvider;
use crate::storage::StorageProvider;

pub struct HostState {
    crypto: Box<dyn CryptoProvider>,
    storage: Box<dyn StorageProvider>,
}

impl HostState {
    pub fn new(crypto: Box<dyn CryptoProvider>, storage: Box<dyn StorageProvider>) -> Self {
        Self { crypto, storage }
    }
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            crypto: Box::new(crate::crypto::DefaultCryptoProvider),
            storage: Box::new(crate::storage::InMemoryStorage::new()),
        }
    }
}

impl host_crypto::Host for HostState {
    fn hash(&mut self, algorithm: String, data: Vec<u8>) -> Vec<u8> {
        self.crypto.hash(&algorithm, &data)
    }

    fn verify_signature(
        &mut self,
        scheme: String,
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> bool {
        self.crypto
            .verify_signature(&scheme, &message, &signature, &public_key)
    }

    fn pairing_check(&mut self, curve: String, pairs: Vec<u8>) -> bool {
        self.crypto.pairing_check(&curve, &pairs)
    }
}

impl host_storage::Host for HostState {
    fn get_verification_key(
        &mut self,
        key_id: String,
    ) -> Result<Vec<u8>, String> {
        self.storage.get_verification_key(&key_id)
    }

    fn get_public_params(
        &mut self,
        params_id: String,
    ) -> Result<Vec<u8>, String> {
        self.storage.get_public_params(&params_id)
    }
}
