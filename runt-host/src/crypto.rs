use sha3::{Digest, Keccak256};

pub trait CryptoProvider: Send + Sync {
    fn hash(&self, algorithm: &str, data: &[u8]) -> Vec<u8>;
    fn verify_signature(
        &self,
        scheme: &str,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> bool;
    fn pairing_check(&self, curve: &str, pairs: &[u8]) -> bool;
}

pub struct DefaultCryptoProvider;

impl CryptoProvider for DefaultCryptoProvider {
    fn hash(&self, algorithm: &str, data: &[u8]) -> Vec<u8> {
        match algorithm {
            "keccak256" => {
                let mut hasher = Keccak256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            "sha256" => {
                use sha2::Sha256;
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            _ => Vec::new(),
        }
    }

    fn verify_signature(
        &self,
        _scheme: &str,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> bool {
        false
    }

    fn pairing_check(&self, _curve: &str, _pairs: &[u8]) -> bool {
        false
    }
}
