use sha2::Digest;
use sha3::Keccak256;

pub trait CryptoProvider: Send + Sync {
    fn keccak256(&self, data: &[u8]) -> [u8; 32];
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn verify_signature(
        &self,
        scheme: u32,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> bool;
    fn pairing_check(&self, curve: u32, pairs: &[u8]) -> bool;
}

pub struct DefaultCryptoProvider;

impl CryptoProvider for DefaultCryptoProvider {
    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    fn verify_signature(
        &self,
        _scheme: u32,
        _message: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
    ) -> bool {
        false
    }

    fn pairing_check(&self, _curve: u32, _pairs: &[u8]) -> bool {
        false
    }
}
