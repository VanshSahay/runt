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
    fn hash(&self, _algorithm: &str, _data: &[u8]) -> Vec<u8> {
        vec![]
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
