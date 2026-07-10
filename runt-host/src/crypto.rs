use sha2::Digest;
use sha3::Keccak256;
use runt_abi::*;

pub trait CryptoProvider: Send + Sync {
    fn keccak256(&self, data: &[u8]) -> [u8; 32];
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn verify_signature(&self, scheme: u32, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool;
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

    fn verify_signature(&self, scheme: u32, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        match scheme {
            SIG_BLS => verify_bls_signature(message, signature, public_key),
            SIG_ECDSA_SECP256K1 => false,
            _ => false,
        }
    }

    fn pairing_check(&self, curve: u32, _pairs: &[u8]) -> bool {
        match curve {
            CURVE_BN254 => false,
            CURVE_BLS12_381 => false,
            _ => false,
        }
    }
}

fn verify_bls_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    use blst::min_pk::{PublicKey, Signature};
    use blst::BLST_ERROR;

    if signature.len() != 96 || public_key.len() != 48 {
        return false;
    }

    let mut sig_bytes = [0u8; 96];
    sig_bytes.copy_from_slice(&signature[..96]);
    let sig = match Signature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut pk_bytes = [0u8; 48];
    pk_bytes.copy_from_slice(&public_key[..48]);
    let pk = match PublicKey::from_bytes(&pk_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let result = sig.verify(true, message, dst, &[], &pk, true);
    matches!(result, BLST_ERROR::BLST_SUCCESS)
}
