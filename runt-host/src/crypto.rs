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

    fn pairing_check(&self, curve: u32, pairs: &[u8]) -> bool {
        match curve {
            CURVE_BN254 => verify_bn254_pairing(pairs),
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

fn verify_bn254_pairing(pairs: &[u8]) -> bool {
    use ark_bn254::{Bn254, Fq2, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ff::{Field, PrimeField};

    const PAIR_SIZE: usize = 192;

    if pairs.len() % PAIR_SIZE != 0 || pairs.is_empty() {
        return false;
    }

    let num_pairs = pairs.len() / PAIR_SIZE;
    let mut g1s = Vec::with_capacity(num_pairs);
    let mut g2s = Vec::with_capacity(num_pairs);

    for i in 0..num_pairs {
        let off = i * PAIR_SIZE;
        let x = read_fq(&pairs[off..off + 32]);
        let y = read_fq(&pairs[off + 32..off + 64]);
        g1s.push(G1Affine::new_unchecked(x, y));

        let x_c0 = read_fq(&pairs[off + 64..off + 96]);
        let x_c1 = read_fq(&pairs[off + 96..off + 128]);
        let y_c0 = read_fq(&pairs[off + 128..off + 160]);
        let y_c1 = read_fq(&pairs[off + 160..off + 192]);
        g2s.push(G2Affine::new_unchecked(
            Fq2::new(x_c0, x_c1),
            Fq2::new(y_c0, y_c1),
        ));
    }

    let result = Bn254::multi_pairing(&g1s, &g2s);
    result.0 == <ark_bn254::Fq12 as Field>::ONE
}

fn read_fq(bytes: &[u8]) -> ark_bn254::Fq {
    use ark_ff::PrimeField;
    let mut be_bytes = [0u8; 32];
    be_bytes.copy_from_slice(&bytes[..32]);
    ark_bn254::Fq::from_be_bytes_mod_order(&be_bytes)
}
