use std::ops::Neg;
use runt_host::crypto::CryptoProvider;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

fn write_fq_be(fq: &ark_bn254::Fq, out: &mut [u8]) {
    let bytes = PrimeField::into_bigint(*fq).to_bytes_be();
    let start = bytes.len().saturating_sub(32);
    out.copy_from_slice(&bytes[start..]);
}

#[test]
fn test_bn254_pairing_valid() {
    let g1 = ark_bn254::G1Affine::generator();
    let g2 = ark_bn254::G2Affine::generator();
    let neg_g1 = -g1;

    let mut pairs = Vec::new();
    append_g1(&mut pairs, &g1);
    append_g2(&mut pairs, &g2);
    append_g1(&mut pairs, &neg_g1);
    append_g2(&mut pairs, &g2);

    let provider = runt_host::crypto::DefaultCryptoProvider;
    assert!(provider.pairing_check(runt_abi::CURVE_BN254, &pairs),
        "e(G1, G2) · e(-G1, G2) should equal 1");
}

fn append_g1(buf: &mut Vec<u8>, p: &ark_bn254::G1Affine) {
    let mut bytes = [0u8; 64];
    write_fq_be(&p.x, &mut bytes[0..32]);
    write_fq_be(&p.y, &mut bytes[32..64]);
    buf.extend_from_slice(&bytes);
}

fn append_g2(buf: &mut Vec<u8>, p: &ark_bn254::G2Affine) {
    let mut bytes = [0u8; 128];
    write_fq_be(&p.x.c0, &mut bytes[0..32]);
    write_fq_be(&p.x.c1, &mut bytes[32..64]);
    write_fq_be(&p.y.c0, &mut bytes[64..96]);
    write_fq_be(&p.y.c1, &mut bytes[96..128]);
    buf.extend_from_slice(&bytes);
}

#[test]
fn test_bn254_pairing_invalid_empty() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    assert!(!provider.pairing_check(runt_abi::CURVE_BN254, &[]));
}

#[test]
fn test_bn254_pairing_invalid_size() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    assert!(!provider.pairing_check(runt_abi::CURVE_BN254, &[0u8; 100]));
}

#[test]
fn test_bn254_pairing_wrong_curve() {
    let provider = runt_host::crypto::DefaultCryptoProvider;
    assert!(!provider.pairing_check(99, &[0u8; 192]));
}
