use ark_ff::BigInteger;
use runt_host::crypto::CryptoProvider;
use wasmtime::Module;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("state") => demo_state_proof(),
        Some("tx") => demo_tx_proof(),
        Some("pairing") => demo_bn254_pairing(),
        Some("bls") => demo_bls(),
        Some("all") => demo_all(),
        Some("live") => demo_live_instructions(),
        _ => {
            println!("Runt Demo Tool");
            println!("Usage: runt-demo <command>");
            println!();
            println!("Commands:");
            println!("  state    — Generate and verify an EIP-1186 state proof");
            println!("  tx       — Generate and verify a transaction receipt proof");
            println!("  pairing  — Test BN254 pairing check (e(G,H)·e(-G,H)=1)");
            println!("  bls      — Test BLS12-381 signature verification");
            println!("  all      — Run all demos");
            println!("  live     — Show how to fetch and verify live Ethereum proofs");
            Ok(())
        }
    }
}

fn demo_state_proof() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  EIP-1186 State Proof — Generate & Verify    ║");
    println!("╚══════════════════════════════════════════════╝\n");

    let account = rlp_account(1, 1_000_000_000_000_000_000u128, &[0u8; 32], &[0u8; 32]);
    let key = keccak256(b"0xAlice"); // the account address as key
    let encoded_path = leaf_path(&bytes_to_nibbles(&key));
    let leaf_rlp = rlp_list(&[&encoded_path, &account]);
    let state_root = keccak256(&leaf_rlp);
    let proof = rlp_list(&[&leaf_rlp]);

    let mut inputs = state_root.to_vec();
    inputs.extend_from_slice(&key);

    println!("  Account data: nonce=1, balance=1 ETH");
    println!("  State root:   0x{}", hex::encode(state_root));
    println!("  Proof bytes:  {} (1 leaf node)", proof.len());
    println!("  Key (nibbles): {}", hex::encode(bytes_to_nibbles(&key)));
    println!();

    let result = verify("state_verifier.wasm", &proof, &inputs)?;
    print_verdict("State Proof", result);
    Ok(())
}

fn demo_tx_proof() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  Receipt Proof — Generate & Verify            ║");
    println!("╚══════════════════════════════════════════════╝\n");

    let tx_index = 5u64;
    let receipt = rlp_receipt(1, 21000, &[], &[0u8; 256]);
    let key = rlp_u64(tx_index);
    let encoded_path = leaf_path(&bytes_to_nibbles(&key));
    let leaf_rlp = rlp_list(&[&encoded_path, &receipt]);
    let receipts_root = keccak256(&leaf_rlp);
    let proof = rlp_list(&[&leaf_rlp]);

    let mut inputs = receipts_root.to_vec();
    inputs.extend_from_slice(&tx_index.to_be_bytes());

    println!("  Receipt:       status=success, gas=21000");
    println!("  Tx index:      {}", tx_index);
    println!("  Receipts root: 0x{}", hex::encode(receipts_root));
    println!("  Proof bytes:   {}", proof.len());
    println!();

    let result = verify("tx_verifier.wasm", &proof, &inputs)?;
    print_verdict("Receipt Proof", result);
    Ok(())
}

fn demo_bn254_pairing() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  BN254 Pairing Check — e(G,H)·e(-G,H)=1      ║");
    println!("╚══════════════════════════════════════════════╝\n");

    use ark_ec::AffineRepr;
    let g1 = ark_bn254::G1Affine::generator();
    let g2 = ark_bn254::G2Affine::generator();
    let neg_g1 = std::ops::Neg::neg(g1);

    let pairs = build_pairing_data(&[(g1, g2), (neg_g1, g2)]);
    let provider = runt_host::crypto::DefaultCryptoProvider;
    let result = provider.pairing_check(runt_abi::CURVE_BN254, &pairs);

    println!("  G1  = generator point on BN254");
    println!("  G2  = generator point on BN254 (twist)");
    println!("  Pairs: e(G1, G2) · e(-G1, G2)");
    println!("  Result: {}", if result { "✅ IDENTITY (valid)" } else { "❌ NON-IDENTITY" });
    println!();

    Ok(())
}

fn demo_bls() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  BLS12-381 Signature — Verify                ║");
    println!("╚══════════════════════════════════════════════╝\n");

    use blst::min_pk::{PublicKey, SecretKey, Signature};
    use blst::BLST_ERROR;
    let ikm: [u8; 32] = rand::random();
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen");
    let pk = sk.sk_to_pk();
    let msg = b"Runt verification demo";
    let sig = sk.sign(msg, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);

    let sig_bytes = sig.to_bytes();
    let pk_bytes = pk.to_bytes();

    let provider = runt_host::crypto::DefaultCryptoProvider;
    let valid = provider.verify_signature(
        runt_abi::SIG_BLS, msg, &sig_bytes, &pk_bytes,
    );
    println!("  Message:   \"Runt verification demo\"");
    println!("  Signature: {} bytes (G2 point)", sig_bytes.len());
    println!("  PublicKey: {} bytes (G1 point)", pk_bytes.len());
    println!("  Result:    {}", if valid { "✅ VALID" } else { "❌ INVALID" });

    let invalid = provider.verify_signature(
        runt_abi::SIG_BLS, b"wrong message", &sig_bytes, &pk_bytes,
    );
    println!("  Wrong msg: {}", if invalid { "❌ (should be invalid)" } else { "✅ correctly rejected" });
    println!();

    Ok(())
}

fn demo_all() -> anyhow::Result<()> {
    demo_state_proof()?;
    demo_tx_proof()?;
    demo_bn254_pairing()?;
    demo_bls()?;
    list_verifiers()?;
    Ok(())
}

fn demo_live_instructions() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  Live Ethereum Proof Verification            ║");
    println!("╚══════════════════════════════════════════════╝\n");

    println!("Fetch a live account proof from Ethereum:");
    println!();
    println!("  # Using cast (Foundry):");
    println!("  cast rpc eth_getProof \\");
    println!("    0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \\  # WETH address");
    println!("    '[]' \\                                          # no storage slots");
    println!("    latest \\");
    println!("    --rpc-url https://eth.merkle.io\n");
    println!("  # This returns JSON with accountProof and storageProof.");
    println!("  # Save to proof.json and verify:");
    println!();
    println!("  cargo run -p runt-cli -- verify \\");
    println!("    --proof-type state:eip1186 \\");
    println!("    --proof-file proof.json\n");
    println!("For a light client update (consensus proof):");
    println!();
    println!("  curl https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/light_client/updates \\");
    println!("    | jq '.data[0]' > update.json\n");
    println!("For Groth16 proofs: generate with SP1/RISC0 zkVM and verify here.");
    println!();
    Ok(())
}

fn list_verifiers() -> anyhow::Result<()> {
    let store_manager = runt_core::StoreManager::new();
    let loader = runt_host::loader::VerifierLoader::new(store_manager);
    let registry = runt_host::registry::VerifierRegistry::new();
    let mut router = runt_host::router::VerificationRouter::new(registry, loader);

    let dir = std::path::Path::new("target/verifiers");
    if dir.exists() {
        router.load_verifiers(dir)?;
    }

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Loaded Verifiers                            ║");
    println!("╚══════════════════════════════════════════════╝\n");

    for v in router.registry().list() {
        println!("  {} v{} ({})", v.proof_type_id, v.version, v.scheme);
        println!("    {}\n", v.description);
    }
    Ok(())
}

fn verify(name: &str, proof: &[u8], inputs: &[u8]) -> anyhow::Result<(u32, String)> {
    let store_manager = runt_core::StoreManager::new();
    let loader = runt_host::loader::VerifierLoader::new(store_manager);
    let path = std::path::Path::new("target/wasm32-unknown-unknown/release").join(name);
    let module = Module::from_file(loader.engine(), &path)?;
    loader.verify(&module, proof, inputs)
}

fn print_verdict(name: &str, (code, msg): (u32, String)) {
    let status = match code {
        0 => "✅ VALID",
        1 => "❌ INVALID",
        _ => "⚠️  ERROR",
    };
    println!("  ─────────────────────────────────────────");
    println!("  Verdict: {status}");
    if !msg.is_empty() && code != 0 {
        println!("  Detail:  {msg}");
    }
    println!("  ─────────────────────────────────────────\n");
}

// --- Crypto helpers ---

fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut n = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes { n.push(b >> 4); n.push(b & 0x0F); }
    n
}

fn leaf_path(nibbles: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let odd = nibbles.len() % 2 != 0;
    let prefix = if odd { 0x30 | nibbles[0] } else { 0x20 };
    encoded.push(prefix);
    let start = if odd { 1 } else { 0 };
    for i in (start..nibbles.len()).step_by(2) {
        encoded.push((nibbles[i] << 4) | nibbles[i + 1]);
    }
    encoded
}

// --- RLP encoding ---

fn rlp_list(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items { payload.extend_from_slice(&rlp_item(item)); }
    let mut out = Vec::new();
    rlp_header(&mut out, 0xc0, payload.len());
    out.extend_from_slice(&payload);
    out
}

fn rlp_item(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 { return data.to_vec(); }
    let mut out = Vec::new();
    rlp_header(&mut out, 0x80, data.len());
    out.extend_from_slice(data);
    out
}

fn rlp_u64(n: u64) -> Vec<u8> {
    if n == 0 { return vec![0x80]; }
    let mut bytes = Vec::new();
    let mut val = n;
    while val > 0 { bytes.insert(0, (val & 0xFF) as u8); val >>= 8; }
    rlp_item(&bytes)
}

fn rlp_header(out: &mut Vec<u8>, offset: u8, len: usize) {
    if len < 55 {
        out.push(offset + len as u8);
    } else {
        let lb = usize_be_bytes(len);
        out.push(offset + 55 + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
}

fn usize_be_bytes(n: usize) -> Vec<u8> {
    let mut b = Vec::new();
    let mut v = n;
    while v > 0 { b.insert(0, (v & 0xFF) as u8); v >>= 8; }
    b
}

fn rlp_account(nonce: u64, balance: u128, storage_root: &[u8; 32], code_hash: &[u8; 32]) -> Vec<u8> {
    rlp_list(&[
        &nonce_be_bytes(nonce),
        &balance_be_bytes(balance),
        storage_root,
        code_hash,
    ])
}

fn rlp_receipt(status: u8, gas: u64, _logs: &[&[u8]], bloom: &[u8; 256]) -> Vec<u8> {
    let status_rlp = rlp_item(&[status]);
    let gas_rlp = rlp_u64(gas);
    let bloom_rlp = rlp_item(bloom);
    let logs_rlp = vec![0xc0u8];
    let items: &[&[u8]] = &[&status_rlp, &gas_rlp, &bloom_rlp, &logs_rlp];
    rlp_list(items)
}

fn nonce_be_bytes(n: u64) -> Vec<u8> {
    if n == 0 { return vec![0x80]; }
    let b = n.to_be_bytes();
    let start = b.iter().position(|&x| x != 0).unwrap_or(7);
    rlp_item(&b[start..])
}

fn balance_be_bytes(b: u128) -> Vec<u8> {
    if b == 0 { return vec![0x80]; }
    let bytes = b.to_be_bytes();
    let start = bytes.iter().position(|&x| x != 0).unwrap_or(15);
    rlp_item(&bytes[start..])
}

// --- BN254 pairing data builder ---

fn build_pairing_data(pairs: &[(ark_bn254::G1Affine, ark_bn254::G2Affine)]) -> Vec<u8> {
    use ark_ff::{BigInteger, PrimeField};
    let mut data = Vec::new();
    for (g1, g2) in pairs {
        data.extend_from_slice(&fq_be_bytes(&g1.x));
        data.extend_from_slice(&fq_be_bytes(&g1.y));
        data.extend_from_slice(&fq_be_bytes(&g2.x.c0));
        data.extend_from_slice(&fq_be_bytes(&g2.x.c1));
        data.extend_from_slice(&fq_be_bytes(&g2.y.c0));
        data.extend_from_slice(&fq_be_bytes(&g2.y.c1));
    }
    data
}

fn fq_be_bytes(f: &ark_bn254::Fq) -> [u8; 32] {
    use ark_ff::PrimeField;
    let bigint = PrimeField::into_bigint(*f);
    let be = bigint.to_bytes_be();
    let mut out = [0u8; 32];
    let start = be.len().saturating_sub(32);
    out[..be.len() - start].copy_from_slice(&be[start..]);
    out
}
