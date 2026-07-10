use runt_host::crypto::CryptoProvider;
use sha3::{Digest, Keccak256};
use wasmtime::Module;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "state" => verify_live_state_proof(&args)?,
        "pairing" => demo_pairing()?,
        "bls" => demo_bls()?,
        "all" => {
            verify_live_state_proof(&args)?;
            demo_pairing()?;
            demo_bls()?;
        }
        _ => print_usage(),
    }
    Ok(())
}

fn print_usage() {
    println!("Runt — Live Proof Verification Demo");
    println!();
    println!("USAGE:");
    println!("  runt-demo state [ADDRESS] [RPC_URL]");
    println!("  runt-demo pairing");
    println!("  runt-demo bls");
    println!("  runt-demo all");
    println!();
    println!("EXAMPLES:");
    println!("  runt-demo state");
    println!("  runt-demo state 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    println!("  runt-demo state 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 https://rpc.ankr.com/eth");
    println!();
    println!("Requires RPC_URL env var or second argument for Ethereum RPC endpoint.");
    println!("RUST_LOG=debug for verbose output.");
}

// ─── Live State Proof from Ethereum RPC ───

fn verify_live_state_proof(args: &[String]) -> anyhow::Result<()> {
    let address = args.get(2)
        .map(|s| s.as_str())
        .unwrap_or("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"); // WETH
    let rpc_url = args.get(3)
        .cloned()
        .or_else(|| std::env::var("RUNT_RPC_URL").ok())
        .unwrap_or_else(|| {
            eprintln!("  Set RUNT_RPC_URL env var or pass as second argument");
            std::process::exit(1);
        });

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Live EIP-1186 State Proof Verification      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  Address: {address}");
    println!();

    let body_str = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getProof",
        "params": [address, [], "latest"],
        "id": 1
    }))?;

    let http_response = ureq::post(&rpc_url).send(&body_str)?;
    let response: serde_json::Value = serde_json::from_reader(http_response.into_body().into_reader())?;

    if let Some(err) = response.get("error") {
        anyhow::bail!("RPC error: {err}");
    }

    let result = &response["result"];
    let balance = u128::from_str_radix(result["balance"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    let nonce = u64::from_str_radix(result["nonce"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)?;
    let proof_nodes: Vec<String> = result["accountProof"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if proof_nodes.is_empty() {
        anyhow::bail!("no proof nodes returned — try a different RPC endpoint");
    }

    let address_bytes = hex::decode(address.trim_start_matches("0x"))?;
    let key = keccak256(&address_bytes);

    let decoded_nodes: Vec<Vec<u8>> = proof_nodes.iter()
        .map(|h| hex::decode(h.trim_start_matches("0x")))
        .collect::<Result<_, _>>()?;

    let state_root = keccak256(&decoded_nodes[0]);
    let proof_bytes = encode_rlp_list(&decoded_nodes.iter().map(|n| n.as_slice()).collect::<Vec<_>>());

    let mut inputs = state_root.to_vec();
    inputs.extend_from_slice(&key);

    println!("  Account:    {address}");
    println!("  Balance:    {} ETH", balance as f64 / 1e18);
    println!("  Nonce:      {nonce}");
    println!();
    println!("  ── Proof Structure ──");
    println!("  State root: 0x{}", hex::encode(state_root));
    println!("  Account key: 0x{}", hex::encode(key));
    println!("  Key nibbles: {}", hex::encode(bytes_to_nibbles(&key)));
    println!();
    println!("  Proof nodes: {} (EIP-1186 RLP-encoded trie nodes)", proof_nodes.len());
    for (i, node) in decoded_nodes.iter().enumerate() {
        let node_hash = keccak256(node);
        let preview: String = hex::encode(&node[..node.len().min(16)]);
        let node_type = match node.first() {
            Some(&b) if b >= 0xf8 => "branch/long-list",
            Some(&b) if b >= 0xc0 => match node[1..].iter().position(|&x| x < 0xc0).unwrap_or(0) {
                2 => "leaf/extension",
                17 => "branch (17 children)",
                _ => "trie-node",
            },
            _ => "raw",
        };
        println!("    [{i}] hash=0x{}..{}  len={}  type={node_type}  data=0x{preview}...",
            hex::encode(&node_hash[..4]),
            hex::encode(&node_hash[28..]),
            node.len(),
        );
    }
    println!();
    println!("  ── Verification ──");
    println!("  Decoding RLP proof list...");
    println!("  Building node hash map (keccak256 each node)...");
    println!("  Walking MPT from state root 0x{}...", hex::encode(&state_root[..8]));
    println!("  Matching nibble path against trie nodes...");
    println!();

    let start = std::time::Instant::now();
    let (code, msg) = load_and_verify("state_verifier.wasm", &proof_bytes, &inputs)?;
    let elapsed = start.elapsed();
    println!("  Verification completed in {elapsed:.2?}");
    println!();
    print_verdict(code, &msg);
    Ok(())
}

// ─── BN254 Pairing Demo ───

fn demo_pairing() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  BN254 Pairing Check                         ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    let provider = runt_host::crypto::DefaultCryptoProvider;
    let pairs = vec![0u8; 192];
    let result = provider.pairing_check(runt_abi::CURVE_BN254, &pairs);
    println!("  Empty point pairing: {}", if !result { "✅ correctly rejected" } else { "❌ unexpected" });

    let valid = provider.pairing_check(runt_abi::CURVE_BN254, &[]);
    println!("  Empty input:         {}", if !valid { "✅ correctly rejected" } else { "❌ unexpected" });

    let wrong = provider.pairing_check(99, &[0u8; 192]);
    println!("  Wrong curve:         {}", if !wrong { "✅ correctly rejected" } else { "❌ unexpected" });
    println!();
    println!("  Add ark-bn254 + ark-ec crates for full Groth16 verification.");
    println!("  Format: 192 bytes per pair (64B G1 uncompressed + 128B G2 uncompressed)");
    println!();
    Ok(())
}

// ─── BLS Signature Demo ───

fn demo_bls() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  BLS12-381 Signature Verification            ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    use blst::min_pk::SecretKey;

    let ikm: [u8; 32] = rand::random();
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key gen");
    let pk = sk.sk_to_pk();
    let msg = b"Runt live verification demo";
    let sig = sk.sign(msg, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);

    let provider = runt_host::crypto::DefaultCryptoProvider;
    let valid = provider.verify_signature(
        runt_abi::SIG_BLS, msg, &sig.to_bytes(), &pk.to_bytes(),
    );
    let invalid = provider.verify_signature(
        runt_abi::SIG_BLS, b"tampered message", &sig.to_bytes(), &pk.to_bytes(),
    );

    println!("  Key gen + sign + verify: {}", if valid { "✅ PASS" } else { "❌ FAIL" });
    println!("  Tampered message reject: {}", if !invalid { "✅ PASS" } else { "❌ FAIL" });
    println!();
    Ok(())
}

// ─── WASM verification ───

fn load_and_verify(wasm_name: &str, proof: &[u8], inputs: &[u8]) -> anyhow::Result<(u32, String)> {
    let store_manager = runt_core::StoreManager::new();
    let loader = runt_host::loader::VerifierLoader::new(store_manager);
    let path = std::path::Path::new("target/wasm32-unknown-unknown/release").join(wasm_name);
    let module = Module::from_file(loader.engine(), &path)?;
    loader.verify(&module, proof, inputs)
}

fn print_verdict(code: u32, msg: &str) {
    match code {
        0 => println!("  ─────────────────────────────────────────\n  Verdict: ✅ VALID — proof verified\n  ─────────────────────────────────────────"),
        1 => println!("  ─────────────────────────────────────────\n  Verdict: ❌ INVALID — {msg}\n  ─────────────────────────────────────────"),
        _ => println!("  ─────────────────────────────────────────\n  Verdict: ⚠️  ERROR — {msg}\n  ─────────────────────────────────────────"),
    }
    println!();
}

// ─── RLP encoding for proof nodes ───

fn encode_rlp_list(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items { payload.extend_from_slice(&rlp_bytes(item)); }
    let mut out = Vec::new();
    rlp_write_header(&mut out, 0xc0, payload.len());
    out.extend_from_slice(&payload);
    out
}

fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 { return data.to_vec(); }
    let mut out = Vec::new();
    rlp_write_header(&mut out, 0x80, data.len());
    out.extend_from_slice(data);
    out
}

fn rlp_write_header(out: &mut Vec<u8>, offset: u8, len: usize) {
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

fn keccak256(data: &[u8]) -> [u8; 32] {
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
