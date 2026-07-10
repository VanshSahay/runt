use runt_core::StoreManager;
use runt_host::loader::VerifierLoader;
use sha3::{Digest, Keccak256};

fn load_module(loader: &VerifierLoader, name: &str) -> Option<wasmtime::Module> {
    let path = std::path::Path::new("target/wasm32-unknown-unknown/release").join(name);
    if !path.exists() {
        eprintln!("{name} not found, skipping test");
        return None;
    }
    wasmtime::Module::from_file(loader.engine(), &path).ok()
}

#[test]
fn test_tx_verifier_valid_receipt_proof() {
    let tx_index = 5u64;
    let receipt_data = vec![0x01u8, 0x02, 0x03];
    let key = rlp_encode_u64(tx_index);
    let encoded_path = leaf_path(&bytes_to_nibbles(&key));
    let leaf_rlp = rlp_encode_list(&[&encoded_path, &receipt_data]);
    let receipts_root = keccak256(&leaf_rlp);
    let proof = rlp_encode_list(&[&leaf_rlp]);

    let mut inputs = receipts_root.to_vec();
    inputs.extend_from_slice(&tx_index.to_be_bytes());

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let module = match load_module(&loader, "tx_verifier.wasm") {
        Some(m) => m,
        None => return,
    };

    let (code, msg) = loader.verify(&module, &proof, &inputs).expect("verify failed");
    assert_eq!(code, runt_abi::VERIFY_VALID, "expected VALID, got {msg}");
}

#[test]
fn test_tx_verifier_wrong_root() {
    let tx_index = 5u64;
    let receipt_data = vec![0x01u8];
    let key = rlp_encode_u64(tx_index);
    let encoded_path = leaf_path(&bytes_to_nibbles(&key));
    let leaf_rlp = rlp_encode_list(&[&encoded_path, &receipt_data]);
    let proof = rlp_encode_list(&[&leaf_rlp]);
    let wrong_root = [0xFFu8; 32];
    let mut inputs = wrong_root.to_vec();
    inputs.extend_from_slice(&tx_index.to_be_bytes());

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let module = match load_module(&loader, "tx_verifier.wasm") {
        Some(m) => m,
        None => return,
    };

    let (code, _msg) = loader.verify(&module, &proof, &inputs).expect("verify failed");
    assert_eq!(code, runt_abi::VERIFY_INVALID, "expected INVALID for wrong root");
}

#[test]
fn test_tx_verifier_wrong_tx_index() {
    let tx_index = 5u64;
    let receipt_data = vec![0x01u8];
    let key = rlp_encode_u64(tx_index);
    let encoded_path = leaf_path(&bytes_to_nibbles(&key));
    let leaf_rlp = rlp_encode_list(&[&encoded_path, &receipt_data]);
    let receipts_root = keccak256(&leaf_rlp);
    let proof = rlp_encode_list(&[&leaf_rlp]);

    let wrong_index = 99u64;
    let mut inputs = receipts_root.to_vec();
    inputs.extend_from_slice(&wrong_index.to_be_bytes());

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let module = match load_module(&loader, "tx_verifier.wasm") {
        Some(m) => m,
        None => return,
    };

    let (code, _msg) = loader.verify(&module, &proof, &inputs).expect("verify failed");
    assert_eq!(code, runt_abi::VERIFY_INVALID, "expected INVALID for wrong tx index");
}

// --- RLP encoding helpers ---

fn rlp_encode_list(items: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items {
        payload.extend_from_slice(&rlp_encode_bytes(item));
    }
    let mut out = Vec::new();
    rlp_write_header(&mut out, 0xc0, payload.len());
    out.extend_from_slice(&payload);
    out
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 { return data.to_vec(); }
    let mut out = Vec::new();
    rlp_write_header(&mut out, 0x80, data.len());
    out.extend_from_slice(data);
    out
}

fn rlp_encode_u64(n: u64) -> Vec<u8> {
    if n == 0 { return vec![0x80]; }
    let mut bytes = Vec::new();
    let mut val = n;
    while val > 0 { bytes.insert(0, (val & 0xFF) as u8); val >>= 8; }
    rlp_encode_bytes(&bytes)
}

fn rlp_write_header(out: &mut Vec<u8>, offset: u8, len: usize) {
    if len < 55 {
        out.push(offset + len as u8);
    } else {
        let len_bytes = usize_to_bytes(len);
        out.push(offset + 55 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
}

fn usize_to_bytes(n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut val = n;
    while val > 0 { bytes.insert(0, (val & 0xFF) as u8); val >>= 8; }
    bytes
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

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
