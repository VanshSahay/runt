use runt_core::StoreManager;
use runt_host::crypto::CryptoProvider;
use runt_host::loader::VerifierLoader;
use sha3::{Digest, Keccak256};

#[test]
fn test_state_verifier_valid_leaf_proof() {
    let encoded_path = vec![0x20u8];
    let value = vec![0x42u8; 5];
    let leaf_rlp = rlp_encode_list(&[&encoded_path, &value]);
    let state_root = keccak256(&leaf_rlp);
    let proof = rlp_encode_list(&[&leaf_rlp]);

    let mut inputs = state_root.to_vec();
    inputs.extend_from_slice(&[]);

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let module_path = std::path::Path::new("target/wasm32-unknown-unknown/release/state_verifier.wasm");

    if !module_path.exists() {
        eprintln!("state_verifier.wasm not found, skipping test");
        return;
    }

    let module = wasmtime::Module::from_file(loader.engine(), module_path)
        .expect("failed to load state-verifier module");

    let (result_code, error_msg) = loader
        .verify(&module, &proof, &inputs)
        .expect("verification call failed");

    assert_eq!(
        result_code,
        runt_abi::VERIFY_VALID,
        "expected VALID, got code={result_code} error={error_msg}"
    );
}

#[test]
fn test_state_verifier_wrong_root() {
    let encoded_path = vec![0x20u8];
    let value = vec![0x42u8; 5];
    let leaf_rlp = rlp_encode_list(&[&encoded_path, &value]);
    let proof = rlp_encode_list(&[&leaf_rlp]);

    let wrong_root = [0xFFu8; 32];
    let inputs = wrong_root.to_vec();

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let module_path = std::path::Path::new("target/wasm32-unknown-unknown/release/state_verifier.wasm");

    if !module_path.exists() {
        eprintln!("state_verifier.wasm not found, skipping test");
        return;
    }

    let module = wasmtime::Module::from_file(loader.engine(), module_path)
        .expect("failed to load state-verifier module");

    let (result_code, _error_msg) = loader
        .verify(&module, &proof, &inputs)
        .expect("verification call failed");

    assert_eq!(
        result_code,
        runt_abi::VERIFY_INVALID,
        "expected INVALID for wrong root"
    );
}

#[test]
fn test_state_verifier_missing_node() {
    let proof = rlp_encode_list(&[]);
    let inputs = [0u8; 33].to_vec();

    let store_manager = StoreManager::new();
    let loader = VerifierLoader::new(store_manager);
    let module_path = std::path::Path::new("target/wasm32-unknown-unknown/release/state_verifier.wasm");

    if !module_path.exists() {
        eprintln!("state_verifier.wasm not found, skipping test");
        return;
    }

    let module = wasmtime::Module::from_file(loader.engine(), module_path)
        .expect("failed to load state-verifier module");

    let (result_code, _error_msg) = loader
        .verify(&module, &proof, &inputs)
        .expect("verification call failed");

    assert_eq!(
        result_code,
        runt_abi::VERIFY_INVALID,
        "expected INVALID for empty proof"
    );
}

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
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = Vec::new();
    rlp_write_header(&mut out, 0x80, data.len());
    out.extend_from_slice(data);
    out
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
    if n == 0 {
        return vec![0x80];
    }
    let mut bytes = Vec::new();
    let mut val = n;
    while val > 0 {
        bytes.insert(0, (val & 0xFF) as u8);
        val >>= 8;
    }
    bytes
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
