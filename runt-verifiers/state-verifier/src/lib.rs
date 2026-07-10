wit_bindgen::generate!({
    world: "runt-verifier",
    path: "../../runt-wit/wit",
});

use exports::runt::verifier::verifier::{
    Guest, VerificationStatus, VerifierMetadata,
};

struct StateVerifier;

impl Guest for StateVerifier {
    fn metadata() -> VerifierMetadata {
        VerifierMetadata {
            proof_type_id: "state:eip1186".to_string(),
            version: "0.1.0".to_string(),
            curve: String::new(),
            scheme: "mpt".to_string(),
            supports_recursion: false,
            trusted_setup_required: false,
            max_proof_size: 10_485_760,
            description: "EIP-1186 Merkle Patricia Trie state proof verifier".to_string(),
        }
    }

    fn verify(
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
        verification_key: Vec<u8>,
    ) -> VerificationStatus {
        verify_eip1186(&proof, &public_inputs, &verification_key)
    }
}

fn verify_eip1186(proof: &[u8], public_inputs: &[u8], _vk: &[u8]) -> VerificationStatus {
    let Ok(inputs) = parse_public_inputs(public_inputs) else {
        return VerificationStatus::Error(
            "failed to parse public inputs: expected state_root (32 bytes) + key (bytes)".into(),
        );
    };

    if inputs.state_root.len() != 32 {
        return VerificationStatus::Error("state_root must be 32 bytes".into());
    }

    let proof_nodes = match <Vec<Vec<u8>> as alloy_rlp::Decodable>::decode(&mut &proof[..]) {
        Ok(nodes) => nodes,
        Err(e) => {
            return VerificationStatus::Error(format!("failed to decode RLP proof: {e}"));
        }
    };

    if proof_nodes.is_empty() {
        return VerificationStatus::Error("empty proof: no trie nodes provided".into());
    }

    match walk_mpt(&proof_nodes, &inputs.state_root, &inputs.key) {
        Ok(value) => {
            if let Some(expected) = inputs.expected_value {
                if value != expected {
                    return VerificationStatus::Invalid(
                        "value mismatch: trie value does not match expected".into(),
                    );
                }
            }
            VerificationStatus::Valid
        }
        Err(reason) => VerificationStatus::Invalid(reason),
    }
}

struct Eip1186Inputs {
    state_root: Vec<u8>,
    key: Vec<u8>,
    expected_value: Option<Vec<u8>>,
}

fn parse_public_inputs(data: &[u8]) -> Result<Eip1186Inputs, ()> {
    if data.len() < 32 {
        return Err(());
    }
    let state_root = data[..32].to_vec();
    let key = data[32..].to_vec();
    Ok(Eip1186Inputs {
        state_root,
        key,
        expected_value: None,
    })
}

fn walk_mpt(
    nodes: &[Vec<u8>],
    root: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, String> {
    use alloy_primitives::B256;

    let root_hash = B256::from_slice(root);
    let nibbles = bytes_to_nibbles(key);

    let mut node_map: std::collections::HashMap<B256, &Vec<u8>> =
        std::collections::HashMap::new();

    for node in nodes {
        let hash = runt::verifier::host_crypto::hash("keccak256", node);
        node_map.insert(B256::from_slice(&hash), node);
    }

    let mut current_hash = root_hash;
    let mut path_offset: usize = 0;

    loop {
        let node = node_map
            .get(&current_hash)
            .ok_or_else(|| format!("missing trie node: {current_hash}"))?;

        let node_type = node.first().copied().unwrap_or(0);

        if node_type == 0 {
            return verify_leaf(node, &nibbles[path_offset..]);
        }

        if node_type == 1 {
            let consumed = verify_extension(node, &nibbles[path_offset..])?;
            path_offset += consumed;
            current_hash = B256::from_slice(&node[node.len() - 32..]);
            continue;
        }

        if node_type == 2 {
            if path_offset >= nibbles.len() {
                return Err("exhausted path at branch node".into());
            }
            let nibble = nibbles[path_offset] as usize;
            path_offset += 1;
            let child_offset = 1 + (nibble * 32);
            if child_offset + 32 > node.len() {
                return Err(format!("branch child {nibble} out of bounds"));
            }
            let child_hash = B256::from_slice(&node[child_offset..child_offset + 32]);
            if child_hash == B256::ZERO {
                if path_offset >= nibbles.len() {
                    return Ok(node[1 + 16 * 32..].to_vec());
                }
                return Err("dead end at branch node".into());
            }
            current_hash = child_hash;
            continue;
        }

        return Err(format!("unknown node type: {node_type}"));
    }
}

fn verify_leaf(node: &[u8], remaining_nibbles: &[u8]) -> Result<Vec<u8>, String> {
    let prefix = node.get(1).copied().unwrap_or(0);
    let (prefix_nibbles, is_leaf) = decode_compact(prefix);

    if !is_leaf {
        return Err("expected leaf node".into());
    }

    let encoded_path: Vec<u8> = node[2..]
        .iter()
        .take((prefix_nibbles + 1) / 2)
        .copied()
        .collect();
    let node_nibbles = bytes_to_nibbles(&encoded_path);

    if prefix_nibbles > 0
        && node_nibbles[..prefix_nibbles.min(node_nibbles.len())]
            != remaining_nibbles[..prefix_nibbles.min(remaining_nibbles.len())]
    {
        return Err("leaf path mismatch".into());
    }

    let skip = 2 + ((prefix_nibbles + 1) / 2);
    Ok(node[skip..].to_vec())
}

fn verify_extension(node: &[u8], remaining_nibbles: &[u8]) -> Result<usize, String> {
    let prefix = node.get(1).copied().unwrap_or(0);
    let (prefix_nibbles, is_leaf) = decode_compact(prefix);

    if is_leaf {
        return Err("expected extension node".into());
    }

    let encoded_path: Vec<u8> = node[2..]
        .iter()
        .take((prefix_nibbles + 1) / 2)
        .copied()
        .collect();
    let node_nibbles = bytes_to_nibbles(&encoded_path);

    if prefix_nibbles > remaining_nibbles.len() {
        return Err("extension path too long".into());
    }

    if node_nibbles[..prefix_nibbles] != remaining_nibbles[..prefix_nibbles] {
        return Err("extension path mismatch".into());
    }

    Ok(prefix_nibbles)
}

fn decode_compact(prefix: u8) -> (usize, bool) {
    let is_leaf = (prefix & 0x20) != 0;
    let len = if (prefix & 0x10) != 0 {
        ((prefix & 0x0F) as usize) + 1
    } else {
        ((prefix & 0x0F) as usize) + 2
    };
    (len, is_leaf)
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    nibbles
}

export!(StateVerifier);
