use runt_abi::*;

#[link(wasm_import_module = "env")]
extern "C" {
    fn host_hash(algorithm: u32, input: *const u8, input_len: u32, output: *mut u8);
}

#[no_mangle]
pub extern "C" fn metadata(buf: *mut u8, buf_len: u32) -> u32 {
    let json = r#"{"proof_type_id":"state:eip1186","version":"0.1.0","curve":"","scheme":"mpt","supports_recursion":false,"trusted_setup_required":false,"max_proof_size":10485760,"description":"EIP-1186 Merkle Patricia Trie state proof verifier"}"#;
    let bytes = json.as_bytes();
    let len = (bytes.len() as u32).min(buf_len);
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len as usize); }
    len
}

#[no_mangle]
pub extern "C" fn verify(
    proof_ptr: *const u8, proof_len: u32,
    inputs_ptr: *const u8, inputs_len: u32,
    error_buf: *mut u8, error_buf_len: u32,
) -> u32 {
    let proof = unsafe { core::slice::from_raw_parts(proof_ptr, proof_len as usize) };
    let inputs = unsafe { core::slice::from_raw_parts(inputs_ptr, inputs_len as usize) };

    match verify_state_proof(proof, inputs) {
        Ok(_) => VERIFY_VALID,
        Err(e) => {
            let msg = e.as_bytes();
            let len = (msg.len() as u32).min(error_buf_len);
            unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), error_buf, len as usize); }
            VERIFY_INVALID
        }
    }
}

fn verify_state_proof(proof: &[u8], inputs: &[u8]) -> Result<(), String> {
    if inputs.len() < 32 {
        return Err("public inputs too short: need state_root (32 bytes) + key".into());
    }
    let state_root: [u8; 32] = inputs[..32].try_into().map_err(|_| "bad state_root")?;
    let key = &inputs[32..];

    let nodes = decode_rlp_list(proof).ok_or("failed to decode proof RLP")?;
    if nodes.is_empty() {
        return Err("empty proof: no trie nodes".into());
    }

    let mut node_map = NodeMap::new();
    for node_bytes in &nodes {
        let hash = keccak256(node_bytes);
        node_map.insert(hash, node_bytes);
    }

    let nibbles = bytes_to_nibbles(key);
    let root_hash: [u8; 32] = state_root;

    let _value = walk_trie(&node_map, root_hash, &nibbles)?;
    Ok(())
}

// ---- RLP decoder ----

fn decode_rlp_list(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    let payload = if first >= 0xc0 {
        let (payload, _prefix) = read_rlp_payload(data, 0xc0)?;
        payload
    } else {
        return None;
    };
    let mut items = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        let (item, consumed) = read_rlp_item(&payload[pos..])?;
        items.push(item.to_vec());
        pos += consumed;
    }
    if pos != payload.len() {
        return None;
    }
    Some(items)
}

fn read_rlp_payload(data: &[u8], offset: u8) -> Option<(&[u8], usize)> {
    let first = *data.first()?;
    if first < offset {
        return None;
    }
    let payload_len: usize;
    let prefix_len: usize;
    let diff = (first - offset) as usize;
    if diff < 55 {
        payload_len = diff;
        prefix_len = 1;
    } else {
        let len_size = diff - 55;
        if data.len() < 1 + len_size {
            return None;
        }
        payload_len = bytes_to_usize(&data[1..1 + len_size]);
        prefix_len = 1 + len_size;
    }
    if data.len() < prefix_len + payload_len {
        return None;
    }
    Some((&data[prefix_len..prefix_len + payload_len], prefix_len + payload_len))
}

fn read_rlp_item(data: &[u8]) -> Option<(&[u8], usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        return Some((&data[..1], 1));
    }
    if first < 0xb8 {
        let len = (first - 0x80) as usize;
        if data.len() < 1 + len {
            return None;
        }
        return Some((&data[1..1 + len], 1 + len));
    }
    if first < 0xc0 {
        let len_of_len = (first - 0xb7) as usize;
        if data.len() < 1 + len_of_len {
            return None;
        }
        let len = bytes_to_usize(&data[1..1 + len_of_len]);
        if data.len() < 1 + len_of_len + len {
            return None;
        }
        return Some((&data[1 + len_of_len..1 + len_of_len + len], 1 + len_of_len + len));
    }
    if first < 0xf8 {
        let (payload, _consumed) = read_rlp_payload(data, 0xc0)?;
        let total = data.len() - payload.len();
        return Some((&data[..total], total));
    }
    None
}

fn bytes_to_usize(bytes: &[u8]) -> usize {
    let mut result: usize = 0;
    for &b in bytes {
        result = result.checked_shl(8).unwrap_or(0) | (b as usize);
    }
    result
}

// ---- Node hash map ----

struct NodeMap {
    hashes: Vec<([u8; 32], Vec<u8>)>,
}

impl NodeMap {
    fn new() -> Self {
        Self { hashes: Vec::new() }
    }

    fn insert(&mut self, hash: [u8; 32], node: &[u8]) {
        self.hashes.push((hash, node.to_vec()));
    }

    fn get(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.hashes.iter().find(|(h, _)| h == hash).map(|(_, n)| n.as_slice())
    }
}

// ---- MPT walker ----

fn walk_trie(
    node_map: &NodeMap,
    root: [u8; 32],
    nibbles: &[u8],
) -> Result<Vec<u8>, String> {
    let mut current_hash = root;
    let mut path_offset: usize = 0;

    loop {
        let node = node_map.get(&current_hash)
            .ok_or_else(|| format!("missing trie node: {}", hex32(&current_hash)))?;

        let decoded = decode_rlp_list(node).ok_or("failed to decode trie node RLP")?;
        let count = decoded.len();

        if count == 2 {
            let encoded_path = &decoded[0];
            if encoded_path.is_empty() {
                return Err("empty encoded path".into());
            }
            let prefix = encoded_path[0];
            let is_leaf = (prefix & 0x20) != 0;
            let (path_nibbles, _odd) = decode_hex_prefix(prefix, &encoded_path[1..]);

            if is_leaf {
                let remaining = &nibbles[path_offset..];
                if path_nibbles.len() > remaining.len() {
                    return Err("leaf path longer than remaining key".into());
                }
                if path_nibbles != &remaining[..path_nibbles.len()] {
                    return Err(format!(
                        "leaf path mismatch: expected {}, got {}",
                        nibbles_hex(&path_nibbles),
                        nibbles_hex(&remaining[..path_nibbles.len().min(remaining.len())]),
                    ));
                }
                return Ok(decoded[1].clone());
            } else {
                let remaining = &nibbles[path_offset..];
                if path_nibbles.len() > remaining.len() {
                    return Err("extension path longer than remaining key".into());
                }
                if path_nibbles != &remaining[..path_nibbles.len()] {
                    return Err(format!(
                        "extension path mismatch: expected {}, got {}",
                        nibbles_hex(&path_nibbles),
                        nibbles_hex(&remaining[..path_nibbles.len().min(remaining.len())]),
                    ));
                }
                path_offset += path_nibbles.len();
                if decoded[1].len() != 32 {
                    return Err(format!("extension child must be 32 bytes, got {}", decoded[1].len()));
                }
                current_hash = decoded[1].as_slice().try_into().map_err(|_| "bad extension child hash")?;
            }
        } else if count == 17 {
            if path_offset >= nibbles.len() {
                let val = &decoded[16];
                if val.len() <= 1 && (val.is_empty() || val[0] == 0x80) {
                    return Err("dead end at branch node: no value".into());
                }
                return Ok(val.clone());
            }
            let nibble = nibbles[path_offset] as usize;
            path_offset += 1;
            let child = &decoded[nibble];
            if child.len() <= 1 && (child.is_empty() || child[0] == 0x80) {
                return Err(format!("dead end at branch child {nibble}"));
            }
            if child.len() == 32 {
                current_hash = child.as_slice().try_into().map_err(|_| "bad branch child hash")?;
            } else {
                let child_hash = keccak256(child);
                current_hash = child_hash;
            }
        } else {
            return Err(format!("unknown trie node type: {count} elements"));
        }
    }
}

// ---- Hex-prefix encoding ----

fn decode_hex_prefix(prefix: u8, encoded: &[u8]) -> (Vec<u8>, bool) {
    let odd = (prefix & 0x10) != 0;
    let mut nibbles = Vec::new();
    if odd {
        nibbles.push(prefix & 0x0F);
    }
    for &byte in encoded {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    (nibbles, odd)
}

// ---- Utility functions ----

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    nibbles
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        host_hash(HASH_KECCAK256, data.as_ptr(), data.len() as u32, out.as_mut_ptr());
    }
    out
}

fn hex32(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0F) as usize]);
    }
    s
}

fn nibbles_hex(n: &[u8]) -> String {
    let mut s = String::with_capacity(n.len());
    for &b in n {
        s.push(HEX_CHARS[b as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
