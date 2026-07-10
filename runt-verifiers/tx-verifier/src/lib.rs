use runt_abi::*;

#[link(wasm_import_module = "env")]
extern "C" {
    fn host_hash(algorithm: u32, input: *const u8, input_len: u32, output: *mut u8);
}

#[no_mangle]
pub extern "C" fn metadata(buf: *mut u8, buf_len: u32) -> u32 {
    let json = r#"{"proof_type_id":"tx:receipt","version":"0.1.0","curve":"","scheme":"mpt","supports_recursion":false,"trusted_setup_required":false,"max_proof_size":10485760,"description":"Transaction receipt inclusion proof verifier"}"#;
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
    match verify_receipt_proof(proof, inputs) {
        Ok(_) => VERIFY_VALID,
        Err(e) => write_error(e, error_buf, error_buf_len),
    }
}

fn write_error(msg: String, buf: *mut u8, buf_len: u32) -> u32 {
    let bytes = msg.as_bytes();
    let len = (bytes.len() as u32).min(buf_len);
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len as usize); }
    VERIFY_INVALID
}

fn verify_receipt_proof(proof: &[u8], inputs: &[u8]) -> Result<(), String> {
    if inputs.len() < 40 {
        return Err("public inputs too short: need receipts_root (32 bytes) + tx_index (8 bytes BE)".into());
    }
    let receipts_root: [u8; 32] = inputs[..32].try_into().map_err(|_| "bad receipts_root")?;
    let tx_index = u64_from_be(&inputs[32..40]);
    let extra = if inputs.len() > 40 { &inputs[40..] } else { &[] };

    let key = rlp_encode_u64(tx_index);
    let nodes = decode_rlp_list(proof).ok_or("failed to decode proof RLP")?;
    if nodes.is_empty() {
        return Err("empty proof".into());
    }

    let mut node_map = NodeMap::new();
    for node_bytes in &nodes {
        let hash = keccak256(node_bytes);
        node_map.insert(hash, node_bytes);
    }

    let nibbles = bytes_to_nibbles(&key);
    let value = walk_trie(&node_map, &receipts_root, &nibbles)?;

    let _receipt = decode_rlp_item(&value)
        .ok_or("failed to decode receipt RLP")?;

    if !extra.is_empty() {
        if extra.len() <= value.len() && extra != &value[..extra.len()] {
            return Err("receipt data mismatch with expected".into());
        }
    }

    Ok(())
}

// --- MPT implementation (same as state-verifier, kept self-contained for minimal WASM) ---

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { host_hash(HASH_KECCAK256, data.as_ptr(), data.len() as u32, out.as_mut_ptr()); }
    out
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut n = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes { n.push(b >> 4); n.push(b & 0x0F); }
    n
}

fn u64_from_be(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes.iter().take(8) { v = (v << 8) | (b as u64); }
    v
}

fn rlp_encode_u64(n: u64) -> Vec<u8> {
    if n == 0 { return vec![0x80]; }
    let mut bytes = Vec::new();
    let mut val = n;
    while val > 0 { bytes.insert(0, (val & 0xFF) as u8); val >>= 8; }
    if bytes.len() == 1 && bytes[0] < 0x80 { bytes }
    else {
        let mut out = vec![0x80 + bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

// --- Minimal RLP decoder ---

fn decode_rlp_list(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() { return None; }
    let first = data[0];
    let payload = if first >= 0xc0 {
        read_rlp_payload(data, 0xc0)?.0
    } else { return None; };
    let mut items = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        let (item, consumed) = decode_rlp_item(&payload[pos..])?;
        items.push(item.to_vec());
        pos += consumed;
    }
    if pos != payload.len() { None } else { Some(items) }
}

fn decode_rlp_item(data: &[u8]) -> Option<(&[u8], usize)> {
    let first = *data.first()?;
    if first < 0x80 { return Some((&data[..1], 1)); }
    if first < 0xb8 {
        let len = (first - 0x80) as usize;
        if data.len() < 1 + len { return None; }
        return Some((&data[1..1 + len], 1 + len));
    }
    if first < 0xc0 {
        let len_of_len = (first - 0xb7) as usize;
        if data.len() < 1 + len_of_len { return None; }
        let len = bytes_to_usize(&data[1..1 + len_of_len]);
        if data.len() < 1 + len_of_len + len { return None; }
        return Some((&data[1 + len_of_len..1 + len_of_len + len], 1 + len_of_len + len));
    }
    if first < 0xf8 {
        let (payload, prefix_len) = read_rlp_payload(data, 0xc0)?;
        let _total = data.len() - payload.len();
        return Some((&data[..prefix_len + payload.len()], prefix_len + payload.len()));
    }
    None
}

fn read_rlp_payload(data: &[u8], offset: u8) -> Option<(&[u8], usize)> {
    let first = *data.first()?;
    if first < offset { return None; }
    let diff = (first - offset) as usize;
    let (payload_len, prefix_len) = if diff < 55 {
        (diff, 1usize)
    } else {
        let len_size = diff - 55;
        if data.len() < 1 + len_size { return None; }
        (bytes_to_usize(&data[1..1 + len_size]), 1 + len_size)
    };
    if data.len() < prefix_len + payload_len { return None; }
    Some((&data[prefix_len..prefix_len + payload_len], prefix_len))
}

fn bytes_to_usize(bytes: &[u8]) -> usize {
    let mut r: usize = 0;
    for &b in bytes { r = r.checked_shl(8).unwrap_or(0) | (b as usize); }
    r
}

// --- Node hash map ---

struct NodeMap { entries: Vec<([u8; 32], Vec<u8>)> }

impl NodeMap {
    fn new() -> Self { Self { entries: Vec::new() } }
    fn insert(&mut self, hash: [u8; 32], data: &[u8]) { self.entries.push((hash, data.to_vec())); }
    fn get(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.entries.iter().find(|(h, _)| h == hash).map(|(_, n)| n.as_slice())
    }
}

// --- MPT walker ---

fn walk_trie(node_map: &NodeMap, root: &[u8; 32], nibbles: &[u8]) -> Result<Vec<u8>, String> {
    let mut current_hash = *root;
    let mut path_offset: usize = 0;
    loop {
        let node = node_map.get(&current_hash)
            .ok_or_else(|| format!("missing trie node"))?;
        let decoded = decode_rlp_list(node).ok_or("failed to decode trie node")?;
        match decoded.len() {
            2 => {
                let encoded_path = &decoded[0];
                if encoded_path.is_empty() { return Err("empty path".into()); }
                let prefix = encoded_path[0];
                let is_leaf = (prefix & 0x20) != 0;
                let (path_nibs, _) = decode_hex_prefix(prefix, &encoded_path[1..]);
                let remaining = &nibbles[path_offset..];
                if path_nibs.len() > remaining.len() {
                    return Err("path longer than remaining key".into());
                }
                if path_nibs != &remaining[..path_nibs.len()] {
                    return Err("path mismatch".into());
                }
                if is_leaf { return Ok(decoded[1].clone()); }
                path_offset += path_nibs.len();
                if decoded[1].len() != 32 { return Err("extension child not 32 bytes".into()); }
                current_hash.copy_from_slice(&decoded[1]);
            }
            17 => {
                if path_offset >= nibbles.len() {
                    let val = &decoded[16];
                    if val.len() <= 1 && (val.is_empty() || val[0] == 0x80) {
                        return Err("no value at branch".into());
                    }
                    return Ok(val.to_vec());
                }
                let nib = nibbles[path_offset] as usize;
                path_offset += 1;
                let child = &decoded[nib];
                if child.len() <= 1 && (child.is_empty() || child[0] == 0x80) {
                    return Err("dead end at branch".into());
                }
                if child.len() == 32 {
                    current_hash.copy_from_slice(child);
                } else {
                    current_hash = keccak256(child);
                }
            }
            _ => return Err(format!("unknown node type: {} elements", decoded.len())),
        }
    }
}

fn decode_hex_prefix(prefix: u8, encoded: &[u8]) -> (Vec<u8>, bool) {
    let odd = (prefix & 0x10) != 0;
    let mut n = Vec::new();
    if odd { n.push(prefix & 0x0F); }
    for &b in encoded { n.push(b >> 4); n.push(b & 0x0F); }
    (n, odd)
}
