use runt_abi::*;

#[link(wasm_import_module = "env")]
#[allow(dead_code)]
extern "C" {
    fn host_hash(algorithm: u32, input: *const u8, input_len: u32, output: *mut u8);
    fn host_verify_signature(
        scheme: u32, msg_ptr: *const u8, msg_len: u32,
        sig_ptr: *const u8, sig_len: u32, pk_ptr: *const u8, pk_len: u32,
    ) -> u32;
    fn host_pairing_check(curve: u32, pairs_ptr: *const u8, pairs_len: u32) -> u32;
}

#[no_mangle]
pub extern "C" fn metadata(buf: *mut u8, buf_len: u32) -> u32 {
    let json = r#"{"proof_type_id":"consensus:altair","version":"0.1.0","curve":"bls12-381","scheme":"sync-committee","supports_recursion":false,"trusted_setup_required":false,"max_proof_size":1048576,"description":"Altair sync committee light client proof verifier"}"#;
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
    match verify_consensus(proof, inputs) {
        Ok(_) => VERIFY_VALID,
        Err(e) => {
            let msg = e.as_bytes();
            let len = (msg.len() as u32).min(error_buf_len);
            unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), error_buf, len as usize); }
            VERIFY_INVALID
        }
    }
}

fn verify_consensus(proof: &[u8], inputs: &[u8]) -> Result<(), String> {
    if inputs.len() < 80 {
        return Err("public inputs too short: need attested_header_root(32) + finalized_header_root(32) + signature_slot(8) + participation_bits_offset(8)".into());
    }

    let _attested_root: [u8; 32] = inputs[..32].try_into().map_err(|_| "bad attested_root")?;
    let _finalized_root: [u8; 32] = inputs[32..64].try_into().map_err(|_| "bad finalized_root")?;
    let _sig_slot = u64_from_be(&inputs[64..72]);
    let bits_offset = u64_from_be(&inputs[72..80]) as usize;

    if proof.len() < bits_offset + 64 + 96 {
        return Err("proof too short: need participation_bits(64) + signature(96)".into());
    }

    let bits = &proof[bits_offset..bits_offset + 64];
    let sig = &proof[bits_offset + 64..bits_offset + 64 + 96];

    let participation: u32 = bits.iter().map(|&b| b.count_ones()).sum();
    if participation < 342 {
        return Err(format!("insufficient participation: {}/512", participation));
    }

    let msg = &inputs[..64];
    let result = unsafe {
        host_verify_signature(
            SIG_BLS,
            msg.as_ptr(), msg.len() as u32,
            sig.as_ptr(), sig.len() as u32,
            bits.as_ptr(), bits.len() as u32,
        )
    };

    if result != 0 {
        Ok(())
    } else {
        Err("BLS signature verification failed".into())
    }
}

fn u64_from_be(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes.iter().take(8) { v = (v << 8) | (b as u64); }
    v
}
