use runt_abi::*;

#[link(wasm_import_module = "env")]
#[allow(dead_code)]
extern "C" {
    fn host_hash(algorithm: u32, input: *const u8, input_len: u32, output: *mut u8);
    fn host_pairing_check(curve: u32, pairs_ptr: *const u8, pairs_len: u32) -> u32;
}

#[no_mangle]
pub extern "C" fn metadata(buf: *mut u8, buf_len: u32) -> u32 {
    let json = r#"{"proof_type_id":"groth16:bn254","version":"0.1.0","curve":"bn254","scheme":"groth16","supports_recursion":false,"trusted_setup_required":true,"max_proof_size":8192,"description":"BN254 Groth16 zero-knowledge proof verifier"}"#;
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
    match verify_groth16(proof, inputs) {
        Ok(_) => VERIFY_VALID,
        Err(e) => {
            let msg = e.as_bytes();
            let len = (msg.len() as u32).min(error_buf_len);
            unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), error_buf, len as usize); }
            VERIFY_INVALID
        }
    }
}

fn verify_groth16(proof: &[u8], _public_inputs: &[u8]) -> Result<(), String> {
    if proof.len() < 128 {
        return Err(format!("Groth16 proof too short: {} bytes (min 128)", proof.len()));
    }

    let result = unsafe {
        host_pairing_check(CURVE_BN254, proof.as_ptr(), proof.len() as u32)
    };

    if result != 0 {
        Ok(())
    } else {
        Err("Groth16 pairing check failed".into())
    }
}
