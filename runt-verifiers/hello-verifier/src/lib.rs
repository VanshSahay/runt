use runt_abi::*;

#[allow(dead_code)]
extern "C" {
    fn host_hash(algorithm: u32, input: *const u8, input_len: u32, output: *mut u8);
}

#[no_mangle]
pub extern "C" fn metadata(buf: *mut u8, buf_len: u32) -> u32 {
    let json = r#"{"proof_type_id":"hello:dummy","version":"0.1.0","curve":"","scheme":"dummy","supports_recursion":false,"trusted_setup_required":false,"max_proof_size":0,"description":"Hello-world verifier for testing the Runt runtime"}"#;
    let bytes = json.as_bytes();
    let len = (bytes.len() as u32).min(buf_len);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, len as usize);
    }
    len
}

#[no_mangle]
pub extern "C" fn verify(
    _proof: *const u8, _proof_len: u32,
    _inputs: *const u8, _inputs_len: u32,
    error_buf: *mut u8, error_buf_len: u32,
) -> u32 {
    let msg = b"not implemented: placeholder verifier";
    let len = (msg.len() as u32).min(error_buf_len);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.as_ptr(), error_buf, len as usize);
    }
    VERIFY_ERROR
}
