wit_bindgen::generate!({
    world: "runt-verifier",
    path: "../../runt-wit/wit",
});

use exports::runt::verifier::verifier::{
    Guest, VerificationStatus, VerifierMetadata,
};

struct HelloVerifier;

impl Guest for HelloVerifier {
    fn metadata() -> VerifierMetadata {
        VerifierMetadata {
            proof_type_id: "hello:dummy".to_string(),
            version: "0.1.0".to_string(),
            curve: String::new(),
            scheme: "dummy".to_string(),
            supports_recursion: false,
            trusted_setup_required: false,
            max_proof_size: 0,
            description: "Hello-world verifier for testing the Runt runtime".to_string(),
        }
    }

    fn verify(
        _proof: Vec<u8>,
        _public_inputs: Vec<u8>,
        _verification_key: Vec<u8>,
    ) -> VerificationStatus {
        VerificationStatus::Error("not implemented: this is a placeholder verifier".to_string())
    }
}

export!(HelloVerifier);
