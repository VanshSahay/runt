use runt_wit::{Guest, VerificationStatus, VerifierMetadata};

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

runt_wit::bindings::exports::runt::verifier::verifier::__export_runt_verifier_verifier_cabi!(
    HelloVerifier
    with_types_in runt_wit::bindings::exports::runt::verifier::verifier
);
