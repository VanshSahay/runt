wit_bindgen::generate!({
    world: "runt-verifier",
    path: "../../runt-wit/wit",
});

use exports::runt::verifier::verifier::{
    Guest, VerificationStatus, VerifierMetadata,
};

struct Groth16Verifier;

impl Guest for Groth16Verifier {
    fn metadata() -> VerifierMetadata {
        VerifierMetadata {
            proof_type_id: "groth16:bn254".to_string(),
            version: "0.1.0".to_string(),
            curve: "bn254".to_string(),
            scheme: "groth16".to_string(),
            supports_recursion: false,
            trusted_setup_required: true,
            max_proof_size: 8192,
            description: "BN254 Groth16 zero-knowledge proof verifier".to_string(),
        }
    }

    fn verify(
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
        verification_key: Vec<u8>,
    ) -> VerificationStatus {
        verify_groth16(&proof, &public_inputs, &verification_key)
    }
}

fn verify_groth16(proof: &[u8], _public_inputs: &[u8], vk: &[u8]) -> VerificationStatus {
    if vk.is_empty() {
        return VerificationStatus::Error(
            "verification key required for Groth16 proof verification".into(),
        );
    }
    if proof.len() < 128 {
        return VerificationStatus::Error("Groth16 proof must be at least 128 bytes".into());
    }

    let result = runt::verifier::host_crypto::pairing_check("bn254", proof);

    if result {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Error("BN254 pairing verification not yet implemented".into())
    }
}

export!(Groth16Verifier);
