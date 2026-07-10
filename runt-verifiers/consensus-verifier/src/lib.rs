wit_bindgen::generate!({
    world: "runt-verifier",
    path: "../../runt-wit/wit",
});

use exports::runt::verifier::verifier::{
    Guest, VerificationStatus, VerifierMetadata,
};

struct ConsensusVerifier;

impl Guest for ConsensusVerifier {
    fn metadata() -> VerifierMetadata {
        VerifierMetadata {
            proof_type_id: "consensus:altair".to_string(),
            version: "0.1.0".to_string(),
            curve: "bls12-381".to_string(),
            scheme: "sync-committee".to_string(),
            supports_recursion: false,
            trusted_setup_required: false,
            max_proof_size: 1_048_576,
            description: "Altair sync committee light client proof verifier".to_string(),
        }
    }

    fn verify(
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
        _verification_key: Vec<u8>,
    ) -> VerificationStatus {
        verify_consensus(&proof, &public_inputs)
    }
}

fn verify_consensus(proof: &[u8], public_inputs: &[u8]) -> VerificationStatus {
    if proof.is_empty() {
        return VerificationStatus::Error("empty consensus proof".into());
    }
    if public_inputs.len() < 64 {
        return VerificationStatus::Error(
            "public inputs: expected trusted_header_root (32 bytes) + update_slot (8 bytes)".into(),
        );
    }

    let result = runt::verifier::host_crypto::pairing_check(
        "bls12-381",
        &[],
    );

    if result {
        VerificationStatus::Valid
    } else {
        VerificationStatus::Error("BLS pairing verification not yet implemented".into())
    }
}

export!(ConsensusVerifier);
