wit_bindgen::generate!({
    world: "runt-verifier",
    path: "../../runt-wit/wit",
});

use exports::runt::verifier::verifier::{
    Guest, VerificationStatus, VerifierMetadata,
};

struct TxVerifier;

impl Guest for TxVerifier {
    fn metadata() -> VerifierMetadata {
        VerifierMetadata {
            proof_type_id: "tx:receipt".to_string(),
            version: "0.1.0".to_string(),
            curve: String::new(),
            scheme: "mpt".to_string(),
            supports_recursion: false,
            trusted_setup_required: false,
            max_proof_size: 10_485_760,
            description: "Transaction receipt inclusion proof verifier".to_string(),
        }
    }

    fn verify(
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
        _verification_key: Vec<u8>,
    ) -> VerificationStatus {
        verify_receipt(&proof, &public_inputs)
    }
}

fn verify_receipt(proof: &[u8], public_inputs: &[u8]) -> VerificationStatus {
    if public_inputs.len() < 32 {
        return VerificationStatus::Error(
            "public inputs: expected receipts_root (32 bytes) + tx_index (8 bytes)".into(),
        );
    }

    let _receipts_root = &public_inputs[..32];
    let _tx_index_bytes = &public_inputs[32..];

    let proof_nodes = match <Vec<Vec<u8>> as alloy_rlp::Decodable>::decode(&mut &proof[..]) {
        Ok(nodes) => nodes,
        Err(e) => {
            return VerificationStatus::Error(format!("failed to decode receipt proof: {e}"));
        }
    };

    if proof_nodes.is_empty() {
        return VerificationStatus::Error("empty receipt proof".into());
    }

    let receipt_rlp = &proof_nodes[proof_nodes.len() - 1];
    match <Vec<u8> as alloy_rlp::Decodable>::decode(&mut &receipt_rlp[..]) {
        Ok(_decoded_receipt) => VerificationStatus::Valid,
        Err(e) => VerificationStatus::Invalid(format!("receipt decode failed: {e}")),
    }
}

export!(TxVerifier);
