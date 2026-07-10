use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierMetadata {
    pub proof_type_id: String,
    pub version: String,
    pub curve: String,
    pub scheme: String,
    pub supports_recursion: bool,
    pub trusted_setup_required: bool,
    pub max_proof_size: u64,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum VerificationResult {
    Valid,
    Invalid(String),
    Error(String),
}

impl VerificationResult {
    pub fn from_u32(code: u32, error_msg: &[u8]) -> Self {
        match code {
            runt_abi::VERIFY_VALID => VerificationResult::Valid,
            runt_abi::VERIFY_INVALID => {
                let msg = String::from_utf8_lossy(error_msg).into_owned();
                let msg = msg.trim_end_matches('\0').trim().to_string();
                if msg.is_empty() {
                    VerificationResult::Invalid("proof verification failed".into())
                } else {
                    VerificationResult::Invalid(msg)
                }
            }
            _ => {
                let msg = String::from_utf8_lossy(error_msg).into_owned();
                let msg = msg.trim_end_matches('\0').trim().to_string();
                if msg.is_empty() {
                    VerificationResult::Error("unknown verification error".into())
                } else {
                    VerificationResult::Error(msg)
                }
            }
        }
    }
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid(reason) => write!(f, "invalid: {reason}"),
            Self::Error(reason) => write!(f, "error: {reason}"),
        }
    }
}
