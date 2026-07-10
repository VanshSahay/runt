pub mod composition;
pub mod crypto;
pub mod loader;
pub mod registry;
pub mod router;
pub mod storage;

pub use crypto::CryptoProvider;
pub use loader::VerifierLoader;
pub use registry::VerifierRegistry;
pub use router::VerificationRouter;
pub use storage::StorageProvider;

/// Result of a verification request.
#[derive(Debug, Clone)]
pub enum VerificationResult {
    Valid,
    Invalid(String),
    Error(String),
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
