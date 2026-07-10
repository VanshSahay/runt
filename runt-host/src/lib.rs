pub mod bindings;
pub mod composition;
pub mod crypto;
pub mod host_impl;
pub mod loader;
pub mod registry;
pub mod router;
pub mod storage;

pub use crypto::CryptoProvider;
pub use host_impl::HostState;
pub use loader::VerifierLoader;
pub use registry::VerifierRegistry;
pub use router::VerificationRouter;
pub use storage::StorageProvider;

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
