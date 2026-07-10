use std::path::Path;

use crate::bindings::RuntVerifier;
use crate::bindings::runt::verifier::verifier::VerificationStatus;
use crate::host_impl::HostState;
use crate::loader::VerifierLoader;
use crate::registry::{VerifierMetadata, VerifierRegistry};
use crate::VerificationResult;

pub struct VerificationRouter {
    registry: VerifierRegistry,
    loader: VerifierLoader,
}

impl VerificationRouter {
    pub fn new(registry: VerifierRegistry, loader: VerifierLoader) -> Self {
        Self { registry, loader }
    }

    pub fn load_verifiers(&mut self, dir: &Path) -> anyhow::Result<usize> {
        let count = self.loader.scan_directory(dir)?;
        Ok(count)
    }

    pub fn verify(
        &self,
        _proof_type_id: &str,
        _proof: &[u8],
        _public_inputs: &[u8],
        _verification_key: &[u8],
    ) -> VerificationResult {
        VerificationResult::Error("verification router not yet wired to loaded components".into())
    }

    pub fn registry(&self) -> &VerifierRegistry {
        &self.registry
    }

    pub fn loader(&self) -> &VerifierLoader {
        &self.loader
    }
}
