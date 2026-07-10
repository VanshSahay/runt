use std::path::Path;

use crate::loader::VerifierLoader;
use crate::registry::VerifierRegistry;
use crate::types::VerificationResult;

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
        for (metadata, _module, _path) in self.loader.modules() {
            let type_id = metadata.proof_type_id.clone();
            self.registry.register(metadata.clone());
            eprintln!("Registered verifier: {type_id}");
        }
        Ok(count)
    }

    pub fn verify(
        &self,
        proof_type_id: &str,
        proof: &[u8],
        public_inputs: &[u8],
    ) -> VerificationResult {
        let module = match self
            .loader
            .modules()
            .iter()
            .find(|(m, _, _)| m.proof_type_id == proof_type_id)
        {
            Some((_, module, _)) => module,
            None => {
                return VerificationResult::Error(format!(
                    "no verifier found for proof type: {proof_type_id}"
                ));
            }
        };

        match self.loader.verify(module, proof, public_inputs) {
            Ok((code, msg)) => VerificationResult::from_u32(code, msg.as_bytes()),
            Err(e) => VerificationResult::Error(format!("verification failed: {e}")),
        }
    }

    pub fn registry(&self) -> &VerifierRegistry {
        &self.registry
    }

    pub fn loader(&self) -> &VerifierLoader {
        &self.loader
    }
}
