use anyhow::Result;
use runt_core::StoreManager;
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::Store;

use crate::bindings::RuntVerifier;
use crate::host_impl::HostState;
use crate::registry::VerifierMetadata;

pub struct LoadedComponent {
    pub component: Component,
    pub path: PathBuf,
}

pub struct VerifierLoader {
    store_manager: StoreManager,
    engine: wasmtime::Engine,
    linker: Linker<HostState>,
    components: Vec<LoadedComponent>,
}

impl VerifierLoader {
    pub fn new(store_manager: StoreManager) -> Result<Self> {
        let engine = store_manager.engine().clone();
        let mut linker: Linker<HostState> = Linker::new(&engine);

        RuntVerifier::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .map_err(|e| anyhow::anyhow!("failed to link host imports: {e}"))?;

        Ok(Self {
            store_manager,
            engine,
            linker,
            components: Vec::new(),
        })
    }

    pub fn scan_directory(&mut self, dir: &Path) -> Result<usize> {
        let mut count = 0;
        for entry in std::fs::read_dir(dir)
            .map_err(|e| anyhow::anyhow!("failed to read directory {}: {e}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "wasm") {
                self.load_component(&path)?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn load_component(&mut self, path: &Path) -> Result<()> {
        let component = Component::from_file(&self.engine, path)
            .map_err(|e| anyhow::anyhow!("failed to load component {}: {e}", path.display()))?;
        self.components.push(LoadedComponent {
            component,
            path: path.to_path_buf(),
        });
        Ok(())
    }

    pub fn extract_metadata(&self) -> Result<Vec<VerifierMetadata>> {
        let mut results = Vec::new();
        for loaded in &self.components {
            let mut store = Store::new(&self.engine, HostState::default());
            let bindings = RuntVerifier::instantiate(
                &mut store,
                &loaded.component,
                &self.linker,
            )?;
            let meta = bindings
                .runt_verifier_verifier()
                .call_metadata(&mut store)
                .map_err(|e| anyhow::anyhow!("failed to call metadata: {e}"))?;

            results.push(VerifierMetadata {
                proof_type_id: meta.proof_type_id,
                version: meta.version,
                curve: meta.curve,
                scheme: meta.scheme,
                supports_recursion: meta.supports_recursion,
                trusted_setup_required: meta.trusted_setup_required,
                max_proof_size: meta.max_proof_size,
                description: meta.description,
            });
        }
        Ok(results)
    }

    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    pub fn store_manager(&self) -> &StoreManager {
        &self.store_manager
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }
}
