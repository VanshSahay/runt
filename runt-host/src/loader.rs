use anyhow::{Context, Result};
use runt_core::StoreManager;
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, Linker, ResourceTable};

use crate::crypto::CryptoProvider;
use crate::storage::StorageProvider;

pub struct HostState {
    pub crypto: Box<dyn CryptoProvider>,
    pub storage: Box<dyn StorageProvider>,
    pub resource_table: ResourceTable,
}

impl Default for HostState {
    fn default() -> Self {
        Self {
            crypto: Box::new(crate::crypto::DefaultCryptoProvider),
            storage: Box::new(crate::storage::InMemoryStorage::new()),
            resource_table: ResourceTable::new(),
        }
    }
}

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
        let linker = Linker::new(&engine);

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
            .with_context(|| format!("failed to read verifier directory: {}", dir.display()))?
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

    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    pub fn linker(&self) -> &Linker<HostState> {
        &self.linker
    }

    pub fn store_manager(&self) -> &StoreManager {
        &self.store_manager
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }
}
