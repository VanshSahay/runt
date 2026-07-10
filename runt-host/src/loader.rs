use anyhow::Result;
use runt_core::StoreManager;
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::Store;

use crate::bindings::RuntVerifier;
use crate::host_impl::HostState;

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

    pub fn instantiate(
        &self,
        host_state: HostState,
        component: &Component,
    ) -> Result<(RuntVerifier, Store<HostState>)> {
        let mut store = Store::new(&self.engine, host_state);
        store.set_fuel(100_000_000).ok();
        let bindings =
            RuntVerifier::instantiate(&mut store, component, &self.linker)?;
        Ok((bindings, store))
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
