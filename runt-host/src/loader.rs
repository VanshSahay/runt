use anyhow::Result;
use runt_abi::*;
use runt_core::StoreManager;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use wasmtime::{Engine, Linker, Memory, Module, Store, TypedFunc};

use crate::crypto::CryptoProvider;
use crate::storage::StorageProvider;
use crate::types::VerifierMetadata;

const GUEST_MEM_OFFSET: u32 = 2048;

pub struct VerifierLoader {
    store_manager: StoreManager,
    engine: Engine,
    crypto: Arc<dyn CryptoProvider>,
    storage: Arc<dyn StorageProvider>,
    modules: Vec<(VerifierMetadata, Module, PathBuf)>,
}

impl VerifierLoader {
    pub fn new(store_manager: StoreManager) -> Self {
        Self {
            engine: store_manager.engine().clone(),
            store_manager,
            crypto: Arc::new(crate::crypto::DefaultCryptoProvider),
            storage: Arc::new(crate::storage::InMemoryStorage::new()),
            modules: Vec::new(),
        }
    }

    pub fn with_crypto(mut self, crypto: Arc<dyn CryptoProvider>) -> Self {
        self.crypto = crypto;
        self
    }

    pub fn with_storage(mut self, storage: Arc<dyn StorageProvider>) -> Self {
        self.storage = storage;
        self
    }

    pub fn scan_directory(&mut self, dir: &Path) -> Result<usize> {
        let mut count = 0;
        for entry in std::fs::read_dir(dir)
            .map_err(|e| anyhow::anyhow!("failed to read directory {}: {e}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "wasm") {
                self.load_module(&path)?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn load_module(&mut self, path: &Path) -> Result<()> {
        let module = Module::from_file(&self.engine, path)
            .map_err(|e| anyhow::anyhow!("failed to load module {}: {e}", path.display()))?;

        let metadata = self.extract_metadata(&module)?;
        self.modules.push((metadata, module, path.to_path_buf()));
        Ok(())
    }

    fn extract_metadata(&self, module: &Module) -> Result<VerifierMetadata> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(10_000_000).ok();

        let linker = self.build_linker();
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| anyhow::anyhow!("failed to instantiate module for metadata: {e}"))?;

        let metadata_fn: TypedFunc<(u32, u32), u32> = instance
            .get_typed_func(&mut store, "metadata")
            .map_err(|e| anyhow::anyhow!("module does not export 'metadata': {e}"))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("module has no 'memory' export"))?;

        let result_len = metadata_fn
            .call(
                &mut store,
                (GUEST_MEM_OFFSET, DEFAULT_METADATA_BUF_SIZE),
            )
            .map_err(|e| anyhow::anyhow!("metadata call trapped: {e:?}"))?;

        let json_bytes = read_guest_mem(
            &store,
            memory,
            GUEST_MEM_OFFSET,
            result_len.min(DEFAULT_METADATA_BUF_SIZE) as usize,
        );

        let metadata: VerifierMetadata = serde_json::from_slice(&json_bytes).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse metadata JSON: {} — raw: {}",
                e,
                String::from_utf8_lossy(&json_bytes)
            )
        })?;

        Ok(metadata)
    }

    pub fn verify(
        &self,
        module: &Module,
        proof: &[u8],
        public_inputs: &[u8],
    ) -> Result<(u32, String)> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(100_000_000).ok();

        let linker = self.build_linker();
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| anyhow::anyhow!("failed to instantiate verifier module: {e}"))?;

        let verify_fn: TypedFunc<(u32, u32, u32, u32, u32, u32), u32> = instance
            .get_typed_func(&mut store, "verify")
            .map_err(|e| anyhow::anyhow!("module does not export 'verify': {e}"))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("module has no 'memory' export"))?;

        write_guest_mem(&mut store, memory, GUEST_MEM_OFFSET, proof);
        let proof_addr = GUEST_MEM_OFFSET;
        let inputs_addr = proof_addr + proof.len() as u32 + 64;
        write_guest_mem(&mut store, memory, inputs_addr, public_inputs);
        let error_addr = inputs_addr + public_inputs.len() as u32 + 64;

        let result_code = verify_fn.call(
            &mut store,
            (
                proof_addr,
                proof.len() as u32,
                inputs_addr,
                public_inputs.len() as u32,
                error_addr,
                DEFAULT_ERROR_BUF_SIZE,
            ),
        )?;

        let error_bytes = read_guest_mem(&store, memory, error_addr, DEFAULT_ERROR_BUF_SIZE as usize);
        let error_str = String::from_utf8_lossy(&error_bytes)
            .trim_end_matches('\0')
            .trim()
            .to_string();

        Ok((result_code, error_str))
    }

    fn build_linker(&self) -> Linker<()> {
        let mut linker = Linker::new(&self.engine);
        let crypto = self.crypto.clone();

        linker
            .func_wrap(
                "env",
                "host_hash",
                move |mut caller: wasmtime::Caller<'_, ()>,
                      algorithm: u32,
                      input_ptr: u32,
                      input_len: u32,
                      output_ptr: u32| {
                    let mem = get_memory(&mut caller);
                    let input_data = read_mem(&caller, mem, input_ptr, input_len);
                    let hash: [u8; 32] = match algorithm {
                        HASH_KECCAK256 => crypto.keccak256(&input_data),
                        HASH_SHA256 => crypto.sha256(&input_data),
                        _ => [0u8; 32],
                    };
                    write_mem(caller, mem, output_ptr, &hash);
                },
            )
            .unwrap();

        let crypto2 = self.crypto.clone();
        linker
            .func_wrap(
                "env",
                "host_verify_signature",
                move |mut caller: wasmtime::Caller<'_, ()>,
                      scheme: u32,
                      msg_ptr: u32,
                      msg_len: u32,
                      sig_ptr: u32,
                      sig_len: u32,
                      pk_ptr: u32,
                      pk_len: u32|
                      -> u32 {
                    let mem = get_memory(&mut caller);
                    let msg = read_mem(&caller, mem, msg_ptr, msg_len);
                    let sig = read_mem(&caller, mem, sig_ptr, sig_len);
                    let pk = read_mem(&caller, mem, pk_ptr, pk_len);
                    crypto2.verify_signature(scheme, &msg, &sig, &pk) as u32
                },
            )
            .unwrap();

        let crypto3 = self.crypto.clone();
        linker
            .func_wrap(
                "env",
                "host_pairing_check",
                move |mut caller: wasmtime::Caller<'_, ()>,
                      curve: u32,
                      pairs_ptr: u32,
                      pairs_len: u32|
                      -> u32 {
                    let mem = get_memory(&mut caller);
                    let pairs = read_mem(&caller, mem, pairs_ptr, pairs_len);
                    crypto3.pairing_check(curve, &pairs) as u32
                },
            )
            .unwrap();

        linker
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn store_manager(&self) -> &StoreManager {
        &self.store_manager
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn modules(&self) -> &[(VerifierMetadata, Module, PathBuf)] {
        &self.modules
    }
}

fn get_memory(caller: &mut wasmtime::Caller<'_, ()>) -> Memory {
    caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .expect("no memory export")
}

fn read_mem(caller: &wasmtime::Caller<'_, ()>, mem: Memory, ptr: u32, len: u32) -> Vec<u8> {
    let mut buf = vec![0u8; len as usize];
    mem.read(caller, ptr as usize, &mut buf).ok();
    buf
}

fn write_mem(mut caller: wasmtime::Caller<'_, ()>, mem: Memory, ptr: u32, data: &[u8]) {
    mem.write(&mut caller, ptr as usize, data).ok();
}

fn read_guest_mem(store: &Store<()>, mem: Memory, offset: u32, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    mem.read(store, offset as usize, &mut buf).ok();
    buf
}

fn write_guest_mem(store: &mut Store<()>, mem: Memory, offset: u32, data: &[u8]) {
    mem.write(store, offset as usize, data).ok();
}
