use wasmtime::{Config, Engine, OptLevel};

pub struct EngineConfig {
    config: Config,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineConfig {
    pub fn new() -> Self {
        let mut config = Config::default();

        config.cranelift_nan_canonicalization(true);
        config.cranelift_opt_level(OptLevel::Speed);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.memory_reservation(64 * 1024 * 1024);
        config.memory_guard_size(0);
        config.memory_reservation_for_growth(0);
        config.parallel_compilation(false);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);

        Self { config }
    }

    pub fn fuel_limit(mut self, _fuel: u64) -> Self {
        self.config.consume_fuel(true);
        self
    }

    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.config.memory_reservation(bytes);
        self
    }

    pub fn build(self) -> Engine {
        Engine::new(&self.config).expect("failed to create wasmtime engine")
    }
}
