use crate::engine::EngineConfig;
use wasmtime::{Engine, Store};

pub struct StoreManager {
    engine: Engine,
    default_fuel: u64,
}

pub struct VerifierStore<T: 'static> {
    pub store: Store<T>,
    pub fuel_budget: u64,
}

impl StoreManager {
    pub fn new() -> Self {
        let engine = EngineConfig::default().build();
        Self {
            engine,
            default_fuel: 100_000_000,
        }
    }

    pub fn with_engine(engine: Engine) -> Self {
        Self {
            engine,
            default_fuel: 100_000_000,
        }
    }

    pub fn create_store<T: Default + 'static>(&self, data: T) -> VerifierStore<T> {
        let mut store = Store::new(&self.engine, data);
        store.set_fuel(self.default_fuel).ok();

        VerifierStore {
            store,
            fuel_budget: self.default_fuel,
        }
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Default for StoreManager {
    fn default() -> Self {
        Self::new()
    }
}
