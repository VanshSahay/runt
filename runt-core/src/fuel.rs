use wasmtime::StoreContextMut;

pub struct FuelMeter {
    budget: u64,
    consumed: u64,
}

impl FuelMeter {
    pub fn new(budget: u64) -> Self {
        Self {
            budget,
            consumed: 0,
        }
    }

    pub fn add_fuel<T>(&mut self, store: &mut StoreContextMut<'_, T>, amount: u64) {
        self.budget += amount;
        store.set_fuel(self.budget).ok();
    }

    pub fn consume_fuel<T>(&mut self, store: &mut StoreContextMut<'_, T>, amount: u64) -> bool {
        if let Ok(remaining) = store.get_fuel() {
            if remaining < amount {
                return false;
            }
            store.set_fuel(remaining - amount).ok();
            self.consumed += amount;
            return true;
        }
        false
    }

    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    pub fn remaining<T>(&self, store: &mut StoreContextMut<'_, T>) -> Option<u64> {
        store.get_fuel().ok()
    }
}
