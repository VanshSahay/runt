use wasmtime::ResourceLimiter;

pub struct SandboxConfig {
    pub memory_limit_bytes: usize,
    pub max_table_elements: u32,
    pub max_instances: u32,
    pub max_tables: u32,
    pub max_memories: u32,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 64 * 1024 * 1024,
            max_table_elements: 10_000,
            max_instances: 1,
            max_tables: 1,
            max_memories: 1,
        }
    }
}

impl SandboxConfig {
    pub fn new(memory_limit_bytes: usize) -> Self {
        Self {
            memory_limit_bytes,
            ..Default::default()
        }
    }
}

impl ResourceLimiter for SandboxConfig {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.memory_limit_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_table_elements as usize)
    }
}
