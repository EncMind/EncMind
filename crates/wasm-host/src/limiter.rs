use wasmtime::ResourceLimiter;

/// Enforces memory and table growth limits for WASM modules.
pub struct SkillResourceLimiter {
    /// Maximum memory in bytes (default 64 MiB).
    pub max_memory_bytes: usize,
    /// Maximum number of table elements.
    pub max_table_elements: usize,
}

impl Default for SkillResourceLimiter {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MiB
            max_table_elements: 10_000usize,
        }
    }
}

impl SkillResourceLimiter {
    pub fn new(max_memory_mb: usize) -> Self {
        Self {
            max_memory_bytes: max_memory_mb * 1024 * 1024,
            ..Default::default()
        }
    }
}

impl ResourceLimiter for SkillResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_memory_bytes && desired >= current)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_table_elements && desired >= current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits() {
        let limiter = SkillResourceLimiter::default();
        assert_eq!(limiter.max_memory_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn allows_growth_within_limit() {
        let mut limiter = SkillResourceLimiter::new(1); // 1 MiB
        assert!(limiter.memory_growing(0, 65536, None).unwrap());
    }

    #[test]
    fn denies_growth_beyond_limit() {
        let mut limiter = SkillResourceLimiter::new(1); // 1 MiB
        let over = 2 * 1024 * 1024;
        assert!(!limiter.memory_growing(0, over, None).unwrap());
    }

    #[test]
    fn table_growth_within_limit() {
        let mut limiter = SkillResourceLimiter::default();
        assert!(limiter.table_growing(0, 100, None).unwrap());
    }

    #[test]
    fn table_growth_beyond_limit() {
        let mut limiter = SkillResourceLimiter::default();
        assert!(!limiter.table_growing(0, 20_000, None).unwrap());
    }
}
