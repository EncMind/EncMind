use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use wasmtime::*;

use encmind_core::error::WasmHostError;
use encmind_core::hooks::HookRegistry;
use encmind_core::traits::CapabilitySet;
use encmind_core::types::SkillApprovalRequest;

use crate::abi;
use crate::limiter::SkillResourceLimiter;

/// Describes the execution context for a WASM skill invocation.
///
/// Used to fast-deny interactive operations (like user approval prompts)
/// in non-interactive contexts such as timers and transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionContext {
    Interactive,
    CronJob,
    SkillTimer,
    ChannelTransform,
}

impl ExecutionContext {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionContext::Interactive => "interactive",
            ExecutionContext::CronJob => "cron",
            ExecutionContext::SkillTimer => "skill_timer",
            ExecutionContext::ChannelTransform => "channel_transform",
        }
    }
}

/// Gateway-provided outbound policy hook for `net.*` host functions.
#[async_trait]
pub trait OutboundPolicy: Send + Sync {
    async fn check_url(&self, url: &str) -> Result<(), String>;
}

/// Gateway-provided approval bridge for `approval.prompt_user`.
#[async_trait]
pub trait ApprovalPrompter: Send + Sync {
    async fn prompt(
        &self,
        request: SkillApprovalRequest,
        timeout: std::time::Duration,
    ) -> encmind_core::types::SkillApprovalResponse;
}

/// Store-level state passed to every WASM invocation.
pub struct StoreState {
    pub limiter: SkillResourceLimiter,
    pub skill_id: String,
    pub capabilities: CapabilitySet,
    pub last_error: Option<String>,
    // Dependencies (all Option for backward compat with existing tests)
    pub db_pool: Option<Arc<crate::SqlitePool>>,
    pub http_client: Option<Arc<reqwest::Client>>,
    pub outbound_policy: Option<Arc<dyn OutboundPolicy>>,
    pub hook_registry: Option<Arc<RwLock<HookRegistry>>>,
    pub skill_config: Option<serde_json::Value>,
    pub approval_prompter: Option<Arc<dyn ApprovalPrompter>>,
    /// Execution context (interactive, timer, transform, etc.).
    pub execution_context: ExecutionContext,
    /// Session identifier for this invocation, when available.
    pub session_id: Option<String>,
    /// Agent identifier for this invocation, when available.
    pub agent_id: Option<String>,
    /// Source channel for this invocation, when available.
    pub channel: Option<String>,
    /// Invocation identifier for this invocation, when available.
    pub invocation_id: Option<String>,
    /// WASI context for Javy-style skills (stdin/stdout piping). None for Native ABI.
    pub wasi_ctx: Option<wasmtime_wasi::p1::WasiP1Ctx>,
}

/// Convert a wasmtime execution error into a WasmHostError, recognising
/// specific trap codes (out-of-fuel, memory-out-of-bounds, etc.).
pub(crate) fn map_execution_error(e: anyhow::Error) -> WasmHostError {
    if let Some(trap) = e.downcast_ref::<Trap>() {
        match trap {
            Trap::OutOfFuel => {
                return WasmHostError::ResourceLimitExceeded("CPU fuel exhausted".into());
            }
            Trap::MemoryOutOfBounds | Trap::HeapMisaligned => {
                return WasmHostError::ResourceLimitExceeded("memory limit exceeded".into());
            }
            Trap::StackOverflow => {
                return WasmHostError::ResourceLimitExceeded("stack overflow".into());
            }
            _ => {}
        }
    }
    WasmHostError::ExecutionFailed(e.to_string())
}

/// Manages compiled WASM modules and provides capability-scoped invocation.
pub struct WasmRuntime {
    engine: Engine,
    modules: HashMap<String, Module>,
    fuel_limit: u64,
    max_memory_mb: usize,
}

impl WasmRuntime {
    /// Create a new runtime with async support.
    ///
    /// * `fuel_limit` – maximum fuel per invocation (0 = unlimited).
    /// * `max_memory_mb` – per-module memory cap in MiB.
    pub fn new(fuel_limit: u64, max_memory_mb: usize) -> Result<Self, WasmHostError> {
        let mut config = Config::new();
        config.async_support(true);
        if fuel_limit > 0 {
            config.consume_fuel(true);
        }
        let engine =
            Engine::new(&config).map_err(|e| WasmHostError::ModuleLoadFailed(e.to_string()))?;

        Ok(Self {
            engine,
            modules: HashMap::new(),
            fuel_limit,
            max_memory_mb,
        })
    }

    /// Compile and cache a WASM module.
    ///
    /// Accepts WASM binary or WAT text format.
    pub fn load_module(&mut self, name: &str, wasm_bytes: &[u8]) -> Result<(), WasmHostError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmHostError::ModuleLoadFailed(e.to_string()))?;
        self.modules.insert(name.to_string(), module);
        Ok(())
    }

    /// Check whether a module is loaded.
    pub fn has_module(&self, name: &str) -> bool {
        self.modules.contains_key(name)
    }

    /// Get a reference to the engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get a compiled module by name.
    pub fn get_module(&self, name: &str) -> Option<&Module> {
        self.modules.get(name)
    }

    fn make_default_state(&self) -> StoreState {
        StoreState {
            limiter: SkillResourceLimiter::new(self.max_memory_mb),
            skill_id: String::new(),
            capabilities: CapabilitySet {
                net_outbound: vec![],
                fs_read: vec![],
                fs_write: vec![],
                exec_shell: false,
                env_secrets: false,
                kv: false,
                prompt_user: false,
                emit_events: vec![],
                hooks: vec![],
                schedule_timers: false,
                schedule_transforms: vec![],
            },
            last_error: None,
            db_pool: None,
            http_client: None,
            outbound_policy: None,
            hook_registry: None,
            skill_config: None,
            approval_prompter: None,
            execution_context: ExecutionContext::Interactive,
            session_id: None,
            agent_id: None,
            channel: None,
            invocation_id: None,
            wasi_ctx: None,
        }
    }

    /// Invoke an exported function by name (async).
    ///
    /// Returns the i32 result of the function (or an error).
    pub async fn invoke(&self, module_name: &str, func_name: &str) -> Result<i32, WasmHostError> {
        let module = self.modules.get(module_name).ok_or_else(|| {
            WasmHostError::ModuleLoadFailed(format!("module not loaded: {module_name}"))
        })?;

        let state = self.make_default_state();
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);

        if self.fuel_limit > 0 {
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmHostError::ExecutionFailed(e.to_string()))?;
        }

        let linker = build_linker(&self.engine)?;

        let instance = linker
            .instantiate_async(&mut store, module)
            .await
            .map_err(|e| WasmHostError::ExecutionFailed(format!("instantiation failed: {e}")))?;

        let func = instance
            .get_typed_func::<(), i32>(&mut store, func_name)
            .map_err(|e| {
                WasmHostError::ExecutionFailed(format!(
                    "function '{func_name}' not found or wrong signature: {e}"
                ))
            })?;

        func.call_async(&mut store, ())
            .await
            .map_err(map_execution_error)
    }

    /// Invoke an exported function that takes (i32, i32) and returns i32 (async).
    pub async fn invoke_with_args(
        &self,
        module_name: &str,
        func_name: &str,
        arg1: i32,
        arg2: i32,
    ) -> Result<i32, WasmHostError> {
        let module = self.modules.get(module_name).ok_or_else(|| {
            WasmHostError::ModuleLoadFailed(format!("module not loaded: {module_name}"))
        })?;

        let state = self.make_default_state();
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);

        if self.fuel_limit > 0 {
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmHostError::ExecutionFailed(e.to_string()))?;
        }

        let linker = build_linker(&self.engine)?;
        let instance = linker
            .instantiate_async(&mut store, module)
            .await
            .map_err(|e| WasmHostError::ExecutionFailed(format!("instantiation failed: {e}")))?;

        let func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, func_name)
            .map_err(|e| {
                WasmHostError::ExecutionFailed(format!(
                    "function '{func_name}' not found or wrong signature: {e}"
                ))
            })?;

        func.call_async(&mut store, (arg1, arg2))
            .await
            .map_err(map_execution_error)
    }

    /// Invoke a skill's `__encmind_invoke` export with JSON input/output.
    ///
    /// Uses the ABI convention: write JSON input to guest memory via `__encmind_alloc`,
    /// call `__encmind_invoke(ptr, len) -> fat_ptr`, read JSON output from fat_ptr.
    pub async fn invoke_json(
        &self,
        module_name: &str,
        input: &serde_json::Value,
        state: StoreState,
    ) -> Result<serde_json::Value, WasmHostError> {
        let module = self.modules.get(module_name).ok_or_else(|| {
            WasmHostError::ModuleLoadFailed(format!("module not loaded: {module_name}"))
        })?;

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);

        if self.fuel_limit > 0 {
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmHostError::ExecutionFailed(e.to_string()))?;
        }

        let linker = build_linker(&self.engine)?;
        let instance = linker
            .instantiate_async(&mut store, module)
            .await
            .map_err(|e| WasmHostError::ExecutionFailed(format!("instantiation failed: {e}")))?;

        let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| {
            WasmHostError::ExecutionFailed("module has no 'memory' export".into())
        })?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "__encmind_alloc")
            .map_err(|e| {
                WasmHostError::ExecutionFailed(format!("__encmind_alloc not found: {e}"))
            })?;

        let invoke_fn = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "__encmind_invoke")
            .map_err(|e| {
                WasmHostError::ExecutionFailed(format!("__encmind_invoke not found: {e}"))
            })?;

        // Write input JSON to guest memory
        let input_bytes = serde_json::to_vec(input)
            .map_err(|e| WasmHostError::ExecutionFailed(format!("JSON serialize failed: {e}")))?;

        let input_fat =
            abi::write_to_guest(&alloc_fn, store.as_context_mut(), &memory, &input_bytes).await?;
        let (input_ptr, input_len) = abi::decode_fat_ptr(input_fat);

        // Call __encmind_invoke
        let result_fat = invoke_fn
            .call_async(&mut store, (input_ptr, input_len))
            .await
            .map_err(map_execution_error)?;

        if result_fat == 0 {
            let error_msg = store
                .data()
                .last_error
                .clone()
                .unwrap_or_else(|| "unknown error (null fat ptr)".into());
            return Err(WasmHostError::ExecutionFailed(error_msg));
        }

        let (result_ptr, result_len) = abi::decode_fat_ptr(result_fat);
        let result_bytes =
            abi::read_guest_bytes(&memory, store.as_context(), result_ptr, result_len)?;

        serde_json::from_slice(&result_bytes)
            .map_err(|e| WasmHostError::ExecutionFailed(format!("JSON parse failed: {e}")))
    }
}

/// Build a Linker with all host functions registered.
pub fn build_linker(engine: &Engine) -> Result<Linker<StoreState>, WasmHostError> {
    let mut linker = Linker::<StoreState>::new(engine);
    crate::host_functions::register_all(&mut linker)?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_and_invoke_simple_module() {
        let mut runtime = WasmRuntime::new(0, 64).unwrap();

        // A module that returns 42
        let wat = r#"(module
            (func (export "run") (result i32)
                i32.const 42
            )
        )"#;

        runtime.load_module("simple", wat.as_bytes()).unwrap();
        assert!(runtime.has_module("simple"));

        let result = runtime.invoke("simple", "run").await.unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn invoke_with_args() {
        let mut runtime = WasmRuntime::new(0, 64).unwrap();

        let wat = r#"(module
            (func (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add
            )
        )"#;

        runtime.load_module("math", wat.as_bytes()).unwrap();
        let result = runtime
            .invoke_with_args("math", "add", 10, 32)
            .await
            .unwrap();
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn module_not_found() {
        let runtime = WasmRuntime::new(0, 64).unwrap();
        let result = runtime.invoke("nonexistent", "run").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            WasmHostError::ModuleLoadFailed(msg) => {
                assert!(msg.contains("not loaded"), "got: {msg}");
            }
            other => panic!("expected ModuleLoadFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn function_not_found() {
        let mut runtime = WasmRuntime::new(0, 64).unwrap();

        let wat = r#"(module
            (func (export "run") (result i32)
                i32.const 1
            )
        )"#;
        runtime.load_module("test", wat.as_bytes()).unwrap();

        let result = runtime.invoke("test", "nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fuel_exhaustion() {
        let mut runtime = WasmRuntime::new(100, 64).unwrap(); // very little fuel

        // An infinite loop
        let wat = r#"(module
            (func (export "run") (result i32)
                (loop $l
                    br $l
                )
                i32.const 0
            )
        )"#;

        runtime.load_module("loop", wat.as_bytes()).unwrap();
        let result = runtime.invoke("loop", "run").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            WasmHostError::ResourceLimitExceeded(msg) => {
                assert!(msg.contains("fuel"), "expected fuel error, got: {msg}");
            }
            other => panic!("expected ResourceLimitExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn memory_limit_enforced() {
        let mut runtime = WasmRuntime::new(100_000, 1).unwrap(); // 1 MiB limit

        // Module that tries to grow memory beyond limit
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                ;; Try to grow by 100 pages (6.4MB) — should fail
                i32.const 100
                memory.grow
                ;; memory.grow returns -1 on failure
            )
        )"#;

        runtime.load_module("grow", wat.as_bytes()).unwrap();
        let result = runtime.invoke("grow", "run").await.unwrap();
        // memory.grow returns -1 when denied
        assert_eq!(result, -1);
    }

    #[test]
    fn load_invalid_wasm() {
        let mut runtime = WasmRuntime::new(0, 64).unwrap();
        let result = runtime.load_module("bad", b"not wasm");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn multiple_modules() {
        let mut runtime = WasmRuntime::new(0, 64).unwrap();

        let wat_a = r#"(module
            (func (export "run") (result i32) i32.const 1)
        )"#;
        let wat_b = r#"(module
            (func (export "run") (result i32) i32.const 2)
        )"#;

        runtime.load_module("a", wat_a.as_bytes()).unwrap();
        runtime.load_module("b", wat_b.as_bytes()).unwrap();

        assert_eq!(runtime.invoke("a", "run").await.unwrap(), 1);
        assert_eq!(runtime.invoke("b", "run").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn build_linker_succeeds() {
        let engine = Engine::new(&{
            let mut c = Config::new();
            c.async_support(true);
            c
        })
        .unwrap();
        let linker = build_linker(&engine);
        assert!(linker.is_ok());
    }
}
