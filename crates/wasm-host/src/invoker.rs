//! Unified WASM skill invoker — branches on ABI (Native vs Javy).
//!
//! Tool, timer, and transform call sites use `SkillInvoker`.
//! Hook bridge (`hook_bridge.rs`) still manages its own invocation.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use wasmtime::{AsContext, AsContextMut, Engine, Module, Store};

use encmind_core::error::WasmHostError;
use encmind_core::hooks::HookRegistry;
use encmind_core::traits::CapabilitySet;

use crate::abi::{self, SkillAbi};
use crate::limiter::SkillResourceLimiter;
use crate::runtime::{
    build_linker, map_execution_error, ApprovalPrompter, ExecutionContext, OutboundPolicy,
    StoreState,
};

/// Dependencies injected per invocation.
pub struct InvokeDeps {
    pub db_pool: Option<Arc<crate::SqlitePool>>,
    pub http_client: Option<Arc<reqwest::Client>>,
    pub outbound_policy: Option<Arc<dyn OutboundPolicy>>,
    pub hook_registry: Option<Arc<RwLock<HookRegistry>>>,
    pub approval_prompter: Option<Arc<dyn ApprovalPrompter>>,
    pub skill_config: Option<serde_json::Value>,
    pub execution_context: ExecutionContext,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub channel: Option<String>,
    pub invocation_id: Option<String>,
}

impl Default for InvokeDeps {
    fn default() -> Self {
        Self {
            db_pool: None,
            http_client: None,
            outbound_policy: None,
            hook_registry: None,
            approval_prompter: None,
            skill_config: None,
            execution_context: ExecutionContext::Interactive,
            session_id: None,
            agent_id: None,
            channel: None,
            invocation_id: None,
        }
    }
}

/// Unified invoker for WASM skill modules.
///
/// Encapsulates a compiled module and its ABI, providing a single
/// `invoke_json()` method that dispatches to the correct ABI path.
pub struct SkillInvoker {
    engine: Engine,
    module: Module,
    abi: SkillAbi,
    skill_id: String,
    capabilities: CapabilitySet,
    fuel_limit: u64,
    max_memory_mb: usize,
}

impl SkillInvoker {
    /// Maximum stdout payload captured for Javy ABI invocations.
    pub const JAVY_STDOUT_MAX_BYTES: usize = 1024 * 1024; // 1 MiB

    /// Construct a skill invoker for a compiled WASM module.
    pub fn new(
        engine: Engine,
        module: Module,
        abi: SkillAbi,
        skill_id: String,
        capabilities: CapabilitySet,
        fuel_limit: u64,
        max_memory_mb: usize,
    ) -> Self {
        Self {
            engine,
            module,
            abi,
            skill_id,
            capabilities,
            fuel_limit,
            max_memory_mb,
        }
    }

    /// Skill identifier used in diagnostics and audit logs.
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    /// Invoke the skill with JSON input, returning JSON output.
    ///
    /// Branches on `self.abi`:
    /// - **Native**: alloc + invoke via fat-pointer ABI with full host functions.
    /// - **Javy**: WASI stdin/stdout piping (tool invocation only, no host functions).
    pub async fn invoke_json(
        &self,
        input: &serde_json::Value,
        deps: &InvokeDeps,
        timeout: Duration,
    ) -> Result<serde_json::Value, WasmHostError> {
        match self.abi {
            SkillAbi::Native => tokio::time::timeout(timeout, self.invoke_native(input, deps))
                .await
                .map_err(|_| {
                    WasmHostError::ExecutionFailed(format!(
                        "skill '{}' timed out after {}ms",
                        self.skill_id,
                        timeout.as_millis()
                    ))
                })?,
            SkillAbi::Javy => tokio::time::timeout(timeout, self.invoke_javy(input, deps))
                .await
                .map_err(|_| {
                    WasmHostError::ExecutionFailed(format!(
                        "skill '{}' timed out after {}ms",
                        self.skill_id,
                        timeout.as_millis()
                    ))
                })?,
        }
    }

    /// Invoke a named export (Native ABI only). Used for timers, transforms, hooks.
    ///
    /// Returns an error for Javy skills (they only support `_start`).
    pub async fn invoke_export(
        &self,
        export_name: &str,
        input: &serde_json::Value,
        deps: &InvokeDeps,
        timeout: Duration,
    ) -> Result<serde_json::Value, WasmHostError> {
        if self.abi == SkillAbi::Javy {
            return Err(WasmHostError::ExecutionFailed(format!(
                "skill '{}' uses Javy ABI which does not support named exports (tried '{}')",
                self.skill_id, export_name
            )));
        }
        tokio::time::timeout(
            timeout,
            self.invoke_native_export(export_name, input, deps, true),
        )
        .await
        .map_err(|_| {
            WasmHostError::ExecutionFailed(format!(
                "skill '{}' export '{}' timed out after {}ms",
                self.skill_id,
                export_name,
                timeout.as_millis()
            ))
        })?
    }

    /// Native ABI invocation: __encmind_alloc + __encmind_invoke.
    async fn invoke_native(
        &self,
        input: &serde_json::Value,
        deps: &InvokeDeps,
    ) -> Result<serde_json::Value, WasmHostError> {
        self.invoke_native_export("__encmind_invoke", input, deps, false)
            .await
    }

    /// Native ABI invocation with a specific export function name.
    async fn invoke_native_export(
        &self,
        export_name: &str,
        input: &serde_json::Value,
        deps: &InvokeDeps,
        allow_empty_output: bool,
    ) -> Result<serde_json::Value, WasmHostError> {
        let state = self.build_store_state(deps);
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);

        if self.fuel_limit > 0 {
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmHostError::ExecutionFailed(format!("set_fuel: {e}")))?;
        }

        let linker = build_linker(&self.engine)?;
        let instance = linker
            .instantiate_async(&mut store, &self.module)
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
            .get_typed_func::<(i32, i32), i64>(&mut store, export_name)
            .map_err(|e| {
                WasmHostError::ExecutionFailed(format!("export '{export_name}' not found: {e}"))
            })?;

        // Write input JSON to guest memory
        let input_bytes = serde_json::to_vec(input)
            .map_err(|e| WasmHostError::ExecutionFailed(format!("JSON serialize failed: {e}")))?;

        let input_fat =
            abi::write_to_guest(&alloc_fn, store.as_context_mut(), &memory, &input_bytes).await?;
        let (input_ptr, input_len) = abi::decode_fat_ptr(input_fat);

        // Call the export function
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
        if result_bytes.is_empty() {
            if allow_empty_output {
                return Ok(serde_json::json!({}));
            }
            return Err(WasmHostError::ExecutionFailed(
                "empty JSON output from __encmind_invoke".into(),
            ));
        }

        serde_json::from_slice(&result_bytes)
            .map_err(|e| WasmHostError::ExecutionFailed(format!("JSON parse failed: {e}")))
    }

    /// Javy ABI invocation: WASI stdin/stdout piping via `_start`.
    async fn invoke_javy(
        &self,
        input: &serde_json::Value,
        deps: &InvokeDeps,
    ) -> Result<serde_json::Value, WasmHostError> {
        let input_bytes = serde_json::to_vec(input)
            .map_err(|e| WasmHostError::ExecutionFailed(format!("JSON serialize failed: {e}")))?;
        if input_bytes.len() > abi::MAX_GUEST_BYTES {
            return Err(WasmHostError::ResourceLimitExceeded(format!(
                "javy input payload too large: {} bytes (max {})",
                input_bytes.len(),
                abi::MAX_GUEST_BYTES
            )));
        }

        // Build WASI context with stdin pipe and stdout capture
        let stdout = wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(Self::JAVY_STDOUT_MAX_BYTES);
        let wasi_ctx = {
            let mut builder = wasmtime_wasi::WasiCtxBuilder::new();
            builder.stdin(wasmtime_wasi::p2::pipe::MemoryInputPipe::new(input_bytes));
            builder.stdout(stdout.clone());
            builder.build_p1()
        };

        let mut state = self.build_store_state(deps);
        state.wasi_ctx = Some(wasi_ctx);

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);

        if self.fuel_limit > 0 {
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| WasmHostError::ExecutionFailed(format!("set_fuel: {e}")))?;
        }

        // Build linker with WASI (no encmind host functions for Javy)
        let mut linker = wasmtime::Linker::<StoreState>::new(&self.engine);
        wasmtime_wasi::p1::add_to_linker_async(&mut linker, |s| {
            s.wasi_ctx
                .as_mut()
                .expect("wasi_ctx must be set for Javy ABI")
        })
        .map_err(|e| WasmHostError::ExecutionFailed(format!("WASI linker setup: {e}")))?;

        let instance = linker
            .instantiate_async(&mut store, &self.module)
            .await
            .map_err(|e| WasmHostError::ExecutionFailed(format!("instantiation failed: {e}")))?;

        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| WasmHostError::ExecutionFailed(format!("_start not found: {e}")))?;

        start_fn
            .call_async(&mut store, ())
            .await
            .map_err(map_execution_error)?;

        // Read stdout
        let output_bytes: Vec<u8> = stdout.contents().to_vec();

        if output_bytes.is_empty() {
            return Err(WasmHostError::ExecutionFailed(format!(
                "skill '{}' produced no stdout output",
                self.skill_id
            )));
        }

        let value: serde_json::Value = serde_json::from_slice(&output_bytes).map_err(|e| {
            WasmHostError::ExecutionFailed(format!("JSON parse stdout failed: {e}"))
        })?;
        let envelope = value
            .get(crate::abi::JAVY_RUNTIME_ENVELOPE_KEY)
            .map(|v| (crate::abi::JAVY_RUNTIME_ENVELOPE_KEY, v))
            .or_else(|| {
                value
                    .get(crate::abi::JAVY_RUNTIME_ENVELOPE_KEY_LEGACY)
                    .map(|v| (crate::abi::JAVY_RUNTIME_ENVELOPE_KEY_LEGACY, v))
            });
        if let Some((envelope_key, envelope)) = envelope {
            if let Some(msg) = envelope
                .get(crate::abi::JAVY_RUNTIME_ERROR_KEY)
                .and_then(|v| v.as_str())
            {
                return Err(WasmHostError::ExecutionFailed(msg.to_string()));
            }

            return Err(WasmHostError::ExecutionFailed(format!(
                "skill '{}' returned malformed reserved '{}' envelope",
                self.skill_id, envelope_key
            )));
        }

        Ok(value)
    }

    fn build_store_state(&self, deps: &InvokeDeps) -> StoreState {
        StoreState {
            limiter: SkillResourceLimiter::new(self.max_memory_mb),
            skill_id: self.skill_id.clone(),
            capabilities: self.capabilities.clone(),
            last_error: None,
            db_pool: deps.db_pool.clone(),
            http_client: deps.http_client.clone(),
            outbound_policy: deps.outbound_policy.clone(),
            hook_registry: deps.hook_registry.clone(),
            skill_config: deps.skill_config.clone(),
            approval_prompter: deps.approval_prompter.clone(),
            execution_context: deps.execution_context,
            session_id: deps.session_id.clone(),
            agent_id: deps.agent_id.clone(),
            channel: deps.channel.clone(),
            invocation_id: deps.invocation_id.clone(),
            wasi_ctx: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_core::traits::CapabilitySet;

    fn default_caps() -> CapabilitySet {
        CapabilitySet {
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
        }
    }

    fn test_engine() -> Engine {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        Engine::new(&config).unwrap()
    }

    #[tokio::test]
    async fn native_abi_invoke_json() {
        let engine = test_engine();

        // A simple echo module: reads input, returns {}
        let wat = r#"(module
            (memory (export "memory") 2)
            (global $offset (mut i32) (i32.const 1024))
            (func (export "__encmind_alloc") (param $size i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $offset))
                (global.set $offset (i32.add (global.get $offset) (local.get $size)))
                (local.get $ptr)
            )
            (func (export "__encmind_invoke") (param $ptr i32) (param $len i32) (result i64)
                ;; Write a static JSON response at offset 0
                (i32.store8 (i32.const 0) (i32.const 123))   ;; {
                (i32.store8 (i32.const 1) (i32.const 125))   ;; }
                ;; Return fat pointer: ptr=0, len=2
                (i64.or
                    (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                    (i64.const 2)
                )
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Native,
            "test-native".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({"message": "hello"});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(result.is_object());
    }

    #[tokio::test]
    async fn javy_abi_invoke_json() {
        let engine = test_engine();

        // A Javy-style WASI module that reads stdin and writes to stdout.
        // This WAT module uses WASI fd_read to read stdin and fd_write to write stdout.
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)

            ;; Pre-baked JSON response at offset 256
            (data (i32.const 256) "{\"result\":\"javy-echo\"}")

            (func (export "_start")
                ;; Read stdin (fd=0) to consume input (we ignore it for this test)
                ;; iovec at offset 0: buf_ptr=512, buf_len=1024
                (i32.store (i32.const 0) (i32.const 512))
                (i32.store (i32.const 4) (i32.const 1024))
                ;; nread at offset 8
                (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))

                ;; Write response to stdout (fd=1)
                ;; iovec at offset 16: buf_ptr=256, buf_len=22
                (i32.store (i32.const 16) (i32.const 256))
                (i32.store (i32.const 20) (i32.const 22))
                ;; nwritten at offset 24
                (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-javy".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({"message": "hello"});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result["result"], "javy-echo");
    }

    #[tokio::test]
    async fn javy_abi_rejects_named_export() {
        let engine = test_engine();
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "_start"))
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-javy".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({});
        let result = invoker
            .invoke_export(
                "__on_timer",
                &input,
                &InvokeDeps::default(),
                Duration::from_secs(5),
            )
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Javy ABI"), "got: {err}");
        assert!(err.contains("named exports"), "got: {err}");
    }

    #[tokio::test]
    async fn native_abi_fuel_exhaustion() {
        let engine = test_engine();

        // Infinite loop module — exhausts fuel before completing
        let wat = r#"(module
            (memory (export "memory") 2)
            (global $offset (mut i32) (i32.const 1024))
            (func (export "__encmind_alloc") (param $size i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $offset))
                (global.set $offset (i32.add (global.get $offset) (local.get $size)))
                (local.get $ptr)
            )
            (func (export "__encmind_invoke") (param $ptr i32) (param $len i32) (result i64)
                (loop $l (br $l))
                i64.const 0
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Native,
            "test-fuel".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.to_lowercase().contains("fuel"),
            "expected fuel exhaustion error, got: {err}"
        );
    }

    #[tokio::test]
    async fn javy_abi_empty_stdout_is_error() {
        let engine = test_engine();

        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "_start")
                ;; consume stdin and write nothing
                (i32.store (i32.const 0) (i32.const 128))
                (i32.store (i32.const 4) (i32.const 256))
                (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-empty-javy".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({"message": "hello"});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("produced no stdout output"), "got: {err}");
    }

    #[tokio::test]
    async fn javy_abi_runtime_error_payload_maps_to_execution_error() {
        let engine = test_engine();

        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 256) "{\"_encmind\":{\"runtime_error\":\"boom\"}}")
            (func (export "_start")
                ;; consume stdin
                (i32.store (i32.const 0) (i32.const 512))
                (i32.store (i32.const 4) (i32.const 1024))
                (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
                ;; write error envelope to stdout
                (i32.store (i32.const 16) (i32.const 256))
                (i32.store (i32.const 20) (i32.const 37))
                (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-javy-runtime-error".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({"message": "hello"});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("boom"), "got: {err}");
    }

    #[tokio::test]
    async fn javy_abi_runtime_error_legacy_envelope_maps_to_execution_error() {
        let engine = test_engine();

        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 256) "{\"__encmind\":{\"runtime_error\":\"boom\"}}")
            (func (export "_start")
                ;; consume stdin
                (i32.store (i32.const 0) (i32.const 512))
                (i32.store (i32.const 4) (i32.const 1024))
                (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
                ;; write error envelope to stdout
                (i32.store (i32.const 16) (i32.const 256))
                (i32.store (i32.const 20) (i32.const 38))
                (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-javy-runtime-error-legacy".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({"message": "hello"});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("boom"), "got: {err}");
    }

    #[tokio::test]
    async fn javy_abi_malformed_reserved_envelope_is_error() {
        let engine = test_engine();

        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
            (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 256) "{\"_encmind\":{\"other\":\"x\"}}")
            (func (export "_start")
                ;; consume stdin
                (i32.store (i32.const 0) (i32.const 512))
                (i32.store (i32.const 4) (i32.const 1024))
                (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
                ;; write malformed reserved envelope to stdout
                (i32.store (i32.const 16) (i32.const 256))
                (i32.store (i32.const 20) (i32.const 26))
                (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-javy-malformed-envelope".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({"message": "hello"});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("malformed reserved"), "got: {err}");
    }

    #[tokio::test]
    async fn javy_abi_rejects_oversized_input_payload() {
        let engine = test_engine();
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "_start"))
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Javy,
            "test-javy-input-limit".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let oversized = "x".repeat(crate::abi::MAX_GUEST_BYTES + 64);
        let input = serde_json::json!({ "payload": oversized });
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"), "got: {err}");
    }

    #[tokio::test]
    async fn native_named_export_allows_empty_output() {
        let engine = test_engine();

        let wat = r#"(module
            (memory (export "memory") 2)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__on_timer") (param i32 i32) (result i64)
                ;; Return ptr=1, len=0 (non-null fat pointer with empty output)
                (i64.shl (i64.extend_i32_u (i32.const 1)) (i64.const 32))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Native,
            "test-native-empty-export".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({});
        let result = invoker
            .invoke_export(
                "__on_timer",
                &input,
                &InvokeDeps::default(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({}));
    }

    #[tokio::test]
    async fn native_invoke_json_rejects_empty_output() {
        let engine = test_engine();

        let wat = r#"(module
            (memory (export "memory") 2)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64)
                ;; Return ptr=1, len=0 (non-null fat pointer with empty output)
                (i64.shl (i64.extend_i32_u (i32.const 1)) (i64.const 32))
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        let invoker = SkillInvoker::new(
            engine.clone(),
            module,
            SkillAbi::Native,
            "test-native-empty-json".into(),
            default_caps(),
            1_000_000,
            64,
        );

        let input = serde_json::json!({});
        let result = invoker
            .invoke_json(&input, &InvokeDeps::default(), Duration::from_secs(5))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty JSON output"), "got: {err}");
    }
}
