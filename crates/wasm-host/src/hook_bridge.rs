//! WASM Hook Bridge — bridges manifest-declared hook bindings to the HookHandler trait.
//!
//! Skills declare hooks in their manifest `[hooks]` section. At skill load time,
//! `WasmHookBridge` handlers are created that re-instantiate the module on each
//! hook invocation. This avoids long-lived WASM instances and simplifies resource
//! management.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use wasmtime::{AsContext, AsContextMut, Engine, Module, Store};

use encmind_core::error::PluginError;
use encmind_core::hooks::{HookContext, HookHandler, HookPoint, HookResult};
use encmind_core::traits::{CapabilitySet, SessionStore};
use tracing::warn;

use crate::abi;
use crate::limiter::SkillResourceLimiter;
use crate::runtime::{
    build_linker, ApprovalPrompter, ExecutionContext, OutboundPolicy, StoreState,
};

/// Runtime dependencies injected into hook execution.
///
/// These match the dependencies used by tool/timer/transform execution paths so
/// hook handlers can use host functions consistently (kv/net/config/approval).
#[derive(Clone, Default)]
pub struct HookRuntimeDeps {
    pub db_pool: Option<Arc<crate::SqlitePool>>,
    pub http_client: Option<Arc<reqwest::Client>>,
    pub outbound_policy: Option<Arc<dyn OutboundPolicy>>,
    pub hook_registry: Option<Arc<RwLock<encmind_core::hooks::HookRegistry>>>,
    pub approval_prompter: Option<Arc<dyn ApprovalPrompter>>,
    pub session_store: Option<Arc<dyn SessionStore>>,
}

/// Maps manifest hook point names to `HookPoint` enum variants.
pub fn hook_point_from_name(name: &str) -> Option<HookPoint> {
    match name {
        "before_tool_call" => Some(HookPoint::BeforeToolCall),
        "after_tool_call" => Some(HookPoint::AfterToolCall),
        "message_received" => Some(HookPoint::OnMessageReceived),
        "message_sending" => Some(HookPoint::OnMessageSending),
        "message_sent" => Some(HookPoint::OnMessageSending),
        "session_start" => Some(HookPoint::BeforeAgentStart),
        "session_end" => Some(HookPoint::AfterAgentComplete),
        _ => None,
    }
}

/// A bridge that invokes a WASM-exported hook function for each hook execution.
///
/// On each `execute()` call, the bridge:
/// 1. Instantiates the compiled module (fresh instance each time)
/// 2. Writes the hook context payload to guest memory
/// 3. Calls the exported hook function
/// 4. Reads the result from guest memory
/// 5. Returns `HookResult::Continue`, `Override`, or `Abort`
pub struct WasmHookBridge {
    engine: Engine,
    module: Module,
    export_name: String,
    skill_id: String,
    capabilities: CapabilitySet,
    fuel_limit: u64,
    max_memory_mb: usize,
    runtime_deps: HookRuntimeDeps,
}

impl WasmHookBridge {
    /// Create a new bridge for a specific hook binding.
    ///
    /// * `engine` – shared wasmtime engine (must have async support)
    /// * `module` – compiled WASM module
    /// * `export_name` – name of the exported function to call (e.g. `__on_before_tool_call`)
    /// * `skill_id` – skill identifier for logging/auditing
    /// * `capabilities` – capability set from manifest
    /// * `fuel_limit` – CPU fuel per hook invocation (0 = unlimited)
    /// * `max_memory_mb` – memory limit per invocation in MiB
    pub fn new(
        engine: Engine,
        module: Module,
        export_name: String,
        skill_id: String,
        capabilities: CapabilitySet,
        fuel_limit: u64,
        max_memory_mb: usize,
    ) -> Self {
        Self {
            engine,
            module,
            export_name,
            skill_id,
            capabilities,
            fuel_limit,
            max_memory_mb,
            runtime_deps: HookRuntimeDeps::default(),
        }
    }

    /// Inject runtime dependencies used by hook host functions.
    pub fn with_runtime_deps(mut self, runtime_deps: HookRuntimeDeps) -> Self {
        self.runtime_deps = runtime_deps;
        self
    }

    async fn load_skill_runtime_config(&self) -> Option<serde_json::Value> {
        let db_pool = self.runtime_deps.db_pool.clone()?;
        let skill_id = self.skill_id.clone();

        let rows = tokio::task::spawn_blocking(move || {
            let conn = db_pool
                .get()
                .map_err(|e| format!("db pool get failed: {e}"))?;
            let mut stmt = conn
                .prepare(
                    "SELECT key, value FROM skill_kv \
                     WHERE skill_id = ?1 AND key LIKE 'config:%' ORDER BY key",
                )
                .map_err(|e| format!("prepare skill config query failed: {e}"))?;
            stmt.query_map(rusqlite::params![skill_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
            .map_err(|e| format!("read skill config failed: {e}"))
        })
        .await;

        let rows = match rows {
            Ok(Ok(rows)) => rows,
            Ok(Err(e)) => {
                warn!(skill_id = %self.skill_id, error = %e, "failed to load hook runtime config");
                return None;
            }
            Err(e) => {
                warn!(skill_id = %self.skill_id, error = %e, "hook config loader task failed");
                return None;
            }
        };

        if rows.is_empty() {
            return None;
        }

        let mut config = serde_json::Map::new();
        for (key, value) in rows {
            let short_key = key.strip_prefix("config:").unwrap_or(&key);
            let parsed = serde_json::from_slice::<serde_json::Value>(&value).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&value).into())
            });
            config.insert(short_key.to_string(), parsed);
        }

        Some(serde_json::Value::Object(config))
    }

    async fn resolve_execution_context(
        &self,
        ctx: &HookContext,
    ) -> (ExecutionContext, Option<String>) {
        if ctx
            .method
            .as_deref()
            .is_some_and(|method| method.starts_with("channel."))
        {
            return (ExecutionContext::ChannelTransform, None);
        }
        if ctx
            .method
            .as_deref()
            .is_some_and(|method| method.starts_with("skill_timer."))
        {
            return (ExecutionContext::SkillTimer, None);
        }
        if ctx
            .method
            .as_deref()
            .is_some_and(|method| method.starts_with("cron."))
        {
            return (ExecutionContext::CronJob, Some("cron".to_string()));
        }

        let Some(session_store) = self.runtime_deps.session_store.as_ref() else {
            return (ExecutionContext::CronJob, None);
        };
        let Some(session_id) = ctx.session_id.as_ref() else {
            return (ExecutionContext::CronJob, None);
        };

        match session_store.get_session(session_id).await {
            Ok(Some(session)) if session.channel == "cron" => {
                (ExecutionContext::CronJob, Some(session.channel))
            }
            Ok(Some(session)) => (ExecutionContext::Interactive, Some(session.channel)),
            Ok(None) => (ExecutionContext::CronJob, None),
            Err(error) => {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "failed to resolve hook execution context from session; defaulting to non-interactive"
                );
                (ExecutionContext::CronJob, None)
            }
        }
    }
}

#[async_trait]
impl HookHandler for WasmHookBridge {
    async fn execute(&self, ctx: &mut HookContext) -> Result<HookResult, PluginError> {
        let has_native_alloc = self.module.exports().any(|e| e.name() == "__encmind_alloc");
        if !has_native_alloc {
            if self.module.exports().any(|e| e.name() == "_start") {
                return Err(PluginError::HookFailed(format!(
                    "skill '{}' uses Javy ABI which does not support hooks",
                    self.skill_id
                )));
            }
            return Err(PluginError::HookFailed(format!(
                "skill '{}' does not export __encmind_alloc required for native hook invocation",
                self.skill_id
            )));
        }

        let (execution_context, channel) = self.resolve_execution_context(ctx).await;
        let skill_config = self.load_skill_runtime_config().await;

        let state = StoreState {
            limiter: SkillResourceLimiter::new(self.max_memory_mb),
            skill_id: self.skill_id.clone(),
            capabilities: self.capabilities.clone(),
            last_error: None,
            db_pool: self.runtime_deps.db_pool.clone(),
            http_client: self.runtime_deps.http_client.clone(),
            outbound_policy: self.runtime_deps.outbound_policy.clone(),
            hook_registry: self.runtime_deps.hook_registry.clone(),
            skill_config,
            approval_prompter: self.runtime_deps.approval_prompter.clone(),
            execution_context,
            session_id: ctx.session_id.as_ref().map(|id| id.as_str().to_string()),
            agent_id: ctx.agent_id.as_ref().map(|id| id.as_str().to_string()),
            channel,
            invocation_id: None,
            wasi_ctx: None,
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limiter);

        if self.fuel_limit > 0 {
            store
                .set_fuel(self.fuel_limit)
                .map_err(|e| PluginError::HookFailed(format!("set_fuel: {e}")))?;
        }

        let linker = build_linker(&self.engine)
            .map_err(|e| PluginError::HookFailed(format!("linker build: {e}")))?;

        let instance = linker
            .instantiate_async(&mut store, &self.module)
            .await
            .map_err(|e| PluginError::HookFailed(format!("instantiation: {e}")))?;

        // Get guest exports
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginError::HookFailed("no memory export".into()))?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "__encmind_alloc")
            .map_err(|e| PluginError::HookFailed(format!("__encmind_alloc: {e}")))?;

        let hook_fn = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, &self.export_name)
            .map_err(|e| PluginError::HookFailed(format!("hook fn '{}': {e}", self.export_name)))?;

        // Write context payload to guest
        let payload_bytes = serde_json::to_vec(&ctx.payload)
            .map_err(|e| PluginError::HookFailed(format!("serialize: {e}")))?;

        let input_fat =
            abi::write_to_guest(&alloc_fn, store.as_context_mut(), &memory, &payload_bytes)
                .await
                .map_err(|e| PluginError::HookFailed(format!("write input: {e}")))?;

        let (input_ptr, input_len) = abi::decode_fat_ptr(input_fat);

        // Call the hook function
        let result_fat = hook_fn
            .call_async(&mut store, (input_ptr, input_len))
            .await
            .map_err(|e| PluginError::HookFailed(format!("hook call: {e}")))?;

        // 0 → Continue (no output)
        if result_fat == 0 {
            return Ok(HookResult::Continue);
        }

        // Read the result
        let (result_ptr, result_len) = abi::decode_fat_ptr(result_fat);
        let result_bytes =
            abi::read_guest_bytes(&memory, store.as_context(), result_ptr, result_len)
                .map_err(|e| PluginError::HookFailed(format!("read result: {e}")))?;

        let result: serde_json::Value = serde_json::from_slice(&result_bytes)
            .map_err(|e| PluginError::HookFailed(format!("parse result: {e}")))?;

        // Interpret the result:
        // {"action": "continue"} → Continue
        // {"action": "override", "payload": ...} → Override
        // {"action": "abort", "reason": "..."} → Abort
        match result.get("action").and_then(|v| v.as_str()) {
            Some("continue") | None => Ok(HookResult::Continue),
            Some("override") => {
                let payload = result
                    .get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                Ok(HookResult::Override(payload))
            }
            Some("abort") => {
                let reason = result
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hook aborted")
                    .to_string();
                Ok(HookResult::Abort { reason })
            }
            Some(other) => Ok(HookResult::Abort {
                reason: format!("unknown hook action: {other}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_core::error::StorageError;
    use encmind_core::traits::SessionStore;
    use encmind_core::types::{Message, Pagination, Session, SessionFilter};

    struct EmptySessionStore;

    #[async_trait::async_trait]
    impl SessionStore for EmptySessionStore {
        async fn create_session(&self, _channel: &str) -> Result<Session, StorageError> {
            Err(StorageError::NotFound("not implemented".into()))
        }

        async fn get_session(
            &self,
            _session_id: &encmind_core::types::SessionId,
        ) -> Result<Option<Session>, StorageError> {
            Ok(None)
        }

        async fn list_sessions(
            &self,
            _filter: SessionFilter,
        ) -> Result<Vec<Session>, StorageError> {
            Ok(Vec::new())
        }

        async fn rename_session(
            &self,
            _id: &encmind_core::types::SessionId,
            _title: &str,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn delete_session(
            &self,
            _session_id: &encmind_core::types::SessionId,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn append_message(
            &self,
            _session_id: &encmind_core::types::SessionId,
            _msg: &Message,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn get_messages(
            &self,
            _session_id: &encmind_core::types::SessionId,
            _pagination: Pagination,
        ) -> Result<Vec<Message>, StorageError> {
            Ok(Vec::new())
        }

        async fn compact_session(
            &self,
            _session_id: &encmind_core::types::SessionId,
            _keep_last: usize,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn make_test_bridge() -> WasmHookBridge {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).unwrap();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 1024
            )
            (func (export "__on_hook") (param i32 i32) (result i64)
                i64.const 0
            )
        )"#;
        let module = Module::new(&engine, wat).unwrap();
        WasmHookBridge::new(
            engine,
            module,
            "__on_hook".into(),
            "test-skill".into(),
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
            },
            1_000_000,
            64,
        )
        .with_runtime_deps(HookRuntimeDeps {
            session_store: Some(Arc::new(EmptySessionStore)),
            ..HookRuntimeDeps::default()
        })
    }

    #[test]
    fn hook_point_from_name_mapping() {
        assert_eq!(
            hook_point_from_name("before_tool_call"),
            Some(HookPoint::BeforeToolCall)
        );
        assert_eq!(
            hook_point_from_name("after_tool_call"),
            Some(HookPoint::AfterToolCall)
        );
        assert_eq!(
            hook_point_from_name("message_received"),
            Some(HookPoint::OnMessageReceived)
        );
        assert_eq!(
            hook_point_from_name("message_sending"),
            Some(HookPoint::OnMessageSending)
        );
        assert_eq!(
            hook_point_from_name("message_sent"),
            Some(HookPoint::OnMessageSending)
        );
        assert_eq!(
            hook_point_from_name("session_start"),
            Some(HookPoint::BeforeAgentStart)
        );
        assert_eq!(
            hook_point_from_name("session_end"),
            Some(HookPoint::AfterAgentComplete)
        );
        assert_eq!(hook_point_from_name("unknown"), None);
    }

    #[tokio::test]
    async fn bridge_invokes_continue_hook() {
        // A WASM module with a hook function that returns 0 (Continue)
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).unwrap();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 1024
            )
            (func (export "__on_hook") (param i32 i32) (result i64)
                ;; Return 0 = Continue
                i64.const 0
            )
        )"#;

        let module = Module::new(&engine, wat).unwrap();
        let bridge = WasmHookBridge::new(
            engine,
            module,
            "__on_hook".into(),
            "test-skill".into(),
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
            },
            1_000_000,
            64,
        );

        let mut ctx = HookContext {
            session_id: None,
            agent_id: None,
            method: Some("test".into()),
            payload: serde_json::json!({"key": "value"}),
        };

        let result = bridge.execute(&mut ctx).await.unwrap();
        assert!(matches!(result, HookResult::Continue));
    }

    #[tokio::test]
    async fn bridge_missing_export_returns_error() {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).unwrap();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 1024
            )
        )"#;

        let module = Module::new(&engine, wat).unwrap();
        let bridge = WasmHookBridge::new(
            engine,
            module,
            "__nonexistent".into(),
            "test-skill".into(),
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
            },
            1_000_000,
            64,
        );

        let mut ctx = HookContext {
            session_id: None,
            agent_id: None,
            method: None,
            payload: serde_json::Value::Null,
        };

        let result = bridge.execute(&mut ctx).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("__nonexistent"), "got: {msg}");
    }

    #[tokio::test]
    async fn bridge_rejects_javy_module_with_clear_error() {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).unwrap();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "_start"))
        )"#;

        let module = Module::new(&engine, wat).unwrap();
        let bridge = WasmHookBridge::new(
            engine,
            module,
            "__on_hook".into(),
            "javy-test".into(),
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
            },
            1_000_000,
            64,
        );

        let mut ctx = HookContext {
            session_id: None,
            agent_id: None,
            method: None,
            payload: serde_json::json!({}),
        };

        let result = bridge.execute(&mut ctx).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Javy ABI which does not support hooks"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_execution_context_uses_method_prefixes_for_non_interactive_paths() {
        let bridge = make_test_bridge();

        let mut cron_ctx = HookContext {
            session_id: None,
            agent_id: None,
            method: Some("cron.skill_event:test".into()),
            payload: serde_json::json!({}),
        };
        let (cron_exec, cron_channel) = bridge.resolve_execution_context(&cron_ctx).await;
        assert_eq!(cron_exec, ExecutionContext::CronJob);
        assert_eq!(cron_channel.as_deref(), Some("cron"));

        cron_ctx.method = Some("skill_timer.skill_event:test".into());
        let (timer_exec, timer_channel) = bridge.resolve_execution_context(&cron_ctx).await;
        assert_eq!(timer_exec, ExecutionContext::SkillTimer);
        assert_eq!(timer_channel, None);

        cron_ctx.method = Some("channel.skill_event:test".into());
        let (channel_exec, channel_name) = bridge.resolve_execution_context(&cron_ctx).await;
        assert_eq!(channel_exec, ExecutionContext::ChannelTransform);
        assert_eq!(channel_name, None);
    }

    #[tokio::test]
    async fn resolve_execution_context_defaults_to_non_interactive_when_session_unresolved() {
        let bridge = make_test_bridge();
        let mut ctx = HookContext {
            session_id: None,
            agent_id: None,
            method: None,
            payload: serde_json::json!({}),
        };
        let (missing_session_id_ctx, missing_session_id_channel) =
            bridge.resolve_execution_context(&ctx).await;
        assert_eq!(missing_session_id_ctx, ExecutionContext::CronJob);
        assert_eq!(missing_session_id_channel, None);

        ctx.session_id = Some(encmind_core::types::SessionId::new());
        let (missing_session_ctx, missing_session_channel) =
            bridge.resolve_execution_context(&ctx).await;
        assert_eq!(missing_session_ctx, ExecutionContext::CronJob);
        assert_eq!(missing_session_channel, None);
    }
}
