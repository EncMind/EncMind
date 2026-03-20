use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};

use encmind_channels::transform::ChannelTransform;
use encmind_core::error::ChannelError;
use encmind_core::hooks::HookRegistry;
use encmind_core::types::{InboundMessage, OutboundMessage};
use encmind_storage::audit::AuditLogger;
use encmind_wasm_host::invoker::{InvokeDeps, SkillInvoker};
use encmind_wasm_host::{ApprovalPrompter, OutboundPolicy};

use crate::server::load_skill_runtime_config;

#[derive(Clone)]
pub struct WasmTransformDependencies {
    pub db_pool: Arc<encmind_wasm_host::SqlitePool>,
    pub http_client: Arc<reqwest::Client>,
    pub outbound_policy: Arc<dyn OutboundPolicy>,
    pub hook_registry: Arc<tokio::sync::RwLock<HookRegistry>>,
    pub approval_prompter: Arc<dyn ApprovalPrompter>,
    pub audit_logger: Option<Arc<AuditLogger>>,
}

#[derive(Clone)]
pub struct WasmTransformRuntimeConfig {
    pub invoker: Arc<SkillInvoker>,
    pub wall_clock_timeout: Duration,
    pub deps: WasmTransformDependencies,
}

/// A WASM-backed channel transform that calls exported functions on a compiled module.
pub struct WasmChannelTransform {
    skill_id: String,
    channel_hint: Option<String>,
    inbound_fn: Option<String>,
    outbound_fn: Option<String>,
    invoker: Option<Arc<SkillInvoker>>,
    wall_clock_timeout: Duration,
    deps: Option<WasmTransformDependencies>,
}

impl WasmChannelTransform {
    pub fn new(skill_id: String, inbound_fn: Option<String>, outbound_fn: Option<String>) -> Self {
        Self {
            skill_id,
            channel_hint: None,
            inbound_fn,
            outbound_fn,
            invoker: None,
            wall_clock_timeout: Duration::from_secs(10),
            deps: None,
        }
    }

    pub fn with_channel_hint(mut self, channel: impl Into<String>) -> Self {
        self.channel_hint = Some(channel.into());
        self
    }

    pub fn with_runtime(mut self, runtime: WasmTransformRuntimeConfig) -> Self {
        self.invoker = Some(runtime.invoker);
        self.wall_clock_timeout = runtime.wall_clock_timeout;
        self.deps = Some(runtime.deps);
        self
    }

    async fn invoke_transform(
        &self,
        direction: &str,
        export_name: &str,
        payload: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, ChannelError> {
        let invoker = match &self.invoker {
            Some(inv) => inv,
            None => return Ok(Some(payload)),
        };
        let deps = match &self.deps {
            Some(deps) => deps,
            None => return Ok(Some(payload)),
        };

        let started_at = Instant::now();
        let invocation_id = ulid::Ulid::new().to_string();
        let channel = payload
            .get("channel")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .or_else(|| self.channel_hint.clone());
        let invoke_deps = InvokeDeps {
            db_pool: Some(deps.db_pool.clone()),
            http_client: Some(deps.http_client.clone()),
            outbound_policy: Some(deps.outbound_policy.clone()),
            hook_registry: Some(deps.hook_registry.clone()),
            approval_prompter: Some(deps.approval_prompter.clone()),
            skill_config: load_skill_runtime_config(&deps.db_pool, &self.skill_id),
            execution_context: encmind_wasm_host::ExecutionContext::ChannelTransform,
            session_id: None,
            agent_id: None,
            channel,
            invocation_id: Some(invocation_id.clone()),
        };

        let result = async {
            let value = invoker
                .invoke_export(export_name, &payload, &invoke_deps, self.wall_clock_timeout)
                .await
                .map_err(|e| ChannelError::SendFailed(format!("{e}")))?;

            if value.get("action").and_then(|v| v.as_str()) == Some("drop")
                || value.get("drop").and_then(|v| v.as_bool()) == Some(true)
            {
                return Ok(None);
            }
            if let Some(message) = value.get("message") {
                return Ok(Some(message.clone()));
            }
            if value.as_object().is_some_and(|obj| obj.is_empty()) {
                // Keep legacy behavior: empty output from a transform means passthrough.
                return Ok(Some(payload));
            }
            Ok(Some(value))
        }
        .await;

        if let Some(ref audit) = deps.audit_logger {
            let duration_ms = started_at.elapsed().as_millis();
            let status = if result.is_ok() { "ok" } else { "error" };
            let detail = serde_json::json!({
                "invocation_id": invocation_id,
                "skill_id": self.skill_id.as_str(),
                "direction": direction,
                "export_name": export_name,
                "status": status,
                "duration_ms": duration_ms,
                "error": result.as_ref().err().map(|e: &ChannelError| e.to_string()),
            });
            let audit = audit.clone();
            let action = format!("skill.{}.transform.{}", self.skill_id, direction);
            let detail_json = detail.to_string();
            let skill_id = self.skill_id.clone();
            let direction = direction.to_string();
            std::mem::drop(tokio::task::spawn_blocking(move || {
                if let Err(err) = audit.append("skill", &action, Some(&detail_json), None) {
                    tracing::warn!(
                        skill_id = %skill_id,
                        direction = %direction,
                        error = %err,
                        "failed to append transform audit entry"
                    );
                }
            }));
        }

        result
    }
}

#[async_trait]
impl ChannelTransform for WasmChannelTransform {
    fn name(&self) -> &str {
        &self.skill_id
    }

    async fn transform_inbound(
        &self,
        msg: InboundMessage,
    ) -> Result<Option<InboundMessage>, ChannelError> {
        if self.inbound_fn.is_none() {
            return Ok(Some(msg));
        }
        let payload = serde_json::to_value(&msg)
            .map_err(|e| ChannelError::SendFailed(format!("serialize inbound message: {e}")))?;
        let transformed = self
            .invoke_transform(
                "inbound",
                self.inbound_fn.as_deref().unwrap_or_default(),
                payload,
            )
            .await?;
        match transformed {
            None => Ok(None),
            Some(value) => {
                let msg = serde_json::from_value::<InboundMessage>(value).map_err(|e| {
                    ChannelError::SendFailed(format!("invalid inbound transform output: {e}"))
                })?;
                Ok(Some(msg))
            }
        }
    }

    async fn transform_outbound(
        &self,
        msg: OutboundMessage,
    ) -> Result<Option<OutboundMessage>, ChannelError> {
        if self.outbound_fn.is_none() {
            return Ok(Some(msg));
        }
        let payload = serde_json::to_value(&msg)
            .map_err(|e| ChannelError::SendFailed(format!("serialize outbound message: {e}")))?;
        let transformed = self
            .invoke_transform(
                "outbound",
                self.outbound_fn.as_deref().unwrap_or_default(),
                payload,
            )
            .await?;
        match transformed {
            None => Ok(None),
            Some(value) => {
                let msg = serde_json::from_value::<OutboundMessage>(value).map_err(|e| {
                    ChannelError::SendFailed(format!("invalid outbound transform output: {e}"))
                })?;
                Ok(Some(msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use encmind_core::hooks::HookRegistry;
    use encmind_core::traits::CapabilitySet;
    use encmind_core::types::{ContentBlock, SkillApprovalRequest, SkillApprovalResponse};
    use encmind_wasm_host::SkillAbi;
    use std::time::Duration as StdDuration;

    struct AllowAllOutboundPolicy;

    #[async_trait]
    impl OutboundPolicy for AllowAllOutboundPolicy {
        async fn check_url(&self, _url: &str) -> Result<(), String> {
            Ok(())
        }
    }

    struct AutoApprovePrompter;

    #[async_trait]
    impl ApprovalPrompter for AutoApprovePrompter {
        async fn prompt(
            &self,
            request: SkillApprovalRequest,
            _timeout: StdDuration,
        ) -> SkillApprovalResponse {
            SkillApprovalResponse {
                request_id: request.request_id,
                approved: true,
                choice: Some("approve".into()),
            }
        }
    }

    struct SlowApprovePrompter;

    #[async_trait]
    impl ApprovalPrompter for SlowApprovePrompter {
        async fn prompt(
            &self,
            request: SkillApprovalRequest,
            _timeout: StdDuration,
        ) -> SkillApprovalResponse {
            tokio::time::sleep(StdDuration::from_millis(200)).await;
            SkillApprovalResponse {
                request_id: request.request_id,
                approved: true,
                choice: Some("approve".into()),
            }
        }
    }

    fn make_inbound(text: &str) -> InboundMessage {
        InboundMessage {
            channel: "telegram".into(),
            sender_id: "user-1".into(),
            content: vec![ContentBlock::Text { text: text.into() }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        }
    }

    fn make_outbound(text: &str) -> OutboundMessage {
        OutboundMessage {
            content: vec![ContentBlock::Text { text: text.into() }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        }
    }

    fn empty_capabilities() -> CapabilitySet {
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

    fn make_test_deps() -> WasmTransformDependencies {
        WasmTransformDependencies {
            db_pool: Arc::new(encmind_storage::pool::create_test_pool()),
            http_client: Arc::new(reqwest::Client::new()),
            outbound_policy: Arc::new(AllowAllOutboundPolicy),
            hook_registry: Arc::new(tokio::sync::RwLock::new(HookRegistry::new())),
            approval_prompter: Arc::new(AutoApprovePrompter),
            audit_logger: None,
        }
    }

    fn make_slow_prompt_test_deps() -> WasmTransformDependencies {
        WasmTransformDependencies {
            db_pool: Arc::new(encmind_storage::pool::create_test_pool()),
            http_client: Arc::new(reqwest::Client::new()),
            outbound_policy: Arc::new(AllowAllOutboundPolicy),
            hook_registry: Arc::new(tokio::sync::RwLock::new(HookRegistry::new())),
            approval_prompter: Arc::new(SlowApprovePrompter),
            audit_logger: None,
        }
    }

    fn compile_module(wat: &str, consume_fuel: bool) -> (wasmtime::Engine, wasmtime::Module) {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(consume_fuel);
        let engine = wasmtime::Engine::new(&config).expect("create test engine");
        let module = wasmtime::Module::new(&engine, wat).expect("compile test module");
        (engine, module)
    }

    fn make_test_runtime_config(
        wat: &str,
        skill_id: &str,
        fuel_limit: u64,
        timeout_ms: u64,
        deps: WasmTransformDependencies,
    ) -> WasmTransformRuntimeConfig {
        make_test_runtime_config_with_capabilities(
            wat,
            skill_id,
            fuel_limit,
            timeout_ms,
            empty_capabilities(),
            deps,
        )
    }

    fn make_test_runtime_config_with_capabilities(
        wat: &str,
        skill_id: &str,
        fuel_limit: u64,
        timeout_ms: u64,
        capabilities: encmind_core::traits::CapabilitySet,
        deps: WasmTransformDependencies,
    ) -> WasmTransformRuntimeConfig {
        let (engine, module) = compile_module(wat, true);
        let invoker = Arc::new(SkillInvoker::new(
            engine,
            module,
            SkillAbi::Native,
            skill_id.to_string(),
            capabilities,
            fuel_limit,
            64,
        ));
        WasmTransformRuntimeConfig {
            invoker,
            wall_clock_timeout: StdDuration::from_millis(timeout_ms),
            deps,
        }
    }

    fn echo_transform_wat(export_fn: &str) -> String {
        format!(
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (i64.or
                        (i64.shl (i64.extend_i32_u (local.get 0)) (i64.const 32))
                        (i64.extend_i32_u (local.get 1))
                    )
                )
            )"#
        )
    }

    fn static_json_transform_wat(export_fn: &str, json: &str) -> String {
        let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
        let len = json.len();
        format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) "{escaped}")
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (i64.or
                        (i64.shl (i64.const 2048) (i64.const 32))
                        (i64.const {len})
                    )
                )
            )"#
        )
    }

    fn spin_transform_wat(export_fn: &str) -> String {
        format!(
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (loop $spin
                        br $spin
                    )
                    i64.const 0
                )
            )"#
        )
    }

    fn approval_wait_transform_wat(export_fn: &str) -> String {
        let prompt = r#"{"prompt":"wait"}"#;
        let escaped = prompt.replace('\\', "\\\\").replace('"', "\\\"");
        let len = prompt.len();
        format!(
            r#"(module
                (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
                (memory (export "memory") 1)
                (data (i32.const 0) "{escaped}")
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (call $prompt (i32.const 0) (i32.const {len}))
                )
            )"#
        )
    }

    #[tokio::test]
    async fn wasm_transform_inbound_passthrough() {
        let transform =
            WasmChannelTransform::new("skill-a".into(), Some("transform_in".into()), None);
        let msg = make_inbound("hello");
        let result = transform.transform_inbound(msg).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn wasm_transform_outbound_passthrough() {
        let transform =
            WasmChannelTransform::new("skill-a".into(), None, Some("transform_out".into()));
        let msg = make_outbound("goodbye");
        let result = transform.transform_outbound(msg).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn wasm_transform_skips_when_no_fn() {
        let transform = WasmChannelTransform::new(
            "skill-a".into(),
            None, // no inbound fn
            None, // no outbound fn
        );
        let in_msg = make_inbound("hello");
        let result = transform.transform_inbound(in_msg).await.unwrap();
        assert!(result.is_some());

        let out_msg = make_outbound("bye");
        let result = transform.transform_outbound(out_msg).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn wasm_transform_runtime_invoke_parses_echo_output() {
        let transform =
            WasmChannelTransform::new("skill-a".into(), Some("transform_in".into()), None)
                .with_runtime(make_test_runtime_config(
                    &echo_transform_wat("transform_in"),
                    "skill-a",
                    1_000_000,
                    500,
                    make_test_deps(),
                ));

        let msg = make_inbound("hello runtime");
        let result = transform.transform_inbound(msg.clone()).await.unwrap();
        let Some(transformed) = result else {
            panic!("expected transformed message");
        };
        assert_eq!(transformed.sender_id, msg.sender_id);
        assert_eq!(transformed.channel, msg.channel);
    }

    #[tokio::test]
    async fn wasm_transform_runtime_drop_action_returns_none() {
        let transform =
            WasmChannelTransform::new("skill-a".into(), Some("transform_in".into()), None)
                .with_runtime(make_test_runtime_config(
                    &static_json_transform_wat("transform_in", r#"{"action":"drop"}"#),
                    "skill-a",
                    1_000_000,
                    500,
                    make_test_deps(),
                ));

        let result = transform
            .transform_inbound(make_inbound("drop this"))
            .await
            .unwrap();
        assert!(result.is_none(), "expected drop action to remove message");
    }

    #[tokio::test]
    async fn wasm_transform_runtime_empty_output_passthroughs_original_message() {
        let transform =
            WasmChannelTransform::new("skill-a".into(), Some("transform_in".into()), None)
                .with_runtime(make_test_runtime_config(
                    &static_json_transform_wat("transform_in", "{}"),
                    "skill-a",
                    1_000_000,
                    500,
                    make_test_deps(),
                ));

        let original = make_inbound("keep original");
        let transformed = transform
            .transform_inbound(original.clone())
            .await
            .unwrap()
            .expect("transform should passthrough");
        assert_eq!(transformed.channel, original.channel);
        assert_eq!(transformed.sender_id, original.sender_id);
        assert_eq!(transformed.content, original.content);
        assert_eq!(transformed.attachments.len(), original.attachments.len());
    }

    #[tokio::test]
    async fn wasm_transform_fast_denies_approval_in_non_interactive_context() {
        // In ChannelTransform context, approval prompts get fast-denied instead of
        // blocking until timeout. The transform returns immediately with a denial
        // response which is not valid transform output, producing an error — but
        // crucially, it does NOT time out.
        let mut capabilities = empty_capabilities();
        capabilities.prompt_user = true;
        let transform =
            WasmChannelTransform::new("skill-a".into(), Some("transform_in".into()), None)
                .with_runtime(make_test_runtime_config_with_capabilities(
                    &approval_wait_transform_wat("transform_in"),
                    "skill-a",
                    1_000_000,
                    20,
                    capabilities,
                    make_slow_prompt_test_deps(),
                ));

        let result = transform
            .transform_inbound(make_inbound("timeout test"))
            .await;
        // The fast-deny returns a JSON that is not a valid InboundMessage,
        // so we get a deserialization error — but NOT a "timed out" error.
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("timed out"),
            "should not time out with fast-deny, got: {err}"
        );
        assert!(
            err.contains("invalid") || err.contains("transform output"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn wasm_transform_runtime_fuel_exhaustion_returns_error() {
        let transform =
            WasmChannelTransform::new("skill-a".into(), Some("transform_in".into()), None)
                .with_runtime(make_test_runtime_config(
                    &spin_transform_wat("transform_in"),
                    "skill-a",
                    50,
                    1_000,
                    make_test_deps(),
                ));

        let err = transform
            .transform_inbound(make_inbound("fuel test"))
            .await
            .unwrap_err()
            .to_string();
        let lower = err.to_lowercase();
        assert!(
            lower.contains("fuel")
                || lower.contains("out of fuel")
                || lower.contains("invocation failed"),
            "unexpected error: {err}"
        );
        assert!(
            !lower.contains("timed out"),
            "expected trap-style failure, got timeout: {err}"
        );
    }

    #[tokio::test]
    async fn wasm_transform_writes_audit_entry() {
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let audit = Arc::new(encmind_storage::audit::AuditLogger::new(pool.clone()));
        let deps = WasmTransformDependencies {
            db_pool: Arc::new(pool),
            http_client: Arc::new(reqwest::Client::new()),
            outbound_policy: Arc::new(AllowAllOutboundPolicy),
            hook_registry: Arc::new(tokio::sync::RwLock::new(HookRegistry::new())),
            approval_prompter: Arc::new(AutoApprovePrompter),
            audit_logger: Some(audit.clone()),
        };

        let transform = WasmChannelTransform::new(
            "skill-transform-audit".into(),
            Some("transform_in".into()),
            None,
        )
        .with_runtime(make_test_runtime_config(
            &echo_transform_wat("transform_in"),
            "skill-transform-audit",
            1_000_000,
            500,
            deps,
        ));

        let _ = transform
            .transform_inbound(make_inbound("audit me"))
            .await
            .unwrap();

        let mut entries = Vec::new();
        for _ in 0..50 {
            entries = audit
                .query(
                    encmind_storage::audit::AuditFilter {
                        category: Some("skill".to_string()),
                        action: Some("skill.skill-transform-audit.transform.inbound".to_string()),
                        ..Default::default()
                    },
                    10,
                    0,
                )
                .unwrap();
            if entries.len() == 1 {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
        assert_eq!(entries.len(), 1, "expected one transform audit entry");
    }
}
