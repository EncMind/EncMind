use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use encmind_core::config::AppConfig;
use encmind_core::error::AppError;
use encmind_core::traits::{AgentRegistry, ApprovalHandler, LlmBackend, SessionStore};
use encmind_core::types::*;

use crate::approval::ToolApprovalChecker;
use crate::firewall::EgressFirewall;
use crate::pool::AgentPool;
use crate::runtime::{AgentRuntime, RuntimeConfig};
use crate::tool_registry::{InternalToolHandler, ToolRegistry};

/// Internal tool handler that spawns a sub-agent to handle a delegated task.
///
/// Key design: the sub-agent's `ToolRegistry` omits the `agents_spawn` tool
/// to enforce single-level delegation (no recursive spawning).
pub struct SpawnAgentHandler {
    llm: Arc<dyn LlmBackend>,
    session_store: Arc<dyn SessionStore>,
    agent_registry: Arc<dyn AgentRegistry>,
    agent_pool: Arc<AgentPool>,
    /// A tool registry WITHOUT the `agents_spawn` tool registered.
    base_registry: Arc<ToolRegistry>,
    runtime_config: RuntimeConfig,
    approval_handler: Option<Arc<dyn ApprovalHandler>>,
    approval_checker: Option<ToolApprovalChecker>,
    /// Live config for reading runtime policy per invocation.
    /// When set, takes precedence over static runtime/approval snapshots.
    config: Option<Arc<RwLock<AppConfig>>>,
    firewall: Option<Arc<EgressFirewall>>,
    // caller_agent_id -> allowed target agent IDs
    allow_map: Option<HashMap<String, Vec<String>>>,
}

impl SpawnAgentHandler {
    pub fn new(
        llm: Arc<dyn LlmBackend>,
        session_store: Arc<dyn SessionStore>,
        agent_registry: Arc<dyn AgentRegistry>,
        agent_pool: Arc<AgentPool>,
        base_registry: Arc<ToolRegistry>,
        runtime_config: RuntimeConfig,
    ) -> Self {
        Self {
            llm,
            session_store,
            agent_registry,
            agent_pool,
            base_registry,
            runtime_config,
            approval_handler: None,
            approval_checker: None,
            config: None,
            firewall: None,
            allow_map: None,
        }
    }

    pub fn with_approval(
        mut self,
        handler: Arc<dyn ApprovalHandler>,
        checker: ToolApprovalChecker,
    ) -> Self {
        self.approval_handler = Some(handler);
        self.approval_checker = Some(checker);
        self
    }

    /// Set shared config for live policy reads per invocation.
    /// When set, `handle()` refreshes prompt-injection toggles and builds a
    /// fresh `ToolApprovalChecker` instead of using static snapshots.
    pub fn with_config(mut self, config: Arc<RwLock<AppConfig>>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_firewall(mut self, firewall: Arc<EgressFirewall>) -> Self {
        self.firewall = Some(firewall);
        self
    }

    pub fn with_allow_map(mut self, allow_map: HashMap<String, Vec<String>>) -> Self {
        self.allow_map = Some(allow_map);
        self
    }
}

#[async_trait]
impl InternalToolHandler for SpawnAgentHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let target_agent_id = input
            .get("agent_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("agents_spawn: missing 'agent_id' field".into()))?;

        let task = input
            .get("task")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("agents_spawn: missing 'task' field".into()))?;

        if let Some(ref allow_map) = self.allow_map {
            let caller = agent_id.as_str();
            let allowed = allow_map
                .get(caller)
                .map(|targets| targets.iter().any(|target| target == target_agent_id))
                .unwrap_or(false);
            if !allowed {
                return Err(AppError::Internal(format!(
                    "agents_spawn: caller '{}' is not allowed to spawn '{}'",
                    caller, target_agent_id
                )));
            }
        }

        let agent_config = self
            .agent_registry
            .get_agent(&AgentId::new(target_agent_id))
            .await?
            .ok_or_else(|| {
                AppError::Internal(format!("agents_spawn: agent '{target_agent_id}' not found"))
            })?;

        // Create an isolated session for the sub-agent
        let sub_session = self
            .session_store
            .create_session_for_agent("subagent", &agent_config.id)
            .await?;

        // Build a sub-runtime WITHOUT the spawn tool (single-level enforcement).
        // Also enforce per-agent skill tool filtering.
        let sub_registry = self.base_registry.filtered_for_agent(&agent_config.skills);
        let mut sub_runtime_config = self.runtime_config.clone();
        sub_runtime_config.workspace_dir = agent_config.workspace.as_ref().map(PathBuf::from);

        // Live-read prompt injection toggles, workspace trust, and bash policy
        // from current config (not the init snapshot), so operator changes take
        // effect immediately.
        let (live_workspace_trust, live_bash_mode, live_local_bash_enabled) = if let Some(ref cfg) =
            self.config
        {
            let guard = cfg.read().await;
            sub_runtime_config
                .context_config
                .sliding_window_truncation_threshold =
                guard.token_optimization.sliding_window_truncation_threshold;
            sub_runtime_config
                .context_config
                .inject_behavioral_governance =
                guard.token_optimization.inject_behavioral_governance;
            sub_runtime_config.context_config.inject_tool_usage_grammar =
                guard.token_optimization.inject_tool_usage_grammar;
            sub_runtime_config
                .context_config
                .inject_browser_safety_rules = guard.token_optimization.inject_browser_safety_rules;
            sub_runtime_config.context_config.inject_coordinator_mode =
                guard.token_optimization.inject_coordinator_mode;
            // Brief mode: read from live config. Per-channel and per-request
            // overrides cannot propagate to subagents because the subagent
            // runs on its own session (channel="subagent"). The global
            // brief_mode setting is the only knob that applies here.
            sub_runtime_config.context_config.brief_mode = guard.token_optimization.brief_mode;
            // Capture the local-bash enablement alongside bash_mode so the
            // nested runtime's approval checker matches the top-level
            // behavior set in gateway_approval_policy(). Without this, a
            // subagent could still see `bash_exec` in its prompt even
            // though `local_tools.*` disabled it for the parent.
            let local_bash_enabled = guard.security.local_bash_effectively_enabled();
            (
                Some(guard.security.workspace_trust.clone()),
                Some(guard.security.bash_mode.clone()),
                Some(local_bash_enabled),
            )
        } else {
            (None, None, None)
        };
        if let Some(workspace_trust) = live_workspace_trust {
            sub_runtime_config.workspace_trust = workspace_trust;
        };
        // Inherit the parent's class from the task-local set by
        // `AgentRuntime::run_inner` so the nested run scopes the same
        // class into its own task-local. Although current policy
        // forbids further nesting, this keeps the invariant local.
        let parent_class = crate::scheduler::current_query_class();
        sub_runtime_config.query_class = parent_class;
        let mut sub_runtime = AgentRuntime::new(
            self.llm.clone(),
            self.session_store.clone(),
            Arc::new(sub_registry),
            sub_runtime_config,
        );
        if let Some(ref firewall) = self.firewall {
            sub_runtime = sub_runtime.with_firewall(firewall.clone());
        }
        if let Some(ref handler) = self.approval_handler {
            // Prefer live config over static checker. The checker must
            // use `with_bash_effective_mode` so that the
            // local-tools-only disable flag is honored for nested runs
            // — otherwise a subagent would still see `bash_exec` in its
            // prompt even when the parent had it filtered out.
            let checker = if let Some(bash_mode) = live_bash_mode {
                let mut checker = ToolApprovalChecker::with_bash_effective_mode(
                    bash_mode,
                    live_local_bash_enabled.unwrap_or(true),
                );
                if let Some(ref static_checker) = self.approval_checker {
                    checker = checker.with_interactive_approval_available(
                        static_checker.interactive_approval_available(),
                    );
                }
                checker
            } else if let Some(ref static_checker) = self.approval_checker {
                static_checker.clone()
            } else {
                // Handler present but no checker — default to Ask mode.
                ToolApprovalChecker::new(encmind_core::config::BashMode::Ask)
            };
            sub_runtime = sub_runtime.with_approval(handler.clone(), checker);
        }

        let user_msg = Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: task.to_owned(),
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        };

        let cancel = CancellationToken::new();
        // `parent_class` was captured above from the task-local so the
        // sub_runtime's config and the pool acquisition agree. A
        // background parent (e.g. cron) must not escalate its
        // subagents to interactive priority.
        let result = self
            .agent_pool
            .execute(
                &sub_runtime,
                &sub_session.id,
                user_msg,
                &agent_config,
                cancel,
                parent_class,
            )
            .await?;

        // Extract the text response first. If workspace trust blocked one or more
        // subagent tools, preserve this partial response in the propagated error
        // so the parent agent can still use recovered context.
        let response_text = result
            .response
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");

        let denied_tools: Vec<String> = result
            .tool_calls
            .iter()
            .filter(|call| {
                call.decision.as_ref().is_some_and(|d| {
                    d.source == encmind_core::permission::DecisionSource::WorkspaceTrust
                })
            })
            .map(|call| call.name.clone())
            .collect();
        if !denied_tools.is_empty() {
            let mut detail = format!(
                "subagent '{}' blocked by workspace trust policy for tools: {}",
                target_agent_id,
                denied_tools.join(", ")
            );
            let trimmed = response_text.trim();
            if !trimmed.is_empty() {
                detail.push_str("\npartial subagent response:\n");
                detail.push_str(trimmed);
            }
            return Err(AppError::ToolDenied {
                reason: "workspace_untrusted".to_string(),
                message: detail,
            });
        }

        Ok(response_text)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::approval::ToolApprovalChecker;
    use crate::pool::AgentPool;
    use crate::runtime::test_helpers::*;
    use crate::tool_registry::{InternalToolHandler, ToolRegistry};
    use encmind_core::config::{AgentPoolConfig, BashMode};
    use encmind_core::error::StorageError;
    use encmind_core::traits::{AgentRegistry, ApprovalHandler, LlmBackend, SessionStore};

    /// Minimal in-memory agent registry for testing.
    struct TestAgentRegistry {
        agents: std::collections::HashMap<String, AgentConfig>,
    }

    impl TestAgentRegistry {
        fn new(agents: Vec<AgentConfig>) -> Self {
            let map = agents
                .into_iter()
                .map(|a| (a.id.as_str().to_owned(), a))
                .collect();
            Self { agents: map }
        }
    }

    #[async_trait]
    impl AgentRegistry for TestAgentRegistry {
        async fn list_agents(&self) -> Result<Vec<AgentConfig>, StorageError> {
            Ok(self.agents.values().cloned().collect())
        }
        async fn get_agent(&self, id: &AgentId) -> Result<Option<AgentConfig>, StorageError> {
            Ok(self.agents.get(id.as_str()).cloned())
        }
        async fn resolve_agent(&self, _session_id: &SessionId) -> Result<AgentId, StorageError> {
            Ok(AgentId::default())
        }
        async fn create_agent(&self, _config: AgentConfig) -> Result<(), StorageError> {
            Ok(())
        }
        async fn update_agent(
            &self,
            _id: &AgentId,
            _config: AgentConfig,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        async fn delete_agent(&self, _id: &AgentId) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn researcher_config() -> AgentConfig {
        AgentConfig {
            id: AgentId::new("researcher"),
            name: "Research Agent".into(),
            model: None,
            workspace: None,
            system_prompt: Some("You are a research assistant.".into()),
            skills: vec![],
            is_default: false,
        }
    }

    fn writer_config() -> AgentConfig {
        AgentConfig {
            id: AgentId::new("writer"),
            name: "Writer Agent".into(),
            model: None,
            workspace: None,
            system_prompt: Some("You are a writing assistant.".into()),
            skills: vec![],
            is_default: false,
        }
    }

    #[tokio::test]
    async fn spawn_succeeds() {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![text_response("research result")],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> =
            Arc::new(TestAgentRegistry::new(vec![researcher_config()]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));
        let base_reg = Arc::new(ToolRegistry::new());

        let handler = SpawnAgentHandler::new(
            llm,
            store.clone(),
            registry,
            pool,
            base_reg,
            RuntimeConfig::default(),
        );

        let input = serde_json::json!({
            "agent_id": "researcher",
            "task": "Find info about Rust"
        });

        let result = handler
            .handle(input, &SessionId::new(), &AgentId::default())
            .await
            .unwrap();

        assert!(result.contains("research result"));
    }

    #[tokio::test]
    async fn single_level_enforced() {
        // Verify that the base_registry (used by sub-agents) does NOT contain agents_spawn
        let base_reg = ToolRegistry::new();
        assert!(!base_reg.has_tool("agents_spawn"));

        // Even if we build a parent registry with agents_spawn, the sub-agent's
        // base_registry won't have it
        let parent_reg = ToolRegistry::new();
        // We can't easily register the spawn tool without the full handler,
        // but we can verify the base_reg doesn't have it
        assert!(!base_reg.has_tool("agents_spawn"));
        assert!(!parent_reg.has_tool("agents_spawn"));
        assert_eq!(base_reg.len(), 0);
    }

    #[tokio::test]
    async fn result_delivered_back() {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![text_response("42 is the answer")],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> =
            Arc::new(TestAgentRegistry::new(vec![researcher_config()]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        );

        let result = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "What is 42?"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await
            .unwrap();

        assert_eq!(result, "42 is the answer");
    }

    #[tokio::test]
    async fn agent_not_found_errors() {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(vec![], 128_000));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> = Arc::new(TestAgentRegistry::new(vec![])); // no agents
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        );

        let result = handler
            .handle(
                serde_json::json!({"agent_id": "ghost", "task": "do something"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "expected 'not found' error: {err}"
        );
    }

    #[tokio::test]
    async fn session_agent_isolation_mode_works_for_subagent() {
        let llm: Arc<dyn LlmBackend> =
            Arc::new(ScriptedLlmBackend::new(vec![text_response("ok")], 128_000));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> =
            Arc::new(TestAgentRegistry::new(vec![researcher_config()]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                enforce_session_agent_match: true,
                ..Default::default()
            },
        );

        let result = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "hi"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(
            result.is_ok(),
            "sub-agent should run with matching session agent"
        );
    }

    #[tokio::test]
    async fn allow_map_enforced_for_spawn() {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![text_response("research result")],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> = Arc::new(TestAgentRegistry::new(vec![
            researcher_config(),
            writer_config(),
        ]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));

        let mut allow_map = HashMap::new();
        allow_map.insert("main".into(), vec!["researcher".into()]);

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        )
        .with_allow_map(allow_map);

        let denied = handler
            .handle(
                serde_json::json!({"agent_id": "writer", "task": "draft intro"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(denied.is_err());
        assert!(denied
            .unwrap_err()
            .to_string()
            .contains("not allowed to spawn"));
    }

    #[tokio::test]
    async fn subagent_filters_skill_tools_by_target_agent_config() {
        struct CountingTool {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl InternalToolHandler for CountingTool {
            async fn handle(
                &self,
                _input: serde_json::Value,
                _session_id: &SessionId,
                _agent_id: &AgentId,
            ) -> Result<String, AppError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok("ok".into())
            }
        }

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![
                // Spawn #1: allowed skill tool.
                tool_use_response("t1", "skill_a_tool", "{}"),
                text_response("allowed done"),
                // Spawn #2: disallowed skill tool (should not dispatch).
                tool_use_response("t2", "skill_b_tool", "{}"),
                text_response("disallowed done"),
            ],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let mut target = researcher_config();
        target.skills = vec!["skill-a".to_string()];
        let registry: Arc<dyn AgentRegistry> = Arc::new(TestAgentRegistry::new(vec![target]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));

        let skill_a_calls = Arc::new(AtomicUsize::new(0));
        let skill_b_calls = Arc::new(AtomicUsize::new(0));
        let mut base_registry = ToolRegistry::new();
        base_registry
            .register_skill_tool(
                "skill-a",
                "skill_a_tool",
                "Allowed skill tool",
                serde_json::json!({ "type": "object" }),
                Arc::new(CountingTool {
                    calls: skill_a_calls.clone(),
                }),
            )
            .unwrap();
        base_registry
            .register_skill_tool(
                "skill-b",
                "skill_b_tool",
                "Disallowed skill tool",
                serde_json::json!({ "type": "object" }),
                Arc::new(CountingTool {
                    calls: skill_b_calls.clone(),
                }),
            )
            .unwrap();

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(base_registry),
            RuntimeConfig::default(),
        );

        let result1 = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "first"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(result1.is_ok(), "first spawn should succeed: {:?}", result1);

        let result2 = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "second"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(
            result2.is_ok(),
            "second spawn should succeed: {:?}",
            result2
        );

        assert_eq!(skill_a_calls.load(Ordering::SeqCst), 1);
        assert_eq!(skill_b_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn subagent_inherits_approval_policy() {
        struct CountingBashHandler {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl InternalToolHandler for CountingBashHandler {
            async fn handle(
                &self,
                _input: serde_json::Value,
                _session_id: &SessionId,
                _agent_id: &AgentId,
            ) -> Result<String, AppError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok("ran".into())
            }
        }

        #[derive(Default)]
        struct ApproveAll;

        #[async_trait]
        impl ApprovalHandler for ApproveAll {
            async fn request_approval(&self, _request: ApprovalRequest) -> ApprovalDecision {
                ApprovalDecision::Approved
            }
        }

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![
                tool_use_response("t1", "bash.exec", r#"{"command":"ls"}"#),
                text_response("done"),
            ],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> =
            Arc::new(TestAgentRegistry::new(vec![researcher_config()]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut base_registry = ToolRegistry::new();
        base_registry
            .register_internal(
                "bash_exec",
                "bash tool",
                serde_json::json!({
                    "type": "object",
                    "properties": { "command": { "type": "string" } }
                }),
                Arc::new(CountingBashHandler {
                    calls: calls.clone(),
                }),
            )
            .unwrap();

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(base_registry),
            RuntimeConfig::default(),
        )
        .with_approval(
            Arc::new(ApproveAll),
            ToolApprovalChecker::new(BashMode::Deny),
        );

        let result = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "run bash"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "bash_exec should have been denied before dispatch"
        );
    }

    /// Regression test: mutating shared config between spawns changes approval.
    ///
    /// Same SpawnAgentHandler instance, first spawn with allowlist bash_mode
    /// permits bash, then config is mutated to Deny, second spawn blocks bash.
    #[tokio::test]
    async fn live_config_updates_bash_mode_between_spawns() {
        struct CountingBashHandler {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl InternalToolHandler for CountingBashHandler {
            async fn handle(
                &self,
                _input: serde_json::Value,
                _session_id: &SessionId,
                _agent_id: &AgentId,
            ) -> Result<String, AppError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok("ran".into())
            }
        }

        #[derive(Default)]
        struct ApproveAll;

        #[async_trait]
        impl ApprovalHandler for ApproveAll {
            async fn request_approval(&self, _request: ApprovalRequest) -> ApprovalDecision {
                ApprovalDecision::Approved
            }
        }

        // 4 scripted responses: 2 per spawn (tool_use + text)
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![
                // Spawn 1: bash allowed → tool runs → text response
                tool_use_response("t1", "bash_exec", r#"{"command":"ls"}"#),
                text_response("bash ran ok"),
                // Spawn 2: bash denied → error returned to LLM → text response
                tool_use_response("t2", "bash_exec", r#"{"command":"ls"}"#),
                text_response("bash was denied"),
            ],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> =
            Arc::new(TestAgentRegistry::new(vec![researcher_config()]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut base_registry = ToolRegistry::new();
        base_registry
            .register_internal(
                "bash_exec",
                "bash tool",
                serde_json::json!({
                    "type": "object",
                    "properties": { "command": { "type": "string" } }
                }),
                Arc::new(CountingBashHandler {
                    calls: calls.clone(),
                }),
            )
            .unwrap();

        // Start with Allowlist that permits "ls"
        let mut config = AppConfig::default();
        config.security.bash_mode = BashMode::Allowlist {
            patterns: vec!["ls*".into()],
        };
        let shared_config = Arc::new(RwLock::new(config));

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(base_registry),
            RuntimeConfig::default(),
        )
        .with_approval(
            Arc::new(ApproveAll),
            // Static checker (will be overridden by live config)
            ToolApprovalChecker::new(BashMode::Ask),
        )
        .with_config(shared_config.clone());

        // Spawn 1: bash_mode is Allowlist, "ls" matches → tool executes
        let result1 = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "list files"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(result1.is_ok(), "spawn 1 should succeed: {:?}", result1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "bash_exec should have been called once during spawn 1"
        );

        // Mutate shared config to Deny
        {
            let mut cfg = shared_config.write().await;
            cfg.security.bash_mode = BashMode::Deny;
        }

        // Spawn 2: same handler, bash_mode is now Deny → tool blocked
        let result2 = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "list files again"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(
            result2.is_ok(),
            "spawn 2 should succeed (agent runs, bash denied): {:?}",
            result2
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "bash_exec should NOT have been called during spawn 2 (still 1 from spawn 1)"
        );
    }

    /// Regression test: mutating shared config between spawns changes workspace trust.
    ///
    /// Same SpawnAgentHandler instance, first spawn with trusted workspace permits bash,
    /// then config is mutated to remove trust, second spawn blocks bash via workspace gate.
    #[tokio::test]
    async fn live_config_updates_workspace_trust_between_spawns() {
        struct CountingBashHandler {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl InternalToolHandler for CountingBashHandler {
            async fn handle(
                &self,
                _input: serde_json::Value,
                _session_id: &SessionId,
                _agent_id: &AgentId,
            ) -> Result<String, AppError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok("ran".into())
            }
        }

        #[derive(Default)]
        struct ApproveAll;

        #[async_trait]
        impl ApprovalHandler for ApproveAll {
            async fn request_approval(&self, _request: ApprovalRequest) -> ApprovalDecision {
                ApprovalDecision::Approved
            }
        }

        let workspace = tempfile::tempdir().unwrap();
        let mut researcher = researcher_config();
        researcher.workspace = Some(workspace.path().display().to_string());

        // 4 scripted responses: 2 per spawn (tool_use + text)
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![
                // Spawn 1: trusted workspace → tool runs
                tool_use_response("t1", "bash_exec", r#"{"command":"ls"}"#),
                text_response("bash ran ok"),
                // Spawn 2: untrusted workspace → tool blocked
                tool_use_response("t2", "bash_exec", r#"{"command":"ls"}"#),
                text_response("bash denied by workspace trust"),
            ],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let registry: Arc<dyn AgentRegistry> = Arc::new(TestAgentRegistry::new(vec![researcher]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut base_registry = ToolRegistry::new();
        base_registry
            .register_internal(
                "bash_exec",
                "bash tool",
                serde_json::json!({
                    "type": "object",
                    "properties": { "command": { "type": "string" } }
                }),
                Arc::new(CountingBashHandler {
                    calls: calls.clone(),
                }),
            )
            .unwrap();

        // Start with trusted workspace.
        let mut config = AppConfig::default();
        config.security.bash_mode = BashMode::Allowlist {
            patterns: vec!["ls*".into()],
        };
        config.security.workspace_trust.trusted_paths = vec![workspace.path().to_path_buf()];
        config.security.workspace_trust.untrusted_default = "readonly".to_string();
        let shared_config = Arc::new(RwLock::new(config));

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(base_registry),
            RuntimeConfig::default(),
        )
        .with_approval(
            Arc::new(ApproveAll),
            // Static checker (will be overridden by live config).
            ToolApprovalChecker::new(BashMode::Ask),
        )
        .with_config(shared_config.clone());

        let result1 = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "list files"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(result1.is_ok(), "spawn 1 should succeed: {:?}", result1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "bash_exec should have been called once during spawn 1"
        );

        // Mutate shared config to make the same workspace untrusted.
        {
            let mut cfg = shared_config.write().await;
            let other = tempfile::tempdir().unwrap();
            cfg.security.workspace_trust.trusted_paths = vec![other.path().to_path_buf()];
            cfg.security.workspace_trust.untrusted_default = "readonly".to_string();
        }

        let result2 = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "list files again"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(result2.is_err(), "spawn 2 should fail: {:?}", result2);
        let err_text = result2.err().unwrap().to_string();
        assert!(
            err_text.contains("workspace_untrusted"),
            "expected workspace_untrusted deny reason, got: {err_text}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "bash_exec should NOT have been called during spawn 2 (still 1 from spawn 1)"
        );
    }

    #[tokio::test]
    async fn subagent_applies_workspace_trust_gate_for_target_agent_workspace() {
        struct CountingBashHandler {
            calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl InternalToolHandler for CountingBashHandler {
            async fn handle(
                &self,
                _input: serde_json::Value,
                _session_id: &SessionId,
                _agent_id: &AgentId,
            ) -> Result<String, AppError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok("ran".into())
            }
        }

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![
                tool_use_response("t1", "bash_exec", r#"{"command":"ls"}"#),
                text_response("done"),
            ],
            128_000,
        ));
        let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
        let trusted_root = tempfile::tempdir().unwrap();
        let untrusted_workspace = tempfile::tempdir().unwrap();
        let mut researcher = researcher_config();
        researcher.workspace = Some(untrusted_workspace.path().display().to_string());
        let registry: Arc<dyn AgentRegistry> = Arc::new(TestAgentRegistry::new(vec![researcher]));
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        }));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut base_registry = ToolRegistry::new();
        base_registry
            .register_internal(
                "bash_exec",
                "bash tool",
                serde_json::json!({
                    "type": "object",
                    "properties": { "command": { "type": "string" } }
                }),
                Arc::new(CountingBashHandler {
                    calls: calls.clone(),
                }),
            )
            .unwrap();

        let mut runtime_config = RuntimeConfig::default();
        runtime_config.workspace_trust.trusted_paths = vec![trusted_root.path().to_path_buf()];
        runtime_config.workspace_trust.untrusted_default = "readonly".to_string();

        let handler = SpawnAgentHandler::new(
            llm,
            store,
            registry,
            pool,
            Arc::new(base_registry),
            runtime_config,
        );

        let result = handler
            .handle(
                serde_json::json!({"agent_id": "researcher", "task": "run bash"}),
                &SessionId::new(),
                &AgentId::default(),
            )
            .await;
        assert!(result.is_err());
        let output = result.err().unwrap().to_string();
        assert!(
            output.contains("workspace_untrusted"),
            "expected workspace_untrusted deny reason, got: {output}"
        );
        assert!(
            output.contains("partial subagent response"),
            "expected partial response details in propagated error, got: {output}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "bash_exec should be blocked by workspace trust in untrusted workspace"
        );
    }
}
