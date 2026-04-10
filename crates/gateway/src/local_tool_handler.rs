use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::warn;

use encmind_agent::tool_registry::InternalToolHandler;
use encmind_agent::workspace_trust::{evaluate_trust, WorkspaceTrustLevel};
use encmind_core::bash_allowlist;
use encmind_core::config::{AppConfig, BashMode, WorkspaceTrustConfig};
use encmind_core::error::AppError;
use encmind_core::traits::AgentRegistry;
use encmind_core::types::{AgentId, SessionId};
use encmind_edge_lib::commands::{
    execute_command, is_command_permitted, validate_file_path, CommandResult, LocalCommand,
    LocalPolicy,
};

use crate::local_tool_policy::LocalToolPolicyEngine;

/// An `InternalToolHandler` that executes file/bash commands locally on the gateway host,
/// without requiring a paired edge device.
pub struct LocalToolHandler {
    command_type: String,
    policy_engine: Arc<LocalToolPolicyEngine>,
    timeout_secs: u64,
    /// Whether this handler can rely on an interactive approval channel for
    /// `security.bash_mode=ask`. Gateway-host dispatch should set this to
    /// false and fail closed.
    interactive_approval_available: bool,
    agent_registry: Option<Arc<dyn AgentRegistry>>,
    shared_config: Option<Arc<RwLock<AppConfig>>>,
}

struct EffectiveCallPolicy {
    workspace_trust: WorkspaceTrustConfig,
    bash_mode: BashMode,
    allow_bash_exec: bool,
    policy: LocalPolicy,
}

impl LocalToolHandler {
    pub fn new(
        command_type: &str,
        policy_engine: Arc<LocalToolPolicyEngine>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            command_type: command_type.to_string(),
            policy_engine,
            timeout_secs,
            interactive_approval_available: true,
            agent_registry: None,
            shared_config: None,
        }
    }

    pub fn with_interactive_approval_available(mut self, available: bool) -> Self {
        self.interactive_approval_available = available;
        self
    }

    pub fn with_agent_registry(mut self, agent_registry: Arc<dyn AgentRegistry>) -> Self {
        self.agent_registry = Some(agent_registry);
        self
    }

    pub fn with_shared_config(mut self, shared_config: Arc<RwLock<AppConfig>>) -> Self {
        self.shared_config = Some(shared_config);
        self
    }

    /// A command is considered read-only iff it cannot mutate state or
    /// execute processes. Used for workspace-trust gating.
    fn is_read_only(&self) -> bool {
        matches!(self.command_type.as_str(), "file.read" | "file.list")
    }

    /// Verify the workspace trust level permits this command. Trust is
    /// evaluated on the agent's configured workspace (or no workspace).
    /// Returns `AppError::ToolDenied` with the canonical
    /// `workspace_untrusted` reason code when denied, so it aggregates
    /// with governance-level denials in the audit log.
    fn check_workspace_trust(
        &self,
        agent_id: &AgentId,
        workspace: Option<&std::path::Path>,
        workspace_trust: &WorkspaceTrustConfig,
    ) -> Result<(), AppError> {
        let trust_level = evaluate_trust(workspace, workspace_trust);
        let allowed = match trust_level {
            WorkspaceTrustLevel::Trusted | WorkspaceTrustLevel::Disabled => true,
            WorkspaceTrustLevel::ReadOnly => self.is_read_only(),
            WorkspaceTrustLevel::Denied => false,
        };
        if allowed {
            return Ok(());
        }
        warn!(
            command_type = %self.command_type,
            agent = %agent_id,
            ?trust_level,
            "local tool blocked by workspace trust policy"
        );
        Err(AppError::ToolDenied {
            reason: "workspace_untrusted".to_string(),
            message: format!(
                "local '{}' blocked by workspace trust policy ({:?})",
                self.command_type, trust_level
            ),
        })
    }

    async fn resolve_agent_workspace(&self, agent_id: &AgentId) -> Option<std::path::PathBuf> {
        if let Some(registry) = &self.agent_registry {
            match registry.get_agent(agent_id).await {
                Ok(Some(agent)) => {
                    if let Some(workspace) = agent.workspace {
                        if workspace.trim().is_empty() {
                            return None;
                        }
                        let path = std::path::PathBuf::from(workspace);
                        return Some(normalize_workspace_path(&path));
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        agent = %agent_id,
                        error = %err,
                        "failed to resolve agent workspace from live registry; falling back to policy snapshot"
                    );
                }
            }
        }
        self.policy_engine
            .agent_workspace(agent_id)
            .map(std::path::Path::to_path_buf)
    }

    /// Enforce `BashMode::Allowlist` patterns at the dispatch layer.
    /// This is defense in depth: the runtime governance approval
    /// checker also enforces these, but the local tool handler must
    /// not rely on that being configured — direct dispatch must still
    /// be gated when the operator has declared an allowlist.
    fn check_bash_allowlist(
        &self,
        command: &str,
        bash_mode: &BashMode,
        allow_bash_exec: bool,
    ) -> Result<(), AppError> {
        if !allow_bash_exec {
            return Err(AppError::ToolDenied {
                reason: "policy_denied".to_string(),
                message: "bash execution is disabled by local tool policy".to_string(),
            });
        }
        match bash_mode {
            BashMode::Deny => Err(AppError::ToolDenied {
                reason: "policy_denied".to_string(),
                message: "bash execution is disabled by security.bash_mode".to_string(),
            }),
            BashMode::Allowlist { patterns } => {
                if bash_allowlist::matches_any(patterns, command) {
                    return Ok(());
                }
                warn!(
                    command_preview = %command.chars().take(80).collect::<String>(),
                    patterns = ?patterns,
                    "bash command rejected by local allowlist enforcement"
                );
                Err(AppError::ToolDenied {
                    reason: "policy_denied".to_string(),
                    message: "bash command does not match any configured allowlist pattern"
                        .to_string(),
                })
            }
            BashMode::Ask => {
                if self.interactive_approval_available {
                    Ok(())
                } else {
                    Err(AppError::ToolDenied {
                        reason: "policy_denied".to_string(),
                        message:
                            "bash execution requires interactive approval which is not configured"
                                .to_string(),
                    })
                }
            }
        }
    }

    fn parse_command(&self, input: &serde_json::Value) -> Result<LocalCommand, AppError> {
        match self.command_type.as_str() {
            "file.read" => {
                let path = input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::Internal("file_read: missing 'path'".into()))?;
                Ok(LocalCommand::FileRead {
                    path: path.to_string(),
                })
            }
            "file.write" => {
                let path = input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::Internal("file_write: missing 'path'".into()))?;
                let content = input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::Internal("file_write: missing 'content'".into()))?;
                Ok(LocalCommand::FileWrite {
                    path: path.to_string(),
                    content: content.to_string(),
                })
            }
            "file.list" => {
                let path = input
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::Internal("file_list: missing 'path'".into()))?;
                Ok(LocalCommand::FileList {
                    path: path.to_string(),
                })
            }
            "bash.exec" => {
                let command = input
                    .get("command")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::Internal("bash_exec: missing 'command'".into()))?;
                Ok(LocalCommand::BashExec {
                    command: command.to_string(),
                })
            }
            other => Err(AppError::Internal(format!(
                "unknown local command type: {other}"
            ))),
        }
    }

    fn effective_policy(&self, workspace: Option<&std::path::Path>) -> LocalPolicy {
        self.policy_engine.effective_policy_for_workspace(workspace)
    }

    async fn load_effective_call_policy(
        &self,
        workspace: Option<&std::path::Path>,
    ) -> EffectiveCallPolicy {
        if let Some(shared) = &self.shared_config {
            // Evaluate roots/denied paths from the live config to avoid
            // long-lived snapshot drift after runtime config reloads.
            // Uses `derive_call_policy_from_config` — a single-agent
            // projection that skips the per-agent iteration done by
            // LocalToolPolicyEngine::from_config.
            let cfg = { shared.read().await.clone() };
            return EffectiveCallPolicy {
                workspace_trust: cfg.security.workspace_trust.clone(),
                bash_mode: cfg.security.bash_mode.clone(),
                allow_bash_exec: cfg.security.local_bash_effectively_enabled(),
                policy: crate::local_tool_policy::derive_call_policy_from_config(&cfg, workspace),
            };
        }
        EffectiveCallPolicy {
            workspace_trust: self.policy_engine.workspace_trust().clone(),
            bash_mode: self.policy_engine.security_bash_mode().clone(),
            allow_bash_exec: self.policy_engine.bash_effective_enabled(),
            policy: self.effective_policy(workspace),
        }
    }
}

fn normalize_workspace_path(path: &std::path::Path) -> std::path::PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    absolute.canonicalize().unwrap_or(absolute)
}

fn command_path(cmd: &LocalCommand) -> Option<&str> {
    match cmd {
        LocalCommand::FileRead { path }
        | LocalCommand::FileWrite { path, .. }
        | LocalCommand::FileList { path } => Some(path.as_str()),
        LocalCommand::BashExec { .. } => None,
    }
}

#[async_trait]
impl InternalToolHandler for LocalToolHandler {
    fn is_concurrent_safe(&self) -> bool {
        // Read-only local commands are safe for parallel execution.
        matches!(self.command_type.as_str(), "file.read" | "file.list")
    }

    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let cmd = self.parse_command(&input)?;
        let workspace = self.resolve_agent_workspace(agent_id).await;
        let call_policy = self.load_effective_call_policy(workspace.as_deref()).await;

        // Workspace-trust gate — evaluated on the agent's configured
        // workspace. Denied/ReadOnly untrusted paths block mutating
        // commands before any path check runs. This is independent of
        // the agent runtime's trust filter and guards any path that
        // bypasses the runtime governance layer.
        self.check_workspace_trust(agent_id, workspace.as_deref(), &call_policy.workspace_trust)?;

        // BashMode::Allowlist enforcement at the dispatch layer —
        // defense in depth vs. the governance approval checker.
        if let LocalCommand::BashExec { command } = &cmd {
            self.check_bash_allowlist(
                command,
                &call_policy.bash_mode,
                call_policy.allow_bash_exec,
            )?;
        }

        let policy = call_policy.policy;

        if !is_command_permitted(&cmd, &policy) {
            return Err(AppError::ToolDenied {
                reason: "policy_denied".to_string(),
                message: format!("local '{}' denied by policy", self.command_type),
            });
        }

        if let Some(path) = command_path(&cmd) {
            if let Err(message) = validate_file_path(path, &policy) {
                return Err(AppError::ToolDenied {
                    reason: "policy_denied".to_string(),
                    message,
                });
            }
        }

        let timeout = tokio::time::Duration::from_secs(self.timeout_secs);
        match tokio::time::timeout(timeout, execute_command(&cmd, &policy)).await {
            Ok(result) => {
                let CommandResult { success, output } = result;
                if success {
                    Ok(output)
                } else {
                    if command_path(&cmd).is_some() && output.starts_with("access denied:") {
                        return Err(AppError::ToolDenied {
                            reason: "policy_denied".to_string(),
                            message: output,
                        });
                    }
                    Err(AppError::Internal(output))
                }
            }
            Err(_elapsed) => Err(AppError::Internal(format!(
                "{}: timed out after {}s",
                self.command_type, self.timeout_secs
            ))),
        }
    }
}

/// Register all four local tool handlers on the given tool registry.
///
/// `name_prefix` is prepended to each tool name (e.g. `local_`), allowing
/// callers to avoid collisions with other tool surfaces while reusing the same
/// command handlers and schemas.
pub fn register_local_tools_with_prefix_and_registry(
    registry: &mut encmind_agent::tool_registry::ToolRegistry,
    policy_engine: Arc<LocalToolPolicyEngine>,
    agent_registry: Option<Arc<dyn AgentRegistry>>,
    shared_config: Option<Arc<RwLock<AppConfig>>>,
    timeout_secs: u64,
    name_prefix: &str,
) -> Result<(), AppError> {
    let mut tools: Vec<(&str, &str, &str, serde_json::Value)> = vec![
        (
            "file_read",
            "file.read",
            "Read a file from the local filesystem",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path to the file" }
                },
                "required": ["path"]
            }),
        ),
        (
            "file_write",
            "file.write",
            "Write content to a file on the local filesystem",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path to write to" },
                    "content": { "type": "string", "description": "Content to write" }
                },
                "required": ["path", "content"]
            }),
        ),
        (
            "file_list",
            "file.list",
            "List files in a directory on the local filesystem",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path to the directory" }
                },
                "required": ["path"]
            }),
        ),
    ];

    tools.push((
        "bash_exec",
        "bash.exec",
        "Execute a bash command on the local system",
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "Shell command to execute" }
            },
            "required": ["command"]
        }),
    ));

    for (tool_name, cmd_type, description, params) in tools {
        let qualified_name = format!("{name_prefix}{tool_name}");
        let mut handler = LocalToolHandler::new(cmd_type, policy_engine.clone(), timeout_secs)
            .with_interactive_approval_available(false);
        if let Some(registry) = agent_registry.clone() {
            handler = handler.with_agent_registry(registry);
        }
        if let Some(config) = shared_config.clone() {
            handler = handler.with_shared_config(config);
        }
        let handler = Arc::new(handler);
        registry.register_internal(&qualified_name, description, params.clone(), handler)?;
    }

    Ok(())
}

pub fn register_local_tools_with_prefix(
    registry: &mut encmind_agent::tool_registry::ToolRegistry,
    policy_engine: Arc<LocalToolPolicyEngine>,
    timeout_secs: u64,
    name_prefix: &str,
) -> Result<(), AppError> {
    register_local_tools_with_prefix_and_registry(
        registry,
        policy_engine,
        None,
        None,
        timeout_secs,
        name_prefix,
    )
}

/// Register local tools using canonical names (`file_read`, `bash_exec`, ...).
pub fn register_local_tools(
    registry: &mut encmind_agent::tool_registry::ToolRegistry,
    policy_engine: Arc<LocalToolPolicyEngine>,
    timeout_secs: u64,
) -> Result<(), AppError> {
    register_local_tools_with_prefix_and_registry(
        registry,
        policy_engine,
        None,
        None,
        timeout_secs,
        "",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use encmind_agent::tool_registry::ToolRegistry;
    use encmind_core::config::{
        AgentConfigEntry, AppConfig, LocalToolsBashMode, SubagentRuntimeConfig,
    };
    use encmind_core::error::StorageError;
    use encmind_core::traits::AgentRegistry;
    use encmind_core::types::AgentConfig;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    fn engine_from_config(config: &AppConfig) -> Arc<LocalToolPolicyEngine> {
        Arc::new(LocalToolPolicyEngine::from_config(config))
    }

    fn default_engine() -> Arc<LocalToolPolicyEngine> {
        engine_from_config(&AppConfig::default())
    }

    #[derive(Default)]
    struct MockAgentRegistry {
        agents: RwLock<HashMap<String, AgentConfig>>,
    }

    impl MockAgentRegistry {
        async fn put_workspace(&self, agent_id: &str, workspace: Option<String>) {
            let mut agents = self.agents.write().await;
            agents.insert(
                agent_id.to_string(),
                AgentConfig {
                    id: AgentId::new(agent_id),
                    name: agent_id.to_string(),
                    model: None,
                    workspace,
                    system_prompt: None,
                    skills: Vec::new(),
                    is_default: false,
                },
            );
        }
    }

    #[async_trait]
    impl AgentRegistry for MockAgentRegistry {
        async fn list_agents(&self) -> Result<Vec<AgentConfig>, StorageError> {
            Ok(self.agents.read().await.values().cloned().collect())
        }

        async fn get_agent(&self, id: &AgentId) -> Result<Option<AgentConfig>, StorageError> {
            Ok(self.agents.read().await.get(id.as_str()).cloned())
        }

        async fn resolve_agent(&self, _session_id: &SessionId) -> Result<AgentId, StorageError> {
            Ok(AgentId::default())
        }

        async fn create_agent(&self, config: AgentConfig) -> Result<(), StorageError> {
            self.agents
                .write()
                .await
                .insert(config.id.as_str().to_string(), config);
            Ok(())
        }

        async fn update_agent(
            &self,
            id: &AgentId,
            config: AgentConfig,
        ) -> Result<(), StorageError> {
            self.agents
                .write()
                .await
                .insert(id.as_str().to_string(), config);
            Ok(())
        }

        async fn delete_agent(&self, id: &AgentId) -> Result<(), StorageError> {
            self.agents.write().await.remove(id.as_str());
            Ok(())
        }
    }

    #[tokio::test]
    async fn local_file_read_success() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let handler = LocalToolHandler::new("file.read", default_engine(), 60);
        let input = serde_json::json!({"path": file_path.to_str().unwrap()});
        let result = handler
            .handle(input, &SessionId("s1".into()), &AgentId("a1".into()))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn local_file_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("output.txt");

        let handler = LocalToolHandler::new("file.write", default_engine(), 60);
        let input = serde_json::json!({
            "path": file_path.to_str().unwrap(),
            "content": "written"
        });
        let result = handler
            .handle(input, &SessionId("s1".into()), &AgentId("a1".into()))
            .await;
        assert!(result.is_ok());
        assert_eq!(std::fs::read_to_string(&file_path).unwrap(), "written");
    }

    #[tokio::test]
    async fn local_file_list_returns_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();
        std::fs::write(dir.path().join("a.txt"), "").unwrap();

        let handler = LocalToolHandler::new("file.list", default_engine(), 60);
        let input = serde_json::json!({"path": dir.path().to_str().unwrap()});
        let result = handler
            .handle(input, &SessionId("s1".into()), &AgentId("a1".into()))
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines.windows(2).all(|w| w[0] <= w[1]));
    }

    #[tokio::test]
    async fn local_bash_exec_echo() {
        let handler = LocalToolHandler::new("bash.exec", default_engine(), 60);
        let input = serde_json::json!({"command": "echo hello"});
        let result = handler
            .handle(input, &SessionId("s1".into()), &AgentId("a1".into()))
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("hello"));
    }

    #[tokio::test]
    async fn local_bash_denied_by_policy() {
        let mut config = AppConfig::default();
        config.security.local_tools.bash_mode = LocalToolsBashMode::Disabled;
        let handler = LocalToolHandler::new("bash.exec", engine_from_config(&config), 60);
        let input = serde_json::json!({"command": "echo hello"});
        let result = handler
            .handle(input, &SessionId("s1".into()), &AgentId("a1".into()))
            .await;
        let err = result.expect_err("bash should be denied by policy");
        match err {
            AppError::ToolDenied { reason, message } => {
                assert_eq!(reason, "policy_denied");
                assert!(
                    message.contains("disabled"),
                    "expected disabled-by-policy message, got: {message}"
                );
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }
    }

    #[tokio::test]
    async fn local_tool_timeout() {
        let handler = LocalToolHandler::new("bash.exec", default_engine(), 1);
        let input = serde_json::json!({"command": "sleep 10"});
        let result = handler
            .handle(input, &SessionId("s1".into()), &AgentId("a1".into()))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn register_base_tools_always_registers_local_tools() {
        let mut registry = ToolRegistry::new();
        register_local_tools(&mut registry, default_engine(), 60).unwrap();
        assert!(registry.has_tool("file_read"));
        assert!(registry.has_tool("file_write"));
        assert!(registry.has_tool("file_list"));
        assert!(registry.has_tool("bash_exec"));
        assert_eq!(registry.tool_count(), 4);
    }

    #[test]
    fn register_local_tools_with_prefix_namespaces_tools() {
        let mut registry = ToolRegistry::new();
        register_local_tools_with_prefix(&mut registry, default_engine(), 60, "local_").unwrap();
        assert!(registry.has_tool("local_file_read"));
        assert!(registry.has_tool("local_file_write"));
        assert!(registry.has_tool("local_file_list"));
        assert!(registry.has_tool("local_bash_exec"));
        assert!(!registry.has_tool("file_read"));
    }

    #[test]
    fn register_local_tools_keeps_bash_registered_when_disabled() {
        let mut config = AppConfig::default();
        config.security.local_tools.bash_mode = LocalToolsBashMode::Disabled;
        let mut registry = ToolRegistry::new();
        register_local_tools(&mut registry, engine_from_config(&config), 60).unwrap();
        assert!(registry.has_tool("file_read"));
        assert!(registry.has_tool("file_write"));
        assert!(registry.has_tool("file_list"));
        assert!(registry.has_tool("bash_exec"));
    }

    #[tokio::test]
    async fn local_tools_work_without_paired_device() {
        // `register_local_tools` constructs handlers with
        // `interactive_approval_available = false` (the gateway has
        // no interactive approval UX), so `BashMode::Ask` would be
        // categorically denied. Configure an allowlist that matches
        // the echo command so bash dispatch reaches the runtime —
        // this is the canonical "operator allows a narrow set of
        // commands" setup.
        let mut config = AppConfig::default();
        config.security.bash_mode = encmind_core::config::BashMode::Allowlist {
            patterns: vec!["echo*".to_string()],
        };
        let mut registry = ToolRegistry::new();
        register_local_tools(&mut registry, engine_from_config(&config), 60).unwrap();

        let result = registry
            .dispatch(
                "bash_exec",
                serde_json::json!({"command": "echo local"}),
                &SessionId("test".into()),
                &AgentId("test".into()),
            )
            .await;
        assert!(result.is_ok(), "dispatch failed: {result:?}");
        let output = result.unwrap();
        assert!(output.contains("local"), "unexpected output: {output}");
    }

    #[tokio::test]
    async fn bash_allowlist_enforces_patterns_at_local_handler() {
        let mut config = AppConfig::default();
        config.security.bash_mode = encmind_core::config::BashMode::Allowlist {
            patterns: vec!["echo*".to_string(), "ls".to_string()],
        };
        let engine = engine_from_config(&config);

        // Matching prefix-glob pattern: allowed.
        let allowed = LocalToolHandler::new("bash.exec", engine.clone(), 60);
        let ok = allowed
            .handle(
                serde_json::json!({"command": "echo allowlisted"}),
                &SessionId("s1".into()),
                &AgentId("a1".into()),
            )
            .await;
        assert!(ok.is_ok(), "echo* pattern should allow 'echo allowlisted'");
        assert!(ok.unwrap().contains("allowlisted"));

        // Exact pattern match: allowed.
        let exact = allowed
            .handle(
                serde_json::json!({"command": "ls"}),
                &SessionId("s1".into()),
                &AgentId("a1".into()),
            )
            .await;
        assert!(exact.is_ok(), "exact 'ls' pattern should allow");

        // Pattern mismatch: denied with ToolDenied provenance.
        let denied = allowed
            .handle(
                serde_json::json!({"command": "rm -rf /tmp/foo"}),
                &SessionId("s1".into()),
                &AgentId("a1".into()),
            )
            .await
            .expect_err("rm should be denied by allowlist");
        let err = denied.to_string();
        assert!(
            err.contains("does not match any configured allowlist pattern"),
            "expected allowlist denial message, got: {err}"
        );
    }

    #[tokio::test]
    async fn ask_mode_requires_interactive_approval_when_unavailable() {
        let mut config = AppConfig::default();
        config.security.bash_mode = encmind_core::config::BashMode::Ask;
        let engine = engine_from_config(&config);

        let handler = LocalToolHandler::new("bash.exec", engine, 60)
            .with_interactive_approval_available(false);

        let denied = handler
            .handle(
                serde_json::json!({"command": "echo blocked"}),
                &SessionId("s1".into()),
                &AgentId("a1".into()),
            )
            .await
            .expect_err("non-interactive ask mode should fail closed");
        match denied {
            AppError::ToolDenied { reason, message } => {
                assert_eq!(reason, "policy_denied");
                assert!(message.contains("interactive approval"));
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }
    }

    #[test]
    fn bash_allowlist_prefix_wildcard_respects_command_boundary() {
        assert!(bash_allowlist::matches_any(&["ls*".to_string()], "ls -la"));
        assert!(
            !bash_allowlist::matches_any(&["ls*".to_string()], "lsblk"),
            "ls* should not match lsblk"
        );
        // Pattern with trailing space in the prefix: the boundary is
        // already satisfied by starts_with, so the next char doesn't
        // need to be whitespace again.
        assert!(
            bash_allowlist::matches_any(&["ls *".to_string()], "ls -la /tmp"),
            "`ls *` should match `ls -la /tmp`"
        );
        assert!(
            !bash_allowlist::matches_any(&["ls *".to_string()], "lsof -i"),
            "`ls *` should not match `lsof -i`"
        );
        assert!(
            !bash_allowlist::matches_any(&["ls *".to_string()], "ls"),
            "`ls *` should not match bare `ls` (starts_with requires the trailing space)"
        );
        assert!(
            !bash_allowlist::matches_any(&["ls *".to_string()], "ls -la; whoami"),
            "`ls *` should not match chained commands"
        );
        assert!(
            !bash_allowlist::matches_any(&["ls *".to_string()], "ls -la\nwhoami"),
            "`ls *` should not match multiline commands"
        );
    }

    #[tokio::test]
    async fn workspace_trust_readonly_blocks_local_bash_exec() {
        let tmp = tempfile::tempdir().unwrap();
        let trusted_root = tmp.path().join("trusted");
        std::fs::create_dir_all(&trusted_root).unwrap();
        let untrusted_workspace = tmp.path().join("untrusted");
        std::fs::create_dir_all(&untrusted_workspace).unwrap();

        let mut config = AppConfig::default();
        config.security.workspace_trust.trusted_paths = vec![trusted_root];
        config.security.workspace_trust.untrusted_default = "readonly".to_string();
        config.agents.list = vec![AgentConfigEntry {
            id: "untrusted".into(),
            name: "U".into(),
            model: None,
            workspace: Some(untrusted_workspace),
            system_prompt: None,
            skills: Vec::new(),
            subagents: SubagentRuntimeConfig::default(),
            is_default: false,
        }];

        let engine = engine_from_config(&config);

        // bash.exec must be blocked by the workspace trust readonly gate.
        let bash_handler = LocalToolHandler::new("bash.exec", engine.clone(), 60);
        let denied = bash_handler
            .handle(
                serde_json::json!({"command": "echo hi"}),
                &SessionId("s1".into()),
                &AgentId("untrusted".into()),
            )
            .await
            .expect_err("bash should be blocked in readonly workspace");
        assert!(
            denied.to_string().contains("workspace trust policy"),
            "expected trust-policy denial, got: {denied}"
        );

        // file.read must still be allowed (read-only operation).
        let read_handler = LocalToolHandler::new("file.read", engine.clone(), 60);
        let read_err = read_handler
            .handle(
                // Path that doesn't exist — ensures we pass the trust
                // gate and hit the path layer, not the trust layer.
                serde_json::json!({"path": "/nonexistent/path.txt"}),
                &SessionId("s1".into()),
                &AgentId("untrusted".into()),
            )
            .await
            .expect_err("read should fail but not on trust grounds");
        assert!(
            !read_err.to_string().contains("workspace trust policy"),
            "read should bypass trust gate in readonly mode, got: {read_err}"
        );
    }

    #[tokio::test]
    async fn workspace_trust_deny_blocks_all_local_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let trusted_root = tmp.path().join("trusted");
        std::fs::create_dir_all(&trusted_root).unwrap();
        let untrusted_workspace = tmp.path().join("untrusted");
        std::fs::create_dir_all(&untrusted_workspace).unwrap();

        let mut config = AppConfig::default();
        config.security.workspace_trust.trusted_paths = vec![trusted_root];
        config.security.workspace_trust.untrusted_default = "deny".to_string();
        config.agents.list = vec![AgentConfigEntry {
            id: "untrusted".into(),
            name: "U".into(),
            model: None,
            workspace: Some(untrusted_workspace),
            system_prompt: None,
            skills: Vec::new(),
            subagents: SubagentRuntimeConfig::default(),
            is_default: false,
        }];

        let engine = engine_from_config(&config);

        for command_type in ["file.read", "file.list", "file.write", "bash.exec"] {
            let handler = LocalToolHandler::new(command_type, engine.clone(), 60);
            let input = match command_type {
                "bash.exec" => serde_json::json!({"command": "echo x"}),
                "file.write" => serde_json::json!({"path": "/tmp/z.txt", "content": "y"}),
                _ => serde_json::json!({"path": "/tmp"}),
            };
            let err = handler
                .handle(input, &SessionId("s1".into()), &AgentId("untrusted".into()))
                .await
                .expect_err(&format!("{command_type} should be blocked in deny mode"));
            assert!(
                err.to_string().contains("workspace trust policy"),
                "{command_type}: expected trust-policy denial, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn operator_denied_paths_layer_on_top_of_defaults() {
        // Put a custom deny entry under tempdir and verify it's blocked.
        let tmp = tempfile::tempdir().unwrap();
        let forbidden_dir = tmp.path().join("forbidden");
        std::fs::create_dir_all(&forbidden_dir).unwrap();
        let forbidden_file = forbidden_dir.join("secret.txt");
        std::fs::write(&forbidden_file, "topsecret").unwrap();

        let mut config = AppConfig::default();
        config.security.local_tools.denied_paths = vec![forbidden_dir.clone()];
        // Also add the tempdir as an allowed base root so the path is
        // otherwise reachable.
        config.security.local_tools.base_roots = vec![tmp.path().to_path_buf()];

        let engine = engine_from_config(&config);
        let handler = LocalToolHandler::new("file.read", engine.clone(), 60);

        let err = handler
            .handle(
                serde_json::json!({"path": forbidden_file.to_str().unwrap()}),
                &SessionId("s1".into()),
                &AgentId("any".into()),
            )
            .await
            .expect_err("operator-denied path must be rejected");
        match err {
            AppError::ToolDenied { reason, message } => {
                assert_eq!(reason, "policy_denied");
                assert!(
                    message.contains("restricted location") || message.contains("access denied"),
                    "expected operator-deny rejection, got: {message}"
                );
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }

        // Sanity: reading another file under the same tempdir that
        // isn't in denied_paths should succeed.
        let ok_file = tmp.path().join("ok.txt");
        std::fs::write(&ok_file, "fine").unwrap();
        let ok = handler
            .handle(
                serde_json::json!({"path": ok_file.to_str().unwrap()}),
                &SessionId("s1".into()),
                &AgentId("any".into()),
            )
            .await;
        assert!(ok.is_ok(), "non-denied file should read: {ok:?}");
    }

    #[tokio::test]
    async fn local_file_access_is_scoped_to_current_agent_workspace() {
        let workspace_a = std::path::PathBuf::from("/opt/encmind-workspace-a");
        let workspace_b = std::path::PathBuf::from("/opt/encmind-workspace-b");
        let file_a = workspace_a.join("a.txt");

        let mut config = AppConfig::default();
        // Keep default roots (cwd/db/tmp). /opt is outside those defaults.
        config.agents.list = vec![
            AgentConfigEntry {
                id: "agent-a".into(),
                name: "Agent A".into(),
                model: None,
                workspace: Some(workspace_a.clone()),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
            AgentConfigEntry {
                id: "agent-b".into(),
                name: "Agent B".into(),
                model: None,
                workspace: Some(workspace_b.clone()),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];
        let handler = LocalToolHandler::new("file.read", engine_from_config(&config), 60);

        let input = serde_json::json!({"path": file_a.to_str().unwrap()});
        let allowed_err = handler
            .handle(
                input.clone(),
                &SessionId("s1".into()),
                &AgentId("agent-a".into()),
            )
            .await
            .expect_err("agent-a read should fail because file does not exist");
        assert!(
            !allowed_err.to_string().contains("outside allowed roots"),
            "agent-a should be allowed by root policy; expected non-policy file error"
        );

        let denied = handler
            .handle(input, &SessionId("s2".into()), &AgentId("agent-b".into()))
            .await
            .expect_err("agent-b should not read agent-a workspace");
        assert!(denied.to_string().contains("outside allowed roots"));
    }

    #[tokio::test]
    async fn workspace_trust_uses_live_registry_workspace_when_available() {
        let tmp = tempfile::tempdir().unwrap();
        let trusted_root = tmp.path().join("trusted");
        let untrusted_root = tmp.path().join("untrusted");
        std::fs::create_dir_all(&trusted_root).unwrap();
        std::fs::create_dir_all(&untrusted_root).unwrap();

        let mut config = AppConfig::default();
        // Snapshot has no agent workspace, so fallback would deny.
        config.security.workspace_trust.trusted_paths = vec![trusted_root.clone()];
        config.security.workspace_trust.untrusted_default = "deny".to_string();
        config.security.workspace_trust.no_workspace_default = "deny".to_string();
        let engine = engine_from_config(&config);

        let registry = Arc::new(MockAgentRegistry::default());
        registry
            .put_workspace(
                "agent-live",
                Some(trusted_root.as_os_str().to_string_lossy().into_owned()),
            )
            .await;

        let handler = LocalToolHandler::new("bash.exec", engine.clone(), 60)
            .with_agent_registry(registry.clone());
        let ok = handler
            .handle(
                serde_json::json!({"command": "echo from-live-registry"}),
                &SessionId("s1".into()),
                &AgentId("agent-live".into()),
            )
            .await;
        assert!(
            ok.is_ok(),
            "trusted workspace from live registry should allow: {ok:?}"
        );

        // Update workspace in the live registry; trust checks should reflect
        // the change without rebuilding the policy engine.
        registry
            .put_workspace(
                "agent-live",
                Some(untrusted_root.as_os_str().to_string_lossy().into_owned()),
            )
            .await;
        let denied = handler
            .handle(
                serde_json::json!({"command": "echo should-block"}),
                &SessionId("s2".into()),
                &AgentId("agent-live".into()),
            )
            .await
            .expect_err("updated untrusted workspace should be denied");
        match denied {
            AppError::ToolDenied { reason, .. } => {
                assert_eq!(reason, "workspace_untrusted");
            }
            other => panic!("expected workspace ToolDenied, got: {other}"),
        }
    }

    #[tokio::test]
    async fn workspace_trust_uses_live_shared_config_when_available() {
        let tmp = tempfile::tempdir().unwrap();
        let trusted_root = tmp.path().join("trusted");
        let untrusted_root = tmp.path().join("untrusted");
        std::fs::create_dir_all(&trusted_root).unwrap();
        std::fs::create_dir_all(&untrusted_root).unwrap();

        let mut config = AppConfig::default();
        config.security.workspace_trust.trusted_paths = vec![trusted_root.clone()];
        config.security.workspace_trust.untrusted_default = "deny".to_string();
        let shared_config = Arc::new(RwLock::new(config.clone()));
        let engine = engine_from_config(&config);

        let registry = Arc::new(MockAgentRegistry::default());
        registry
            .put_workspace(
                "agent-live",
                Some(untrusted_root.as_os_str().to_string_lossy().into_owned()),
            )
            .await;

        let handler = LocalToolHandler::new("bash.exec", engine, 60)
            .with_agent_registry(registry.clone())
            .with_shared_config(shared_config.clone());

        let denied = handler
            .handle(
                serde_json::json!({"command": "echo should-block"}),
                &SessionId("s1".into()),
                &AgentId("agent-live".into()),
            )
            .await
            .expect_err("untrusted workspace should be denied");
        match denied {
            AppError::ToolDenied { reason, .. } => {
                assert_eq!(reason, "workspace_untrusted");
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }

        // Update trust config in shared state without rebuilding handler.
        {
            let mut cfg = shared_config.write().await;
            cfg.security
                .workspace_trust
                .trusted_paths
                .push(untrusted_root);
        }

        let ok = handler
            .handle(
                serde_json::json!({"command": "echo now-trusted"}),
                &SessionId("s2".into()),
                &AgentId("agent-live".into()),
            )
            .await;
        assert!(
            ok.is_ok(),
            "updated shared trust config should be honored: {ok:?}"
        );
    }

    #[tokio::test]
    async fn bash_allowlist_uses_live_shared_config_when_available() {
        let mut config = AppConfig::default();
        config.security.bash_mode = encmind_core::config::BashMode::Ask;
        let shared_config = Arc::new(RwLock::new(config.clone()));
        let engine = engine_from_config(&config);

        let handler = LocalToolHandler::new("bash.exec", engine, 60)
            .with_shared_config(shared_config.clone());

        let initial = handler
            .handle(
                serde_json::json!({"command": "printf initial"}),
                &SessionId("s1".into()),
                &AgentId("a1".into()),
            )
            .await;
        assert!(initial.is_ok(), "ask mode should allow bash");

        {
            let mut cfg = shared_config.write().await;
            cfg.security.bash_mode = encmind_core::config::BashMode::Allowlist {
                patterns: vec!["echo*".to_string()],
            };
        }

        let denied = handler
            .handle(
                serde_json::json!({"command": "printf blocked"}),
                &SessionId("s2".into()),
                &AgentId("a1".into()),
            )
            .await
            .expect_err("allowlist should block non-matching command");
        match denied {
            AppError::ToolDenied { reason, message } => {
                assert_eq!(reason, "policy_denied");
                assert!(message.contains("allowlist pattern"));
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }

        let allowed = handler
            .handle(
                serde_json::json!({"command": "echo allowlisted"}),
                &SessionId("s3".into()),
                &AgentId("a1".into()),
            )
            .await;
        assert!(allowed.is_ok(), "allowlisted command should pass");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_policy_uses_live_base_roots_and_denied_paths_from_shared_config() {
        let allowed_root = std::path::PathBuf::from("/etc");
        let file_path = allowed_root.join("hosts");

        let mut config = AppConfig::default();
        // Start with no explicit local roots for /etc.
        config.security.local_tools.base_roots = Vec::new();
        config.security.local_tools.denied_paths = Vec::new();
        let shared_config = Arc::new(RwLock::new(config.clone()));
        let engine = engine_from_config(&config);

        let handler = LocalToolHandler::new("file.read", engine, 60)
            .with_shared_config(shared_config.clone());

        let denied = handler
            .handle(
                serde_json::json!({"path": file_path.to_string_lossy()}),
                &SessionId("s1".into()),
                &AgentId("a1".into()),
            )
            .await
            .expect_err("path outside roots should be denied");
        match denied {
            AppError::ToolDenied { reason, message } => {
                assert_eq!(reason, "policy_denied");
                assert!(message.contains("outside allowed roots"));
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }

        {
            let mut cfg = shared_config.write().await;
            cfg.security.local_tools.base_roots = vec![allowed_root.clone()];
        }

        let ok = handler
            .handle(
                serde_json::json!({"path": file_path.to_string_lossy()}),
                &SessionId("s2".into()),
                &AgentId("a1".into()),
            )
            .await;
        assert!(
            ok.is_ok(),
            "live base_roots update should allow read: {ok:?}"
        );

        {
            let mut cfg = shared_config.write().await;
            cfg.security.local_tools.denied_paths = vec![allowed_root];
        }

        let denied_again = handler
            .handle(
                serde_json::json!({"path": file_path.to_string_lossy()}),
                &SessionId("s3".into()),
                &AgentId("a1".into()),
            )
            .await
            .expect_err("live denied_paths update should block read");
        match denied_again {
            AppError::ToolDenied { reason, message } => {
                assert_eq!(reason, "policy_denied");
                assert!(message.contains("restricted location"));
            }
            other => panic!("expected ToolDenied, got: {other}"),
        }
    }
}
