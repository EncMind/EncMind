use std::sync::Arc;

use async_trait::async_trait;

use encmind_agent::tool_registry::InternalToolHandler;
use encmind_core::error::AppError;
use encmind_core::types::{AgentId, SessionId};
use encmind_edge_lib::commands::{
    execute_command, is_command_permitted, CommandResult, LocalCommand,
};

use crate::local_tool_policy::LocalToolPolicyEngine;

/// An `InternalToolHandler` that executes file/bash commands locally on the gateway host,
/// without requiring a paired edge device.
pub struct LocalToolHandler {
    command_type: String,
    policy_engine: Arc<LocalToolPolicyEngine>,
    timeout_secs: u64,
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

    fn effective_policy(&self, agent_id: &AgentId) -> encmind_edge_lib::commands::LocalPolicy {
        self.policy_engine.effective_policy(agent_id)
    }
}

#[async_trait]
impl InternalToolHandler for LocalToolHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let cmd = self.parse_command(&input)?;
        let policy = self.effective_policy(agent_id);

        if !is_command_permitted(&cmd, &policy) {
            return Err(AppError::Internal(format!(
                "{}: denied by policy",
                self.command_type
            )));
        }

        let timeout = tokio::time::Duration::from_secs(self.timeout_secs);
        match tokio::time::timeout(timeout, execute_command(&cmd, &policy)).await {
            Ok(result) => {
                let CommandResult { success, output } = result;
                if success {
                    Ok(output)
                } else {
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
pub fn register_local_tools_with_prefix(
    registry: &mut encmind_agent::tool_registry::ToolRegistry,
    policy_engine: Arc<LocalToolPolicyEngine>,
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

    if policy_engine.bash_effective_enabled() {
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
    }

    for (tool_name, cmd_type, description, params) in tools {
        let qualified_name = format!("{name_prefix}{tool_name}");
        let handler = Arc::new(LocalToolHandler::new(
            cmd_type,
            policy_engine.clone(),
            timeout_secs,
        ));
        registry.register_internal(&qualified_name, description, params.clone(), handler)?;
    }

    Ok(())
}

/// Register local tools using canonical names (`file_read`, `bash_exec`, ...).
pub fn register_local_tools(
    registry: &mut encmind_agent::tool_registry::ToolRegistry,
    policy_engine: Arc<LocalToolPolicyEngine>,
    timeout_secs: u64,
) -> Result<(), AppError> {
    register_local_tools_with_prefix(registry, policy_engine, timeout_secs, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_agent::tool_registry::ToolRegistry;
    use encmind_core::config::{
        AgentConfigEntry, AppConfig, LocalToolsBashMode, SubagentRuntimeConfig,
    };

    fn engine_from_config(config: &AppConfig) -> Arc<LocalToolPolicyEngine> {
        Arc::new(LocalToolPolicyEngine::from_config(config))
    }

    fn default_engine() -> Arc<LocalToolPolicyEngine> {
        engine_from_config(&AppConfig::default())
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
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("denied by policy"));
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
    fn register_local_tools_omits_bash_when_disabled() {
        let mut config = AppConfig::default();
        config.security.local_tools.bash_mode = LocalToolsBashMode::Disabled;
        let mut registry = ToolRegistry::new();
        register_local_tools(&mut registry, engine_from_config(&config), 60).unwrap();
        assert!(registry.has_tool("file_read"));
        assert!(registry.has_tool("file_write"));
        assert!(registry.has_tool("file_list"));
        assert!(!registry.has_tool("bash_exec"));
    }

    #[tokio::test]
    async fn local_tools_work_without_paired_device() {
        let mut registry = ToolRegistry::new();
        register_local_tools(&mut registry, default_engine(), 60).unwrap();

        let result = registry
            .dispatch(
                "bash_exec",
                serde_json::json!({"command": "echo local"}),
                &SessionId("test".into()),
                &AgentId("test".into()),
            )
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("local"));
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
}
