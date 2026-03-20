use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use encmind_core::error::{AppError, McpError};
use encmind_core::traits::{McpClient, Skill, ToolDefinition};
use encmind_core::types::{AgentId, SessionId};
use sha2::{Digest, Sha256};

// Re-export from core for backward compatibility.
pub use encmind_core::traits::InternalToolHandler;

/// Where a tool comes from — a local WASM skill, a remote MCP server, or an internal handler.
#[derive(Clone)]
pub enum ToolSource {
    Skill(Arc<dyn Skill>),
    Mcp {
        client: Arc<dyn McpClient>,
        server_name: String,
    },
    Internal(Arc<dyn InternalToolHandler>),
}

#[derive(Clone)]
struct RegisteredTool {
    source: ToolSource,
    definition: ToolDefinition,
    /// Set for WASM skill tools; `None` for built-in internal / MCP tools.
    skill_id: Option<String>,
    /// Original tool name on the remote server (MCP tools only).
    /// Used for dispatch: we call the server with this name, not the namespaced key.
    remote_tool_name: Option<String>,
}

/// Validate a tool or alias name.
///
/// Rules:
/// - Must be 1–128 characters
/// - Must match `^[a-zA-Z0-9_-]+$` (OpenAI function-calling compatible)
pub fn validate_tool_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::Internal(
            "tool name must not be empty".to_string(),
        ));
    }
    if name.len() > 128 {
        return Err(AppError::Internal(format!(
            "tool name exceeds 128 characters: '{}'",
            &name[..32]
        )));
    }
    if !name
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'))
    {
        return Err(AppError::Internal(format!(
            "tool name must match ^[a-zA-Z0-9_-]+$: '{name}'"
        )));
    }
    Ok(())
}

/// Validate an alias name.
///
/// Alias names are not sent to LLM providers, so they may include dots for
/// backward-compatible local dispatch paths.
fn validate_alias_name(alias: &str) -> Result<(), AppError> {
    if alias.is_empty() {
        return Err(AppError::Internal(
            "alias name must not be empty".to_string(),
        ));
    }
    if alias.len() > 128 {
        return Err(AppError::Internal(format!(
            "alias name exceeds 128 characters: '{}'",
            &alias[..32]
        )));
    }
    for ch in alias.chars() {
        if ch == ' ' || ch == '/' || ch == '\\' || (ch as u32) < 0x20 {
            return Err(AppError::Internal(format!(
                "alias name contains invalid character: '{alias}'"
            )));
        }
    }
    Ok(())
}

fn short_hash_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    )
}

/// Sanitize one MCP tool-name component so it only contains `[A-Za-z0-9_-]`,
/// capped at `max_len`. If sanitization changes input (replacement/truncation/empty),
/// append `_` + 16-hex hash to reduce collisions.
fn sanitize_tool_component(
    raw: &str,
    fallback: &str,
    max_len: usize,
    allow_hyphen: bool,
) -> String {
    if max_len == 0 {
        return String::new();
    }

    let mut out = String::with_capacity(raw.len().min(max_len));
    let mut changed = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || (allow_hyphen && ch == '-') {
            out.push(ch);
        } else {
            out.push('_');
            changed = true;
        }
    }
    if out.is_empty() {
        out.push_str(fallback);
        changed = true;
    }
    if out.len() > max_len {
        out.truncate(max_len);
        changed = true;
    }

    if changed {
        let hash = short_hash_hex(raw);
        if max_len <= hash.len() {
            return hash[..max_len].to_string();
        }
        let keep = max_len.saturating_sub(hash.len() + 1);
        if out.len() > keep {
            out.truncate(keep);
        }
        out.push('_');
        out.push_str(&hash);
    }

    if out.len() > max_len {
        out.truncate(max_len);
    }
    out
}

/// Sanitize an MCP server name for use in tool name prefixes.
///
/// Produces a deterministic component that fits in 32 chars.
fn sanitize_server_name(name: &str) -> String {
    sanitize_tool_component(name, "mcp", 32, true)
}

/// Registry mapping tool names to their implementations.
#[derive(Clone)]
pub struct ToolRegistry {
    tools: HashMap<String, RegisteredTool>,
    aliases: HashMap<String, String>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    fn is_name_available(&self, name: &str) -> bool {
        !self.tools.contains_key(name) && !self.aliases.contains_key(name)
    }

    /// Register a local WASM skill.
    pub fn register_skill(&mut self, skill: Arc<dyn Skill>) -> Result<(), AppError> {
        let def = skill.definition();
        let name = def.name.clone();
        validate_tool_name(&name)?;
        if !self.is_name_available(&name) {
            return Err(AppError::Internal(format!(
                "duplicate tool name '{name}' during skill registration"
            )));
        }
        self.tools.insert(
            name,
            RegisteredTool {
                source: ToolSource::Skill(skill),
                definition: ToolDefinition {
                    name: def.name,
                    description: def.description,
                    parameters: def.parameters,
                },
                skill_id: None,
                remote_tool_name: None,
            },
        );
        Ok(())
    }

    /// Register all tools from an MCP server.
    ///
    /// Tools are namespaced as `mcp_{sanitized_server}_{original_name}` to avoid
    /// collisions between servers. The original name is stored in `remote_tool_name`
    /// and used when dispatching calls to the MCP server.
    pub async fn register_mcp_tools(
        &mut self,
        client: Arc<dyn McpClient>,
        server_name: &str,
    ) -> Result<(), McpError> {
        let tools = client.list_tools().await?;
        let sanitized = sanitize_server_name(server_name);
        let max_tool_component_len = 128usize.saturating_sub("mcp_".len() + sanitized.len() + 1);
        // With a 32-char server component cap, this remains > 0.
        debug_assert!(max_tool_component_len > 0);
        let mut staged = Vec::with_capacity(tools.len());
        let mut batch_names = HashSet::with_capacity(tools.len());
        for tool in tools {
            let display_component =
                sanitize_tool_component(&tool.name, "tool", max_tool_component_len, true);
            let display_name = format!("mcp_{}_{}", sanitized, display_component);
            validate_tool_name(&display_name).map_err(|e| {
                McpError::ToolCallFailed(format!(
                    "invalid namespaced tool name '{}' for remote tool '{}' from MCP server '{}': {}",
                    display_name, tool.name, server_name, e
                ))
            })?;
            if self.tools.contains_key(&display_name) {
                return Err(McpError::ToolCallFailed(format!(
                    "duplicate tool name '{}' from MCP server '{}': conflicts with existing registered tool",
                    display_name, server_name
                )));
            }
            if self.aliases.contains_key(&display_name) {
                return Err(McpError::ToolCallFailed(format!(
                    "duplicate tool name '{}' from MCP server '{}': conflicts with existing alias",
                    display_name, server_name
                )));
            }
            if !batch_names.insert(display_name.clone()) {
                return Err(McpError::ToolCallFailed(format!(
                    "duplicate tool name '{}' from MCP server '{}': duplicate in MCP tool list response",
                    display_name, server_name
                )));
            }
            staged.push((display_name, tool));
        }
        for (display_name, tool) in staged {
            self.tools.insert(
                display_name.clone(),
                RegisteredTool {
                    source: ToolSource::Mcp {
                        client: Arc::clone(&client),
                        server_name: server_name.to_owned(),
                    },
                    definition: ToolDefinition {
                        name: display_name,
                        description: tool.description,
                        parameters: tool.parameters,
                    },
                    skill_id: None,
                    remote_tool_name: Some(tool.name),
                },
            );
        }
        Ok(())
    }

    /// Register an internal tool handler.
    pub fn register_internal(
        &mut self,
        name: &str,
        description: &str,
        parameters: serde_json::Value,
        handler: Arc<dyn InternalToolHandler>,
    ) -> Result<(), AppError> {
        validate_tool_name(name)?;
        if !self.is_name_available(name) {
            return Err(AppError::Internal(format!(
                "duplicate tool name '{name}' during internal registration"
            )));
        }
        self.tools.insert(
            name.to_owned(),
            RegisteredTool {
                source: ToolSource::Internal(handler),
                definition: ToolDefinition {
                    name: name.to_owned(),
                    description: description.to_owned(),
                    parameters,
                },
                skill_id: None,
                remote_tool_name: None,
            },
        );
        Ok(())
    }

    /// Register an internal tool handler tied to a specific WASM skill.
    ///
    /// Same as `register_internal`, but records the `skill_id` so the tool can
    /// be filtered by `filtered_for_agent`.
    pub fn register_skill_tool(
        &mut self,
        skill_id: &str,
        name: &str,
        description: &str,
        parameters: serde_json::Value,
        handler: Arc<dyn InternalToolHandler>,
    ) -> Result<(), AppError> {
        validate_tool_name(name)?;
        if !self.is_name_available(name) {
            return Err(AppError::Internal(format!(
                "duplicate tool name '{name}' during skill tool registration"
            )));
        }
        self.tools.insert(
            name.to_owned(),
            RegisteredTool {
                source: ToolSource::Internal(handler),
                definition: ToolDefinition {
                    name: name.to_owned(),
                    description: description.to_owned(),
                    parameters,
                },
                skill_id: Some(skill_id.to_owned()),
                remote_tool_name: None,
            },
        );
        Ok(())
    }

    /// Register an alias that maps to an existing tool.
    ///
    /// Alias dispatches are transparent — calling the alias behaves identically
    /// to calling the target tool. Useful for backward-compatible renames
    /// (e.g. `browser_navigate` → `browser.navigate`).
    pub fn register_alias(&mut self, alias: &str, target: &str) -> Result<(), AppError> {
        validate_alias_name(alias)?;
        if !self.tools.contains_key(target) {
            return Err(AppError::Internal(format!(
                "alias target '{target}' does not exist"
            )));
        }
        if self.tools.contains_key(alias) || self.aliases.contains_key(alias) {
            return Err(AppError::Internal(format!(
                "alias '{alias}' collides with an existing tool or alias"
            )));
        }
        self.aliases.insert(alias.to_owned(), target.to_owned());
        Ok(())
    }

    /// Create a clone containing only tools whose skill_id is in `allowed_skills`.
    ///
    /// Non-skill tools (those without a `skill_id`) are always retained.
    /// If `allowed_skills` is empty, returns a full clone (backward compat).
    pub fn filtered_for_agent(&self, allowed_skills: &[String]) -> Self {
        if allowed_skills.is_empty() {
            return self.clone();
        }
        let allowed_set: HashSet<&str> = allowed_skills
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if allowed_set.is_empty() {
            return self.clone();
        }
        let mut filtered = Self::new();
        for (name, tool) in &self.tools {
            let keep = match &tool.skill_id {
                Some(sid) => allowed_set.contains(sid.as_str()),
                None => true,
            };
            if keep {
                filtered.tools.insert(name.clone(), tool.clone());
            }
        }
        // Aliases are only kept if their target survived filtering
        for (alias, target) in &self.aliases {
            if filtered.tools.contains_key(target) {
                filtered.aliases.insert(alias.clone(), target.clone());
            }
        }
        filtered
    }

    /// Get tool definitions for LLM completion params.
    pub fn tool_definitions(&self) -> Vec<ToolDefinition> {
        self.tools.values().map(|t| t.definition.clone()).collect()
    }

    /// Dispatch a tool call by name. Aliases are resolved transparently.
    pub async fn dispatch(
        &self,
        name: &str,
        input: serde_json::Value,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let resolved = self.aliases.get(name).map(|s| s.as_str()).unwrap_or(name);
        let tool = self
            .tools
            .get(resolved)
            .ok_or_else(|| AppError::Internal(format!("tool not found: {name}")))?;

        match &tool.source {
            ToolSource::Skill(skill) => {
                let ctx = encmind_core::traits::SkillContext {
                    session_id: session_id.clone(),
                    agent_id: agent_id.clone(),
                    invocation_id: ulid::Ulid::new().to_string(),
                };
                let output = skill.invoke(input, ctx).await?;
                Ok(output.content)
            }
            ToolSource::Mcp { client, .. } => {
                let call_name = tool.remote_tool_name.as_deref().unwrap_or(resolved);
                let result = client.call_tool(call_name, input).await?;
                Ok(serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_owned()))
            }
            ToolSource::Internal(handler) => handler.handle(input, session_id, agent_id).await,
        }
    }

    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name) || self.aliases.contains_key(name)
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Number of registered tools (not counting aliases).
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Names of all registered tools (not counting aliases), sorted.
    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tools.keys().cloned().collect();
        names.sort();
        names
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use async_trait::async_trait;
    use encmind_core::error::WasmHostError;
    use encmind_core::traits::{
        CapabilitySet, SkillContext, SkillDefinition, SkillManifest, SkillOutput, SKILL_HOST_ABI_V1,
    };
    use std::sync::Mutex;

    /// A skill that echoes its input as JSON.
    pub struct TestEchoSkill;

    #[async_trait]
    impl Skill for TestEchoSkill {
        fn definition(&self) -> SkillDefinition {
            SkillDefinition {
                name: "echo".into(),
                description: "Echoes input back".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "text": { "type": "string" }
                    }
                }),
                output_schema: None,
            }
        }

        fn manifest(&self) -> SkillManifest {
            SkillManifest {
                name: "echo".into(),
                version: "1.0.0".into(),
                description: "Echo skill for testing".into(),
                host_abi: SKILL_HOST_ABI_V1.into(),
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
            }
        }

        async fn invoke(
            &self,
            input: serde_json::Value,
            _ctx: SkillContext,
        ) -> Result<SkillOutput, WasmHostError> {
            Ok(SkillOutput {
                content: serde_json::to_string(&input).unwrap_or_default(),
                artifacts: vec![],
            })
        }
    }

    /// A skill that always returns an error.
    pub struct FailingSkill;

    #[async_trait]
    impl Skill for FailingSkill {
        fn definition(&self) -> SkillDefinition {
            SkillDefinition {
                name: "failing".into(),
                description: "Always fails".into(),
                parameters: serde_json::json!({}),
                output_schema: None,
            }
        }

        fn manifest(&self) -> SkillManifest {
            SkillManifest {
                name: "failing".into(),
                version: "1.0.0".into(),
                description: "Failing skill".into(),
                host_abi: SKILL_HOST_ABI_V1.into(),
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
            }
        }

        async fn invoke(
            &self,
            _input: serde_json::Value,
            _ctx: SkillContext,
        ) -> Result<SkillOutput, WasmHostError> {
            Err(WasmHostError::ExecutionFailed("test failure".into()))
        }
    }

    /// A stub MCP client that returns canned tools and results.
    pub struct StubMcpClient {
        pub tools: Vec<ToolDefinition>,
        pub call_results: Mutex<Vec<serde_json::Value>>,
    }

    impl StubMcpClient {
        pub fn new(tools: Vec<ToolDefinition>, results: Vec<serde_json::Value>) -> Self {
            Self {
                tools,
                call_results: Mutex::new(results),
            }
        }
    }

    #[async_trait]
    impl McpClient for StubMcpClient {
        async fn connect(
            &mut self,
            _config: &encmind_core::config::McpServerConfig,
        ) -> Result<(), McpError> {
            Ok(())
        }

        async fn disconnect(&mut self) -> Result<(), McpError> {
            Ok(())
        }

        async fn list_tools(&self) -> Result<Vec<ToolDefinition>, McpError> {
            Ok(self.tools.clone())
        }

        async fn call_tool(
            &self,
            _name: &str,
            _input: serde_json::Value,
        ) -> Result<serde_json::Value, McpError> {
            let mut results = self.call_results.lock().unwrap();
            if results.is_empty() {
                Ok(serde_json::json!({"result": "stub"}))
            } else {
                Ok(results.remove(0))
            }
        }

        fn is_connected(&self) -> bool {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn new_registry_is_empty() {
        let reg = ToolRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_skill_adds_tool() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        assert!(reg.has_tool("echo"));
        assert_eq!(reg.len(), 1);
    }

    #[tokio::test]
    async fn register_mcp_tools_adds_tools() {
        let mut reg = ToolRegistry::new();
        let client = Arc::new(StubMcpClient::new(
            vec![
                ToolDefinition {
                    name: "search".into(),
                    description: "Search".into(),
                    parameters: serde_json::json!({}),
                },
                ToolDefinition {
                    name: "fetch".into(),
                    description: "Fetch".into(),
                    parameters: serde_json::json!({}),
                },
            ],
            vec![],
        ));
        reg.register_mcp_tools(client, "test-server").await.unwrap();
        assert_eq!(reg.len(), 2);
        // Namespaced: mcp_{sanitized_server}_{tool}
        let prefix = sanitize_server_name("test-server");
        assert!(reg.has_tool(&format!("mcp_{}_search", prefix)));
        assert!(reg.has_tool(&format!("mcp_{}_fetch", prefix)));
    }

    #[test]
    fn tool_definitions_returns_all() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        let defs = reg.tool_definitions();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "echo");
    }

    #[tokio::test]
    async fn dispatch_skill_succeeds() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        let result = reg
            .dispatch(
                "echo",
                serde_json::json!({"text": "hello"}),
                &SessionId::from_string("s1"),
                &AgentId::new("main"),
            )
            .await
            .unwrap();
        assert!(result.contains("hello"));
    }

    #[tokio::test]
    async fn dispatch_mcp_tool_succeeds() {
        let mut reg = ToolRegistry::new();
        let client = Arc::new(StubMcpClient::new(
            vec![ToolDefinition {
                name: "tool".into(),
                description: "MCP tool".into(),
                parameters: serde_json::json!({}),
            }],
            vec![serde_json::json!({"answer": 42})],
        ));
        reg.register_mcp_tools(client, "server").await.unwrap();

        let result = reg
            .dispatch(
                "mcp_server_tool",
                serde_json::json!({}),
                &SessionId::from_string("s1"),
                &AgentId::new("main"),
            )
            .await
            .unwrap();
        assert!(result.contains("42"));
    }

    #[tokio::test]
    async fn dispatch_unknown_tool_errors() {
        let reg = ToolRegistry::new();
        let result = reg
            .dispatch(
                "nonexistent",
                serde_json::json!({}),
                &SessionId::from_string("s1"),
                &AgentId::new("main"),
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn has_tool_returns_false_for_missing() {
        let reg = ToolRegistry::new();
        assert!(!reg.has_tool("missing"));
    }

    #[test]
    fn register_duplicate_skill_errors() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        let err = reg.register_skill(Arc::new(TestEchoSkill)).unwrap_err();
        assert!(
            err.to_string().contains("duplicate tool name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn register_skill_rejects_alias_name_collision() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        reg.register_alias("failing", "echo").unwrap();

        let err = reg.register_skill(Arc::new(FailingSkill)).unwrap_err();
        assert!(
            err.to_string().contains("duplicate tool name"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn register_duplicate_mcp_tool_errors() {
        let mut reg = ToolRegistry::new();
        // Pre-register colliding namespaced key to simulate existing-tool conflict.
        let colliding = format!("mcp_{}_echo", sanitize_server_name("dup-server"));
        reg.register_internal(
            &colliding,
            "Pre-existing",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        let client = Arc::new(StubMcpClient::new(
            vec![ToolDefinition {
                name: "echo".into(),
                description: "dup".into(),
                parameters: serde_json::json!({}),
            }],
            vec![],
        ));
        let err = reg
            .register_mcp_tools(client, "dup-server")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("conflicts with existing registered tool"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn register_mcp_tools_is_atomic_on_batch_duplicate() {
        let mut reg = ToolRegistry::new();
        let client = Arc::new(StubMcpClient::new(
            vec![
                ToolDefinition {
                    name: "echo".into(),
                    description: "first".into(),
                    parameters: serde_json::json!({}),
                },
                ToolDefinition {
                    name: "echo".into(),
                    description: "second".into(),
                    parameters: serde_json::json!({}),
                },
            ],
            vec![],
        ));

        let err = reg
            .register_mcp_tools(client, "dup-server")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate tool name"),
            "unexpected error: {err}"
        );
        assert!(
            !reg.has_tool(&format!("mcp_{}_echo", sanitize_server_name("dup-server"))),
            "registry should not partially register tools on failure"
        );
        assert_eq!(reg.len(), 0, "registry should stay unchanged on failure");
    }

    #[tokio::test]
    async fn register_mcp_tools_rejects_alias_name_collision() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        reg.register_alias("mcp_db_search", "echo").unwrap();

        let client = Arc::new(StubMcpClient::new(
            vec![ToolDefinition {
                name: "search".into(),
                description: "Search".into(),
                parameters: serde_json::json!({}),
            }],
            vec![],
        ));

        let err = reg.register_mcp_tools(client, "db").await.unwrap_err();
        assert!(
            err.to_string().contains("conflicts with existing alias"),
            "unexpected error: {err}"
        );
    }

    // --- Tool name validation tests ---

    #[test]
    fn validate_tool_name_empty_rejected() {
        let err = validate_tool_name("").unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn validate_tool_name_too_long_rejected() {
        let long = "a".repeat(129);
        let err = validate_tool_name(&long).unwrap_err();
        assert!(err.to_string().contains("128"), "got: {err}");
    }

    #[test]
    fn validate_tool_name_spaces_rejected() {
        let err = validate_tool_name("my tool").unwrap_err();
        assert!(err.to_string().contains("must match"), "got: {err}");
    }

    #[test]
    fn validate_tool_name_valid_plain() {
        validate_tool_name("echo").unwrap();
    }

    #[test]
    fn validate_tool_name_valid_dotted() {
        let err = validate_tool_name("browser.navigate").unwrap_err();
        assert!(err.to_string().contains("^[a-zA-Z0-9_-]+$"), "got: {err}");
    }

    // --- Alias tests ---

    #[tokio::test]
    async fn register_alias_dispatches_to_target() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        reg.register_alias("echo_alias", "echo").unwrap();

        assert!(reg.has_tool("echo_alias"));

        let result = reg
            .dispatch(
                "echo_alias",
                serde_json::json!({"text": "via alias"}),
                &SessionId::from_string("s1"),
                &AgentId::new("main"),
            )
            .await
            .unwrap();
        assert!(result.contains("via alias"));
    }

    #[test]
    fn register_alias_allows_dotted_name() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        reg.register_alias("echo.v1", "echo").unwrap();
        assert!(reg.has_tool("echo.v1"));
    }

    #[tokio::test]
    async fn dispatch_mcp_alias_calls_remote_name() {
        use std::sync::Mutex;

        struct RecordingMcpClient {
            called: Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl McpClient for RecordingMcpClient {
            async fn connect(
                &mut self,
                _config: &encmind_core::config::McpServerConfig,
            ) -> Result<(), McpError> {
                Ok(())
            }

            async fn disconnect(&mut self) -> Result<(), McpError> {
                Ok(())
            }

            async fn list_tools(&self) -> Result<Vec<ToolDefinition>, McpError> {
                Ok(vec![ToolDefinition {
                    name: "tool".into(),
                    description: "MCP tool".into(),
                    parameters: serde_json::json!({}),
                }])
            }

            async fn call_tool(
                &self,
                name: &str,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, McpError> {
                self.called.lock().unwrap().push(name.to_string());
                Ok(serde_json::json!({"ok": true}))
            }

            fn is_connected(&self) -> bool {
                true
            }
        }

        let mut reg = ToolRegistry::new();
        let client = Arc::new(RecordingMcpClient {
            called: Mutex::new(Vec::new()),
        });
        reg.register_mcp_tools(client.clone(), "server")
            .await
            .unwrap();
        // Namespaced name is mcp_server_tool
        reg.register_alias("mcp_alias", "mcp_server_tool").unwrap();

        let _ = reg
            .dispatch(
                "mcp_alias",
                serde_json::json!({}),
                &SessionId::from_string("s1"),
                &AgentId::new("main"),
            )
            .await
            .unwrap();

        // Dispatch uses the original remote name "tool", not the namespaced name
        let called = client.called.lock().unwrap().clone();
        assert_eq!(called, vec!["tool".to_string()]);
    }

    #[test]
    fn register_alias_nonexistent_target_rejected() {
        let mut reg = ToolRegistry::new();
        let err = reg.register_alias("my_alias", "nonexistent").unwrap_err();
        assert!(err.to_string().contains("does not exist"), "got: {err}");
    }

    // --- Skill tool and filtered_for_agent tests ---

    struct StubToolHandler;
    #[async_trait::async_trait]
    impl InternalToolHandler for StubToolHandler {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, encmind_core::error::AppError> {
            Ok("ok".into())
        }
    }

    #[test]
    fn register_skill_tool_sets_skill_id() {
        let mut reg = ToolRegistry::new();
        reg.register_skill_tool(
            "my-skill",
            "skill_echo",
            "Echo via skill",
            serde_json::json!({"type": "object"}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        assert!(reg.has_tool("skill_echo"));
        assert_eq!(reg.len(), 1);
        // Verify skill_id is set
        let tool = reg.tools.get("skill_echo").unwrap();
        assert_eq!(tool.skill_id.as_deref(), Some("my-skill"));
    }

    #[test]
    fn register_internal_rejects_alias_name_collision() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        reg.register_alias("shadowed_name", "echo").unwrap();

        let err = reg
            .register_internal(
                "shadowed_name",
                "Would shadow alias",
                serde_json::json!({}),
                Arc::new(StubToolHandler),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate tool name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn register_skill_tool_rejects_alias_name_collision() {
        let mut reg = ToolRegistry::new();
        reg.register_skill(Arc::new(TestEchoSkill)).unwrap();
        reg.register_alias("shadowed_name", "echo").unwrap();

        let err = reg
            .register_skill_tool(
                "my-skill",
                "shadowed_name",
                "Would shadow alias",
                serde_json::json!({}),
                Arc::new(StubToolHandler),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate tool name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn filtered_for_agent_empty_returns_all() {
        let mut reg = ToolRegistry::new();
        reg.register_skill_tool(
            "skill-a",
            "tool_a",
            "Tool A",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_internal(
            "builtin_tool",
            "Built-in",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();

        let filtered = reg.filtered_for_agent(&[]);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.has_tool("tool_a"));
        assert!(filtered.has_tool("builtin_tool"));
    }

    #[test]
    fn filtered_for_agent_filters_skill_tools() {
        let mut reg = ToolRegistry::new();
        reg.register_skill_tool(
            "skill-a",
            "tool_a",
            "Tool A",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_skill_tool(
            "skill-b",
            "tool_b",
            "Tool B",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();

        let filtered = reg.filtered_for_agent(&["skill-a".to_string()]);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.has_tool("tool_a"));
        assert!(!filtered.has_tool("tool_b"));
    }

    #[test]
    fn filtered_for_agent_keeps_non_skill_tools() {
        let mut reg = ToolRegistry::new();
        reg.register_internal(
            "builtin",
            "Built-in tool",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_skill_tool(
            "skill-a",
            "tool_a",
            "Tool A",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();

        let filtered = reg.filtered_for_agent(&["other-skill".to_string()]);
        // Built-in tool always kept, skill-a not in allowlist so filtered out
        assert_eq!(filtered.len(), 1);
        assert!(filtered.has_tool("builtin"));
        assert!(!filtered.has_tool("tool_a"));
    }

    // --- MCP namespacing tests ---

    #[tokio::test]
    async fn two_mcp_servers_same_tool_no_collision() {
        let mut reg = ToolRegistry::new();
        let client_alpha = Arc::new(StubMcpClient::new(
            vec![ToolDefinition {
                name: "search".into(),
                description: "Alpha search".into(),
                parameters: serde_json::json!({}),
            }],
            vec![],
        ));
        let client_beta = Arc::new(StubMcpClient::new(
            vec![ToolDefinition {
                name: "search".into(),
                description: "Beta search".into(),
                parameters: serde_json::json!({}),
            }],
            vec![],
        ));
        reg.register_mcp_tools(client_alpha, "alpha").await.unwrap();
        reg.register_mcp_tools(client_beta, "beta").await.unwrap();

        assert!(reg.has_tool("mcp_alpha_search"));
        assert!(reg.has_tool("mcp_beta_search"));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn sanitize_server_name_works() {
        let sanitized = sanitize_server_name("my-server.local");
        assert!(
            sanitized.starts_with("my-server_local_"),
            "got: {sanitized}"
        );
        assert!(sanitized.len() <= 32, "got: {sanitized}");
        assert_eq!(sanitize_server_name("alpha"), "alpha");
        let empty = sanitize_server_name("");
        assert!(empty.starts_with("mcp_"), "got: {empty}");
        assert_eq!(empty.len(), 20, "got: {empty}");
        let replaced = sanitize_server_name("a/b\\c d");
        assert!(replaced.starts_with("a_b_c_d_"), "got: {replaced}");
        // Truncates to 32 chars and appends hash when truncation occurs
        let long = "a".repeat(50);
        assert_eq!(sanitize_server_name(&long).len(), 32);
    }

    #[test]
    fn sanitize_server_name_avoids_collision_for_similar_inputs() {
        let a = sanitize_server_name("prod.server");
        let b = sanitize_server_name("prod-server");
        assert_ne!(a, b, "sanitized names must remain distinct");
    }

    #[tokio::test]
    async fn mcp_dispatch_uses_remote_name() {
        use std::sync::Mutex;

        struct RecordingClient {
            called: Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl McpClient for RecordingClient {
            async fn connect(
                &mut self,
                _config: &encmind_core::config::McpServerConfig,
            ) -> Result<(), McpError> {
                Ok(())
            }
            async fn disconnect(&mut self) -> Result<(), McpError> {
                Ok(())
            }
            async fn list_tools(&self) -> Result<Vec<ToolDefinition>, McpError> {
                Ok(vec![ToolDefinition {
                    name: "query".into(),
                    description: "Query".into(),
                    parameters: serde_json::json!({}),
                }])
            }
            async fn call_tool(
                &self,
                name: &str,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, McpError> {
                self.called.lock().unwrap().push(name.to_string());
                Ok(serde_json::json!({"ok": true}))
            }
            fn is_connected(&self) -> bool {
                true
            }
        }

        let mut reg = ToolRegistry::new();
        let client = Arc::new(RecordingClient {
            called: Mutex::new(Vec::new()),
        });
        reg.register_mcp_tools(client.clone(), "db-server")
            .await
            .unwrap();

        // Registry key is mcp_{sanitized_server}_query
        let namespaced = format!("mcp_{}_query", sanitize_server_name("db-server"));
        assert!(reg.has_tool(&namespaced));

        let _ = reg
            .dispatch(
                &namespaced,
                serde_json::json!({}),
                &SessionId::from_string("s1"),
                &AgentId::new("main"),
            )
            .await
            .unwrap();

        // The server receives the original name "query"
        let called = client.called.lock().unwrap().clone();
        assert_eq!(called, vec!["query".to_string()]);
    }

    #[tokio::test]
    async fn register_mcp_tools_sanitizes_invalid_remote_tool_names() {
        let mut reg = ToolRegistry::new();
        let client = Arc::new(StubMcpClient::new(
            vec![ToolDefinition {
                name: "web.search.v1".into(),
                description: "Search".into(),
                parameters: serde_json::json!({}),
            }],
            vec![],
        ));

        reg.register_mcp_tools(client, "db-server").await.unwrap();
        let defs = reg.tool_definitions();
        assert_eq!(defs.len(), 1);
        assert!(
            defs[0]
                .name
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-')),
            "tool name should be OpenAI-compatible: {}",
            defs[0].name
        );
        assert!(
            defs[0]
                .name
                .starts_with(&format!("mcp_{}_", sanitize_server_name("db-server"))),
            "unexpected prefix: {}",
            defs[0].name
        );
    }

    #[test]
    fn wasm_skill_tools_namespace_by_skill_id() {
        // Simulates the gateway's namespacing: two skills both have a tool named "run"
        // but they register as "alpha_run" and "beta_run".
        let mut reg = ToolRegistry::new();
        reg.register_skill_tool(
            "alpha",
            "alpha_run",
            "Run alpha",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_skill_tool(
            "beta",
            "beta_run",
            "Run beta",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        assert!(reg.has_tool("alpha_run"));
        assert!(reg.has_tool("beta_run"));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn filtered_for_agent_drops_orphan_aliases() {
        let mut reg = ToolRegistry::new();
        reg.register_skill_tool(
            "skill-a",
            "tool_a",
            "Tool A",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_alias("alias_a", "tool_a").unwrap();

        // Filter out skill-a
        let filtered = reg.filtered_for_agent(&["other-skill".to_string()]);
        assert!(!filtered.has_tool("tool_a"));
        assert!(!filtered.has_tool("alias_a"));
    }

    #[test]
    fn filtered_for_agent_whitespace_only_allowlist_returns_all() {
        let mut reg = ToolRegistry::new();
        reg.register_skill_tool(
            "skill-a",
            "tool_a",
            "Tool A",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_internal(
            "internal_ping",
            "Internal ping",
            serde_json::json!({"type":"object"}),
            Arc::new(StubToolHandler),
        )
        .unwrap();

        let filtered = reg.filtered_for_agent(&["   ".to_string()]);
        assert!(filtered.has_tool("tool_a"));
        assert!(filtered.has_tool("internal_ping"));
    }

    #[test]
    fn tool_count_reflects_registered_tools() {
        let mut reg = ToolRegistry::new();
        assert_eq!(reg.tool_count(), 0);
        assert!(reg.tool_names().is_empty());

        reg.register_internal(
            "alpha",
            "Alpha tool",
            serde_json::json!({"type":"object"}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        reg.register_internal(
            "beta",
            "Beta tool",
            serde_json::json!({"type":"object"}),
            Arc::new(StubToolHandler),
        )
        .unwrap();

        assert_eq!(reg.tool_count(), 2);
        assert_eq!(reg.tool_names(), vec!["alpha", "beta"]);
    }
}
