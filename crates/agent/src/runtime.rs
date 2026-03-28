use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use encmind_core::error::{AppError, PluginError};
use encmind_core::hooks::{HookContext, HookPoint, HookRegistry, HookResult};
use encmind_core::traits::{
    ApprovalHandler, CompletionParams, FinishReason, LlmBackend, MemorySearchProvider, SessionStore,
};
use encmind_core::types::*;

use crate::approval::{NoopApprovalHandler, ToolApprovalChecker};
use crate::context::{ContextConfig, ContextManager};
use crate::firewall::EgressFirewall;
use crate::tool_registry::ToolRegistry;

/// Configuration for the agent runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub max_tool_iterations: u32,
    pub context_config: ContextConfig,
    /// If set, verify that the session's agent_id matches the agent being run.
    pub enforce_session_agent_match: bool,
    /// Optional workspace directory to create for the agent.
    pub workspace_dir: Option<PathBuf>,
    /// If set, trigger compaction when message count exceeds this threshold.
    pub compaction_threshold: Option<usize>,
    /// Number of recent messages to keep when compacting (default 50).
    pub compaction_keep_last: usize,
    /// Maximum chars to keep in a tool result before truncation.
    /// Full output is retained in ToolCallRecord for auditing.
    /// Default: 32768 (~8K tokens).
    pub max_tool_output_chars: usize,
    /// Per-tool overrides for max_tool_output_chars.
    /// Keys are tool names (e.g. "bash_exec", "file_read").
    /// Missing keys fall back to max_tool_output_chars.
    pub per_tool_output_chars: HashMap<String, usize>,
    /// Hard cap on total tool calls per run. When exceeded the loop detector
    /// stops the run early with a diagnostic message. Defaults to `None`
    /// (which falls back to `max_tool_iterations * 5`).
    pub tool_calls_per_run: Option<u32>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_tool_iterations: 20,
            context_config: ContextConfig::default(),
            enforce_session_agent_match: false,
            workspace_dir: None,
            compaction_threshold: Some(100),
            compaction_keep_last: 50,
            max_tool_output_chars: 32_768,
            per_tool_output_chars: HashMap::new(),
            tool_calls_per_run: None,
        }
    }
}

/// A record of a single tool call made during a run.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    pub name: String,
    pub input: serde_json::Value,
    pub output: String,
    pub is_error: bool,
}

/// The result of a complete agent run.
#[derive(Debug)]
pub struct RunResult {
    pub response: Message,
    pub tool_calls: Vec<ToolCallRecord>,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub iterations: u32,
    /// Set when the loop detector triggered and stopped the run.
    pub loop_break: Option<String>,
    /// Stable reason code for loop-break audit/reporting.
    pub loop_break_code: Option<String>,
}

/// The core agent runtime: drives the conversation loop.
pub struct AgentRuntime {
    llm: Arc<dyn LlmBackend>,
    session_store: Arc<dyn SessionStore>,
    tool_registry: Arc<ToolRegistry>,
    firewall: Option<Arc<EgressFirewall>>,
    context_manager: ContextManager,
    config: RuntimeConfig,
    approval_handler: Arc<dyn ApprovalHandler>,
    approval_checker: Option<ToolApprovalChecker>,
    hook_registry: Option<Arc<RwLock<HookRegistry>>>,
}

impl AgentRuntime {
    pub fn new(
        llm: Arc<dyn LlmBackend>,
        session_store: Arc<dyn SessionStore>,
        tool_registry: Arc<ToolRegistry>,
        config: RuntimeConfig,
    ) -> Self {
        let context_manager = ContextManager::new(config.context_config.clone());
        Self {
            llm,
            session_store,
            tool_registry,
            firewall: None,
            context_manager,
            config,
            approval_handler: Arc::new(NoopApprovalHandler),
            approval_checker: None,
            hook_registry: None,
        }
    }

    /// Attach a memory search provider for context augmentation.
    pub fn with_memory(mut self, provider: Arc<dyn MemorySearchProvider>) -> Self {
        self.context_manager = self.context_manager.with_memory(provider);
        self
    }

    /// Set the approval handler and checker for this runtime.
    pub fn with_approval(
        mut self,
        handler: Arc<dyn ApprovalHandler>,
        checker: ToolApprovalChecker,
    ) -> Self {
        self.approval_handler = handler;
        self.approval_checker = Some(checker);
        self
    }

    /// Attach an egress firewall that is enforced on tool inputs.
    pub fn with_firewall(mut self, firewall: Arc<EgressFirewall>) -> Self {
        self.firewall = Some(firewall);
        self
    }

    /// Attach a plugin hook registry to this runtime.
    pub fn with_hooks(mut self, hook_registry: Arc<RwLock<HookRegistry>>) -> Self {
        self.hook_registry = Some(hook_registry);
        self
    }

    /// Run a single user turn through the full conversation loop.
    pub async fn run(
        &self,
        session_id: &SessionId,
        user_message: Message,
        agent_config: &AgentConfig,
        cancel: CancellationToken,
    ) -> Result<RunResult, AppError> {
        let mut user_message = user_message;

        // 0a. Session-agent isolation check
        if self.config.enforce_session_agent_match {
            if let Some(session) = self.session_store.get_session(session_id).await? {
                if session.agent_id != agent_config.id {
                    return Err(AppError::Internal(format!(
                        "session {} belongs to agent '{}', not '{}'",
                        session_id, session.agent_id, agent_config.id
                    )));
                }
            }
        }

        // 0b. Workspace directory creation
        if let Some(ref dir) = self.config.workspace_dir {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|e| {
                    AppError::Internal(format!(
                        "failed to create workspace dir '{}': {e}",
                        dir.display()
                    ))
                })?;
                info!(path = %dir.display(), "created workspace directory");
            }
        }

        if let Some(override_payload) = self
            .execute_hook(
                HookPoint::BeforeAgentStart,
                session_id,
                &agent_config.id,
                None,
                serde_json::json!({
                    "user_message": user_message.clone(),
                }),
            )
            .await?
        {
            let candidate = override_payload
                .get("user_message")
                .cloned()
                .unwrap_or(override_payload);
            match serde_json::from_value::<Message>(candidate) {
                Ok(overridden) => {
                    // Preserve provenance for audit: the pre-hook user input is
                    // not persisted to session history when an override applies.
                    let original_text = Self::message_text_for_audit(&user_message);
                    let overridden_text = Self::message_text_for_audit(&overridden);
                    info!(
                        session_id = %session_id,
                        agent_id = %agent_config.id,
                        original_chars = original_text.chars().count(),
                        overridden_chars = overridden_text.chars().count(),
                        original_fingerprint = %Self::audit_fingerprint(&original_text),
                        overridden_fingerprint = %Self::audit_fingerprint(&overridden_text),
                        "BeforeAgentStart override applied"
                    );
                    user_message = overridden;
                }
                Err(e) => warn!(error = %e, "ignoring invalid BeforeAgentStart override payload"),
            }
        }

        // 1. Persist user message
        self.session_store
            .append_message(session_id, &user_message)
            .await?;

        let mut tool_calls = Vec::new();
        let mut input_tokens: u32 = 0;
        let mut output_tokens: u32 = 0;
        let mut total_tokens: u32 = 0;
        let mut last_response: Option<Message> = None;
        let mut loop_detector = crate::loop_detector::LoopDetector::new(
            self.config
                .tool_calls_per_run
                .unwrap_or(self.config.max_tool_iterations * 5),
        );

        // 2. Conversation loop
        for iteration in 0..self.config.max_tool_iterations {
            if cancel.is_cancelled() {
                return Err(AppError::Internal("request cancelled".into()));
            }

            // 2a. Build context
            let (context, max_output) = self
                .context_manager
                .build_context(session_id, agent_config, &self.session_store, &self.llm)
                .await?;
            let prompt_tokens = match self.llm.count_tokens(&context).await {
                Ok(tokens) => tokens,
                Err(e) => {
                    warn!(error = %e, "failed to count prompt tokens");
                    0
                }
            };
            input_tokens = input_tokens.saturating_add(prompt_tokens);
            total_tokens = total_tokens.saturating_add(prompt_tokens);

            // 2b. Call LLM
            let params = CompletionParams {
                model: agent_config.model.clone(),
                max_tokens: max_output,
                tools: self.tool_registry.tool_definitions(),
                ..Default::default()
            };

            let stream = self.llm.complete(&context, params, cancel.clone()).await?;

            // 2c. Collect streaming response
            let mut text_buf = String::new();
            let mut thinking_buf = String::new();
            let mut tool_uses: Vec<(String, String, String)> = Vec::new(); // (id, name, input_json)
            let mut finish_reason = None;

            tokio::pin!(stream);
            while let Some(delta_result) = stream.next().await {
                let delta = delta_result?;
                if let Some(ref text) = delta.text {
                    text_buf.push_str(text);
                }
                if let Some(ref thinking) = delta.thinking {
                    thinking_buf.push_str(thinking);
                }
                if let Some(ref tu) = delta.tool_use {
                    tool_uses.push((tu.id.clone(), tu.name.clone(), tu.input_json.clone()));
                }
                if let Some(ref fr) = delta.finish_reason {
                    finish_reason = Some(fr.clone());
                }
            }

            // Build assistant content blocks
            let parsed_tool_uses: Vec<(String, String, serde_json::Value)> = tool_uses
                .iter()
                .map(|(id, name, input_json)| {
                    (
                        id.clone(),
                        name.clone(),
                        Self::sanitize_tool_use_input(id, name, input_json),
                    )
                })
                .collect();

            let mut content_blocks = Vec::new();
            if !thinking_buf.is_empty() {
                content_blocks.push(ContentBlock::Thinking {
                    text: thinking_buf.clone(),
                });
            }
            if !text_buf.is_empty() {
                content_blocks.push(ContentBlock::Text {
                    text: text_buf.clone(),
                });
            }
            for (id, name, input) in &parsed_tool_uses {
                content_blocks.push(ContentBlock::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                });
            }

            let mut assistant_msg = Message {
                id: MessageId::new(),
                role: Role::Assistant,
                content: content_blocks,
                created_at: Utc::now(),
                token_count: None,
            };

            let completion_chars = text_buf
                .len()
                .saturating_add(thinking_buf.len())
                .saturating_add(
                    tool_uses
                        .iter()
                        .map(|(id, name, input_json)| id.len() + name.len() + input_json.len())
                        .sum::<usize>(),
                );
            let completion_tokens = (completion_chars / 4) as u32;
            output_tokens = output_tokens.saturating_add(completion_tokens);
            total_tokens = total_tokens.saturating_add(completion_tokens);

            // 2d. Dispatch tools if model emitted tool calls, even when finish_reason is omitted.
            let should_dispatch_tools = !tool_uses.is_empty()
                && matches!(finish_reason, Some(FinishReason::ToolUse) | None);
            if should_dispatch_tools {
                self.session_store
                    .append_message(session_id, &assistant_msg)
                    .await?;
                'tool_loop: for (id, name, parsed_input) in &parsed_tool_uses {
                    let mut input = parsed_input.clone();

                    if let Some(override_payload) = self
                        .execute_hook(
                            HookPoint::BeforeToolCall,
                            session_id,
                            &agent_config.id,
                            Some(name.clone()),
                            serde_json::json!({
                                "tool_name": name,
                                "input": input.clone(),
                            }),
                        )
                        .await?
                    {
                        // Abort from BeforeToolCall is fail-closed and bubbles
                        // out as a run error via execute_hook(). At this point
                        // the assistant tool_use message has already been
                        // persisted, so the session may show a tool_use without
                        // a corresponding tool_result.
                        let new_input = override_payload
                            .get("input")
                            .cloned()
                            .unwrap_or(override_payload);
                        input = new_input;
                    }

                    if let Some(ref firewall) = self.firewall {
                        let urls = Self::extract_http_urls(&input);
                        for url in urls {
                            if let Err(e) = firewall
                                .check_url_for_agent(&url, agent_config.id.as_str())
                                .await
                            {
                                warn!(
                                    tool = %name,
                                    url = %url,
                                    error = %e,
                                    "tool call blocked by egress firewall"
                                );
                                self.record_tool_error(
                                    session_id,
                                    &mut tool_calls,
                                    id,
                                    name,
                                    &input,
                                    format!("Error: {e}"),
                                )
                                .await?;
                                // Intentionally ignore HookResult on error
                                // paths. This keeps denied/blocked/error
                                // outcomes fail-closed and prevents hooks from
                                // "un-denying" by overriding is_error/output.
                                let _ = self
                                    .execute_hook(
                                        HookPoint::AfterToolCall,
                                        session_id,
                                        &agent_config.id,
                                        Some(name.clone()),
                                        serde_json::json!({
                                            "tool_name": name,
                                            "input": input.clone(),
                                            "output": format!("Error: {e}"),
                                            "is_error": true,
                                        }),
                                    )
                                    .await;
                                continue 'tool_loop;
                            }
                        }
                    }

                    // Approval check before dispatch
                    if let Some(ref checker) = self.approval_checker {
                        if checker.is_denied(name) {
                            self.record_tool_error(
                                session_id,
                                &mut tool_calls,
                                id,
                                name,
                                &input,
                                format!("Error: tool '{}' is denied by security policy", name),
                            )
                            .await?;
                            // Intentionally ignore HookResult on error paths
                            // (see fail-closed rationale above).
                            let _ = self
                                .execute_hook(
                                    HookPoint::AfterToolCall,
                                    session_id,
                                    &agent_config.id,
                                    Some(name.clone()),
                                    serde_json::json!({
                                        "tool_name": name,
                                        "input": input.clone(),
                                        "output": format!("Error: tool '{}' is denied by security policy", name),
                                        "is_error": true,
                                    }),
                                )
                                .await;
                            continue 'tool_loop;
                        }

                        if checker.requires_approval(name, &input) {
                            let req = ApprovalRequest {
                                tool_name: name.clone(),
                                tool_input: input.clone(),
                                session_id: session_id.clone(),
                                agent_id: agent_config.id.clone(),
                            };
                            let decision = self.approval_handler.request_approval(req).await;
                            if let ApprovalDecision::Denied { reason } = decision {
                                self.record_tool_error(
                                    session_id,
                                    &mut tool_calls,
                                    id,
                                    name,
                                    &input,
                                    format!("Error: tool '{}' denied: {}", name, reason),
                                )
                                .await?;
                                // Intentionally ignore HookResult on error
                                // paths (see fail-closed rationale above).
                                let _ = self
                                    .execute_hook(
                                        HookPoint::AfterToolCall,
                                        session_id,
                                        &agent_config.id,
                                        Some(name.clone()),
                                        serde_json::json!({
                                            "tool_name": name,
                                            "input": input.clone(),
                                            "output": format!("Error: tool '{}' denied: {}", name, reason),
                                            "is_error": true,
                                        }),
                                    )
                                    .await;
                                continue 'tool_loop;
                            }
                        }
                    }

                    let (output, is_error) = match self
                        .tool_registry
                        .dispatch(name, input.clone(), session_id, &agent_config.id)
                        .await
                    {
                        Ok(result) => (result, false),
                        Err(e) => {
                            warn!(tool = %name, error = %e, "tool dispatch failed");
                            (format!("Error: {e}"), true)
                        }
                    };

                    let mut output = output;
                    let mut is_error = is_error;
                    if let Some(override_payload) = self
                        .execute_hook(
                            HookPoint::AfterToolCall,
                            session_id,
                            &agent_config.id,
                            Some(name.clone()),
                            serde_json::json!({
                                "tool_name": name,
                                "input": input.clone(),
                                "output": output.clone(),
                                "is_error": is_error,
                            }),
                        )
                        .await?
                    {
                        if let Some(obj) = override_payload.as_object() {
                            if let Some(new_output) = obj.get("output").and_then(|v| v.as_str()) {
                                output = new_output.to_owned();
                            }
                            if let Some(new_error) = obj.get("is_error").and_then(|v| v.as_bool()) {
                                is_error = new_error;
                            }
                        } else if let Some(new_output) = override_payload.as_str() {
                            output = new_output.to_owned();
                        }
                    }

                    tool_calls.push(ToolCallRecord {
                        name: name.clone(),
                        input: input.clone(),
                        output: output.clone(),
                        is_error,
                    });

                    let limit = self
                        .config
                        .per_tool_output_chars
                        .get(name.as_str())
                        .copied()
                        .unwrap_or(self.config.max_tool_output_chars);
                    let persisted_output = Self::truncate_tool_output(&output, limit);
                    if persisted_output.len() < output.len() {
                        info!(
                            tool = %name,
                            original_chars = output.chars().count(),
                            truncated_to = limit,
                            "tool output truncated for LLM context"
                        );
                    }

                    let tool_result_msg = Message {
                        id: MessageId::new(),
                        role: Role::Tool,
                        content: vec![ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: persisted_output,
                            is_error,
                        }],
                        created_at: Utc::now(),
                        token_count: None,
                    };

                    self.session_store
                        .append_message(session_id, &tool_result_msg)
                        .await?;

                    // Loop detection: check for runaway patterns after each tool call
                    if let Some(violation) = loop_detector.record_and_check(name, is_error) {
                        let reason = violation.to_string();
                        let reason_code = match &violation {
                            crate::loop_detector::LoopViolation::ToolCallCapExceeded { .. } => {
                                "tool_call_cap_exceeded"
                            }
                            crate::loop_detector::LoopViolation::ConsecutiveFailures { .. } => {
                                "consecutive_failures"
                            }
                            crate::loop_detector::LoopViolation::RepeatingPattern { .. } => {
                                "repeating_pattern"
                            }
                        }
                        .to_string();
                        warn!(reason = %reason, "loop detector triggered, stopping run");

                        let stop_msg = Message {
                            id: MessageId::new(),
                            role: Role::Assistant,
                            content: vec![ContentBlock::Text {
                                text: format!("[Loop breaker: {reason}]"),
                            }],
                            created_at: Utc::now(),
                            token_count: None,
                        };
                        let _ = self
                            .session_store
                            .append_message(session_id, &stop_msg)
                            .await;

                        return Ok(RunResult {
                            response: stop_msg,
                            tool_calls,
                            input_tokens,
                            output_tokens,
                            iterations: iteration + 1,
                            total_tokens,
                            loop_break: Some(reason),
                            loop_break_code: Some(reason_code),
                        });
                    }
                }

                debug!(iteration, "tool use round complete, continuing loop");
                continue;
            }

            // If model asked for tool use but did not provide calls, bail out explicitly.
            if matches!(finish_reason, Some(FinishReason::ToolUse)) && tool_uses.is_empty() {
                self.session_store
                    .append_message(session_id, &assistant_msg)
                    .await?;
                return Err(AppError::Internal(
                    "model returned finish_reason=tool_use without tool calls".into(),
                ));
            }

            if let Some(override_payload) = self
                .execute_hook(
                    HookPoint::AfterAgentComplete,
                    session_id,
                    &agent_config.id,
                    None,
                    serde_json::json!({
                        "assistant_message": assistant_msg.clone(),
                    }),
                )
                .await?
            {
                let candidate = override_payload
                    .get("assistant_message")
                    .cloned()
                    .unwrap_or(override_payload);
                match serde_json::from_value::<Message>(candidate) {
                    Ok(overridden) => assistant_msg = overridden,
                    Err(e) => {
                        warn!(error = %e, "ignoring invalid AfterAgentComplete override payload")
                    }
                }
            }

            self.session_store
                .append_message(session_id, &assistant_msg)
                .await?;

            last_response = Some(assistant_msg);
            let result = RunResult {
                response: last_response.unwrap(),
                tool_calls,
                input_tokens,
                output_tokens,
                total_tokens,
                iterations: iteration + 1,
                loop_break: None,
                loop_break_code: None,
            };
            self.maybe_compact(session_id).await;
            return Ok(result);
        }

        // Iteration limit reached
        warn!(
            max = self.config.max_tool_iterations,
            "agent hit max tool iterations"
        );

        // Return whatever we have
        let fallback = last_response.unwrap_or_else(|| Message {
            id: MessageId::new(),
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "I've reached the maximum number of tool iterations.".into(),
            }],
            created_at: Utc::now(),
            token_count: None,
        });

        let result = RunResult {
            response: fallback,
            tool_calls,
            input_tokens,
            output_tokens,
            total_tokens,
            iterations: self.config.max_tool_iterations,
            loop_break: None,
            loop_break_code: None,
        };
        self.maybe_compact(session_id).await;
        Ok(result)
    }

    async fn execute_hook(
        &self,
        point: HookPoint,
        session_id: &SessionId,
        agent_id: &AgentId,
        method: Option<String>,
        payload: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, AppError> {
        let Some(registry) = self.hook_registry.as_ref() else {
            return Ok(None);
        };

        let registry_snapshot = { registry.read().await.clone() };
        let mut ctx = HookContext {
            session_id: Some(session_id.clone()),
            agent_id: Some(agent_id.clone()),
            method,
            payload,
        };

        match registry_snapshot
            .execute(point, &mut ctx)
            .await
            .map_err(AppError::Plugin)?
        {
            HookResult::Continue => Ok(None),
            HookResult::Override(value) => Ok(Some(value)),
            HookResult::Abort { reason } => Err(AppError::Plugin(PluginError::HookFailed(
                format!("hook {:?} aborted: {}", point, reason),
            ))),
        }
    }

    fn message_text_for_audit(message: &Message) -> String {
        message
            .content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Text { text } | ContentBlock::Thinking { text } => {
                    Some(text.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn audit_fingerprint(text: &str) -> String {
        // Stable across Rust versions/toolchains: SHA-256 truncated to 8 bytes.
        let hash = Sha256::digest(text.as_bytes());
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&hash[..8]);
        format!("{:016x}", u64::from_be_bytes(prefix))
    }

    async fn record_tool_error(
        &self,
        session_id: &SessionId,
        tool_calls: &mut Vec<ToolCallRecord>,
        tool_use_id: &str,
        tool_name: &str,
        input: &serde_json::Value,
        output: String,
    ) -> Result<(), AppError> {
        tool_calls.push(ToolCallRecord {
            name: tool_name.to_owned(),
            input: input.clone(),
            output: output.clone(),
            is_error: true,
        });

        let tool_result_msg = Message {
            id: MessageId::new(),
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: tool_use_id.to_owned(),
                content: output,
                is_error: true,
            }],
            created_at: Utc::now(),
            token_count: None,
        };
        self.session_store
            .append_message(session_id, &tool_result_msg)
            .await?;
        Ok(())
    }

    fn extract_http_urls(input: &serde_json::Value) -> Vec<String> {
        let mut urls = HashSet::new();
        Self::collect_http_urls(input, &mut urls);
        urls.into_iter().collect()
    }

    fn sanitize_tool_use_input(
        tool_use_id: &str,
        tool_name: &str,
        input_json: &str,
    ) -> serde_json::Value {
        let parsed = match serde_json::from_str::<serde_json::Value>(input_json) {
            Ok(v) => v,
            Err(err) => {
                warn!(
                    tool_use_id = %tool_use_id,
                    tool = %tool_name,
                    error = %err,
                    "tool_use input is invalid JSON; coercing to empty object"
                );
                return serde_json::json!({});
            }
        };
        if parsed.is_object() {
            parsed
        } else {
            warn!(
                tool_use_id = %tool_use_id,
                tool = %tool_name,
                input_type = %match parsed {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                },
                "tool_use input must be an object; coercing to empty object"
            );
            serde_json::json!({})
        }
    }

    fn collect_http_urls(value: &serde_json::Value, urls: &mut HashSet<String>) {
        match value {
            serde_json::Value::String(text) => Self::collect_urls_from_text(text, urls),
            serde_json::Value::Array(items) => {
                for item in items {
                    Self::collect_http_urls(item, urls);
                }
            }
            serde_json::Value::Object(map) => {
                for item in map.values() {
                    Self::collect_http_urls(item, urls);
                }
            }
            _ => {}
        }
    }

    fn collect_urls_from_text(text: &str, urls: &mut HashSet<String>) {
        if let Some(url) = Self::normalize_http_url_candidate(text) {
            urls.insert(url);
        }

        for token in text.split_whitespace() {
            if let Some(url) = Self::normalize_http_url_candidate(token) {
                urls.insert(url);
            }
        }
    }

    fn normalize_http_url_candidate(raw: &str) -> Option<String> {
        let trimmed = raw.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>'
            )
        });
        let parsed = url::Url::parse(trimmed).ok()?;
        match parsed.scheme() {
            "http" | "https" => Some(trimmed.to_owned()),
            _ => None,
        }
    }

    /// Check if the session's message count exceeds the compaction threshold,
    /// and compact if so. Failures are logged but don't abort the run.
    async fn maybe_compact(&self, session_id: &SessionId) {
        let threshold = match self.config.compaction_threshold {
            Some(t) => t,
            None => return,
        };

        // Probe whether a message exists at offset = threshold.
        let probe = self
            .session_store
            .get_messages(
                session_id,
                Pagination {
                    offset: threshold as u32,
                    limit: 1,
                },
            )
            .await;

        let should_compact = match probe {
            Ok(msgs) => !msgs.is_empty(),
            Err(_) => false,
        };

        if should_compact {
            info!(
                session = %session_id,
                threshold,
                keep_last = self.config.compaction_keep_last,
                "compacting session"
            );
            if let Err(e) = self
                .session_store
                .compact_session(session_id, self.config.compaction_keep_last)
                .await
            {
                warn!(session = %session_id, error = %e, "session compaction failed");
            }
        }
    }

    fn truncate_tool_output(output: &str, max_chars: usize) -> String {
        if output.len() <= max_chars {
            return output.to_owned();
        }
        let char_count = output.chars().count();
        if char_count <= max_chars {
            return output.to_owned();
        }
        let truncated: String = output.chars().take(max_chars).collect();
        format!("{truncated}\n\n[truncated from {char_count} chars to {max_chars}]")
    }
}

// ─── Test helpers ──────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use async_trait::async_trait;
    use encmind_core::error::{LlmError, StorageError};
    use encmind_core::traits::{CompletionDelta, CompletionParams, ModelInfo};
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;
    use tokio_stream::Stream;

    /// An LLM backend that returns scripted responses.
    /// Each call to `complete` pops the next response from the queue.
    pub struct ScriptedLlmBackend {
        responses: Mutex<Vec<Vec<CompletionDelta>>>,
        context_window: u32,
    }

    impl ScriptedLlmBackend {
        pub fn new(responses: Vec<Vec<CompletionDelta>>, context_window: u32) -> Self {
            Self {
                responses: Mutex::new(responses),
                context_window,
            }
        }
    }

    #[async_trait]
    impl LlmBackend for ScriptedLlmBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(LlmError::InferenceError(
                    "no more scripted responses".into(),
                ));
            }
            let deltas = responses.remove(0);
            let stream = tokio_stream::iter(deltas.into_iter().map(Ok));
            Ok(Box::pin(stream))
        }

        async fn count_tokens(&self, messages: &[Message]) -> Result<u32, LlmError> {
            // Simple approximation: count total chars / 4
            let total_chars: usize = messages
                .iter()
                .flat_map(|m| &m.content)
                .map(|block| match block {
                    ContentBlock::Text { text } => text.len(),
                    ContentBlock::Thinking { text } => text.len(),
                    ContentBlock::ToolUse { input, .. } => input.to_string().len(),
                    ContentBlock::ToolResult { content, .. } => content.len(),
                    ContentBlock::Image { data, .. } => data.len(),
                })
                .sum();
            Ok((total_chars / 4) as u32)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "test-model".into(),
                name: "Test Model".into(),
                context_window: self.context_window,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    /// A simpler mock LLM that just reports model info and counts tokens.
    pub struct MockLlmBackend {
        context_window: u32,
    }

    impl MockLlmBackend {
        pub fn new(context_window: u32) -> Self {
            Self { context_window }
        }
    }

    #[async_trait]
    impl LlmBackend for MockLlmBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            Err(LlmError::InferenceError(
                "MockLlmBackend does not support complete".into(),
            ))
        }

        async fn count_tokens(&self, messages: &[Message]) -> Result<u32, LlmError> {
            let total_chars: usize = messages
                .iter()
                .flat_map(|m| &m.content)
                .map(|block| match block {
                    ContentBlock::Text { text } => text.len(),
                    ContentBlock::Thinking { text } => text.len(),
                    ContentBlock::ToolUse { input, .. } => input.to_string().len(),
                    ContentBlock::ToolResult { content, .. } => content.len(),
                    ContentBlock::Image { data, .. } => data.len(),
                })
                .sum();
            Ok((total_chars / 4) as u32)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "mock-model".into(),
                name: "Mock Model".into(),
                context_window: self.context_window,
                provider: "mock".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    /// In-memory session store for testing.
    pub struct InMemorySessionStore {
        sessions: Mutex<HashMap<String, Session>>,
        messages: Mutex<HashMap<String, Vec<Message>>>,
    }

    impl InMemorySessionStore {
        pub fn new() -> Self {
            Self {
                sessions: Mutex::new(HashMap::new()),
                messages: Mutex::new(HashMap::new()),
            }
        }

        /// Create a session with a specific agent_id (for testing isolation).
        pub async fn create_session_for_agent(
            &self,
            channel: &str,
            agent_id: AgentId,
        ) -> Result<Session, StorageError> {
            let session = Session {
                id: SessionId::new(),
                title: None,
                channel: channel.to_owned(),
                agent_id,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                archived: false,
            };
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id.as_str().to_owned(), session.clone());
            self.messages
                .lock()
                .unwrap()
                .insert(session.id.as_str().to_owned(), Vec::new());
            Ok(session)
        }
    }

    #[async_trait]
    impl SessionStore for InMemorySessionStore {
        async fn create_session(&self, channel: &str) -> Result<Session, StorageError> {
            let session = Session {
                id: SessionId::new(),
                title: None,
                channel: channel.to_owned(),
                agent_id: AgentId::default(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                archived: false,
            };
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id.as_str().to_owned(), session.clone());
            self.messages
                .lock()
                .unwrap()
                .insert(session.id.as_str().to_owned(), Vec::new());
            Ok(session)
        }

        async fn create_session_for_agent(
            &self,
            channel: &str,
            agent_id: &AgentId,
        ) -> Result<Session, StorageError> {
            InMemorySessionStore::create_session_for_agent(self, channel, agent_id.clone()).await
        }

        async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StorageError> {
            Ok(self.sessions.lock().unwrap().get(id.as_str()).cloned())
        }

        async fn list_sessions(
            &self,
            _filter: SessionFilter,
        ) -> Result<Vec<Session>, StorageError> {
            Ok(self.sessions.lock().unwrap().values().cloned().collect())
        }

        async fn rename_session(&self, id: &SessionId, title: &str) -> Result<(), StorageError> {
            let mut sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get_mut(id.as_str())
                .ok_or_else(|| StorageError::NotFound(format!("session {id}")))?;
            session.title = Some(title.to_owned());
            Ok(())
        }

        async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError> {
            self.sessions.lock().unwrap().remove(id.as_str());
            self.messages.lock().unwrap().remove(id.as_str());
            Ok(())
        }

        async fn append_message(
            &self,
            session_id: &SessionId,
            msg: &Message,
        ) -> Result<(), StorageError> {
            let mut messages = self.messages.lock().unwrap();
            messages
                .entry(session_id.as_str().to_owned())
                .or_default()
                .push(msg.clone());
            Ok(())
        }

        async fn get_messages(
            &self,
            session_id: &SessionId,
            pagination: Pagination,
        ) -> Result<Vec<Message>, StorageError> {
            let messages = self.messages.lock().unwrap();
            let msgs = messages
                .get(session_id.as_str())
                .cloned()
                .unwrap_or_default();
            let start = pagination.offset as usize;
            let end = (start + pagination.limit as usize).min(msgs.len());
            if start >= msgs.len() {
                return Ok(vec![]);
            }
            Ok(msgs[start..end].to_vec())
        }

        async fn compact_session(
            &self,
            session_id: &SessionId,
            keep_last: usize,
        ) -> Result<(), StorageError> {
            let mut messages = self.messages.lock().unwrap();
            if let Some(msgs) = messages.get_mut(session_id.as_str()) {
                if msgs.len() > keep_last {
                    let start = msgs.len() - keep_last;
                    *msgs = msgs[start..].to_vec();
                }
            }
            Ok(())
        }
    }

    /// Helper to create a simple text completion delta sequence (final answer).
    pub fn text_response(text: &str) -> Vec<CompletionDelta> {
        vec![CompletionDelta {
            text: Some(text.to_owned()),
            thinking: None,
            tool_use: None,
            finish_reason: Some(FinishReason::Stop),
        }]
    }

    /// Helper to create a tool_use delta sequence.
    pub fn tool_use_response(
        tool_id: &str,
        tool_name: &str,
        input_json: &str,
    ) -> Vec<CompletionDelta> {
        vec![CompletionDelta {
            text: None,
            thinking: None,
            tool_use: Some(encmind_core::traits::ToolUseDelta {
                id: tool_id.to_owned(),
                name: tool_name.to_owned(),
                input_json: input_json.to_owned(),
            }),
            finish_reason: Some(FinishReason::ToolUse),
        }]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use encmind_core::config::EgressFirewallConfig;
    use encmind_core::error::LlmError;
    use encmind_core::error::PluginError;
    use encmind_core::hooks::{HookHandler, HookPoint, HookRegistry, HookResult};
    use encmind_core::traits::{CompletionDelta, ModelInfo};

    use super::test_helpers::*;
    use super::*;
    use crate::tool_registry::test_helpers::{FailingSkill, TestEchoSkill};

    fn default_agent() -> AgentConfig {
        AgentConfig {
            id: AgentId::default(),
            name: "Test Agent".into(),
            model: None,
            workspace: None,
            system_prompt: Some("You are a test assistant.".into()),
            skills: vec![],
            is_default: true,
        }
    }

    fn make_user_msg(text: &str) -> Message {
        Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_owned(),
            }],
            created_at: Utc::now(),
            token_count: None,
        }
    }

    async fn setup_runtime(
        responses: Vec<Vec<encmind_core::traits::CompletionDelta>>,
        registry: ToolRegistry,
    ) -> (AgentRuntime, Arc<InMemorySessionStore>) {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                ..Default::default()
            },
        );

        (runtime, store)
    }

    fn make_firewall_config(
        domains: Vec<&str>,
        block_private_ranges: bool,
    ) -> EgressFirewallConfig {
        EgressFirewallConfig {
            enabled: true,
            mode: encmind_core::config::FirewallMode::default(),
            global_allowlist: domains.into_iter().map(String::from).collect(),
            block_private_ranges,
            per_agent_overrides: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn simple_text_response() {
        let (runtime, store) =
            setup_runtime(vec![text_response("Hello!")], ToolRegistry::new()).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("Hi"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.iterations, 1);
        assert!(result.tool_calls.is_empty());
        // Response should contain "Hello!"
        let text = match &result.response.content[0] {
            ContentBlock::Text { text } => text.as_str(),
            _ => panic!("expected text"),
        };
        assert_eq!(text, "Hello!");
    }

    #[tokio::test]
    async fn single_tool_use_round() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            // First LLM call: tool_use
            tool_use_response("t1", "echo", r#"{"text":"world"}"#),
            // Second LLM call: final text
            text_response("Done!"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("test"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.iterations, 2);
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].name, "echo");
        assert!(!result.tool_calls[0].is_error);
    }

    #[tokio::test]
    async fn tool_use_without_finish_reason_still_dispatches() {
        use encmind_core::traits::{CompletionDelta, ToolUseDelta};

        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            vec![CompletionDelta {
                text: None,
                thinking: None,
                tool_use: Some(ToolUseDelta {
                    id: "t1".into(),
                    name: "echo".into(),
                    input_json: r#"{"text":"world"}"#.into(),
                }),
                finish_reason: None,
            }],
            text_response("Done!"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("test"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.iterations, 2);
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].name, "echo");
    }

    #[tokio::test]
    async fn firewall_blocks_disallowed_tool_url() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response(
                "t1",
                "echo",
                r#"{"url":"https://evil.com/data","text":"hi"}"#,
            ),
            text_response("done"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let runtime = runtime.with_firewall(Arc::new(crate::firewall::EgressFirewall::new(
            &make_firewall_config(vec!["api.openai.com"], false),
        )));

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("test"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        assert!(
            result.tool_calls[0].output.contains("egress blocked"),
            "expected firewall block output: {}",
            result.tool_calls[0].output
        );
    }

    #[tokio::test]
    async fn firewall_allows_url_in_command_text_when_allowlisted() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response(
                "t1",
                "echo",
                r#"{"command":"curl https://example.com/path"}"#,
            ),
            text_response("done"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let runtime = runtime.with_firewall(Arc::new(crate::firewall::EgressFirewall::new(
            &make_firewall_config(vec!["example.com"], false),
        )));

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("test"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(!result.tool_calls[0].is_error);
        assert!(
            result.tool_calls[0].output.contains("example.com"),
            "tool should have executed for allowlisted URL"
        );
    }

    #[tokio::test]
    async fn multi_tool_rounds() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response("t1", "echo", r#"{"text":"first"}"#),
            tool_use_response("t2", "echo", r#"{"text":"second"}"#),
            text_response("All done"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("multi"),
                &default_agent(),
                cancel,
            )
            .await
            .unwrap();

        assert_eq!(result.iterations, 3);
        assert_eq!(result.tool_calls.len(), 2);
    }

    #[tokio::test]
    async fn iteration_limit_stops_loop() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        // Generate more tool use responses than the iteration limit
        let responses: Vec<_> = (0..15)
            .map(|i| tool_use_response(&format!("t{i}"), "echo", r#"{"text":"x"}"#))
            .collect();

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 5,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("loop"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.iterations, 5);
    }

    #[tokio::test]
    async fn cancellation_stops_run() {
        let responses = vec![text_response("should not reach")];

        let (runtime, store) = setup_runtime(responses, ToolRegistry::new()).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel(); // Cancel immediately

        let result = runtime
            .run(
                &session.id,
                make_user_msg("cancel"),
                &default_agent(),
                cancel,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cancelled"),
            "expected cancellation error: {err}"
        );
    }

    #[tokio::test]
    async fn llm_error_propagates() {
        // Empty response list causes error on first complete() call
        let (runtime, store) = setup_runtime(vec![], ToolRegistry::new()).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("error"),
                &default_agent(),
                cancel,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tool_error_becomes_error_result() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(FailingSkill)).unwrap();

        let responses = vec![
            tool_use_response("t1", "failing", "{}"),
            text_response("handled"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("fail"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        assert!(result.tool_calls[0].output.contains("Error"));
    }

    #[tokio::test]
    async fn messages_are_persisted() {
        let (runtime, store) =
            setup_runtime(vec![text_response("reply")], ToolRegistry::new()).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        runtime
            .run(
                &session.id,
                make_user_msg("persist"),
                &default_agent(),
                cancel,
            )
            .await
            .unwrap();

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();

        // user msg + assistant msg = 2
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, Role::User);
        assert_eq!(messages[1].role, Role::Assistant);
    }

    #[tokio::test]
    async fn tool_results_are_persisted() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response("t1", "echo", r#"{"text":"hi"}"#),
            text_response("done"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        runtime
            .run(&session.id, make_user_msg("tool"), &default_agent(), cancel)
            .await
            .unwrap();

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();

        // user + assistant(tool_use) + tool_result + assistant(text) = 4
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[0].role, Role::User);
        assert_eq!(messages[1].role, Role::Assistant);
        assert_eq!(messages[2].role, Role::Tool);
        assert_eq!(messages[3].role, Role::Assistant);
    }

    #[tokio::test]
    async fn thinking_preserved_in_response() {
        use encmind_core::traits::CompletionDelta;

        let responses = vec![vec![
            CompletionDelta {
                text: None,
                thinking: Some("Let me think...".into()),
                tool_use: None,
                finish_reason: None,
            },
            CompletionDelta {
                text: Some("The answer is 42.".into()),
                thinking: None,
                tool_use: None,
                finish_reason: Some(FinishReason::Stop),
            },
        ]];

        let (runtime, store) = setup_runtime(responses, ToolRegistry::new()).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("think"),
                &default_agent(),
                cancel,
            )
            .await
            .unwrap();

        let has_thinking = result
            .response
            .content
            .iter()
            .any(|b| matches!(b, ContentBlock::Thinking { text } if text == "Let me think..."));
        assert!(has_thinking, "thinking block should be preserved");

        let has_text = result
            .response
            .content
            .iter()
            .any(|b| matches!(b, ContentBlock::Text { text } if text == "The answer is 42."));
        assert!(has_text, "text block should be present");
    }

    #[tokio::test]
    async fn finish_reason_length_stops_loop() {
        use encmind_core::traits::CompletionDelta;

        let responses = vec![vec![CompletionDelta {
            text: Some("truncated...".into()),
            thinking: None,
            tool_use: None,
            finish_reason: Some(FinishReason::Length),
        }]];

        let (runtime, store) = setup_runtime(responses, ToolRegistry::new()).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("long"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.iterations, 1);
    }

    // ── Approval integration tests ─────────────────────────────────

    #[tokio::test]
    async fn deny_mode_blocks_bash_tool() {
        use crate::approval::ToolApprovalChecker;
        use encmind_core::config::BashMode;

        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response("t1", "bash.exec", r#"{"command":"ls"}"#),
            text_response("ok"),
        ];

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                ..Default::default()
            },
        )
        .with_approval(
            Arc::new(crate::approval::NoopApprovalHandler),
            ToolApprovalChecker::new(BashMode::Deny),
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("run"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        assert!(result.tool_calls[0]
            .output
            .contains("denied by security policy"));
    }

    #[tokio::test]
    async fn ask_mode_approval_denied() {
        use crate::approval::ToolApprovalChecker;
        use encmind_core::config::BashMode;

        struct DenyHandler;

        #[async_trait::async_trait]
        impl ApprovalHandler for DenyHandler {
            async fn request_approval(&self, _req: ApprovalRequest) -> ApprovalDecision {
                ApprovalDecision::Denied {
                    reason: "user said no".into(),
                }
            }
        }

        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response("t1", "bash.exec", r#"{"command":"rm -rf /"}"#),
            text_response("ok"),
        ];

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                ..Default::default()
            },
        )
        .with_approval(
            Arc::new(DenyHandler),
            ToolApprovalChecker::new(BashMode::Ask),
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("run"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        assert!(result.tool_calls[0].output.contains("user said no"));
    }

    #[tokio::test]
    async fn ask_mode_approval_granted() {
        use crate::approval::ToolApprovalChecker;
        use encmind_core::config::BashMode;

        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        // NoopApprovalHandler auto-approves. We also need echo registered
        // but bash.exec is not in the registry — the tool dispatch will fail
        // with "tool not found" which is fine; the point is the approval didn't block it.
        let responses = vec![
            tool_use_response("t1", "bash.exec", r#"{"command":"ls"}"#),
            text_response("ok"),
        ];

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                ..Default::default()
            },
        )
        .with_approval(
            Arc::new(crate::approval::NoopApprovalHandler),
            ToolApprovalChecker::new(BashMode::Ask),
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("run"), &default_agent(), cancel)
            .await
            .unwrap();

        // Tool was approved, then dispatch failed with "tool not found" (is_error)
        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        assert!(result.tool_calls[0].output.contains("tool not found"));
    }

    struct AbortBeforeToolHook;
    #[async_trait::async_trait]
    impl HookHandler for AbortBeforeToolHook {
        async fn execute(
            &self,
            _ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            Ok(HookResult::Abort {
                reason: "blocked".into(),
            })
        }
    }

    struct OverrideToolInputHook;
    #[async_trait::async_trait]
    impl HookHandler for OverrideToolInputHook {
        async fn execute(
            &self,
            _ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            Ok(HookResult::Override(
                serde_json::json!({"input": {"text": "rewritten"}}),
            ))
        }
    }

    struct OverrideToolOutputHook;
    #[async_trait::async_trait]
    impl HookHandler for OverrideToolOutputHook {
        async fn execute(
            &self,
            _ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            Ok(HookResult::Override(
                serde_json::json!({"output": "sanitized", "is_error": false}),
            ))
        }
    }

    struct AbortBeforeAgentStartHook;
    #[async_trait::async_trait]
    impl HookHandler for AbortBeforeAgentStartHook {
        async fn execute(
            &self,
            _ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            Ok(HookResult::Abort {
                reason: "blocked before start".into(),
            })
        }
    }

    struct OverrideBeforeAgentStartHook;
    #[async_trait::async_trait]
    impl HookHandler for OverrideBeforeAgentStartHook {
        async fn execute(
            &self,
            ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            let mut payload = ctx.payload.clone();
            payload["user_message"]["content"] = serde_json::json!([{
                "type": "text",
                "text": "rewritten prompt",
            }]);
            Ok(HookResult::Override(payload))
        }
    }

    struct OverrideAfterAgentCompleteHook;
    #[async_trait::async_trait]
    impl HookHandler for OverrideAfterAgentCompleteHook {
        async fn execute(
            &self,
            ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            let mut payload = ctx.payload.clone();
            payload["assistant_message"]["content"] = serde_json::json!([{
                "type": "text",
                "text": "overridden assistant",
            }]);
            Ok(HookResult::Override(payload))
        }
    }

    struct CaptureUserTextLlm {
        seen_user_text: Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl LlmBackend for CaptureUserTextLlm {
        async fn complete(
            &self,
            messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<
            std::pin::Pin<
                Box<dyn futures::Stream<Item = Result<CompletionDelta, LlmError>> + Send>,
            >,
            LlmError,
        > {
            let user_text = messages.iter().rev().find_map(|m| {
                if m.role != Role::User {
                    return None;
                }
                m.content.iter().find_map(|block| match block {
                    ContentBlock::Text { text } => Some(text.clone()),
                    _ => None,
                })
            });
            *self.seen_user_text.lock().unwrap() = user_text;

            let stream = tokio_stream::iter(vec![Ok(CompletionDelta {
                text: Some("ok".into()),
                thinking: None,
                tool_use: None,
                finish_reason: Some(FinishReason::Stop),
            })]);
            Ok(Box::pin(stream))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Ok(0)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "capture-llm".into(),
                name: "Capture LLM".into(),
                context_window: 32_768,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[tokio::test]
    async fn before_agent_start_hook_can_abort_run() {
        let (runtime, store) = setup_runtime(vec![text_response("ok")], ToolRegistry::new()).await;
        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::BeforeAgentStart,
                100,
                "test",
                Arc::new(AbortBeforeAgentStartHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let err = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("BeforeAgentStart"));
    }

    #[tokio::test]
    async fn before_agent_start_hook_can_override_user_message() {
        let seen_user_text = Arc::new(std::sync::Mutex::new(None));
        let llm: Arc<dyn LlmBackend> = Arc::new(CaptureUserTextLlm {
            seen_user_text: seen_user_text.clone(),
        });
        let store = Arc::new(InMemorySessionStore::new());
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        );

        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::BeforeAgentStart,
                100,
                "test",
                Arc::new(OverrideBeforeAgentStartHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        runtime
            .run(
                &session.id,
                make_user_msg("original"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(
            seen_user_text.lock().unwrap().as_deref(),
            Some("rewritten prompt")
        );
    }

    #[tokio::test]
    async fn after_agent_complete_hook_can_override_assistant_message() {
        let (runtime, store) = setup_runtime(
            vec![text_response("original assistant")],
            ToolRegistry::new(),
        )
        .await;
        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::AfterAgentComplete,
                100,
                "test",
                Arc::new(OverrideAfterAgentCompleteHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let result = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        let final_text = result
            .response
            .content
            .iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            });
        assert_eq!(final_text, Some("overridden assistant"));
    }

    #[tokio::test]
    async fn before_tool_call_hook_can_abort_run() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();
        let responses = vec![
            tool_use_response("t1", "echo", r#"{"text":"hello"}"#),
            text_response("ok"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::BeforeToolCall,
                100,
                "test",
                Arc::new(AbortBeforeToolHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let err = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("BeforeToolCall"));
    }

    #[tokio::test]
    async fn before_tool_call_hook_can_override_input() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();
        let responses = vec![
            tool_use_response("t1", "echo", r#"{"text":"hello"}"#),
            text_response("ok"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::BeforeToolCall,
                100,
                "test",
                Arc::new(OverrideToolInputHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let result = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].input["text"], "rewritten");
    }

    #[tokio::test]
    async fn after_tool_call_hook_can_override_output() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();
        let responses = vec![
            tool_use_response("t1", "echo", r#"{"text":"hello"}"#),
            text_response("ok"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::AfterToolCall,
                100,
                "test",
                Arc::new(OverrideToolOutputHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let result = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].output, "sanitized");
        assert!(!result.tool_calls[0].is_error);
    }

    // ── Isolation tests ────────────────────────────────────────────

    #[tokio::test]
    async fn session_agent_mismatch_rejected() {
        let (_runtime_base, store) =
            setup_runtime(vec![text_response("x")], ToolRegistry::new()).await;

        // Reconfigure with enforcement enabled
        let llm: Arc<dyn LlmBackend> =
            Arc::new(ScriptedLlmBackend::new(vec![text_response("x")], 128_000));
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                enforce_session_agent_match: true,
                ..Default::default()
            },
        );

        // Create session for agent "researcher"
        let session = store
            .create_session_for_agent("web", AgentId::new("researcher"))
            .await
            .unwrap();

        // Try to run with agent "main" — should fail
        let mut agent = default_agent();
        agent.id = AgentId::new("main");
        let cancel = CancellationToken::new();

        let err = runtime
            .run(&session.id, make_user_msg("hi"), &agent, cancel)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("belongs to agent"),
            "expected mismatch error: {err}"
        );
    }

    #[tokio::test]
    async fn session_agent_match_succeeds() {
        let llm: Arc<dyn LlmBackend> =
            Arc::new(ScriptedLlmBackend::new(vec![text_response("ok")], 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                enforce_session_agent_match: true,
                ..Default::default()
            },
        );

        let session = store
            .create_session_for_agent("web", AgentId::default())
            .await
            .unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("hi"), &default_agent(), cancel)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn workspace_dir_created() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("agent_workspace");
        assert!(!workspace.exists());

        let llm: Arc<dyn LlmBackend> =
            Arc::new(ScriptedLlmBackend::new(vec![text_response("ok")], 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                workspace_dir: Some(workspace.clone()),
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        runtime
            .run(&session.id, make_user_msg("hi"), &default_agent(), cancel)
            .await
            .unwrap();

        assert!(workspace.exists(), "workspace directory should be created");
    }

    // ── Compaction tests ───────────────────────────────────────────

    #[tokio::test]
    async fn compaction_triggered_above_threshold() {
        let llm: Arc<dyn LlmBackend> =
            Arc::new(ScriptedLlmBackend::new(vec![text_response("ok")], 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                compaction_threshold: Some(5),
                compaction_keep_last: 3,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();

        // Pre-populate with messages above threshold
        for i in 0..8 {
            let msg = Message {
                id: MessageId::new(),
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: format!("msg {i}"),
                }],
                created_at: Utc::now(),
                token_count: None,
            };
            store.append_message(&session.id, &msg).await.unwrap();
        }

        let cancel = CancellationToken::new();
        runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                cancel,
            )
            .await
            .unwrap();

        // After compaction, should have keep_last=3 messages (from the pre-existing 8 + user + assistant = 10, keep last 3)
        let msgs = store
            .get_messages(
                &session.id,
                Pagination {
                    offset: 0,
                    limit: 100,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            msgs.len(),
            3,
            "compaction should keep only last 3 messages, got {}",
            msgs.len()
        );
    }

    #[tokio::test]
    async fn compaction_not_triggered_below_threshold() {
        let llm: Arc<dyn LlmBackend> =
            Arc::new(ScriptedLlmBackend::new(vec![text_response("ok")], 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                compaction_threshold: Some(100),
                compaction_keep_last: 50,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        runtime
            .run(&session.id, make_user_msg("hi"), &default_agent(), cancel)
            .await
            .unwrap();

        // Only 2 messages (user + assistant), well below threshold 100
        let msgs = store
            .get_messages(
                &session.id,
                Pagination {
                    offset: 0,
                    limit: 100,
                },
            )
            .await
            .unwrap();
        assert_eq!(msgs.len(), 2);
    }

    // ── Memory integration tests ─────────────────────────────────

    #[tokio::test]
    async fn runtime_with_memory_injects_context() {
        use encmind_core::error::MemoryError;
        use encmind_core::traits::MemorySearchProvider;
        use encmind_core::types::{MemoryEntry, MemoryId, MemoryResult, MemorySource};

        struct StaticMemory;

        #[async_trait::async_trait]
        impl MemorySearchProvider for StaticMemory {
            async fn search_for_context(
                &self,
                _query: &str,
                _limit: usize,
            ) -> Result<Vec<MemoryResult>, MemoryError> {
                Ok(vec![MemoryResult {
                    entry: MemoryEntry {
                        id: MemoryId::new(),
                        session_id: None,
                        vector_point_id: "pt-1".into(),
                        summary: "User prefers dark mode".into(),
                        source_channel: Some("web".into()),
                        source_device: None,
                        created_at: chrono::Utc::now(),
                    },
                    score: 0.9,
                    source: MemorySource::Hybrid,
                }])
            }
        }

        let (runtime, store) =
            setup_runtime(vec![text_response("Got it!")], ToolRegistry::new()).await;
        let runtime = runtime.with_memory(Arc::new(StaticMemory));

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("What do I prefer?"),
                &default_agent(),
                cancel,
            )
            .await
            .unwrap();

        assert_eq!(result.iterations, 1);
    }

    #[tokio::test]
    async fn runtime_without_memory_works() {
        let (runtime, store) =
            setup_runtime(vec![text_response("Hello!")], ToolRegistry::new()).await;
        // No memory attached
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("Hi"), &default_agent(), cancel)
            .await
            .unwrap();

        assert_eq!(result.iterations, 1);
    }

    // ── Token optimization tests ─────────────────────────────────

    #[test]
    fn default_max_tool_iterations_is_20() {
        assert_eq!(RuntimeConfig::default().max_tool_iterations, 20);
    }

    #[test]
    fn default_config_enables_compaction() {
        assert_eq!(RuntimeConfig::default().compaction_threshold, Some(100));
    }

    #[test]
    fn truncate_tool_output_not_truncated_when_under_limit() {
        let output = "short output";
        let result = AgentRuntime::truncate_tool_output(output, 100);
        assert_eq!(result, output);
    }

    #[test]
    fn truncate_tool_output_truncated_when_over_limit() {
        let output = "x".repeat(200);
        let result = AgentRuntime::truncate_tool_output(&output, 50);
        assert!(result.contains("[truncated from 200 chars to 50]"));
        // The truncated part should have 50 x's + the notice
        assert!(result.starts_with(&"x".repeat(50)));
    }

    #[tokio::test]
    async fn tool_output_truncated_in_message_but_full_in_record() {
        use crate::tool_registry::test_helpers::TestEchoSkill;

        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        // Echo returns serde_json::to_string(&input), which for a large text field
        // will be the JSON serialization. Create input that produces large output.
        let large_text = "x".repeat(50_000);
        let input_json = serde_json::json!({"text": large_text}).to_string();

        let responses = vec![
            tool_use_response("t1", "echo", &input_json),
            text_response("Done"),
        ];

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                max_tool_output_chars: 100,
                compaction_threshold: None,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("test"), &default_agent(), cancel)
            .await
            .unwrap();

        // ToolCallRecord should have the full output
        assert_eq!(result.tool_calls.len(), 1);
        assert!(
            result.tool_calls[0].output.len() > 100,
            "audit record should have full output"
        );

        // The persisted Tool message should have truncated content
        let messages = store
            .get_messages(
                &session.id,
                encmind_core::types::Pagination {
                    offset: 0,
                    limit: 100,
                },
            )
            .await
            .unwrap();
        let tool_msg = messages.iter().find(|m| m.role == Role::Tool).unwrap();
        match &tool_msg.content[0] {
            ContentBlock::ToolResult { content, .. } => {
                assert!(
                    content.contains("[truncated from"),
                    "persisted message should be truncated, got: {}",
                    &content[..content.len().min(200)]
                );
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[tokio::test]
    async fn per_tool_limit_overrides_global_limit() {
        use crate::tool_registry::test_helpers::TestEchoSkill;

        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let large_text = "y".repeat(1_000);
        let input_json = serde_json::json!({"text": large_text}).to_string();

        let responses = vec![
            tool_use_response("t1", "echo", &input_json),
            text_response("Done"),
        ];

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let mut per_tool = HashMap::new();
        per_tool.insert("echo".to_string(), 50_usize);

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                max_tool_output_chars: 100_000, // global is very large
                per_tool_output_chars: per_tool,
                compaction_threshold: None,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(&session.id, make_user_msg("test"), &default_agent(), cancel)
            .await
            .unwrap();

        // Full output in audit record
        assert!(result.tool_calls[0].output.len() > 50);

        // Persisted message should be truncated to per-tool limit of 50
        let messages = store
            .get_messages(
                &session.id,
                encmind_core::types::Pagination {
                    offset: 0,
                    limit: 100,
                },
            )
            .await
            .unwrap();
        let tool_msg = messages.iter().find(|m| m.role == Role::Tool).unwrap();
        match &tool_msg.content[0] {
            ContentBlock::ToolResult { content, .. } => {
                assert!(
                    content.contains("[truncated from"),
                    "per-tool limit should truncate, got: {}",
                    &content[..content.len().min(200)]
                );
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[tokio::test]
    async fn non_object_tool_use_input_is_coerced_to_object() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        let responses = vec![
            tool_use_response("t1", "echo", r#""/tmp/austin-eyedrop.pdf""#),
            text_response("Done"),
        ];

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                max_tool_iterations: 10,
                compaction_threshold: None,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("summarize austin-eyedrop.pdf"),
                &default_agent(),
                cancel,
            )
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(
            result.tool_calls[0].input.is_object(),
            "tool call input should be coerced to object"
        );

        let messages = store
            .get_messages(
                &session.id,
                encmind_core::types::Pagination {
                    offset: 0,
                    limit: 100,
                },
            )
            .await
            .unwrap();

        let assistant_tool_use = messages
            .iter()
            .flat_map(|m| m.content.iter())
            .find_map(|b| match b {
                ContentBlock::ToolUse { input, .. } => Some(input),
                _ => None,
            })
            .expect("assistant tool_use block should exist");

        assert!(
            assistant_tool_use.is_object(),
            "persisted tool_use.input should be object for Anthropic compatibility"
        );
    }
}
