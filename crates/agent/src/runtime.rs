use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::{FutureExt, StreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use encmind_core::error::{AppError, LlmError, PluginError};
use encmind_core::hooks::{HookContext, HookPoint, HookRegistry, HookResult};
use encmind_core::traits::{
    ApprovalHandler, CompletionParams, FinishReason, LlmBackend, MemorySearchProvider,
    SessionStore, ToolInterruptBehavior,
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
    /// Max parallel dispatch fanout for concurrent-safe tools.
    /// Values <= 1 disable safe-tool parallelism.
    pub max_parallel_safe_tools: usize,
    /// Optional per-tool interrupt behavior overrides.
    ///
    /// This can override behavior for any registered tool name (internal,
    /// MCP, or skill), not just internal handlers.
    pub per_tool_interrupt_behavior: HashMap<String, ToolInterruptBehavior>,
    /// How long to wait for a `Block` tool to finish after cancellation
    /// before fail-closing with an error result.
    pub blocking_tool_cancel_grace: Duration,
    /// Workspace trust configuration. When set, tools are filtered based on
    /// whether `workspace_dir` is in the trusted set.
    pub workspace_trust: encmind_core::config::WorkspaceTrustConfig,
    /// Priority class for this run. Used by subagent spawns so that a
    /// background parent (e.g. cron) does not escalate its children to
    /// interactive priority. The top-level entrypoint is scheduled by
    /// the pool directly — this field only affects nested spawns.
    pub query_class: crate::scheduler::QueryClass,
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
            max_parallel_safe_tools: DEFAULT_MAX_PARALLEL_SAFE_TOOLS,
            per_tool_interrupt_behavior: HashMap::new(),
            blocking_tool_cancel_grace: Duration::from_secs(10),
            workspace_trust: encmind_core::config::WorkspaceTrustConfig::default(),
            query_class: crate::scheduler::QueryClass::Interactive,
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
    /// Set when governance denied the call. Carries typed provenance
    /// (source subsystem, optional rule id, reason, input fingerprint).
    pub decision: Option<encmind_core::permission::PermissionDecision>,
}

/// Streaming events emitted during an agent run.
///
/// These are sent to the client as they happen, before the run completes.
/// The final event is either `Done` or `Error`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatEvent {
    /// Streaming text delta from the LLM.
    Delta { text: String },
    /// Thinking/reasoning delta (if thinking is enabled).
    Thinking { text: String },
    /// A tool call is about to start.
    ToolStart {
        tool_use_id: String,
        tool_name: String,
        input: serde_json::Value,
    },
    /// Progress update from a long-running tool, emitted between
    /// `ToolStart` and `ToolComplete`. Tools opt in by sending into
    /// the `ToolProgressSink` task-local; clients can render a
    /// live status line (e.g. "fetching…", "parsing… 42%").
    ToolProgress {
        tool_use_id: String,
        tool_name: String,
        /// Short human-readable status message.
        message: String,
        /// Optional progress fraction in `[0.0, 1.0]`. `None` means
        /// the tool has no known total and is reporting unbounded
        /// progress (e.g. "connected… received 2.3MB…").
        #[serde(skip_serializing_if = "Option::is_none")]
        fraction: Option<f32>,
    },
    /// A tool call completed (success or error).
    ToolComplete {
        tool_use_id: String,
        tool_name: String,
        output: String,
        is_error: bool,
    },
    /// The agent run completed.
    Done {
        stop_reason: StopReason,
        input_tokens: u32,
        output_tokens: u32,
        total_tokens: u32,
        iterations: u32,
    },
    /// An error occurred during the run.
    Error { message: String },
}

/// Why the agent run stopped.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// LLM finished generating (no more tool calls).
    EndTurn,
    /// Max iterations reached.
    MaxIterations,
    /// Cancelled by user.
    Cancelled,
    /// Loop detector triggered.
    LoopDetected { reason: String },
    /// An error terminated the run.
    Error,
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
    /// True when the run stopped because max_tool_iterations was reached.
    pub reached_max_iterations: bool,
    /// True when the run was cancelled by user/token.
    pub cancelled: bool,
}

const DEFAULT_MAX_PARALLEL_SAFE_TOOLS: usize = 4;
const MAX_PARALLEL_SAFE_TOOLS_CAP: usize = 16;

enum PreparedToolCall {
    Ready {
        input: serde_json::Value,
    },
    Finalized {
        input: serde_json::Value,
        output: String,
        is_error: bool,
        decision: Option<encmind_core::permission::PermissionDecision>,
    },
}

struct CompletedToolCall {
    tool_use_id: String,
    tool_name: String,
    input: serde_json::Value,
    output: String,
    is_error: bool,
    decision: Option<encmind_core::permission::PermissionDecision>,
}

struct DenyHookDetails<'a> {
    output: &'a str,
    decision: &'a encmind_core::permission::PermissionDecision,
    risk_level: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct RunAccounting {
    input_tokens: u32,
    output_tokens: u32,
    total_tokens: u32,
    iteration: u32,
}

struct SafeBatchState<'a> {
    tool_calls: &'a mut Vec<ToolCallRecord>,
    loop_detector: &'a mut crate::loop_detector::LoopDetector,
    event_tx: &'a Option<tokio::sync::mpsc::Sender<ChatEvent>>,
    cancel: &'a CancellationToken,
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

    /// Cheap clone for streaming — all fields are Arc-wrapped.
    fn clone_for_streaming(&self) -> Self {
        Self {
            llm: self.llm.clone(),
            session_store: self.session_store.clone(),
            tool_registry: self.tool_registry.clone(),
            firewall: self.firewall.clone(),
            context_manager: self.context_manager.clone(),
            config: self.config.clone(),
            approval_handler: self.approval_handler.clone(),
            approval_checker: self.approval_checker.clone(),
            hook_registry: self.hook_registry.clone(),
        }
    }

    fn prompt_visible_tools(&self) -> Vec<String> {
        let trust_level = crate::workspace_trust::evaluate_trust(
            self.config.workspace_dir.as_deref(),
            &self.config.workspace_trust,
        );
        self.tool_registry
            .tool_names()
            .into_iter()
            .filter(|tool_name| crate::workspace_trust::is_tool_allowed(tool_name, trust_level))
            .filter(|tool_name| {
                self.approval_checker
                    .as_ref()
                    .map(|checker| !checker.is_denied(tool_name))
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Run a single user turn, streaming events as they happen.
    ///
    /// Returns a receiver that yields `ChatEvent`s in real-time:
    /// `Delta` / `Thinking` as the LLM generates, `ToolStart` / `ToolComplete`
    /// as tools execute, and `Done` or `Error` when the run finishes.
    ///
    /// The `RunResult` is still returned as the function's return value after
    /// all events have been sent (for backward-compatible callers that need it).
    pub fn run_streaming(
        &self,
        session_id: SessionId,
        user_message: Message,
        agent_config: AgentConfig,
        cancel: CancellationToken,
    ) -> (
        tokio::sync::mpsc::Receiver<ChatEvent>,
        tokio::task::JoinHandle<Result<RunResult, AppError>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let runtime = self.clone_for_streaming();
        let sid = session_id.clone();
        let handle = tokio::spawn(async move {
            let result = runtime
                .run_inner(&sid, user_message, &agent_config, cancel, Some(tx.clone()))
                .await;
            // Send final event.
            match &result {
                Ok(run_result) => {
                    let stop_reason = if run_result.cancelled {
                        StopReason::Cancelled
                    } else if run_result.loop_break.is_some() {
                        StopReason::LoopDetected {
                            reason: run_result.loop_break.clone().unwrap_or_default(),
                        }
                    } else if run_result.reached_max_iterations {
                        StopReason::MaxIterations
                    } else {
                        StopReason::EndTurn
                    };
                    let _ = tx
                        .send(ChatEvent::Done {
                            stop_reason,
                            input_tokens: run_result.input_tokens,
                            output_tokens: run_result.output_tokens,
                            total_tokens: run_result.total_tokens,
                            iterations: run_result.iterations,
                        })
                        .await;
                }
                Err(e) => {
                    let _ = tx
                        .send(ChatEvent::Error {
                            message: e.to_string(),
                        })
                        .await;
                }
            }
            result
        });
        (rx, handle)
    }

    /// Run a single user turn through the full conversation loop.
    pub async fn run(
        &self,
        session_id: &SessionId,
        user_message: Message,
        agent_config: &AgentConfig,
        cancel: CancellationToken,
    ) -> Result<RunResult, AppError> {
        self.run_inner(session_id, user_message, agent_config, cancel, None)
            .await
    }

    /// Internal run implementation that optionally emits streaming events.
    async fn run_inner(
        &self,
        session_id: &SessionId,
        user_message: Message,
        agent_config: &AgentConfig,
        cancel: CancellationToken,
        event_tx: Option<tokio::sync::mpsc::Sender<ChatEvent>>,
    ) -> Result<RunResult, AppError> {
        // Bind the run's priority class to a task-local so nested tool
        // handlers (SpawnAgentHandler in particular) can read it when
        // acquiring agent-pool permits. The scope lasts exactly one
        // run; subagent invocations run within the same task and
        // therefore inherit it automatically.
        let class = self.config.query_class;
        crate::scheduler::CURRENT_QUERY_CLASS
            .scope(
                class,
                self.run_inner_body(session_id, user_message, agent_config, cancel, event_tx),
            )
            .await
    }

    async fn run_inner_body(
        &self,
        session_id: &SessionId,
        user_message: Message,
        agent_config: &AgentConfig,
        cancel: CancellationToken,
        event_tx: Option<tokio::sync::mpsc::Sender<ChatEvent>>,
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
                let result = Self::make_cancelled_result(
                    last_response,
                    tool_calls,
                    input_tokens,
                    output_tokens,
                    total_tokens,
                    iteration,
                );
                self.maybe_compact(session_id).await;
                return Ok(result);
            }

            // 2a. Build context
            let available_tools = self.prompt_visible_tools();
            let (mut context, max_output) = self
                .context_manager
                .build_context(
                    session_id,
                    agent_config,
                    &self.session_store,
                    &self.llm,
                    &available_tools,
                )
                .await?;

            // 2b. Normalize messages before token counting and LLM call.
            // Must run before count_tokens so telemetry reflects actual payload.
            let norm_report = crate::message_validation::normalize_for_api(&mut context);
            if norm_report.tool_use_inputs_coerced > 0
                || norm_report.orphaned_tool_results_removed > 0
                || norm_report.consecutive_roles_merged > 0
                || norm_report.empty_messages_removed > 0
                || norm_report.role_incompatible_blocks_dropped > 0
                || norm_report.synthetic_tool_results_injected > 0
                || norm_report.duplicate_tool_uses_removed > 0
                || norm_report.duplicate_tool_results_removed > 0
            {
                tracing::info!(
                    coerced = norm_report.tool_use_inputs_coerced,
                    orphans = norm_report.orphaned_tool_results_removed,
                    merged = norm_report.consecutive_roles_merged,
                    empty = norm_report.empty_messages_removed,
                    role_drops = norm_report.role_incompatible_blocks_dropped,
                    synthetics = norm_report.synthetic_tool_results_injected,
                    dup_uses = norm_report.duplicate_tool_uses_removed,
                    dup_results = norm_report.duplicate_tool_results_removed,
                    "message normalization applied before LLM call"
                );
            }

            let prompt_tokens = match self.llm.count_tokens(&context).await {
                Ok(tokens) => tokens,
                Err(e) => {
                    warn!(error = %e, "failed to count prompt tokens");
                    0
                }
            };
            input_tokens = input_tokens.saturating_add(prompt_tokens);
            total_tokens = total_tokens.saturating_add(prompt_tokens);

            // 2c. Call LLM
            let params = CompletionParams {
                model: agent_config.model.clone(),
                max_tokens: max_output,
                tools: available_tools
                    .iter()
                    .filter_map(|name| self.tool_registry.tool_definition(name))
                    .collect(),
                ..Default::default()
            };

            let stream = match self.llm.complete(&context, params, cancel.clone()).await {
                Ok(stream) => stream,
                Err(e) => {
                    if cancel.is_cancelled() || matches!(e, LlmError::Cancelled) {
                        let result = Self::make_cancelled_result(
                            last_response,
                            tool_calls,
                            input_tokens,
                            output_tokens,
                            total_tokens,
                            iteration + 1,
                        );
                        self.maybe_compact(session_id).await;
                        return Ok(result);
                    }
                    return Err(e.into());
                }
            };

            // 2c. Collect streaming response
            let mut text_buf = String::new();
            let mut thinking_buf = String::new();
            let mut tool_uses: Vec<(String, String, String)> = Vec::new(); // (id, name, input_json)
            let mut finish_reason = None;

            tokio::pin!(stream);
            while let Some(delta_result) = stream.next().await {
                let delta = match delta_result {
                    Ok(delta) => delta,
                    Err(e) => {
                        if cancel.is_cancelled() || matches!(e, LlmError::Cancelled) {
                            let partial_chars = text_buf
                                .len()
                                .saturating_add(thinking_buf.len())
                                .saturating_add(
                                    tool_uses
                                        .iter()
                                        .map(|(id, name, input_json)| {
                                            id.len() + name.len() + input_json.len()
                                        })
                                        .sum::<usize>(),
                                );
                            let partial_tokens = (partial_chars / 4) as u32;
                            output_tokens = output_tokens.saturating_add(partial_tokens);
                            total_tokens = total_tokens.saturating_add(partial_tokens);
                            let result = Self::make_cancelled_result(
                                last_response,
                                tool_calls,
                                input_tokens,
                                output_tokens,
                                total_tokens,
                                iteration + 1,
                            );
                            self.maybe_compact(session_id).await;
                            return Ok(result);
                        }
                        return Err(e.into());
                    }
                };
                if let Some(ref text) = delta.text {
                    text_buf.push_str(text);
                    if let Some(ref tx) = event_tx {
                        Self::emit_delta_event(tx, ChatEvent::Delta { text: text.clone() });
                    }
                }
                if let Some(ref thinking) = delta.thinking {
                    thinking_buf.push_str(thinking);
                    if let Some(ref tx) = event_tx {
                        Self::emit_delta_event(
                            tx,
                            ChatEvent::Thinking {
                                text: thinking.clone(),
                            },
                        );
                    }
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

                // Run tools in original model order.
                // Contiguous concurrent-safe tools are executed as bounded
                // parallel batches, then their results are persisted in order.
                let mut safe_batch: Vec<(String, String, serde_json::Value)> = Vec::new();
                for (id, name, parsed_input) in &parsed_tool_uses {
                    if self.tool_registry.is_tool_concurrent_safe(name) {
                        safe_batch.push((id.clone(), name.clone(), parsed_input.clone()));
                        continue;
                    }

                    if !safe_batch.is_empty() {
                        let mut safe_batch_state = SafeBatchState {
                            tool_calls: &mut tool_calls,
                            loop_detector: &mut loop_detector,
                            event_tx: &event_tx,
                            cancel: &cancel,
                        };
                        let safe_batch_result = self
                            .execute_safe_batch(
                                session_id,
                                &agent_config.id,
                                &safe_batch,
                                &mut safe_batch_state,
                            )
                            .await;
                        let maybe_violation = match safe_batch_result {
                            Ok(v) => v,
                            Err(e) if Self::is_cancelled_app_error(&e) || cancel.is_cancelled() => {
                                let result = Self::make_cancelled_result(
                                    last_response,
                                    tool_calls,
                                    input_tokens,
                                    output_tokens,
                                    total_tokens,
                                    iteration + 1,
                                );
                                self.maybe_compact(session_id).await;
                                return Ok(result);
                            }
                            Err(e) => return Err(e),
                        };

                        if let Some(violation) = maybe_violation {
                            return self
                                .build_loop_break_result(
                                    session_id,
                                    tool_calls,
                                    RunAccounting {
                                        input_tokens,
                                        output_tokens,
                                        total_tokens,
                                        iteration,
                                    },
                                    violation,
                                )
                                .await;
                        }
                        safe_batch.clear();
                    }

                    match self
                        .prepare_tool_call(session_id, &agent_config.id, name, parsed_input)
                        .await
                    {
                        Ok(PreparedToolCall::Finalized {
                            input,
                            output,
                            is_error,
                            decision,
                        }) => {
                            Self::emit_tool_start_event(&event_tx, id, name, &input).await;
                            self.persist_completed_tool_call(
                                session_id,
                                &mut tool_calls,
                                CompletedToolCall {
                                    tool_use_id: (*id).clone(),
                                    tool_name: (*name).clone(),
                                    input,
                                    output,
                                    is_error,
                                    decision,
                                },
                                &event_tx,
                            )
                            .await?;
                            if let Some(violation) = loop_detector.record_and_check(name, is_error)
                            {
                                return self
                                    .build_loop_break_result(
                                        session_id,
                                        tool_calls,
                                        RunAccounting {
                                            input_tokens,
                                            output_tokens,
                                            total_tokens,
                                            iteration,
                                        },
                                        violation,
                                    )
                                    .await;
                            }
                        }
                        Ok(PreparedToolCall::Ready { input }) => {
                            Self::emit_tool_start_event(&event_tx, id, name, &input).await;
                            let interrupt_behavior = self.resolve_tool_interrupt_behavior(name);
                            let (output, is_error, decision) = if cancel.is_cancelled()
                                && matches!(interrupt_behavior, ToolInterruptBehavior::Cancel)
                            {
                                ("Error: request cancelled".to_string(), true, None)
                            } else {
                                // Scope a ToolProgress sink around the dispatch so
                                // long-running handlers can emit intermediate status
                                // updates via `tool_progress::report_progress`.
                                Self::dispatch_with_progress_scope(
                                    &event_tx,
                                    id,
                                    name,
                                    async {
                                        let mut dispatch_future =
                                            Box::pin(self.tool_registry.dispatch(
                                                name,
                                                input.clone(),
                                                session_id,
                                                &agent_config.id,
                                            ));
                                        match interrupt_behavior {
                                            ToolInterruptBehavior::Cancel => {
                                                tokio::select! {
                                                    _ = cancel.cancelled() => ("Error: request cancelled".to_string(), true, None),
                                                    result = dispatch_future.as_mut() => Self::normalize_dispatch_outcome(name, &input, result),
                                                }
                                            }
                                            ToolInterruptBehavior::Block => {
                                                tokio::select! {
                                                    result = dispatch_future.as_mut() => Self::normalize_dispatch_outcome(name, &input, result),
                                                    _ = cancel.cancelled() => {
                                                        self.await_blocking_dispatch_with_grace(name, &input, &mut dispatch_future).await
                                                    },
                                                }
                                            }
                                        }
                                    },
                                )
                                .await
                            };

                            let (output, is_error, decision) = match self
                                .apply_after_tool_call_hook(
                                    session_id,
                                    &agent_config.id,
                                    name,
                                    &input,
                                    output,
                                    is_error,
                                    decision.as_ref(),
                                )
                                .await
                            {
                                Ok((hook_output, hook_error)) => {
                                    let decision = if hook_error { decision } else { None };
                                    (hook_output, hook_error, decision)
                                }
                                Err(e) => {
                                    self.persist_completed_tool_call(
                                        session_id,
                                        &mut tool_calls,
                                        CompletedToolCall {
                                            tool_use_id: (*id).clone(),
                                            tool_name: (*name).clone(),
                                            input: input.clone(),
                                            output: format!("Error: hook aborted — {e}"),
                                            is_error: true,
                                            decision: None,
                                        },
                                        &event_tx,
                                    )
                                    .await?;
                                    return Err(e);
                                }
                            };

                            self.persist_completed_tool_call(
                                session_id,
                                &mut tool_calls,
                                CompletedToolCall {
                                    tool_use_id: (*id).clone(),
                                    tool_name: (*name).clone(),
                                    input,
                                    output,
                                    is_error,
                                    decision,
                                },
                                &event_tx,
                            )
                            .await?;

                            if let Some(violation) = loop_detector.record_and_check(name, is_error)
                            {
                                return self
                                    .build_loop_break_result(
                                        session_id,
                                        tool_calls,
                                        RunAccounting {
                                            input_tokens,
                                            output_tokens,
                                            total_tokens,
                                            iteration,
                                        },
                                        violation,
                                    )
                                    .await;
                            }
                        }
                        Err(e) => {
                            Self::emit_tool_start_event(&event_tx, id, name, parsed_input).await;
                            self.persist_completed_tool_call(
                                session_id,
                                &mut tool_calls,
                                CompletedToolCall {
                                    tool_use_id: (*id).clone(),
                                    tool_name: (*name).clone(),
                                    input: parsed_input.clone(),
                                    output: format!("Error: hook aborted — {e}"),
                                    is_error: true,
                                    decision: None,
                                },
                                &event_tx,
                            )
                            .await?;
                            return Err(e);
                        }
                    }
                }

                if !safe_batch.is_empty() {
                    let mut safe_batch_state = SafeBatchState {
                        tool_calls: &mut tool_calls,
                        loop_detector: &mut loop_detector,
                        event_tx: &event_tx,
                        cancel: &cancel,
                    };
                    let safe_batch_result = self
                        .execute_safe_batch(
                            session_id,
                            &agent_config.id,
                            &safe_batch,
                            &mut safe_batch_state,
                        )
                        .await;
                    let maybe_violation = match safe_batch_result {
                        Ok(v) => v,
                        Err(e) if Self::is_cancelled_app_error(&e) || cancel.is_cancelled() => {
                            let result = Self::make_cancelled_result(
                                last_response,
                                tool_calls,
                                input_tokens,
                                output_tokens,
                                total_tokens,
                                iteration + 1,
                            );
                            self.maybe_compact(session_id).await;
                            return Ok(result);
                        }
                        Err(e) => return Err(e),
                    };

                    if let Some(violation) = maybe_violation {
                        return self
                            .build_loop_break_result(
                                session_id,
                                tool_calls,
                                RunAccounting {
                                    input_tokens,
                                    output_tokens,
                                    total_tokens,
                                    iteration,
                                },
                                violation,
                            )
                            .await;
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
                reached_max_iterations: false,
                cancelled: false,
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
            reached_max_iterations: true,
            cancelled: false,
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

    async fn emit_tool_start_event(
        event_tx: &Option<tokio::sync::mpsc::Sender<ChatEvent>>,
        tool_use_id: &str,
        tool_name: &str,
        input: &serde_json::Value,
    ) {
        if let Some(tx) = event_tx {
            let stream_input = Self::truncate_stream_event_input(input);
            Self::emit_event(
                tx,
                ChatEvent::ToolStart {
                    tool_use_id: tool_use_id.to_owned(),
                    tool_name: tool_name.to_owned(),
                    input: stream_input,
                },
            )
            .await;
        }
    }

    async fn emit_tool_complete_event(
        event_tx: &Option<tokio::sync::mpsc::Sender<ChatEvent>>,
        tool_use_id: &str,
        tool_name: &str,
        output: &str,
        is_error: bool,
    ) {
        if let Some(tx) = event_tx {
            Self::emit_event(
                tx,
                ChatEvent::ToolComplete {
                    tool_use_id: tool_use_id.to_owned(),
                    tool_name: tool_name.to_owned(),
                    output: Self::truncate_stream_event_output(output),
                    is_error,
                },
            )
            .await;
        }
    }

    /// Wrap a dispatch future in a `TOOL_PROGRESS_SINK` scope and,
    /// when an `event_tx` is present, spawn a forwarder that turns
    /// `ProgressUpdate`s from handlers into `ChatEvent::ToolProgress`
    /// events on the streaming channel. When no streaming channel is
    /// attached, progress updates are still accepted by the sink and
    /// silently dropped (zero overhead beyond an mpsc channel create).
    ///
    /// The scope is tightly bound to the dispatch future: when the
    /// future completes, the sink sender is dropped, the forwarder's
    /// `recv()` returns `None`, and the forwarder task exits.
    async fn dispatch_with_progress_scope<F, T>(
        event_tx: &Option<tokio::sync::mpsc::Sender<ChatEvent>>,
        tool_use_id: &str,
        tool_name: &str,
        fut: F,
    ) -> T
    where
        F: std::future::Future<Output = T>,
    {
        use crate::tool_progress::{ProgressUpdate, TOOL_PROGRESS_SINK};
        const PROGRESS_BUFFER: usize = 16;

        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::channel::<ProgressUpdate>(PROGRESS_BUFFER);
        let forwarder = event_tx.clone().map(|tx| {
            let tool_use_id = tool_use_id.to_string();
            let tool_name = tool_name.to_string();
            tokio::spawn(async move {
                while let Some(update) = progress_rx.recv().await {
                    // Best-effort: never await here. A full channel must not
                    // stall tool completion while waiting on client I/O.
                    Self::emit_delta_event(
                        &tx,
                        ChatEvent::ToolProgress {
                            tool_use_id: tool_use_id.clone(),
                            tool_name: tool_name.clone(),
                            message: update.message,
                            fraction: update.fraction,
                        },
                    );
                }
            })
        });

        let result = TOOL_PROGRESS_SINK.scope(progress_tx, fut).await;

        if let Some(handle) = forwarder {
            let _ = handle.await;
        }
        result
    }

    async fn emit_remaining_safe_batch_completions(
        event_tx: &Option<tokio::sync::mpsc::Sender<ChatEvent>>,
        prepared: &[(String, String, PreparedToolCall)],
        start_order: usize,
        output: &str,
    ) {
        for (tool_use_id, tool_name, _) in prepared.iter().skip(start_order) {
            Self::emit_tool_complete_event(event_tx, tool_use_id, tool_name, output, true).await;
        }
    }

    /// Compatibility view of a `PermissionDecision`: prefer `rule_id`,
    /// fall back to the source name. Emitted as the legacy flat
    /// `deny_reason` field on hook payloads and chat.send responses
    /// so existing consumers of the pre-structured contract keep
    /// working. Will be removed in a future major revision.
    fn legacy_deny_reason(decision: &encmind_core::permission::PermissionDecision) -> String {
        decision
            .rule_id
            .clone()
            .unwrap_or_else(|| decision.source.as_str().to_string())
    }

    async fn invoke_after_tool_call_deny_hook(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
        tool_name: &str,
        input: &serde_json::Value,
        details: DenyHookDetails<'_>,
    ) {
        use encmind_core::hooks::ToolOutcome;
        let decision_value =
            serde_json::to_value(details.decision).unwrap_or(serde_json::Value::Null);
        let legacy_reason = Self::legacy_deny_reason(details.decision);
        let mut payload = serde_json::json!({
            "tool_name": tool_name,
            "input": input.clone(),
            "output": details.output,
            "is_error": true,
            "outcome": ToolOutcome::Denied.as_str(),
            "decision": decision_value,
            // Deprecated: kept during the structured-decision transition.
            // Prefer `decision.rule_id` / `decision.source`.
            "deny_reason": legacy_reason,
        });
        if let Some(level) = details.risk_level {
            payload["risk_level"] = serde_json::Value::String(level.to_owned());
        }
        let _ = self
            .execute_hook(
                HookPoint::AfterToolCall,
                session_id,
                agent_id,
                Some(tool_name.to_owned()),
                payload,
            )
            .await;
    }

    async fn prepare_tool_call(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
        tool_name: &str,
        parsed_input: &serde_json::Value,
    ) -> Result<PreparedToolCall, AppError> {
        use encmind_core::permission::{DecisionSource, PermissionDecision};
        let mut input = parsed_input.clone();
        // Resolve aliases once for governance decisions so local-vs-node and
        // allow/deny checks use canonical tool identity.
        let policy_tool_name = self.tool_registry.canonical_tool_name(tool_name);

        // Governance step 1: immutable deny-list.
        let risk = crate::risk_classifier::classify_tool_risk(policy_tool_name, &input, session_id);
        if risk.level == crate::risk_classifier::ToolRiskLevel::Denied {
            warn!(
                tool = %policy_tool_name,
                requested_tool = %tool_name,
                reason = %risk.reason,
                "tool call blocked by immutable deny-list"
            );
            let output = format!(
                "Error: operation denied by security policy — {}",
                risk.reason
            );
            let decision = PermissionDecision::new(DecisionSource::RiskClassifier, risk.reason)
                .with_rule_id("immutable_deny_list")
                .with_input_fingerprint(&input);
            self.invoke_after_tool_call_deny_hook(
                session_id,
                agent_id,
                tool_name,
                &input,
                DenyHookDetails {
                    output: &output,
                    decision: &decision,
                    risk_level: Some(&format!("{:?}", risk.level)),
                },
            )
            .await;
            return Ok(PreparedToolCall::Finalized {
                input,
                output,
                is_error: true,
                decision: Some(decision),
            });
        }

        // Governance step 1b: workspace trust gate.
        let trust_tool_name = self.tool_registry.resolve_tool_name(tool_name);
        let trust_level = crate::workspace_trust::evaluate_trust(
            self.config.workspace_dir.as_deref(),
            &self.config.workspace_trust,
        );
        if !crate::workspace_trust::is_tool_allowed(trust_tool_name, trust_level) {
            warn!(
                tool = %tool_name,
                resolved_tool = %trust_tool_name,
                trust_level = ?trust_level,
                workspace = ?self.config.workspace_dir,
                "tool blocked by workspace trust policy"
            );
            let output = format!(
                "Error: tool '{}' is not available in untrusted workspace",
                tool_name
            );
            let decision = PermissionDecision::new(
                DecisionSource::WorkspaceTrust,
                format!("tool '{tool_name}' is not available in untrusted workspace"),
            )
            // rule_id matches the legacy `deny_reason` code verbatim so
            // `legacy_deny_reason()` emits the original string for
            // backward-compat consumers.
            .with_rule_id("workspace_untrusted")
            .with_input_fingerprint(&input);
            self.invoke_after_tool_call_deny_hook(
                session_id,
                agent_id,
                tool_name,
                &input,
                DenyHookDetails {
                    output: &output,
                    decision: &decision,
                    risk_level: None,
                },
            )
            .await;
            return Ok(PreparedToolCall::Finalized {
                input,
                output,
                is_error: true,
                decision: Some(decision),
            });
        }

        // Governance step 2: tool input must be an object.
        if !input.is_object() {
            warn!(
                tool = %tool_name,
                input_type = %crate::message_validation::json_type_name(&input),
                "tool_use input is not an object — coercing to empty object"
            );
            input = serde_json::json!({});
        }

        // Governance step 3: BeforeToolCall hook.
        if let Some(override_payload) = self
            .execute_hook(
                HookPoint::BeforeToolCall,
                session_id,
                agent_id,
                Some(tool_name.to_owned()),
                serde_json::json!({
                    "tool_name": tool_name,
                    "input": input.clone(),
                }),
            )
            .await?
        {
            let new_input = override_payload
                .get("input")
                .cloned()
                .unwrap_or(override_payload);
            input = new_input;

            if !input.is_object() {
                warn!(
                    tool = %tool_name,
                    "hook set non-object input — coercing to empty object"
                );
                input = serde_json::json!({});
            }

            // Hooks must not bypass immutable deny-list.
            let post_hook_risk =
                crate::risk_classifier::classify_tool_risk(policy_tool_name, &input, session_id);
            if post_hook_risk.level == crate::risk_classifier::ToolRiskLevel::Denied {
                warn!(
                    tool = %policy_tool_name,
                    requested_tool = %tool_name,
                    reason = %post_hook_risk.reason,
                    "tool call blocked after hook modified input — deny-list match"
                );
                let output = format!(
                    "Error: operation denied by security policy — {}",
                    post_hook_risk.reason
                );
                let decision =
                    PermissionDecision::new(DecisionSource::RiskClassifier, post_hook_risk.reason)
                        .with_rule_id("immutable_deny_list")
                        .with_input_fingerprint(&input);
                self.invoke_after_tool_call_deny_hook(
                    session_id,
                    agent_id,
                    tool_name,
                    &input,
                    DenyHookDetails {
                        output: &output,
                        decision: &decision,
                        risk_level: Some(&format!("{:?}", post_hook_risk.level)),
                    },
                )
                .await;
                return Ok(PreparedToolCall::Finalized {
                    input,
                    output,
                    is_error: true,
                    decision: Some(decision),
                });
            }
        }

        // Governance step 4: egress firewall.
        if let Some(firewall) = &self.firewall {
            let urls = Self::extract_http_urls(&input);
            for url in urls {
                if let Err(e) = firewall.check_url_for_agent(&url, agent_id.as_str()).await {
                    warn!(
                        tool = %tool_name,
                        url = %url,
                        error = %e,
                        "tool call blocked by egress firewall"
                    );
                    let output = format!("Error: {e}");
                    let decision = PermissionDecision::new(DecisionSource::Firewall, e.to_string())
                        .with_rule_id("egress_firewall")
                        .with_input_fingerprint(&input);
                    self.invoke_after_tool_call_deny_hook(
                        session_id,
                        agent_id,
                        tool_name,
                        &input,
                        DenyHookDetails {
                            output: &output,
                            decision: &decision,
                            risk_level: None,
                        },
                    )
                    .await;
                    return Ok(PreparedToolCall::Finalized {
                        input,
                        output,
                        is_error: true,
                        decision: Some(decision),
                    });
                }
            }
        }

        // Governance step 5: approval policy.
        if let Some(checker) = &self.approval_checker {
            if checker.is_denied(policy_tool_name) {
                let output = format!("Error: tool '{}' is denied by security policy", tool_name);
                let decision = PermissionDecision::new(
                    DecisionSource::Approval,
                    format!("tool '{tool_name}' is denied by security policy"),
                )
                .with_rule_id("policy_denied")
                .with_input_fingerprint(&input);
                self.invoke_after_tool_call_deny_hook(
                    session_id,
                    agent_id,
                    tool_name,
                    &input,
                    DenyHookDetails {
                        output: &output,
                        decision: &decision,
                        risk_level: None,
                    },
                )
                .await;
                return Ok(PreparedToolCall::Finalized {
                    input,
                    output,
                    is_error: true,
                    decision: Some(decision),
                });
            }

            if checker.requires_approval(policy_tool_name, &input) {
                let req = ApprovalRequest {
                    tool_name: tool_name.to_owned(),
                    tool_input: input.clone(),
                    session_id: session_id.clone(),
                    agent_id: agent_id.clone(),
                };
                let approval_decision = self.approval_handler.request_approval(req).await;
                if let ApprovalDecision::Denied { reason } = approval_decision {
                    let output = format!("Error: tool '{}' denied: {}", tool_name, reason);
                    let decision = PermissionDecision::new(DecisionSource::Approval, reason)
                        .with_rule_id("approval_denied")
                        .with_input_fingerprint(&input);
                    self.invoke_after_tool_call_deny_hook(
                        session_id,
                        agent_id,
                        tool_name,
                        &input,
                        DenyHookDetails {
                            output: &output,
                            decision: &decision,
                            risk_level: None,
                        },
                    )
                    .await;
                    return Ok(PreparedToolCall::Finalized {
                        input,
                        output,
                        is_error: true,
                        decision: Some(decision),
                    });
                }
            }
        }

        Ok(PreparedToolCall::Ready { input })
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_after_tool_call_hook(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
        tool_name: &str,
        input: &serde_json::Value,
        output: String,
        is_error: bool,
        decision: Option<&encmind_core::permission::PermissionDecision>,
    ) -> Result<(String, bool), AppError> {
        use encmind_core::hooks::ToolOutcome;
        let mut output = output;
        let mut is_error = is_error;
        let outcome = ToolOutcome::classify(is_error, decision.is_some());
        let decision_value = decision
            .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null))
            .unwrap_or(serde_json::Value::Null);
        // Deprecated flat `deny_reason`, emitted only when a structured
        // decision is present, so existing consumers that key off this
        // field continue to work during the transition window.
        let legacy_reason = decision
            .map(Self::legacy_deny_reason)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null);
        if let Some(override_payload) = self
            .execute_hook(
                HookPoint::AfterToolCall,
                session_id,
                agent_id,
                Some(tool_name.to_owned()),
                serde_json::json!({
                    "tool_name": tool_name,
                    "input": input.clone(),
                    "output": output.clone(),
                    "is_error": is_error,
                    "outcome": outcome.as_str(),
                    "decision": decision_value,
                    "deny_reason": legacy_reason,
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
        Ok((output, is_error))
    }

    fn resolve_tool_interrupt_behavior(&self, tool_name: &str) -> ToolInterruptBehavior {
        let overrides = &self.config.per_tool_interrupt_behavior;
        if let Some(behavior) = overrides.get(tool_name).copied() {
            return behavior;
        }
        let normalized = tool_name.trim().to_ascii_lowercase();
        if let Some(behavior) = overrides.get(normalized.as_str()).copied() {
            return behavior;
        }
        // Backward-compat path for in-memory configs that still carry raw keys.
        if let Some((_, behavior)) = overrides
            .iter()
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(normalized.as_str()))
        {
            return *behavior;
        }
        self.tool_registry.tool_interrupt_behavior(tool_name)
    }

    fn normalize_dispatch_outcome(
        tool_name: &str,
        dispatch_input: &serde_json::Value,
        dispatch_result: Result<String, AppError>,
    ) -> (
        String,
        bool,
        Option<encmind_core::permission::PermissionDecision>,
    ) {
        use encmind_core::permission::{DecisionSource, PermissionDecision};
        match dispatch_result {
            Ok(result) => (result, false, None),
            Err(AppError::ToolDenied { reason, message }) => {
                warn!(
                    tool = %tool_name,
                    deny_reason = %reason,
                    message = %message,
                    "tool dispatch denied"
                );
                // Map tool-level denial reasons to the appropriate
                // decision source. The rule_id always mirrors the legacy
                // `deny_reason` string verbatim so `legacy_deny_reason()`
                // emits the same codes existing consumers saw before the
                // structured transition. Unknown reasons fall back to
                // Approval (the most common operator-configured denial
                // path) with the original string as the rule_id.
                let source = match reason.as_str() {
                    "workspace_untrusted" => DecisionSource::WorkspaceTrust,
                    "egress_firewall" => DecisionSource::Firewall,
                    "approval_denied" | "policy_denied" => DecisionSource::Approval,
                    _ => DecisionSource::Approval,
                };
                let decision = PermissionDecision::new(source, message.clone())
                    .with_rule_id(reason.clone())
                    .with_input_fingerprint(dispatch_input);
                (format!("Error: {message}"), true, Some(decision))
            }
            Err(e) => {
                warn!(tool = %tool_name, error = %e, "tool dispatch failed");
                (format!("Error: {e}"), true, None)
            }
        }
    }

    async fn await_blocking_dispatch_with_grace<F>(
        &self,
        tool_name: &str,
        dispatch_input: &serde_json::Value,
        dispatch_future: &mut std::pin::Pin<Box<F>>,
    ) -> (
        String,
        bool,
        Option<encmind_core::permission::PermissionDecision>,
    )
    where
        F: std::future::Future<Output = Result<String, AppError>> + Send,
    {
        let grace = self.config.blocking_tool_cancel_grace;
        match tokio::time::timeout(grace, dispatch_future.as_mut()).await {
            Ok(result) => Self::normalize_dispatch_outcome(tool_name, dispatch_input, result),
            Err(_) => {
                warn!(
                    tool = %tool_name,
                    grace_ms = grace.as_millis(),
                    "blocking tool did not finish within cancel grace"
                );
                (
                    format!(
                        "Error: blocking tool did not finish within cancel grace ({}ms)",
                        grace.as_millis()
                    ),
                    true,
                    None,
                )
            }
        }
    }

    async fn execute_safe_batch(
        &self,
        session_id: &SessionId,
        agent_id: &AgentId,
        safe_batch: &[(String, String, serde_json::Value)],
        state: &mut SafeBatchState<'_>,
    ) -> Result<Option<crate::loop_detector::LoopViolation>, AppError> {
        if safe_batch.is_empty() {
            return Ok(None);
        }

        let mut cancel_requested = state.cancel.is_cancelled();

        // Pre-governance is still sequential/fail-closed.
        let mut prepared: Vec<(String, String, PreparedToolCall)> =
            Vec::with_capacity(safe_batch.len());
        let mut interrupt_behaviors: Vec<ToolInterruptBehavior> =
            Vec::with_capacity(safe_batch.len());
        for (id, name, parsed_input) in safe_batch {
            let interrupt_behavior = self.resolve_tool_interrupt_behavior(name);
            interrupt_behaviors.push(interrupt_behavior);

            match self
                .prepare_tool_call(session_id, agent_id, name, parsed_input)
                .await
            {
                Ok(prepared_call) => prepared.push((id.clone(), name.clone(), prepared_call)),
                Err(e) => {
                    Self::emit_tool_start_event(state.event_tx, id, name, parsed_input).await;
                    self.persist_completed_tool_call(
                        session_id,
                        state.tool_calls,
                        CompletedToolCall {
                            tool_use_id: id.clone(),
                            tool_name: name.clone(),
                            input: parsed_input.clone(),
                            output: format!("Error: hook aborted — {e}"),
                            is_error: true,
                            decision: None,
                        },
                        state.event_tx,
                    )
                    .await?;
                    return Err(e);
                }
            }

            if state.cancel.is_cancelled() {
                cancel_requested = true;
            }
        }

        // Emit starts in original order with post-governance input.
        for (id, name, prepared_call) in &prepared {
            let input = match prepared_call {
                PreparedToolCall::Ready { input } => input,
                PreparedToolCall::Finalized { input, .. } => input,
            };
            Self::emit_tool_start_event(state.event_tx, id, name, input).await;
        }

        let mut loop_violation: Option<crate::loop_detector::LoopViolation> = None;

        if state.cancel.is_cancelled() {
            cancel_requested = true;
        }

        // Dispatch only "Ready" calls in bounded parallelism.
        let ready_dispatches: Vec<(
            usize,
            String,
            String,
            serde_json::Value,
            ToolInterruptBehavior,
        )> =
            prepared
                .iter()
                .enumerate()
                .filter_map(|(order, (id, name, prepared_call))| match prepared_call {
                    PreparedToolCall::Ready { input } => {
                        let interrupt_behavior = interrupt_behaviors
                            .get(order)
                            .copied()
                            .unwrap_or(ToolInterruptBehavior::Cancel);
                        if cancel_requested && interrupt_behavior == ToolInterruptBehavior::Cancel {
                            None
                        } else {
                            Some((
                                order,
                                id.clone(),
                                name.clone(),
                                input.clone(),
                                interrupt_behavior,
                            ))
                        }
                    }
                    PreparedToolCall::Finalized { .. } => None,
                })
                .collect();

        // Dispatch ready tools in bounded parallelism and keep only out-of-order
        // results in memory. As soon as a contiguous prefix is ready, persist it.
        let mut dispatch_results_by_order: HashMap<
            usize,
            (
                String,
                bool,
                Option<encmind_core::permission::PermissionDecision>,
            ),
        > = HashMap::new();
        let mut next_order_to_persist = 0usize;
        let requested = self.config.max_parallel_safe_tools;
        let parallelism = requested.clamp(1, MAX_PARALLEL_SAFE_TOOLS_CAP);
        if parallelism != requested {
            debug!(
                requested,
                clamped = parallelism,
                cap = MAX_PARALLEL_SAFE_TOOLS_CAP,
                "parallel tool concurrency clamped"
            );
        }

        if !ready_dispatches.is_empty() {
            let event_tx_for_batch = state.event_tx.clone();
            let mut dispatch_stream =
                futures::stream::iter(ready_dispatches.into_iter().map(
                    |(order, id, name, input, interrupt_behavior)| {
                        let tool_registry = self.tool_registry.clone();
                        let dispatch_session_id = session_id.clone();
                        let dispatch_agent_id = agent_id.clone();
                        let dispatch_cancel = state.cancel.clone();
                        let cancel_grace = self.config.blocking_tool_cancel_grace;
                        // Two copies: one keyed into the progress scope
                        // (borrowed) and one moved into the dispatch
                        // async block (owned).
                        let progress_tool_name = name.clone();
                        let dispatch_name = name.clone();
                        let dispatch_id = id.clone();
                        let batch_event_tx = event_tx_for_batch.clone();
                        // Retain a copy of the input so normalize can attach
                        // an input fingerprint to dispatch-level denials for
                        // audit correlation.
                        let fingerprint_input = input.clone();
                        async move {
                            // Wrap the dispatch in a per-tool ToolProgress
                            // sink so long-running handlers running
                            // concurrently each report against their own
                            // tool_use_id without cross-talk.
                            let (output, is_error, decision) = Self::dispatch_with_progress_scope(
                                &batch_event_tx,
                                &dispatch_id,
                                &progress_tool_name,
                                async move {
                                    let dispatch_future = std::panic::AssertUnwindSafe(
                                        tool_registry.dispatch(
                                            &dispatch_name,
                                            input,
                                            &dispatch_session_id,
                                            &dispatch_agent_id,
                                        ),
                                    )
                                    .catch_unwind();
                                    tokio::pin!(dispatch_future);

                                    let normalize = |dispatch_result: Result<
                                        Result<String, AppError>,
                                        Box<dyn std::any::Any + Send>,
                                    >| {
                                        let dispatch_result = match dispatch_result {
                                            Ok(inner) => inner,
                                            Err(_) => Err(AppError::Internal(
                                                "parallel tool task panicked".to_string(),
                                            )),
                                        };
                                        Self::normalize_dispatch_outcome(
                                            &dispatch_name,
                                            &fingerprint_input,
                                            dispatch_result,
                                        )
                                    };

                                    match interrupt_behavior {
                                        ToolInterruptBehavior::Cancel => {
                                            tokio::select! {
                                                _ = dispatch_cancel.cancelled() => ("Error: request cancelled".to_string(), true, None),
                                                result = dispatch_future.as_mut() => normalize(result),
                                            }
                                        }
                                        ToolInterruptBehavior::Block => {
                                            if dispatch_cancel.is_cancelled() {
                                                match tokio::time::timeout(cancel_grace, dispatch_future.as_mut()).await {
                                                    Ok(result) => normalize(result),
                                                    Err(_) => {
                                                        warn!(
                                                            tool = %dispatch_name,
                                                            grace_ms = cancel_grace.as_millis(),
                                                            "blocking tool did not finish within cancel grace"
                                                        );
                                                        (
                                                            format!(
                                                                "Error: blocking tool did not finish within cancel grace ({}ms)",
                                                                cancel_grace.as_millis()
                                                            ),
                                                            true,
                                                            None,
                                                        )
                                                    }
                                                }
                                            } else {
                                                tokio::select! {
                                                    result = dispatch_future.as_mut() => normalize(result),
                                                    _ = dispatch_cancel.cancelled() => {
                                                        match tokio::time::timeout(cancel_grace, dispatch_future.as_mut()).await {
                                                            Ok(result) => normalize(result),
                                                            Err(_) => {
                                                                warn!(
                                                                    tool = %dispatch_name,
                                                                    grace_ms = cancel_grace.as_millis(),
                                                                    "blocking tool did not finish within cancel grace"
                                                                );
                                                                (
                                                                    format!(
                                                                        "Error: blocking tool did not finish within cancel grace ({}ms)",
                                                                        cancel_grace.as_millis()
                                                                    ),
                                                                    true,
                                                                    None,
                                                                )
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                            )
                            .await;
                            (order, name, output, is_error, decision)
                        }
                    },
                ))
                .buffer_unordered(parallelism);

            loop {
                while next_order_to_persist < prepared.len() {
                    if state.cancel.is_cancelled() {
                        cancel_requested = true;
                    }

                    let (id, name, prepared_call) = &prepared[next_order_to_persist];
                    let interrupt_behavior = interrupt_behaviors
                        .get(next_order_to_persist)
                        .copied()
                        .unwrap_or(ToolInterruptBehavior::Cancel);
                    let short_circuit_cancel = cancel_requested
                        && matches!(interrupt_behavior, ToolInterruptBehavior::Cancel);

                    let (input, output, is_error, decision) = match prepared_call {
                        PreparedToolCall::Finalized {
                            input,
                            output,
                            is_error,
                            decision,
                        } => (input.clone(), output.clone(), *is_error, decision.clone()),
                        PreparedToolCall::Ready { input } => {
                            let maybe_dispatch =
                                dispatch_results_by_order.remove(&next_order_to_persist);
                            let (dispatch_output, dispatch_error, dispatch_decision) =
                                if short_circuit_cancel {
                                    maybe_dispatch.unwrap_or((
                                        "Error: request cancelled".to_string(),
                                        true,
                                        None,
                                    ))
                                } else {
                                    let Some(result) = maybe_dispatch else {
                                        break;
                                    };
                                    result
                                };

                            match self
                                .apply_after_tool_call_hook(
                                    session_id,
                                    agent_id,
                                    name,
                                    input,
                                    dispatch_output,
                                    dispatch_error,
                                    dispatch_decision.as_ref(),
                                )
                                .await
                            {
                                Ok((hook_output, hook_error)) => (
                                    input.clone(),
                                    hook_output,
                                    hook_error,
                                    if hook_error { dispatch_decision } else { None },
                                ),
                                Err(e) => {
                                    if let Err(persist_err) = self
                                        .persist_completed_tool_call(
                                            session_id,
                                            state.tool_calls,
                                            CompletedToolCall {
                                                tool_use_id: id.clone(),
                                                tool_name: name.clone(),
                                                input: input.clone(),
                                                output: format!("Error: hook aborted — {e}"),
                                                is_error: true,
                                                decision: None,
                                            },
                                            state.event_tx,
                                        )
                                        .await
                                    {
                                        Self::emit_remaining_safe_batch_completions(
                                            state.event_tx,
                                            &prepared,
                                            next_order_to_persist + 1,
                                            "Error: aborted due to persistence failure",
                                        )
                                        .await;
                                        return Err(persist_err);
                                    }
                                    let _ = state.loop_detector.record_and_check(name, true);

                                    for (
                                        remaining_order,
                                        (remaining_id, remaining_name, remaining_prepared_call),
                                    ) in
                                        prepared.iter().enumerate().skip(next_order_to_persist + 1)
                                    {
                                        let remaining_input = match remaining_prepared_call {
                                            PreparedToolCall::Ready { input } => input.clone(),
                                            PreparedToolCall::Finalized { input, .. } => {
                                                input.clone()
                                            }
                                        };
                                        if let Err(persist_err) = self
                                            .persist_completed_tool_call(
                                                session_id,
                                                state.tool_calls,
                                                CompletedToolCall {
                                                    tool_use_id: remaining_id.clone(),
                                                    tool_name: remaining_name.clone(),
                                                    input: remaining_input,
                                                    output:
                                                        "Error: aborted by hook (sibling tool abort)"
                                                            .to_string(),
                                                    is_error: true,
                                                    decision: None,
                                                },
                                                state.event_tx,
                                            )
                                            .await
                                        {
                                            Self::emit_remaining_safe_batch_completions(
                                                state.event_tx,
                                                &prepared,
                                                remaining_order + 1,
                                                "Error: aborted due to persistence failure",
                                            )
                                            .await;
                                            return Err(persist_err);
                                        }
                                        let _ = state
                                            .loop_detector
                                            .record_and_check(remaining_name, true);
                                    }
                                    return Err(e);
                                }
                            }
                        }
                    };

                    if let Err(persist_err) = self
                        .persist_completed_tool_call(
                            session_id,
                            state.tool_calls,
                            CompletedToolCall {
                                tool_use_id: id.clone(),
                                tool_name: name.clone(),
                                input,
                                output,
                                is_error,
                                decision,
                            },
                            state.event_tx,
                        )
                        .await
                    {
                        Self::emit_remaining_safe_batch_completions(
                            state.event_tx,
                            &prepared,
                            next_order_to_persist + 1,
                            "Error: aborted due to persistence failure",
                        )
                        .await;
                        return Err(persist_err);
                    }

                    let violation = state.loop_detector.record_and_check(name, is_error);
                    if loop_violation.is_none() {
                        loop_violation = violation;
                    }
                    next_order_to_persist += 1;
                }

                if next_order_to_persist >= prepared.len() {
                    break;
                }

                let next_result = if cancel_requested {
                    dispatch_stream.next().await
                } else {
                    tokio::select! {
                        _ = state.cancel.cancelled() => {
                            cancel_requested = true;
                            continue;
                        }
                        result = dispatch_stream.next() => result,
                    }
                };

                match next_result {
                    Some((order, tool_name, output, is_error, decision)) => {
                        if is_error {
                            let preview: String = output.chars().take(200).collect();
                            warn!(
                                order,
                                tool = %tool_name,
                                error = %preview,
                                "parallel tool dispatch failed"
                            );
                        }
                        dispatch_results_by_order.insert(order, (output, is_error, decision));
                    }
                    None => {
                        // Stream ended unexpectedly. Missing results are handled
                        // as synthetic errors below in the final flush.
                        break;
                    }
                }
            }
        }

        // Final flush (covers all-finalized batches and any missing dispatch results).
        while next_order_to_persist < prepared.len() {
            if state.cancel.is_cancelled() {
                cancel_requested = true;
            }

            let (id, name, prepared_call) = &prepared[next_order_to_persist];
            let interrupt_behavior = interrupt_behaviors
                .get(next_order_to_persist)
                .copied()
                .unwrap_or(ToolInterruptBehavior::Cancel);
            let short_circuit_cancel =
                cancel_requested && matches!(interrupt_behavior, ToolInterruptBehavior::Cancel);

            let (input, output, is_error, decision) = match prepared_call {
                PreparedToolCall::Finalized {
                    input,
                    output,
                    is_error,
                    decision,
                } => (input.clone(), output.clone(), *is_error, decision.clone()),
                PreparedToolCall::Ready { input } => {
                    let maybe_dispatch = dispatch_results_by_order.remove(&next_order_to_persist);
                    let (dispatch_output, dispatch_error, dispatch_decision) =
                        if short_circuit_cancel {
                            maybe_dispatch.unwrap_or((
                                "Error: request cancelled".to_string(),
                                true,
                                None,
                            ))
                        } else {
                            match maybe_dispatch {
                                Some(result) => result,
                                None => {
                                    warn!(
                                        order = next_order_to_persist,
                                        "missing parallel dispatch result; marking as error"
                                    );
                                    (
                                        "Error: parallel tool dispatch result missing".to_string(),
                                        true,
                                        None,
                                    )
                                }
                            }
                        };
                    match self
                        .apply_after_tool_call_hook(
                            session_id,
                            agent_id,
                            name,
                            input,
                            dispatch_output,
                            dispatch_error,
                            dispatch_decision.as_ref(),
                        )
                        .await
                    {
                        Ok((hook_output, hook_error)) => (
                            input.clone(),
                            hook_output,
                            hook_error,
                            if hook_error { dispatch_decision } else { None },
                        ),
                        Err(e) => {
                            if let Err(persist_err) = self
                                .persist_completed_tool_call(
                                    session_id,
                                    state.tool_calls,
                                    CompletedToolCall {
                                        tool_use_id: id.clone(),
                                        tool_name: name.clone(),
                                        input: input.clone(),
                                        output: format!("Error: hook aborted — {e}"),
                                        is_error: true,
                                        decision: None,
                                    },
                                    state.event_tx,
                                )
                                .await
                            {
                                Self::emit_remaining_safe_batch_completions(
                                    state.event_tx,
                                    &prepared,
                                    next_order_to_persist + 1,
                                    "Error: aborted due to persistence failure",
                                )
                                .await;
                                return Err(persist_err);
                            }
                            let _ = state.loop_detector.record_and_check(name, true);

                            for (
                                remaining_order,
                                (remaining_id, remaining_name, remaining_prepared_call),
                            ) in prepared.iter().enumerate().skip(next_order_to_persist + 1)
                            {
                                let remaining_input = match remaining_prepared_call {
                                    PreparedToolCall::Ready { input } => input.clone(),
                                    PreparedToolCall::Finalized { input, .. } => input.clone(),
                                };
                                if let Err(persist_err) = self
                                    .persist_completed_tool_call(
                                        session_id,
                                        state.tool_calls,
                                        CompletedToolCall {
                                            tool_use_id: remaining_id.clone(),
                                            tool_name: remaining_name.clone(),
                                            input: remaining_input,
                                            output: "Error: aborted by hook (sibling tool abort)"
                                                .to_string(),
                                            is_error: true,
                                            decision: None,
                                        },
                                        state.event_tx,
                                    )
                                    .await
                                {
                                    Self::emit_remaining_safe_batch_completions(
                                        state.event_tx,
                                        &prepared,
                                        remaining_order + 1,
                                        "Error: aborted due to persistence failure",
                                    )
                                    .await;
                                    return Err(persist_err);
                                }
                                let _ = state.loop_detector.record_and_check(remaining_name, true);
                            }
                            return Err(e);
                        }
                    }
                }
            };

            if let Err(persist_err) = self
                .persist_completed_tool_call(
                    session_id,
                    state.tool_calls,
                    CompletedToolCall {
                        tool_use_id: id.clone(),
                        tool_name: name.clone(),
                        input,
                        output,
                        is_error,
                        decision,
                    },
                    state.event_tx,
                )
                .await
            {
                Self::emit_remaining_safe_batch_completions(
                    state.event_tx,
                    &prepared,
                    next_order_to_persist + 1,
                    "Error: aborted due to persistence failure",
                )
                .await;
                return Err(persist_err);
            }

            let violation = state.loop_detector.record_and_check(name, is_error);
            if loop_violation.is_none() {
                loop_violation = violation;
            }
            next_order_to_persist += 1;
        }

        if cancel_requested {
            return Err(LlmError::Cancelled.into());
        }

        Ok(loop_violation)
    }

    async fn persist_completed_tool_call(
        &self,
        session_id: &SessionId,
        tool_calls: &mut Vec<ToolCallRecord>,
        completed: CompletedToolCall,
        event_tx: &Option<tokio::sync::mpsc::Sender<ChatEvent>>,
    ) -> Result<(), AppError> {
        tool_calls.push(ToolCallRecord {
            name: completed.tool_name.clone(),
            input: completed.input.clone(),
            output: completed.output.clone(),
            is_error: completed.is_error,
            decision: completed.decision.clone(),
        });

        let limit = self
            .config
            .per_tool_output_chars
            .get(completed.tool_name.as_str())
            .copied()
            .unwrap_or(self.config.max_tool_output_chars);
        let persisted_output = Self::truncate_tool_output(&completed.output, limit);
        if persisted_output.len() < completed.output.len() {
            info!(
                tool = %completed.tool_name,
                original_chars = completed.output.chars().count(),
                truncated_to = limit,
                "tool output truncated for LLM context"
            );
        }

        let tool_result_msg = Message {
            id: MessageId::new(),
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: completed.tool_use_id.clone(),
                content: persisted_output,
                is_error: completed.is_error,
            }],
            created_at: Utc::now(),
            token_count: None,
        };

        // Persist before emitting ToolComplete. If persistence fails, emit a
        // synthetic ToolComplete error to preserve start/complete pairing.
        match self
            .session_store
            .append_message(session_id, &tool_result_msg)
            .await
        {
            Ok(()) => {
                Self::emit_tool_complete_event(
                    event_tx,
                    &completed.tool_use_id,
                    &completed.tool_name,
                    &completed.output,
                    completed.is_error,
                )
                .await;
            }
            Err(e) => {
                let emit_output = format!("Error: failed to persist tool result — {e}");
                Self::emit_tool_complete_event(
                    event_tx,
                    &completed.tool_use_id,
                    &completed.tool_name,
                    &emit_output,
                    true,
                )
                .await;
                return Err(e.into());
            }
        }

        Ok(())
    }

    async fn build_loop_break_result(
        &self,
        session_id: &SessionId,
        tool_calls: Vec<ToolCallRecord>,
        accounting: RunAccounting,
        violation: crate::loop_detector::LoopViolation,
    ) -> Result<RunResult, AppError> {
        let reason = violation.to_string();
        let reason_code = match &violation {
            crate::loop_detector::LoopViolation::ToolCallCapExceeded { .. } => {
                "tool_call_cap_exceeded"
            }
            crate::loop_detector::LoopViolation::ConsecutiveFailures { .. } => {
                "consecutive_failures"
            }
            crate::loop_detector::LoopViolation::RepeatingPattern { .. } => "repeating_pattern",
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

        Ok(RunResult {
            response: stop_msg,
            tool_calls,
            input_tokens: accounting.input_tokens,
            output_tokens: accounting.output_tokens,
            iterations: accounting.iteration + 1,
            total_tokens: accounting.total_tokens,
            loop_break: Some(reason),
            loop_break_code: Some(reason_code),
            reached_max_iterations: false,
            cancelled: false,
        })
    }

    fn emit_delta_event(tx: &tokio::sync::mpsc::Sender<ChatEvent>, event: ChatEvent) {
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                debug!("dropping streaming delta event due full channel buffer");
            }
            Err(TrySendError::Closed(_)) => {
                debug!("dropping streaming delta event because receiver is closed");
            }
        }
    }

    async fn emit_event(tx: &tokio::sync::mpsc::Sender<ChatEvent>, event: ChatEvent) {
        match tokio::time::timeout(Duration::from_millis(50), tx.send(event)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                debug!("dropping streaming event because receiver is closed");
            }
            Err(_) => {
                debug!("dropping streaming event because send timed out");
            }
        }
    }

    fn is_cancelled_app_error(err: &AppError) -> bool {
        matches!(err, AppError::Llm(LlmError::Cancelled))
    }

    fn make_cancelled_result(
        last_response: Option<Message>,
        tool_calls: Vec<ToolCallRecord>,
        input_tokens: u32,
        output_tokens: u32,
        total_tokens: u32,
        iterations: u32,
    ) -> RunResult {
        let response = last_response.unwrap_or_else(|| Message {
            id: MessageId::new(),
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "Request cancelled.".into(),
            }],
            created_at: Utc::now(),
            token_count: None,
        });
        RunResult {
            response,
            tool_calls,
            input_tokens,
            output_tokens,
            total_tokens,
            iterations,
            loop_break: None,
            loop_break_code: None,
            reached_max_iterations: false,
            cancelled: true,
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

    const MAX_STREAM_EVENT_OUTPUT_CHARS: usize = 4_000;
    const MAX_STREAM_EVENT_INPUT_STRING_CHARS: usize = 512;
    const MAX_STREAM_EVENT_INPUT_ARRAY_ITEMS: usize = 16;
    const MAX_STREAM_EVENT_INPUT_OBJECT_KEYS: usize = 32;
    const MAX_STREAM_EVENT_INPUT_DEPTH: usize = 3;

    fn truncate_stream_event_output(output: &str) -> String {
        Self::truncate_tool_output(output, Self::MAX_STREAM_EVENT_OUTPUT_CHARS)
    }

    fn truncate_stream_event_input(input: &serde_json::Value) -> serde_json::Value {
        if Self::serialized_char_count(input) <= Self::MAX_STREAM_EVENT_OUTPUT_CHARS {
            return input.clone();
        }

        // Prefer preserving structure (top-level keys, scalar fields) while
        // reducing deep/large values to bounded previews.
        let mut summarized = Self::summarize_stream_event_input(input, 0);
        match &mut summarized {
            serde_json::Value::Object(map) => {
                map.insert("_truncated".to_string(), serde_json::Value::Bool(true));
            }
            _ => {
                summarized = serde_json::json!({
                    "_truncated": true,
                    "_value": summarized,
                });
            }
        }
        if Self::serialized_char_count(&summarized) <= Self::MAX_STREAM_EVENT_OUTPUT_CHARS {
            return summarized;
        }

        // Fallback when even structured summary is too large.
        let serialized = match serde_json::to_string(input) {
            Ok(s) => s,
            Err(_) => return summarized,
        };
        let preview: String = serialized
            .chars()
            .take(Self::MAX_STREAM_EVENT_OUTPUT_CHARS)
            .collect();
        serde_json::json!({
            "_truncated": true,
            "_preview": preview,
            "_original_type": Self::json_type_name_for_stream(input),
        })
    }

    fn serialized_char_count(value: &serde_json::Value) -> usize {
        serde_json::to_string(value)
            .map(|s| s.chars().count())
            .unwrap_or(usize::MAX)
    }

    fn summarize_stream_event_input(value: &serde_json::Value, depth: usize) -> serde_json::Value {
        if depth >= Self::MAX_STREAM_EVENT_INPUT_DEPTH {
            return serde_json::Value::String("[truncated depth]".to_string());
        }

        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                value.clone()
            }
            serde_json::Value::String(s) => {
                let char_count = s.chars().count();
                if char_count <= Self::MAX_STREAM_EVENT_INPUT_STRING_CHARS {
                    serde_json::Value::String(s.clone())
                } else {
                    let preview: String = s
                        .chars()
                        .take(Self::MAX_STREAM_EVENT_INPUT_STRING_CHARS)
                        .collect();
                    serde_json::Value::String(format!(
                        "{preview}...[truncated from {char_count} chars]"
                    ))
                }
            }
            serde_json::Value::Array(items) => {
                let mut summarized: Vec<serde_json::Value> = items
                    .iter()
                    .take(Self::MAX_STREAM_EVENT_INPUT_ARRAY_ITEMS)
                    .map(|item| Self::summarize_stream_event_input(item, depth + 1))
                    .collect();
                if items.len() > Self::MAX_STREAM_EVENT_INPUT_ARRAY_ITEMS {
                    let remaining = items.len() - Self::MAX_STREAM_EVENT_INPUT_ARRAY_ITEMS;
                    summarized.push(serde_json::Value::String(format!(
                        "[{remaining} items truncated]"
                    )));
                }
                serde_json::Value::Array(summarized)
            }
            serde_json::Value::Object(map) => {
                let mut summarized = serde_json::Map::new();
                for (idx, (key, item)) in map.iter().enumerate() {
                    if idx >= Self::MAX_STREAM_EVENT_INPUT_OBJECT_KEYS {
                        break;
                    }
                    summarized.insert(
                        key.clone(),
                        Self::summarize_stream_event_input(item, depth + 1),
                    );
                }
                if map.len() > Self::MAX_STREAM_EVENT_INPUT_OBJECT_KEYS {
                    summarized.insert(
                        "_truncated_keys".to_string(),
                        serde_json::json!(map.len() - Self::MAX_STREAM_EVENT_INPUT_OBJECT_KEYS),
                    );
                }
                serde_json::Value::Object(summarized)
            }
        }
    }

    fn json_type_name_for_stream(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        }
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

    use async_trait::async_trait;
    use encmind_core::config::EgressFirewallConfig;
    use encmind_core::error::LlmError;
    use encmind_core::error::PluginError;
    use encmind_core::hooks::{HookHandler, HookPoint, HookRegistry, HookResult};
    use encmind_core::traits::{CompletionDelta, InternalToolHandler, ModelInfo};

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

    struct DelayedInternalTool {
        name: &'static str,
        delay_ms: u64,
        concurrent_safe: bool,
        interrupt_behavior: ToolInterruptBehavior,
    }

    #[async_trait::async_trait]
    impl InternalToolHandler for DelayedInternalTool {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(self.name.to_string())
        }

        fn is_concurrent_safe(&self) -> bool {
            self.concurrent_safe
        }

        fn interrupt_behavior(&self) -> ToolInterruptBehavior {
            self.interrupt_behavior
        }
    }

    fn register_noop_internal_tool(registry: &mut ToolRegistry, name: &str) {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        registry
            .register_internal(
                name,
                name,
                schema,
                Arc::new(DelayedInternalTool {
                    name: "noop",
                    delay_ms: 0,
                    concurrent_safe: false,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();
    }

    #[test]
    fn prompt_visible_tools_respects_workspace_trust_readonly() {
        let mut registry = ToolRegistry::new();
        register_noop_internal_tool(&mut registry, "file_read");
        register_noop_internal_tool(&mut registry, "file_list");
        register_noop_internal_tool(&mut registry, "local_file_read");
        register_noop_internal_tool(&mut registry, "local_file_list");
        register_noop_internal_tool(&mut registry, "node_file_read");
        register_noop_internal_tool(&mut registry, "netprobe_search");
        register_noop_internal_tool(&mut registry, "bash_exec");

        let runtime = AgentRuntime::new(
            Arc::new(MockLlmBackend::new(128_000)),
            Arc::new(InMemorySessionStore::new()) as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig {
                workspace_dir: Some(std::path::PathBuf::from("/tmp/untrusted")),
                workspace_trust: encmind_core::config::WorkspaceTrustConfig {
                    trusted_paths: vec![std::path::PathBuf::from("/home/trusted")],
                    untrusted_default: "readonly".to_string(),
                    no_workspace_default: "trusted".to_string(),
                },
                ..Default::default()
            },
        );

        let visible = runtime.prompt_visible_tools();
        assert_eq!(
            visible,
            vec![
                "file_list".to_string(),
                "file_read".to_string(),
                "local_file_list".to_string(),
                "local_file_read".to_string(),
            ]
        );
    }

    #[test]
    fn prompt_visible_tools_hides_denied_bash_tools() {
        let mut registry = ToolRegistry::new();
        register_noop_internal_tool(&mut registry, "file_read");
        register_noop_internal_tool(&mut registry, "bash_exec");
        register_noop_internal_tool(&mut registry, "node_bash_exec");

        let runtime = AgentRuntime::new(
            Arc::new(MockLlmBackend::new(128_000)),
            Arc::new(InMemorySessionStore::new()) as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig::default(),
        )
        .with_approval(
            Arc::new(crate::approval::NoopApprovalHandler),
            crate::approval::ToolApprovalChecker::with_bash_effective_mode(
                encmind_core::config::BashMode::Ask,
                false,
            ),
        );

        let visible = runtime.prompt_visible_tools();
        assert_eq!(
            visible,
            vec!["file_read".to_string(), "node_bash_exec".to_string()]
        );
    }

    #[test]
    fn prompt_visible_tools_hides_bash_when_interactive_approval_unavailable() {
        let mut registry = ToolRegistry::new();
        register_noop_internal_tool(&mut registry, "file_read");
        register_noop_internal_tool(&mut registry, "bash_exec");
        register_noop_internal_tool(&mut registry, "node_bash_exec");

        let runtime = AgentRuntime::new(
            Arc::new(MockLlmBackend::new(128_000)),
            Arc::new(InMemorySessionStore::new()) as Arc<dyn SessionStore>,
            Arc::new(registry),
            RuntimeConfig::default(),
        )
        .with_approval(
            Arc::new(crate::approval::NoopApprovalHandler),
            crate::approval::ToolApprovalChecker::new(encmind_core::config::BashMode::Ask)
                .with_interactive_approval_available(false),
        );

        let visible = runtime.prompt_visible_tools();
        assert_eq!(visible, vec!["file_read".to_string()]);
    }

    #[tokio::test]
    async fn mixed_safe_and_sequential_tools_preserve_model_order() {
        let mut registry = ToolRegistry::new();
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });

        registry
            .register_internal(
                "safe_slow",
                "safe slow",
                empty_schema.clone(),
                Arc::new(DelayedInternalTool {
                    name: "safe_slow",
                    delay_ms: 30,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();
        registry
            .register_internal(
                "safe_fast",
                "safe fast",
                empty_schema.clone(),
                Arc::new(DelayedInternalTool {
                    name: "safe_fast",
                    delay_ms: 1,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();
        registry
            .register_internal(
                "seq_tool",
                "sequential",
                empty_schema,
                Arc::new(DelayedInternalTool {
                    name: "seq_tool",
                    delay_ms: 1,
                    concurrent_safe: false,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();

        let responses = vec![
            vec![
                CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: Some(encmind_core::traits::ToolUseDelta {
                        id: "t1".into(),
                        name: "safe_slow".into(),
                        input_json: "{}".into(),
                    }),
                    finish_reason: None,
                },
                CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: Some(encmind_core::traits::ToolUseDelta {
                        id: "t2".into(),
                        name: "safe_fast".into(),
                        input_json: "{}".into(),
                    }),
                    finish_reason: None,
                },
                CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: Some(encmind_core::traits::ToolUseDelta {
                        id: "t3".into(),
                        name: "seq_tool".into(),
                        input_json: "{}".into(),
                    }),
                    finish_reason: Some(FinishReason::ToolUse),
                },
            ],
            text_response("done"),
        ];

        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();
        let result = runtime
            .run(
                &session.id,
                make_user_msg("run mixed tools"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        let names: Vec<_> = result.tool_calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["safe_slow", "safe_fast", "seq_tool"]);
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

        // Cancellation now returns Ok with a cancelled result (not Err)
        // so streaming path can emit Done { stop_reason: Cancelled }.
        assert!(
            result.is_ok(),
            "cancelled run should return Ok, got: {:?}",
            result.err()
        );
        let run_result = result.unwrap();
        // The response should be a fallback message since no LLM turn completed.
        assert_eq!(run_result.iterations, 0);
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

        // Use a non-denied bash command (ls is Sensitive, not Denied).
        // The deny-list blocks rm -rf / before approval; this tests the
        // approval flow for commands that pass the deny-list.
        let responses = vec![
            tool_use_response("t1", "bash.exec", r#"{"command":"ls -la /tmp"}"#),
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

    /// Hook that returns a non-object input override (should be coerced to {}).
    struct NonObjectInputHook;
    #[async_trait::async_trait]
    impl HookHandler for NonObjectInputHook {
        async fn execute(
            &self,
            _ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            // Return a string instead of an object — runtime should coerce to {}.
            Ok(HookResult::Override(
                serde_json::json!({"input": "not an object"}),
            ))
        }
    }

    /// Hook that captures AfterToolCall payloads for test assertions.
    struct CaptureAfterToolHook {
        payloads: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    }
    #[async_trait::async_trait]
    impl HookHandler for CaptureAfterToolHook {
        async fn execute(
            &self,
            ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            self.payloads.lock().unwrap().push(ctx.payload.clone());
            Ok(HookResult::Continue)
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

    struct AbortAfterToolHook;
    #[async_trait::async_trait]
    impl HookHandler for AbortAfterToolHook {
        async fn execute(
            &self,
            _ctx: &mut encmind_core::hooks::HookContext,
        ) -> Result<HookResult, PluginError> {
            Ok(HookResult::Abort {
                reason: "after tool blocked".into(),
            })
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

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        let tool_results: Vec<&Message> =
            messages.iter().filter(|m| m.role == Role::Tool).collect();
        assert_eq!(
            tool_results.len(),
            1,
            "abort path must persist a tool_result"
        );
    }

    #[tokio::test]
    async fn streaming_hook_abort_emits_tool_complete_before_error() {
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
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("trigger"),
            default_agent(),
            CancellationToken::new(),
        );

        let mut started_tool_use_id: Option<String> = None;
        let mut completed_tool_use_id: Option<String> = None;
        let mut saw_error_event = false;
        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart {
                    tool_use_id,
                    tool_name,
                    ..
                } if tool_name == "echo" => started_tool_use_id = Some(tool_use_id),
                ChatEvent::ToolComplete {
                    tool_use_id,
                    tool_name,
                    is_error,
                    ..
                } if tool_name == "echo" && is_error => completed_tool_use_id = Some(tool_use_id),
                ChatEvent::Error { .. } => {
                    saw_error_event = true;
                    break;
                }
                ChatEvent::Done { .. } => break,
                _ => {}
            }
        }

        let err = handle.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("BeforeToolCall"));
        assert!(saw_error_event, "expected final Error event");
        assert_eq!(
            completed_tool_use_id, started_tool_use_id,
            "ToolComplete must correspond to the started tool call"
        );
    }

    #[tokio::test]
    async fn streaming_safe_batch_after_hook_abort_pairs_all_started_tools() {
        let mut registry = ToolRegistry::new();
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        registry
            .register_internal(
                "safe_a",
                "safe a",
                empty_schema.clone(),
                Arc::new(DelayedInternalTool {
                    name: "safe_a",
                    delay_ms: 1,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();
        registry
            .register_internal(
                "safe_b",
                "safe b",
                empty_schema,
                Arc::new(DelayedInternalTool {
                    name: "safe_b",
                    delay_ms: 1,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();

        let responses = vec![vec![
            CompletionDelta {
                text: None,
                thinking: None,
                tool_use: Some(encmind_core::traits::ToolUseDelta {
                    id: "ta".into(),
                    name: "safe_a".into(),
                    input_json: "{}".into(),
                }),
                finish_reason: None,
            },
            CompletionDelta {
                text: None,
                thinking: None,
                tool_use: Some(encmind_core::traits::ToolUseDelta {
                    id: "tb".into(),
                    name: "safe_b".into(),
                    input_json: "{}".into(),
                }),
                finish_reason: Some(FinishReason::ToolUse),
            },
        ]];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::AfterToolCall,
                100,
                "test",
                Arc::new(AbortAfterToolHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("trigger"),
            default_agent(),
            CancellationToken::new(),
        );

        let mut started: HashSet<String> = HashSet::new();
        let mut completed: HashSet<String> = HashSet::new();
        let mut saw_error_event = false;

        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart { tool_use_id, .. } => {
                    started.insert(tool_use_id);
                }
                ChatEvent::ToolComplete {
                    tool_use_id,
                    is_error,
                    ..
                } => {
                    assert!(is_error, "expected error completions on abort");
                    completed.insert(tool_use_id);
                }
                ChatEvent::Error { .. } => {
                    saw_error_event = true;
                    break;
                }
                ChatEvent::Done { .. } => break,
                _ => {}
            }
        }

        let err = handle.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("AfterToolCall"));
        assert!(saw_error_event, "expected final Error event");
        assert_eq!(
            started, completed,
            "all started tool calls must have matching completion events"
        );

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        let tool_result_count = messages.iter().filter(|m| m.role == Role::Tool).count();
        assert_eq!(
            tool_result_count, 2,
            "synthetic tool results must be persisted"
        );
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
    async fn before_tool_call_hook_non_object_input_coerced() {
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
                Arc::new(NonObjectInputHook),
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

        // The hook returned a string input which should be coerced to {}.
        // TestEchoSkill echoes input.text — with {} input, text is absent
        // so output should be empty or "null".
        assert_eq!(result.tool_calls.len(), 1);
        assert!(!result.tool_calls[0].is_error);
        // Input should have been coerced to empty object.
        assert!(
            result.tool_calls[0].input.is_object(),
            "non-object input should be coerced to object"
        );
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

    #[test]
    fn truncate_stream_event_input_is_utf8_safe_and_truncates() {
        let input = serde_json::json!({
            "text": "你好🚀".repeat(5_000),
        });

        let stream_input = AgentRuntime::truncate_stream_event_input(&input);
        let obj = stream_input
            .as_object()
            .expect("truncated payload must be object");
        assert_eq!(obj.get("_truncated").and_then(|v| v.as_bool()), Some(true));
        let preview = obj
            .get("text")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("_preview").and_then(|v| v.as_str()))
            .expect("structured text preview or fallback _preview must be string");
        assert!(
            preview.chars().count() <= AgentRuntime::MAX_STREAM_EVENT_OUTPUT_CHARS,
            "preview must be char-truncated to stream limit"
        );
    }

    #[test]
    fn truncate_stream_event_input_preserves_top_level_object_shape() {
        let input = serde_json::json!({
            "query": "x".repeat(10_000),
            "limit": 5,
            "nested": {
                "topic": "alerts"
            }
        });

        let stream_input = AgentRuntime::truncate_stream_event_input(&input);
        let obj = stream_input
            .as_object()
            .expect("truncated payload must remain an object");
        assert_eq!(obj.get("_truncated").and_then(|v| v.as_bool()), Some(true));
        assert!(
            obj.contains_key("query"),
            "top-level field should be preserved"
        );
        assert_eq!(obj.get("limit"), Some(&serde_json::json!(5)));
        assert!(
            obj.contains_key("nested"),
            "nested field should be preserved"
        );
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

    #[tokio::test]
    async fn deny_list_block_emits_structured_decision_in_hook_payload() {
        let mut registry = ToolRegistry::new();
        registry.register_skill(Arc::new(TestEchoSkill)).unwrap();

        // bash.exec with rm -rf / triggers the immutable deny-list.
        let responses = vec![
            tool_use_response("t1", "bash.exec", r#"{"command":"rm -rf /"}"#),
            text_response("ok"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let payloads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::AfterToolCall,
                100,
                "capture",
                Arc::new(CaptureAfterToolHook {
                    payloads: payloads.clone(),
                }),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let result = runtime
            .run(
                &session.id,
                make_user_msg("delete everything"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        // Tool should have been denied.
        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        let decision = result.tool_calls[0]
            .decision
            .as_ref()
            .expect("deny path must set a structured decision");
        assert_eq!(
            decision.source,
            encmind_core::permission::DecisionSource::RiskClassifier
        );
        assert_eq!(decision.rule_id.as_deref(), Some("immutable_deny_list"));
        assert!(decision.input_fingerprint.is_some());

        // AfterToolCall hook should have received the structured decision + outcome.
        let captured = payloads.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "expected exactly 1 AfterToolCall hook call"
        );
        let payload = &captured[0];
        assert_eq!(payload["is_error"], true);
        assert_eq!(payload["outcome"], "denied");
        let decision_payload = payload
            .get("decision")
            .expect("payload must include structured decision");
        assert_eq!(decision_payload["source"], "risk_classifier");
        assert_eq!(decision_payload["rule_id"], "immutable_deny_list");
        // Legacy compat field must also be present for existing plugins.
        assert_eq!(payload["deny_reason"], "immutable_deny_list");
    }

    struct WorkspaceDenyTool;

    #[async_trait]
    impl InternalToolHandler for WorkspaceDenyTool {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            Err(AppError::ToolDenied {
                reason: "workspace_untrusted".to_string(),
                message: "subagent blocked by workspace trust policy".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn tool_denied_dispatch_sets_tool_call_decision() {
        let mut registry = ToolRegistry::new();
        registry
            .register_internal(
                "delegated_action",
                "delegated action",
                serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                Arc::new(WorkspaceDenyTool),
            )
            .unwrap();

        let responses = vec![
            tool_use_response("t1", "delegated_action", "{}"),
            text_response("done"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("run delegated action"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        let decision = result.tool_calls[0]
            .decision
            .as_ref()
            .expect("dispatch denial must set a structured decision");
        assert_eq!(
            decision.source,
            encmind_core::permission::DecisionSource::WorkspaceTrust
        );
        // rule_id is pinned to the legacy deny_reason code verbatim so
        // `legacy_deny_reason()` emits the original backward-compat value.
        assert_eq!(decision.rule_id.as_deref(), Some("workspace_untrusted"));
        // Dispatch-level denials must also carry the input fingerprint
        // for audit correlation, matching the governance-level path.
        assert!(
            decision.input_fingerprint.is_some(),
            "dispatch-level denial should attach input fingerprint"
        );
        assert_eq!(decision.input_fingerprint.as_ref().unwrap().len(), 12);
        assert!(
            result.tool_calls[0]
                .output
                .contains("subagent blocked by workspace trust policy"),
            "unexpected output: {}",
            result.tool_calls[0].output
        );
    }

    struct SentinelLookingInternalErrorTool;

    #[async_trait]
    impl InternalToolHandler for SentinelLookingInternalErrorTool {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            Err(AppError::Internal(
                "__encmind_deny_reason__:workspace_untrusted:spoof attempt".to_string(),
            ))
        }
    }

    struct ClassCapturingTool {
        captured: Arc<std::sync::Mutex<Option<crate::scheduler::QueryClass>>>,
    }

    #[async_trait]
    impl InternalToolHandler for ClassCapturingTool {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            *self.captured.lock().unwrap() = Some(crate::scheduler::current_query_class());
            Ok("ok".to_string())
        }
    }

    #[tokio::test]
    async fn run_inner_scopes_query_class_task_local_to_runtime_config() {
        // When config.query_class = Background, any tool dispatched
        // during the run must observe Background via the task-local.
        let captured = Arc::new(std::sync::Mutex::new(None));
        let mut registry = ToolRegistry::new();
        registry
            .register_internal(
                "capture_class",
                "capture task-local class",
                serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                Arc::new(ClassCapturingTool {
                    captured: captured.clone(),
                }),
            )
            .unwrap();

        let responses = vec![
            tool_use_response("t1", "capture_class", "{}"),
            text_response("done"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        // Rebuild the runtime with query_class = Background.
        let runtime = AgentRuntime::new(
            runtime.llm.clone(),
            runtime.session_store.clone(),
            runtime.tool_registry.clone(),
            RuntimeConfig {
                query_class: crate::scheduler::QueryClass::Background,
                compaction_threshold: None,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let _ = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(
            *captured,
            Some(crate::scheduler::QueryClass::Background),
            "tool handler should observe Background via task-local set by run_inner"
        );
    }

    #[tokio::test]
    async fn normalize_dispatch_outcome_pins_rule_ids_to_legacy_codes() {
        // Each mapped denial reason must produce a PermissionDecision
        // whose rule_id equals the legacy deny_reason code verbatim,
        // so `legacy_deny_reason()` emits the original string.
        let input = serde_json::json!({"arg": "x"});
        for (reason, expected_source) in [
            (
                "workspace_untrusted",
                encmind_core::permission::DecisionSource::WorkspaceTrust,
            ),
            (
                "egress_firewall",
                encmind_core::permission::DecisionSource::Firewall,
            ),
            (
                "approval_denied",
                encmind_core::permission::DecisionSource::Approval,
            ),
            (
                "policy_denied",
                encmind_core::permission::DecisionSource::Approval,
            ),
            (
                "some_custom_reason",
                encmind_core::permission::DecisionSource::Approval,
            ),
        ] {
            let (_, is_error, decision) = AgentRuntime::normalize_dispatch_outcome(
                "t",
                &input,
                Err(AppError::ToolDenied {
                    reason: reason.to_string(),
                    message: format!("denied: {reason}"),
                }),
            );
            assert!(is_error, "{reason} should be an error");
            let decision = decision.expect("dispatch denial must produce a decision");
            assert_eq!(decision.source, expected_source, "source for {reason}");
            assert_eq!(
                decision.rule_id.as_deref(),
                Some(reason),
                "rule_id must match legacy code verbatim for {reason}"
            );
            assert!(
                decision.input_fingerprint.is_some(),
                "input_fingerprint must be attached for {reason}"
            );
            // The compat derivation MUST match the original string.
            assert_eq!(AgentRuntime::legacy_deny_reason(&decision), reason);
        }
    }

    #[tokio::test]
    async fn run_inner_defaults_query_class_to_interactive() {
        // Default RuntimeConfig must observe Interactive.
        let captured = Arc::new(std::sync::Mutex::new(None));
        let mut registry = ToolRegistry::new();
        registry
            .register_internal(
                "capture_class",
                "capture task-local class",
                serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                Arc::new(ClassCapturingTool {
                    captured: captured.clone(),
                }),
            )
            .unwrap();

        let responses = vec![
            tool_use_response("t1", "capture_class", "{}"),
            text_response("done"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let session = store.create_session("web").await.unwrap();
        let _ = runtime
            .run(
                &session.id,
                make_user_msg("trigger"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(
            *captured,
            Some(crate::scheduler::QueryClass::Interactive),
            "default RuntimeConfig should use Interactive query class"
        );
    }

    #[tokio::test]
    async fn internal_error_string_does_not_set_decision() {
        let mut registry = ToolRegistry::new();
        registry
            .register_internal(
                "bad_internal",
                "bad internal",
                serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                Arc::new(SentinelLookingInternalErrorTool),
            )
            .unwrap();

        let responses = vec![
            tool_use_response("t1", "bad_internal", "{}"),
            text_response("done"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;
        let session = store.create_session("web").await.unwrap();

        let result = runtime
            .run(
                &session.id,
                make_user_msg("run internal"),
                &default_agent(),
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].is_error);
        assert!(
            result.tool_calls[0].decision.is_none(),
            "internal error sentinel must not be re-interpreted as a structured decision"
        );
        assert!(
            result.tool_calls[0]
                .output
                .contains("__encmind_deny_reason__:workspace_untrusted:spoof attempt"),
            "output should preserve original internal error"
        );
    }

    #[tokio::test]
    async fn streaming_done_reports_max_iterations() {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(vec![], 128_000));
        let store = Arc::new(InMemorySessionStore::new());
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                max_tool_iterations: 0,
                compaction_threshold: None,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("hello"),
            default_agent(),
            CancellationToken::new(),
        );

        let mut stop_reason = None;
        while let Some(event) = rx.recv().await {
            if let ChatEvent::Done {
                stop_reason: sr, ..
            } = event
            {
                stop_reason = Some(sr);
                break;
            }
        }

        let result = handle.await.unwrap().unwrap();
        assert!(result.reached_max_iterations);
        match stop_reason {
            Some(StopReason::MaxIterations) => {}
            other => panic!("expected max_iterations stop reason, got {other:?}"),
        }
    }

    struct ProgressEmittingTool;

    #[async_trait]
    impl InternalToolHandler for ProgressEmittingTool {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            crate::tool_progress::report_status("fetching");
            crate::tool_progress::report_progress("parsing", Some(0.42));
            crate::tool_progress::report_status("done");
            Ok("ok".to_string())
        }
    }

    #[tokio::test]
    async fn streaming_emits_tool_progress_events_from_handler() {
        let mut registry = ToolRegistry::new();
        registry
            .register_internal(
                "progress_tool",
                "tool that emits progress events",
                serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
                Arc::new(ProgressEmittingTool),
            )
            .unwrap();

        let responses = vec![
            tool_use_response("t1", "progress_tool", "{}"),
            text_response("done"),
        ];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let session = store.create_session("web").await.unwrap();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("go"),
            default_agent(),
            CancellationToken::new(),
        );

        // Collect streaming events until the run completes.
        let mut progress_events = Vec::new();
        let mut saw_tool_start = false;
        let mut saw_tool_complete = false;
        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart { .. } => saw_tool_start = true,
                ChatEvent::ToolProgress {
                    tool_name,
                    message,
                    fraction,
                    ..
                } => {
                    progress_events.push((tool_name, message, fraction));
                }
                ChatEvent::ToolComplete { .. } => saw_tool_complete = true,
                ChatEvent::Done { .. } => break,
                ChatEvent::Error { message } => panic!("unexpected error: {message}"),
                _ => {}
            }
        }

        let result = handle.await.unwrap().unwrap();
        assert!(!result.cancelled);
        assert!(saw_tool_start, "ToolStart must be emitted");
        assert!(saw_tool_complete, "ToolComplete must be emitted");
        assert_eq!(
            progress_events.len(),
            3,
            "expected 3 ToolProgress events, got: {progress_events:?}"
        );
        assert_eq!(progress_events[0].1, "fetching");
        assert_eq!(progress_events[0].2, None);
        assert_eq!(progress_events[1].1, "parsing");
        assert_eq!(progress_events[1].2, Some(0.42));
        assert_eq!(progress_events[2].1, "done");
        // All progress events should carry the tool name.
        for (name, _, _) in &progress_events {
            assert_eq!(name, "progress_tool");
        }
    }

    #[tokio::test]
    async fn streaming_cancel_emits_done_cancelled() {
        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(vec![], 128_000));
        let store = Arc::new(InMemorySessionStore::new());
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig {
                compaction_threshold: None,
                ..Default::default()
            },
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("hello"),
            default_agent(),
            cancel,
        );

        let mut saw_cancelled = false;
        while let Some(event) = rx.recv().await {
            if let ChatEvent::Done {
                stop_reason: StopReason::Cancelled,
                ..
            } = event
            {
                saw_cancelled = true;
                break;
            }
        }

        assert!(saw_cancelled, "expected streaming Done(cancelled) event");
        let result = handle.await.unwrap().unwrap();
        assert!(
            result.cancelled,
            "cancelled run should return cancelled result"
        );
        assert_eq!(result.iterations, 0);
    }

    #[tokio::test]
    async fn safe_batch_cancel_still_applies_after_tool_hook_for_completed_results() {
        let mut registry = ToolRegistry::new();
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        registry
            .register_internal(
                "safe_slow",
                "safe slow",
                empty_schema,
                Arc::new(DelayedInternalTool {
                    name: "safe_slow",
                    delay_ms: 200,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();

        let responses = vec![tool_use_response("t1", "safe_slow", "{}")];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let mut hooks = HookRegistry::new();
        hooks
            .register(
                HookPoint::AfterToolCall,
                100,
                "sanitize",
                Arc::new(OverrideToolOutputHook),
                5000,
            )
            .unwrap();
        let runtime = runtime.with_hooks(Arc::new(RwLock::new(hooks)));

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("run"),
            default_agent(),
            cancel_for_task,
        );

        let mut saw_start = false;
        let mut saw_cancel_done = false;
        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart { tool_use_id, .. } if tool_use_id == "t1" => {
                    saw_start = true;
                    cancel.cancel();
                }
                ChatEvent::Done {
                    stop_reason: StopReason::Cancelled,
                    ..
                } => {
                    saw_cancel_done = true;
                    break;
                }
                ChatEvent::Error { .. } => break,
                _ => {}
            }
        }

        assert!(saw_start, "expected ToolStart before cancellation");
        assert!(saw_cancel_done, "expected Done(cancelled) event");
        let result = handle.await.unwrap().unwrap();
        assert!(result.cancelled, "run should return cancelled result");

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        let tool_result = messages
            .iter()
            .find(|m| m.role == Role::Tool)
            .expect("tool_result should be persisted on cancel");
        match &tool_result.content[0] {
            ContentBlock::ToolResult {
                content, is_error, ..
            } => {
                assert_eq!(content, "sanitized");
                assert!(!is_error, "hook should be able to clear error flag");
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[tokio::test]
    async fn safe_batch_cancel_respects_interrupt_behavior_per_tool() {
        let mut registry = ToolRegistry::new();
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        registry
            .register_internal(
                "safe_block",
                "safe blocking tool",
                empty_schema.clone(),
                Arc::new(DelayedInternalTool {
                    name: "safe_block",
                    delay_ms: 120,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Block,
                }),
            )
            .unwrap();
        registry
            .register_internal(
                "safe_cancel",
                "safe cancelable tool",
                empty_schema,
                Arc::new(DelayedInternalTool {
                    name: "safe_cancel",
                    delay_ms: 350,
                    concurrent_safe: true,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();

        let responses = vec![vec![
            CompletionDelta {
                text: None,
                thinking: None,
                tool_use: Some(encmind_core::traits::ToolUseDelta {
                    id: "t1".into(),
                    name: "safe_block".into(),
                    input_json: "{}".into(),
                }),
                finish_reason: None,
            },
            CompletionDelta {
                text: None,
                thinking: None,
                tool_use: Some(encmind_core::traits::ToolUseDelta {
                    id: "t2".into(),
                    name: "safe_cancel".into(),
                    input_json: "{}".into(),
                }),
                finish_reason: Some(FinishReason::ToolUse),
            },
        ]];
        let (runtime, store) = setup_runtime(responses, registry).await;

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("run"),
            default_agent(),
            cancel.clone(),
        );

        let mut saw_t1_start = false;
        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart { tool_use_id, .. } if tool_use_id == "t1" => {
                    saw_t1_start = true;
                    cancel.cancel();
                }
                ChatEvent::Done {
                    stop_reason: StopReason::Cancelled,
                    ..
                } => break,
                ChatEvent::Error { .. } => break,
                _ => {}
            }
        }

        assert!(
            saw_t1_start,
            "expected safe_block ToolStart before cancellation"
        );
        let result = handle.await.unwrap().unwrap();
        assert!(result.cancelled, "run should return cancelled result");

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        let mut by_tool_use_id: HashMap<String, (String, bool)> = HashMap::new();
        for msg in messages.iter().filter(|m| m.role == Role::Tool) {
            if let ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } = &msg.content[0]
            {
                by_tool_use_id.insert(tool_use_id.clone(), (content.clone(), *is_error));
            }
        }

        let (block_output, block_error) = by_tool_use_id
            .get("t1")
            .expect("expected tool_result for blocking tool");
        assert_eq!(block_output, "safe_block");
        assert!(
            !block_error,
            "blocking tool should finish normally after cancellation"
        );

        let (cancel_output, cancel_error) = by_tool_use_id
            .get("t2")
            .expect("expected tool_result for cancelable tool");
        assert!(cancel_output.contains("request cancelled"));
        assert!(
            *cancel_error,
            "cancelable tool should be short-circuited as error on cancellation"
        );
    }

    #[tokio::test]
    async fn interrupt_behavior_override_applies_by_tool_name() {
        let mut registry = ToolRegistry::new();
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        registry
            .register_internal(
                "seq_cancel",
                "sequential cancelable tool",
                empty_schema,
                Arc::new(DelayedInternalTool {
                    name: "seq_cancel",
                    delay_ms: 120,
                    concurrent_safe: false,
                    interrupt_behavior: ToolInterruptBehavior::Cancel,
                }),
            )
            .unwrap();

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![tool_use_response("t1", "seq_cancel", "{}")],
            128_000,
        ));
        let store = Arc::new(InMemorySessionStore::new());
        let mut config = RuntimeConfig {
            max_tool_iterations: 10,
            ..Default::default()
        };
        config
            .per_tool_interrupt_behavior
            .insert(" Seq_Cancel ".to_string(), ToolInterruptBehavior::Block);
        config.blocking_tool_cancel_grace = Duration::from_millis(250);
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            config,
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("run"),
            default_agent(),
            cancel.clone(),
        );
        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart { tool_use_id, .. } if tool_use_id == "t1" => {
                    cancel.cancel();
                }
                ChatEvent::Done {
                    stop_reason: StopReason::Cancelled,
                    ..
                }
                | ChatEvent::Error { .. } => break,
                _ => {}
            }
        }

        let result = handle.await.unwrap().unwrap();
        assert!(result.cancelled, "run should return cancelled result");

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        let (output, is_error) = messages
            .iter()
            .filter(|m| m.role == Role::Tool)
            .find_map(|m| match &m.content[0] {
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } if tool_use_id == "t1" => Some((content.clone(), *is_error)),
                _ => None,
            })
            .expect("expected tool_result for override test");
        assert_eq!(output, "seq_cancel");
        assert!(!is_error, "override should force blocking behavior");
    }

    #[tokio::test]
    async fn blocking_tool_cancel_grace_fail_closes() {
        let mut registry = ToolRegistry::new();
        let empty_schema = serde_json::json!({
            "type": "object",
            "properties": {}
        });
        registry
            .register_internal(
                "seq_block",
                "sequential blocking tool",
                empty_schema,
                Arc::new(DelayedInternalTool {
                    name: "seq_block",
                    delay_ms: 1_000,
                    concurrent_safe: false,
                    interrupt_behavior: ToolInterruptBehavior::Block,
                }),
            )
            .unwrap();

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(
            vec![tool_use_response("t1", "seq_block", "{}")],
            128_000,
        ));
        let store = Arc::new(InMemorySessionStore::new());
        let config = RuntimeConfig {
            max_tool_iterations: 10,
            blocking_tool_cancel_grace: Duration::from_millis(20),
            ..Default::default()
        };
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn SessionStore>,
            Arc::new(registry),
            config,
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        let (mut rx, handle) = runtime.run_streaming(
            session.id.clone(),
            make_user_msg("run"),
            default_agent(),
            cancel.clone(),
        );
        while let Some(event) = rx.recv().await {
            match event {
                ChatEvent::ToolStart { tool_use_id, .. } if tool_use_id == "t1" => {
                    cancel.cancel();
                }
                ChatEvent::Done {
                    stop_reason: StopReason::Cancelled,
                    ..
                }
                | ChatEvent::Error { .. } => break,
                _ => {}
            }
        }

        let result = handle.await.unwrap().unwrap();
        assert!(result.cancelled, "run should return cancelled result");

        let messages = store
            .get_messages(&session.id, Pagination::default())
            .await
            .unwrap();
        let (output, is_error) = messages
            .iter()
            .filter(|m| m.role == Role::Tool)
            .find_map(|m| match &m.content[0] {
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } if tool_use_id == "t1" => Some((content.clone(), *is_error)),
                _ => None,
            })
            .expect("expected tool_result for blocking timeout test");
        assert!(output.contains("cancel grace"));
        assert!(
            is_error,
            "blocking tool timeout should fail-close with an error result"
        );
    }
}
