use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::SinkExt;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use encmind_agent::context::ContextConfig;
use encmind_agent::runtime::{AgentRuntime, ChatEvent, RuntimeConfig};
use encmind_core::config::InferenceMode;
use encmind_core::error::{AppError, LlmError};
use encmind_core::types::{AgentId, ContentBlock, Message, MessageId, Role, SessionId};

use crate::approval::gateway_approval_policy;
use crate::protocol::*;
use crate::runtime_config::parse_tool_interrupt_behavior_map;
use crate::state::AppState;

const MAX_CHANNEL_LEN: usize = 64;
const STREAM_EVENT_SEND_TIMEOUT_MS: u64 = 250;

fn model_allowed_in_current_mode(config: &encmind_core::config::AppConfig, model: &str) -> bool {
    match &config.llm.mode {
        InferenceMode::ApiProvider { provider } => config
            .llm
            .api_providers
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(provider))
            .is_some_and(|p| p.model == model),
        // Local inference is currently unavailable in this build. Local mode
        // falls back to configured API providers, so model overrides are
        // restricted to that effective provider pool.
        InferenceMode::Local => config.llm.api_providers.iter().any(|p| p.model == model),
    }
}

// ActiveRunGuard is replaced by QueryPermit from query_guard module.
// The query guard serializes concurrent chat.send calls per session (FIFO)
// instead of rejecting them with ERR_RATE_LIMITED.

pub async fn handle_send(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
    ws_sender: Option<crate::ws::WsSender>,
) -> ServerMessage {
    handle_send_with_class(
        state,
        params,
        req_id,
        ws_sender,
        encmind_agent::scheduler::QueryClass::Interactive,
    )
    .await
}

/// Like `handle_send`, but with an explicit priority class. Used by
/// background entrypoints (cron, webhook runners, workflow timers)
/// that should yield to user-initiated traffic.
pub async fn handle_send_with_class(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
    ws_sender: Option<crate::ws::WsSender>,
    query_class: encmind_agent::scheduler::QueryClass,
) -> ServerMessage {
    let text = params
        .get("text")
        .and_then(|v| v.as_str())
        .or_else(|| params.get("message").and_then(|v| v.as_str()))
        .unwrap_or_default()
        .trim()
        .to_string();

    if text.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "text required"),
        };
    }

    // Session rate limiting
    {
        let session_key = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or(req_id);
        if let Err(retry_after) = state.session_rate_limiter.check_and_record(session_key) {
            let _ = state.audit.append(
                "security",
                "rate_limited",
                Some(&format!(
                    "session={session_key}, retry_after={retry_after}s"
                )),
                None,
            );
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_RATE_LIMITED,
                    format!("rate limited; retry after {retry_after}s"),
                ),
            };
        }
    }

    // API budget check
    if let Some(ref tracker) = state.api_budget_tracker {
        if tracker.is_exceeded() {
            let _ = state.audit.append(
                "security",
                "api_budget_exceeded",
                Some("request denied before execution"),
                None,
            );
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_RATE_LIMITED,
                    "API budget exceeded for current period",
                ),
            };
        }
    }

    let requested_agent_id = params
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(AgentId::new);

    let requested_model = params
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_owned());

    if let Some(model) = requested_model.as_ref() {
        let config = state.config.read().await;
        let model_is_configured = model_allowed_in_current_mode(&config, model);

        if !model_is_configured {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    format!("model '{model}' is not available in current llm.mode"),
                ),
            };
        }
    }

    // When session_id is provided, use the session's canonical channel to prevent
    // clients from spoofing source_channel in memory metadata.
    let (session_id, channel) = match params
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(id) => {
            let sid = SessionId::from_string(id);
            match state.session_store.get_session(&sid).await {
                Ok(Some(session)) => (session.id, session.channel),
                Ok(None) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            format!("session not found: {sid}"),
                        ),
                    };
                }
                Err(e) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
                    };
                }
            }
        }
        None => {
            let channel = params
                .get("channel")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("web");
            if channel.len() > MAX_CHANNEL_LEN {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("channel too long (max {MAX_CHANNEL_LEN})"),
                    ),
                };
            }
            let channel = channel.to_owned();
            let agent_id = requested_agent_id.clone().unwrap_or_default();
            match state.agent_registry.get_agent(&agent_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            format!("agent not found: {agent_id}"),
                        ),
                    };
                }
                Err(e) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
                    };
                }
            }
            match state
                .session_store
                .create_session_for_agent(&channel, &agent_id)
                .await
            {
                Ok(session) => (session.id, channel),
                Err(e) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
                    };
                }
            }
        }
    };

    // Acquire per-session query guard. If another chat.send is running on this
    // session, we wait in FIFO order (not reject). Different sessions proceed
    // independently. The guard also registers the cancellation token in active_runs
    // so chat.abort continues to work.
    let query_permit = match state
        .query_guard
        .acquire(session_id.as_str(), state.active_runs.clone())
        .await
    {
        Some(permit) => permit,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_RATE_LIMITED,
                    "too many queued requests for this session",
                ),
            };
        }
    };
    let cancel_token = query_permit.cancel_token().clone();

    let agent_id = match state.agent_registry.resolve_agent(&session_id).await {
        Ok(agent_id) => agent_id,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    if let Some(requested_agent) = requested_agent_id {
        if requested_agent != agent_id {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    format!(
                        "session {} belongs to agent {}, not {}",
                        session_id, agent_id, requested_agent
                    ),
                ),
            };
        }
    }

    let mut agent_config = match state.agent_registry.get_agent(&agent_id).await {
        Ok(Some(config)) => config,
        Ok(None) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    format!("agent not found: {agent_id}"),
                ),
            };
        }
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    if let Some(model) = requested_model {
        // Runtime passes this through CompletionParams so API backends can honor
        // a per-request model override (used by cron jobs and direct chat.send).
        agent_config.model = Some(model);
    }

    let (llm_backend, tool_registry) = {
        // Take a coherent snapshot of runtime + loaded skills while refresh is serialized.
        // This avoids transient mismatches during key/mode refresh rebuild commits.
        let _refresh_guard = state.refresh_lock.read().await;

        let runtime = state.runtime.read().await;
        let llm = match runtime.llm_backend.as_ref() {
            Some(llm) => llm.clone(),
            None => {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INTERNAL,
                        "LLM not configured. Configure llm.api_providers and API keys.",
                    ),
                };
            }
        };
        let tool_registry = if agent_config.skills.is_empty() {
            runtime.tool_registry.clone()
        } else {
            Arc::new(
                runtime
                    .tool_registry
                    .filtered_for_agent(&agent_config.skills),
            )
        };
        (llm, tool_registry)
    };

    let user_message = Message {
        id: MessageId::new(),
        role: Role::User,
        content: vec![ContentBlock::Text { text: text.clone() }],
        created_at: Utc::now(),
        token_count: None,
    };

    let (
        max_context_memories,
        api_provider_disclosure,
        tok_config,
        bash_mode,
        workspace_trust,
        tool_calls_per_run,
        max_parallel_safe_tools,
        per_tool_interrupt_behavior,
        blocking_tool_cancel_grace_secs,
    ) = {
        let config = state.config.read().await;
        let disclosure = match &config.llm.mode {
            encmind_core::config::InferenceMode::ApiProvider { provider } => Some(provider.clone()),
            _ => None,
        };
        (
            config.memory.max_context_memories,
            disclosure,
            config.token_optimization.clone(),
            config.security.bash_mode.clone(),
            config.security.workspace_trust.clone(),
            config.security.rate_limit.tool_calls_per_run,
            config.agent_pool.max_parallel_safe_tools,
            config.security.per_tool_interrupt_behavior.clone(),
            config.security.blocking_tool_cancel_grace_secs,
        )
    };

    let runtime_config = RuntimeConfig {
        enforce_session_agent_match: true,
        max_tool_iterations: tok_config.max_tool_iterations,
        max_tool_output_chars: tok_config.max_tool_output_chars,
        per_tool_output_chars: tok_config.per_tool_output_chars.clone(),
        workspace_dir: agent_config
            .workspace
            .as_ref()
            .map(|workspace| PathBuf::from(workspace.as_str())),
        context_config: ContextConfig {
            max_context_memories,
            channel: Some(channel.clone()),
            api_provider_disclosure,
            sliding_window_truncation_threshold: tok_config.sliding_window_truncation_threshold,
            inject_behavioral_governance: tok_config.inject_behavioral_governance,
            inject_tool_usage_grammar: tok_config.inject_tool_usage_grammar,
            inject_browser_safety_rules: tok_config.inject_browser_safety_rules,
            inject_coordinator_mode: tok_config.inject_coordinator_mode,
            ..ContextConfig::default()
        },
        tool_calls_per_run: Some(tool_calls_per_run),
        max_parallel_safe_tools,
        per_tool_interrupt_behavior: parse_tool_interrupt_behavior_map(
            &per_tool_interrupt_behavior,
        ),
        blocking_tool_cancel_grace: Duration::from_secs(blocking_tool_cancel_grace_secs),
        workspace_trust,
        // Subagents spawned inside this run inherit the parent's class
        // via runtime_config. Without this, a cron (background) parent
        // would escalate its children to interactive priority and
        // dilute the two-class scheduler.
        query_class,
        ..RuntimeConfig::default()
    };

    let (approval_handler, approval_checker) = gateway_approval_policy(bash_mode);
    let mut runtime = AgentRuntime::new(
        llm_backend,
        state.session_store.clone(),
        tool_registry,
        runtime_config,
    )
    .with_firewall(state.firewall.clone())
    .with_hooks(state.hook_registry.clone())
    .with_approval(approval_handler, approval_checker);

    if let Some(memory_store) = &state.memory_store {
        runtime = runtime.with_memory(memory_store.clone());
    }

    let title_cancel = cancel_token.clone();
    let stream_cancel = cancel_token.clone();

    // If we have a WS sender, stream events in real-time.
    // Otherwise, fall back to the non-streaming execute path.
    let execute_result = if let Some(ref sender) = ws_sender {
        match state
            .agent_pool
            .execute_streaming(
                &runtime,
                session_id.clone(),
                user_message,
                agent_config.clone(),
                cancel_token,
                query_class,
            )
            .await
        {
            Ok((mut rx, mut handle)) => {
                let mut final_result: Option<
                    Result<encmind_agent::runtime::RunResult, encmind_core::error::AppError>,
                > = None;
                loop {
                    tokio::select! {
                        join_out = &mut handle => {
                            final_result = Some(match join_out {
                                Ok(result) => result,
                                Err(join_err) => Err(encmind_core::error::AppError::Internal(
                                    format!("agent task failed: {join_err}"),
                                )),
                            });
                            break;
                        }
                        maybe_event = rx.recv() => {
                            match maybe_event {
                                Some(event) => {
                                    if let Err(err) = send_stream_event(sender, req_id, &session_id, &event).await {
                                        warn!(error = %err, "failed to forward streaming event; cancelling run");
                                        stream_cancel.cancel();
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }

                // Flush any queued events produced before the run handle resolved.
                while let Ok(event) = rx.try_recv() {
                    if let Err(err) = send_stream_event(sender, req_id, &session_id, &event).await {
                        warn!(error = %err, "failed to forward queued streaming event");
                        stream_cancel.cancel();
                        break;
                    }
                }

                // Drop the receiver to close the channel. This unblocks
                // the runtime's final tx.send(Done/Error) if the channel was full.
                drop(rx);

                if let Some(result) = final_result {
                    result
                } else {
                    match handle.await {
                        Ok(result) => result,
                        Err(join_err) => Err(encmind_core::error::AppError::Internal(format!(
                            "agent task failed: {join_err}"
                        ))),
                    }
                }
            }
            Err(e) => Err(e),
        }
    } else {
        state
            .agent_pool
            .execute(
                &runtime,
                &session_id,
                user_message,
                &agent_config,
                cancel_token,
                query_class,
            )
            .await
    };

    // query_permit drops here (or on any early return above), releasing the session
    // semaphore (next queued request proceeds) and cleaning up active_runs.

    let run_result = match execute_result {
        Ok(result) => result,
        Err(e) => {
            if is_cancelled_app_error(&e) {
                return ServerMessage::Res {
                    id: req_id.to_string(),
                    result: serde_json::json!({
                        "status": "cancelled",
                        "session_id": session_id.as_str(),
                        "agent_id": agent_id.as_str(),
                        "iterations": 0,
                        "total_tokens": 0,
                    }),
                };
            }
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    // Audit governance denials with structured provenance.
    for call in &run_result.tool_calls {
        let Some(decision) = call.decision.as_ref() else {
            continue;
        };
        // Workspace-trust denials get their own category for operator
        // alerting; other sources share the generic governance category.
        let (category, action) = match decision.source {
            encmind_core::permission::DecisionSource::WorkspaceTrust => {
                ("security", "workspace_trust_denied")
            }
            _ => ("security", "tool_denied"),
        };
        let detail = serde_json::json!({
            "tool": call.name,
            "source": decision.source.as_str(),
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "input_fingerprint": decision.input_fingerprint,
        });
        let _ = state.audit.append(
            category,
            action,
            Some(&detail.to_string()),
            Some(agent_id.as_str()),
        );
    }

    // Audit loop-break events for parity with rate-limit / budget audit.
    if let Some(ref reason) = run_result.loop_break {
        append_loop_break_audit(state, run_result.loop_break_code.as_deref(), reason);
    }

    // Record token usage for budget tracking
    if let Some(ref tracker) = state.api_budget_tracker {
        let still_within_budget = tracker.record_tokens(
            run_result.input_tokens as u64,
            run_result.output_tokens as u64,
        );
        if !still_within_budget {
            let _ = state.audit.append(
                "security",
                "api_budget_exceeded",
                Some("budget exceeded after request completion"),
                None,
            );
        }
    }

    let assistant_text = extract_text_blocks(&run_result.response.content);
    if run_result.cancelled {
        return ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({
                "status": "cancelled",
                "session_id": session_id.as_str(),
                "agent_id": agent_id.as_str(),
                "response": assistant_text,
                "iterations": run_result.iterations,
                "total_tokens": run_result.total_tokens,
            }),
        };
    }

    let tool_calls = run_result
        .tool_calls
        .iter()
        .map(|call| {
            // Deprecated compat view: rule_id, else source name.
            // Kept during the structured-decision transition window.
            let legacy_deny_reason = call.decision.as_ref().map(|d| {
                d.rule_id
                    .clone()
                    .unwrap_or_else(|| d.source.as_str().to_string())
            });
            serde_json::json!({
                "name": call.name,
                "input": call.input,
                "output": call.output,
                "is_error": call.is_error,
                "decision": call.decision,
                "deny_reason": legacy_deny_reason,
            })
        })
        .collect::<Vec<_>>();

    maybe_store_memory(state, &session_id, &channel, &text, &assistant_text);
    if tok_config.auto_title_enabled {
        maybe_generate_title(state, &session_id, &text, &assistant_text, &title_cancel);
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "status": "completed",
            "session_id": session_id.as_str(),
            "agent_id": agent_id.as_str(),
            "assistant_message_id": run_result.response.id.as_str(),
            "response": assistant_text,
            "tool_calls": tool_calls,
            "iterations": run_result.iterations,
            "total_tokens": run_result.total_tokens,
        }),
    }
}

async fn send_stream_event(
    sender: &crate::ws::WsSender,
    req_id: &str,
    session_id: &SessionId,
    event: &ChatEvent,
) -> Result<(), String> {
    let event_json = serde_json::to_value(event).map_err(|e| e.to_string())?;
    let msg = ServerMessage::Event {
        event: "chat.event".to_string(),
        data: serde_json::json!({
            "req_id": req_id,
            "session_id": session_id.as_str(),
            "event": event_json,
        }),
    };
    let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
    let send_result =
        tokio::time::timeout(Duration::from_millis(STREAM_EVENT_SEND_TIMEOUT_MS), async {
            let mut s = sender.lock().await;
            s.send(axum::extract::ws::Message::Text(json.into())).await
        })
        .await;

    match send_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "ws stream event send timed out after {STREAM_EVENT_SEND_TIMEOUT_MS}ms"
        )),
    }
}

fn is_cancelled_app_error(err: &AppError) -> bool {
    matches!(err, AppError::Llm(LlmError::Cancelled))
}

fn extract_text_blocks(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn loop_break_audit_detail(code: Option<&str>, reason: &str) -> String {
    serde_json::json!({
        "code": code.unwrap_or("unknown"),
        "reason": reason,
    })
    .to_string()
}

fn append_loop_break_audit(state: &AppState, code: Option<&str>, reason: &str) {
    let detail = loop_break_audit_detail(code, reason);
    if let Err(e) = state
        .audit
        .append("security", "loop_break", Some(&detail), None)
    {
        warn!(error = %e, "failed to append loop_break audit entry");
    }
}

fn maybe_store_memory(
    state: &AppState,
    session_id: &SessionId,
    channel: &str,
    user_text: &str,
    assistant_text: &str,
) {
    let memory_store = match state.memory_store.clone() {
        Some(store) => store,
        None => return,
    };

    let user_text = user_text.trim().to_owned();
    let assistant_text = assistant_text.trim().to_owned();
    if user_text.is_empty() && assistant_text.is_empty() {
        return;
    }

    let session_id = session_id.clone();
    let channel = channel.to_owned();

    tokio::spawn(async move {
        let mut summary = String::new();
        if !user_text.is_empty() {
            summary.push_str("User: ");
            summary.push_str(&user_text);
        }
        if !assistant_text.is_empty() {
            if !summary.is_empty() {
                summary.push('\n');
            }
            summary.push_str("Assistant: ");
            summary.push_str(&assistant_text);
        }

        let truncated = summary.chars().take(2000).collect::<String>();
        let insert = memory_store.insert(&truncated, Some(session_id.clone()), Some(channel), None);
        match tokio::time::timeout(Duration::from_secs(10), insert).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                warn!(error = %e, "failed to persist chat memory");
            }
            Err(_) => {
                warn!(session = %session_id, "timed out while persisting chat memory");
            }
        }
    });
}

fn maybe_generate_title(
    state: &AppState,
    session_id: &SessionId,
    user_text: &str,
    assistant_text: &str,
    cancel: &CancellationToken,
) {
    let session_store = state.session_store.clone();
    let runtime = state.runtime.clone();
    let session_id = session_id.clone();
    let user_text = user_text.trim().to_owned();
    let assistant_text = assistant_text.trim().to_owned();
    let cancel = cancel.child_token();

    if user_text.is_empty() && assistant_text.is_empty() {
        return;
    }

    tokio::spawn(async move {
        // Check if session already has a title
        match session_store.get_session(&session_id).await {
            Ok(Some(session)) if session.title.is_some() => return,
            Ok(None) => return,
            Err(_) => return,
            _ => {}
        }

        let llm = {
            let guard = runtime.read().await;
            match guard.llm_backend.as_ref() {
                Some(llm) => llm.clone(),
                None => return,
            }
        };

        let prompt = format!(
            "Generate a concise title (max 6 words) for this conversation. \
             Return only the title, nothing else.\n\n\
             User: {user_text}\nAssistant: {assistant_text}"
        );

        let messages = vec![Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
            created_at: Utc::now(),
            token_count: None,
        }];

        let params = encmind_core::traits::CompletionParams {
            max_tokens: 30,
            temperature: 0.3,
            ..Default::default()
        };

        let stream = match llm.complete(&messages, params, cancel).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "title generation failed");
                return;
            }
        };

        use futures::StreamExt;
        let mut title = String::new();
        let mut stream = std::pin::pin!(stream);
        while let Some(Ok(delta)) = stream.next().await {
            if let Some(text) = delta.text {
                title.push_str(&text);
            }
        }

        let title = title.trim().trim_matches('"').trim();
        if title.is_empty() {
            return;
        }

        // Truncate to 100 chars
        let title: String = title.chars().take(100).collect();

        if let Err(e) = session_store.rename_session(&session_id, &title).await {
            tracing::debug!(error = %e, "failed to set session title");
        }
    });
}

pub async fn handle_history(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let session_id = params["session_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    if session_id.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "session_id required"),
        };
    }

    let sid = encmind_core::types::SessionId::from_string(&session_id);
    match state
        .session_store
        .get_messages(&sid, encmind_core::types::Pagination::default())
        .await
    {
        Ok(messages) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"messages": messages}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_abort(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if session_id.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "session_id required"),
        };
    }
    // Skip session existence check: abort is a safety operation that should
    // always succeed. If the session was deleted while a run is in-flight,
    // we still need to cancel the token.
    let cancelled = {
        let token = {
            let active_runs = state.active_runs.lock().unwrap();
            active_runs.get(&session_id).cloned()
        };
        if let Some(token) = token {
            token.cancel();
            true
        } else {
            false
        }
    };

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "status": if cancelled { "cancelled" } else { "no_active_run" },
            "session_id": session_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_loop_break_audit, extract_text_blocks, handle_abort, handle_history, handle_send,
        loop_break_audit_detail, maybe_generate_title,
    };
    use crate::protocol::{ServerMessage, ERR_INVALID_PARAMS};
    use crate::test_utils::make_test_state;
    use encmind_agent::tool_registry::{InternalToolHandler, ToolRegistry};
    use encmind_core::config::BashMode;
    use encmind_core::error::{AppError, LlmError};
    use encmind_core::traits::{
        CompletionDelta, CompletionParams, FinishReason, LlmBackend, ModelInfo,
    };
    use encmind_core::types::{AgentConfig, AgentId, ContentBlock, SessionId};
    use futures::Stream;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn extract_text_blocks_joins_text_segments() {
        let content = vec![
            ContentBlock::Thinking {
                text: "internal".into(),
            },
            ContentBlock::Text {
                text: "first".into(),
            },
            ContentBlock::Text {
                text: "second".into(),
            },
        ];

        let extracted = extract_text_blocks(&content);
        assert_eq!(extracted, "first\nsecond");
    }

    #[tokio::test]
    async fn abort_cancels_active_run_for_session() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let token = CancellationToken::new();
        {
            let mut active_runs = state.active_runs.lock().unwrap();
            active_runs.insert(session.id.as_str().to_owned(), token.clone());
        }

        let response = handle_abort(
            &state,
            serde_json::json!({ "session_id": session.id.as_str() }),
            "req-1",
        )
        .await;

        assert!(token.is_cancelled());
        match response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["status"], "cancelled");
                assert_eq!(result["session_id"], session.id.as_str());
            }
            _ => panic!("expected success response"),
        }
    }

    #[tokio::test]
    async fn send_queues_concurrent_run_for_session() {
        // With the query guard, concurrent sends on the same session are queued
        // (FIFO) instead of rejected. This test verifies that a second send
        // waits for the first to complete rather than returning ERR_RATE_LIMITED.
        //
        // We can't easily test the full FIFO flow in a unit test (would need a
        // real agent pool), but we can verify the guard acquires and releases
        // correctly by checking active_runs state.
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        // Acquire a permit directly to simulate an in-flight run.
        let permit = state
            .query_guard
            .acquire(session.id.as_str(), state.active_runs.clone())
            .await;
        assert!(permit.is_some(), "first acquire should succeed");

        // Verify token is registered in active_runs.
        assert!(
            state
                .active_runs
                .lock()
                .unwrap()
                .contains_key(session.id.as_str()),
            "cancel token should be in active_runs"
        );

        // Drop the permit — simulates run completing.
        drop(permit);

        // After drop, active_runs should be clean.
        assert!(
            !state
                .active_runs
                .lock()
                .unwrap()
                .contains_key(session.id.as_str()),
            "active_runs should be clean after permit drop"
        );
    }

    #[tokio::test]
    async fn send_rejects_unconfigured_model_override() {
        let state = make_test_state();
        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "hello",
                "model": "unknown-model"
            }),
            "req-3",
            None,
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("not available in current llm.mode"));
            }
            _ => panic!("expected model validation error"),
        }
    }

    #[tokio::test]
    async fn send_rejects_model_override_not_in_selected_api_provider_mode() {
        let state = make_test_state();
        {
            let mut config = state.config.write().await;
            config.llm.mode = encmind_core::config::InferenceMode::ApiProvider {
                provider: "openai".to_owned(),
            };
            config.llm.api_providers = vec![
                encmind_core::config::ApiProviderConfig {
                    name: "openai".to_owned(),
                    model: "gpt-4o-mini".to_owned(),
                    base_url: None,
                },
                encmind_core::config::ApiProviderConfig {
                    name: "anthropic".to_owned(),
                    model: "claude-3-5-sonnet-latest".to_owned(),
                    base_url: None,
                },
            ];
        }

        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "hello",
                "model": "claude-3-5-sonnet-latest"
            }),
            "req-4",
            None,
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("not available in current llm.mode"));
            }
            _ => panic!("expected model validation error"),
        }
    }

    #[tokio::test]
    async fn send_rejects_local_model_override_when_local_mode_falls_back_to_api_providers() {
        let state = make_test_state();
        {
            let mut config = state.config.write().await;
            config.llm.mode = encmind_core::config::InferenceMode::Local;
            config.llm.local = Some(encmind_core::config::LocalLlmConfig {
                model_path: std::path::PathBuf::from("/tmp/fake.bin"),
                model_name: "llama-3-8b".to_owned(),
                context_length: 8192,
                threads: None,
                gpu_layers: None,
            });
            config.llm.api_providers = vec![encmind_core::config::ApiProviderConfig {
                name: "openai".to_owned(),
                model: "gpt-4o-mini".to_owned(),
                base_url: None,
            }];
        }

        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "hello",
                "model": "llama-3-8b"
            }),
            "req-5",
            None,
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("not available in current llm.mode"));
            }
            _ => panic!("expected model validation error"),
        }
    }

    #[tokio::test]
    async fn send_rejects_overlong_channel_name() {
        let state = make_test_state();
        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "hello",
                "channel": "x".repeat(65)
            }),
            "req-6",
            None,
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("channel too long"));
            }
            _ => panic!("expected channel validation error"),
        }
    }

    #[tokio::test]
    async fn send_with_unknown_agent_does_not_create_session() {
        let state = make_test_state();
        let before = state
            .session_store
            .list_sessions(encmind_core::types::SessionFilter::default())
            .await
            .unwrap()
            .len();

        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "hello",
                "agent_id": "does-not-exist"
            }),
            "req-unknown-agent",
            None,
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("agent not found"));
            }
            _ => panic!("expected error for unknown agent"),
        }

        let after = state
            .session_store
            .list_sessions(encmind_core::types::SessionFilter::default())
            .await
            .unwrap()
            .len();
        assert_eq!(after, before, "unknown agent must not create a session");
    }

    // ── Title generation mock ─────────────────────────────────

    struct TitleMockLlm {
        response: String,
    }

    impl TitleMockLlm {
        fn new(response: &str) -> Self {
            Self {
                response: response.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for TitleMockLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            let deltas = vec![
                Ok(CompletionDelta {
                    text: Some(self.response.clone()),
                    thinking: None,
                    tool_use: None,
                    finish_reason: None,
                }),
                Ok(CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: None,
                    finish_reason: Some(FinishReason::Stop),
                }),
            ];
            Ok(Box::pin(futures::stream::iter(deltas)))
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "title-mock".into(),
                name: "title-mock".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    struct FailingTitleLlm;

    #[async_trait::async_trait]
    impl LlmBackend for FailingTitleLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            Err(LlmError::NotConfigured)
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "fail".into(),
                name: "fail".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[tokio::test]
    async fn title_generated_on_first_response() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        // Set up an LLM that returns a title
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TitleMockLlm::new("Dark Mode Preferences")));
        }

        let cancel = CancellationToken::new();
        maybe_generate_title(&state, &session.id, "enable dark mode", "Done!", &cancel);

        // Wait for the spawned task
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.title, Some("Dark Mode Preferences".to_string()));
    }

    #[tokio::test]
    async fn title_not_regenerated_if_set() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        // Set existing title
        state
            .session_store
            .rename_session(&session.id, "Existing Title")
            .await
            .unwrap();

        // Set up an LLM that would return a different title
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TitleMockLlm::new("New Title")));
        }

        let cancel = CancellationToken::new();
        maybe_generate_title(&state, &session.id, "hello", "hi", &cancel);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.title, Some("Existing Title".to_string()));
    }

    #[tokio::test]
    async fn title_generation_without_llm_is_noop() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        // No LLM set (default is None)
        let cancel = CancellationToken::new();
        maybe_generate_title(&state, &session.id, "hello", "hi", &cancel);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert!(updated.title.is_none());
    }

    #[tokio::test]
    async fn title_truncated_to_max_length() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        let long_title = "A".repeat(200);
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TitleMockLlm::new(&long_title)));
        }

        let cancel = CancellationToken::new();
        maybe_generate_title(&state, &session.id, "hello", "hi", &cancel);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        let title = updated.title.unwrap();
        assert_eq!(title.chars().count(), 100);
    }

    #[tokio::test]
    async fn title_generation_failure_is_nonfatal() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(FailingTitleLlm));
        }

        let cancel = CancellationToken::new();
        maybe_generate_title(&state, &session.id, "hello", "hi", &cancel);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Should not panic, session title should remain None
        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert!(updated.title.is_none());
    }

    // ── Token optimization wiring tests ─────────────────────────

    struct LoopingToolUseLlm {
        calls: Arc<AtomicUsize>,
    }

    impl LoopingToolUseLlm {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for LoopingToolUseLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let delta = CompletionDelta {
                text: None,
                thinking: None,
                tool_use: Some(encmind_core::traits::ToolUseDelta {
                    id: "tool-1".to_string(),
                    name: "unknown_tool".to_string(),
                    input_json: "{}".to_string(),
                }),
                finish_reason: Some(FinishReason::ToolUse),
            };
            Ok(Box::pin(futures::stream::iter(vec![Ok(delta)])))
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "looping-tool-use".into(),
                name: "looping-tool-use".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    struct TwoTurnBashLlm {
        calls: Arc<AtomicUsize>,
    }

    impl TwoTurnBashLlm {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for TwoTurnBashLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            let deltas = if idx == 0 {
                vec![Ok(CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: Some(encmind_core::traits::ToolUseDelta {
                        id: "tool-bash-1".to_string(),
                        name: "bash_exec".to_string(),
                        input_json: r#"{"command":"echo hello"}"#.to_string(),
                    }),
                    finish_reason: Some(FinishReason::ToolUse),
                })]
            } else {
                vec![Ok(CompletionDelta {
                    text: Some("done".to_string()),
                    thinking: None,
                    tool_use: None,
                    finish_reason: Some(FinishReason::Stop),
                })]
            };
            Ok(Box::pin(futures::stream::iter(deltas)))
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "two-turn-bash".into(),
                name: "two-turn-bash".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    struct CountingBashTool {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl InternalToolHandler for CountingBashTool {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok("executed".to_string())
        }
    }

    #[tokio::test]
    async fn send_uses_token_optimization_max_tool_iterations() {
        let state = make_test_state();
        let calls = Arc::new(AtomicUsize::new(0));

        {
            let mut config = state.config.write().await;
            config.token_optimization.max_tool_iterations = 1;
            config.token_optimization.auto_title_enabled = false;
        }

        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(LoopingToolUseLlm::new(calls.clone())));
        }

        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "trigger tool loop"
            }),
            "req-token-opt-1",
            None,
        )
        .await;

        match response {
            ServerMessage::Res { result, .. } => {
                let text = result
                    .get("response")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                assert!(
                    text.contains("maximum number of tool iterations"),
                    "expected iteration-limit fallback, got: {text}"
                );
            }
            other => panic!("expected success response, got: {other:?}"),
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "max_tool_iterations=1 should invoke complete() exactly once"
        );
    }

    #[tokio::test]
    async fn send_enforces_bash_mode_deny() {
        let state = make_test_state();
        let llm_calls = Arc::new(AtomicUsize::new(0));
        let bash_tool_calls = Arc::new(AtomicUsize::new(0));

        {
            let mut config = state.config.write().await;
            config.security.bash_mode = BashMode::Deny;
            config.token_optimization.auto_title_enabled = false;
        }

        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TwoTurnBashLlm::new(llm_calls.clone())));

            let mut registry = ToolRegistry::new();
            registry
                .register_internal(
                    "bash_exec",
                    "bash",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                    }),
                    Arc::new(CountingBashTool {
                        calls: bash_tool_calls.clone(),
                    }),
                )
                .unwrap();
            runtime.tool_registry = Arc::new(registry);
        }

        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "run bash",
            }),
            "req-bash-deny",
            None,
        )
        .await;

        match response {
            ServerMessage::Res { result, .. } => {
                let tool_calls = result["tool_calls"].as_array().expect("tool_calls array");
                assert_eq!(tool_calls.len(), 1);
                assert_eq!(tool_calls[0]["name"], "bash_exec");
                assert_eq!(tool_calls[0]["is_error"], true);
                let decision = &tool_calls[0]["decision"];
                assert_eq!(decision["source"], "approval");
                assert_eq!(decision["rule_id"], "policy_denied");
                // Legacy compat field must still be present for existing clients.
                assert_eq!(tool_calls[0]["deny_reason"], "policy_denied");
                let output = tool_calls[0]["output"].as_str().unwrap_or_default();
                assert!(
                    output.contains("denied by security policy"),
                    "got: {output}"
                );
            }
            other => panic!("expected success response, got: {other:?}"),
        }

        assert_eq!(
            bash_tool_calls.load(Ordering::SeqCst),
            0,
            "bash tool should not execute when bash_mode=deny"
        );
        assert_eq!(
            llm_calls.load(Ordering::SeqCst),
            2,
            "runtime should perform tool round then final response round"
        );

        let entries = state
            .audit
            .query(
                encmind_storage::audit::AuditFilter {
                    category: Some("security".to_string()),
                    action: Some("workspace_trust_denied".to_string()),
                    since: None,
                    until: None,
                    skill_id: None,
                },
                10,
                0,
            )
            .expect("audit query should succeed");
        assert!(
            entries.is_empty(),
            "did not expect workspace_trust_denied audit entry for bash policy denial"
        );
    }

    #[tokio::test]
    async fn send_applies_workspace_trust_gate_from_config() {
        let state = make_test_state();
        let llm_calls = Arc::new(AtomicUsize::new(0));
        let bash_tool_calls = Arc::new(AtomicUsize::new(0));
        let trusted_root = tempfile::tempdir().unwrap();
        let untrusted_workspace = tempfile::tempdir().unwrap();

        let mut agent: AgentConfig = state
            .agent_registry
            .get_agent(&AgentId::default())
            .await
            .unwrap()
            .expect("default agent exists");
        agent.workspace = Some(untrusted_workspace.path().display().to_string());
        state
            .agent_registry
            .update_agent(&AgentId::default(), agent)
            .await
            .unwrap();

        {
            let mut config = state.config.write().await;
            config.security.bash_mode = BashMode::Allowlist {
                patterns: vec!["echo*".to_string()],
            };
            config.security.workspace_trust.trusted_paths = vec![trusted_root.path().to_path_buf()];
            config.security.workspace_trust.untrusted_default = "readonly".to_string();
            config.token_optimization.auto_title_enabled = false;
        }

        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TwoTurnBashLlm::new(llm_calls.clone())));

            let mut registry = ToolRegistry::new();
            registry
                .register_internal(
                    "bash_exec",
                    "bash",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                    }),
                    Arc::new(CountingBashTool {
                        calls: bash_tool_calls.clone(),
                    }),
                )
                .unwrap();
            runtime.tool_registry = Arc::new(registry);
        }

        let response = handle_send(
            &state,
            serde_json::json!({
                "text": "run bash in untrusted workspace",
            }),
            "req-workspace-trust-1",
            None,
        )
        .await;

        match response {
            ServerMessage::Res { result, .. } => {
                let tool_calls = result["tool_calls"].as_array().expect("tool_calls array");
                assert_eq!(tool_calls.len(), 1);
                assert_eq!(tool_calls[0]["name"], "bash_exec");
                assert_eq!(tool_calls[0]["is_error"], true);
                let decision = &tool_calls[0]["decision"];
                assert_eq!(decision["source"], "workspace_trust");
                // rule_id is pinned to the legacy deny_reason code.
                assert_eq!(decision["rule_id"], "workspace_untrusted");
                // Legacy compat field — must match the pre-structured value.
                assert_eq!(tool_calls[0]["deny_reason"], "workspace_untrusted");
                let output = tool_calls[0]["output"].as_str().unwrap_or_default();
                assert!(
                    output.contains("not available in untrusted workspace"),
                    "got: {output}"
                );
            }
            other => panic!("expected success response, got: {other:?}"),
        }

        assert_eq!(
            bash_tool_calls.load(Ordering::SeqCst),
            0,
            "bash tool should not execute in untrusted readonly workspace"
        );
        assert_eq!(
            llm_calls.load(Ordering::SeqCst),
            2,
            "runtime should perform tool round then final response round"
        );
    }

    #[tokio::test]
    async fn auto_title_gated_by_config() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        // Set up LLM that would generate a title
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TitleMockLlm::new("Should Not Appear")));
        }

        // Ensure auto_title is disabled (default)
        {
            let config = state.config.read().await;
            assert!(
                !config.token_optimization.auto_title_enabled,
                "auto_title should be disabled by default"
            );
        }

        // The gating logic: title should NOT be generated when disabled
        // We simulate what handle_send does by checking the config gate
        let tok_config = {
            let config = state.config.read().await;
            config.token_optimization.clone()
        };
        let cancel = CancellationToken::new();

        if tok_config.auto_title_enabled {
            maybe_generate_title(&state, &session.id, "hello", "hi", &cancel);
        }
        // else: no title generation call

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            updated.title.is_none(),
            "title should not be generated when auto_title_enabled=false"
        );

        // Now enable auto_title and verify it generates
        {
            let mut config = state.config.write().await;
            config.token_optimization.auto_title_enabled = true;
        }

        let tok_config = {
            let config = state.config.read().await;
            config.token_optimization.clone()
        };

        if tok_config.auto_title_enabled {
            maybe_generate_title(&state, &session.id, "hello", "hi", &cancel);
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.title,
            Some("Should Not Appear".to_string()),
            "title should be generated when auto_title_enabled=true"
        );
    }

    // ── 11.6: Chat History ────────────────────────────────────

    #[tokio::test]
    async fn history_returns_messages_for_session() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        let msg = encmind_core::types::Message {
            id: encmind_core::types::MessageId::new(),
            role: encmind_core::types::Role::User,
            content: vec![encmind_core::types::ContentBlock::Text {
                text: "hello".to_string(),
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        };
        state
            .session_store
            .append_message(&session.id, &msg)
            .await
            .unwrap();

        let response = handle_history(
            &state,
            serde_json::json!({"session_id": session.id.as_str()}),
            "s-11-6",
        )
        .await;

        match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "s-11-6");
                let messages = result["messages"].as_array().unwrap();
                assert_eq!(messages.len(), 1);
                let m = &messages[0];
                assert!(m["role"].as_str().is_some());
                assert!(m["content"].is_array());
                assert!(m["created_at"].as_str().is_some());
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn history_empty_for_new_session() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        let response = handle_history(
            &state,
            serde_json::json!({"session_id": session.id.as_str()}),
            "s-11-6b",
        )
        .await;

        match response {
            ServerMessage::Res { result, .. } => {
                let messages = result["messages"].as_array().unwrap();
                assert!(messages.is_empty());
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn history_rejects_empty_session_id() {
        let state = make_test_state();
        let response = handle_history(&state, serde_json::json!({}), "s-11-6c").await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── 11.3: Auto-title via chat.send ────────────────────────

    // ── 12.1: Chat Abort In-Flight ─────────────────────────────

    struct SlowCancellableLlm {
        entered: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl LlmBackend for SlowCancellableLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            // Signal the test that the LLM is now in-flight
            self.entered.notify_one();
            // Block until abort fires the cancellation token
            cancel.cancelled().await;
            Err(LlmError::InferenceError("cancelled".into()))
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "slow-cancellable".into(),
                name: "slow-cancellable".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[tokio::test]
    async fn abort_stops_inflight_chat_send() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(SlowCancellableLlm {
                entered: entered.clone(),
            }));
        }

        let state2 = state.clone();
        let sid_str = session.id.as_str().to_owned();
        let send_task = tokio::spawn(async move {
            handle_send(
                &state2,
                serde_json::json!({
                    "text": "hello",
                    "session_id": sid_str,
                }),
                "req-abort-inflight",
                None,
            )
            .await
        });

        // Wait for the LLM to confirm it's blocking, but fail fast if it never starts.
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .expect("send task did not reach in-flight LLM call in time");

        // Now fire the abort
        let abort_response = handle_abort(
            &state,
            serde_json::json!({ "session_id": session.id.as_str() }),
            "req-abort-1",
        )
        .await;

        match &abort_response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["status"], "cancelled");
            }
            other => panic!("expected abort Res, got {other:?}"),
        }

        // Collect the send result — should return cancelled status.
        let send_response = send_task.await.expect("send task should not panic");
        match send_response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["status"], "cancelled");
            }
            other => panic!("expected send Res(cancelled) after abort, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn chat_send_triggers_auto_title_on_new_session() {
        let state = make_test_state();

        // Enable auto-title
        {
            let mut config = state.config.write().await;
            config.token_optimization.auto_title_enabled = true;
        }

        // Set up a mock LLM that returns a simple text response for both
        // chat completion and title generation.
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(TitleMockLlm::new("Weather Question")));
        }

        let response = handle_send(
            &state,
            serde_json::json!({"text": "What is the weather?"}),
            "s-11-3",
            None,
        )
        .await;

        let session_id = match &response {
            ServerMessage::Res { result, .. } => result["session_id"].as_str().unwrap().to_string(),
            other => panic!("expected Res, got {other:?}"),
        };

        let sid = encmind_core::types::SessionId::from_string(&session_id);
        // Poll until title is generated (or timeout) to avoid fixed sleep flakiness.
        let title_set = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let updated = state
                    .session_store
                    .get_session(&sid)
                    .await
                    .unwrap()
                    .unwrap();
                if updated.title.is_some() {
                    break true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or(false);

        assert!(title_set, "auto-title should have been set on the session");
    }

    // ── Loop-break audit parity ────────────────────────────────

    #[test]
    fn loop_break_audit_detail_includes_code_and_reason() {
        let detail =
            loop_break_audit_detail(Some("consecutive_failures"), "tool 'x' failed 5 times");
        let value: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(value["code"], "consecutive_failures");
        assert_eq!(value["reason"], "tool 'x' failed 5 times");
    }

    #[test]
    fn loop_break_audit_detail_uses_unknown_when_code_missing() {
        let detail = loop_break_audit_detail(None, "some reason");
        let value: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(value["code"], "unknown");
        assert_eq!(value["reason"], "some reason");
    }

    #[tokio::test]
    async fn append_loop_break_audit_writes_entry() {
        let state = make_test_state();
        append_loop_break_audit(&state, Some("repeating_pattern"), "repeating tool calls");

        let rows = state
            .audit
            .query(
                encmind_storage::audit::AuditFilter {
                    action: Some("loop_break".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert!(!rows.is_empty());
        let detail = rows[0].detail.clone().unwrap_or_default();
        let parsed: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(parsed["code"], "repeating_pattern");
        assert_eq!(parsed["reason"], "repeating tool calls");
    }
}
