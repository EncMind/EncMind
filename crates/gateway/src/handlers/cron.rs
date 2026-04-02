use crate::protocol::*;
use crate::state::AppState;
use chrono::{DateTime, Datelike, Duration as ChronoDuration, Timelike, Utc};
use encmind_core::traits::CronStore;
use encmind_core::types::{AgentId, CronJob, CronJobId, SessionFilter, SessionId};
use futures::FutureExt;
use std::any::Any;
use std::sync::Arc;
use tracing::warn;

const CRON_MAX_LOOKAHEAD_MINUTES: usize = 5 * 366 * 24 * 60;

/// Handle cron.list — list all cron jobs.
pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let cron_store = match &state.cron_store {
        Some(store) => store,
        None => {
            return ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!([]),
            };
        }
    };

    match cron_store.list_jobs().await {
        Ok(jobs) => {
            let data = serde_json::to_value(&jobs).unwrap_or(serde_json::Value::Null);
            ServerMessage::Res {
                id: req_id.to_string(),
                result: data,
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("cron list failed: {e}")),
        },
    }
}

/// Handle cron.create — create a new cron job.
pub async fn handle_create(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let cron_store = match &state.cron_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "cron not configured"),
            };
        }
    };

    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "name is required"),
            };
        }
    };

    let schedule = match params.get("schedule").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "schedule is required"),
            };
        }
    };
    if let Err(e) = parse_cron_schedule(&schedule) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, format!("invalid schedule: {e}")),
        };
    }

    let prompt = match params.get("prompt").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "prompt is required"),
            };
        }
    };

    let agent_id = params
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(AgentId::new)
        .unwrap_or_default();
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

    let model = params
        .get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let enabled = params
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // If caller supplies next_run_at, it must be a valid RFC3339 string.
    // Otherwise default to now so scheduler picks it up on the next tick.
    let next_run_at = match params.get("next_run_at") {
        Some(raw) => {
            let raw = match raw.as_str() {
                Some(value) => value,
                None => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            "next_run_at must be an RFC3339 string",
                        ),
                    };
                }
            };

            match chrono::DateTime::parse_from_rfc3339(raw) {
                Ok(dt) => Some(dt.with_timezone(&Utc)),
                Err(e) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            format!("invalid next_run_at RFC3339 timestamp: {e}"),
                        ),
                    };
                }
            }
        }
        None => Some(Utc::now()),
    };

    let job = CronJob {
        id: CronJobId::new(),
        name,
        schedule,
        prompt,
        agent_id,
        model,
        max_concurrent_runs: 4,
        enabled,
        last_run_at: None,
        next_run_at,
        created_at: Utc::now(),
    };

    match cron_store.create_job(&job).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::to_value(&job).unwrap_or(serde_json::Value::Null),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("cron create failed: {e}")),
        },
    }
}

/// Handle cron.delete — delete a cron job by id.
pub async fn handle_delete(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let cron_store = match &state.cron_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "cron not configured"),
            };
        }
    };

    let id_str = match params.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            };
        }
    };

    let job_id = CronJobId::from_string(id_str);
    match cron_store.delete_job(&job_id).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"deleted": true}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("cron delete failed: {e}")),
        },
    }
}

/// Handle cron.trigger — immediately dispatch a cron job.
/// Respects the same concurrency guard as the scheduled cron loop: a job that is
/// already running (via schedule or another trigger) will be rejected.
pub async fn handle_trigger(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let fallback_delay_secs = {
        let cfg = state.config.read().await;
        cfg.cron.check_interval_secs.max(1)
    };

    let cron_store = match &state.cron_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "cron not configured"),
            };
        }
    };

    let id_str = match params.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            };
        }
    };

    let job_id = CronJobId::from_string(id_str);
    let job = match cron_store.get_job(&job_id).await {
        Ok(Some(job)) => job,
        Ok(None) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "cron job not found"),
            };
        }
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("cron trigger failed: {e}")),
            };
        }
    };

    // Reserve a concurrency slot via the shared dispatcher so that manual triggers
    // cannot overlap with scheduled runs (or with each other) for the same job.
    let dispatcher = state.cron_dispatcher.clone();
    if let Some(ref d) = dispatcher {
        if let Err(msg) = d.try_reserve_job(job.id.as_str()).await {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, msg),
            };
        }
    }

    let result = run_cron_job_once(state, cron_store, &job, fallback_delay_secs).await;

    // Always release the dispatcher slot, even on failure.
    if let Some(ref d) = dispatcher {
        d.mark_job_complete(job.id.as_str()).await;
    }

    match result {
        Ok(outcome) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({
                "triggered": true,
                "job_name": job.name,
                "next_run_at": outcome.next_run_at.to_rfc3339(),
                "run": outcome.run_result,
            }),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("cron trigger failed: {e}")),
        },
    }
}

pub(crate) struct CronRunOutcome {
    pub run_result: serde_json::Value,
    pub next_run_at: DateTime<Utc>,
}

pub(crate) async fn run_cron_job_once(
    state: &AppState,
    cron_store: &Arc<dyn CronStore>,
    job: &CronJob,
    fallback_delay_secs: u64,
) -> Result<CronRunOutcome, String> {
    let started_at = Utc::now();
    cron_store
        .mark_run_started(&job.id, started_at)
        .await
        .map_err(|e| format!("failed to mark cron job started: {e}"))?;

    let run_result = match std::panic::AssertUnwindSafe(execute_cron_job(state, job))
        .catch_unwind()
        .await
    {
        Ok(result) => result,
        Err(payload) => Err(format!(
            "cron execution panicked: {}",
            panic_payload_to_string(payload)
        )),
    };

    let next_run_at = match compute_next_run_at(&job.schedule, started_at) {
        Ok(next) => next,
        Err(e) => {
            let fallback = started_at + ChronoDuration::seconds(fallback_delay_secs as i64);
            warn!(
                job_id = %job.id,
                schedule = %job.schedule,
                error = %e,
                fallback_next = %fallback,
                "invalid cron schedule; using fallback next_run_at"
            );
            fallback
        }
    };

    cron_store
        .mark_run_completed(&job.id, next_run_at)
        .await
        .map_err(|e| format!("failed to mark cron job completed: {e}"))?;

    match run_result {
        Ok(result) => Ok(CronRunOutcome {
            run_result: result,
            next_run_at,
        }),
        Err(e) => Err(format!("cron execution failed: {e}")),
    }
}

pub(crate) async fn execute_cron_job(
    state: &AppState,
    job: &CronJob,
) -> Result<serde_json::Value, String> {
    let session_id = resolve_cron_session_id(state, job).await?;
    let req_id = format!("cron-run-{}", job.id.as_str());
    let mut send_params = serde_json::json!({
        "text": job.prompt,
        "agent_id": job.agent_id.as_str(),
        "session_id": session_id.as_str(),
    });
    if let Some(ref model) = job.model {
        send_params["model"] = serde_json::Value::String(model.clone());
    }
    let response = super::chat::handle_send(state, send_params, &req_id, None).await;

    match response {
        ServerMessage::Res { result, .. } => Ok(result),
        ServerMessage::Error { error, .. } => Err(error.message),
        other => Err(format!("unexpected cron execution response: {other:?}")),
    }
}

async fn resolve_cron_session_id(state: &AppState, job: &CronJob) -> Result<SessionId, String> {
    let title = cron_session_title(job);
    let sessions = state
        .session_store
        .list_sessions(SessionFilter {
            channel: Some("cron".to_string()),
            agent_id: Some(job.agent_id.clone()),
            archived: Some(false),
        })
        .await
        .map_err(|e| format!("failed to list cron sessions: {e}"))?;

    if let Some(session) = sessions
        .into_iter()
        .find(|s| s.title.as_deref() == Some(title.as_str()))
    {
        return Ok(session.id);
    }

    let session = state
        .session_store
        .create_session_for_agent("cron", &job.agent_id)
        .await
        .map_err(|e| format!("failed to create cron session: {e}"))?;

    if let Err(e) = state
        .session_store
        .rename_session(&session.id, &title)
        .await
    {
        warn!(
            session_id = %session.id,
            job_id = %job.id,
            error = %e,
            "failed to label cron session; proceeding with unlabeled session"
        );
    }

    Ok(session.id)
}

fn cron_session_title(job: &CronJob) -> String {
    format!("cron:{}", job.id.as_str())
}

fn panic_payload_to_string(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_string()
}

#[derive(Clone)]
struct CronField {
    min: u32,
    max: u32,
    allowed: Vec<bool>,
    any: bool,
}

impl CronField {
    fn new(min: u32, max: u32, any: bool) -> Self {
        let mut allowed = vec![false; (max + 1) as usize];
        if any {
            for value in min..=max {
                allowed[value as usize] = true;
            }
        }
        Self {
            min,
            max,
            allowed,
            any,
        }
    }

    fn set(&mut self, value: u32) {
        self.allowed[value as usize] = true;
    }

    fn contains(&self, value: u32) -> bool {
        value >= self.min && value <= self.max && self.allowed[value as usize]
    }
}

struct ParsedCron {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
}

impl ParsedCron {
    fn matches(&self, dt: DateTime<Utc>) -> bool {
        if !self.minute.contains(dt.minute()) {
            return false;
        }
        if !self.hour.contains(dt.hour()) {
            return false;
        }
        if !self.month.contains(dt.month()) {
            return false;
        }

        let dom_match = self.day_of_month.contains(dt.day());
        let dow_match = self
            .day_of_week
            .contains(dt.weekday().num_days_from_sunday());

        // Standard cron behavior:
        // - if either DOM or DOW is '*', the other field controls matching
        // - otherwise, either DOM or DOW match is sufficient
        if self.day_of_month.any && self.day_of_week.any {
            true
        } else if self.day_of_month.any {
            dow_match
        } else if self.day_of_week.any {
            dom_match
        } else {
            dom_match || dow_match
        }
    }
}

fn parse_cron_value(token: &str, min: u32, max: u32, allow_weekday_7: bool) -> Result<u32, String> {
    let value = token
        .parse::<u32>()
        .map_err(|_| format!("invalid cron value '{token}'"))?;
    // Accept 7 as valid for weekday fields; normalization to 0 happens in the caller
    // after range expansion so that ranges like 1-7 and 5-7 work correctly.
    let effective_max = if allow_weekday_7 { 7 } else { max };
    if value < min || value > effective_max {
        return Err(format!(
            "cron value '{token}' out of range {min}..{effective_max}"
        ));
    }
    Ok(value)
}

fn parse_cron_field(
    expression: &str,
    min: u32,
    max: u32,
    allow_weekday_7: bool,
) -> Result<CronField, String> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err("empty cron field".into());
    }
    if expression == "*" {
        return Ok(CronField::new(min, max, true));
    }

    let mut field = CronField::new(min, max, false);
    for part in expression.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("invalid cron field list '{expression}'"));
        }

        let (base, step) = match part.split_once('/') {
            Some((base, step_str)) => {
                let step = step_str
                    .parse::<u32>()
                    .map_err(|_| format!("invalid cron step '{step_str}'"))?;
                if step == 0 {
                    return Err("cron step cannot be zero".into());
                }
                (base.trim(), step)
            }
            None => (part, 1),
        };

        let (start, end) = if base == "*" {
            (min, max)
        } else if let Some((start, end)) = base.split_once('-') {
            (
                parse_cron_value(start.trim(), min, max, allow_weekday_7)?,
                parse_cron_value(end.trim(), min, max, allow_weekday_7)?,
            )
        } else {
            let value = parse_cron_value(base, min, max, allow_weekday_7)?;
            (value, value)
        };

        if start > end {
            return Err(format!("invalid cron range '{base}'"));
        }

        for value in start..=end {
            if (value - start) % step == 0 {
                // Normalize weekday 7 → 0 (Sunday) after range expansion
                let v = if allow_weekday_7 && value == 7 {
                    0
                } else {
                    value
                };
                field.set(v);
            }
        }
    }

    if !(min..=max).any(|value| field.contains(value)) {
        return Err(format!("cron field '{expression}' produced no values"));
    }

    Ok(field)
}

fn parse_cron_schedule(schedule: &str) -> Result<ParsedCron, String> {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "expected 5 cron fields (minute hour day month weekday), got {}",
            fields.len()
        ));
    }

    Ok(ParsedCron {
        minute: parse_cron_field(fields[0], 0, 59, false)?,
        hour: parse_cron_field(fields[1], 0, 23, false)?,
        day_of_month: parse_cron_field(fields[2], 1, 31, false)?,
        month: parse_cron_field(fields[3], 1, 12, false)?,
        day_of_week: parse_cron_field(fields[4], 0, 6, true)?,
    })
}

pub(crate) fn compute_next_run_at(
    schedule: &str,
    from: DateTime<Utc>,
) -> Result<DateTime<Utc>, String> {
    let parsed = parse_cron_schedule(schedule)?;

    let mut candidate = from + ChronoDuration::minutes(1);
    candidate = candidate
        .with_second(0)
        .and_then(|dt| dt.with_nanosecond(0))
        .ok_or_else(|| "failed to normalize next cron candidate time".to_string())?;

    // Search up to five years in minute increments. This covers sparse-but-valid
    // schedules like leap day (Feb 29), whose next occurrence can be ~4 years out.
    for _ in 0..CRON_MAX_LOOKAHEAD_MINUTES {
        if parsed.matches(candidate) {
            return Ok(candidate);
        }
        candidate += ChronoDuration::minutes(1);
    }

    Err("could not find next run time within five years".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use encmind_core::error::LlmError;
    use encmind_core::traits::{
        CompletionDelta, CompletionParams, FinishReason, LlmBackend, ModelInfo,
    };
    use encmind_core::types::{AgentId, CronJob, CronJobId, Pagination, SessionFilter};
    use futures::Stream;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio_util::sync::CancellationToken;

    struct MockLlm;

    #[async_trait::async_trait]
    impl LlmBackend for MockLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            let deltas = vec![
                Ok(CompletionDelta {
                    text: Some("scheduled response".to_string()),
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
                id: "mock".into(),
                name: "mock".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    struct CaptureModelLlm {
        seen_model: Arc<StdMutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl LlmBackend for CaptureModelLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            *self.seen_model.lock().unwrap() = params.model.clone();
            let deltas = vec![
                Ok(CompletionDelta {
                    text: Some("ok".to_string()),
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
                id: "capture".into(),
                name: "capture".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[test]
    fn compute_next_run_at_hourly() {
        let from = DateTime::parse_from_rfc3339("2026-02-16T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = compute_next_run_at("0 * * * *", from).unwrap();
        assert_eq!(next.to_rfc3339(), "2026-02-16T13:00:00+00:00");
    }

    #[test]
    fn compute_next_run_at_rejects_invalid_schedule() {
        let from = DateTime::parse_from_rfc3339("2026-02-16T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let err = compute_next_run_at("not-a-cron", from).unwrap_err();
        assert!(err.contains("expected 5 cron fields"));
    }

    #[test]
    fn weekday_7_standalone_means_sunday() {
        // 2026-02-16 is a Monday. Next Sunday is 2026-02-22.
        let from = DateTime::parse_from_rfc3339("2026-02-16T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = compute_next_run_at("0 0 * * 7", from).unwrap();
        assert_eq!(next.to_rfc3339(), "2026-02-22T00:00:00+00:00");
    }

    #[test]
    fn weekday_range_1_to_7_matches_every_day() {
        // 1-7 = Mon-Sun = every day. Next match should be the very next minute.
        let from = DateTime::parse_from_rfc3339("2026-02-16T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = compute_next_run_at("* * * * 1-7", from).unwrap();
        assert_eq!(next.to_rfc3339(), "2026-02-16T12:01:00+00:00");
    }

    #[test]
    fn weekday_range_5_to_7_matches_fri_sat_sun() {
        // 2026-02-16 is Monday. Next Friday is 2026-02-20.
        let from = DateTime::parse_from_rfc3339("2026-02-16T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = compute_next_run_at("0 9 * * 5-7", from).unwrap();
        assert_eq!(next.to_rfc3339(), "2026-02-20T09:00:00+00:00");
    }

    #[test]
    fn weekday_range_0_to_7_matches_every_day() {
        // 0-7 = every day
        let from = DateTime::parse_from_rfc3339("2026-02-16T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = compute_next_run_at("* * * * 0-7", from).unwrap();
        assert_eq!(next.to_rfc3339(), "2026-02-16T12:01:00+00:00");
    }

    #[test]
    fn compute_next_run_at_handles_leap_day_schedule() {
        let from = DateTime::parse_from_rfc3339("2025-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = compute_next_run_at("0 0 29 2 *", from).unwrap();
        assert_eq!(next.to_rfc3339(), "2028-02-29T00:00:00+00:00");
    }

    #[tokio::test]
    async fn create_rejects_unknown_agent() {
        let state = make_test_state();
        let response = handle_create(
            &state,
            serde_json::json!({
                "name": "bad-agent",
                "schedule": "* * * * *",
                "prompt": "hello",
                "agent_id": "does-not-exist",
            }),
            "req-create-agent",
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("agent not found"));
            }
            other => panic!("expected error, got {other:?}"),
        }

        let jobs = state
            .cron_store
            .as_ref()
            .unwrap()
            .list_jobs()
            .await
            .unwrap();
        assert!(jobs.is_empty(), "unknown agent must not persist cron jobs");
    }

    #[tokio::test]
    async fn trigger_executes_job_and_records_messages() {
        let state = make_test_state();
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(MockLlm));
        }

        let job = CronJob {
            id: CronJobId::new(),
            name: "immediate".into(),
            schedule: "* * * * *".into(),
            prompt: "Do the thing".into(),
            agent_id: AgentId::default(),
            model: None,
            max_concurrent_runs: 1,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        let cron_store = state.cron_store.clone().unwrap();
        cron_store.create_job(&job).await.unwrap();

        let before_sessions = state
            .session_store
            .list_sessions(SessionFilter::default())
            .await
            .unwrap()
            .len();

        let response = handle_trigger(
            &state,
            serde_json::json!({ "id": job.id.as_str() }),
            "req-trigger",
        )
        .await;

        let run_session_id = match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-trigger");
                assert_eq!(result["triggered"], true);
                result["run"]["session_id"]
                    .as_str()
                    .expect("session_id present")
                    .to_string()
            }
            other => panic!("expected success response, got {other:?}"),
        };

        let after_sessions = state
            .session_store
            .list_sessions(SessionFilter::default())
            .await
            .unwrap()
            .len();
        assert_eq!(after_sessions, before_sessions + 1);

        let messages = state
            .session_store
            .get_messages(
                &encmind_core::types::SessionId::from_string(&run_session_id),
                Pagination::default(),
            )
            .await
            .unwrap();
        assert!(
            messages.len() >= 2,
            "expected at least user+assistant messages from cron run"
        );

        let stored_job = cron_store.get_job(&job.id).await.unwrap().unwrap();
        assert!(stored_job.last_run_at.is_some());
        assert!(stored_job.next_run_at.is_some());
        assert!(stored_job.next_run_at.unwrap() > stored_job.last_run_at.unwrap());
    }

    #[tokio::test]
    async fn trigger_reuses_session_for_same_job() {
        let state = make_test_state();
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(MockLlm));
        }

        let job = CronJob {
            id: CronJobId::new(),
            name: "reuse-session".into(),
            schedule: "* * * * *".into(),
            prompt: "Do it again".into(),
            agent_id: AgentId::default(),
            model: None,
            max_concurrent_runs: 1,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        let cron_store = state.cron_store.clone().unwrap();
        cron_store.create_job(&job).await.unwrap();

        let first = handle_trigger(
            &state,
            serde_json::json!({ "id": job.id.as_str() }),
            "req-trigger-1",
        )
        .await;
        let second = handle_trigger(
            &state,
            serde_json::json!({ "id": job.id.as_str() }),
            "req-trigger-2",
        )
        .await;

        let sid_1 = match first {
            ServerMessage::Res { result, .. } => result["run"]["session_id"]
                .as_str()
                .expect("first response includes session_id")
                .to_string(),
            other => panic!("unexpected first response: {other:?}"),
        };
        let sid_2 = match second {
            ServerMessage::Res { result, .. } => result["run"]["session_id"]
                .as_str()
                .expect("second response includes session_id")
                .to_string(),
            other => panic!("unexpected second response: {other:?}"),
        };
        assert_eq!(sid_1, sid_2, "same cron job should reuse same session");

        let cron_sessions = state
            .session_store
            .list_sessions(SessionFilter {
                channel: Some("cron".into()),
                agent_id: Some(AgentId::default()),
                archived: Some(false),
            })
            .await
            .unwrap();
        let expected_title = cron_session_title(&job);
        let matching = cron_sessions
            .into_iter()
            .filter(|s| s.title.as_deref() == Some(expected_title.as_str()))
            .count();
        assert_eq!(matching, 1, "should keep a single session per cron job");
    }

    #[tokio::test]
    async fn trigger_rejects_when_job_already_active() {
        let state = make_test_state();
        let cron_store = state.cron_store.clone().unwrap();
        let dispatcher = state.cron_dispatcher.clone().unwrap();

        let job = CronJob {
            id: CronJobId::new(),
            name: "active-guard".into(),
            schedule: "* * * * *".into(),
            prompt: "overlap".into(),
            agent_id: AgentId::default(),
            model: None,
            max_concurrent_runs: 1,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        cron_store.create_job(&job).await.unwrap();

        // Simulate a scheduled run holding the dispatcher slot
        dispatcher.try_reserve_job(job.id.as_str()).await.unwrap();

        let response = handle_trigger(
            &state,
            serde_json::json!({ "id": job.id.as_str() }),
            "req-overlap",
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(
                    error.message.contains("already running"),
                    "expected 'already running' error, got: {}",
                    error.message
                );
            }
            other => panic!("expected error, got {other:?}"),
        }

        // Clean up
        dispatcher.mark_job_complete(job.id.as_str()).await;
    }

    #[tokio::test]
    async fn trigger_forwards_job_model_to_llm_params() {
        let state = make_test_state();
        let seen_model = Arc::new(StdMutex::new(None));
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(CaptureModelLlm {
                seen_model: seen_model.clone(),
            }));
        }
        {
            let mut cfg = state.config.write().await;
            cfg.llm
                .api_providers
                .push(encmind_core::config::ApiProviderConfig {
                    name: "test-provider".into(),
                    model: "gpt-4o-mini".into(),
                    base_url: None,
                });
        }

        let job = CronJob {
            id: CronJobId::new(),
            name: "model-override".into(),
            schedule: "* * * * *".into(),
            prompt: "Use specific model".into(),
            agent_id: AgentId::default(),
            model: Some("gpt-4o-mini".into()),
            max_concurrent_runs: 1,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        let cron_store = state.cron_store.clone().unwrap();
        cron_store.create_job(&job).await.unwrap();

        let response = handle_trigger(
            &state,
            serde_json::json!({ "id": job.id.as_str() }),
            "req-model",
        )
        .await;
        match response {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-model"),
            other => panic!("expected success response, got {other:?}"),
        }

        let captured = seen_model.lock().unwrap().clone();
        assert_eq!(captured.as_deref(), Some("gpt-4o-mini"));
    }
}
