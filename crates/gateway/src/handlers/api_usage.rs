//! Admin RPC for querying per-turn API usage attribution.
//!
//! Backed by `encmind_storage::api_usage::ApiUsageStore`, which stores
//! one row per `chat.send` turn (completed, cancelled, or error).
//! The handler lets operators filter by session / agent / channel /
//! status / time window and returns both a paged row list and an
//! aggregate roll-up across every matching row (not just the
//! returned page).

use encmind_storage::api_usage::ApiUsageFilter;
use chrono::{DateTime, SecondsFormat, Utc};

use crate::protocol::*;
use crate::state::AppState;

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 1000;

pub async fn handle_query(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    // Fail loud when the store isn't configured. Returning an empty
    // success would mask the misconfiguration as "no data" — an
    // operator querying "show me cancelled turns this week" would
    // see zero rows and assume all their runs completed cleanly.
    let Some(ref store) = state.api_usage_store else {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INTERNAL,
                "api_usage store is not configured on this gateway; cost attribution is unavailable",
            ),
        };
    };

    // Validate RFC3339 timestamps (reject garbage explicitly rather
    // than silently dropping the filter).
    let since = match parse_optional_rfc3339(&params, "since") {
        Ok(v) => v,
        Err(message) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
            };
        }
    };
    let until = match parse_optional_rfc3339(&params, "until") {
        Ok(v) => v,
        Err(message) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
            };
        }
    };
    if let (Some(s), Some(u)) = (since.as_ref(), until.as_ref()) {
        if s > u {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "since must be <= until"),
            };
        }
    }

    let filter = ApiUsageFilter {
        session_id: params
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        agent_id: params
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        channel: params
            .get("channel")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        status: match params.get("status").and_then(|v| v.as_str()) {
            None => None,
            Some(s) => {
                let valid = ["completed", "cancelled", "error"];
                if !valid.contains(&s) {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            format!(
                                "status must be one of {}; got '{s}'",
                                valid.join(", ")
                            ),
                        ),
                    };
                }
                Some(s.to_string())
            }
        },
        since: since
            .as_ref()
            .map(|ts| ts.to_rfc3339_opts(SecondsFormat::Millis, true)),
        until: until
            .as_ref()
            .map(|ts| ts.to_rfc3339_opts(SecondsFormat::Millis, true)),
    };

    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);

    let store = store.clone();
    let filter_for_query = filter.clone();
    let query_result =
        tokio::task::spawn_blocking(move || store.query(&filter_for_query, limit)).await;
    let (rows, aggregate) = match query_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("api_usage.query failed: {e}")),
            };
        }
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INTERNAL,
                    format!("api_usage.query worker failed: {e}"),
                ),
            };
        }
    };

    let rows_json: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "session_id": r.session_id,
                "agent_id": r.agent_id,
                "channel": r.channel,
                "model": r.model,
                "provider": r.provider,
                "input_tokens": r.input_tokens,
                "output_tokens": r.output_tokens,
                "total_tokens": r.total_tokens,
                "iterations": r.iterations,
                "duration_ms": r.duration_ms,
                "started_at": r.started_at,
                "status": r.status,
                "cost_usd": r.cost_usd,
            })
        })
        .collect();

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "rows": rows_json,
            "aggregate": {
                "row_count": aggregate.row_count,
                "input_tokens": aggregate.input_tokens,
                "output_tokens": aggregate.output_tokens,
                "total_tokens": aggregate.total_tokens,
                "total_duration_ms": aggregate.total_duration_ms,
                "total_cost_usd": aggregate.total_cost_usd,
            }
        }),
    }
}

fn parse_optional_rfc3339(
    params: &serde_json::Value,
    key: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(value) => {
            if value.is_null() {
                return Ok(None);
            }
            let raw = value
                .as_str()
                .ok_or_else(|| format!("{key} must be an RFC3339 string"))?;
            let parsed = chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|e| format!("invalid {key} RFC3339 timestamp: {e}"))?;
            Ok(Some(parsed.with_timezone(&Utc)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_optional_rfc3339;
    use chrono::{TimeZone, Utc};

    #[test]
    fn parse_optional_rfc3339_normalizes_timezone_to_utc() {
        let params = serde_json::json!({
            "since": "2026-03-20T09:00:00+09:00"
        });
        let parsed = parse_optional_rfc3339(&params, "since")
            .expect("timestamp should parse")
            .expect("timestamp should be present");
        assert_eq!(parsed, Utc.with_ymd_and_hms(2026, 3, 20, 0, 0, 0).unwrap());
    }

    #[test]
    fn parse_optional_rfc3339_rejects_invalid_input() {
        let params = serde_json::json!({
            "since": "not-a-timestamp"
        });
        let err = parse_optional_rfc3339(&params, "since")
            .expect_err("invalid timestamp must fail");
        assert!(err.contains("invalid since RFC3339 timestamp"));
    }

    #[tokio::test]
    async fn handle_query_rejects_invalid_status_filter() {
        use crate::test_utils::make_test_state;
        use crate::protocol::ServerMessage;

        let state = make_test_state();
        let response = super::handle_query(
            &state,
            serde_json::json!({"status": "typo"}),
            "req-bad-status",
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(
                    error.message.contains("status must be one of"),
                    "expected status validation error, got: {}",
                    error.message
                );
                assert!(error.message.contains("typo"));
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_query_errors_when_store_is_unavailable() {
        // When state.api_usage_store is None, the handler must fail
        // loud rather than silently return an empty result. An empty
        // success would mask backend misconfiguration as "no data".
        use crate::test_utils::make_test_state;
        use crate::protocol::ServerMessage;

        let mut state = make_test_state();
        // make_test_state attaches a store; explicitly clear it to
        // simulate a deployment that didn't configure cost
        // attribution.
        state.api_usage_store = None;

        let response = super::handle_query(
            &state,
            serde_json::json!({}),
            "req-no-store",
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert!(
                    error.message.contains("api_usage store is not configured"),
                    "expected unconfigured-store error, got: {}",
                    error.message
                );
            }
            other => panic!("expected Error response, got: {other:?}"),
        }
    }
}
