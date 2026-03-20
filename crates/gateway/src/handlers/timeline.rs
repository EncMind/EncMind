use crate::protocol::*;
use crate::state::AppState;
use encmind_core::types::{AgentId, Pagination, TimelineFilter};

const TIMELINE_DEFAULT_LIMIT: u32 = 50;
const TIMELINE_MAX_LIMIT: u32 = 200;

fn parse_optional_rfc3339_utc(
    params: &serde_json::Value,
    key: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(value) => {
            if value.is_null() {
                return Ok(None);
            }
            let raw = value
                .as_str()
                .ok_or_else(|| format!("{key} must be an RFC3339 string"))?;
            let dt = chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|e| format!("invalid {key} RFC3339 timestamp: {e}"))?;
            Ok(Some(dt.with_timezone(&chrono::Utc)))
        }
    }
}

pub async fn handle_query(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let timeline_store = match &state.timeline_store {
        Some(store) => store,
        None => {
            return ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!([]),
            };
        }
    };

    let since = match parse_optional_rfc3339_utc(&params, "since") {
        Ok(value) => value,
        Err(message) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
            };
        }
    };

    let until = match parse_optional_rfc3339_utc(&params, "until") {
        Ok(value) => value,
        Err(message) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
            };
        }
    };
    if let (Some(since), Some(until)) = (since.as_ref(), until.as_ref()) {
        if since > until {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "since must be <= until"),
            };
        }
    }

    let filter = TimelineFilter {
        event_type: params
            .get("event_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        source: params
            .get("source")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        agent_id: params
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(AgentId::new),
        since,
        until,
    };

    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|v| v.clamp(1, TIMELINE_MAX_LIMIT as u64) as u32)
        .unwrap_or(TIMELINE_DEFAULT_LIMIT);
    let offset = params
        .get("offset")
        .and_then(|v| v.as_u64())
        .map(|v| v.min(u32::MAX as u64) as u32)
        .unwrap_or(0);
    let pagination = Pagination { offset, limit };

    match timeline_store.query_events(&filter, &pagination).await {
        Ok(events) => {
            let data = serde_json::to_value(&events).unwrap_or(serde_json::Value::Null);
            ServerMessage::Res {
                id: req_id.to_string(),
                result: data,
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("timeline query failed: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use chrono::{TimeZone, Utc};
    use encmind_core::types::{AgentId, TimelineEvent, TimelineEventId};

    /// Insert 6 diverse timeline events with fixed timestamps for deterministic filter tests.
    async fn seed_events(state: &AppState) {
        // Ensure the "research" agent exists (FK on timeline_events.agent_id → agents.id).
        // "main" is seeded by the migration; "research" is not.
        {
            let conn = state.db_pool.get().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO agents (id, name, is_default) VALUES ('research', 'Research Agent', 0)",
                [],
            )
            .unwrap();
        }
        let store = state.timeline_store.as_ref().expect("timeline_store");
        let events = vec![
            TimelineEvent {
                id: TimelineEventId::from_string(String::from("01JTEST0001")),
                event_type: "message".into(),
                source: "web".into(),
                session_id: None,
                agent_id: AgentId::new("main"),
                summary: "User asked about weather".into(),
                detail: Some(serde_json::json!({"tokens": 150})),
                created_at: Utc.with_ymd_and_hms(2026, 2, 20, 10, 0, 0).unwrap(),
            },
            TimelineEvent {
                id: TimelineEventId::from_string(String::from("01JTEST0002")),
                event_type: "message".into(),
                source: "telegram".into(),
                session_id: None,
                agent_id: AgentId::new("main"),
                summary: "User sent /status".into(),
                detail: None,
                created_at: Utc.with_ymd_and_hms(2026, 2, 20, 11, 0, 0).unwrap(),
            },
            TimelineEvent {
                id: TimelineEventId::from_string(String::from("01JTEST0003")),
                event_type: "cron_executed".into(),
                source: "cron".into(),
                session_id: None,
                agent_id: AgentId::new("main"),
                summary: "Daily digest ran".into(),
                detail: Some(serde_json::json!({"job_id": "digest-daily"})),
                created_at: Utc.with_ymd_and_hms(2026, 2, 21, 6, 0, 0).unwrap(),
            },
            TimelineEvent {
                id: TimelineEventId::from_string(String::from("01JTEST0004")),
                event_type: "cron_executed".into(),
                source: "cron".into(),
                session_id: None,
                agent_id: AgentId::new("main"),
                summary: "Backup reminder ran".into(),
                detail: Some(serde_json::json!({"job_id": "backup-remind"})),
                created_at: Utc.with_ymd_and_hms(2026, 2, 22, 6, 0, 0).unwrap(),
            },
            TimelineEvent {
                id: TimelineEventId::from_string(String::from("01JTEST0005")),
                event_type: "message".into(),
                source: "web".into(),
                session_id: None,
                agent_id: AgentId::new("research"),
                summary: "Research agent response".into(),
                detail: None,
                created_at: Utc.with_ymd_and_hms(2026, 2, 23, 14, 0, 0).unwrap(),
            },
            TimelineEvent {
                id: TimelineEventId::from_string(String::from("01JTEST0006")),
                event_type: "message".into(),
                source: "slack".into(),
                session_id: None,
                agent_id: AgentId::new("main"),
                summary: "Slack user asked question".into(),
                detail: Some(serde_json::json!({"channel": "#general"})),
                created_at: Utc.with_ymd_and_hms(2026, 2, 24, 9, 0, 0).unwrap(),
            },
        ];
        for event in &events {
            store.insert_event(event).await.unwrap();
        }
    }

    /// Helper: extract a successful result array from a ServerMessage::Res.
    fn unwrap_result_array(response: ServerMessage, expected_id: &str) -> Vec<serde_json::Value> {
        match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, expected_id);
                result
                    .as_array()
                    .unwrap_or_else(|| panic!("expected array, got {result}"))
                    .clone()
            }
            ServerMessage::Error { error, .. } => {
                panic!("expected Res, got Error: {}: {}", error.code, error.message)
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    // ---- Test 10.1: Query all events (no filters) ----

    #[tokio::test]
    async fn query_all_events_returns_seeded_data_desc_order() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(&state, serde_json::json!({}), "tl-10-1").await,
            "tl-10-1",
        );

        // All 6 events returned
        assert_eq!(items.len(), 6);

        // Descending order by created_at
        assert_eq!(items[0]["id"], "01JTEST0006");
        assert_eq!(items[1]["id"], "01JTEST0005");
        assert_eq!(items[2]["id"], "01JTEST0004");
        assert_eq!(items[3]["id"], "01JTEST0003");
        assert_eq!(items[4]["id"], "01JTEST0002");
        assert_eq!(items[5]["id"], "01JTEST0001");

        // Each event has the expected fields
        for item in &items {
            assert!(item.get("id").is_some(), "missing id");
            assert!(item.get("event_type").is_some(), "missing event_type");
            assert!(item.get("source").is_some(), "missing source");
            assert!(item.get("agent_id").is_some(), "missing agent_id");
            assert!(item.get("summary").is_some(), "missing summary");
            assert!(item.get("created_at").is_some(), "missing created_at");
            // session_id and detail may be null
        }

        // detail is a JSON object or null, never a stringified JSON
        let detail_0 = &items[0]["detail"];
        assert!(
            detail_0.is_object(),
            "detail should be object, got {detail_0}"
        );
        assert_eq!(detail_0["channel"], "#general");

        let detail_1 = &items[1]["detail"];
        assert!(detail_1.is_null(), "detail should be null for event 5");
    }

    // ---- Test 10.2: Filter by event_type ----

    #[tokio::test]
    async fn query_filter_by_event_type() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"event_type": "cron_executed"}),
                "tl-10-2",
            )
            .await,
            "tl-10-2",
        );

        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["event_type"], "cron_executed");
        assert_eq!(items[1]["event_type"], "cron_executed");
        // Descending: 01JTEST0004 before 01JTEST0003
        assert_eq!(items[0]["id"], "01JTEST0004");
        assert_eq!(items[1]["id"], "01JTEST0003");
    }

    #[tokio::test]
    async fn query_filter_by_nonexistent_event_type_returns_empty() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"event_type": "nonexistent_type"}),
                "tl-10-2-neg",
            )
            .await,
            "tl-10-2-neg",
        );
        assert!(items.is_empty());
    }

    // ---- Test 10.3a: Both since and until ----

    #[tokio::test]
    async fn query_date_range_both_bounds() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({
                    "since": "2026-02-21T00:00:00Z",
                    "until": "2026-02-23T00:00:00Z"
                }),
                "tl-10-3a",
            )
            .await,
            "tl-10-3a",
        );

        // Should include events at 2026-02-21T06:00 and 2026-02-22T06:00
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "01JTEST0004"); // Feb 22
        assert_eq!(items[1]["id"], "01JTEST0003"); // Feb 21
    }

    // ---- Test 10.3b: Only since ----

    #[tokio::test]
    async fn query_date_range_since_only() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"since": "2026-02-23T00:00:00Z"}),
                "tl-10-3b",
            )
            .await,
            "tl-10-3b",
        );

        // Events on or after Feb 23: 01JTEST0005 (Feb 23 14:00) and 01JTEST0006 (Feb 24 09:00)
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "01JTEST0006");
        assert_eq!(items[1]["id"], "01JTEST0005");
    }

    // ---- Test 10.3c: Only until ----

    #[tokio::test]
    async fn query_date_range_until_only() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"until": "2026-02-20T10:30:00Z"}),
                "tl-10-3c",
            )
            .await,
            "tl-10-3c",
        );

        // Only 01JTEST0001 (10:00:00Z) is <= 10:30:00Z. 01JTEST0002 (11:00:00Z) is excluded.
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "01JTEST0001");
    }

    // ---- Test 10.4a: Limit only ----

    #[tokio::test]
    async fn query_pagination_limit_only() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"limit": 2, "offset": 0}),
                "tl-10-4a",
            )
            .await,
            "tl-10-4a",
        );

        assert_eq!(items.len(), 2);
        // Most recent 2
        assert_eq!(items[0]["id"], "01JTEST0006");
        assert_eq!(items[1]["id"], "01JTEST0005");
    }

    // ---- Test 10.4b: Offset + limit ----

    #[tokio::test]
    async fn query_pagination_offset_plus_limit() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"limit": 2, "offset": 2}),
                "tl-10-4b",
            )
            .await,
            "tl-10-4b",
        );

        assert_eq!(items.len(), 2);
        // Positions 2 and 3 (0-indexed): 01JTEST0004, 01JTEST0003
        assert_eq!(items[0]["id"], "01JTEST0004");
        assert_eq!(items[1]["id"], "01JTEST0003");
    }

    // ---- Test 10.4c: Offset beyond available rows ----

    #[tokio::test]
    async fn query_pagination_offset_beyond_rows() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"limit": 10, "offset": 100}),
                "tl-10-4c",
            )
            .await,
            "tl-10-4c",
        );

        assert!(items.is_empty());
    }

    // ---- Test 10.4d: Limit clamped to max 200 ----

    #[tokio::test]
    async fn query_pagination_limit_clamped_to_max() {
        let state = make_test_state();
        seed_events(&state).await;

        // Requesting limit=999 should succeed (clamped to 200), returning all 6 events
        let items = unwrap_result_array(
            handle_query(&state, serde_json::json!({"limit": 999}), "tl-10-4d").await,
            "tl-10-4d",
        );

        assert_eq!(items.len(), 6);
    }

    // ---- Test 10.4e: Limit clamped to min 1 ----

    #[tokio::test]
    async fn query_pagination_limit_clamped_to_min() {
        let state = make_test_state();
        seed_events(&state).await;

        // limit=0 should be clamped to 1, returning exactly 1 event
        let items = unwrap_result_array(
            handle_query(&state, serde_json::json!({"limit": 0}), "tl-10-4e").await,
            "tl-10-4e",
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "01JTEST0006"); // most recent
    }

    // ---- Test 10.2 extra: Filter by source ----

    #[tokio::test]
    async fn query_filter_by_source() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(&state, serde_json::json!({"source": "cron"}), "tl-src").await,
            "tl-src",
        );

        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|e| e["source"] == "cron"));
    }

    // ---- Test 10.2 extra: Filter by agent_id ----

    #[tokio::test]
    async fn query_filter_by_agent_id() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({"agent_id": "research"}),
                "tl-agent",
            )
            .await,
            "tl-agent",
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "01JTEST0005");
    }

    // ---- Test: Combined filters (event_type + since) ----

    #[tokio::test]
    async fn query_combined_event_type_and_since() {
        let state = make_test_state();
        seed_events(&state).await;

        let items = unwrap_result_array(
            handle_query(
                &state,
                serde_json::json!({
                    "event_type": "message",
                    "since": "2026-02-23T00:00:00Z"
                }),
                "tl-combined",
            )
            .await,
            "tl-combined",
        );

        // Messages on or after Feb 23: 01JTEST0005, 01JTEST0006
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|e| e["event_type"] == "message"));
    }

    #[tokio::test]
    async fn timeline_query_rejects_invalid_since() {
        let state = make_test_state();
        let response = handle_query(
            &state,
            serde_json::json!({"since": "not-a-date"}),
            "req-tl-invalid",
        )
        .await;

        match response {
            ServerMessage::Error { id, error } => {
                assert_eq!(id.as_deref(), Some("req-tl-invalid"));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("invalid since RFC3339 timestamp"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[tokio::test]
    async fn timeline_query_rejects_invalid_until_type() {
        let state = make_test_state();
        let response = handle_query(
            &state,
            serde_json::json!({"until": 12345}),
            "req-tl-invalid-type",
        )
        .await;

        match response {
            ServerMessage::Error { id, error } => {
                assert_eq!(id.as_deref(), Some("req-tl-invalid-type"));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("until must be an RFC3339 string"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[tokio::test]
    async fn timeline_query_rejects_inverted_range() {
        let state = make_test_state();
        let response = handle_query(
            &state,
            serde_json::json!({
                "since": "2026-02-16T00:00:00Z",
                "until": "2026-02-15T00:00:00Z",
            }),
            "req-tl-range",
        )
        .await;

        match response {
            ServerMessage::Error { id, error } => {
                assert_eq!(id.as_deref(), Some("req-tl-range"));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert_eq!(error.message, "since must be <= until");
            }
            _ => panic!("expected Error"),
        }
    }

    #[tokio::test]
    async fn timeline_query_clamps_large_offset_without_wrapping() {
        let state = make_test_state();
        if let Some(store) = &state.timeline_store {
            let event = TimelineEvent {
                id: TimelineEventId::new(),
                event_type: "message".into(),
                source: "web".into(),
                session_id: None,
                agent_id: AgentId::default(),
                summary: "hello".into(),
                detail: None,
                created_at: Utc::now(),
            };
            store.insert_event(&event).await.unwrap();
        }

        let response = handle_query(
            &state,
            serde_json::json!({
                "offset": (u32::MAX as u64) + 1,
                "limit": 1,
            }),
            "req-tl-clamp",
        )
        .await;

        match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-tl-clamp");
                let items = result.as_array().expect("array result");
                assert!(items.is_empty(), "offset should not wrap back to zero");
            }
            _ => panic!("expected Res"),
        }
    }

    #[tokio::test]
    async fn timeline_query_accepts_null_since_until() {
        let state = make_test_state();
        let response = handle_query(
            &state,
            serde_json::json!({
                "since": null,
                "until": null,
            }),
            "req-tl-null",
        )
        .await;

        match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-tl-null");
                assert!(result.is_array());
            }
            _ => panic!("expected Res"),
        }
    }
}
