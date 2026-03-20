use crate::protocol::*;
use crate::state::AppState;
use encmind_core::error::StorageError;
use tracing::warn;

/// Handle timers.list — list all skill timers.
pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let timer_store = match &state.skill_timer_store {
        Some(store) => store,
        None => {
            return ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!([]),
            };
        }
    };

    match timer_store.list_timers().await {
        Ok(timers) => {
            let data: Vec<serde_json::Value> = timers
                .into_iter()
                .map(|t| {
                    serde_json::json!({
                        "id": t.id,
                        "skill_id": t.skill_id,
                        "timer_name": t.timer_name,
                        "interval_secs": t.interval_secs,
                        "export_fn": t.export_fn,
                        "enabled": t.enabled,
                        "last_tick_at": t.last_tick_at.map(|dt| dt.to_rfc3339()),
                        "next_tick_at": t.next_tick_at.map(|dt| dt.to_rfc3339()),
                        "consecutive_failures": t.consecutive_failures,
                    })
                })
                .collect();
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!(data),
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("timers list failed: {e}")),
        },
    }
}

/// Handle timers.toggle — enable or disable a skill timer by id.
pub async fn handle_toggle(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let timer_store = match &state.skill_timer_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "timers not configured"),
            };
        }
    };

    let timer_id = match params.get("id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            };
        }
    };

    let enabled = match params.get("enabled").and_then(|v| v.as_bool()) {
        Some(e) => e,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "enabled (bool) is required"),
            };
        }
    };

    // Check timer exists
    let timers = match timer_store.list_timers().await {
        Ok(t) => t,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("failed to list timers: {e}")),
            };
        }
    };

    let timer = match timers.iter().find(|t| t.id == timer_id) {
        Some(t) => t.clone(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "timer not found"),
            };
        }
    };

    if enabled {
        // Re-enable: set enabled=true, reset failures, set next_tick to now
        match timer_store.enable_timer(timer_id, chrono::Utc::now()).await {
            Ok(()) => {
                let action = format!("skill.{}.timer_toggle", timer.skill_id);
                let detail = serde_json::json!({
                    "timer_id": timer.id,
                    "timer_name": timer.timer_name,
                    "enabled": true,
                });
                if let Err(e) =
                    state
                        .audit
                        .append("skill", &action, Some(&detail.to_string()), Some("admin"))
                {
                    warn!(
                        error = %e,
                        skill_id = %timer.skill_id,
                        timer_id = %timer.id,
                        "failed to append timers.toggle audit event"
                    );
                }

                ServerMessage::Res {
                    id: req_id.to_string(),
                    result: serde_json::json!({"id": timer_id, "enabled": true}),
                }
            }
            Err(e) => match e {
                StorageError::NotFound(_) => ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(ERR_INVALID_PARAMS, "timer not found"),
                },
                _ => ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(ERR_INTERNAL, format!("failed to enable timer: {e}")),
                },
            },
        }
    } else {
        // Disable
        match timer_store.disable_timer(timer_id).await {
            Ok(()) => {
                let action = format!("skill.{}.timer_toggle", timer.skill_id);
                let detail = serde_json::json!({
                    "timer_id": timer.id,
                    "timer_name": timer.timer_name,
                    "enabled": false,
                });
                if let Err(e) =
                    state
                        .audit
                        .append("skill", &action, Some(&detail.to_string()), Some("admin"))
                {
                    warn!(
                        error = %e,
                        skill_id = %timer.skill_id,
                        timer_id = %timer.id,
                        "failed to append timers.toggle audit event"
                    );
                }

                ServerMessage::Res {
                    id: req_id.to_string(),
                    result: serde_json::json!({"id": timer_id, "enabled": false}),
                }
            }
            Err(e) => match e {
                StorageError::NotFound(_) => ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(ERR_INVALID_PARAMS, "timer not found"),
                },
                _ => ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(ERR_INTERNAL, format!("failed to disable timer: {e}")),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use encmind_storage::audit::AuditFilter;

    #[tokio::test]
    async fn timers_list_empty() {
        let state = make_test_state();
        let result = handle_list(&state, serde_json::json!({}), "req-t1").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t1");
                assert!(result.as_array().unwrap().is_empty());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timers_list_with_data() {
        let state = make_test_state();
        let store = state.skill_timer_store.as_ref().unwrap();

        let now = chrono::Utc::now();
        let timer = encmind_core::types::SkillTimer {
            id: "skill-a:heartbeat".into(),
            skill_id: "skill-a".into(),
            timer_name: "heartbeat".into(),
            interval_secs: 120,
            export_fn: "on_tick".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now),
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: now,
            updated_at: now,
        };
        store.upsert_timer(&timer).await.unwrap();

        let result = handle_list(&state, serde_json::json!({}), "req-t2").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t2");
                let arr = result.as_array().unwrap();
                assert_eq!(arr.len(), 1);
                assert_eq!(arr[0]["skill_id"], "skill-a");
                assert_eq!(arr[0]["timer_name"], "heartbeat");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timers_toggle_disable() {
        let state = make_test_state();
        let store = state.skill_timer_store.as_ref().unwrap();

        let now = chrono::Utc::now();
        let timer = encmind_core::types::SkillTimer {
            id: "skill-a:check".into(),
            skill_id: "skill-a".into(),
            timer_name: "check".into(),
            interval_secs: 60,
            export_fn: "on_check".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now),
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: now,
            updated_at: now,
        };
        store.upsert_timer(&timer).await.unwrap();

        let result = handle_toggle(
            &state,
            serde_json::json!({"id": "skill-a:check", "enabled": false}),
            "req-t3",
        )
        .await;

        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t3");
                assert_eq!(result["enabled"], false);
            }
            other => panic!("Expected Res, got {other:?}"),
        }

        // Verify disabled in store
        let timers = store.list_timers().await.unwrap();
        assert!(!timers[0].enabled);
    }

    #[tokio::test]
    async fn timers_toggle_enable() {
        let state = make_test_state();
        let store = state.skill_timer_store.as_ref().unwrap();

        let now = chrono::Utc::now();
        let timer = encmind_core::types::SkillTimer {
            id: "skill-b:poll".into(),
            skill_id: "skill-b".into(),
            timer_name: "poll".into(),
            interval_secs: 300,
            export_fn: "on_poll".into(),
            enabled: false,
            last_tick_at: None,
            next_tick_at: None,
            source_manifest_hash: None,
            consecutive_failures: 3,
            created_at: now,
            updated_at: now,
        };
        store.upsert_timer(&timer).await.unwrap();

        let result = handle_toggle(
            &state,
            serde_json::json!({"id": "skill-b:poll", "enabled": true}),
            "req-t4",
        )
        .await;

        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t4");
                assert_eq!(result["enabled"], true);
            }
            other => panic!("Expected Res, got {other:?}"),
        }

        // Verify re-enabled with reset failures and next_tick set
        let timers = store.list_timers().await.unwrap();
        let t = &timers[0];
        assert!(t.enabled);
        assert_eq!(t.consecutive_failures, 0);
        assert!(t.next_tick_at.is_some());
    }

    #[tokio::test]
    async fn timers_toggle_emits_audit_event() {
        let state = make_test_state();
        let store = state.skill_timer_store.as_ref().unwrap();

        let now = chrono::Utc::now();
        let timer = encmind_core::types::SkillTimer {
            id: "skill-a:audit".into(),
            skill_id: "skill-a".into(),
            timer_name: "audit".into(),
            interval_secs: 60,
            export_fn: "on_audit".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now),
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: now,
            updated_at: now,
        };
        store.upsert_timer(&timer).await.unwrap();

        let result = handle_toggle(
            &state,
            serde_json::json!({"id": "skill-a:audit", "enabled": false}),
            "req-t-audit",
        )
        .await;
        match result {
            ServerMessage::Res { .. } => {}
            other => panic!("expected Res, got {other:?}"),
        }

        let entries = state
            .audit
            .query(
                AuditFilter {
                    action: Some("skill.skill-a.timer_toggle".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 1);
        let detail = entries[0]
            .detail
            .as_ref()
            .expect("audit detail should be present");
        let detail_json: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(detail_json["timer_id"], "skill-a:audit");
        assert_eq!(detail_json["timer_name"], "audit");
        assert_eq!(detail_json["enabled"], false);
        assert_eq!(entries[0].source.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn timers_toggle_missing_id() {
        let state = make_test_state();
        let result = handle_toggle(&state, serde_json::json!({"enabled": true}), "req-t5").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("id is required"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timers_toggle_not_found() {
        let state = make_test_state();
        let result = handle_toggle(
            &state,
            serde_json::json!({"id": "nonexistent", "enabled": true}),
            "req-t6",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("timer not found"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }
}
