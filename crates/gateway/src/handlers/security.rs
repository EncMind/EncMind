use crate::protocol::*;
use crate::state::AppState;

pub async fn handle_lockdown(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let should_activate = params["active"].as_bool().unwrap_or(false);
    let reason = params["reason"].as_str().unwrap_or("manual").to_string();

    if should_activate {
        state.lockdown.activate(&reason);
    } else {
        state.lockdown.deactivate();
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "active": state.lockdown.is_active(),
        }),
    }
}

pub async fn handle_audit(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let limit = (params["limit"].as_u64().unwrap_or(50) as u32).clamp(1, 200);
    let offset = params["offset"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32;
    let category = params["category"].as_str().map(|s| s.to_string());
    let action = params["action"].as_str().map(|s| s.to_string());
    let since = params["since"].as_str().map(|s| s.to_string());
    let until = params["until"].as_str().map(|s| s.to_string());

    let skill_id = match params["skill_id"].as_str() {
        Some(raw) => {
            let skill_id = raw.trim();
            if let Err(reason) = encmind_core::skill_id::validate_skill_id(skill_id) {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
                };
            }
            Some(skill_id.to_string())
        }
        None => None,
    };

    let filter = encmind_storage::audit::AuditFilter {
        category,
        action,
        since,
        until,
        skill_id,
    };

    match state.audit.query(filter, limit, offset) {
        Ok(entries) => {
            let entries_json: Vec<_> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "category": e.category,
                        "action": e.action,
                        "detail": e.detail,
                        "source": e.source,
                    })
                })
                .collect();
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({"entries": entries_json}),
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;

    #[tokio::test]
    async fn audit_filters_by_action() {
        let state = make_test_state();

        // Insert audit entries with different actions
        let _ = state.audit.append("keys", "set", Some("openai"), None);
        let _ = state.audit.append("keys", "delete", Some("openai"), None);
        let _ = state.audit.append("security", "lockdown", None, None);

        let result = handle_audit(&state, serde_json::json!({"action": "set"}), "req-a1").await;
        match result {
            ServerMessage::Res { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                assert!(!entries.is_empty());
                for entry in entries {
                    assert_eq!(entry["action"], "set");
                }
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn audit_filters_by_date_range() {
        let state = make_test_state();

        let _ = state.audit.append("test", "action1", None, None);

        // Query with since far in the future — should return nothing
        let result = handle_audit(
            &state,
            serde_json::json!({"since": "2099-01-01T00:00:00Z"}),
            "req-a2",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                assert!(entries.is_empty());
            }
            _ => panic!("Expected Res"),
        }

        // Query with until far in the future — should return the entry
        let result = handle_audit(
            &state,
            serde_json::json!({"until": "2099-01-01T00:00:00Z"}),
            "req-a3",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                assert!(!entries.is_empty());
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn audit_clamps_pagination() {
        let state = make_test_state();

        // Insert a few entries
        for i in 0..5 {
            let _ = state.audit.append("test", &format!("act-{i}"), None, None);
        }

        // limit=0 should clamp to 1
        let result = handle_audit(&state, serde_json::json!({"limit": 0}), "req-a4").await;
        match result {
            ServerMessage::Res { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                assert_eq!(entries.len(), 1);
            }
            _ => panic!("Expected Res"),
        }

        // limit=999 should clamp to 200
        let result = handle_audit(&state, serde_json::json!({"limit": 999}), "req-a5").await;
        match result {
            ServerMessage::Res { result, .. } => {
                let entries = result["entries"].as_array().unwrap();
                // We only have 5 entries, so should return all 5 (clamped to 200 but only 5 exist)
                assert_eq!(entries.len(), 5);
            }
            _ => panic!("Expected Res"),
        }
    }
}
