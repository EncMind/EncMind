use crate::protocol::*;
use crate::state::AppState;

pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    match state
        .session_store
        .list_sessions(encmind_core::types::SessionFilter::default())
        .await
    {
        Ok(sessions) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"sessions": sessions}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_create(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let channel = params["channel"].as_str().unwrap_or("web");
    match state.session_store.create_session(channel).await {
        Ok(session) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"session": session}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_delete(
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
    match state.session_store.delete_session(&sid).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "deleted"}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_rename(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let session_id = params["session_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let title = params["title"].as_str().unwrap_or_default().to_string();

    if session_id.is_empty() || title.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "session_id and title required"),
        };
    }

    let sid = encmind_core::types::SessionId::from_string(&session_id);
    match state.session_store.rename_session(&sid, &title).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "renamed"}),
        },
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

    // ── 11.1: Create Session ──────────────────────────────────

    #[tokio::test]
    async fn create_session_returns_new_session() {
        let state = make_test_state();
        let response = handle_create(&state, serde_json::json!({}), "s-11-1").await;

        match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "s-11-1");
                let session = &result["session"];
                assert!(
                    session["id"].as_str().is_some_and(|s| !s.is_empty()),
                    "session.id should be a non-empty string"
                );
                assert_eq!(session["channel"], "web");
                assert!(session["title"].is_null());
                assert_eq!(session["agent_id"], "main");
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_session_with_custom_channel() {
        let state = make_test_state();
        let response = handle_create(
            &state,
            serde_json::json!({"channel": "telegram"}),
            "s-11-1b",
        )
        .await;

        match response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["session"]["channel"], "telegram");
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    // ── 11.2: List Sessions ───────────────────────────────────

    #[tokio::test]
    async fn list_sessions_shows_all() {
        let state = make_test_state();
        state.session_store.create_session("web").await.unwrap();
        state
            .session_store
            .create_session("telegram")
            .await
            .unwrap();
        state.session_store.create_session("slack").await.unwrap();

        let response = handle_list(&state, serde_json::json!({}), "s-11-2").await;

        match response {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "s-11-2");
                let sessions = result["sessions"].as_array().unwrap();
                assert_eq!(sessions.len(), 3);
                for s in sessions {
                    assert!(s["id"].as_str().is_some_and(|v| !v.is_empty()));
                    assert!(s["channel"].as_str().is_some());
                    assert!(s["created_at"].as_str().is_some());
                    assert!(s["updated_at"].as_str().is_some());
                }
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_sessions_empty_when_none() {
        let state = make_test_state();
        let response = handle_list(&state, serde_json::json!({}), "s-11-2b").await;

        match response {
            ServerMessage::Res { result, .. } => {
                let sessions = result["sessions"].as_array().unwrap();
                assert!(sessions.is_empty());
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    // ── 11.4: Rename Session ──────────────────────────────────

    #[tokio::test]
    async fn rename_session_updates_title() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        let response = handle_rename(
            &state,
            serde_json::json!({"session_id": sid, "title": "My Chat"}),
            "s-11-4",
        )
        .await;

        match response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["status"], "renamed");
            }
            other => panic!("expected Res, got {other:?}"),
        }

        let updated = state
            .session_store
            .get_session(&session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.title, Some("My Chat".to_string()));
    }

    #[tokio::test]
    async fn rename_visible_in_list() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        handle_rename(
            &state,
            serde_json::json!({"session_id": sid, "title": "My Chat"}),
            "s-11-4b",
        )
        .await;

        let response = handle_list(&state, serde_json::json!({}), "s-11-4c").await;
        match response {
            ServerMessage::Res { result, .. } => {
                let sessions = result["sessions"].as_array().unwrap();
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0]["title"], "My Chat");
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rename_rejects_empty_title() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        let response = handle_rename(
            &state,
            serde_json::json!({"session_id": sid, "title": ""}),
            "s-11-4d",
        )
        .await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("session_id and title required"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rename_rejects_missing_session_id() {
        let state = make_test_state();
        let response = handle_rename(&state, serde_json::json!({"title": "x"}), "s-11-4e").await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── 11.5: Delete Session ──────────────────────────────────

    #[tokio::test]
    async fn delete_session_removes_from_list() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        // Verify it appears in list
        let list_response = handle_list(&state, serde_json::json!({}), "s-11-5a").await;
        match &list_response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["sessions"].as_array().unwrap().len(), 1);
            }
            _ => panic!("expected list to have 1 session"),
        }

        // Delete
        let response =
            handle_delete(&state, serde_json::json!({"session_id": sid}), "s-11-5b").await;
        match response {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["status"], "deleted");
            }
            other => panic!("expected Res, got {other:?}"),
        }

        // Verify it's gone
        let list_response = handle_list(&state, serde_json::json!({}), "s-11-5c").await;
        match list_response {
            ServerMessage::Res { result, .. } => {
                assert!(result["sessions"].as_array().unwrap().is_empty());
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_rejects_empty_session_id() {
        let state = make_test_state();
        let response = handle_delete(&state, serde_json::json!({}), "s-11-5d").await;

        match response {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
