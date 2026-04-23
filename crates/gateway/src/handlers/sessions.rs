use crate::protocol::*;
use crate::state::AppState;

/// Map a StorageError to an appropriate protocol error code + message.
fn storage_err(req_id: &str, e: encmind_core::error::StorageError) -> ServerMessage {
    use encmind_core::error::StorageError;
    let (code, msg) = match &e {
        StorageError::NotFound(_) => (ERR_NOT_FOUND, e.to_string()),
        StorageError::ValidationFailed(_) => (ERR_INVALID_PARAMS, e.to_string()),
        StorageError::NotSupported(_) => (ERR_NOT_IMPLEMENTED, e.to_string()),
        _ => (ERR_INTERNAL, e.to_string()),
    };
    ServerMessage::Error {
        id: Some(req_id.to_string()),
        error: ErrorPayload::new(code, msg),
    }
}

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
        Err(e) => storage_err(req_id, e),
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
        Err(e) => storage_err(req_id, e),
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
        Err(e) => storage_err(req_id, e),
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
        Err(e) => storage_err(req_id, e),
    }
}

pub async fn handle_archive(
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
    match state.session_store.archive_session(&sid).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "archived"}),
        },
        Err(e) => storage_err(req_id, e),
    }
}

pub async fn handle_unarchive(
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
    match state.session_store.unarchive_session(&sid).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "unarchived"}),
        },
        Err(e) => storage_err(req_id, e),
    }
}

pub async fn handle_export(
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
    match state.session_store.export_session(&sid).await {
        Ok(export) => match serde_json::to_value(&export) {
            Ok(val) => ServerMessage::Res {
                id: req_id.to_string(),
                result: val,
            },
            Err(e) => ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("export serialization failed: {e}")),
            },
        },
        Err(e) => storage_err(req_id, e),
    }
}

pub async fn handle_tag_add(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let session_id = params["session_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let tag = params["tag"].as_str().unwrap_or_default().to_string();
    if session_id.is_empty() || tag.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "session_id and tag required"),
        };
    }
    let sid = encmind_core::types::SessionId::from_string(&session_id);
    match state.session_store.add_session_tag(&sid, &tag).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "added", "tag": tag}),
        },
        Err(e) => storage_err(req_id, e),
    }
}

pub async fn handle_tag_remove(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let session_id = params["session_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let tag = params["tag"].as_str().unwrap_or_default().to_string();
    if session_id.is_empty() || tag.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "session_id and tag required"),
        };
    }
    let sid = encmind_core::types::SessionId::from_string(&session_id);
    match state.session_store.remove_session_tag(&sid, &tag).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "removed", "tag": tag}),
        },
        Err(e) => storage_err(req_id, e),
    }
}

pub async fn handle_tags(
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
    match state.session_store.get_session_tags(&sid).await {
        Ok(tags) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"tags": tags}),
        },
        Err(e) => storage_err(req_id, e),
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

    // ── Archive / Unarchive ──────────────────────────────────

    #[tokio::test]
    async fn archive_session_success() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        let response =
            handle_archive(&state, serde_json::json!({"session_id": sid}), "arc-1").await;
        match response {
            ServerMessage::Res { result, .. } => assert_eq!(result["status"], "archived"),
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn archive_nonexistent_returns_not_found() {
        let state = make_test_state();
        let response = handle_archive(
            &state,
            serde_json::json!({"session_id": "missing"}),
            "arc-2",
        )
        .await;
        match response {
            ServerMessage::Error { error, .. } => assert_eq!(error.code, ERR_NOT_FOUND),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unarchive_session_success() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();
        state
            .session_store
            .archive_session(&session.id)
            .await
            .unwrap();

        let response =
            handle_unarchive(&state, serde_json::json!({"session_id": sid}), "unarc-1").await;
        match response {
            ServerMessage::Res { result, .. } => assert_eq!(result["status"], "unarchived"),
            other => panic!("expected Res, got {other:?}"),
        }
    }

    // ── Export ────────────────────────────────────────────────

    #[tokio::test]
    async fn export_session_returns_messages() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        let msg = encmind_core::types::Message {
            id: encmind_core::types::MessageId::new(),
            role: encmind_core::types::Role::User,
            content: vec![encmind_core::types::ContentBlock::Text {
                text: "hello export".into(),
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        };
        state
            .session_store
            .append_message(&session.id, &msg)
            .await
            .unwrap();

        let response = handle_export(&state, serde_json::json!({"session_id": sid}), "exp-1").await;
        match response {
            ServerMessage::Res { result, .. } => {
                let messages = result["messages"].as_array().unwrap();
                assert_eq!(messages.len(), 1);
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn export_nonexistent_returns_not_found() {
        let state = make_test_state();
        let response = handle_export(
            &state,
            serde_json::json!({"session_id": "missing"}),
            "exp-2",
        )
        .await;
        match response {
            ServerMessage::Error { error, .. } => assert_eq!(error.code, ERR_NOT_FOUND),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── Tags ─────────────────────────────────────────────────

    #[tokio::test]
    async fn tag_add_remove_list_round_trip() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        // Add
        let response = handle_tag_add(
            &state,
            serde_json::json!({"session_id": sid, "tag": "important"}),
            "tag-1",
        )
        .await;
        match &response {
            ServerMessage::Res { result, .. } => assert_eq!(result["status"], "added"),
            other => panic!("expected Res, got {other:?}"),
        }

        // List
        let response = handle_tags(&state, serde_json::json!({"session_id": sid}), "tag-2").await;
        match &response {
            ServerMessage::Res { result, .. } => {
                let tags = result["tags"].as_array().unwrap();
                assert_eq!(tags.len(), 1);
                assert_eq!(tags[0], "important");
            }
            other => panic!("expected Res, got {other:?}"),
        }

        // Remove
        let response = handle_tag_remove(
            &state,
            serde_json::json!({"session_id": sid, "tag": "important"}),
            "tag-3",
        )
        .await;
        match &response {
            ServerMessage::Res { result, .. } => assert_eq!(result["status"], "removed"),
            other => panic!("expected Res, got {other:?}"),
        }

        // List again — should be empty
        let response = handle_tags(&state, serde_json::json!({"session_id": sid}), "tag-4").await;
        match response {
            ServerMessage::Res { result, .. } => {
                assert!(result["tags"].as_array().unwrap().is_empty());
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tag_add_invalid_format_returns_error() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        let sid = session.id.as_str().to_string();

        let response = handle_tag_add(
            &state,
            serde_json::json!({"session_id": sid, "tag": "has spaces"}),
            "tag-5",
        )
        .await;
        match response {
            ServerMessage::Error { error, .. } => assert_eq!(error.code, ERR_INVALID_PARAMS),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tags_nonexistent_session_returns_not_found() {
        let state = make_test_state();
        let response = handle_tags(
            &state,
            serde_json::json!({"session_id": "missing"}),
            "tag-6",
        )
        .await;
        match response {
            ServerMessage::Error { error, .. } => assert_eq!(error.code, ERR_NOT_FOUND),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── Error mapping ────────────────────────────────────────

    #[test]
    fn storage_err_maps_not_supported_to_not_implemented() {
        use encmind_core::error::StorageError;
        let resp = storage_err("r1", StorageError::NotSupported("archive_session".into()));
        match resp {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_NOT_IMPLEMENTED);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn storage_err_maps_validation_failed_to_invalid_params() {
        use encmind_core::error::StorageError;
        let resp = storage_err(
            "r2",
            StorageError::ValidationFailed("tag must be 1-64 characters".into()),
        );
        match resp {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn storage_err_maps_data_corruption_to_internal() {
        use encmind_core::error::StorageError;
        // Non-tag InvalidData (e.g., timestamp parse failure) → internal error
        let resp = storage_err(
            "r3",
            StorageError::InvalidData("invalid timestamp '???': parse error".into()),
        );
        match resp {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INTERNAL);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
