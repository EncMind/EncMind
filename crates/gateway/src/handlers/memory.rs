use crate::protocol::*;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use encmind_core::types::{MemoryFilter, Pagination, SessionId};

const MAX_SEARCH_LIMIT: u64 = 100;
const MAX_LIST_LIMIT: u64 = 200;

fn parse_rfc3339_utc(
    params: &serde_json::Value,
    key: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    match params.get(key).and_then(|value| value.as_str()) {
        Some(raw) => DateTime::parse_from_rfc3339(raw)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|e| format!("{key} must be RFC3339: {e}")),
        None => Ok(None),
    }
}

fn parse_memory_filter(params: &serde_json::Value) -> Result<MemoryFilter, String> {
    let source_channel = params
        .get("source_channel")
        .and_then(|value| value.as_str())
        .map(|value| value.to_owned());
    let source_device = params
        .get("source_device")
        .and_then(|value| value.as_str())
        .map(|value| value.to_owned());
    let session_id = params
        .get("session_id")
        .and_then(|value| value.as_str())
        .map(SessionId::from_string);
    let since = parse_rfc3339_utc(params, "since")?;
    let until = parse_rfc3339_utc(params, "until")?;

    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Err("since must be <= until".to_owned());
        }
        Ok(MemoryFilter {
            source_channel,
            source_device,
            session_id,
            since: Some(since),
            until: Some(until),
        })
    } else {
        Ok(MemoryFilter {
            source_channel,
            source_device,
            session_id,
            since,
            until,
        })
    }
}

fn has_filter(filter: &MemoryFilter) -> bool {
    filter.source_channel.is_some()
        || filter.source_device.is_some()
        || filter.session_id.is_some()
        || filter.since.is_some()
        || filter.until.is_some()
}

/// Handle memory.search
pub async fn handle_search(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let memory_store = match &state.memory_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "memory not enabled"),
            };
        }
    };

    let query = params["query"].as_str().unwrap_or("");
    if query.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "query is required"),
        };
    }

    let default_limit = {
        let config = state.config.read().await;
        config.memory.default_search_limit as u64
    };
    let limit = params["limit"]
        .as_u64()
        .unwrap_or(default_limit)
        .clamp(1, MAX_SEARCH_LIMIT) as usize;

    let filter = match parse_memory_filter(&params) {
        Ok(filter) => filter,
        Err(message) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
            };
        }
    };
    let filter_opt = if has_filter(&filter) {
        Some(&filter)
    } else {
        None
    };

    match memory_store.search(query, limit, filter_opt).await {
        Ok(results) => {
            let data = serde_json::to_value(&results).unwrap_or(serde_json::Value::Null);
            ServerMessage::Res {
                id: req_id.to_string(),
                result: data,
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("memory search failed: {e}")),
        },
    }
}

/// Handle memory.list
pub async fn handle_list(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let memory_store = match &state.memory_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "memory not enabled"),
            };
        }
    };

    let filter = match parse_memory_filter(&params) {
        Ok(filter) => filter,
        Err(message) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
            };
        }
    };
    let pagination = Pagination {
        offset: params["offset"].as_u64().unwrap_or(0).min(u32::MAX as u64) as u32,
        limit: params["limit"]
            .as_u64()
            .unwrap_or(50)
            .clamp(1, MAX_LIST_LIMIT) as u32,
    };

    match memory_store.list(&filter, &pagination).await {
        Ok(entries) => {
            let data = serde_json::to_value(&entries).unwrap_or(serde_json::Value::Null);
            ServerMessage::Res {
                id: req_id.to_string(),
                result: data,
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("memory list failed: {e}")),
        },
    }
}

/// Handle memory.delete
pub async fn handle_delete(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let memory_store = match &state.memory_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "memory not enabled"),
            };
        }
    };

    let id_str = match params["id"].as_str() {
        Some(id) => id,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            };
        }
    };

    let memory_id = encmind_core::types::MemoryId::from_string(id_str);
    match memory_store.delete(&memory_id).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"deleted": true}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("memory delete failed: {e}")),
        },
    }
}

/// Handle memory.status
pub async fn handle_status(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let memory_store = match &state.memory_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "memory not enabled"),
            };
        }
    };

    match memory_store.status().await {
        Ok(status) => {
            let data = serde_json::to_value(&status).unwrap_or(serde_json::Value::Null);
            ServerMessage::Res {
                id: req_id.to_string(),
                result: data,
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("memory status failed: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::test_utils::make_test_state;

    fn make_test_state_with_memory() -> AppState {
        let mut state = make_test_state();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let embedder = Arc::new(encmind_memory::embedder::MockEmbedder::new(128));
        let vector_store = Arc::new(encmind_memory::vector_store::InMemoryVectorStore::new());
        let metadata_store =
            Arc::new(encmind_storage::memory_metadata::SqliteMemoryMetadataStore::new(pool));
        state.memory_store = Some(Arc::new(
            encmind_memory::memory_store::MemoryStoreImpl::new(
                embedder,
                vector_store,
                metadata_store,
            ),
        ));
        state
    }

    #[tokio::test]
    async fn memory_status_returns_store_info() {
        let state = make_test_state_with_memory();
        let result = handle_status(&state, serde_json::json!({}), "req-13-1").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-13-1");
                assert_eq!(result["entry_count"], 0);
                assert_eq!(result["model_name"], "mock-embedder");
                assert_eq!(result["embedding_dimensions"], 128);
            }
            other => panic!("expected Res, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn memory_list_returns_entries() {
        let state = make_test_state_with_memory();
        let store = state.memory_store.as_ref().unwrap();
        let entry = store
            .insert("test memory content", None, Some("web".into()), None)
            .await
            .expect("insert should succeed");

        let result = handle_list(&state, serde_json::json!({}), "req-13-2").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-13-2");
                let entries = result.as_array().expect("result should be an array");
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0]["summary"], "test memory content");
                assert_eq!(entries[0]["id"], entry.id.as_str());
            }
            other => panic!("expected Res, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn memory_list_without_store_returns_error() {
        let state = make_test_state();
        let result = handle_list(&state, serde_json::json!({}), "req-13-3").await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id.as_deref(), Some("req-13-3"));
                assert!(error.message.contains("memory not enabled"));
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn memory_delete_removes_entry() {
        let state = make_test_state_with_memory();
        let store = state.memory_store.as_ref().unwrap();
        let entry = store
            .insert("ephemeral memory", None, None, None)
            .await
            .expect("insert should succeed");

        // Verify it exists
        let list_result = handle_list(&state, serde_json::json!({}), "list-before").await;
        match &list_result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result.as_array().unwrap().len(), 1);
            }
            other => panic!("expected Res, got: {other:?}"),
        }

        // Delete
        let del_result = handle_delete(
            &state,
            serde_json::json!({"id": entry.id.as_str()}),
            "req-13-4",
        )
        .await;
        match del_result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-13-4");
                assert_eq!(result["deleted"], true);
            }
            other => panic!("expected Res, got: {other:?}"),
        }

        // Verify gone
        let list_after = handle_list(&state, serde_json::json!({}), "list-after").await;
        match list_after {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result.as_array().unwrap().len(), 0);
            }
            other => panic!("expected Res, got: {other:?}"),
        }
    }

    #[test]
    fn parse_memory_filter_supports_all_fields() {
        let params = serde_json::json!({
            "source_channel": "slack",
            "source_device": "phone",
            "session_id": "sess-123",
            "since": "2026-02-15T00:00:00Z",
            "until": "2026-02-16T00:00:00Z"
        });

        let filter = parse_memory_filter(&params).expect("filter should parse");
        assert_eq!(filter.source_channel.as_deref(), Some("slack"));
        assert_eq!(filter.source_device.as_deref(), Some("phone"));
        assert_eq!(
            filter.session_id.as_ref().map(|id| id.as_str()),
            Some("sess-123")
        );
        assert!(filter.since.is_some());
        assert!(filter.until.is_some());
    }

    #[test]
    fn parse_memory_filter_rejects_invalid_timestamp() {
        let params = serde_json::json!({
            "since": "not-a-timestamp"
        });
        let err = parse_memory_filter(&params).unwrap_err();
        assert!(err.contains("since must be RFC3339"));
    }

    #[test]
    fn parse_memory_filter_rejects_inverted_range() {
        let params = serde_json::json!({
            "since": "2026-02-16T00:00:00Z",
            "until": "2026-02-15T00:00:00Z"
        });
        let err = parse_memory_filter(&params).unwrap_err();
        assert_eq!(err, "since must be <= until");
    }
}
