use crate::handlers;
use crate::protocol::*;
use crate::state::AppState;
use crate::ws::WsSender;

/// Dispatch a method call to the appropriate handler.
pub async fn dispatch_method(
    state: &AppState,
    method: &str,
    params: serde_json::Value,
    req_id: &str,
    ws_sender: Option<WsSender>,
) -> ServerMessage {
    // Check lockdown first
    if state.lockdown.is_active() && !is_lockdown_exempt(method) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_LOCKDOWN, "lockdown active"),
        };
    }

    match method {
        "chat.send" => handlers::chat::handle_send(state, params, req_id, ws_sender).await,
        "chat.history" => handlers::chat::handle_history(state, params, req_id).await,
        "chat.abort" => handlers::chat::handle_abort(state, params, req_id).await,
        "sessions.list" => handlers::sessions::handle_list(state, params, req_id).await,
        "sessions.create" => handlers::sessions::handle_create(state, params, req_id).await,
        "sessions.delete" => handlers::sessions::handle_delete(state, params, req_id).await,
        "sessions.rename" => handlers::sessions::handle_rename(state, params, req_id).await,
        "config.get" => handlers::config_handler::handle_get(state, params, req_id).await,
        "config.set" => handlers::config_handler::handle_set(state, params, req_id).await,
        "security.lockdown" => handlers::security::handle_lockdown(state, params, req_id).await,
        "security.audit" => handlers::security::handle_audit(state, params, req_id).await,
        "models.list" => handlers::models::handle_list(state, params, req_id).await,
        "agents.list" => handlers::agents::handle_list(state, params, req_id).await,
        "agents.get" => handlers::agents::handle_get(state, params, req_id).await,
        "nodes.list" => handlers::nodes::handle_node_list(state, params, req_id).await,
        "nodes.invoke" => handlers::nodes::handle_node_invoke(state, params, req_id).await,
        "nodes.update_permissions" => {
            handlers::nodes::handle_update_permissions(state, params, req_id).await
        }
        "nodes.revoke" => handlers::nodes::handle_revoke(state, params, req_id).await,
        "memory.search" => handlers::memory::handle_search(state, params, req_id).await,
        "memory.list" => handlers::memory::handle_list(state, params, req_id).await,
        "memory.delete" => handlers::memory::handle_delete(state, params, req_id).await,
        "memory.status" => handlers::memory::handle_status(state, params, req_id).await,
        "cron.list" => handlers::cron::handle_list(state, params, req_id).await,
        "cron.create" => handlers::cron::handle_create(state, params, req_id).await,
        "cron.delete" => handlers::cron::handle_delete(state, params, req_id).await,
        "cron.trigger" => handlers::cron::handle_trigger(state, params, req_id).await,
        "timeline.query" => handlers::timeline::handle_query(state, params, req_id).await,
        "api_usage.query" => handlers::api_usage::handle_query(state, params, req_id).await,
        "keys.list" => handlers::keys::handle_list(state, params, req_id).await,
        "keys.set" => handlers::keys::handle_set(state, params, req_id).await,
        "keys.delete" => handlers::keys::handle_delete(state, params, req_id).await,
        "config.set_inference_mode" => handlers::keys::handle_set_mode(state, params, req_id).await,
        "backup.trigger" => handlers::backup::handle_trigger(state, params, req_id).await,
        "backup.list" => handlers::backup::handle_list(state, params, req_id).await,
        "skills.list" => handlers::skills::handle_list(state, params, req_id).await,
        "skills.toggle" => handlers::skills::handle_toggle(state, params, req_id).await,
        "approval.respond" => handlers::skills::handle_respond(state, params, req_id).await,
        "timers.list" => handlers::timers::handle_list(state, params, req_id).await,
        "timers.toggle" => handlers::timers::handle_toggle(state, params, req_id).await,
        "plugins.status" => handlers::plugins::handle_status(state, params, req_id).await,
        "plugins.reload" => handlers::plugins::handle_reload(state, params, req_id).await,
        "skills.metrics" => handlers::skills::handle_metrics(state, params, req_id).await,
        "skills.config.get" => handlers::skills::handle_config_get(state, params, req_id).await,
        "skills.config.set" => handlers::skills::handle_config_set(state, params, req_id).await,
        "skills.resources.get" => {
            handlers::skills::handle_resources_get(state, params, req_id).await
        }
        "skills.resources.set" => {
            handlers::skills::handle_resources_set(state, params, req_id).await
        }
        "status.readiness" => handlers::readiness::handle_readiness(state, params, req_id).await,
        "channels.list" => handlers::channels::handle_list(state, params, req_id).await,
        "channels.add" => handlers::channels::handle_add(state, params, req_id).await,
        "channels.remove" => handlers::channels::handle_remove(state, params, req_id).await,
        "channels.login" => handlers::channels::handle_login(state, params, req_id).await,
        "channels.logout" => handlers::channels::handle_logout(state, params, req_id).await,
        "channels.status" => handlers::channels::handle_status(state, params, req_id).await,
        _ => {
            // Try plugin-registered method handlers before returning unknown.
            let plugin_manager = { state.plugin_manager.read().await.clone() };
            if let Some(ref pm) = plugin_manager {
                if let Some(response) = pm.dispatch_method(method, params, req_id).await {
                    return response;
                }
            }
            ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_UNKNOWN_METHOD, format!("unknown method: {method}")),
            }
        }
    }
}

/// Methods that can execute even during lockdown.
fn is_lockdown_exempt(method: &str) -> bool {
    matches!(
        method,
        "security.lockdown"
            | "security.audit"
            | "config.get"
            | "models.list"
            | "chat.abort"
            | "status.readiness"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;

    use async_trait::async_trait;

    use crate::test_utils::make_test_state;
    use encmind_core::error::ChannelError;
    use encmind_core::traits::ChannelAdapter;
    use encmind_core::types::{
        ChannelAccountStatus, ChannelTarget, InboundMessage, OutboundMessage,
    };

    struct RunningNoopAdapter;

    #[async_trait]
    impl ChannelAdapter for RunningNoopAdapter {
        async fn start(&self) -> Result<(), ChannelError> {
            Ok(())
        }

        async fn stop(&self) -> Result<(), ChannelError> {
            Ok(())
        }

        async fn send_message(
            &self,
            _target: &ChannelTarget,
            _msg: &OutboundMessage,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn inbound(&self) -> Pin<Box<dyn futures::Stream<Item = InboundMessage> + Send>> {
            Box::pin(futures::stream::empty())
        }

        fn health_status(&self) -> ChannelAccountStatus {
            ChannelAccountStatus::Active
        }
    }

    #[tokio::test]
    async fn dispatch_chat_send() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "chat.send", serde_json::json!({}), "req-1", None).await;
        // Should return a response (possibly stub)
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-1"),
            ServerMessage::Error { id, .. } => assert_eq!(id, Some("req-1".to_string())),
            _ => panic!("Expected Res or Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_sessions_list() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "sessions.list",
            serde_json::json!({}),
            "req-2",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-2"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_sessions_create() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "sessions.create",
            serde_json::json!({}),
            "req-3",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-3"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_config_get() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "config.get", serde_json::json!({}), "req-4", None).await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-4"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_security_lockdown() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "security.lockdown",
            serde_json::json!({"active": true}),
            "req-5",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-5"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_models_list() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "models.list", serde_json::json!({}), "req-6", None).await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-6"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_agents_list() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "agents.list", serde_json::json!({}), "req-7", None).await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-7"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_agents_get() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "agents.get",
            serde_json::json!({"agent_id": "main"}),
            "req-8",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } | ServerMessage::Error { id: Some(id), .. } => {
                assert_eq!(id, "req-8")
            }
            _ => panic!("Expected Res or Error with id"),
        }
    }

    #[tokio::test]
    async fn dispatch_unknown_method() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "nonexistent.method",
            serde_json::json!({}),
            "req-u",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_UNKNOWN_METHOD);
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_memory_search_returns_error_no_query() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "memory.search",
            serde_json::json!({}),
            "req-m1",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-m1".to_string()));
                assert!(
                    error.message.contains("query is required")
                        || error.message.contains("memory not enabled"),
                    "unexpected error: {}",
                    error.message
                );
            }
            _ => panic!("Expected Error for empty query"),
        }
    }

    #[tokio::test]
    async fn dispatch_memory_list() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "memory.list", serde_json::json!({}), "req-m2", None).await;
        match result {
            ServerMessage::Res { id, .. } | ServerMessage::Error { id: Some(id), .. } => {
                assert_eq!(id, "req-m2");
            }
            _ => panic!("Expected Res or Error with id"),
        }
    }

    #[tokio::test]
    async fn dispatch_memory_delete() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "memory.delete",
            serde_json::json!({"id": "mem-1"}),
            "req-m3",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } | ServerMessage::Error { id: Some(id), .. } => {
                assert_eq!(id, "req-m3");
            }
            _ => panic!("Expected Res or Error with id"),
        }
    }

    #[tokio::test]
    async fn dispatch_memory_status() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "memory.status",
            serde_json::json!({}),
            "req-m4",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } | ServerMessage::Error { id: Some(id), .. } => {
                assert_eq!(id, "req-m4");
            }
            _ => panic!("Expected Res or Error with id"),
        }
    }

    #[tokio::test]
    async fn dispatch_memory_search_with_query() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "memory.search",
            serde_json::json!({"query": "dark mode"}),
            "req-m5",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } | ServerMessage::Error { id: Some(id), .. } => {
                assert_eq!(id, "req-m5");
            }
            _ => panic!("Expected Res or Error with id"),
        }
    }

    #[tokio::test]
    async fn dispatch_cron_list() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "cron.list", serde_json::json!({}), "req-c1", None).await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-c1"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_cron_create() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "cron.create",
            serde_json::json!({
                "name": "test-job",
                "schedule": "0 * * * *",
                "prompt": "do something"
            }),
            "req-c2",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-c2"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_cron_create_rejects_invalid_next_run_at() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "cron.create",
            serde_json::json!({
                "name": "bad-next-run",
                "schedule": "0 * * * *",
                "prompt": "do something",
                "next_run_at": "not-a-timestamp"
            }),
            "req-c2b",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-c2b".to_string()));
                assert!(error.message.contains("invalid next_run_at"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_cron_delete() {
        let state = make_test_state();
        // Create first so delete has something to delete
        let _ = dispatch_method(
            &state,
            "cron.create",
            serde_json::json!({
                "name": "del-job",
                "schedule": "0 * * * *",
                "prompt": "run"
            }),
            "req-c3a",
            None,
        )
        .await;

        // Get the job id from list
        let list_result =
            dispatch_method(&state, "cron.list", serde_json::json!({}), "req-c3b", None).await;
        let job_id = match &list_result {
            ServerMessage::Res { result, .. } => result.as_array().unwrap()[0]["id"]
                .as_str()
                .unwrap()
                .to_string(),
            _ => panic!("Expected Res"),
        };

        let result = dispatch_method(
            &state,
            "cron.delete",
            serde_json::json!({"id": job_id}),
            "req-c3c",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-c3c");
                assert_eq!(result["deleted"], true);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_cron_trigger() {
        let state = make_test_state();
        // Create a job to trigger
        let _ = dispatch_method(
            &state,
            "cron.create",
            serde_json::json!({
                "name": "trigger-job",
                "schedule": "0 * * * *",
                "prompt": "run"
            }),
            "req-c4a",
            None,
        )
        .await;

        let list_result =
            dispatch_method(&state, "cron.list", serde_json::json!({}), "req-c4b", None).await;
        let job_id = match &list_result {
            ServerMessage::Res { result, .. } => result.as_array().unwrap()[0]["id"]
                .as_str()
                .unwrap()
                .to_string(),
            _ => panic!("Expected Res"),
        };

        let result = dispatch_method(
            &state,
            "cron.trigger",
            serde_json::json!({"id": job_id}),
            "req-c4c",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-c4c");
                assert_eq!(result["triggered"], true);
            }
            ServerMessage::Error { id, .. } => {
                assert_eq!(id, Some("req-c4c".to_string()));
            }
            _ => panic!("Expected Res or Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_timeline_query() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "timeline.query",
            serde_json::json!({}),
            "req-tl1",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-tl1");
                assert!(result.is_array());
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_backup_trigger() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "backup.trigger",
            serde_json::json!({}),
            "req-b1",
            None,
        )
        .await;
        match result {
            // backup_manager is None in test state → error
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-b1".to_string()));
                assert!(error.message.contains("backup is not enabled"));
            }
            _ => panic!("Expected Error since backup not enabled"),
        }
    }

    #[tokio::test]
    async fn dispatch_backup_list() {
        let state = make_test_state();
        let result =
            dispatch_method(&state, "backup.list", serde_json::json!({}), "req-b2", None).await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-b2".to_string()));
                assert!(error.message.contains("backup is not enabled"));
            }
            _ => panic!("Expected Error since backup not enabled"),
        }
    }

    #[tokio::test]
    async fn lockdown_rejects_non_exempt() {
        let state = make_test_state();
        state.lockdown.activate("test");
        let result =
            dispatch_method(&state, "chat.send", serde_json::json!({}), "req-lock", None).await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_LOCKDOWN);
            }
            _ => panic!("Expected lockdown error"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_list() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "skills.list",
            serde_json::json!({}),
            "req-sk1",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-sk1");
                assert!(result["skills"].is_array());
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_approval_respond_missing_request_id() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "approval.respond",
            serde_json::json!({}),
            "req-ap1",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ap1".to_string()));
                assert!(error.message.contains("request_id is required"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_timers_list() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "timers.list",
            serde_json::json!({}),
            "req-tl1",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-tl1");
                assert!(result.as_array().unwrap().is_empty());
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_timers_toggle_missing_params() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "timers.toggle",
            serde_json::json!({}),
            "req-tt1",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-tt1".to_string()));
                assert!(error.message.contains("id is required"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_toggle_missing_params() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "skills.toggle",
            serde_json::json!({}),
            "req-st1",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-st1".to_string()));
                assert!(error.message.contains("skill_id is required"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_toggle_persists_state() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "skill-a".to_string(),
                version: "1.0.0".to_string(),
                description: "test skill".to_string(),
                tool_name: Some("skill_a_tool".to_string()),
                hook_points: vec![],
                enabled: false,
                output_schema: None,
            });
        }
        let store = state.skill_toggle_store.as_ref().unwrap();
        store.set_enabled("skill-a", false).await.unwrap();
        let result = dispatch_method(
            &state,
            "skills.toggle",
            serde_json::json!({"skill_id": "skill-a", "enabled": true}),
            "req-st2",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-st2");
                assert_eq!(result["toggled"], true);
                assert_eq!(result["enabled"], true);
            }
            _ => panic!("Expected Res"),
        }

        // Verify the store persisted the state
        assert!(store.is_enabled("skill-a").await.unwrap());
    }

    #[tokio::test]
    async fn lockdown_allows_chat_abort() {
        let state = make_test_state();
        let session = state.session_store.create_session("web").await.unwrap();
        state.lockdown.activate("test");

        let result = dispatch_method(
            &state,
            "chat.abort",
            serde_json::json!({ "session_id": session.id.as_str() }),
            "req-abort",
            None,
        )
        .await;

        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-abort"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_plugins_status() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "plugins.status",
            serde_json::json!({}),
            "req-ps",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ps");
                assert_eq!(result["loaded_count"], 0);
                assert!(result["loaded"].as_array().unwrap().is_empty());
                assert!(result["failed"].as_array().unwrap().is_empty());
                assert_eq!(result["plugin_degraded"], false);
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_metrics() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "skills.metrics",
            serde_json::json!({}),
            "req-sm",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-sm");
                assert!(result["skills"].is_array());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_config_get() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "test".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        let result = dispatch_method(
            &state,
            "skills.config.get",
            serde_json::json!({"skill_id": "test"}),
            "req-cg",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-cg"),
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_config_set() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "test".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        let result = dispatch_method(
            &state,
            "skills.config.set",
            serde_json::json!({"skill_id": "test", "key": "k", "value": "v"}),
            "req-cs",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-cs");
                assert_eq!(result["ok"], true);
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_resources_get() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "test".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        let result = dispatch_method(
            &state,
            "skills.resources.get",
            serde_json::json!({"skill_id": "test"}),
            "req-rg",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-rg"),
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn readiness_dispatch_works() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "status.readiness",
            serde_json::json!({}),
            "req-rd",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-rd");
                // Should have readiness fields
                assert!(result.get("status").is_some());
                assert!(result.get("llm").is_some());
                assert!(result.get("tools").is_some());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_skills_resources_set() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "test".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        let result = dispatch_method(
            &state,
            "skills.resources.set",
            serde_json::json!({"skill_id": "test", "overrides": {"max_concurrent": 2}}),
            "req-rs",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-rs");
                assert_eq!(result["ok"], true);
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    // ---- channels.* dispatch tests ----

    #[tokio::test]
    async fn dispatch_channels_list() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.list",
            serde_json::json!({}),
            "req-ch1",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch1");
                assert!(result.is_array());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_list_rejects_unknown_param() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.list",
            serde_json::json!({"foo": "bar"}),
            "req-ch1b",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch1b".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("unknown parameter: foo"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_add() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "My Bot"}),
            "req-ch2",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch2");
                assert_eq!(result["channel_type"], "telegram");
                assert_eq!(result["label"], "My Bot");
                assert!(result["id"].is_string());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_add_missing_type() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({}),
            "req-ch2b",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch2b".to_string()));
                assert!(error.message.contains("channel_type is required"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_add_rejects_unknown_param() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "My Bot", "foo": "bar"}),
            "req-ch2c",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch2c".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("unknown parameter: foo"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_remove() {
        let state = make_test_state();
        // First add an account
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch3a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        // Then remove it
        let result = dispatch_method(
            &state,
            "channels.remove",
            serde_json::json!({"id": account_id}),
            "req-ch3b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch3b");
                assert_eq!(result["deleted"], true);
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_remove_not_found() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.remove",
            serde_json::json!({"id": "nonexistent"}),
            "req-ch3c",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch3c".to_string()));
                assert!(error.message.contains("account not found"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_remove_rejects_unknown_param() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.remove",
            serde_json::json!({"id": "nonexistent", "foo": "bar"}),
            "req-ch3d",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch3d".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("unknown parameter: foo"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login() {
        let state = make_test_state();
        // First add an account
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id, "bot_token": "test-token-123"}),
            "req-ch4b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch4b");
                // With dynamic lifecycle, the adapter is constructed and probed.
                // Probe fails with fake token, so status becomes "degraded".
                assert_eq!(result["status"], "degraded");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_no_creds() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4c",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id}),
            "req-ch4d",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4d".to_string()));
                assert!(error.message.contains("at least one credential"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_no_creds_uses_existing_stored_credential() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4d-existing-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let store = state.channel_account_store.as_ref().unwrap();
        let account = store
            .get_account(&encmind_core::types::ChannelAccountId::from_string(
                &account_id,
            ))
            .await
            .expect("account lookup should succeed")
            .expect("account should exist");
        store
            .store_credential(&account.id, r#"{"bot_token":"existing-token"}"#)
            .await
            .expect("seed credential should succeed");

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id}),
            "req-ch4d-existing-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch4d-existing-b");
                // Probe with fake token fails; account should still be brought online as degraded.
                assert_eq!(result["status"], "degraded");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_rejects_unknown_param() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4d2-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id, "bot_token": "token", "foo": "bar"}),
            "req-ch4d2-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4d2-b".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("unknown parameter: foo"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_add_unknown_channel_type_returns_error() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "discord"}),
            "req-ch4e-a",
            None,
        )
        .await;
        match add_result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4e-a".to_string()));
                assert!(error.message.contains("unsupported channel_type: discord"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_add_duplicate_type_returns_invalid_params() {
        let state = make_test_state();
        let first = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "A"}),
            "req-ch4d-a",
            None,
        )
        .await;
        match first {
            ServerMessage::Res { .. } => {}
            other => panic!("Expected Res, got {other:?}"),
        }

        let second = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "B"}),
            "req-ch4d-b",
            None,
        )
        .await;
        match second {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4d-b".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("channel_type already exists"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_unknown_channel_type_returns_error() {
        let state = make_test_state();
        let store = state.channel_account_store.as_ref().unwrap();
        let legacy_account = encmind_core::types::ChannelAccount {
            id: encmind_core::types::ChannelAccountId::new(),
            channel_type: "discord".to_string(),
            label: "Legacy Discord".to_string(),
            enabled: true,
            status: encmind_core::types::ChannelAccountStatus::Stopped,
            config_source: encmind_core::types::ConfigSource::Api,
            policy: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        store
            .create_account(&legacy_account)
            .await
            .expect("failed to insert legacy channel account");

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": legacy_account.id.as_str(), "bot_token": "token"}),
            "req-ch4e-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4e-b".to_string()));
                assert!(error.message.contains("unsupported channel_type"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_by_type_rejects_ambiguous_type_lookup() {
        let state = make_test_state();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        {
            let conn = state.db_pool.get().expect("db connection");
            // Simulate a legacy/corrupted DB state with duplicate channel_type rows.
            conn.execute("DROP INDEX IF EXISTS idx_channel_accounts_type_unique", [])
                .expect("drop unique channel_type index");
            conn.execute(
                "INSERT INTO channel_accounts (id, channel_type, label, enabled, status, config_source, policy_json, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    "acct-dup-1",
                    "telegram",
                    "Dup 1",
                    1_i64,
                    "stopped",
                    "api",
                    Option::<String>::None,
                    now,
                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
                ],
            )
            .expect("insert duplicate account 1");
            conn.execute(
                "INSERT INTO channel_accounts (id, channel_type, label, enabled, status, config_source, policy_json, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    "acct-dup-2",
                    "telegram",
                    "Dup 2",
                    1_i64,
                    "stopped",
                    "api",
                    Option::<String>::None,
                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
                ],
            )
            .expect("insert duplicate account 2");
        }

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": "telegram", "bot_token": "token"}),
            "req-ch4e-c",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4e-c".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error
                    .message
                    .contains("multiple accounts configured for channel_type"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_corrupt_stored_credential_returns_internal() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4g-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let store = state.channel_account_store.as_ref().unwrap();
        let account = store
            .get_account(&encmind_core::types::ChannelAccountId::from_string(
                &account_id,
            ))
            .await
            .expect("account lookup should succeed")
            .expect("account should exist");
        store
            .store_credential(&account.id, "not-json")
            .await
            .expect("should be able to seed malformed credential");

        let login_result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id, "bot_token": "new-token"}),
            "req-ch4g-b",
            None,
        )
        .await;
        match login_result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4g-b".to_string()));
                assert_eq!(error.code, ERR_INTERNAL);
                assert!(error.message.contains("stored credential is corrupted"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_ignores_unexpected_stored_credential_field() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4h-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let store = state.channel_account_store.as_ref().unwrap();
        let account = store
            .get_account(&encmind_core::types::ChannelAccountId::from_string(
                &account_id,
            ))
            .await
            .expect("account lookup should succeed")
            .expect("account should exist");
        store
            .store_credential(&account.id, r#"{"bot_token":"old","extra_token":"bad"}"#)
            .await
            .expect("should be able to seed credential with unexpected field");

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id, "bot_token": "token"}),
            "req-ch4h-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch4h-b");
                assert_eq!(result["status"], "degraded");
            }
            other => panic!("Expected Res, got {other:?}"),
        }

        let stored = store
            .get_credential(&account.id)
            .await
            .expect("credential lookup should succeed")
            .expect("credential should exist");
        let cred_json: serde_json::Value =
            serde_json::from_str(&stored).expect("credential JSON should parse");
        assert_eq!(cred_json["bot_token"], "token");
        assert!(cred_json.get("extra_token").is_none());
    }

    #[tokio::test]
    async fn dispatch_channels_login_partial_slack_update_preserves_existing_required_fields() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "slack"}),
            "req-ch4f-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let first_login = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({
                "id": account_id,
                "bot_token": "xoxb-original",
                "app_token": "xapp-original"
            }),
            "req-ch4f-b",
            None,
        )
        .await;
        match first_login {
            ServerMessage::Res { .. } => {}
            other => panic!("Expected Res, got {other:?}"),
        }

        let second_login = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({
                "id": account_id,
                "bot_token": "xoxb-rotated"
            }),
            "req-ch4f-c",
            None,
        )
        .await;
        match second_login {
            ServerMessage::Res { .. } => {}
            other => panic!("Expected Res, got {other:?}"),
        }

        let store = state.channel_account_store.as_ref().unwrap();
        let account = store
            .get_account_by_type("slack")
            .await
            .expect("query should succeed")
            .expect("slack account should exist");
        let stored = store
            .get_credential(&account.id)
            .await
            .expect("credential lookup should succeed")
            .expect("credential should exist");
        let cred_json: serde_json::Value =
            serde_json::from_str(&stored).expect("credential JSON should parse");
        assert_eq!(cred_json["bot_token"], "xoxb-rotated");
        assert_eq!(cred_json["app_token"], "xapp-original");
    }

    #[tokio::test]
    async fn dispatch_channels_login_accepts_gmail_credential_params() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "gmail"}),
            "req-ch4gml-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({
                "id": account_id,
                "client_id": "cid-only"
            }),
            "req-ch4gml-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch4gml-b".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(
                    error
                        .message
                        .contains("missing required credential field: client_secret"),
                    "unexpected error: {}",
                    error.message
                );
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_login_probe_failure_preserves_active_when_runtime_adapter_exists() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch4x-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let store = state.channel_account_store.as_ref().unwrap();
        let account = store
            .get_account(&encmind_core::types::ChannelAccountId::from_string(
                &account_id,
            ))
            .await
            .expect("account lookup should succeed")
            .expect("account should exist");
        store
            .store_credential(&account.id, r#"{"bot_token":"existing-token"}"#)
            .await
            .expect("seed credential should succeed");
        store
            .update_status(&account.id, ChannelAccountStatus::Active)
            .await
            .expect("status update should succeed");

        state
            .channel_manager
            .start_adapter("telegram", Arc::new(RunningNoopAdapter), |_, _| {
                tokio::spawn(async {})
            })
            .await
            .expect("runtime adapter should start");

        let login_result = dispatch_method(
            &state,
            "channels.login",
            serde_json::json!({"id": account_id, "bot_token": "new-invalid-token"}),
            "req-ch4x-b",
            None,
        )
        .await;
        match login_result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch4x-b");
                assert_eq!(result["status"], "active");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_logout() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram"}),
            "req-ch5a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.logout",
            serde_json::json!({"id": account_id}),
            "req-ch5b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch5b");
                assert_eq!(result["status"], "stopped");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_logout_rejects_unknown_param() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.logout",
            serde_json::json!({"id": "nonexistent", "foo": "bar"}),
            "req-ch5c",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch5c".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("unknown parameter: foo"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_status() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "Test"}),
            "req-ch6a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.status",
            serde_json::json!({"id": account_id}),
            "req-ch6b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch6b");
                assert_eq!(result["channel_type"], "telegram");
                assert_eq!(result["label"], "Test");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_status_probe_reports_adapter_state() {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "Test"}),
            "req-ch6p-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let result = dispatch_method(
            &state,
            "channels.status",
            serde_json::json!({"id": account_id, "probe": true}),
            "req-ch6p-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch6p-b");
                assert_eq!(result["probe"]["ok"], false);
                assert_eq!(result["probe"]["error"], "adapter not running");
                assert_eq!(result["status"], "login_required");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_status_probe_without_running_adapter_is_degraded_when_credential_exists(
    ) {
        let state = make_test_state();
        let add_result = dispatch_method(
            &state,
            "channels.add",
            serde_json::json!({"channel_type": "telegram", "label": "Test"}),
            "req-ch6p2-a",
            None,
        )
        .await;
        let account_id = match add_result {
            ServerMessage::Res { result, .. } => result["id"].as_str().unwrap().to_string(),
            other => panic!("Expected Res, got {other:?}"),
        };

        let store = state.channel_account_store.as_ref().unwrap();
        let account = store
            .get_account(&encmind_core::types::ChannelAccountId::from_string(
                &account_id,
            ))
            .await
            .expect("account lookup should succeed")
            .expect("account should exist");
        store
            .store_credential(&account.id, r#"{"bot_token":"token"}"#)
            .await
            .expect("should be able to seed credential");

        let result = dispatch_method(
            &state,
            "channels.status",
            serde_json::json!({"id": account_id, "probe": true}),
            "req-ch6p2-b",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch6p2-b");
                assert_eq!(result["probe"]["ok"], false);
                assert_eq!(result["probe"]["error"], "adapter not running");
                assert_eq!(result["status"], "degraded");
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_status_no_id_falls_back_to_list() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.status",
            serde_json::json!({}),
            "req-ch6c",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch6c");
                // falls back to handle_list which returns an array
                assert!(result.is_array());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_status_probe_without_id_falls_back_to_list() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.status",
            serde_json::json!({"probe": true}),
            "req-ch6c2",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ch6c2");
                assert!(result.is_array());
            }
            other => panic!("Expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_channels_status_rejects_unknown_param() {
        let state = make_test_state();
        let result = dispatch_method(
            &state,
            "channels.status",
            serde_json::json!({"foo": "bar"}),
            "req-ch6d",
            None,
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ch6d".to_string()));
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("unknown parameter: foo"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }
}
