use crate::protocol::*;
use crate::state::AppState;

pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    match state.agent_registry.list_agents().await {
        Ok(agents) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"agents": agents}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_get(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let agent_id = params["agent_id"].as_str().unwrap_or_default().to_string();

    if agent_id.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "agent_id required"),
        };
    }

    let aid = encmind_core::types::AgentId::new(&agent_id);
    match state.agent_registry.get_agent(&aid).await {
        Ok(Some(agent)) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"agent": agent}),
        },
        Ok(None) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, format!("agent not found: {agent_id}")),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}
