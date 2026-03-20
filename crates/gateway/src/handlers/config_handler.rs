use crate::protocol::*;
use crate::state::AppState;

pub async fn handle_get(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let config = state.config.read().await;
    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "server": {
                "host": config.server.host,
                "port": config.server.port,
            },
            "gateway": {
                "heartbeat_interval_ms": config.gateway.heartbeat_interval_ms,
                "idempotency_ttl_secs": config.gateway.idempotency_ttl_secs,
                "max_connections": config.gateway.max_connections,
                "mdns_enabled": config.gateway.mdns_enabled,
            }
        }),
    }
}

pub async fn handle_set(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let key = params
        .get("key")
        .or_else(|| params.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if key.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "key is required"),
        };
    }

    let Some(value) = params.get("value") else {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "value is required"),
        };
    };

    let mut config = state.config.write().await;
    let mut restart_required = false;
    let mut applied_value = serde_json::Value::Null;

    let apply_result: Result<(), String> = match key.as_str() {
        "server.host" => value
            .as_str()
            .map(|v| {
                config.server.host = v.to_string();
                applied_value = serde_json::json!(v);
            })
            .ok_or_else(|| "server.host must be a string".to_string()),
        "server.port" => value
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .map(|v| {
                config.server.port = v;
                applied_value = serde_json::json!(v);
            })
            .ok_or_else(|| "server.port must be a number between 0 and 65535".to_string()),
        "gateway.heartbeat_interval_ms" => value
            .as_u64()
            .map(|v| {
                config.gateway.heartbeat_interval_ms = v.max(1000);
                applied_value = serde_json::json!(config.gateway.heartbeat_interval_ms);
            })
            .ok_or_else(|| "gateway.heartbeat_interval_ms must be a number".to_string()),
        "gateway.idempotency_ttl_secs" => value
            .as_u64()
            .map(|v| {
                config.gateway.idempotency_ttl_secs = v.max(1);
                applied_value = serde_json::json!(config.gateway.idempotency_ttl_secs);
            })
            .ok_or_else(|| "gateway.idempotency_ttl_secs must be a number".to_string()),
        "gateway.max_connections" => value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .map(|v| {
                let new_limit = v.max(1);
                let old_limit = config.gateway.max_connections.max(1);
                config.gateway.max_connections = new_limit;
                if new_limit > old_limit {
                    state
                        .connection_permits
                        .add_permits((new_limit - old_limit) as usize);
                } else if new_limit < old_limit {
                    restart_required = true;
                }
                applied_value = serde_json::json!(new_limit);
            })
            .ok_or_else(|| "gateway.max_connections must be a positive number".to_string()),
        "gateway.mdns_enabled" => value
            .as_bool()
            .map(|v| {
                config.gateway.mdns_enabled = v;
                restart_required = true;
                applied_value = serde_json::json!(v);
            })
            .ok_or_else(|| "gateway.mdns_enabled must be a boolean".to_string()),
        _ => Err(format!("unsupported config key: {key}")),
    };

    if let Err(message) = apply_result {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, message),
        };
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "status": "updated",
            "key": key,
            "value": applied_value,
            "restart_required": restart_required,
        }),
    }
}
