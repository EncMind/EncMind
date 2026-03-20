use crate::node::check_permission;
use crate::protocol::*;
use crate::state::AppState;
use tokio::time::{timeout, Duration};
use ulid::Ulid;

pub async fn handle_node_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    match state.device_store.list_devices().await {
        Ok(devices) => {
            let mut device_list = Vec::with_capacity(devices.len());
            for d in &devices {
                let connected = state.node_registry.is_connected(&d.id).await;
                device_list.push(serde_json::json!({
                    "id": d.id,
                    "name": d.name,
                    "permissions": d.permissions,
                    "last_seen": d.last_seen,
                    "connected": connected,
                }));
            }
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({"nodes": device_list}),
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_node_invoke(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let device_id = params["device_id"].as_str().unwrap_or_default().to_string();
    let command = params["command"].as_str().unwrap_or_default().to_string();

    if device_id.is_empty() || command.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "device_id and command required"),
        };
    }

    // Look up device permissions
    let device = match state.device_store.get_device(&device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_AUTH_FAILED, format!("device not found: {device_id}")),
            };
        }
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    // Check permission
    if !check_permission(&command, &device.permissions) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_AUTH_FAILED,
                format!("permission denied for command: {command}"),
            ),
        };
    }

    if !state.node_registry.is_connected(&device_id).await {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("device not connected: {device_id}")),
        };
    }

    let command_req_id = format!("{req_id}-{}", Ulid::new());
    let response_rx = match state
        .node_registry
        .send_command(
            &device_id,
            command_req_id.clone(),
            command.clone(),
            params
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .await
    {
        Ok(rx) => rx,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e),
            };
        }
    };

    match timeout(Duration::from_secs(30), response_rx).await {
        Ok(Ok(result)) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({
                "status": "completed",
                "device_id": device_id,
                "command": command,
                "result": result,
            }),
        },
        Ok(Err(_)) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, "device disconnected before returning result"),
        },
        Err(_) => {
            state.node_registry.cancel_command(&command_req_id).await;
            ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "command timed out"),
            }
        }
    }
}

pub async fn handle_update_permissions(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let device_id = params["device_id"].as_str().unwrap_or_default().to_string();

    if device_id.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "device_id required"),
        };
    }

    let permissions: encmind_core::types::DevicePermissions =
        match serde_json::from_value(params["permissions"].clone()) {
            Ok(p) => p,
            Err(e) => {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("invalid permissions: {e}"),
                    ),
                };
            }
        };

    match state
        .device_store
        .update_permissions(&device_id, &permissions)
        .await
    {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "updated"}),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_revoke(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let device_id = params["device_id"].as_str().unwrap_or_default().to_string();

    if device_id.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "device_id required"),
        };
    }

    match state.device_store.remove_device(&device_id).await {
        Ok(()) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({"status": "revoked"}),
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
    use chrono::Utc;
    use encmind_core::types::{DevicePermissions, PairedDevice};

    fn test_device(id: &str, name: &str, perms: DevicePermissions) -> PairedDevice {
        PairedDevice {
            id: id.to_string(),
            name: name.to_string(),
            public_key: vec![0u8; 32],
            permissions: perms,
            paired_at: Utc::now(),
            last_seen: None,
        }
    }

    #[tokio::test]
    async fn node_list_shows_paired_devices() {
        let state = make_test_state();
        let perms = DevicePermissions {
            chat: true,
            file_read: true,
            ..Default::default()
        };
        let device = test_device("dev-1", "My Laptop", perms);
        state.device_store.add_device(&device).await.unwrap();

        let result = handle_node_list(&state, serde_json::json!({}), "req-14-1").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-14-1");
                let nodes = result["nodes"].as_array().expect("nodes should be array");
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0]["id"], "dev-1");
                assert_eq!(nodes[0]["name"], "My Laptop");
                assert_eq!(nodes[0]["connected"], false);
                assert_eq!(nodes[0]["permissions"]["chat"], true);
                assert_eq!(nodes[0]["permissions"]["file_read"], true);
                assert_eq!(nodes[0]["permissions"]["bash_exec"], false);
            }
            other => panic!("expected Res, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn update_permissions_removes_bash_exec() {
        let state = make_test_state();
        let perms = DevicePermissions {
            chat: true,
            bash_exec: true,
            ..Default::default()
        };
        let device = test_device("dev-2", "Workstation", perms);
        state.device_store.add_device(&device).await.unwrap();

        let result = handle_update_permissions(
            &state,
            serde_json::json!({
                "device_id": "dev-2",
                "permissions": {
                    "chat": true,
                    "bash_exec": false,
                    "file_read": false,
                    "file_write": false,
                    "file_list": false,
                    "admin": false
                }
            }),
            "req-14-2",
        )
        .await;

        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-14-2");
                assert_eq!(result["status"], "updated");
            }
            other => panic!("expected Res, got: {other:?}"),
        }

        let updated = state
            .device_store
            .get_device("dev-2")
            .await
            .unwrap()
            .unwrap();
        assert!(updated.permissions.chat);
        assert!(!updated.permissions.bash_exec);
    }

    #[tokio::test]
    async fn revoke_device_removes_from_store() {
        let state = make_test_state();
        let device = test_device("dev-3", "Old Phone", DevicePermissions::default());
        state.device_store.add_device(&device).await.unwrap();

        // Verify it exists
        assert!(state
            .device_store
            .get_device("dev-3")
            .await
            .unwrap()
            .is_some());

        let result = handle_revoke(
            &state,
            serde_json::json!({"device_id": "dev-3"}),
            "req-14-3",
        )
        .await;

        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-14-3");
                assert_eq!(result["status"], "revoked");
            }
            other => panic!("expected Res, got: {other:?}"),
        }

        assert!(state
            .device_store
            .get_device("dev-3")
            .await
            .unwrap()
            .is_none());
    }
}
