use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ulid::Ulid;

use encmind_agent::tool_registry::InternalToolHandler;
use encmind_core::error::AppError;
use encmind_core::traits::DeviceStore;
use encmind_core::types::{AgentId, SessionId};

use crate::node::{self, ConnectedNodeInfo, NodeRegistry};

/// Default command timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// A generic tool handler that forwards commands to a connected edge device.
///
/// One instance is created per command type (file.read, file.write, file.list, bash.exec).
/// All instances share the same logic — only the command name/description/schema differs.
///
/// ## Device selection
///
/// The LLM may pass an optional `device_id` in the tool input to target a specific
/// edge device. When omitted, the handler picks the first connected device.
pub struct NodeCommandHandler {
    command: String,
    node_registry: Arc<NodeRegistry>,
    device_store: Arc<dyn DeviceStore>,
    timeout: Duration,
}

impl NodeCommandHandler {
    pub fn new(
        command: String,
        node_registry: Arc<NodeRegistry>,
        device_store: Arc<dyn DeviceStore>,
    ) -> Self {
        Self {
            command,
            node_registry,
            device_store,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Override the command timeout (useful for tests).
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Pick a connected device.
///
/// If `requested_id` is `Some`, look for that specific device among the connected
/// nodes. Otherwise fall back to the first connected device.
fn select_device<'a>(
    connected: &'a [ConnectedNodeInfo],
    requested_id: Option<&str>,
) -> Result<&'a ConnectedNodeInfo, AppError> {
    match requested_id {
        Some(id) => connected.iter().find(|n| n.device_id == id).ok_or_else(|| {
            // Distinguish "exists but offline" from "never heard of it" for
            // a better LLM error message.  We only have the connected list
            // here, so keep it simple.
            AppError::Internal(format!(
                "device '{id}' is not connected \u{2014} run: encmind-edge connect"
            ))
        }),
        None => connected.first().ok_or_else(|| {
            AppError::Internal("no edge device connected \u{2014} run: encmind-edge connect".into())
        }),
    }
}

#[async_trait]
impl InternalToolHandler for NodeCommandHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        _agent_id: &AgentId,
    ) -> Result<String, AppError> {
        // 0. Extract optional device_id from input
        let requested_device_id = input
            .get("device_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // 1. Select connected device
        let connected = self.node_registry.list().await;
        let device = select_device(&connected, requested_device_id.as_deref())?;

        // 2. Check permissions
        let device_info = self
            .device_store
            .get_device(&device.device_id)
            .await
            .map_err(|e| AppError::Internal(format!("device lookup failed: {e}")))?
            .ok_or_else(|| {
                AppError::Internal(format!("device '{}' not found in store", device.device_id))
            })?;
        if !node::check_permission(&self.command, &device_info.permissions) {
            return Err(AppError::Internal(format!(
                "{}: not permitted on device '{}'",
                self.command, device_info.name
            )));
        }

        // 3. Send command
        let request_id = Ulid::new().to_string();
        let rx = self
            .node_registry
            .send_command(
                &device.device_id,
                request_id.clone(),
                self.command.clone(),
                input,
            )
            .await
            .map_err(AppError::Internal)?;

        // 4. Await result with timeout
        let result = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                return Err(AppError::Internal(format!(
                    "{}: device disconnected",
                    self.command
                )));
            }
            Err(_) => {
                self.node_registry.cancel_command(&request_id).await;
                return Err(AppError::Internal(format!(
                    "{}: timed out after {}s",
                    self.command,
                    self.timeout.as_secs()
                )));
            }
        };

        Ok(result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_core::types::PairedDevice;
    use encmind_storage::device_store::SqliteDeviceStore;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;
    use tokio::sync::mpsc;

    fn make_device_store_and_registry() -> (Arc<dyn DeviceStore>, Arc<NodeRegistry>) {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let device_store: Arc<dyn DeviceStore> = Arc::new(SqliteDeviceStore::new(pool));
        let node_registry = Arc::new(NodeRegistry::new());
        (device_store, node_registry)
    }

    fn make_paired_device(
        id: &str,
        name: &str,
        perms: encmind_core::types::DevicePermissions,
    ) -> PairedDevice {
        PairedDevice {
            id: id.into(),
            name: name.into(),
            public_key: vec![0u8; 32],
            permissions: perms,
            paired_at: chrono::Utc::now(),
            last_seen: None,
        }
    }

    // ── select_device unit tests ──────────────────────────────────

    #[test]
    fn select_device_returns_first_when_no_id_requested() {
        let nodes = vec![
            ConnectedNodeInfo {
                device_id: "dev-a".into(),
                name: "Alpha".into(),
            },
            ConnectedNodeInfo {
                device_id: "dev-b".into(),
                name: "Beta".into(),
            },
        ];
        let picked = select_device(&nodes, None).unwrap();
        assert_eq!(picked.device_id, "dev-a");
    }

    #[test]
    fn select_device_returns_requested_device() {
        let nodes = vec![
            ConnectedNodeInfo {
                device_id: "dev-a".into(),
                name: "Alpha".into(),
            },
            ConnectedNodeInfo {
                device_id: "dev-b".into(),
                name: "Beta".into(),
            },
        ];
        let picked = select_device(&nodes, Some("dev-b")).unwrap();
        assert_eq!(picked.device_id, "dev-b");
    }

    #[test]
    fn select_device_errors_when_requested_device_not_connected() {
        let nodes = vec![ConnectedNodeInfo {
            device_id: "dev-a".into(),
            name: "Alpha".into(),
        }];
        let err = select_device(&nodes, Some("dev-missing")).unwrap_err();
        assert!(
            err.to_string().contains("dev-missing"),
            "error should mention the requested device id"
        );
        assert!(
            err.to_string().contains("not connected"),
            "error should say 'not connected'"
        );
    }

    #[test]
    fn select_device_errors_when_no_devices_connected() {
        let err = select_device(&[], None).unwrap_err();
        assert!(err.to_string().contains("no edge device connected"));
    }

    // ── handler integration tests ──────────────────────────────────

    #[tokio::test]
    async fn returns_error_when_no_device_connected() {
        let (device_store, node_registry) = make_device_store_and_registry();
        let handler = NodeCommandHandler::new("file.read".to_string(), node_registry, device_store);

        let result = handler
            .handle(
                serde_json::json!({"path": "/tmp/test"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("no edge device connected"),
            "expected 'no edge device connected', got: {err}"
        );
    }

    #[tokio::test]
    async fn returns_error_when_requested_device_not_connected() {
        let (device_store, node_registry) = make_device_store_and_registry();

        // Connect dev-a but request dev-b
        let dev = make_paired_device(
            "dev-a",
            "Alpha",
            encmind_core::types::DevicePermissions {
                file_read: true,
                ..Default::default()
            },
        );
        device_store.add_device(&dev).await.unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        node_registry.register("dev-a", "Alpha", tx).await;

        let handler = NodeCommandHandler::new("file.read".to_string(), node_registry, device_store);

        let result = handler
            .handle(
                serde_json::json!({"path": "/tmp/test", "device_id": "dev-b"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("dev-b"),
            "expected error mentioning 'dev-b', got: {err}"
        );
    }

    #[tokio::test]
    async fn routes_to_requested_device_when_multiple_connected() {
        let (device_store, node_registry) = make_device_store_and_registry();

        // Register two paired devices
        let dev_a = make_paired_device(
            "dev-a",
            "Alpha",
            encmind_core::types::DevicePermissions {
                file_read: true,
                ..Default::default()
            },
        );
        let dev_b = make_paired_device(
            "dev-b",
            "Beta",
            encmind_core::types::DevicePermissions {
                file_read: true,
                ..Default::default()
            },
        );
        device_store.add_device(&dev_a).await.unwrap();
        device_store.add_device(&dev_b).await.unwrap();

        // Connect both
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = mpsc::unbounded_channel();
        node_registry.register("dev-a", "Alpha", tx_a).await;
        node_registry.register("dev-b", "Beta", tx_b).await;

        let handler =
            NodeCommandHandler::new("file.read".to_string(), node_registry.clone(), device_store);

        // Simulate dev-b responding
        let nr = node_registry.clone();
        tokio::spawn(async move {
            let msg = rx_b.recv().await.unwrap();
            if let crate::node::NodeServerMessage::Command { request_id, .. } = msg {
                nr.complete_command(
                    "dev-b",
                    &request_id,
                    serde_json::json!({"content": "from beta"}),
                )
                .await;
            }
        });

        let result = handler
            .handle(
                serde_json::json!({"path": "/tmp/test", "device_id": "dev-b"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["content"], "from beta");
    }

    #[tokio::test]
    async fn returns_error_when_permission_denied() {
        let (device_store, node_registry) = make_device_store_and_registry();

        let device = make_paired_device(
            "dev-1",
            "Test Device",
            encmind_core::types::DevicePermissions {
                file_read: false,
                ..Default::default()
            },
        );
        device_store.add_device(&device).await.unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        node_registry.register("dev-1", "Test Device", tx).await;

        let handler = NodeCommandHandler::new("file.read".to_string(), node_registry, device_store);

        let result = handler
            .handle(
                serde_json::json!({"path": "/tmp/test"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("not permitted"),
            "expected 'not permitted', got: {err}"
        );
    }

    #[tokio::test]
    async fn forwards_command_and_returns_result() {
        let (device_store, node_registry) = make_device_store_and_registry();

        let device = make_paired_device(
            "dev-1",
            "Test Device",
            encmind_core::types::DevicePermissions {
                file_read: true,
                ..Default::default()
            },
        );
        device_store.add_device(&device).await.unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        node_registry.register("dev-1", "Test Device", tx).await;

        let handler =
            NodeCommandHandler::new("file.read".to_string(), node_registry.clone(), device_store);

        // Spawn a task to simulate the edge device responding
        let nr = node_registry.clone();
        tokio::spawn(async move {
            let msg = rx.recv().await.unwrap();
            if let crate::node::NodeServerMessage::Command { request_id, .. } = msg {
                nr.complete_command(
                    "dev-1",
                    &request_id,
                    serde_json::json!({"content": "hello world"}),
                )
                .await;
            }
        });

        let result = handler
            .handle(
                serde_json::json!({"path": "/tmp/test"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["content"], "hello world");
    }

    #[tokio::test]
    async fn handler_timeout_emits_timed_out_error() {
        let (device_store, node_registry) = make_device_store_and_registry();

        let device = make_paired_device(
            "dev-1",
            "Test Device",
            encmind_core::types::DevicePermissions {
                bash_exec: true,
                ..Default::default()
            },
        );
        device_store.add_device(&device).await.unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        node_registry.register("dev-1", "Test Device", tx).await;
        let registry_for_assert = node_registry.clone();

        // Use a very short timeout so the test completes quickly
        let handler = NodeCommandHandler::new("bash.exec".to_string(), node_registry, device_store)
            .with_timeout(Duration::from_millis(50));

        let result = handler
            .handle(
                serde_json::json!({"command": "sleep 999"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await;

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("timed out"),
            "expected 'timed out' in error, got: {msg}"
        );
        assert!(
            msg.contains("bash.exec"),
            "timeout error should mention the command name, got: {msg}"
        );
        assert_eq!(
            registry_for_assert.pending_result_count().await,
            0,
            "timed out commands should be removed from pending results"
        );
    }

    #[tokio::test]
    async fn returns_error_when_device_disconnects() {
        let (device_store, node_registry) = make_device_store_and_registry();

        let device = make_paired_device(
            "dev-1",
            "Test Device",
            encmind_core::types::DevicePermissions {
                file_list: true,
                ..Default::default()
            },
        );
        device_store.add_device(&device).await.unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let conn_id = node_registry.register("dev-1", "Test Device", tx).await;

        let handler =
            NodeCommandHandler::new("file.list".to_string(), node_registry.clone(), device_store);

        // Spawn a task that receives the command then disconnects the device
        let nr = node_registry.clone();
        tokio::spawn(async move {
            let _ = rx.recv().await;
            nr.unregister("dev-1", &conn_id).await;
        });

        let result = handler
            .handle(
                serde_json::json!({"path": "/tmp"}),
                &SessionId::default(),
                &AgentId::default(),
            )
            .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("device disconnected"),
            "expected 'device disconnected', got: {err}"
        );
    }
}
