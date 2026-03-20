use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use ulid::Ulid;

use encmind_core::types::DevicePermissions;

/// Messages sent from a connected node client → server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeClientMessage {
    /// Register this node with the gateway.
    Register { device_id: String, name: String },
    /// Complete node registration using signed nonce challenge.
    RegisterAuth {
        device_id: String,
        nonce: String,
        signature: String,
    },
    /// Result of a command execution.
    CommandResult {
        request_id: String,
        result: serde_json::Value,
    },
}

/// Messages sent from server → a connected node client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeServerMessage {
    /// Server-issued nonce challenge for node registration.
    AuthChallenge { device_id: String, nonce: String },
    /// Acknowledge registration.
    Registered { device_id: String },
    /// Command to execute on the node.
    Command {
        request_id: String,
        command: String,
        params: serde_json::Value,
    },
    /// Error message.
    Error { message: String },
}

/// Information about a connected node.
#[derive(Debug, Clone)]
pub struct ConnectedNode {
    pub device_id: String,
    pub name: String,
    connection_id: String,
    sender: mpsc::UnboundedSender<NodeServerMessage>,
}

#[derive(Debug, Clone)]
pub struct ConnectedNodeInfo {
    pub device_id: String,
    pub name: String,
}

/// Registry of currently connected node clients.
pub struct NodeRegistry {
    nodes: Arc<RwLock<HashMap<String, ConnectedNode>>>,
    pending_results: Arc<RwLock<HashMap<String, PendingCommandResult>>>,
}

struct PendingCommandResult {
    device_id: String,
    sender: oneshot::Sender<serde_json::Value>,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            pending_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(
        &self,
        device_id: &str,
        name: &str,
        sender: mpsc::UnboundedSender<NodeServerMessage>,
    ) -> String {
        let connection_id = Ulid::new().to_string();
        let mut nodes = self.nodes.write().await;
        nodes.insert(
            device_id.to_string(),
            ConnectedNode {
                device_id: device_id.to_string(),
                name: name.to_string(),
                connection_id: connection_id.clone(),
                sender,
            },
        );
        connection_id
    }

    pub async fn unregister(&self, device_id: &str, connection_id: &str) {
        let removed = {
            let mut nodes = self.nodes.write().await;
            match nodes.get(device_id) {
                Some(node) if node.connection_id == connection_id => {
                    nodes.remove(device_id);
                    true
                }
                _ => false,
            }
        };
        if !removed {
            return;
        }

        // Drop all pending result senders for this device so waiters fail fast.
        let mut pending = self.pending_results.write().await;
        pending.retain(|_, entry| entry.device_id != device_id);
    }

    pub async fn list(&self) -> Vec<ConnectedNodeInfo> {
        let nodes = self.nodes.read().await;
        let mut connected: Vec<ConnectedNodeInfo> = nodes
            .values()
            .map(|n| ConnectedNodeInfo {
                device_id: n.device_id.clone(),
                name: n.name.clone(),
            })
            .collect();
        // Keep default device selection deterministic when callers don't pass
        // an explicit device_id.
        connected.sort_by(|a, b| {
            a.device_id
                .cmp(&b.device_id)
                .then_with(|| a.name.cmp(&b.name))
        });
        connected
    }

    pub async fn is_connected(&self, device_id: &str) -> bool {
        let nodes = self.nodes.read().await;
        nodes.contains_key(device_id)
    }

    pub async fn send_command(
        &self,
        device_id: &str,
        request_id: String,
        command: String,
        params: serde_json::Value,
    ) -> Result<oneshot::Receiver<serde_json::Value>, String> {
        let node_sender = {
            let nodes = self.nodes.read().await;
            nodes
                .get(device_id)
                .map(|node| node.sender.clone())
                .ok_or_else(|| format!("device not connected: {device_id}"))?
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_results.write().await;
            pending.insert(
                request_id.clone(),
                PendingCommandResult {
                    device_id: device_id.to_string(),
                    sender: tx,
                },
            );
        }

        if node_sender
            .send(NodeServerMessage::Command {
                request_id: request_id.clone(),
                command,
                params,
            })
            .is_err()
        {
            self.cancel_command(&request_id).await;
            return Err(format!("failed to send command to device: {device_id}"));
        }

        Ok(rx)
    }

    pub async fn complete_command(
        &self,
        device_id: &str,
        request_id: &str,
        result: serde_json::Value,
    ) {
        let sender = {
            let mut pending = self.pending_results.write().await;
            match pending.get(request_id) {
                Some(entry) if entry.device_id == device_id => {
                    pending.remove(request_id).map(|entry| entry.sender)
                }
                _ => None,
            }
        };
        if let Some(tx) = sender {
            let _ = tx.send(result);
        }
    }

    pub async fn cancel_command(&self, request_id: &str) {
        let mut pending = self.pending_results.write().await;
        pending.remove(request_id);
    }

    #[cfg(test)]
    pub async fn pending_result_count(&self) -> usize {
        self.pending_results.read().await.len()
    }
}

/// Check if a command type is permitted by the device's permissions.
pub fn check_permission(command: &str, permissions: &DevicePermissions) -> bool {
    match command {
        "file.read" => permissions.file_read,
        "file.write" => permissions.file_write,
        "file.list" => permissions.file_list,
        "bash.exec" => permissions.bash_exec,
        "chat.send" | "chat.history" => permissions.chat,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn node_register_and_list() {
        let registry = NodeRegistry::new();
        let (tx1, _) = mpsc::unbounded_channel();
        let (tx2, _) = mpsc::unbounded_channel();
        registry.register("dev-1", "Laptop", tx1).await;
        registry.register("dev-2", "Phone", tx2).await;

        let nodes = registry.list().await;
        assert_eq!(nodes.len(), 2);
    }

    #[tokio::test]
    async fn node_list_is_sorted_for_deterministic_selection() {
        let registry = NodeRegistry::new();
        let (tx1, _) = mpsc::unbounded_channel();
        let (tx2, _) = mpsc::unbounded_channel();
        registry.register("dev-b", "Beta", tx1).await;
        registry.register("dev-a", "Alpha", tx2).await;

        let nodes = registry.list().await;
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].device_id, "dev-a");
        assert_eq!(nodes[1].device_id, "dev-b");
    }

    #[tokio::test]
    async fn node_unregister() {
        let registry = NodeRegistry::new();
        let (tx, _) = mpsc::unbounded_channel();
        let conn_id = registry.register("dev-1", "Laptop", tx).await;
        registry.unregister("dev-1", &conn_id).await;

        let nodes = registry.list().await;
        assert!(nodes.is_empty());
    }

    #[tokio::test]
    async fn node_is_connected() {
        let registry = NodeRegistry::new();
        assert!(!registry.is_connected("dev-1").await);
        let (tx, _) = mpsc::unbounded_channel();
        registry.register("dev-1", "Laptop", tx).await;
        assert!(registry.is_connected("dev-1").await);
    }

    #[tokio::test]
    async fn send_command_and_complete_result() {
        let registry = NodeRegistry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        registry.register("dev-1", "Laptop", tx).await;

        let recv = registry
            .send_command(
                "dev-1",
                "req-1".to_string(),
                "file.read".to_string(),
                serde_json::json!({"path": "/tmp/a"}),
            )
            .await
            .expect("send command");

        let outbound = rx.recv().await.expect("outbound command");
        match outbound {
            NodeServerMessage::Command {
                request_id,
                command,
                ..
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(command, "file.read");
            }
            _ => panic!("Expected Command"),
        }

        registry
            .complete_command("dev-1", "req-1", serde_json::json!({"ok": true}))
            .await;

        let result = recv.await.expect("command result");
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    async fn unregister_drops_pending_results_for_device() {
        let registry = NodeRegistry::new();
        let (tx, mut rx_node) = mpsc::unbounded_channel();
        let conn_id = registry.register("dev-1", "Laptop", tx).await;

        let recv = registry
            .send_command(
                "dev-1",
                "req-disconnect".to_string(),
                "file.read".to_string(),
                serde_json::json!({"path": "/tmp/a"}),
            )
            .await
            .expect("send command");

        // Consume outbound command so sender path is exercised.
        let _ = rx_node.recv().await.expect("outbound command");

        registry.unregister("dev-1", &conn_id).await;
        assert!(
            recv.await.is_err(),
            "pending receiver should fail when node unregisters"
        );
    }

    #[tokio::test]
    async fn stale_unregister_does_not_remove_newer_connection() {
        let registry = NodeRegistry::new();
        let (tx_old, _) = mpsc::unbounded_channel();
        let old_conn = registry.register("dev-1", "Old", tx_old).await;

        let (tx_new, mut rx_new) = mpsc::unbounded_channel();
        let new_conn = registry.register("dev-1", "New", tx_new).await;

        registry.unregister("dev-1", &old_conn).await;
        assert!(registry.is_connected("dev-1").await);

        let recv = registry
            .send_command(
                "dev-1",
                "req-stale".to_string(),
                "file.read".to_string(),
                serde_json::json!({"path": "/tmp/a"}),
            )
            .await
            .expect("send command");
        let outbound = rx_new.recv().await.expect("outbound command");
        assert!(matches!(outbound, NodeServerMessage::Command { .. }));

        registry
            .complete_command("dev-1", "req-stale", serde_json::json!({"ok": true}))
            .await;
        let result = recv.await.expect("command result");
        assert_eq!(result["ok"], true);

        registry.unregister("dev-1", &new_conn).await;
        assert!(!registry.is_connected("dev-1").await);
    }

    #[tokio::test]
    async fn command_result_from_wrong_device_is_ignored() {
        let registry = NodeRegistry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        registry.register("dev-1", "Laptop", tx).await;

        let recv = registry
            .send_command(
                "dev-1",
                "req-wrong-device".to_string(),
                "file.read".to_string(),
                serde_json::json!({"path": "/tmp/a"}),
            )
            .await
            .expect("send command");
        let _ = rx.recv().await.expect("outbound command");

        registry
            .complete_command("dev-2", "req-wrong-device", serde_json::json!({"ok": true}))
            .await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), recv)
                .await
                .is_err(),
            "wrong device should not complete pending result"
        );
    }

    #[test]
    fn permission_file_read() {
        let perms = DevicePermissions {
            file_read: true,
            ..Default::default()
        };
        assert!(check_permission("file.read", &perms));
        assert!(!check_permission("file.write", &perms));
    }

    #[test]
    fn permission_bash_exec() {
        let perms = DevicePermissions {
            bash_exec: true,
            ..Default::default()
        };
        assert!(check_permission("bash.exec", &perms));
        assert!(!check_permission("file.read", &perms));
    }

    #[test]
    fn permission_chat() {
        let perms = DevicePermissions {
            chat: true,
            ..Default::default()
        };
        assert!(check_permission("chat.send", &perms));
        assert!(check_permission("chat.history", &perms));
        assert!(!check_permission("bash.exec", &perms));
    }

    #[test]
    fn permission_unknown_command_denied() {
        let perms = DevicePermissions {
            file_read: true,
            file_write: true,
            file_list: true,
            bash_exec: true,
            chat: true,
            admin: false,
        };
        assert!(!check_permission("unknown.command", &perms));
    }

    #[test]
    fn permission_all_denied_by_default() {
        let perms = DevicePermissions::default();
        assert!(!check_permission("file.read", &perms));
        assert!(!check_permission("file.write", &perms));
        assert!(!check_permission("file.list", &perms));
        assert!(!check_permission("bash.exec", &perms));
        assert!(!check_permission("chat.send", &perms));
    }

    #[test]
    fn node_client_message_serde() {
        let msg = NodeClientMessage::Register {
            device_id: "d1".into(),
            name: "Laptop".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: NodeClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            NodeClientMessage::Register { device_id, name } => {
                assert_eq!(device_id, "d1");
                assert_eq!(name, "Laptop");
            }
            _ => panic!("Expected Register"),
        }

        let msg = NodeClientMessage::RegisterAuth {
            device_id: "d1".into(),
            nonce: "abc".into(),
            signature: "def".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: NodeClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            NodeClientMessage::RegisterAuth {
                device_id,
                nonce,
                signature,
            } => {
                assert_eq!(device_id, "d1");
                assert_eq!(nonce, "abc");
                assert_eq!(signature, "def");
            }
            _ => panic!("Expected RegisterAuth"),
        }
    }

    #[test]
    fn node_server_message_serde() {
        let msg = NodeServerMessage::Command {
            request_id: "r1".into(),
            command: "file.read".into(),
            params: serde_json::json!({"path": "/tmp/test"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: NodeServerMessage = serde_json::from_str(&json).unwrap();
        match back {
            NodeServerMessage::Command {
                request_id,
                command,
                ..
            } => {
                assert_eq!(request_id, "r1");
                assert_eq!(command, "file.read");
            }
            _ => panic!("Expected Command"),
        }

        let msg = NodeServerMessage::AuthChallenge {
            device_id: "d1".into(),
            nonce: "abc".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: NodeServerMessage = serde_json::from_str(&json).unwrap();
        match back {
            NodeServerMessage::AuthChallenge { device_id, nonce } => {
                assert_eq!(device_id, "d1");
                assert_eq!(nonce, "abc");
            }
            _ => panic!("Expected AuthChallenge"),
        }
    }
}
