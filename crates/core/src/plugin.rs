use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::PluginError;
use crate::hooks::{HookHandler, HookPoint};
use crate::traits::InternalToolHandler;
use crate::types::{InboundMessage, OutboundMessage};

/// Trait implemented by native (Rust) plugins that register tools, hooks, and services.
#[async_trait]
pub trait NativePlugin: Send + Sync {
    /// Return the plugin's manifest describing its identity and requirements.
    fn manifest(&self) -> PluginManifest;

    /// Register tools, hooks, and services through the provided API.
    async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError>;

    /// Gracefully shut down the plugin. Default is a no-op.
    async fn shutdown(&self) -> Result<(), PluginError> {
        Ok(())
    }
}

/// Metadata describing a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique identifier (e.g. "browser", "telegram").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Category of the plugin.
    pub kind: PluginKind,
    /// If true, startup fails when this plugin's registration fails.
    pub required: bool,
}

/// Category of a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    Memory,
    Channel,
    Provider,
    General,
}

/// Handler for plugin-registered gateway RPC methods.
/// Defined in encmind-core so PluginRegistrar can reference it without depending
/// on gateway types. The gateway dispatch layer wraps the returned Value into
/// ServerMessage::Result or maps PluginError to ServerMessage::Error.
#[async_trait]
pub trait GatewayMethodHandler: Send + Sync {
    async fn handle(&self, params: serde_json::Value) -> Result<serde_json::Value, PluginError>;
}

/// Handler for plugin-registered channel transforms.
#[async_trait]
pub trait NativeChannelTransform: Send + Sync {
    /// Stable transform identifier.
    ///
    /// Used for duplicate registration guards and deterministic ordering when
    /// multiple transforms share the same priority.
    fn name(&self) -> &str;

    /// Transform an inbound message. Return `None` to drop the message.
    async fn transform_inbound(
        &self,
        msg: InboundMessage,
    ) -> Result<Option<InboundMessage>, PluginError>;

    /// Transform an outbound message. Return `None` to drop the message.
    async fn transform_outbound(
        &self,
        msg: OutboundMessage,
    ) -> Result<Option<OutboundMessage>, PluginError>;
}

/// Handler for plugin-registered periodic timers.
#[async_trait]
pub trait NativePluginTimer: Send + Sync {
    /// Human-readable timer name for logs/debugging.
    fn name(&self) -> &str;

    /// Execute one timer tick.
    async fn tick(&self) -> Result<(), PluginError>;
}

/// Persistent key-value store for plugin state.
/// Implementations are provided by the storage layer.
pub trait PluginStateStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PluginError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), PluginError>;
    fn delete(&self, key: &str) -> Result<(), PluginError>;
    fn list_keys(&self) -> Result<Vec<String>, PluginError>;
}

/// Abstract registration API that plugins use to register tools, hooks, and methods.
/// The concrete implementation lives in the gateway crate.
pub trait PluginRegistrar: Send {
    /// The ID of the plugin currently being registered.
    fn plugin_id(&self) -> &str;

    /// Register a tool handler. The registrar may namespace the tool name
    /// (e.g. prepend `plugin_id_`).
    fn register_tool(
        &mut self,
        name: &str,
        description: &str,
        parameters: serde_json::Value,
        handler: Arc<dyn InternalToolHandler>,
    ) -> Result<(), PluginError>;

    /// Register a hook handler at the given hook point with a priority.
    /// Higher priority handlers run first.
    fn register_hook(
        &mut self,
        point: HookPoint,
        priority: i32,
        handler: Arc<dyn HookHandler>,
    ) -> Result<(), PluginError>;

    /// Register a native gateway RPC method handler.
    /// Only available to Tier 1 (compiled-in) plugins.
    fn register_gateway_method(
        &mut self,
        method: &str,
        handler: Arc<dyn GatewayMethodHandler>,
    ) -> Result<(), PluginError>;

    /// Register a channel transform for the given channel.
    ///
    /// Transforms run in descending priority order (higher first).
    fn register_channel_transform(
        &mut self,
        channel: &str,
        priority: i32,
        handler: Arc<dyn NativeChannelTransform>,
    ) -> Result<(), PluginError>;

    /// Register a periodic native timer for this plugin.
    ///
    /// `interval_secs` must be >= 1.
    fn register_timer(
        &mut self,
        name: &str,
        interval_secs: u64,
        handler: Arc<dyn NativePluginTimer>,
    ) -> Result<(), PluginError>;

    /// Return the plugin's configuration section from `AppConfig.plugins`, if any.
    fn config(&self) -> Option<&serde_json::Value> {
        None
    }

    /// Return a persistent state store for the plugin.
    ///
    /// Returns an owned `Arc` so plugin registration code can retain the store
    /// inside long-lived tool/method handlers.
    fn state_store(&self) -> Option<Arc<dyn PluginStateStore>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_manifest_construction() {
        let manifest = PluginManifest {
            id: "browser".into(),
            name: "Browser Automation".into(),
            version: "0.1.0".into(),
            description: "Headless Chrome pool".into(),
            kind: PluginKind::General,
            required: false,
        };
        assert_eq!(manifest.id, "browser");
        assert_eq!(manifest.kind, PluginKind::General);
        assert!(!manifest.required);
    }

    #[test]
    fn plugin_kind_serde_roundtrip() {
        let kinds = vec![
            PluginKind::Memory,
            PluginKind::Channel,
            PluginKind::Provider,
            PluginKind::General,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PluginKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn plugin_manifest_required_flag() {
        let required = PluginManifest {
            id: "critical".into(),
            name: "Critical Plugin".into(),
            version: "1.0.0".into(),
            description: "Must not fail".into(),
            kind: PluginKind::General,
            required: true,
        };
        assert!(required.required);

        let optional = PluginManifest {
            id: "optional".into(),
            name: "Optional Plugin".into(),
            version: "1.0.0".into(),
            description: "Best-effort".into(),
            kind: PluginKind::General,
            required: false,
        };
        assert!(!optional.required);
    }
}
