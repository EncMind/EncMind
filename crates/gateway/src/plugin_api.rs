use std::sync::Arc;

use encmind_agent::tool_registry::{InternalToolHandler, ToolRegistry};
use encmind_core::error::PluginError;
use encmind_core::hooks::{HookHandler, HookPoint, HookRegistry};
use encmind_core::plugin::{
    GatewayMethodHandler, NativeChannelTransform, NativePluginTimer, PluginRegistrar,
    PluginStateStore,
};

/// A fully-resolved plugin tool registration captured at startup.
///
/// The tool name is already namespaced (e.g. `browser_navigate`) and can be
/// replayed into fresh runtime registries without re-running plugin code.
#[derive(Clone)]
pub(crate) struct RegisteredPluginTool {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub handler: Arc<dyn InternalToolHandler>,
}

/// A plugin-registered hook snapshot captured at startup.
#[derive(Clone)]
pub(crate) struct RegisteredPluginHook {
    pub plugin_id: String,
    pub point: HookPoint,
    pub priority: i32,
    pub handler: Arc<dyn HookHandler>,
    pub timeout_ms: u64,
}

/// A plugin-registered transform snapshot captured at startup.
#[derive(Clone)]
pub(crate) struct RegisteredPluginTransform {
    pub plugin_id: String,
    /// Stable transform identity within a plugin/channel registration scope.
    pub transform_id: String,
    pub channel: String,
    pub priority: i32,
    pub handler: Arc<dyn NativeChannelTransform>,
}

/// A plugin-registered periodic timer snapshot captured at startup.
#[derive(Clone)]
pub(crate) struct RegisteredPluginTimer {
    pub plugin_id: String,
    pub name: String,
    pub interval_secs: u64,
    pub handler: Arc<dyn NativePluginTimer>,
}

/// Concrete implementation of `PluginRegistrar` used during plugin initialization.
/// Collects tool registrations into the shared `ToolRegistry`, hook registrations
/// into the shared `HookRegistry`, and method handlers into a `Vec` that
/// `PluginManager` consumes after all plugins have registered.
pub struct GatewayPluginApi<'a> {
    plugin_id: String,
    tool_registry: &'a mut ToolRegistry,
    hook_registry: &'a mut HookRegistry,
    method_handlers: &'a mut Vec<(String, Arc<dyn GatewayMethodHandler>)>,
    tool_snapshots: &'a mut Vec<RegisteredPluginTool>,
    hook_snapshots: Vec<RegisteredPluginHook>,
    transform_snapshots: &'a mut Vec<RegisteredPluginTransform>,
    timer_snapshots: &'a mut Vec<RegisteredPluginTimer>,
    config: Option<serde_json::Value>,
    state_store: Option<Arc<dyn PluginStateStore>>,
}

impl<'a> GatewayPluginApi<'a> {
    pub(crate) fn new(
        plugin_id: String,
        tool_registry: &'a mut ToolRegistry,
        hook_registry: &'a mut HookRegistry,
        method_handlers: &'a mut Vec<(String, Arc<dyn GatewayMethodHandler>)>,
        tool_snapshots: &'a mut Vec<RegisteredPluginTool>,
        transform_snapshots: &'a mut Vec<RegisteredPluginTransform>,
        timer_snapshots: &'a mut Vec<RegisteredPluginTimer>,
    ) -> Self {
        Self {
            plugin_id,
            tool_registry,
            hook_registry,
            method_handlers,
            tool_snapshots,
            hook_snapshots: Vec::new(),
            transform_snapshots,
            timer_snapshots,
            config: None,
            state_store: None,
        }
    }

    /// Set the plugin's configuration section.
    pub(crate) fn with_config(mut self, config: Option<serde_json::Value>) -> Self {
        self.config = config;
        self
    }

    /// Set the plugin's state store.
    pub(crate) fn with_state_store(mut self, store: Option<Arc<dyn PluginStateStore>>) -> Self {
        self.state_store = store;
        self
    }

    /// Drain collected hook snapshots after plugin registration.
    pub(crate) fn take_hook_snapshots(&mut self) -> Vec<RegisteredPluginHook> {
        std::mem::take(&mut self.hook_snapshots)
    }
}

impl PluginRegistrar for GatewayPluginApi<'_> {
    fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    fn register_tool(
        &mut self,
        name: &str,
        description: &str,
        parameters: serde_json::Value,
        handler: Arc<dyn InternalToolHandler>,
    ) -> Result<(), PluginError> {
        let namespaced = format!("{}_{}", self.plugin_id, name);
        self.tool_registry
            .register_internal(
                &namespaced,
                description,
                parameters.clone(),
                handler.clone(),
            )
            .map_err(|e| PluginError::RegistrationFailed(e.to_string()))?;
        self.tool_snapshots.push(RegisteredPluginTool {
            name: namespaced,
            description: description.to_owned(),
            parameters,
            handler,
        });
        Ok(())
    }

    fn register_hook(
        &mut self,
        point: HookPoint,
        priority: i32,
        handler: Arc<dyn HookHandler>,
    ) -> Result<(), PluginError> {
        let timeout_ms = 5000;
        self.hook_registry
            .register(
                point,
                priority,
                &self.plugin_id,
                handler.clone(),
                timeout_ms,
            )
            .map_err(|e| PluginError::RegistrationFailed(e.to_string()))?;
        self.hook_snapshots.push(RegisteredPluginHook {
            plugin_id: self.plugin_id.clone(),
            point,
            priority,
            handler,
            timeout_ms,
        });
        Ok(())
    }

    fn register_gateway_method(
        &mut self,
        method: &str,
        handler: Arc<dyn GatewayMethodHandler>,
    ) -> Result<(), PluginError> {
        self.method_handlers.push((method.to_string(), handler));
        Ok(())
    }

    fn register_channel_transform(
        &mut self,
        channel: &str,
        priority: i32,
        handler: Arc<dyn NativeChannelTransform>,
    ) -> Result<(), PluginError> {
        let channel = channel.trim();
        if channel.is_empty() {
            return Err(PluginError::RegistrationFailed(
                "channel transform registration requires non-empty channel".into(),
            ));
        }
        let transform_id = handler.name().trim().to_string();
        if transform_id.is_empty() {
            return Err(PluginError::RegistrationFailed(
                "channel transform registration requires non-empty transform name".into(),
            ));
        }
        if self.transform_snapshots.iter().any(|existing| {
            existing.plugin_id == self.plugin_id
                && existing.channel == channel
                && existing.transform_id == transform_id
        }) {
            return Err(PluginError::RegistrationFailed(format!(
                "duplicate channel transform registration for channel '{channel}' and transform_id '{transform_id}'"
            )));
        }
        self.transform_snapshots.push(RegisteredPluginTransform {
            plugin_id: self.plugin_id.clone(),
            transform_id,
            channel: channel.to_string(),
            priority,
            handler,
        });
        Ok(())
    }

    fn register_timer(
        &mut self,
        name: &str,
        interval_secs: u64,
        handler: Arc<dyn NativePluginTimer>,
    ) -> Result<(), PluginError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(PluginError::RegistrationFailed(
                "timer registration requires non-empty name".into(),
            ));
        }
        if interval_secs == 0 {
            return Err(PluginError::RegistrationFailed(
                "timer registration requires interval_secs >= 1".into(),
            ));
        }
        if self
            .timer_snapshots
            .iter()
            .any(|existing| existing.plugin_id == self.plugin_id && existing.name == name)
        {
            return Err(PluginError::RegistrationFailed(format!(
                "duplicate timer registration for name '{name}'"
            )));
        }
        self.timer_snapshots.push(RegisteredPluginTimer {
            plugin_id: self.plugin_id.clone(),
            name: name.to_string(),
            interval_secs,
            handler,
        });
        Ok(())
    }

    fn config(&self) -> Option<&serde_json::Value> {
        self.config.as_ref()
    }

    fn state_store(&self) -> Option<Arc<dyn PluginStateStore>> {
        self.state_store.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use encmind_core::error::AppError;
    use encmind_core::types::{AgentId, InboundMessage, OutboundMessage, SessionId};

    struct StubToolHandler;
    #[async_trait]
    impl InternalToolHandler for StubToolHandler {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            Ok("ok".into())
        }
    }

    struct StubMethodHandler;
    #[async_trait]
    impl GatewayMethodHandler for StubMethodHandler {
        async fn handle(
            &self,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, PluginError> {
            Ok(serde_json::json!({"ok": true}))
        }
    }

    struct StubTransformHandler;
    #[async_trait]
    impl NativeChannelTransform for StubTransformHandler {
        fn name(&self) -> &str {
            "stub-transform"
        }

        async fn transform_inbound(
            &self,
            msg: InboundMessage,
        ) -> Result<Option<InboundMessage>, PluginError> {
            Ok(Some(msg))
        }

        async fn transform_outbound(
            &self,
            msg: OutboundMessage,
        ) -> Result<Option<OutboundMessage>, PluginError> {
            Ok(Some(msg))
        }
    }

    struct StubTimerHandler;
    #[async_trait]
    impl NativePluginTimer for StubTimerHandler {
        fn name(&self) -> &str {
            "stub-timer"
        }

        async fn tick(&self) -> Result<(), PluginError> {
            Ok(())
        }
    }

    #[test]
    fn plugin_id_returns_correct_id() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let api = GatewayPluginApi::new(
            "browser".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );
        assert_eq!(api.plugin_id(), "browser");
    }

    #[test]
    fn register_tool_namespaces_correctly() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "browser".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );
        api.register_tool(
            "navigate",
            "Go to a URL",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        assert!(tr.has_tool("browser_navigate"));
        assert!(!tr.has_tool("navigate"));
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "browser_navigate");
    }

    #[test]
    fn duplicate_tool_rejected() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "browser".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );
        api.register_tool(
            "nav",
            "desc",
            serde_json::json!({}),
            Arc::new(StubToolHandler),
        )
        .unwrap();
        let err = api
            .register_tool(
                "nav",
                "desc",
                serde_json::json!({}),
                Arc::new(StubToolHandler),
            )
            .unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn register_hook_delegates() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();

        struct StubHook;
        #[async_trait]
        impl encmind_core::hooks::HookHandler for StubHook {
            async fn execute(
                &self,
                _ctx: &mut encmind_core::hooks::HookContext,
            ) -> Result<encmind_core::hooks::HookResult, PluginError> {
                Ok(encmind_core::hooks::HookResult::Continue)
            }
        }

        let mut api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );
        api.register_hook(HookPoint::OnStartup, 10, Arc::new(StubHook))
            .unwrap();
        assert_eq!(hr.total_hooks(), 1);
    }

    #[test]
    fn register_gateway_method_collects() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );
        api.register_gateway_method("custom.method", Arc::new(StubMethodHandler))
            .unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].0, "custom.method");
    }

    #[test]
    fn config_access_through_registrar() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let api = GatewayPluginApi::new(
            "browser".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        )
        .with_config(Some(serde_json::json!({"headless": true, "pool_size": 3})));
        let config = api.config().unwrap();
        assert_eq!(config["headless"], true);
        assert_eq!(config["pool_size"], 3);
    }

    #[test]
    fn state_store_access_through_registrar() {
        use encmind_storage::migrations::run_migrations;
        use encmind_storage::plugin_state::SqlitePluginStateStore;
        use encmind_storage::pool::create_test_pool;

        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let store: Arc<dyn PluginStateStore> =
            Arc::new(SqlitePluginStateStore::new(pool, "test-plugin"));

        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        )
        .with_state_store(Some(store));

        let ss = api.state_store().unwrap();
        ss.set("key1", b"value1").unwrap();
        assert_eq!(ss.get("key1").unwrap().unwrap(), b"value1");
    }

    #[test]
    fn register_channel_transform_collects() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );
        api.register_channel_transform("slack", 10, Arc::new(StubTransformHandler))
            .unwrap();
        assert_eq!(transforms.len(), 1);
        assert_eq!(transforms[0].plugin_id, "test-plugin");
        assert_eq!(transforms[0].transform_id, "stub-transform");
        assert_eq!(transforms[0].channel, "slack");
        assert_eq!(transforms[0].priority, 10);
    }

    #[test]
    fn register_timer_collects() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );

        api.register_timer("heartbeat", 30, Arc::new(StubTimerHandler))
            .unwrap();

        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].plugin_id, "test-plugin");
        assert_eq!(timers[0].name, "heartbeat");
        assert_eq!(timers[0].interval_secs, 30);
    }

    #[test]
    fn register_channel_transform_rejects_duplicate_for_same_plugin_and_channel() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );

        api.register_channel_transform("slack", 10, Arc::new(StubTransformHandler))
            .unwrap();
        let err = api
            .register_channel_transform("slack", 5, Arc::new(StubTransformHandler))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate channel transform registration"),
            "expected duplicate transform error, got {err}"
        );
    }

    #[test]
    fn register_timer_rejects_duplicate_name_for_same_plugin() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let mut methods = Vec::new();
        let mut tools = Vec::new();
        let mut transforms = Vec::new();
        let mut timers = Vec::new();
        let mut api = GatewayPluginApi::new(
            "test-plugin".into(),
            &mut tr,
            &mut hr,
            &mut methods,
            &mut tools,
            &mut transforms,
            &mut timers,
        );

        api.register_timer("heartbeat", 30, Arc::new(StubTimerHandler))
            .unwrap();
        let err = api
            .register_timer("heartbeat", 30, Arc::new(StubTimerHandler))
            .unwrap_err();
        assert!(
            err.to_string().contains("duplicate timer registration"),
            "expected duplicate timer error, got {err}"
        );
    }
}
