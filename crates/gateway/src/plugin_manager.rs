use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tracing::{info, warn};

use encmind_agent::tool_registry::ToolRegistry;
use encmind_core::error::PluginError;
use encmind_core::hooks::HookRegistry;
use encmind_core::plugin::{GatewayMethodHandler, NativePlugin, PluginStateStore};

use crate::plugin_api::{
    GatewayPluginApi, RegisteredPluginHook, RegisteredPluginTimer, RegisteredPluginTool,
    RegisteredPluginTransform,
};
use crate::protocol::{ErrorPayload, ServerMessage, ERR_INTERNAL};

const BUILTIN_RPC_METHODS: &[&str] = &[
    "chat.send",
    "chat.history",
    "chat.abort",
    "sessions.list",
    "sessions.create",
    "sessions.delete",
    "sessions.rename",
    "sessions.archive",
    "sessions.unarchive",
    "sessions.export",
    "sessions.tag_add",
    "sessions.tag_remove",
    "sessions.tags",
    "models.list",
    "nodes.list",
    "nodes.invoke",
    "nodes.update_permissions",
    "nodes.revoke",
    "security.lockdown",
    "security.audit",
    "config.get",
    "config.set",
    "config.set_inference_mode",
    "agents.list",
    "agents.get",
    "memory.search",
    "memory.list",
    "memory.delete",
    "memory.status",
    "cron.list",
    "cron.create",
    "cron.delete",
    "cron.trigger",
    "timeline.query",
    "keys.list",
    "keys.set",
    "keys.delete",
    "backup.trigger",
    "backup.list",
    "skills.list",
    "skills.toggle",
    "approval.respond",
    "timers.list",
    "timers.toggle",
    "plugins.status",
    "plugins.reload",
    "skills.metrics",
    "skills.config.get",
    "skills.config.set",
    "skills.resources.get",
    "skills.resources.set",
];

/// Information about a plugin that failed to load.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailedPluginInfo {
    pub id: String,
    pub error: String,
}

/// Manages the lifecycle of native (Tier 1) plugins.
/// Created during gateway startup; stores the plugin instances and any
/// gateway method handlers they registered.
pub struct PluginManager {
    plugins: Vec<Box<dyn NativePlugin>>,
    method_handlers: HashMap<String, Arc<dyn GatewayMethodHandler>>,
    registered_tools: Vec<RegisteredPluginTool>,
    registered_hooks: Vec<RegisteredPluginHook>,
    registered_transforms: Vec<RegisteredPluginTransform>,
    registered_timers: Vec<RegisteredPluginTimer>,
    failed_plugins: Vec<FailedPluginInfo>,
    initialized_at: Option<String>,
}

impl std::fmt::Debug for PluginManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginManager")
            .field("plugin_count", &self.plugins.len())
            .field("method_count", &self.method_handlers.len())
            .field("tool_count", &self.registered_tools.len())
            .field("hook_count", &self.registered_hooks.len())
            .field("transform_count", &self.registered_transforms.len())
            .field("timer_count", &self.registered_timers.len())
            .finish()
    }
}

/// Per-plugin context passed during initialization for config/state access.
pub struct PluginContext {
    pub config: Option<serde_json::Value>,
    pub state_store: Option<Arc<dyn PluginStateStore>>,
}

impl PluginManager {
    /// Initialize all plugins, collecting their tool/hook/method registrations.
    ///
    /// - `required=true` plugins fail startup if registration fails.
    /// - `required=false` plugins fail open (degraded mode) with a warning.
    ///
    /// `plugin_contexts` maps plugin ID → config/state context. Plugins not in
    /// the map get `None` for both.
    pub async fn initialize(
        plugins: Vec<Box<dyn NativePlugin>>,
        tool_registry: &mut ToolRegistry,
        hook_registry: &mut HookRegistry,
        plugin_contexts: HashMap<String, PluginContext>,
    ) -> Result<Self, anyhow::Error> {
        let mut loaded_plugins: Vec<Box<dyn NativePlugin>> = Vec::new();
        let mut method_handlers: HashMap<String, Arc<dyn GatewayMethodHandler>> = HashMap::new();
        let mut registered_tools: Vec<RegisteredPluginTool> = Vec::new();
        let mut registered_hooks: Vec<RegisteredPluginHook> = Vec::new();
        let mut registered_transforms: Vec<RegisteredPluginTransform> = Vec::new();
        let mut registered_timers: Vec<RegisteredPluginTimer> = Vec::new();
        let mut failed_plugins: Vec<FailedPluginInfo> = Vec::new();

        for plugin in plugins {
            let manifest = plugin.manifest();
            let mut staged_tools = tool_registry.clone();
            let mut staged_hooks = hook_registry.clone();
            let mut staged_methods: Vec<(String, Arc<dyn GatewayMethodHandler>)> = Vec::new();
            let mut staged_tool_snapshots: Vec<RegisteredPluginTool> = Vec::new();
            let mut staged_transform_snapshots: Vec<RegisteredPluginTransform> = Vec::new();
            let mut staged_timer_snapshots: Vec<RegisteredPluginTimer> = Vec::new();

            let ctx = plugin_contexts.get(&manifest.id);
            let mut api = GatewayPluginApi::new(
                manifest.id.clone(),
                &mut staged_tools,
                &mut staged_hooks,
                &mut staged_methods,
                &mut staged_tool_snapshots,
                &mut staged_transform_snapshots,
                &mut staged_timer_snapshots,
            )
            .with_config(ctx.and_then(|c| c.config.clone()))
            .with_state_store(ctx.and_then(|c| c.state_store.clone()));

            let register_result = plugin.register(&mut api).await;
            let staged_hook_snapshots = api.take_hook_snapshots();
            drop(api);
            let registration = register_result.and_then(|_| {
                validate_method_batch(&manifest.id, &staged_methods, &method_handlers)
                    .map_err(|e| PluginError::RegistrationFailed(e.to_string()))
            });

            match registration {
                Ok(()) => {
                    *tool_registry = staged_tools;
                    *hook_registry = staged_hooks;
                    for (method, handler) in staged_methods {
                        method_handlers.insert(method, handler);
                    }
                    registered_tools.extend(staged_tool_snapshots);
                    registered_hooks.extend(staged_hook_snapshots);
                    registered_transforms.extend(staged_transform_snapshots);
                    registered_timers.extend(staged_timer_snapshots);
                    info!(
                        plugin = %manifest.id,
                        kind = ?manifest.kind,
                        "plugin registered"
                    );
                    loaded_plugins.push(plugin);
                }
                Err(e) if manifest.required => {
                    return Err(anyhow::anyhow!(
                        "required plugin '{}' failed to register: {}",
                        manifest.id,
                        e
                    ));
                }
                Err(e) => {
                    warn!(
                        plugin = %manifest.id,
                        error = %e,
                        "optional plugin failed to register; continuing in degraded mode"
                    );
                    failed_plugins.push(FailedPluginInfo {
                        id: manifest.id.to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }

        let initialized_at = Some(chrono::Utc::now().to_rfc3339());

        Ok(Self {
            plugins: loaded_plugins,
            method_handlers,
            registered_tools,
            registered_hooks,
            registered_transforms,
            registered_timers,
            failed_plugins,
            initialized_at,
        })
    }

    /// Try to dispatch a method to a plugin-registered handler.
    /// Returns `None` if no handler is registered for this method.
    pub async fn dispatch_method(
        &self,
        method: &str,
        params: serde_json::Value,
        req_id: &str,
    ) -> Option<ServerMessage> {
        let handler = self.method_handlers.get(method)?;
        match handler.handle(params).await {
            Ok(result) => Some(ServerMessage::Res {
                id: req_id.to_string(),
                result,
            }),
            Err(e) => Some(ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }),
        }
    }

    /// Check whether a plugin-registered RPC method exists.
    pub fn has_method(&self, method: &str) -> bool {
        self.method_handlers.contains_key(method)
    }

    /// Re-register plugin tools into a freshly-built tool registry.
    ///
    /// This is used when runtime resources are rebuilt (for example after key
    /// rotation) so plugin tools remain available.
    ///
    pub async fn register_tools(&self, registry: &mut ToolRegistry) -> Result<(), anyhow::Error> {
        for tool in &self.registered_tools {
            registry
                .register_internal(
                    &tool.name,
                    &tool.description,
                    tool.parameters.clone(),
                    tool.handler.clone(),
                )
                .map_err(|e| {
                    anyhow::anyhow!("failed to replay cached plugin tool '{}': {}", tool.name, e)
                })?;
        }

        Ok(())
    }

    /// Re-register plugin hooks into a refreshed hook registry.
    pub async fn register_hooks(&self, registry: &mut HookRegistry) -> Result<(), anyhow::Error> {
        for hook in &self.registered_hooks {
            registry
                .register(
                    hook.point,
                    hook.priority,
                    &hook.plugin_id,
                    hook.handler.clone(),
                    hook.timeout_ms,
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to replay cached plugin hook '{}::{:?}': {}",
                        hook.plugin_id,
                        hook.point,
                        e
                    )
                })?;
        }
        Ok(())
    }

    /// Snapshot of plugin-registered channel transforms.
    pub(crate) fn registered_transforms(&self) -> &[RegisteredPluginTransform] {
        &self.registered_transforms
    }

    /// Number of cached plugin hook registrations for replay.
    pub(crate) fn hook_count(&self) -> usize {
        self.registered_hooks.len()
    }

    /// Snapshot of plugin-registered periodic timers.
    pub(crate) fn registered_timers(&self) -> &[RegisteredPluginTimer] {
        &self.registered_timers
    }

    /// Shut down all plugins gracefully.
    pub async fn shutdown(&self) {
        for plugin in &self.plugins {
            let id = plugin.manifest().id;
            if let Err(e) = plugin.shutdown().await {
                warn!(plugin = %id, error = %e, "plugin shutdown error");
            }
        }
    }

    /// Number of registered method handlers.
    pub fn method_count(&self) -> usize {
        self.method_handlers.len()
    }

    /// Number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// IDs of successfully loaded plugins.
    pub fn plugin_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.plugins.iter().map(|p| p.manifest().id).collect();
        ids.sort();
        ids
    }

    /// Plugins that failed to load (optional plugins only).
    pub fn failed_plugins(&self) -> &[FailedPluginInfo] {
        &self.failed_plugins
    }

    /// Whether the system is running in degraded mode (some plugins failed).
    pub fn is_degraded(&self) -> bool {
        !self.failed_plugins.is_empty()
    }

    /// RFC3339 timestamp when plugins were initialized.
    pub fn initialized_at(&self) -> Option<&str> {
        self.initialized_at.as_deref()
    }
}

fn validate_method_batch(
    plugin_id: &str,
    batch: &[(String, Arc<dyn GatewayMethodHandler>)],
    existing: &HashMap<String, Arc<dyn GatewayMethodHandler>>,
) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for (method, _handler) in batch {
        if !seen.insert(method.as_str()) {
            return Err(anyhow::anyhow!(
                "plugin '{}' registered duplicate gateway method '{}'",
                plugin_id,
                method
            ));
        }
        if existing.contains_key(method) {
            return Err(anyhow::anyhow!(
                "plugin '{}' attempted to overwrite gateway method '{}'",
                plugin_id,
                method
            ));
        }
        if BUILTIN_RPC_METHODS.contains(&method.as_str()) {
            return Err(anyhow::anyhow!(
                "plugin '{}' tried to register method '{}' which shadows a built-in method",
                plugin_id,
                method
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use encmind_core::error::{AppError, PluginError};
    use encmind_core::hooks::{HookContext, HookHandler, HookPoint, HookResult};
    use encmind_core::plugin::{PluginKind, PluginManifest, PluginRegistrar};
    use encmind_core::traits::InternalToolHandler;
    use encmind_core::types::{AgentId, SessionId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NoopPlugin {
        required: bool,
    }

    #[async_trait]
    impl NativePlugin for NoopPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "noop".into(),
                name: "No-Op Plugin".into(),
                version: "0.1.0".into(),
                description: "Does nothing".into(),
                kind: PluginKind::General,
                required: self.required,
            }
        }

        async fn register(&self, _api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            Ok(())
        }
    }

    struct FailingPlugin {
        required: bool,
    }

    #[async_trait]
    impl NativePlugin for FailingPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "failing".into(),
                name: "Failing Plugin".into(),
                version: "0.1.0".into(),
                description: "Always fails".into(),
                kind: PluginKind::General,
                required: self.required,
            }
        }

        async fn register(&self, _api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            Err(PluginError::RegistrationFailed(
                "intentional failure".into(),
            ))
        }
    }

    #[tokio::test]
    async fn initialize_loads_plugins() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(NoopPlugin { required: false })];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();
        assert_eq!(pm.plugin_count(), 1);
    }

    #[tokio::test]
    async fn required_plugin_failure_aborts() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(FailingPlugin { required: true })];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let result = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("intentional failure"));
    }

    #[tokio::test]
    async fn optional_plugin_failure_continues() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![
            Box::new(FailingPlugin { required: false }),
            Box::new(NoopPlugin { required: false }),
        ];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();
        assert_eq!(pm.plugin_count(), 1);
    }

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

    struct CountedRegisterPlugin {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl NativePlugin for CountedRegisterPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "counted".into(),
                name: "Counted Plugin".into(),
                version: "0.1.0".into(),
                description: "tracks register calls".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            api.register_tool(
                "echo",
                "desc",
                serde_json::json!({"type":"object"}),
                Arc::new(StubToolHandler),
            )
        }
    }

    struct StubHookHandler;
    #[async_trait]
    impl HookHandler for StubHookHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Continue)
        }
    }

    struct CountedHookRegisterPlugin {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl NativePlugin for CountedHookRegisterPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "hooked".into(),
                name: "Hooked Plugin".into(),
                version: "0.1.0".into(),
                description: "tracks hook register calls".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            api.register_hook(HookPoint::BeforeToolCall, 1, Arc::new(StubHookHandler))
        }
    }

    struct TransformPlugin;

    #[async_trait]
    impl NativePlugin for TransformPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "xfm".into(),
                name: "Transform Plugin".into(),
                version: "0.1.0".into(),
                description: "Registers channel transforms".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            struct PassthroughTransform;
            #[async_trait]
            impl encmind_core::plugin::NativeChannelTransform for PassthroughTransform {
                fn name(&self) -> &str {
                    "xfm_passthrough"
                }

                async fn transform_inbound(
                    &self,
                    msg: encmind_core::types::InboundMessage,
                ) -> Result<Option<encmind_core::types::InboundMessage>, PluginError>
                {
                    Ok(Some(msg))
                }

                async fn transform_outbound(
                    &self,
                    msg: encmind_core::types::OutboundMessage,
                ) -> Result<Option<encmind_core::types::OutboundMessage>, PluginError>
                {
                    Ok(Some(msg))
                }
            }
            api.register_channel_transform("slack", 5, Arc::new(PassthroughTransform))
        }
    }

    struct TimerPlugin;

    #[async_trait]
    impl NativePlugin for TimerPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "timer".into(),
                name: "Timer Plugin".into(),
                version: "0.1.0".into(),
                description: "Registers plugin timers".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            struct TickHandler;
            #[async_trait]
            impl encmind_core::plugin::NativePluginTimer for TickHandler {
                fn name(&self) -> &str {
                    "heartbeat"
                }

                async fn tick(&self) -> Result<(), PluginError> {
                    Ok(())
                }
            }
            api.register_timer("heartbeat", 10, Arc::new(TickHandler))
        }
    }

    struct PartiallyFailingPlugin;
    #[async_trait]
    impl NativePlugin for PartiallyFailingPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "partial".into(),
                name: "Partial".into(),
                version: "0.1.0".into(),
                description: "Registers then fails".into(),
                kind: PluginKind::General,
                required: false,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            api.register_tool(
                "echo",
                "desc",
                serde_json::json!({"type":"object"}),
                Arc::new(StubToolHandler),
            )?;
            api.register_gateway_method("custom.partial", Arc::new(TestMethodHandler))?;
            Err(PluginError::RegistrationFailed("boom".into()))
        }
    }

    struct TestMethodHandler;
    #[async_trait]
    impl GatewayMethodHandler for TestMethodHandler {
        async fn handle(
            &self,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, PluginError> {
            Ok(serde_json::json!({"ok": true}))
        }
    }

    #[tokio::test]
    async fn optional_partial_failure_does_not_commit_registrations() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(PartiallyFailingPlugin)];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();

        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();

        assert_eq!(pm.plugin_count(), 0);
        assert_eq!(pm.method_count(), 0);
        assert_eq!(hr.total_hooks(), 0);
        assert!(!tr.has_tool("partial_echo"));
    }

    #[tokio::test]
    async fn register_tools_replays_cached_tools_without_rerunning_plugin_register() {
        let calls = Arc::new(AtomicUsize::new(0));
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(CountedRegisterPlugin {
            calls: calls.clone(),
        })];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "register should run once at startup"
        );
        let mut fresh_registry = ToolRegistry::new();
        pm.register_tools(&mut fresh_registry).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "register_tools should replay cached registrations"
        );
        assert!(fresh_registry.has_tool("counted_echo"));
    }

    #[tokio::test]
    async fn register_hooks_replays_cached_hooks_without_rerunning_plugin_register() {
        let calls = Arc::new(AtomicUsize::new(0));
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(CountedHookRegisterPlugin {
            calls: calls.clone(),
        })];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "register should run once at startup"
        );
        let mut fresh_registry = HookRegistry::new();
        pm.register_hooks(&mut fresh_registry).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "register_hooks should replay cached registrations"
        );
        assert_eq!(fresh_registry.total_hooks(), 1);
        assert!(fresh_registry.registered_plugin_ids().contains("hooked"));
    }

    #[tokio::test]
    async fn initialize_caches_registered_transforms() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(TransformPlugin)];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();

        assert_eq!(pm.plugin_count(), 1);
        let transforms = pm.registered_transforms();
        assert_eq!(transforms.len(), 1);
        assert_eq!(transforms[0].plugin_id, "xfm");
        assert_eq!(transforms[0].channel, "slack");
        assert_eq!(transforms[0].priority, 5);
    }

    #[tokio::test]
    async fn initialize_caches_registered_timers() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(TimerPlugin)];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();

        assert_eq!(pm.plugin_count(), 1);
        let timers = pm.registered_timers();
        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].plugin_id, "timer");
        assert_eq!(timers[0].name, "heartbeat");
        assert_eq!(timers[0].interval_secs, 10);
    }

    #[tokio::test]
    async fn dispatch_method_returns_none_for_unknown() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();
        let result = pm
            .dispatch_method("unknown.method", serde_json::json!({}), "req-1")
            .await;
        assert!(result.is_none());
    }

    struct MethodPlugin;
    #[async_trait]
    impl NativePlugin for MethodPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "meth".into(),
                name: "Method Plugin".into(),
                version: "0.1.0".into(),
                description: "Registers a method".into(),
                kind: PluginKind::General,
                required: false,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            struct TestHandler;
            #[async_trait]
            impl GatewayMethodHandler for TestHandler {
                async fn handle(
                    &self,
                    _params: serde_json::Value,
                ) -> Result<serde_json::Value, PluginError> {
                    Ok(serde_json::json!({"hello": "world"}))
                }
            }
            api.register_gateway_method("custom.hello", Arc::new(TestHandler))
        }
    }

    struct MethodPluginDuplicateA;
    #[async_trait]
    impl NativePlugin for MethodPluginDuplicateA {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "dup-a".into(),
                name: "Dup A".into(),
                version: "0.1.0".into(),
                description: "Registers duplicate method".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            api.register_gateway_method("custom.dupe", Arc::new(TestMethodHandler))
        }
    }

    struct MethodPluginDuplicateB;
    #[async_trait]
    impl NativePlugin for MethodPluginDuplicateB {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "dup-b".into(),
                name: "Dup B".into(),
                version: "0.1.0".into(),
                description: "Registers duplicate method".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            api.register_gateway_method("custom.dupe", Arc::new(TestMethodHandler))
        }
    }

    #[tokio::test]
    async fn duplicate_gateway_method_rejected() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![
            Box::new(MethodPluginDuplicateA),
            Box::new(MethodPluginDuplicateB),
        ];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();

        let result = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("overwrite gateway method"));
    }

    struct BuiltinShadowPlugin;
    #[async_trait]
    impl NativePlugin for BuiltinShadowPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "shadow".into(),
                name: "Shadow Plugin".into(),
                version: "0.1.0".into(),
                description: "Attempts to shadow built-in RPC".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            api.register_gateway_method("chat.send", Arc::new(TestMethodHandler))
        }
    }

    #[tokio::test]
    async fn built_in_method_shadow_rejected() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(BuiltinShadowPlugin)];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();

        let result = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("shadows a built-in method"));
    }

    #[test]
    fn builtin_rpc_methods_covers_all_dispatch_entries() {
        // This test ensures BUILTIN_RPC_METHODS stays in sync with dispatch.rs.
        // If you add a new dispatch entry, you must also add it here.
        let dispatch_methods = [
            "chat.send",
            "chat.history",
            "chat.abort",
            "sessions.list",
            "sessions.create",
            "sessions.delete",
            "sessions.rename",
            "sessions.archive",
            "sessions.unarchive",
            "sessions.export",
            "sessions.tag_add",
            "sessions.tag_remove",
            "sessions.tags",
            "config.get",
            "config.set",
            "security.lockdown",
            "security.audit",
            "models.list",
            "agents.list",
            "agents.get",
            "nodes.list",
            "nodes.invoke",
            "nodes.update_permissions",
            "nodes.revoke",
            "memory.search",
            "memory.list",
            "memory.delete",
            "memory.status",
            "cron.list",
            "cron.create",
            "cron.delete",
            "cron.trigger",
            "timeline.query",
            "keys.list",
            "keys.set",
            "keys.delete",
            "config.set_inference_mode",
            "backup.trigger",
            "backup.list",
            "skills.list",
            "skills.toggle",
            "approval.respond",
            "timers.list",
            "timers.toggle",
            "plugins.status",
            "plugins.reload",
            "skills.metrics",
            "skills.config.get",
            "skills.config.set",
            "skills.resources.get",
            "skills.resources.set",
        ];
        for method in dispatch_methods {
            assert!(
                BUILTIN_RPC_METHODS.contains(&method),
                "dispatch method '{method}' missing from BUILTIN_RPC_METHODS"
            );
        }
    }

    #[tokio::test]
    async fn dispatch_method_calls_registered_handler() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![Box::new(MethodPlugin)];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();
        assert_eq!(pm.method_count(), 1);
        assert!(pm.has_method("custom.hello"));

        let result = pm
            .dispatch_method("custom.hello", serde_json::json!({}), "req-1")
            .await;
        assert!(result.is_some());
        match result.unwrap() {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-1");
                assert_eq!(result["hello"], "world");
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn optional_plugin_failure_tracks_failed_info() {
        let plugins: Vec<Box<dyn NativePlugin>> = vec![
            Box::new(FailingPlugin { required: false }),
            Box::new(NoopPlugin { required: false }),
        ];
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = PluginManager::initialize(plugins, &mut tr, &mut hr, HashMap::new())
            .await
            .unwrap();
        assert_eq!(pm.plugin_count(), 1); // noop loaded
        assert!(pm.is_degraded());
        let failed = pm.failed_plugins();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].id, "failing");
        assert!(
            failed[0].error.contains("intentional failure"),
            "got: {}",
            failed[0].error
        );
    }
}
