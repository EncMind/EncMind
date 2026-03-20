use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::PluginError;
use crate::types::*;

const MAX_CUSTOM_EVENT_DEPTH: u8 = 4;

tokio::task_local! {
    static CUSTOM_EVENT_DEPTH: Cell<u8>;
}

/// Hook points in the gateway lifecycle where plugins can intercept processing.
/// Phase 1 ships this minimal set. Additional points are added in later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPoint {
    OnStartup,
    OnShutdown,
    BeforeAgentStart,
    AfterAgentComplete,
    BeforeToolCall,
    AfterToolCall,
    OnMessageReceived,
    OnMessageSending,
    /// Custom event emitted by a WASM skill.
    CustomEvent,
}

/// Context passed to hook handlers.
pub struct HookContext {
    pub session_id: Option<SessionId>,
    pub agent_id: Option<AgentId>,
    pub method: Option<String>,
    pub payload: serde_json::Value,
}

/// Result of a hook execution.
#[derive(Debug)]
pub enum HookResult {
    /// Proceed normally.
    Continue,
    /// Replace payload with an override value.
    Override(serde_json::Value),
    /// Stop processing with a reason.
    Abort { reason: String },
}

/// Trait implemented by hook handlers (both native and WASM-backed).
#[async_trait]
pub trait HookHandler: Send + Sync {
    async fn execute(&self, ctx: &mut HookContext) -> Result<HookResult, PluginError>;
}

/// A hook handler with priority and metadata.
#[derive(Clone)]
pub struct PrioritizedHook {
    pub priority: i32,
    pub plugin_id: String,
    pub handler: Arc<dyn HookHandler>,
    pub timeout_ms: u64,
}

/// Registry of hook handlers, organized by hook point.
#[derive(Clone)]
pub struct HookRegistry {
    hooks: HashMap<HookPoint, Vec<PrioritizedHook>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }

    /// Register a hook handler at the given point.
    pub fn register(
        &mut self,
        point: HookPoint,
        priority: i32,
        plugin_id: &str,
        handler: Arc<dyn HookHandler>,
        timeout_ms: u64,
    ) -> Result<(), PluginError> {
        let entry = self.hooks.entry(point).or_default();
        entry.push(PrioritizedHook {
            priority,
            plugin_id: plugin_id.to_string(),
            handler,
            timeout_ms,
        });
        // Sort by descending priority, then stable by plugin_id
        entry.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.plugin_id.cmp(&b.plugin_id))
        });
        Ok(())
    }

    /// Execute all hooks at the given point in priority order.
    ///
    /// Hooks receive a mutable `HookContext` and execute in priority order.
    /// Each hook can read and modify the context; subsequent hooks observe
    /// modifications made by earlier hooks (chain-of-responsibility pattern).
    ///
    /// Returns the first `Override` or `Abort` encountered, or `Continue` if
    /// all hooks pass.
    pub async fn execute(
        &self,
        point: HookPoint,
        ctx: &mut HookContext,
    ) -> Result<HookResult, PluginError> {
        let Some(hooks) = self.hooks.get(&point) else {
            return Ok(HookResult::Continue);
        };

        if point == HookPoint::CustomEvent {
            return execute_custom_event_with_depth_guard(hooks, ctx).await;
        }

        execute_hook_chain(point, hooks, ctx).await
    }

    /// Return the number of registered hooks across all points.
    pub fn total_hooks(&self) -> usize {
        self.hooks.values().map(|v| v.len()).sum()
    }

    /// Return the set of plugin IDs that currently have registered hooks.
    pub fn registered_plugin_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for handlers in self.hooks.values() {
            for handler in handlers {
                ids.insert(handler.plugin_id.clone());
            }
        }
        ids
    }

    /// Remove all hooks whose `plugin_id` is in `plugin_ids`.
    ///
    /// Returns the number of removed hook handlers.
    pub fn unregister_plugins(&mut self, plugin_ids: &HashSet<String>) -> usize {
        if plugin_ids.is_empty() {
            return 0;
        }

        let mut removed = 0usize;
        self.hooks.retain(|_point, handlers| {
            let before = handlers.len();
            handlers.retain(|h| !plugin_ids.contains(&h.plugin_id));
            removed += before.saturating_sub(handlers.len());
            !handlers.is_empty()
        });
        removed
    }
}

async fn execute_custom_event_with_depth_guard(
    hooks: &[PrioritizedHook],
    ctx: &mut HookContext,
) -> Result<HookResult, PluginError> {
    match CUSTOM_EVENT_DEPTH.try_with(|depth| depth.get()) {
        Ok(depth) => {
            if depth >= MAX_CUSTOM_EVENT_DEPTH {
                return Ok(HookResult::Abort {
                    reason: format!(
                        "maximum custom event hook depth exceeded ({MAX_CUSTOM_EVENT_DEPTH})"
                    ),
                });
            }
            CUSTOM_EVENT_DEPTH.with(|d| d.set(depth + 1));
            let result = execute_hook_chain(HookPoint::CustomEvent, hooks, ctx).await;
            CUSTOM_EVENT_DEPTH.with(|d| d.set(depth));
            result
        }
        Err(_) => {
            CUSTOM_EVENT_DEPTH
                .scope(Cell::new(1), async {
                    execute_hook_chain(HookPoint::CustomEvent, hooks, ctx).await
                })
                .await
        }
    }
}

async fn execute_hook_chain(
    point: HookPoint,
    hooks: &[PrioritizedHook],
    ctx: &mut HookContext,
) -> Result<HookResult, PluginError> {
    for hook in hooks {
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(hook.timeout_ms),
            hook.handler.execute(ctx),
        )
        .await;

        match result {
            Ok(Ok(HookResult::Continue)) => continue,
            Ok(Ok(other)) => return Ok(other),
            Ok(Err(e)) => {
                if is_fail_closed(point) {
                    return Ok(HookResult::Abort {
                        reason: format!("hook error from plugin '{}': {}", hook.plugin_id, e),
                    });
                }
                // fail-open: log warning and continue
                tracing::warn!(
                    plugin = %hook.plugin_id,
                    hook_point = ?point,
                    error = %e,
                    "hook error (fail-open); continuing"
                );
            }
            Err(_timeout) => {
                if is_fail_closed(point) {
                    return Ok(HookResult::Abort {
                        reason: format!(
                            "hook timeout from plugin '{}' ({}ms)",
                            hook.plugin_id, hook.timeout_ms
                        ),
                    });
                }
                tracing::warn!(
                    plugin = %hook.plugin_id,
                    hook_point = ?point,
                    timeout_ms = hook.timeout_ms,
                    "hook timeout (fail-open); continuing"
                );
            }
        }
    }

    Ok(HookResult::Continue)
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Safety-critical hook points use fail-closed policy (timeout/error → Abort).
fn is_fail_closed(point: HookPoint) -> bool {
    matches!(
        point,
        HookPoint::BeforeToolCall | HookPoint::BeforeAgentStart
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    struct PassHandler;
    #[async_trait]
    impl HookHandler for PassHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Continue)
        }
    }

    struct AbortHandler {
        reason: String,
    }
    #[async_trait]
    impl HookHandler for AbortHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Abort {
                reason: self.reason.clone(),
            })
        }
    }

    struct OverrideHandler {
        value: serde_json::Value,
    }
    #[async_trait]
    impl HookHandler for OverrideHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Override(self.value.clone()))
        }
    }

    struct ErrorHandler;
    #[async_trait]
    impl HookHandler for ErrorHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Err(PluginError::RegistrationFailed("boom".into()))
        }
    }

    struct SlowHandler;
    #[async_trait]
    impl HookHandler for SlowHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            Ok(HookResult::Continue)
        }
    }

    struct RecursiveCustomEventHandler {
        registry: Arc<OnceLock<Arc<HookRegistry>>>,
    }
    #[async_trait]
    impl HookHandler for RecursiveCustomEventHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            let registry = self
                .registry
                .get()
                .expect("recursive test registry must be initialized");
            let mut nested_ctx = HookContext {
                session_id: None,
                agent_id: None,
                method: Some("skill_event:recursive".into()),
                payload: serde_json::json!({"type": "recursive"}),
            };
            registry
                .execute(HookPoint::CustomEvent, &mut nested_ctx)
                .await
        }
    }

    fn test_ctx() -> HookContext {
        HookContext {
            session_id: None,
            agent_id: None,
            method: None,
            payload: serde_json::Value::Null,
        }
    }

    #[test]
    fn new_registry_has_no_hooks() {
        let reg = HookRegistry::new();
        assert_eq!(reg.total_hooks(), 0);
    }

    #[test]
    fn register_single_hook() {
        let mut reg = HookRegistry::new();
        reg.register(HookPoint::OnStartup, 0, "test", Arc::new(PassHandler), 5000)
            .unwrap();
        assert_eq!(reg.total_hooks(), 1);
    }

    #[test]
    fn unregister_plugins_removes_only_matching_hooks() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::BeforeToolCall,
            0,
            "skill-a",
            Arc::new(PassHandler),
            5000,
        )
        .unwrap();
        reg.register(
            HookPoint::BeforeToolCall,
            0,
            "native",
            Arc::new(PassHandler),
            5000,
        )
        .unwrap();
        reg.register(
            HookPoint::OnMessageSending,
            0,
            "skill-a",
            Arc::new(PassHandler),
            5000,
        )
        .unwrap();
        assert_eq!(reg.total_hooks(), 3);

        let mut ids = HashSet::new();
        ids.insert("skill-a".to_string());
        let removed = reg.unregister_plugins(&ids);
        assert_eq!(removed, 2);
        assert_eq!(reg.total_hooks(), 1);

        // Remaining hook is from `native` plugin.
        let remaining = reg
            .hooks
            .get(&HookPoint::BeforeToolCall)
            .unwrap()
            .iter()
            .map(|h| h.plugin_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec!["native".to_string()]);
    }

    #[test]
    fn register_multiple_with_priority_ordering() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::BeforeToolCall,
            10,
            "low",
            Arc::new(PassHandler),
            5000,
        )
        .unwrap();
        reg.register(
            HookPoint::BeforeToolCall,
            100,
            "high",
            Arc::new(PassHandler),
            5000,
        )
        .unwrap();
        let hooks = reg.hooks.get(&HookPoint::BeforeToolCall).unwrap();
        assert_eq!(hooks[0].plugin_id, "high");
        assert_eq!(hooks[1].plugin_id, "low");
    }

    #[tokio::test]
    async fn execute_single_continue() {
        let mut reg = HookRegistry::new();
        reg.register(HookPoint::OnStartup, 0, "test", Arc::new(PassHandler), 5000)
            .unwrap();
        let mut ctx = test_ctx();
        let result = reg.execute(HookPoint::OnStartup, &mut ctx).await.unwrap();
        assert!(matches!(result, HookResult::Continue));
    }

    #[tokio::test]
    async fn execute_chain_with_abort_stops_propagation() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::OnMessageReceived,
            100,
            "first",
            Arc::new(AbortHandler {
                reason: "blocked".into(),
            }),
            5000,
        )
        .unwrap();
        reg.register(
            HookPoint::OnMessageReceived,
            0,
            "second",
            Arc::new(PassHandler),
            5000,
        )
        .unwrap();
        let mut ctx = test_ctx();
        let result = reg
            .execute(HookPoint::OnMessageReceived, &mut ctx)
            .await
            .unwrap();
        match result {
            HookResult::Abort { reason } => assert_eq!(reason, "blocked"),
            _ => panic!("expected Abort"),
        }
    }

    #[tokio::test]
    async fn execute_chain_with_override() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::OnMessageSending,
            100,
            "modifier",
            Arc::new(OverrideHandler {
                value: serde_json::json!({"modified": true}),
            }),
            5000,
        )
        .unwrap();
        let mut ctx = test_ctx();
        let result = reg
            .execute(HookPoint::OnMessageSending, &mut ctx)
            .await
            .unwrap();
        match result {
            HookResult::Override(v) => assert_eq!(v["modified"], true),
            _ => panic!("expected Override"),
        }
    }

    #[tokio::test]
    async fn empty_hook_point_returns_continue() {
        let reg = HookRegistry::new();
        let mut ctx = test_ctx();
        let result = reg.execute(HookPoint::OnShutdown, &mut ctx).await.unwrap();
        assert!(matches!(result, HookResult::Continue));
    }

    #[tokio::test]
    async fn error_on_fail_closed_hook_returns_abort() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::BeforeToolCall,
            0,
            "buggy",
            Arc::new(ErrorHandler),
            5000,
        )
        .unwrap();
        let mut ctx = test_ctx();
        let result = reg
            .execute(HookPoint::BeforeToolCall, &mut ctx)
            .await
            .unwrap();
        match result {
            HookResult::Abort { reason } => {
                assert!(reason.contains("buggy"));
                assert!(reason.contains("boom"));
            }
            _ => panic!("expected Abort on fail-closed hook error"),
        }
    }

    #[tokio::test]
    async fn error_on_fail_open_hook_continues() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::OnMessageSending,
            0,
            "buggy",
            Arc::new(ErrorHandler),
            5000,
        )
        .unwrap();
        let mut ctx = test_ctx();
        let result = reg
            .execute(HookPoint::OnMessageSending, &mut ctx)
            .await
            .unwrap();
        assert!(matches!(result, HookResult::Continue));
    }

    #[tokio::test]
    async fn timeout_on_fail_closed_hook_returns_abort() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::BeforeAgentStart,
            0,
            "slow",
            Arc::new(SlowHandler),
            50, // 50ms timeout — handler sleeps 10s
        )
        .unwrap();
        let mut ctx = test_ctx();
        let result = reg
            .execute(HookPoint::BeforeAgentStart, &mut ctx)
            .await
            .unwrap();
        match result {
            HookResult::Abort { reason } => assert!(reason.contains("timeout")),
            _ => panic!("expected Abort on timeout"),
        }
    }

    #[tokio::test]
    async fn timeout_on_fail_open_hook_continues() {
        let mut reg = HookRegistry::new();
        reg.register(
            HookPoint::OnMessageSending,
            0,
            "slow",
            Arc::new(SlowHandler),
            50,
        )
        .unwrap();
        let mut ctx = test_ctx();
        let result = reg
            .execute(HookPoint::OnMessageSending, &mut ctx)
            .await
            .unwrap();
        assert!(matches!(result, HookResult::Continue));
    }

    #[tokio::test]
    async fn custom_event_depth_guard_aborts_recursive_emit() {
        let registry_holder: Arc<OnceLock<Arc<HookRegistry>>> = Arc::new(OnceLock::new());
        let mut registry = HookRegistry::new();
        registry
            .register(
                HookPoint::CustomEvent,
                0,
                "recursive",
                Arc::new(RecursiveCustomEventHandler {
                    registry: registry_holder.clone(),
                }),
                5000,
            )
            .unwrap();
        let registry = Arc::new(registry);
        assert!(registry_holder.set(registry.clone()).is_ok());

        let mut ctx = HookContext {
            session_id: None,
            agent_id: None,
            method: Some("skill_event:recursive".into()),
            payload: serde_json::json!({"type": "recursive"}),
        };
        let result = registry
            .execute(HookPoint::CustomEvent, &mut ctx)
            .await
            .unwrap();

        match result {
            HookResult::Abort { reason } => {
                assert!(reason.contains("maximum custom event hook depth exceeded"));
            }
            other => panic!("expected Abort, got {other:?}"),
        }
    }

    #[test]
    fn hook_context_construction() {
        let ctx = HookContext {
            session_id: Some(SessionId::from_string("s1")),
            agent_id: Some(AgentId::new("main")),
            method: Some("chat.send".into()),
            payload: serde_json::json!({"text": "hello"}),
        };
        assert_eq!(ctx.session_id.unwrap().as_str(), "s1");
        assert_eq!(ctx.agent_id.unwrap().as_str(), "main");
        assert_eq!(ctx.method.unwrap(), "chat.send");
    }

    #[test]
    fn hook_point_variants_are_distinct() {
        let points = [
            HookPoint::OnStartup,
            HookPoint::OnShutdown,
            HookPoint::BeforeAgentStart,
            HookPoint::AfterAgentComplete,
            HookPoint::BeforeToolCall,
            HookPoint::AfterToolCall,
            HookPoint::OnMessageReceived,
            HookPoint::OnMessageSending,
            HookPoint::CustomEvent,
        ];
        for (i, a) in points.iter().enumerate() {
            for (j, b) in points.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
