use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use encmind_agent::tool_registry::ToolRegistry;
use encmind_core::hooks::HookRegistry;

use crate::handlers::keys::refresh_llm_and_tool_registry_with_previous_plugins_under_lock;
use crate::plugin_manager::{PluginContext, PluginManager};
use crate::protocol::{ErrorPayload, ServerMessage, ERR_INTERNAL};
use crate::server::replace_native_plugin_timer_tasks;
use crate::state::AppState;
use tracing::warn;

fn append_plugins_reload_audit(state: &AppState, detail: serde_json::Value) {
    if let Err(e) = state.audit.append(
        "plugin",
        "plugins.reload",
        Some(&detail.to_string()),
        Some("admin"),
    ) {
        warn!(error = %e, "failed to append plugins.reload audit event");
    }
}

/// Handler for `plugins.status` — returns loaded plugin count, failures, and init timestamp.
pub async fn handle_status(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let (native_timers, native_timer_running_count) = {
        let runtime = state.native_plugin_timers.lock().await;
        let timers: Vec<serde_json::Value> = runtime
            .handles
            .iter()
            .map(|task| {
                let running = !task.handle.is_finished();
                serde_json::json!({
                    "plugin_id": task.plugin_id,
                    "timer_name": task.timer_name,
                    "running": running,
                })
            })
            .collect();
        let running_count = timers
            .iter()
            .filter(|timer| timer["running"].as_bool().unwrap_or(false))
            .count();
        (timers, running_count)
    };
    let plugin_manager = { state.plugin_manager.read().await.clone() };
    match plugin_manager {
        Some(pm) => {
            let failed: Vec<serde_json::Value> = pm
                .failed_plugins()
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "id": f.id,
                        "error": f.error,
                    })
                })
                .collect();
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({
                    "loaded_count": pm.plugin_count(),
                    "loaded": pm.plugin_ids(),
                    "failed": failed,
                    "initialized_at": pm.initialized_at(),
                    "plugin_degraded": pm.is_degraded(),
                    "native_timer_count": native_timers.len(),
                    "native_timer_running_count": native_timer_running_count,
                    "native_timers": native_timers,
                }),
            }
        }
        None => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({
                "loaded_count": 0,
                "loaded": [],
                "failed": [],
                "initialized_at": null,
                "plugin_degraded": false,
                "native_timer_count": native_timers.len(),
                "native_timer_running_count": native_timer_running_count,
                "native_timers": native_timers,
            }),
        },
    }
}

/// Handler for `plugins.reload` — rebuilds native plugin manager with current config
/// and refreshes runtime resources atomically (with rollback on failure).
pub async fn handle_reload(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    handle_reload_with_native_plugins_factory(state, params, req_id, |config_snapshot, state| {
        crate::server::build_native_plugins(
            config_snapshot,
            state.browser_pool.clone(),
            state.firewall.clone(),
        )
    })
    .await
}

async fn handle_reload_with_native_plugins_factory<F>(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
    build_native_plugins: F,
) -> ServerMessage
where
    F: FnOnce(
        &encmind_core::config::AppConfig,
        &AppState,
    ) -> Vec<Box<dyn encmind_core::plugin::NativePlugin>>,
{
    type ReloadStageOk = (
        Option<Arc<PluginManager>>,
        Vec<crate::plugin_api::RegisteredPluginTimer>,
    );
    type ReloadStageErr = (Option<Arc<PluginManager>>, String);

    let staged_outcome: Result<ReloadStageOk, ReloadStageErr> = {
        // Serialize reload against other refresh paths (keys.set/delete, mode
        // switches) so plugin manager swap + runtime refresh are atomic together.
        let _refresh_guard = state.refresh_lock.write().await;

        let config_snapshot = { state.config.read().await.clone() };
        let native_plugins = build_native_plugins(&config_snapshot, state);

        let new_manager = if native_plugins.is_empty() {
            None
        } else {
            let mut plugin_contexts: HashMap<String, PluginContext> = HashMap::new();
            for plugin in &native_plugins {
                let pid = plugin.manifest().id;
                plugin_contexts.insert(
                    pid.clone(),
                    PluginContext {
                        config: config_snapshot.plugins.get(&pid).cloned(),
                        state_store: Some(Arc::new(
                            encmind_storage::plugin_state::SqlitePluginStateStore::new(
                                state.db_pool.clone(),
                                &pid,
                            ),
                        )
                            as Arc<dyn encmind_core::plugin::PluginStateStore>),
                    },
                );
            }

            let mut staged_tools = ToolRegistry::new();
            let mut staged_hooks = HookRegistry::new();
            match PluginManager::initialize(
                native_plugins,
                &mut staged_tools,
                &mut staged_hooks,
                plugin_contexts,
            )
            .await
            {
                Ok(pm) => Some(Arc::new(pm)),
                Err(e) => {
                    let err_msg = format!("plugin reload failed: {e}");
                    append_plugins_reload_audit(
                        state,
                        serde_json::json!({
                            "reloaded": false,
                            "stage": "initialize",
                            "error": err_msg.clone(),
                        }),
                    );
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(ERR_INTERNAL, err_msg),
                    };
                }
            }
        };

        let previous_manager = { state.plugin_manager.read().await.clone() };
        let previous_plugin_ids: HashSet<String> = previous_manager
            .as_ref()
            .map(|pm| pm.plugin_ids().into_iter().collect())
            .unwrap_or_default();

        if let Err(e) = refresh_llm_and_tool_registry_with_previous_plugins_under_lock(
            state,
            new_manager.clone(),
            previous_plugin_ids,
        )
        .await
        {
            Err((
                new_manager,
                format!("plugin reload applied then rolled back: {e}"),
            ))
        } else {
            let new_native_timers = new_manager
                .as_ref()
                .map(|pm| pm.registered_timers().to_vec())
                .unwrap_or_default();
            // Publish new manager while refresh_lock is still held so concurrent
            // refresh paths always see a runtime + plugin-manager coherent pair.
            let replaced_manager = {
                let mut lock = state.plugin_manager.write().await;
                std::mem::replace(&mut *lock, new_manager.clone())
            };
            Ok((replaced_manager, new_native_timers))
        }
    };

    let (previous_manager, new_native_timers) = match staged_outcome {
        Ok(value) => value,
        Err((manager_to_shutdown, err_msg)) => {
            if let Some(pm) = manager_to_shutdown {
                pm.shutdown().await;
            }
            append_plugins_reload_audit(
                state,
                serde_json::json!({
                    "reloaded": false,
                    "stage": "refresh",
                    "error": err_msg.clone(),
                }),
            );
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, err_msg),
            };
        }
    };

    // Teardown/restart paths intentionally run after releasing refresh_lock.
    replace_native_plugin_timer_tasks(state, &new_native_timers).await;

    let previous_loaded = previous_manager
        .as_ref()
        .map(|pm| pm.plugin_ids())
        .unwrap_or_default();
    if let Some(pm) = previous_manager {
        pm.shutdown().await;
    }

    let plugin_manager = { state.plugin_manager.read().await.clone() };
    match plugin_manager {
        Some(pm) => {
            let failed: Vec<serde_json::Value> = pm
                .failed_plugins()
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "id": f.id,
                        "error": f.error,
                    })
                })
                .collect();
            let loaded_ids = pm.plugin_ids();
            let detail = serde_json::json!({
                "reloaded": true,
                "loaded_count": pm.plugin_count(),
                "loaded": loaded_ids,
                "failed_count": failed.len(),
                "previous_loaded": previous_loaded,
                "native_timer_count": new_native_timers.len(),
            });
            append_plugins_reload_audit(state, detail);
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({
                    "reloaded": true,
                    "loaded_count": pm.plugin_count(),
                    "loaded": pm.plugin_ids(),
                    "failed": failed,
                    "initialized_at": pm.initialized_at(),
                    "plugin_degraded": pm.is_degraded(),
                }),
            }
        }
        None => ServerMessage::Res {
            id: req_id.to_string(),
            result: {
                let detail = serde_json::json!({
                    "reloaded": true,
                    "loaded_count": 0,
                    "loaded": [],
                    "failed_count": 0,
                    "previous_loaded": previous_loaded,
                    "native_timer_count": new_native_timers.len(),
                });
                append_plugins_reload_audit(state, detail);
                serde_json::json!({
                    "reloaded": true,
                    "loaded_count": 0,
                    "loaded": [],
                    "failed": [],
                    "initialized_at": null,
                    "plugin_degraded": false,
                })
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::keys::refresh_llm_and_tool_registry;
    use crate::state::LoadedSkillSummary;
    use crate::test_utils::make_test_state;
    use encmind_agent::tool_registry::ToolRegistry;
    use encmind_core::error::PluginError;
    use encmind_core::hooks::{HookContext, HookHandler, HookPoint, HookRegistry, HookResult};
    use encmind_core::plugin::{NativePlugin, PluginKind, PluginManifest, PluginRegistrar};
    use encmind_storage::audit::AuditFilter;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    struct NoopHookHandler;
    #[async_trait::async_trait]
    impl HookHandler for NoopHookHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Continue)
        }
    }

    struct HookOnlyPlugin {
        id: &'static str,
    }
    #[async_trait::async_trait]
    impl NativePlugin for HookOnlyPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: self.id.into(),
                name: format!("{} plugin", self.id),
                version: "0.1.0".into(),
                description: "Registers only hooks".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            api.register_hook(HookPoint::BeforeToolCall, 0, Arc::new(NoopHookHandler))
        }
    }

    struct InitFailingPlugin;

    #[async_trait::async_trait]
    impl NativePlugin for InitFailingPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "init_failing".into(),
                name: "Init failing plugin".into(),
                version: "0.1.0".into(),
                description: "Fails registration during plugin manager initialize".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, _api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            Err(PluginError::RegistrationFailed(
                "intentional initialize-stage failure".into(),
            ))
        }
    }

    #[tokio::test]
    async fn status_reports_no_plugins_when_uninitialized() {
        let state = make_test_state();
        let resp = handle_status(&state, serde_json::json!({}), "req-status").await;
        match resp {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-status");
                assert_eq!(result["loaded_count"], 0);
                assert_eq!(result["plugin_degraded"], false);
                assert_eq!(result["native_timer_count"], 0);
                assert_eq!(result["native_timer_running_count"], 0);
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn status_reports_native_timer_runtime_health() {
        let state = make_test_state();
        {
            let mut runtime = state.native_plugin_timers.lock().await;
            runtime.cancel = CancellationToken::new();
            runtime.handles = vec![crate::state::NativePluginTimerHandle {
                plugin_id: "native-plugin".to_string(),
                timer_name: "heartbeat".to_string(),
                handle: tokio::spawn(async {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }),
            }];
        }

        let resp = handle_status(&state, serde_json::json!({}), "req-status-timer").await;
        match resp {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-status-timer");
                assert_eq!(result["native_timer_count"], 1);
                assert_eq!(result["native_timer_running_count"], 1);
                assert_eq!(result["native_timers"][0]["plugin_id"], "native-plugin");
                assert_eq!(result["native_timers"][0]["timer_name"], "heartbeat");
                assert_eq!(result["native_timers"][0]["running"], true);
            }
            other => panic!("expected Res, got {other:?}"),
        }

        crate::server::replace_native_plugin_timer_tasks(&state, &[]).await;
    }

    #[tokio::test]
    async fn reload_succeeds_when_no_native_plugins_configured() {
        let state = make_test_state();
        let resp = handle_reload(&state, serde_json::json!({}), "req-reload").await;
        match resp {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-reload");
                assert_eq!(result["reloaded"], true);
                assert_eq!(result["loaded_count"], 0);
                assert_eq!(result["plugin_degraded"], false);
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reload_waits_for_refresh_lock() {
        let state = make_test_state();
        let refresh_guard = state.refresh_lock.write().await;

        let state_for_task = state.clone();
        let task = tokio::spawn(async move {
            handle_reload(&state_for_task, serde_json::json!({}), "req-reload-lock").await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "plugins.reload should block while refresh_lock is held"
        );

        drop(refresh_guard);
        let resp = task.await.unwrap();
        match resp {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-reload-lock");
                assert_eq!(result["reloaded"], true);
            }
            other => panic!("expected Res, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reload_replaces_native_plugin_timer_tasks() {
        struct CountingTimer {
            ticks: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl encmind_core::plugin::NativePluginTimer for CountingTimer {
            fn name(&self) -> &str {
                "heartbeat"
            }

            async fn tick(&self) -> Result<(), PluginError> {
                self.ticks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let state = make_test_state();
        let ticks = Arc::new(AtomicUsize::new(0));
        let timers = vec![crate::plugin_api::RegisteredPluginTimer {
            plugin_id: "native-plugin-a".to_string(),
            name: "heartbeat-a".to_string(),
            interval_secs: 1,
            handler: Arc::new(CountingTimer {
                ticks: ticks.clone(),
            }),
        }];

        crate::server::replace_native_plugin_timer_tasks(&state, &timers).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            ticks.load(Ordering::SeqCst) >= 1,
            "pre-reload native timer should be running"
        );

        let resp = handle_reload(&state, serde_json::json!({}), "req-reload-timer").await;
        match resp {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-reload-timer");
                assert_eq!(result["reloaded"], true);
            }
            other => panic!("expected Res, got {other:?}"),
        }

        let after_reload = ticks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after_reload,
            "reload should stop prior native plugin timer tasks when no timers are configured"
        );
    }

    #[tokio::test]
    async fn reload_emits_audit_event() {
        let state = make_test_state();
        let resp = handle_reload(&state, serde_json::json!({}), "req-reload-audit").await;
        match resp {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-reload-audit");
                assert_eq!(result["reloaded"], true);
            }
            other => panic!("expected Res, got {other:?}"),
        }

        let entries = state
            .audit
            .query(
                AuditFilter {
                    category: Some("plugin".into()),
                    action: Some("plugins.reload".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source.as_deref(), Some("admin"));
        let detail = entries[0]
            .detail
            .as_ref()
            .expect("plugins.reload audit detail should exist");
        let detail_json: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(detail_json["reloaded"], true);
        assert!(detail_json["loaded_count"].is_number());
    }

    #[tokio::test]
    async fn reload_failure_emits_audit_event() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(LoadedSkillSummary {
                id: "dummy-skill".into(),
                version: "0.1.0".into(),
                description: "dummy".into(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        {
            let mut cfg = state.config.write().await;
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos();
            cfg.skills.wasm_dir = std::path::PathBuf::from(format!(
                "/tmp/encmind-missing-skills-{}-{nonce}",
                std::process::id(),
            ));
        }

        let resp = handle_reload(&state, serde_json::json!({}), "req-reload-audit-fail").await;
        match resp {
            ServerMessage::Error { id, .. } => {
                assert_eq!(id.as_deref(), Some("req-reload-audit-fail"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let entries = state
            .audit
            .query(
                AuditFilter {
                    category: Some("plugin".into()),
                    action: Some("plugins.reload".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 1);
        let detail = entries[0]
            .detail
            .as_ref()
            .expect("plugins.reload audit detail should exist");
        let detail_json: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(detail_json["reloaded"], false);
        assert_eq!(detail_json["stage"], "refresh");
        assert!(detail_json["error"].is_string());
    }

    #[tokio::test]
    async fn reload_initialize_failure_emits_audit_event() {
        let state = make_test_state();
        let resp = handle_reload_with_native_plugins_factory(
            &state,
            serde_json::json!({}),
            "req-reload-audit-init-fail",
            |_config, _state| vec![Box::new(InitFailingPlugin)],
        )
        .await;
        match resp {
            ServerMessage::Error { id, .. } => {
                assert_eq!(id.as_deref(), Some("req-reload-audit-init-fail"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let entries = state
            .audit
            .query(
                AuditFilter {
                    category: Some("plugin".into()),
                    action: Some("plugins.reload".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 1);
        let detail = entries[0]
            .detail
            .as_ref()
            .expect("plugins.reload audit detail should exist");
        let detail_json: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(detail_json["reloaded"], false);
        assert_eq!(detail_json["stage"], "initialize");
        assert!(detail_json["error"].is_string());
    }

    #[tokio::test]
    async fn reload_publishes_plugin_manager_before_unlock_for_concurrent_refresh() {
        let state = make_test_state();

        let mut old_tools = ToolRegistry::new();
        let mut old_hooks = HookRegistry::new();
        let old_pm = crate::plugin_manager::PluginManager::initialize(
            vec![Box::new(HookOnlyPlugin {
                id: "old_plugin_hook",
            })],
            &mut old_tools,
            &mut old_hooks,
            HashMap::new(),
        )
        .await
        .unwrap();

        {
            let mut manager = state.plugin_manager.write().await;
            *manager = Some(Arc::new(old_pm));
        }
        {
            let mut hooks = state.hook_registry.write().await;
            *hooks = old_hooks;
        }

        // Inject a slow timer task so reload spends time after releasing refresh_lock.
        // This widens the window where a concurrent refresh could observe stale manager
        // state if manager swap happened too late.
        {
            let mut timers = state.native_plugin_timers.lock().await;
            timers.cancel = CancellationToken::new();
            timers.handles = vec![crate::state::NativePluginTimerHandle {
                plugin_id: "old_plugin_hook".to_string(),
                timer_name: "slow-teardown".to_string(),
                handle: tokio::spawn(async {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }),
            }];
        }

        let reload_state = state.clone();
        let reload_task = tokio::spawn(async move {
            handle_reload(&reload_state, serde_json::json!({}), "req-reload-coherence").await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        refresh_llm_and_tool_registry(&state)
            .await
            .expect("concurrent refresh should succeed");

        match reload_task.await.unwrap() {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-reload-coherence");
                assert_eq!(result["reloaded"], true);
            }
            other => panic!("expected Res, got {other:?}"),
        }

        let hook_ids = state.hook_registry.read().await.registered_plugin_ids();
        assert!(
            !hook_ids.contains("old_plugin_hook"),
            "concurrent refresh must not reintroduce hooks from pre-reload manager"
        );
        assert!(
            state.plugin_manager.read().await.is_none(),
            "reload with no configured native plugins should publish empty manager"
        );
    }
}
