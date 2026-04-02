use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use encmind_core::config::{AppConfig, InferenceMode};
use encmind_core::traits::ApiKeyStore;
use tracing::{info, warn};

use crate::plugin_manager::PluginManager;
use crate::protocol::*;
use crate::server::{
    build_skill_timer_limits, build_skill_timer_runtime_specs, build_timer_reconcile_data,
    build_transform_chains, initialize_tool_registry, load_wasm_skills_refresh,
    rebuild_llm_backend,
};
use crate::skill_timer::reconcile_all_timers;
use crate::state::AppState;

fn canonical_provider_name(config: &AppConfig, provider_input: &str) -> Option<String> {
    config
        .llm
        .api_providers
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(provider_input))
        .map(|p| p.name.clone())
}

/// Refresh the LLM backend, tool registry, transform chains, and skill timers.
/// Uses build→validate→commit pattern under the refresh_lock to ensure atomicity.
pub(crate) async fn refresh_llm_and_tool_registry(state: &AppState) -> Result<(), String> {
    // Serialize concurrent refreshes.
    let _refresh_guard = state.refresh_lock.write().await;
    let plugin_manager = { state.plugin_manager.read().await.clone() };
    refresh_llm_and_tool_registry_inner(state, plugin_manager, None).await
}

/// Refresh runtime state while the caller already holds `refresh_lock`.
///
/// This exists for `plugins.reload`, which must atomically swap plugin manager
/// plus refresh runtime under the same lock to avoid races with other refresh
/// paths.
pub(crate) async fn refresh_llm_and_tool_registry_with_previous_plugins_under_lock(
    state: &AppState,
    plugin_manager_for_refresh: Option<Arc<PluginManager>>,
    previous_native_plugin_ids: HashSet<String>,
) -> Result<(), String> {
    refresh_llm_and_tool_registry_inner(
        state,
        plugin_manager_for_refresh,
        Some(previous_native_plugin_ids),
    )
    .await
}

async fn refresh_llm_and_tool_registry_inner(
    state: &AppState,
    plugin_manager: Option<Arc<PluginManager>>,
    previous_native_plugin_ids: Option<HashSet<String>>,
) -> Result<(), String> {
    // ---- BUILD PHASE ----
    let config_snapshot = { state.config.read().await.clone() };
    let new_backend = rebuild_llm_backend(&config_snapshot, state.api_key_store.clone()).await;
    let mut new_tool_registry = initialize_tool_registry(
        &config_snapshot,
        &new_backend,
        state.session_store.clone(),
        state.agent_registry.clone(),
        state.agent_pool.clone(),
        state.firewall.clone(),
        state.browser_pool.clone(),
        Some(state.node_registry.clone()),
        Some(state.device_store.clone()),
        Some(state.config.clone()),
    );
    if let Some(pm) = plugin_manager.as_ref() {
        if let Err(e) = pm.register_tools(&mut new_tool_registry).await {
            warn!(
                error = %e,
                "failed to re-register plugin tools; keeping previous runtime"
            );
            return Err(format!("failed to re-register plugin tools: {e}"));
        }
    }

    // Stage a hook registry rebuild:
    // 1) start from current hooks,
    // 2) remove previously loaded WASM skill hooks,
    // 3) remove previous native plugin hooks,
    // 4) replay current native plugin hooks,
    // 5) let skill loader register currently enabled WASM skill hooks.
    let previous_skill_ids: HashSet<String> = {
        let loaded = state.loaded_skills.read().await;
        loaded.iter().map(|s| format!("skill:{}", s.id)).collect()
    };
    let mut staged_hook_registry = { state.hook_registry.read().await.clone() };
    let removed_skill_hooks = staged_hook_registry.unregister_plugins(&previous_skill_ids);
    let native_plugin_ids_to_remove: HashSet<String> = match previous_native_plugin_ids {
        Some(ids) => ids,
        None => plugin_manager
            .as_ref()
            .map(|pm| pm.plugin_ids().into_iter().collect())
            .unwrap_or_default(),
    };
    let removed_native_hooks =
        staged_hook_registry.unregister_plugins(&native_plugin_ids_to_remove);
    info!(
        removed_skill_hooks,
        removed_native_hooks,
        native_plugin_ids = native_plugin_ids_to_remove.len(),
        "staged hook registry cleanup complete"
    );
    if let Some(pm) = plugin_manager.as_ref() {
        let replay_hook_count = pm.hook_count();
        if let Err(e) = pm.register_hooks(&mut staged_hook_registry).await {
            warn!(
                error = %e,
                "failed to re-register plugin hooks; keeping previous runtime"
            );
            return Err(format!("failed to re-register plugin hooks: {e}"));
        }
        info!(
            replay_hook_count,
            plugin_count = pm.plugin_count(),
            "replayed native plugin hooks into staged hook registry"
        );
    }

    // Re-register WASM skill tools and hooks into rebuilt runtime state.
    let skills_dir = crate::server::resolve_skills_dir(&config_snapshot);
    let previously_loaded_skill_count = { state.loaded_skills.read().await.len() };
    if previously_loaded_skill_count > 0 && !skills_dir.exists() {
        return Err(format!(
            "failed to reload WASM skills: skills directory missing at {}",
            skills_dir.display()
        ));
    }

    let loaded_wasm = load_wasm_skills_refresh(
        &config_snapshot,
        &skills_dir,
        &mut new_tool_registry,
        state.session_store.clone(),
        Some(&mut staged_hook_registry),
        Arc::new(state.db_pool.clone()),
        state.firewall.clone(),
        state.wasm_http_client.clone(),
        state.pending_approvals.clone(),
        state.hook_registry.clone(),
        state.skill_toggle_store.clone(),
        Some(state.audit.clone()),
        state.skill_metrics.clone(),
    )
    .await
    .map_err(|e| format!("failed to reload WASM skills: {e}"))?;

    let outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy> =
        Arc::new(crate::server::GatewayOutboundPolicy {
            firewall: state.firewall.clone(),
        });
    let approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter> =
        Arc::new(crate::server::GatewayApprovalPrompter {
            pending_approvals: state.pending_approvals.clone(),
        });
    let new_transforms: HashMap<String, encmind_channels::transform::TransformChain> = {
        let native_transforms = plugin_manager
            .as_ref()
            .map(|pm| pm.registered_transforms().to_vec())
            .unwrap_or_default();
        build_transform_chains(
            &config_snapshot,
            &loaded_wasm.runtime_specs,
            &native_transforms,
            state.db_pool.clone(),
            state.wasm_http_client.clone(),
            state.hook_registry.clone(),
            outbound_policy,
            approval_prompter,
            state.audit.clone(),
        )
    };
    let timer_data = build_timer_reconcile_data(&loaded_wasm.runtime_specs);
    let runner_limits = build_skill_timer_limits(&loaded_wasm.runtime_specs);
    let runner_specs = build_skill_timer_runtime_specs(&loaded_wasm.runtime_specs);

    // ---- VALIDATE PHASE ----
    // All build steps succeeded if we reach here. If any had failed, we returned
    // Err above and the existing runtime is untouched.

    // ---- COMMIT PHASE (ordered, non-fallible swaps) ----

    // 1. Reconcile timers in DB (durable, idempotent — safe to commit first)
    if let Some(ref timer_store) = state.skill_timer_store {
        if let Err(e) = reconcile_all_timers(timer_store.as_ref(), &timer_data).await {
            warn!(error = %e, "timer reconciliation failed during refresh");
            // Non-fatal: timer state may be stale but runtime is still valid
        }
    }
    if let Some(ref timer_runner) = state.skill_timer_runner {
        timer_runner.set_skill_limits(runner_limits).await;
        timer_runner.set_skill_runtime_specs(runner_specs).await;
    }

    // 2. Swap tool registry
    let mut runtime = state.runtime.write().await;
    runtime.llm_backend = new_backend;
    runtime.tool_registry = Arc::new(new_tool_registry);
    drop(runtime);

    // 3. Swap transform chains
    let mut transforms = state.channel_transforms.write().await;
    *transforms = new_transforms;
    drop(transforms);

    // 4. Swap hook registry
    let mut hooks = state.hook_registry.write().await;
    *hooks = staged_hook_registry;
    drop(hooks);

    // 5. Swap API-facing metadata
    let retained_skill_ids: HashSet<String> =
        loaded_wasm.summaries.iter().map(|s| s.id.clone()).collect();

    let mut skills = state.loaded_skills.write().await;
    *skills = loaded_wasm.summaries;
    drop(skills);

    let mut known_ids = state.known_skill_ids.write().await;
    *known_ids = loaded_wasm.known_skill_ids;
    drop(known_ids);

    // 6. Prune stale in-memory metrics for skills no longer loaded.
    let mut metrics = state.skill_metrics.write().await;
    metrics.retain(|skill_id, _| retained_skill_ids.contains(skill_id));
    Ok(())
}

async fn restore_provider_key(
    api_key_store: &Arc<dyn ApiKeyStore>,
    provider: &str,
    previous_key: Option<String>,
) -> Result<(), String> {
    match previous_key {
        Some(key) => api_key_store
            .set_key(provider, &key)
            .await
            .map_err(|e| format!("failed to restore previous key: {e}")),
        None => api_key_store
            .delete_key(provider)
            .await
            .map_err(|e| format!("failed to restore missing-key state: {e}")),
    }
}

pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let api_key_store = match &state.api_key_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "key store not configured"),
            };
        }
    };

    match api_key_store.list_keys().await {
        Ok(records) => {
            let keys: Vec<serde_json::Value> = records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "provider": r.provider,
                        "created_at": r.created_at.to_rfc3339(),
                        "updated_at": r.updated_at.to_rfc3339(),
                    })
                })
                .collect();
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({ "keys": keys }),
            }
        }
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        },
    }
}

pub async fn handle_set(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let api_key_store = match &state.api_key_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "key store not configured"),
            };
        }
    };

    let provider_input = match params.get("provider").and_then(|v| v.as_str()) {
        Some(p) => p.trim(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "provider is required"),
            };
        }
    };

    if provider_input.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "provider is required"),
        };
    }

    let api_key = match params.get("api_key").and_then(|v| v.as_str()) {
        Some(k) => k.trim(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "api_key is required"),
            };
        }
    };

    if api_key.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "api_key must not be empty"),
        };
    }

    let provider = {
        let config = state.config.read().await;
        match canonical_provider_name(&config, provider_input) {
            Some(name) => name,
            None => {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown provider: {provider_input}"),
                    ),
                };
            }
        }
    };

    let previous_key = match api_key_store.get_key(&provider).await {
        Ok(key) => key,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    if let Err(e) = api_key_store.set_key(&provider, api_key).await {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        };
    }

    // Rebuild runtime state with the new key.
    if let Err(refresh_err) = refresh_llm_and_tool_registry(state).await {
        if let Err(rollback_err) =
            restore_provider_key(api_key_store, &provider, previous_key.clone()).await
        {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INTERNAL,
                    format!(
                        "runtime refresh failed: {refresh_err}; rollback failed: {rollback_err}"
                    ),
                ),
            };
        }
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INTERNAL,
                format!("runtime refresh failed; key change rolled back: {refresh_err}"),
            ),
        };
    }

    let _ = state
        .audit
        .append("keys", "set", Some(provider.as_str()), None);

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "provider": provider,
            "status": "stored",
        }),
    }
}

pub async fn handle_delete(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let api_key_store = match &state.api_key_store {
        Some(store) => store,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "key store not configured"),
            };
        }
    };

    let provider_input = match params.get("provider").and_then(|v| v.as_str()) {
        Some(p) => p.trim(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "provider is required"),
            };
        }
    };

    if provider_input.is_empty() {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "provider is required"),
        };
    }

    let provider = {
        let config = state.config.read().await;
        // Allow deleting keys for providers that are no longer present in
        // current config to support cleanup after provider rename/removal.
        canonical_provider_name(&config, provider_input)
            .unwrap_or_else(|| provider_input.to_owned())
    };

    let previous_key = match api_key_store.get_key(&provider).await {
        Ok(key) => key,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    if let Err(e) = api_key_store.delete_key(&provider).await {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        };
    }

    // Rebuild runtime state without the deleted key.
    if let Err(refresh_err) = refresh_llm_and_tool_registry(state).await {
        if let Err(rollback_err) =
            restore_provider_key(api_key_store, &provider, previous_key).await
        {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INTERNAL,
                    format!(
                        "runtime refresh failed: {refresh_err}; rollback failed: {rollback_err}"
                    ),
                ),
            };
        }
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INTERNAL,
                format!("runtime refresh failed; delete rolled back: {refresh_err}"),
            ),
        };
    }

    let _ = state
        .audit
        .append("keys", "delete", Some(provider.as_str()), None);

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "provider": provider,
            "status": "deleted",
        }),
    }
}

pub async fn handle_set_mode(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let mode_str = match params.get("mode").and_then(|v| v.as_str()) {
        Some(m) => m.trim(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "mode is required"),
            };
        }
    };

    let new_mode = match mode_str {
        "local" => InferenceMode::Local,
        "api_provider" => {
            let provider_input = match params.get("provider").and_then(|v| v.as_str()) {
                Some(p) => p.trim().to_owned(),
                None => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            "provider is required for api_provider mode",
                        ),
                    };
                }
            };

            if provider_input.is_empty() {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        "provider is required for api_provider mode",
                    ),
                };
            }

            let provider = {
                let config = state.config.read().await;
                match canonical_provider_name(&config, &provider_input) {
                    Some(name) => name,
                    None => {
                        return ServerMessage::Error {
                            id: Some(req_id.to_string()),
                            error: ErrorPayload::new(
                                ERR_INVALID_PARAMS,
                                format!("unknown provider: {provider_input}"),
                            ),
                        };
                    }
                }
            };

            InferenceMode::ApiProvider { provider }
        }
        _ => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    format!("unknown mode: {mode_str}; expected 'local' or 'api_provider'"),
                ),
            };
        }
    };

    let previous_mode = { state.config.read().await.llm.mode.clone() };

    // Update config
    {
        let mut config = state.config.write().await;
        config.llm.mode = new_mode.clone();
    }

    // Rebuild runtime state with the new mode.
    if let Err(refresh_err) = refresh_llm_and_tool_registry(state).await {
        {
            let mut config = state.config.write().await;
            config.llm.mode = previous_mode;
        }
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INTERNAL,
                format!("runtime refresh failed; mode change rolled back: {refresh_err}"),
            ),
        };
    }

    let audit_detail = match &new_mode {
        InferenceMode::Local => "local".to_string(),
        InferenceMode::ApiProvider { provider } => format!("api_provider:{provider}"),
    };
    let _ = state
        .audit
        .append("config", "set_inference_mode", Some(&audit_detail), None);

    let mode_json = match state.config.read().await.llm.mode.clone() {
        InferenceMode::Local => serde_json::json!({ "type": "local" }),
        InferenceMode::ApiProvider { provider } => {
            serde_json::json!({ "type": "api_provider", "provider": provider })
        }
    };

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({ "mode": mode_json }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use async_trait::async_trait;
    use encmind_agent::tool_registry::ToolRegistry;
    use encmind_core::config::{
        AgentConfigEntry, ApiProviderConfig, InferenceMode, SubagentRuntimeConfig,
    };
    use encmind_core::error::{AppError, PluginError};
    use encmind_core::hooks::{HookContext, HookHandler, HookPoint, HookRegistry, HookResult};
    use encmind_core::plugin::{NativePlugin, PluginKind, PluginManifest, PluginRegistrar};
    use encmind_core::traits::InternalToolHandler;
    use encmind_core::types::{AgentId, SessionId};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn state_with_key_store() -> AppState {
        let state = make_test_state();
        let key = [0u8; 32];
        let enc = Arc::new(encmind_storage::encryption::Aes256GcmAdapter::new(&key));
        let api_key_store: Arc<dyn encmind_core::traits::ApiKeyStore> = Arc::new(
            encmind_storage::api_key_store::SqliteApiKeyStore::new(state.db_pool.clone(), enc),
        );
        AppState {
            api_key_store: Some(api_key_store),
            ..state
        }
    }

    async fn add_provider_to_config(state: &AppState, name: &str) {
        let mut config = state.config.write().await;
        config.llm.api_providers.push(ApiProviderConfig {
            name: name.into(),
            model: format!("{name}-model"),
            base_url: Some(format!("https://api.{name}.example")),
        });
        config.llm.mode = InferenceMode::ApiProvider {
            provider: name.into(),
        };
    }

    async fn enable_spawn_permissions(state: &AppState) {
        let mut config = state.config.write().await;
        config.agents.list = vec![AgentConfigEntry {
            id: "main".into(),
            name: "Main".into(),
            model: None,
            workspace: None,
            system_prompt: None,
            skills: vec![],
            subagents: SubagentRuntimeConfig {
                allow_agents: vec!["helper".into()],
                model: None,
            },
            is_default: true,
        }];
    }

    struct NoopToolHandler;
    #[async_trait]
    impl InternalToolHandler for NoopToolHandler {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, AppError> {
            Ok("ok".into())
        }
    }

    struct CollidingAgentsSpawnPlugin;

    #[async_trait]
    impl NativePlugin for CollidingAgentsSpawnPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "agents".into(),
                name: "Colliding Agents Plugin".into(),
                version: "0.1.0".into(),
                description: "Registers agents_spawn as plugin tool".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            // Namespaced by plugin id => "agents_spawn".
            api.register_tool(
                "spawn",
                "desc",
                serde_json::json!({"type":"object"}),
                Arc::new(NoopToolHandler),
            )
        }
    }

    struct CollidingFileReadPlugin;

    #[async_trait]
    impl NativePlugin for CollidingFileReadPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "file".into(),
                name: "Colliding File Plugin".into(),
                version: "0.1.0".into(),
                description: "Registers file_read as plugin tool".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            // Namespaced by plugin id => "file_read".
            api.register_tool(
                "read",
                "desc",
                serde_json::json!({"type":"object"}),
                Arc::new(NoopToolHandler),
            )
        }
    }

    struct NoopHookHandler;

    #[async_trait]
    impl HookHandler for NoopHookHandler {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Continue)
        }
    }

    struct HookOnlyPlugin {
        id: &'static str,
    }

    #[async_trait]
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

    #[tokio::test]
    async fn list_empty() {
        let state = state_with_key_store();
        let result = handle_list(&state, serde_json::json!({}), "req-1").await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["keys"].as_array().unwrap().len(), 0);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn set_then_list() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let set_result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-2",
        )
        .await;
        assert!(matches!(set_result, ServerMessage::Res { .. }));

        let list_result = handle_list(&state, serde_json::json!({}), "req-3").await;
        match list_result {
            ServerMessage::Res { result, .. } => {
                let keys = result["keys"].as_array().unwrap();
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0]["provider"], "testprov");
                // Must not contain the actual key value
                assert!(keys[0].get("api_key").is_none());
                assert!(keys[0].get("key_blob").is_none());
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn set_key_refresh_re_registers_wasm_skill_tools() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        std::fs::write(skills_dir.join("echo.wasm"), wasm.as_bytes()).unwrap();
        let manifest = r#"
[skill]
name = "echo_skill"
version = "1.0.0"
description = "Echo skill"

[tool]
name = "echo_tool"
description = "Echo input"
"#;
        std::fs::write(skills_dir.join("echo.toml"), manifest).unwrap();

        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
            cfg.plugin_policy.allow_risk_levels = vec![
                encmind_core::policy::CapabilityRiskLevel::Low,
                encmind_core::policy::CapabilityRiskLevel::Sensitive,
            ];
        }

        let set_result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-wasm-refresh",
        )
        .await;
        assert!(matches!(set_result, ServerMessage::Res { .. }));

        let runtime = state.runtime.read().await;
        assert!(
            runtime.tool_registry.has_tool("echo_skill_echo_tool"),
            "expected WASM tool to be present after runtime refresh (namespaced as echo_skill_echo_tool)"
        );
    }

    #[tokio::test]
    async fn set_key_refresh_prunes_stale_skill_metrics() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        std::fs::write(skills_dir.join("echo.wasm"), wasm.as_bytes()).unwrap();
        let manifest = r#"
[skill]
name = "echo_skill"
version = "1.0.0"
description = "Echo skill"

[tool]
name = "echo_tool"
description = "Echo input"
"#;
        std::fs::write(skills_dir.join("echo.toml"), manifest).unwrap();

        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
            cfg.plugin_policy.allow_risk_levels = vec![
                encmind_core::policy::CapabilityRiskLevel::Low,
                encmind_core::policy::CapabilityRiskLevel::Sensitive,
            ];
        }

        {
            let mut metrics = state.skill_metrics.write().await;
            metrics.insert(
                "echo_skill".into(),
                Arc::new(crate::state::SkillMetrics::new()),
            );
            metrics.insert(
                "stale_skill".into(),
                Arc::new(crate::state::SkillMetrics::new()),
            );
        }

        let set_result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-prune-metrics",
        )
        .await;
        assert!(matches!(set_result, ServerMessage::Res { .. }));

        let metrics = state.skill_metrics.read().await;
        assert!(metrics.contains_key("echo_skill"));
        assert!(
            !metrics.contains_key("stale_skill"),
            "stale skill metrics should be pruned on refresh"
        );
    }

    #[tokio::test]
    async fn set_key_keeps_previous_runtime_when_plugin_tool_refresh_fails() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;
        // Ensure built-in agents_spawn is present when backend becomes available,
        // so replaying plugin-cached "agents_spawn" fails with duplicate name.
        enable_spawn_permissions(&state).await;

        let mut sentinel_registry = ToolRegistry::new();
        sentinel_registry
            .register_internal(
                "sentinel_tool",
                "Sentinel",
                serde_json::json!({"type":"object"}),
                Arc::new(NoopToolHandler),
            )
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            runtime.tool_registry = Arc::new(sentinel_registry);
        }

        let mut init_registry = ToolRegistry::new();
        let mut init_hooks = HookRegistry::new();
        let pm = crate::plugin_manager::PluginManager::initialize(
            vec![Box::new(CollidingAgentsSpawnPlugin)],
            &mut init_registry,
            &mut init_hooks,
            std::collections::HashMap::new(),
        )
        .await
        .unwrap();
        {
            let mut lock = state.plugin_manager.write().await;
            *lock = Some(Arc::new(pm));
        }

        let result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-refresh-fail",
        )
        .await;

        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INTERNAL);
                assert!(error.message.contains("failed to re-register plugin tools"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let runtime = state.runtime.read().await;
        assert!(
            runtime.tool_registry.has_tool("sentinel_tool"),
            "previous runtime tool registry should remain active on plugin refresh failure"
        );

        let store = state.api_key_store.as_ref().unwrap();
        assert!(
            store.get_key("testprov").await.unwrap().is_none(),
            "failed set should roll back persisted key value"
        );
    }

    #[tokio::test]
    async fn refresh_replaces_native_plugin_hooks_with_current_manager_snapshots() {
        let state = make_test_state();

        let mut old_tools = ToolRegistry::new();
        let mut old_hooks = HookRegistry::new();
        let _old_pm = crate::plugin_manager::PluginManager::initialize(
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
            let mut hooks = state.hook_registry.write().await;
            *hooks = old_hooks;
        }

        let mut new_tools = ToolRegistry::new();
        let mut new_hooks = HookRegistry::new();
        let new_pm = crate::plugin_manager::PluginManager::initialize(
            vec![Box::new(HookOnlyPlugin {
                id: "new_plugin_hook",
            })],
            &mut new_tools,
            &mut new_hooks,
            HashMap::new(),
        )
        .await
        .unwrap();

        {
            let mut lock = state.plugin_manager.write().await;
            *lock = Some(Arc::new(new_pm));
        }

        let _refresh_guard = state.refresh_lock.write().await;
        let plugin_manager = { state.plugin_manager.read().await.clone() };
        refresh_llm_and_tool_registry_with_previous_plugins_under_lock(
            &state,
            plugin_manager,
            HashSet::from(["old_plugin_hook".to_string()]),
        )
        .await
        .unwrap();

        let ids = state.hook_registry.read().await.registered_plugin_ids();
        assert!(!ids.contains("old_plugin_hook"));
        assert!(ids.contains("new_plugin_hook"));
    }

    #[tokio::test]
    async fn set_key_keeps_previous_runtime_when_wasm_reload_fails() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let mut sentinel_registry = ToolRegistry::new();
        sentinel_registry
            .register_internal(
                "sentinel_tool",
                "Sentinel",
                serde_json::json!({"type":"object"}),
                Arc::new(NoopToolHandler),
            )
            .unwrap();
        {
            let mut runtime = state.runtime.write().await;
            runtime.tool_registry = Arc::new(sentinel_registry);
        }

        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        // Invalid skill pair: missing manifest for wasm file => reload should fail closed.
        std::fs::write(skills_dir.join("broken.wasm"), b"(module)").unwrap();

        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
            cfg.plugin_policy.allow_risk_levels = vec![
                encmind_core::policy::CapabilityRiskLevel::Low,
                encmind_core::policy::CapabilityRiskLevel::Sensitive,
            ];
        }

        let result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-wasm-reload-fail",
        )
        .await;

        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INTERNAL);
                assert!(error.message.contains("failed to reload WASM skills"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let runtime = state.runtime.read().await;
        assert!(
            runtime.tool_registry.has_tool("sentinel_tool"),
            "previous runtime tool registry should remain active on WASM reload failure"
        );

        let store = state.api_key_store.as_ref().unwrap();
        assert!(
            store.get_key("testprov").await.unwrap().is_none(),
            "failed set should roll back persisted key value"
        );
    }

    #[tokio::test]
    async fn set_key_allows_disabled_broken_skill_during_refresh() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        // Invalid skill pair: missing manifest for wasm file.
        std::fs::write(skills_dir.join("broken.wasm"), b"(module)").unwrap();

        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
            cfg.plugin_policy.allow_risk_levels = vec![
                encmind_core::policy::CapabilityRiskLevel::Low,
                encmind_core::policy::CapabilityRiskLevel::Sensitive,
            ];
        }

        // Disable by skill id so malformed load errors are suppressed.
        let toggle_store = state.skill_toggle_store.as_ref().unwrap();
        toggle_store.set_enabled("broken", false).await.unwrap();

        let result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-wasm-disabled-broken",
        )
        .await;

        match result {
            ServerMessage::Res { .. } => {}
            other => panic!("expected Res, got {other:?}"),
        }

        let key_store = state.api_key_store.as_ref().unwrap();
        assert_eq!(
            key_store.get_key("testprov").await.unwrap().as_deref(),
            Some("sk-test")
        );
    }

    #[tokio::test]
    async fn delete_key_rolls_back_store_when_plugin_tool_refresh_fails() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let store = state.api_key_store.as_ref().unwrap();
        store.set_key("testprov", "sk-existing").await.unwrap();

        let mut init_registry = ToolRegistry::new();
        let mut init_hooks = HookRegistry::new();
        let pm = crate::plugin_manager::PluginManager::initialize(
            vec![Box::new(CollidingFileReadPlugin)],
            &mut init_registry,
            &mut init_hooks,
            std::collections::HashMap::new(),
        )
        .await
        .unwrap();
        {
            let mut lock = state.plugin_manager.write().await;
            *lock = Some(Arc::new(pm));
        }

        let result = handle_delete(
            &state,
            serde_json::json!({"provider": "testprov"}),
            "req-delete-refresh-fail",
        )
        .await;

        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INTERNAL);
                assert!(error.message.contains("rolled back"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        assert_eq!(
            store.get_key("testprov").await.unwrap(),
            Some("sk-existing".to_string()),
            "failed delete should restore the previous key",
        );
    }

    #[tokio::test]
    async fn set_mode_rolls_back_config_when_plugin_tool_refresh_fails() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;
        {
            let mut config = state.config.write().await;
            config.llm.mode = InferenceMode::Local;
        }
        let store = state.api_key_store.as_ref().unwrap();
        store.set_key("testprov", "sk-existing").await.unwrap();

        let mut init_registry = ToolRegistry::new();
        let mut init_hooks = HookRegistry::new();
        let pm = crate::plugin_manager::PluginManager::initialize(
            vec![Box::new(CollidingFileReadPlugin)],
            &mut init_registry,
            &mut init_hooks,
            std::collections::HashMap::new(),
        )
        .await
        .unwrap();
        {
            let mut lock = state.plugin_manager.write().await;
            *lock = Some(Arc::new(pm));
        }

        let result = handle_set_mode(
            &state,
            serde_json::json!({"mode": "api_provider", "provider": "testprov"}),
            "req-mode-refresh-fail",
        )
        .await;

        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INTERNAL);
                assert!(error.message.contains("rolled back"));
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let config = state.config.read().await;
        assert!(
            matches!(config.llm.mode, InferenceMode::Local),
            "failed mode switch should restore previous config mode"
        );
    }

    #[tokio::test]
    async fn set_then_get_from_store() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-secret"}),
            "req-4",
        )
        .await;

        let store = state.api_key_store.as_ref().unwrap();
        let key = store.get_key("testprov").await.unwrap();
        assert_eq!(key, Some("sk-secret".to_string()));
    }

    #[tokio::test]
    async fn delete_removes() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-5",
        )
        .await;

        let del_result =
            handle_delete(&state, serde_json::json!({"provider": "testprov"}), "req-6").await;
        match del_result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["status"], "deleted");
            }
            _ => panic!("Expected Res"),
        }

        let store = state.api_key_store.as_ref().unwrap();
        assert!(store.get_key("testprov").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_requires_provider() {
        let state = state_with_key_store();
        let result = handle_set(&state, serde_json::json!({"api_key": "sk-test"}), "req-7").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("provider"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn set_requires_api_key() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let result = handle_set(&state, serde_json::json!({"provider": "testprov"}), "req-8").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("api_key"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn set_rejects_blank_api_key() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "   "}),
            "req-8b",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("api_key must not be empty"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn set_rejects_unknown_provider() {
        let state = state_with_key_store();
        // Don't add any provider to config
        let result = handle_set(
            &state,
            serde_json::json!({"provider": "unknown", "api_key": "sk-test"}),
            "req-9",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown provider"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn set_canonicalizes_provider_name_for_storage_lookup() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let result = handle_set(
            &state,
            serde_json::json!({"provider": "TeStPrOv", "api_key": "sk-secret"}),
            "req-9b",
        )
        .await;
        assert!(matches!(result, ServerMessage::Res { .. }));

        let store = state.api_key_store.as_ref().unwrap();
        assert_eq!(
            store.get_key("testprov").await.unwrap(),
            Some("sk-secret".to_string())
        );
        assert!(
            store.get_key("TeStPrOv").await.unwrap().is_some(),
            "legacy mixed-case lookups should still resolve"
        );
    }

    #[tokio::test]
    async fn delete_canonicalizes_provider_name_for_storage_lookup() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-secret"}),
            "req-9c",
        )
        .await;

        let result = handle_delete(
            &state,
            serde_json::json!({"provider": "TeStPrOv"}),
            "req-9d",
        )
        .await;
        assert!(matches!(result, ServerMessage::Res { .. }));

        let store = state.api_key_store.as_ref().unwrap();
        assert!(store.get_key("testprov").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_allows_cleanup_of_provider_not_in_config() {
        let state = state_with_key_store();

        {
            let store = state.api_key_store.as_ref().unwrap();
            store.set_key("legacy-provider", "sk-legacy").await.unwrap();
        }

        let result = handle_delete(
            &state,
            serde_json::json!({"provider": "legacy-provider"}),
            "req-9e",
        )
        .await;
        assert!(matches!(result, ServerMessage::Res { .. }));

        let store = state.api_key_store.as_ref().unwrap();
        assert!(store.get_key("legacy-provider").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn dispatch_keys_list() {
        let state = state_with_key_store();
        let result = crate::dispatch::dispatch_method(
            &state,
            "keys.list",
            serde_json::json!({}),
            "req-d1",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-d1"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn dispatch_keys_set() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let result = crate::dispatch::dispatch_method(
            &state,
            "keys.set",
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-d2",
            None,
        )
        .await;
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "req-d2"),
            _ => panic!("Expected Res"),
        }
    }

    #[test]
    fn keys_require_admin() {
        use encmind_core::types::DevicePermissions;

        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };
        let params = serde_json::json!({});

        for method in &["keys.list", "keys.set", "keys.delete"] {
            assert!(
                !crate::ws::is_method_allowed(method, &params, &chat_user),
                "{method} should require admin"
            );
            assert!(
                crate::ws::is_method_allowed(method, &params, &admin_user),
                "{method} should be allowed for admin"
            );
        }
    }

    // ── Refresh atomicity tests ─────────────────────────────

    #[tokio::test]
    async fn concurrent_refreshes_are_serialized() {
        // Verify that two concurrent refreshes both complete without error or deadlock.
        // The refresh_lock in AppState ensures serialization.
        let state = Arc::new(state_with_key_store());
        add_provider_to_config(&state, "testprov").await;

        let state1 = state.clone();
        let state2 = state.clone();

        let (r1, r2) = tokio::join!(
            async move {
                handle_set(
                    &state1,
                    serde_json::json!({"provider": "testprov", "api_key": "sk-first"}),
                    "req-conc1",
                )
                .await
            },
            async move {
                handle_set(
                    &state2,
                    serde_json::json!({"provider": "testprov", "api_key": "sk-second"}),
                    "req-conc2",
                )
                .await
            }
        );

        // Both should succeed (serialized by refresh_lock)
        assert!(
            matches!(r1, ServerMessage::Res { .. }),
            "first refresh should succeed"
        );
        assert!(
            matches!(r2, ServerMessage::Res { .. }),
            "second refresh should succeed"
        );

        // The final key should be one of the two values (last writer wins)
        let store = state.api_key_store.as_ref().unwrap();
        let key = store.get_key("testprov").await.unwrap().unwrap();
        assert!(
            key == "sk-first" || key == "sk-second",
            "final key should be one of the two values, got: {key}"
        );
    }

    #[tokio::test]
    async fn refresh_commit_is_atomic() {
        // Verify that after a successful refresh, all state (runtime, skills metadata)
        // is updated consistently.
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        // Initial state: no backend, empty skills
        {
            let runtime = state.runtime.read().await;
            assert!(runtime.llm_backend.is_none());
        }
        assert!(state.loaded_skills.read().await.is_empty());

        // Set a key, which triggers refresh
        let result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-test"}),
            "req-atomic",
        )
        .await;
        assert!(matches!(result, ServerMessage::Res { .. }));

        // After refresh, runtime should have a backend
        let runtime = state.runtime.read().await;
        assert!(
            runtime.llm_backend.is_some(),
            "backend should be set after refresh"
        );
        // Tool registry should be non-null (always created fresh)
        drop(runtime);
    }

    // ── Inference mode switch tests ─────────────────────────────

    #[tokio::test]
    async fn switch_to_api_provider() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let result = handle_set_mode(
            &state,
            serde_json::json!({"mode": "api_provider", "provider": "testprov"}),
            "req-m1",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["mode"]["type"], "api_provider");
                assert_eq!(result["mode"]["provider"], "testprov");
            }
            _ => panic!("Expected Res"),
        }

        let config = state.config.read().await;
        match &config.llm.mode {
            InferenceMode::ApiProvider { provider } => assert_eq!(provider, "testprov"),
            _ => panic!("Expected ApiProvider mode"),
        }
    }

    #[tokio::test]
    async fn switch_to_api_provider_canonicalizes_provider_name() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        let result = handle_set_mode(
            &state,
            serde_json::json!({"mode": "api_provider", "provider": "TeStPrOv"}),
            "req-m1b",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["mode"]["provider"], "testprov");
            }
            _ => panic!("Expected Res"),
        }

        let config = state.config.read().await;
        match &config.llm.mode {
            InferenceMode::ApiProvider { provider } => assert_eq!(provider, "testprov"),
            _ => panic!("Expected ApiProvider mode"),
        }
    }

    #[tokio::test]
    async fn switch_to_local() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        // First switch to API provider
        handle_set_mode(
            &state,
            serde_json::json!({"mode": "api_provider", "provider": "testprov"}),
            "req-m2a",
        )
        .await;

        // Then switch back to local
        let result = handle_set_mode(&state, serde_json::json!({"mode": "local"}), "req-m2b").await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["mode"]["type"], "local");
            }
            _ => panic!("Expected Res"),
        }

        let config = state.config.read().await;
        assert!(matches!(config.llm.mode, InferenceMode::Local));
    }

    #[tokio::test]
    async fn reject_unknown_mode() {
        let state = state_with_key_store();

        let result =
            handle_set_mode(&state, serde_json::json!({"mode": "quantum"}), "req-m3").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown mode"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn reject_missing_provider() {
        let state = state_with_key_store();

        let result = handle_set_mode(
            &state,
            serde_json::json!({"mode": "api_provider"}),
            "req-m4",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("provider is required"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn mode_switch_audit_logged() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;

        handle_set_mode(
            &state,
            serde_json::json!({"mode": "api_provider", "provider": "testprov"}),
            "req-m5",
        )
        .await;

        let filter = encmind_storage::audit::AuditFilter {
            action: Some("set_inference_mode".to_string()),
            ..Default::default()
        };
        let entries = state.audit.query(filter, 10, 0).unwrap();
        assert!(!entries.is_empty());
        assert_eq!(entries[0].category, "config");
        assert_eq!(entries[0].action, "set_inference_mode");
        assert_eq!(
            entries[0].detail.as_deref(),
            Some("api_provider:testprov"),
            "audit should include provider in detail"
        );
    }

    #[tokio::test]
    async fn set_key_refreshes_tool_registry_when_backend_becomes_available() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;
        enable_spawn_permissions(&state).await;
        std::env::remove_var("TESTPROV_API_KEY");

        {
            let runtime = state.runtime.read().await;
            assert!(!runtime.tool_registry.has_tool("agents_spawn"));
        }

        let result = handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-live"}),
            "req-r1",
        )
        .await;
        assert!(matches!(result, ServerMessage::Res { .. }));

        let runtime = state.runtime.read().await;
        assert!(runtime.llm_backend.is_some());
        assert!(runtime.tool_registry.has_tool("agents_spawn"));
    }

    #[tokio::test]
    async fn delete_key_refreshes_tool_registry_when_backend_becomes_unavailable() {
        let state = state_with_key_store();
        add_provider_to_config(&state, "testprov").await;
        enable_spawn_permissions(&state).await;
        std::env::remove_var("TESTPROV_API_KEY");

        handle_set(
            &state,
            serde_json::json!({"provider": "testprov", "api_key": "sk-live"}),
            "req-r2a",
        )
        .await;
        {
            let runtime = state.runtime.read().await;
            assert!(runtime.tool_registry.has_tool("agents_spawn"));
        }

        let result = handle_delete(
            &state,
            serde_json::json!({"provider": "testprov"}),
            "req-r2b",
        )
        .await;
        assert!(matches!(result, ServerMessage::Res { .. }));

        let runtime = state.runtime.read().await;
        assert!(runtime.llm_backend.is_none());
        assert!(!runtime.tool_registry.has_tool("agents_spawn"));
    }
}
