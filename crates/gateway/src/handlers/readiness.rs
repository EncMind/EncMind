use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::local_tool_policy::LocalToolPolicyStatus;
use crate::protocol::ServerMessage;
use crate::state::AppState;

const MIN_SKILL_INVOCATIONS_FOR_DEGRADE: u64 = 5;

/// Overall readiness status of the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    Degraded,
    Unhealthy,
    Unavailable,
    Disabled,
}

/// Per-subsystem status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemStatus {
    pub status: ReadinessStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Rate limiting configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
    pub messages_per_minute: u32,
    pub tool_calls_per_run: u32,
    pub api_budget_usd: Option<f64>,
    pub active_sessions_tracked: usize,
}

/// Full readiness report returned by `/health?detail=true` and `status.readiness`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub status: ReadinessStatus,
    pub llm: SubsystemStatus,
    pub api_key: SubsystemStatus,
    pub tools: SubsystemStatus,
    pub channels: SubsystemStatus,
    pub plugins: SubsystemStatus,
    pub skills: SubsystemStatus,
    pub memory: SubsystemStatus,
    pub browser: SubsystemStatus,
    pub lockdown: bool,
    pub rate_limiting: RateLimitStatus,
    pub local_tools_policy: LocalToolPolicyStatus,
}

/// Collect readiness report from current application state.
pub async fn collect_readiness(state: &AppState) -> ReadinessReport {
    let config = state.config.read().await;

    // LLM
    let runtime = state.runtime.read().await;
    let llm = if runtime.llm_backend.is_some() {
        SubsystemStatus {
            status: ReadinessStatus::Ready,
            detail: None,
        }
    } else {
        SubsystemStatus {
            status: ReadinessStatus::Unhealthy,
            detail: Some("no LLM backend configured".to_string()),
        }
    };

    // API key
    let api_key = if !config.llm.api_providers.is_empty() {
        SubsystemStatus {
            status: ReadinessStatus::Ready,
            detail: Some(format!("{} provider(s)", config.llm.api_providers.len())),
        }
    } else if config.llm.local.is_some() {
        SubsystemStatus {
            status: ReadinessStatus::Ready,
            detail: Some("local model".to_string()),
        }
    } else {
        SubsystemStatus {
            status: ReadinessStatus::Unavailable,
            detail: Some("no LLM providers configured".to_string()),
        }
    };

    // Tools
    let tool_count = runtime.tool_registry.tool_count();
    let tools = SubsystemStatus {
        status: ReadinessStatus::Ready,
        detail: Some(format!("{tool_count} tools registered")),
    };

    // Channels
    let channels = if state.channel_router.is_some() {
        let running_count = state.channel_manager.running_count().await;
        let mut configured_channels: Vec<String> =
            state.channel_startup_intent.iter().cloned().collect();
        configured_channels.sort();
        let configured_count = configured_channels.len();
        let mut configured_not_running = 0usize;
        for channel in &configured_channels {
            if !state.channel_manager.is_running(channel.as_str()).await {
                configured_not_running += 1;
            }
        }
        if let Some(store) = state.channel_account_store.as_ref() {
            match store.list_accounts().await {
                Ok(accounts) => {
                    // Only enabled accounts should affect readiness degradation.
                    // Disabled accounts are intentionally inactive and should not
                    // make channels look unhealthy.
                    let account_count = accounts.len();
                    let enabled_count = accounts.iter().filter(|a| a.enabled).count();
                    let active_count = accounts
                        .iter()
                        .filter(|a| {
                            a.enabled
                                && matches!(
                                    a.status,
                                    encmind_core::types::ChannelAccountStatus::Active
                                )
                        })
                        .count();
                    let login_required_count = accounts
                        .iter()
                        .filter(|a| {
                            a.enabled
                                && matches!(
                                    a.status,
                                    encmind_core::types::ChannelAccountStatus::LoginRequired
                                )
                        })
                        .count();
                    let degraded_count = accounts
                        .iter()
                        .filter(|a| {
                            a.enabled
                                && matches!(
                                    a.status,
                                    encmind_core::types::ChannelAccountStatus::Degraded
                                        | encmind_core::types::ChannelAccountStatus::Error
                                )
                        })
                        .count();
                    let status = if degraded_count > 0
                        || login_required_count > 0
                        || configured_not_running > 0
                    {
                        ReadinessStatus::Degraded
                    } else {
                        ReadinessStatus::Ready
                    };
                    SubsystemStatus {
                        status,
                        detail: Some(format!(
                            "{account_count} account(s), {enabled_count} enabled, {active_count} active, {running_count} running adapters, {configured_count} configured, {configured_not_running} not running"
                        )),
                    }
                }
                Err(e) => SubsystemStatus {
                    status: ReadinessStatus::Degraded,
                    detail: Some(format!("failed to list channel accounts: {e}")),
                },
            }
        } else {
            let status = if configured_not_running > 0 {
                ReadinessStatus::Degraded
            } else {
                ReadinessStatus::Ready
            };
            SubsystemStatus {
                status,
                detail: Some(format!(
                    "{running_count} running adapters, {configured_count} configured, {configured_not_running} not running"
                )),
            }
        }
    } else {
        SubsystemStatus {
            status: ReadinessStatus::Disabled,
            detail: None,
        }
    };

    // Plugins
    let plugin_mgr = state.plugin_manager.read().await;
    let plugins = if let Some(ref pm) = *plugin_mgr {
        if pm.is_degraded() {
            SubsystemStatus {
                status: ReadinessStatus::Degraded,
                detail: Some("one or more plugins degraded".to_string()),
            }
        } else {
            SubsystemStatus {
                status: ReadinessStatus::Ready,
                detail: None,
            }
        }
    } else {
        SubsystemStatus {
            status: ReadinessStatus::Disabled,
            detail: None,
        }
    };

    // Skills
    let (loaded_count, enabled_count, enabled_skill_ids) = {
        let loaded_skills = state.loaded_skills.read().await;
        (
            loaded_skills.len(),
            loaded_skills.iter().filter(|s| s.enabled).count(),
            loaded_skills
                .iter()
                .filter(|s| s.enabled)
                .map(|s| s.id.clone())
                .collect::<std::collections::HashSet<String>>(),
        )
    };
    let skills = if loaded_count == 0 {
        SubsystemStatus {
            status: ReadinessStatus::Disabled,
            detail: None,
        }
    } else {
        let metrics = state.skill_metrics.read().await;
        let errored_count = metrics
            .iter()
            .filter(|(skill_id, _)| enabled_skill_ids.contains(skill_id.as_str()))
            .filter(|(_, m)| {
                let inv = m.invocations.load(std::sync::atomic::Ordering::Relaxed);
                let err = m.errors.load(std::sync::atomic::Ordering::Relaxed);
                // A skill with errors and >50% error rate is considered degraded
                err > 0 && inv >= MIN_SKILL_INVOCATIONS_FOR_DEGRADE && err * 2 > inv
            })
            .count();

        if errored_count > 0 {
            SubsystemStatus {
                status: ReadinessStatus::Degraded,
                detail: Some(format!(
                    "{loaded_count} loaded, {enabled_count} enabled, {errored_count} degraded (high error rate)"
                )),
            }
        } else {
            SubsystemStatus {
                status: ReadinessStatus::Ready,
                detail: Some(format!("{loaded_count} loaded, {enabled_count} enabled")),
            }
        }
    };

    // Memory
    let memory = if !config.memory.enabled {
        SubsystemStatus {
            status: ReadinessStatus::Disabled,
            detail: None,
        }
    } else if state.memory_store.is_some() {
        SubsystemStatus {
            status: ReadinessStatus::Ready,
            detail: None,
        }
    } else {
        SubsystemStatus {
            status: ReadinessStatus::Degraded,
            detail: Some("enabled but store not initialized".to_string()),
        }
    };

    // Browser
    let browser = if !config.browser.enabled {
        SubsystemStatus {
            status: ReadinessStatus::Disabled,
            detail: None,
        }
    } else if state.browser_pool.is_some() {
        SubsystemStatus {
            status: ReadinessStatus::Ready,
            detail: None,
        }
    } else {
        SubsystemStatus {
            status: ReadinessStatus::Degraded,
            detail: Some("enabled but pool not initialized".to_string()),
        }
    };

    // Lockdown
    let lockdown = state.lockdown.is_active();

    // Rate limiting
    let rate_limiting = RateLimitStatus {
        messages_per_minute: config.security.rate_limit.messages_per_minute,
        tool_calls_per_run: config.security.rate_limit.tool_calls_per_run,
        api_budget_usd: config.security.rate_limit.api_budget_usd,
        active_sessions_tracked: state.session_rate_limiter.active_session_count(),
    };
    let local_tools_policy = crate::local_tool_policy::status_from_config(&config);

    // Overall status
    let overall = if llm.status == ReadinessStatus::Unhealthy {
        ReadinessStatus::Unhealthy
    } else if plugins.status == ReadinessStatus::Degraded
        || channels.status == ReadinessStatus::Degraded
        || skills.status == ReadinessStatus::Degraded
        || memory.status == ReadinessStatus::Degraded
        || browser.status == ReadinessStatus::Degraded
    {
        ReadinessStatus::Degraded
    } else {
        ReadinessStatus::Ready
    };

    ReadinessReport {
        status: overall,
        llm,
        api_key,
        tools,
        channels,
        plugins,
        skills,
        memory,
        browser,
        lockdown,
        rate_limiting,
        local_tools_policy,
    }
}

/// Handle `status.readiness` dispatch method.
pub async fn handle_readiness(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let report = collect_readiness(state).await;
    let value = serde_json::to_value(&report).unwrap_or(json!({"error": "serialization failed"}));
    ServerMessage::Res {
        id: req_id.to_string(),
        result: value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore};
    use tokio_util::sync::CancellationToken;

    use encmind_agent::firewall::EgressFirewall;
    use encmind_agent::lockdown::LockdownManager;
    use encmind_agent::pool::AgentPool;
    use encmind_agent::tool_registry::ToolRegistry;
    use encmind_core::config::{AppConfig, LockdownConfig, TelegramConfig, TelegramMode};
    use encmind_storage::audit::AuditLogger;
    use encmind_storage::channel_account_store::SqliteChannelAccountStore;
    use encmind_storage::device_store::SqliteDeviceStore;
    use encmind_storage::encryption::Aes256GcmAdapter;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;
    use encmind_storage::session_store::SqliteSessionStore;

    use crate::channel_manager::ChannelAdapterManager;
    use crate::device_auth::NonceStore;
    use crate::idempotency::IdempotencyCache;
    use crate::node::NodeRegistry;
    use crate::rate_limiter::SessionRateLimiter;
    use crate::state::{NativePluginTimerRuntime, RuntimeResources};

    use encmind_agent::registry::SqliteAgentRegistry;
    use encmind_channels::router::ChannelRouter;
    use encmind_core::hooks::HookRegistry;
    use encmind_core::traits::{AgentRegistry, ChannelAccountStore, DeviceStore, SessionStore};
    use encmind_core::types::{
        ChannelAccount, ChannelAccountId, ChannelAccountStatus, ConfigSource,
    };

    struct EnvVarGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                original,
            }
        }

        fn unset(key: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::remove_var(key);
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                std::env::set_var(&self.key, value);
            } else {
                std::env::remove_var(&self.key);
            }
        }
    }

    fn make_test_state(llm_present: bool, config: AppConfig) -> AppState {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }

        let key = [0u8; 32];
        let enc = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), enc));
        let agent_registry: Arc<dyn AgentRegistry> =
            Arc::new(SqliteAgentRegistry::new(pool.clone()));
        let device_store: Arc<dyn DeviceStore> = Arc::new(SqliteDeviceStore::new(pool.clone()));

        let lockdown = Arc::new(LockdownManager::new(&LockdownConfig::default()));
        let agent_pool = Arc::new(AgentPool::new(
            &encmind_core::config::AgentPoolConfig::default(),
        ));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
        let audit = Arc::new(AuditLogger::new(pool.clone()));
        let channel_startup_intent =
            Arc::new(crate::state::compute_channel_startup_intent(&config));

        let llm_backend: Option<Arc<dyn encmind_core::traits::LlmBackend>> = if llm_present {
            Some(Arc::new(StubLlmBackend))
        } else {
            None
        };

        AppState {
            session_store,
            agent_registry,
            device_store,
            lockdown,
            agent_pool,
            runtime: Arc::new(RwLock::new(RuntimeResources {
                llm_backend,
                tool_registry: Arc::new(ToolRegistry::new()),
            })),
            api_key_store: None,
            firewall,
            audit,
            config: Arc::new(RwLock::new(config)),
            tls: None,
            node_registry: Arc::new(NodeRegistry::new()),
            connection_permits: Arc::new(Semaphore::new(64)),
            idempotency: Arc::new(Mutex::new(IdempotencyCache::new(300))),
            nonce_store: Arc::new(NonceStore::new()),
            pairing_sessions: Arc::new(Mutex::new(HashMap::new())),
            admin_bootstrap_lock: Arc::new(AsyncMutex::new(())),
            active_runs: Arc::new(Mutex::new(HashMap::new())),
            db_pool: pool,
            memory_store: None,
            cron_store: None,
            cron_dispatcher: None,
            channel_router: None,
            channel_manager: Arc::new(ChannelAdapterManager::new(CancellationToken::new())),
            timeline_store: None,
            backup_manager: None,
            browser_pool: None,
            hook_registry: Arc::new(RwLock::new(HookRegistry::new())),
            plugin_manager: Arc::new(RwLock::new(None)),
            loaded_skills: Arc::new(RwLock::new(Vec::new())),
            known_skill_ids: Arc::new(RwLock::new(HashSet::new())),
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
            wasm_http_client: Arc::new(reqwest::Client::new()),
            skill_timer_store: None,
            skill_timer_runner: None,
            channel_transforms: Arc::new(RwLock::new(HashMap::new())),
            refresh_lock: Arc::new(RwLock::new(())),
            skill_toggle_store: None,
            skill_toggle_lock: Arc::new(AsyncMutex::new(())),
            skill_resources_lock: Arc::new(AsyncMutex::new(())),
            skill_metrics: Arc::new(RwLock::new(HashMap::new())),
            native_plugin_timers: Arc::new(AsyncMutex::new(NativePluginTimerRuntime {
                cancel: CancellationToken::new(),
                handles: Vec::new(),
            })),
            native_timer_replace_lock: Arc::new(AsyncMutex::new(())),
            session_rate_limiter: Arc::new(SessionRateLimiter::new(30)),
            api_budget_tracker: None,
            channel_account_store: None,
            channel_startup_intent,
        }
    }

    struct StubLlmBackend;

    #[async_trait::async_trait]
    impl encmind_core::traits::LlmBackend for StubLlmBackend {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: encmind_core::traits::CompletionParams,
            _cancel: tokio_util::sync::CancellationToken,
        ) -> Result<
            std::pin::Pin<
                Box<
                    dyn futures::Stream<
                            Item = Result<
                                encmind_core::traits::CompletionDelta,
                                encmind_core::error::LlmError,
                            >,
                        > + Send,
                >,
            >,
            encmind_core::error::LlmError,
        > {
            Err(encmind_core::error::LlmError::NotConfigured)
        }

        fn model_info(&self) -> encmind_core::traits::ModelInfo {
            encmind_core::traits::ModelInfo {
                id: "stub".into(),
                name: "Stub".into(),
                provider: "test".into(),
                context_window: 4096,
                supports_tools: false,
                supports_streaming: false,
                supports_thinking: false,
            }
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, encmind_core::error::LlmError> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn readiness_healthy_when_llm_present() {
        let state = make_test_state(true, AppConfig::default());
        let report = collect_readiness(&state).await;
        assert_eq!(report.llm.status, ReadinessStatus::Ready);
        // Overall is Ready (no degraded optionals)
        assert_eq!(report.status, ReadinessStatus::Ready);
    }

    #[tokio::test]
    async fn readiness_unhealthy_when_no_llm() {
        let state = make_test_state(false, AppConfig::default());
        let report = collect_readiness(&state).await;
        assert_eq!(report.llm.status, ReadinessStatus::Unhealthy);
        assert_eq!(report.status, ReadinessStatus::Unhealthy);
    }

    #[tokio::test]
    async fn readiness_degraded_on_optional_failure() {
        let mut config = AppConfig::default();
        config.memory.enabled = true;
        let state = make_test_state(true, config);
        // memory enabled but no store → degraded
        let report = collect_readiness(&state).await;
        assert_eq!(report.memory.status, ReadinessStatus::Degraded);
        assert_eq!(report.status, ReadinessStatus::Degraded);
    }

    #[tokio::test]
    async fn readiness_disabled_no_degrade() {
        let state = make_test_state(true, AppConfig::default());
        let report = collect_readiness(&state).await;
        // Memory disabled should not cause degradation
        assert_eq!(report.memory.status, ReadinessStatus::Disabled);
        assert_eq!(report.channels.status, ReadinessStatus::Disabled);
        assert_eq!(report.status, ReadinessStatus::Ready);
    }

    #[tokio::test]
    async fn readiness_lockdown_visible() {
        let state = make_test_state(true, AppConfig::default());
        state.lockdown.activate("test");
        let report = collect_readiness(&state).await;
        assert!(report.lockdown);
    }

    #[tokio::test]
    async fn readiness_shows_rate_limit_config() {
        let state = make_test_state(true, AppConfig::default());
        let report = collect_readiness(&state).await;
        assert_eq!(report.rate_limiting.messages_per_minute, 30);
        assert_eq!(report.rate_limiting.tool_calls_per_run, 50);
        assert!(report.rate_limiting.api_budget_usd.is_none());
    }

    #[tokio::test]
    async fn readiness_channels_degraded_when_login_required_accounts_exist() {
        let mut state = make_test_state(true, AppConfig::default());
        state.channel_router = Some(Arc::new(ChannelRouter::new(
            state.config.read().await.channels.access_policy.clone(),
            state.session_store.clone(),
        )));

        let account_store: Arc<dyn ChannelAccountStore> = Arc::new(SqliteChannelAccountStore::new(
            state.db_pool.clone(),
            Arc::new(Aes256GcmAdapter::new(&[9u8; 32])),
        ));
        state.channel_account_store = Some(account_store.clone());

        account_store
            .create_account(&ChannelAccount {
                id: ChannelAccountId::new(),
                channel_type: "telegram".to_string(),
                label: "Test".to_string(),
                enabled: true,
                status: ChannelAccountStatus::LoginRequired,
                config_source: ConfigSource::Api,
                policy: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .await
            .expect("create account should succeed");

        let report = collect_readiness(&state).await;
        assert_eq!(report.channels.status, ReadinessStatus::Degraded);
        assert_eq!(report.status, ReadinessStatus::Degraded);
        assert!(report
            .channels
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 account(s)"));
    }

    #[tokio::test]
    async fn readiness_channels_ignores_disabled_login_required_accounts() {
        let mut state = make_test_state(true, AppConfig::default());
        state.channel_router = Some(Arc::new(ChannelRouter::new(
            state.config.read().await.channels.access_policy.clone(),
            state.session_store.clone(),
        )));

        let account_store: Arc<dyn ChannelAccountStore> = Arc::new(SqliteChannelAccountStore::new(
            state.db_pool.clone(),
            Arc::new(Aes256GcmAdapter::new(&[7u8; 32])),
        ));
        state.channel_account_store = Some(account_store.clone());

        account_store
            .create_account(&ChannelAccount {
                id: ChannelAccountId::new(),
                channel_type: "telegram".to_string(),
                label: "Disabled".to_string(),
                enabled: false,
                status: ChannelAccountStatus::LoginRequired,
                config_source: ConfigSource::Api,
                policy: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .await
            .expect("create account should succeed");

        let report = collect_readiness(&state).await;
        assert_eq!(report.channels.status, ReadinessStatus::Ready);
        assert_eq!(report.status, ReadinessStatus::Ready);
        assert!(report
            .channels
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 account(s), 0 enabled"));
    }

    #[tokio::test]
    async fn readiness_channels_degraded_when_configured_channel_not_running() {
        let mut config = AppConfig::default();
        let _guard = EnvVarGuard::set("ENCMIND_READINESS_TEST_TELEGRAM_TOKEN", "test-token");
        config.channels.telegram = Some(TelegramConfig {
            bot_token_env: "ENCMIND_READINESS_TEST_TELEGRAM_TOKEN".to_string(),
            mode: TelegramMode::Polling,
            webhook_url: None,
            ..Default::default()
        });
        let mut state = make_test_state(true, config);
        state.channel_router = Some(Arc::new(ChannelRouter::new(
            state.config.read().await.channels.access_policy.clone(),
            state.session_store.clone(),
        )));

        let report = collect_readiness(&state).await;
        assert_eq!(report.channels.status, ReadinessStatus::Degraded);
        assert_eq!(report.status, ReadinessStatus::Degraded);
        assert!(report
            .channels
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 configured, 1 not running"));
    }

    #[tokio::test]
    async fn readiness_skills_ready_when_no_errors() {
        use crate::state::{LoadedSkillSummary, SkillMetrics};
        use std::sync::atomic::AtomicU64;

        let state = make_test_state(true, AppConfig::default());

        // Add a loaded skill
        state.loaded_skills.write().await.push(LoadedSkillSummary {
            id: "test-skill".to_string(),
            version: "1.0".to_string(),
            description: "Test".to_string(),
            tool_name: Some("test_tool".to_string()),
            hook_points: vec![],
            enabled: true,
            output_schema: None,
        });

        // Add metrics with some invocations but no errors
        let metrics = Arc::new(SkillMetrics {
            invocations: AtomicU64::new(10),
            errors: AtomicU64::new(0),
            last_invoked_at: std::sync::Mutex::new(None),
        });
        state
            .skill_metrics
            .write()
            .await
            .insert("test-skill".to_string(), metrics);

        let report = collect_readiness(&state).await;
        assert_eq!(report.skills.status, ReadinessStatus::Ready);
        assert!(report
            .skills
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 loaded, 1 enabled"));
    }

    #[tokio::test]
    async fn readiness_skills_degraded_when_high_error_rate() {
        use crate::state::{LoadedSkillSummary, SkillMetrics};
        use std::sync::atomic::AtomicU64;

        let state = make_test_state(true, AppConfig::default());

        state.loaded_skills.write().await.push(LoadedSkillSummary {
            id: "bad-skill".to_string(),
            version: "1.0".to_string(),
            description: "Bad".to_string(),
            tool_name: Some("bad_tool".to_string()),
            hook_points: vec![],
            enabled: true,
            output_schema: None,
        });

        // 8 out of 10 calls failed — 80% error rate, well above 50% threshold
        let metrics = Arc::new(SkillMetrics {
            invocations: AtomicU64::new(10),
            errors: AtomicU64::new(8),
            last_invoked_at: std::sync::Mutex::new(None),
        });
        state
            .skill_metrics
            .write()
            .await
            .insert("bad-skill".to_string(), metrics);

        let report = collect_readiness(&state).await;
        assert_eq!(report.skills.status, ReadinessStatus::Degraded);
        assert_eq!(report.status, ReadinessStatus::Degraded);
        assert!(report
            .skills
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 degraded"));
    }

    #[tokio::test]
    async fn readiness_skills_ready_when_low_error_rate() {
        use crate::state::{LoadedSkillSummary, SkillMetrics};
        use std::sync::atomic::AtomicU64;

        let state = make_test_state(true, AppConfig::default());

        state.loaded_skills.write().await.push(LoadedSkillSummary {
            id: "ok-skill".to_string(),
            version: "1.0".to_string(),
            description: "OK".to_string(),
            tool_name: Some("ok_tool".to_string()),
            hook_points: vec![],
            enabled: true,
            output_schema: None,
        });

        // 2 out of 10 calls failed — 20% error rate, below 50% threshold
        let metrics = Arc::new(SkillMetrics {
            invocations: AtomicU64::new(10),
            errors: AtomicU64::new(2),
            last_invoked_at: std::sync::Mutex::new(None),
        });
        state
            .skill_metrics
            .write()
            .await
            .insert("ok-skill".to_string(), metrics);

        let report = collect_readiness(&state).await;
        assert_eq!(report.skills.status, ReadinessStatus::Ready);
    }

    #[tokio::test]
    async fn readiness_skills_ignores_disabled_skill_metrics() {
        use crate::state::{LoadedSkillSummary, SkillMetrics};
        use std::sync::atomic::AtomicU64;

        let state = make_test_state(true, AppConfig::default());

        state.loaded_skills.write().await.push(LoadedSkillSummary {
            id: "disabled-skill".to_string(),
            version: "1.0".to_string(),
            description: "Disabled".to_string(),
            tool_name: Some("disabled_tool".to_string()),
            hook_points: vec![],
            enabled: false,
            output_schema: None,
        });

        // Even with high errors, disabled skills should not degrade readiness.
        let metrics = Arc::new(SkillMetrics {
            invocations: AtomicU64::new(10),
            errors: AtomicU64::new(10),
            last_invoked_at: std::sync::Mutex::new(None),
        });
        state
            .skill_metrics
            .write()
            .await
            .insert("disabled-skill".to_string(), metrics);

        let report = collect_readiness(&state).await;
        assert_eq!(report.skills.status, ReadinessStatus::Ready);
        assert!(report
            .skills
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 loaded, 0 enabled"));
    }

    #[tokio::test]
    async fn readiness_skills_not_degraded_with_too_few_samples() {
        use crate::state::{LoadedSkillSummary, SkillMetrics};
        use std::sync::atomic::AtomicU64;

        let state = make_test_state(true, AppConfig::default());

        state.loaded_skills.write().await.push(LoadedSkillSummary {
            id: "small-sample-skill".to_string(),
            version: "1.0".to_string(),
            description: "Small sample".to_string(),
            tool_name: Some("small_tool".to_string()),
            hook_points: vec![],
            enabled: true,
            output_schema: None,
        });

        // 1/1 errors is high ratio but below MIN_SKILL_INVOCATIONS_FOR_DEGRADE.
        let metrics = Arc::new(SkillMetrics {
            invocations: AtomicU64::new(1),
            errors: AtomicU64::new(1),
            last_invoked_at: std::sync::Mutex::new(None),
        });
        state
            .skill_metrics
            .write()
            .await
            .insert("small-sample-skill".to_string(), metrics);

        let report = collect_readiness(&state).await;
        assert_eq!(report.skills.status, ReadinessStatus::Ready);
    }

    #[tokio::test]
    async fn readiness_channels_not_degraded_when_channel_config_present_but_env_missing() {
        let mut config = AppConfig::default();
        let _guard = EnvVarGuard::unset("ENCMIND_READINESS_TEST_TELEGRAM_TOKEN_MISSING");
        config.channels.telegram = Some(TelegramConfig {
            bot_token_env: "ENCMIND_READINESS_TEST_TELEGRAM_TOKEN_MISSING".to_string(),
            mode: TelegramMode::Polling,
            webhook_url: None,
            ..Default::default()
        });
        let mut state = make_test_state(true, config);
        state.channel_router = Some(Arc::new(ChannelRouter::new(
            state.config.read().await.channels.access_policy.clone(),
            state.session_store.clone(),
        )));

        let report = collect_readiness(&state).await;
        assert_eq!(report.channels.status, ReadinessStatus::Ready);
        assert_eq!(report.status, ReadinessStatus::Ready);
        assert!(report
            .channels
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("0 configured, 0 not running"));
    }

    #[tokio::test]
    async fn readiness_channels_degraded_when_gmail_env_refs_declared_but_values_missing() {
        let mut config = AppConfig::default();
        let _cid_guard = EnvVarGuard::unset("ENCMIND_READINESS_TEST_GMAIL_CID_MISSING");
        let _csec_guard = EnvVarGuard::unset("ENCMIND_READINESS_TEST_GMAIL_CSEC_MISSING");
        let _rt_guard = EnvVarGuard::unset("ENCMIND_READINESS_TEST_GMAIL_RT_MISSING");
        config.channels.gmail = Some(encmind_core::config::GmailConfig {
            client_id_env: "ENCMIND_READINESS_TEST_GMAIL_CID_MISSING".to_string(),
            client_secret_env: "ENCMIND_READINESS_TEST_GMAIL_CSEC_MISSING".to_string(),
            refresh_token_env: "ENCMIND_READINESS_TEST_GMAIL_RT_MISSING".to_string(),
            ..Default::default()
        });

        let mut state = make_test_state(true, config);
        state.channel_router = Some(Arc::new(ChannelRouter::new(
            state.config.read().await.channels.access_policy.clone(),
            state.session_store.clone(),
        )));

        let report = collect_readiness(&state).await;
        assert_eq!(report.channels.status, ReadinessStatus::Degraded);
        assert_eq!(report.status, ReadinessStatus::Degraded);
        assert!(report
            .channels
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 configured, 1 not running"));
    }

    #[tokio::test]
    async fn readiness_channels_degraded_when_partial_multifield_env_is_set() {
        let mut config = AppConfig::default();
        config.channels.gmail = Some(encmind_core::config::GmailConfig {
            client_id_env: "ENCMIND_READINESS_TEST_GMAIL_CID_PARTIAL".to_string(),
            client_secret_env: "ENCMIND_READINESS_TEST_GMAIL_CSEC_PARTIAL".to_string(),
            refresh_token_env: "ENCMIND_READINESS_TEST_GMAIL_RT_PARTIAL".to_string(),
            ..Default::default()
        });
        let _cid_guard = EnvVarGuard::set("ENCMIND_READINESS_TEST_GMAIL_CID_PARTIAL", "cid");
        let _csec_guard = EnvVarGuard::unset("ENCMIND_READINESS_TEST_GMAIL_CSEC_PARTIAL");
        let _rt_guard = EnvVarGuard::unset("ENCMIND_READINESS_TEST_GMAIL_RT_PARTIAL");

        let mut state = make_test_state(true, config);
        state.channel_router = Some(Arc::new(ChannelRouter::new(
            state.config.read().await.channels.access_policy.clone(),
            state.session_store.clone(),
        )));

        let report = collect_readiness(&state).await;
        assert_eq!(report.channels.status, ReadinessStatus::Degraded);
        assert_eq!(report.status, ReadinessStatus::Degraded);
        assert!(report
            .channels
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 configured, 1 not running"));
    }
}
