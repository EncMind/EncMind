use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{FutureExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use encmind_agent::context::ContextConfig;
use encmind_agent::firewall::EgressFirewall;
use encmind_agent::lockdown::LockdownManager;
use encmind_agent::pool::AgentPool;
use encmind_agent::registry::SqliteAgentRegistry;
use encmind_agent::runtime::RuntimeConfig;
use encmind_agent::subagent::SpawnAgentHandler;
use encmind_agent::tool_registry::ToolRegistry;
use encmind_channels::cron_dispatcher::CronDispatcher;
use encmind_channels::router::ChannelRouter;
use encmind_channels::slack::SlackAdapter;
use encmind_channels::telegram::TelegramAdapter;
use encmind_channels::transform::{ChannelTransform, TransformChain};
use encmind_core::config::{
    AccessAction, ApiProviderConfig, AppConfig, BrowserStartupPolicy, FirewallMode, InferenceMode,
    ServerProfile, VectorBackendConfig,
};
use encmind_core::error::LlmError;
use encmind_core::plugin::NativePlugin;
use encmind_core::policy::{resolve_resource_limits, PolicyDecision, PolicyEnforcer};
use encmind_core::traits::{
    AgentRegistry, ApiKeyStore, ChannelAdapter, DeviceStore, Embedder, LlmBackend,
    MemoryMetadataStore, SessionStore, VectorStore,
};
use encmind_core::types::{
    Attachment, ChannelAccountStatus, ChannelTarget, ConfigSource, ContentBlock, InboundMessage,
    Message, MessageId, OutboundMessage, Role, SkillApprovalRequest, SkillApprovalResponse,
};
use encmind_llm::anthropic::AnthropicBackend;
use encmind_llm::openai::OpenAiBackend;
use encmind_llm::LlmDispatcher;
use encmind_memory::embedding_mode::EmbeddingModeEnforcer;
use encmind_memory::memory_store::MemoryStoreImpl;
use encmind_memory::vector_store::SqliteVectorStore;
use encmind_storage::audit::AuditLogger;
use encmind_storage::device_store::SqliteDeviceStore;
use encmind_storage::encryption::Aes256GcmAdapter;
use encmind_storage::memory_metadata::SqliteMemoryMetadataStore;
use encmind_storage::session_store::SqliteSessionStore;

use encmind_core::hooks::{HookContext, HookPoint, HookRegistry, HookResult};

use crate::approval::gateway_approval_policy;
use crate::budget::ApiBudgetTracker;
use crate::channel_manager::ChannelAdapterManager;
use crate::idempotency::IdempotencyCache;
use crate::local_tool_policy::LocalToolPolicyEngine;
use crate::node::NodeRegistry;
use crate::plugin_api::{RegisteredPluginTimer, RegisteredPluginTransform};
use crate::plugin_manager::PluginManager;
use crate::rate_limiter::SessionRateLimiter;
use crate::routes::build_router;
use crate::skill_timer::{
    reconcile_all_timers, SkillTimerLimits, SkillTimerRunner, SkillTimerRuntimeSpec,
    TimerWasmDependencies,
};
use crate::state::{
    AppState, LoadedSkillRuntimeSpec, LoadedSkillSummary, NativePluginTimerHandle,
    NativePluginTimerRuntime, PendingSkillApproval, RuntimeResources, SkillMetrics,
};
use crate::tls::TlsLifecycleManager;
use crate::tls_listener::TlsTcpListener;
use crate::wasm_channel_transform::{
    WasmChannelTransform, WasmTransformDependencies, WasmTransformRuntimeConfig,
};
use crate::{device_auth::NonceStore, pairing::PairingSession};

/// Run the gateway server with the given configuration.
pub async fn run_gateway(
    config: AppConfig,
    shutdown: CancellationToken,
) -> Result<(), anyhow::Error> {
    // Install rustls CryptoProvider before any TLS operations. Required when
    // both `aws-lc-rs` and `ring` features are active in the dependency tree
    // (qdrant-client brings `ring` via tonic).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Validate configuration before proceeding
    let validation_errors = config.validate();
    if !validation_errors.is_empty() {
        anyhow::bail!("config validation failed: {}", validation_errors.join("; "));
    }
    let shutdown_join_timeout =
        Duration::from_secs(config.server.shutdown_timeout_secs.max(1) as u64);

    let heartbeat_interval_ms = config.gateway.heartbeat_interval_ms.max(1000);
    let max_connections = config.gateway.max_connections.max(1) as usize;
    let mdns_enabled = config.gateway.mdns_enabled;

    // Create storage pool
    let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
    info!(db_path = %config.storage.db_path.display(), "database connected");

    // Run migrations
    {
        let conn = pool
            .get()
            .map_err(|e| anyhow::anyhow!("failed to get DB connection: {e}"))?;
        encmind_storage::migrations::run_migrations(&conn)?;
        info!("migrations applied");
    }

    // Derive encryption key
    let tee = encmind_tee::detect_tee();
    let data_dir = config
        .storage
        .db_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let key = encmind_storage::key_derivation::derive_key(
        &config.storage.key_source,
        tee.as_ref(),
        data_dir,
    )
    .await?;
    let encryption = Arc::new(Aes256GcmAdapter::new(&key));

    // Build stores
    let session_store: Arc<dyn SessionStore> =
        Arc::new(SqliteSessionStore::new(pool.clone(), encryption.clone()));
    let agent_registry: Arc<dyn AgentRegistry> = Arc::new(SqliteAgentRegistry::new(pool.clone()));
    let device_store: Arc<dyn DeviceStore> = Arc::new(SqliteDeviceStore::new(pool.clone()));

    // Build runtime components
    let audit_logger = Arc::new(AuditLogger::new(pool.clone()));
    let lockdown =
        Arc::new(LockdownManager::new(&config.security.lockdown).with_audit(audit_logger.clone()));
    let agent_pool = Arc::new(AgentPool::new(&config.agent_pool));
    let firewall = Arc::new(
        EgressFirewall::new(&config.security.egress_firewall).with_audit(audit_logger.clone()),
    );

    if config.security.egress_firewall.enabled
        && config.security.egress_firewall.mode == FirewallMode::DenyByDefault
        && config.security.egress_firewall.global_allowlist.is_empty()
        && config
            .security
            .egress_firewall
            .per_agent_overrides
            .values()
            .all(|v| v.is_empty())
    {
        warn!(
            "egress firewall is enabled with empty allowlist — all outbound requests will be blocked. \
             Add domains to security.egress_firewall.global_allowlist or set \
             mode to 'allow_public_internet' for development"
        );
    }

    // TLS setup
    let (tls_manager, auto_tls_fingerprint) = match (
        config.server.tls_cert_path.as_ref(),
        config.server.tls_key_path.as_ref(),
    ) {
        (Some(cert_path), Some(key_path)) => {
            let mgr = TlsLifecycleManager::from_files(
                cert_path,
                key_path,
                &config.security.tls_lifecycle,
            )?;
            (Some(Arc::new(mgr)), None)
        }
        (None, None) if config.server.auto_tls => {
            let tls_dir = auto_tls_dir_for_db_path(&config.storage.db_path);
            let sans = crate::tls::auto_tls_sans();
            let (mgr, fingerprint) =
                TlsLifecycleManager::auto_tls(&tls_dir, sans, &config.security.tls_lifecycle)?;
            (Some(Arc::new(mgr)), Some(fingerprint))
        }
        (None, None) => (None, None),
        _ => {
            return Err(anyhow::anyhow!(
                "both server.tls_cert_path and server.tls_key_path must be set together"
            ));
        }
    };

    let idempotency = Arc::new(Mutex::new(IdempotencyCache::new(
        config.gateway.idempotency_ttl_secs,
    )));
    let nonce_store = Arc::new(NonceStore::new());
    let node_registry = Arc::new(NodeRegistry::new());
    let connection_permits = Arc::new(Semaphore::new(max_connections));
    let pairing_sessions = Arc::new(Mutex::new(HashMap::<String, PairingSession>::new()));
    let admin_bootstrap_lock = Arc::new(AsyncMutex::new(()));
    let active_runs = Arc::new(Mutex::new(HashMap::<String, CancellationToken>::new()));
    let api_key_store: Arc<dyn ApiKeyStore> = Arc::new(
        encmind_storage::api_key_store::SqliteApiKeyStore::new(pool.clone(), encryption.clone()),
    );
    // Browser pool
    let browser_pool = if config.browser.enabled {
        match encmind_browser::pool::BrowserPool::new(
            config.browser.pool_size.max(1),
            config.browser.idle_timeout_secs,
            config.browser.no_sandbox,
        )
        .await
        {
            Ok(pool) => {
                info!(
                    pool_size = config.browser.pool_size,
                    no_sandbox = config.browser.no_sandbox,
                    "browser pool initialized"
                );
                Some(Arc::new(pool))
            }
            Err(e) => match config.browser.startup_policy {
                BrowserStartupPolicy::Required => {
                    return Err(anyhow::anyhow!(
                            "browser is enabled but initialization failed (startup_policy=required): {e}"
                        ));
                }
                BrowserStartupPolicy::BestEffort => {
                    warn!(
                        error = %e,
                        "failed to start browser pool; continuing with browser tools disabled (startup_policy=best_effort)"
                    );
                    None
                }
            },
        }
    } else {
        None
    };

    let shared_config = Arc::new(RwLock::new(config.clone()));

    let llm_backend_initial = rebuild_llm_backend(&config, Some(api_key_store.clone())).await;
    let mut tool_registry = initialize_tool_registry(
        &config,
        &llm_backend_initial,
        session_store.clone(),
        agent_registry.clone(),
        agent_pool.clone(),
        firewall.clone(),
        browser_pool.clone(),
        Some(node_registry.clone()),
        Some(device_store.clone()),
        Some(shared_config.clone()),
    );
    let memory_store = initialize_memory_store(&config, &pool).await?;

    // Build cron infrastructure before state so the dispatcher is available to handlers.
    let cron_store: Option<Arc<dyn encmind_core::traits::CronStore>> = Some(Arc::new(
        encmind_storage::cron_store::SqliteCronStore::new(pool.clone()),
    ));
    let agent_parallelism = config.agent_pool.max_concurrent_agents.max(1) as usize;
    let cron_parallelism = cron_dispatch_parallelism(agent_parallelism);
    if cron_parallelism >= agent_parallelism {
        warn!(
            agent_parallelism,
            cron_parallelism,
            "cron dispatch can occupy all agent slots; increase agent_pool.max_concurrent_agents to preserve interactive headroom"
        );
    }
    let cron_dispatcher = cron_store
        .as_ref()
        .map(|store| Arc::new(CronDispatcher::new(store.clone(), cron_parallelism)));
    let (channel_router, channel_adapters) =
        initialize_channel_router(&config, session_store.clone(), shutdown.clone()).await;

    // Backup manager
    let backup_manager = if config.backup.enabled {
        let backup_dir = config.storage.backup_dir.clone().unwrap_or_else(|| {
            config
                .storage
                .db_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("backups")
        });
        let enc: Option<Box<dyn encmind_core::traits::EncryptionAdapter>> =
            if config.backup.encryption {
                Some(Box::new(Aes256GcmAdapter::new(&key)))
            } else {
                None
            };
        match encmind_storage::backup::BackupManager::new(
            pool.clone(),
            backup_dir.clone(),
            enc,
            config.backup.retention.clone(),
        ) {
            Ok(mgr) => {
                info!(backup_dir = %backup_dir.display(), "backup manager enabled");
                Some(Arc::new(mgr))
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "backup is enabled but initialization failed: {e}"
                ));
            }
        }
    } else {
        None
    };

    // Initialize plugin system
    let mut hook_registry_raw = HookRegistry::new();
    // Create runtime Arc early so plugins (e.g. NetProbe synthesis) can reference
    // the LLM backend. The tool_registry will be replaced after plugin init.
    let shared_runtime = Arc::new(RwLock::new(RuntimeResources {
        llm_backend: llm_backend_initial.clone(),
        tool_registry: Arc::new(ToolRegistry::new()),
    }));
    let native_plugins = build_native_plugins(
        &config,
        browser_pool.clone(),
        firewall.clone(),
        shared_runtime.clone(),
    );
    let plugin_manager = if native_plugins.is_empty() {
        None
    } else {
        // Build per-plugin contexts (config + state store)
        let mut plugin_contexts = std::collections::HashMap::new();
        for plugin in &native_plugins {
            let pid = plugin.manifest().id;
            plugin_contexts.insert(
                pid.clone(),
                crate::plugin_manager::PluginContext {
                    config: config.plugins.get(&pid).cloned(),
                    state_store: Some(Arc::new(
                        encmind_storage::plugin_state::SqlitePluginStateStore::new(
                            pool.clone(),
                            &pid,
                        ),
                    )
                        as Arc<dyn encmind_core::plugin::PluginStateStore>),
                },
            );
        }
        let manager = PluginManager::initialize(
            native_plugins,
            &mut tool_registry,
            &mut hook_registry_raw,
            plugin_contexts,
        )
        .await?;
        info!(
            plugin_count = manager.plugin_count(),
            method_count = manager.method_count(),
            "plugin manager initialized"
        );
        if manager.is_degraded() {
            let detail = serde_json::json!({
                "loaded_count": manager.plugin_count(),
                "loaded": manager.plugin_ids(),
                "failed": manager.failed_plugins(),
            })
            .to_string();
            if let Err(e) =
                audit_logger.append("plugin", "startup_degraded", Some(detail.as_str()), None)
            {
                warn!(error = %e, "failed to append startup degraded plugin audit event");
            }
        }
        Some(Arc::new(manager))
    };
    let pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let skill_metrics: Arc<RwLock<HashMap<String, Arc<SkillMetrics>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let wasm_db_pool = Arc::new(pool.clone());
    let wasm_http_client = Arc::new(reqwest::Client::new());
    let skill_toggle_store: Arc<dyn encmind_core::traits::SkillToggleStore> =
        Arc::new(encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool.clone()));

    // Load WASM skills from configured skills directory.
    let skills_dir = resolve_skills_dir(&config);
    let loaded_wasm = load_wasm_skills_startup(
        &config,
        &skills_dir,
        &mut tool_registry,
        session_store.clone(),
        &mut hook_registry_raw,
        wasm_db_pool.clone(),
        firewall.clone(),
        wasm_http_client.clone(),
        pending_approvals.clone(),
        Some(skill_toggle_store.clone()),
        Some(audit_logger.clone()),
        skill_metrics.clone(),
    )
    .await;

    let mut startup_hook_ctx = HookContext {
        session_id: None,
        agent_id: None,
        method: None,
        payload: serde_json::json!({}),
    };
    match hook_registry_raw
        .execute(HookPoint::OnStartup, &mut startup_hook_ctx)
        .await?
    {
        HookResult::Continue | HookResult::Override(_) => {}
        HookResult::Abort { reason } => {
            return Err(anyhow::anyhow!(
                "startup hook aborted gateway startup: {reason}"
            ));
        }
    }

    let hook_registry = Arc::new(RwLock::new(hook_registry_raw));
    let outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy> =
        Arc::new(GatewayOutboundPolicy {
            firewall: firewall.clone(),
        });
    let approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter> =
        Arc::new(GatewayApprovalPrompter {
            pending_approvals: pending_approvals.clone(),
        });
    let native_transforms = plugin_manager
        .as_ref()
        .map(|pm| pm.registered_transforms().to_vec())
        .unwrap_or_default();
    let native_timers = plugin_manager
        .as_ref()
        .map(|pm| pm.registered_timers().to_vec())
        .unwrap_or_default();
    let native_plugin_timer_cancel = CancellationToken::new();
    let native_plugin_timer_handles =
        spawn_native_plugin_timer_tasks(&native_timers, native_plugin_timer_cancel.clone());
    let initial_channel_transforms = build_transform_chains(
        &config,
        &loaded_wasm.runtime_specs,
        &native_transforms,
        pool.clone(),
        wasm_http_client.clone(),
        hook_registry.clone(),
        outbound_policy.clone(),
        approval_prompter.clone(),
        audit_logger.clone(),
    );
    let skill_timer_store: Arc<dyn encmind_core::traits::SkillTimerStore> =
        Arc::new(encmind_storage::skill_timer_store::SqliteSkillTimerStore::new(pool.clone()));
    let skill_timer_runner = Arc::new(
        SkillTimerRunner::new(
            skill_timer_store.clone(),
            config.agent_pool.max_concurrent_agents.max(1) as usize,
            10,
        )
        .with_wasm_dependencies(TimerWasmDependencies {
            db_pool: Arc::new(pool.clone()),
            http_client: wasm_http_client.clone(),
            outbound_policy: outbound_policy.clone(),
            hook_registry: hook_registry.clone(),
            approval_prompter: approval_prompter.clone(),
        })
        .with_audit_logger(audit_logger.clone()),
    );
    skill_timer_runner
        .set_skill_limits(build_skill_timer_limits(&loaded_wasm.runtime_specs))
        .await;
    skill_timer_runner
        .set_skill_runtime_specs(build_skill_timer_runtime_specs(&loaded_wasm.runtime_specs))
        .await;
    if let Err(e) = reconcile_all_timers(
        skill_timer_store.as_ref(),
        &build_timer_reconcile_data(&loaded_wasm.runtime_specs),
    )
    .await
    {
        warn!(error = %e, "failed to reconcile skill timers at startup");
    }
    let channel_startup_intent = Arc::new(crate::state::compute_channel_startup_intent(&config));
    let state = AppState {
        session_store,
        agent_registry,
        device_store,
        lockdown,
        agent_pool,
        runtime: {
            // Update the shared_runtime with the final tool_registry (after plugin init).
            let mut rt = shared_runtime.write().await;
            rt.tool_registry = Arc::new(tool_registry);
            drop(rt);
            shared_runtime.clone()
        },
        api_key_store: Some(api_key_store),
        firewall,
        audit: audit_logger,
        config: shared_config,
        tls: tls_manager.clone(),
        node_registry,
        connection_permits,
        idempotency,
        nonce_store,
        pairing_sessions,
        admin_bootstrap_lock,
        active_runs,
        timeline_store: Some(Arc::new(
            encmind_storage::timeline_store::SqliteTimelineStore::new(pool.clone()),
        )),
        skill_timer_store: Some(skill_timer_store),
        skill_timer_runner: Some(skill_timer_runner.clone()),
        db_pool: pool.clone(),
        memory_store,
        cron_store,
        cron_dispatcher,
        channel_router: Some(channel_router.clone()),
        channel_manager: Arc::new(ChannelAdapterManager::new(shutdown.clone())),
        channel_startup_intent,
        backup_manager,
        browser_pool,
        hook_registry,
        plugin_manager: Arc::new(RwLock::new(plugin_manager)),
        loaded_skills: Arc::new(RwLock::new(loaded_wasm.summaries)),
        known_skill_ids: Arc::new(RwLock::new(loaded_wasm.known_skill_ids)),
        pending_approvals,
        wasm_http_client,
        channel_transforms: Arc::new(RwLock::new(initial_channel_transforms)),
        refresh_lock: Arc::new(RwLock::new(())),
        skill_toggle_store: Some(skill_toggle_store),
        skill_toggle_lock: Arc::new(AsyncMutex::new(())),
        skill_resources_lock: Arc::new(AsyncMutex::new(())),
        skill_metrics: skill_metrics.clone(),
        native_plugin_timers: Arc::new(AsyncMutex::new(NativePluginTimerRuntime {
            cancel: native_plugin_timer_cancel,
            handles: native_plugin_timer_handles,
        })),
        native_timer_replace_lock: Arc::new(AsyncMutex::new(())),
        session_rate_limiter: Arc::new(SessionRateLimiter::new(
            config.security.rate_limit.messages_per_minute,
        )),
        api_budget_tracker: config
            .security
            .rate_limit
            .api_budget_usd
            .map(|budget| Arc::new(ApiBudgetTracker::new(budget))),
        channel_account_store: Some(Arc::new(
            encmind_storage::channel_account_store::SqliteChannelAccountStore::new(
                pool.clone(),
                encryption.clone(),
            ),
        )),
    };

    let app = build_router(state.clone());
    // Register boot-time channel adapters with the manager
    for (channel_name, adapter) in channel_adapters {
        let router = channel_router.clone();
        let runtime_state = state.clone();
        let shutdown_token = shutdown.clone();
        let cn = channel_name.clone();

        if let Err(e) = state
            .channel_manager
            .start_adapter(&channel_name, adapter, move |a, cancel| {
                let inbound = a.inbound();
                tokio::spawn(async move {
                    channel_inbound_loop(
                        runtime_state,
                        router,
                        a,
                        cn,
                        inbound,
                        shutdown_token,
                        cancel,
                    )
                    .await;
                })
            })
            .await
        {
            warn!(
                channel = %channel_name,
                error = %e,
                "failed to register boot-time adapter with manager"
            );
        }
    }

    // Restore API-managed channel adapters from encrypted credentials.
    restore_api_channel_adapters(&state, channel_router.clone()).await;
    let active_channels = state.channel_manager.running_channel_types().await;
    if !active_channels.is_empty() && channel_policy_blocks_all(&config, &active_channels) {
        warn!(
            channels = %active_channels.join(","),
            "channel access policy blocks all active inbound adapters (default_action=reject and allowlist is empty)"
        );
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;

    if config.server.profile == ServerProfile::Remote && config.server.host == "127.0.0.1" {
        warn!("remote profile with host=127.0.0.1 will not be reachable remotely");
    }

    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    info!(addr = %bound_addr, "gateway listening");

    // Print auto-TLS connection info
    if let Some(ref fingerprint) = auto_tls_fingerprint {
        let scheme = "wss";
        info!("Auto-generated TLS certificate (self-signed)");
        info!("Certificate fingerprint: {fingerprint}");
        info!("Listening on {scheme}://{bound_addr}");
        info!("");
        info!("Connect from a remote device:");
        info!(
            "  encmind-edge --gateway {scheme}://YOUR_IP:{} \\",
            bound_addr.port()
        );
        info!("    --fingerprint {fingerprint} \\");
        info!("    pair --name \"my-device\"");
    }

    let mut mdns_advertiser = None;
    if mdns_enabled {
        match crate::mdns::MdnsAdvertiser::new(bound_addr.port(), "encmind-gateway") {
            Ok(advertiser) => {
                info!(port = bound_addr.port(), "mDNS advertising enabled");
                mdns_advertiser = Some(advertiser);
            }
            Err(e) => {
                warn!(error = %e, "failed to start mDNS advertising");
            }
        }
    }

    let maintenance_shutdown = shutdown.clone();
    let maintenance_state = state.clone();
    let maintenance_handle = tokio::spawn(async move {
        maintenance_loop(
            maintenance_state,
            maintenance_shutdown,
            heartbeat_interval_ms,
        )
        .await;
    });

    let cron_handle = if let Some(dispatcher) = state.cron_dispatcher.clone() {
        let cron_shutdown = shutdown.clone();
        let cron_state = state.clone();
        let check_interval_secs = config.cron.check_interval_secs.max(1);
        Some(tokio::spawn(async move {
            cron_loop(cron_state, dispatcher, cron_shutdown, check_interval_secs).await;
        }))
    } else {
        None
    };
    let skill_timer_handle = if let Some(timer_runner) = state.skill_timer_runner.clone() {
        let timer_shutdown = shutdown.clone();
        let error_policy = config.skill_error_policy.clone();
        Some(tokio::spawn(async move {
            timer_runner.run_loop(timer_shutdown, error_policy).await;
        }))
    } else {
        None
    };

    let serve_result = if let Some(tls_manager) = tls_manager {
        if auto_tls_fingerprint.is_some() {
            info!("auto-TLS enabled (self-signed)");
        } else {
            info!("native TLS enabled");
        }
        let tls_listener = TlsTcpListener::new(listener, tls_manager);
        axum::serve(
            tls_listener,
            app.into_make_service_with_connect_info::<crate::routes::PeerAddr>(),
        )
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .await
    } else {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<crate::routes::PeerAddr>(),
        )
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .await
    };

    shutdown.cancel();

    // Cancel all active agent runs so in-flight requests terminate promptly.
    {
        let active: Vec<(String, CancellationToken)> =
            state.active_runs.lock().unwrap().drain().collect();
        if !active.is_empty() {
            info!(count = active.len(), "cancelling active runs for shutdown");
            for (_session_id, token) in &active {
                token.cancel();
            }
        }
    }

    match tokio::time::timeout(shutdown_join_timeout, maintenance_handle).await {
        Ok(join_result) => {
            let _ = join_result;
        }
        Err(_) => {
            warn!(
                timeout_secs = shutdown_join_timeout.as_secs(),
                "maintenance task did not stop before shutdown timeout"
            );
        }
    }
    if let Some(handle) = cron_handle {
        if tokio::time::timeout(shutdown_join_timeout, handle)
            .await
            .is_err()
        {
            warn!(
                timeout_secs = shutdown_join_timeout.as_secs(),
                "cron loop did not stop before shutdown timeout"
            );
        }
    }
    if let Some(handle) = skill_timer_handle {
        if tokio::time::timeout(shutdown_join_timeout, handle)
            .await
            .is_err()
        {
            warn!(
                timeout_secs = shutdown_join_timeout.as_secs(),
                "skill timer loop did not stop before shutdown timeout"
            );
        }
    }
    // Reuse bounded shutdown semantics for native plugin timer tasks.
    replace_native_plugin_timer_tasks(&state, &[]).await;
    // Stop all channel adapters via the manager.
    state.channel_manager.stop_all().await;
    let hook_registry_snapshot = { state.hook_registry.read().await.clone() };
    let mut shutdown_hook_ctx = HookContext {
        session_id: None,
        agent_id: None,
        method: None,
        payload: serde_json::json!({}),
    };
    match hook_registry_snapshot
        .execute(HookPoint::OnShutdown, &mut shutdown_hook_ctx)
        .await
    {
        Ok(HookResult::Continue | HookResult::Override(_)) => {}
        Ok(HookResult::Abort { reason }) => {
            warn!(reason = %reason, "shutdown hook aborted; continuing shutdown");
        }
        Err(e) => {
            warn!(error = %e, "shutdown hook execution failed");
        }
    }
    let plugin_manager = { state.plugin_manager.read().await.clone() };
    if let Some(ref plugin_manager) = plugin_manager {
        plugin_manager.shutdown().await;
    }
    if let Some(advertiser) = mdns_advertiser {
        if let Err(e) = advertiser.shutdown() {
            warn!(error = %e, "failed to stop mDNS advertising cleanly");
        }
    }

    // Write a final audit entry recording clean shutdown.
    if let Err(e) = state
        .audit
        .append("system", "shutdown", Some("clean"), None)
    {
        warn!(error = %e, "failed to write shutdown audit entry");
    }

    serve_result?;

    info!("gateway stopped");
    Ok(())
}

type RunningChannelAdapter = (String, Arc<dyn ChannelAdapter>);
const CHANNEL_GENERIC_ERROR_REPLY: &str =
    "I couldn't process that message right now. Please try again.";

async fn initialize_channel_router(
    config: &AppConfig,
    session_store: Arc<dyn SessionStore>,
    shutdown: CancellationToken,
) -> (Arc<ChannelRouter>, Vec<RunningChannelAdapter>) {
    let mut router = ChannelRouter::new(config.channels.access_policy.clone(), session_store);
    let mut adapters: Vec<RunningChannelAdapter> = Vec::new();
    let configured_channels = configured_inbound_channels(config);
    let mut startup_intent_channels: Vec<String> =
        crate::state::compute_channel_startup_intent(config)
            .into_iter()
            .collect();
    startup_intent_channels.sort();

    if configured_channels.is_empty() {
        info!("no inbound channel adapters configured");
    } else if startup_intent_channels.is_empty() {
        info!(
            channels = %configured_channels.join(","),
            "inbound channels configured; no boot-time env credentials detected (API account restore/login can activate adapters)"
        );
    } else {
        info!(
            configured = %configured_channels.join(","),
            startup_intent = %startup_intent_channels.join(","),
            "initializing inbound channel adapters"
        );
    }

    if let Some(telegram_config) = config.channels.telegram.clone() {
        match TelegramAdapter::new(telegram_config) {
            Ok(adapter) => {
                adapter.set_runtime_shutdown(shutdown.clone()).await;
                let adapter: Arc<dyn ChannelAdapter> = Arc::new(adapter);
                router.register_adapter("telegram", adapter.clone());
                adapters.push(("telegram".to_string(), adapter));
                info!("telegram channel adapter initialized");
            }
            Err(e) => {
                warn!(error = %e, "telegram adapter disabled due to configuration error");
            }
        }
    }

    if let Some(slack_config) = config.channels.slack.clone() {
        match SlackAdapter::new(slack_config) {
            Ok(adapter) => {
                adapter.set_runtime_shutdown(shutdown.clone()).await;
                let adapter: Arc<dyn ChannelAdapter> = Arc::new(adapter);
                router.register_adapter("slack", adapter.clone());
                adapters.push(("slack".to_string(), adapter));
                info!("slack channel adapter initialized");
            }
            Err(e) => {
                warn!(error = %e, "slack adapter disabled due to configuration error");
            }
        }
    }

    if let Some(gmail_config) = config.channels.gmail.clone() {
        match gmail_boot_credential_json(&gmail_config) {
            Ok(Some(cred_json)) => {
                match encmind_channels::gmail::GmailAdapter::from_config_and_credentials(
                    gmail_config,
                    &cred_json,
                ) {
                    Ok(adapter) => {
                        let adapter: Arc<dyn ChannelAdapter> = Arc::new(adapter);
                        router.register_adapter("gmail", adapter.clone());
                        adapters.push(("gmail".to_string(), adapter));
                        info!("gmail channel adapter initialized");
                    }
                    Err(e) => {
                        warn!(error = %e, "gmail adapter disabled due to configuration error");
                    }
                }
            }
            Ok(None) => {
                info!("gmail adapter not initialized from env credentials (using API login flow)");
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "gmail adapter disabled due to invalid env credential configuration"
                );
            }
        }
    }

    if adapters.is_empty() && !startup_intent_channels.is_empty() {
        warn!(
            channels = %startup_intent_channels.join(","),
            "no configured channel adapters started; check channel token env vars and outbound connectivity"
        );
    }

    (Arc::new(router), adapters)
}

async fn restore_api_channel_adapters(state: &AppState, router: Arc<ChannelRouter>) {
    let Some(store) = state.channel_account_store.as_ref() else {
        return;
    };

    let config = { state.config.read().await.clone() };
    let accounts = match store.list_accounts().await {
        Ok(accounts) => accounts,
        Err(e) => {
            warn!(error = %e, "failed to list channel accounts for restore");
            return;
        }
    };

    for account in accounts {
        if account.config_source != ConfigSource::Api || !account.enabled {
            continue;
        }
        if !matches!(
            account.status,
            ChannelAccountStatus::Active
                | ChannelAccountStatus::Degraded
                | ChannelAccountStatus::LoginRequired
        ) {
            continue;
        }

        // Explicit precedence: if a boot-time config adapter is already running for this
        // channel type, keep it and skip API-account restore.
        if state
            .channel_manager
            .is_running(&account.channel_type)
            .await
        {
            warn!(
                channel = %account.channel_type,
                account_id = %account.id,
                "skipping API channel account restore because a boot-time adapter is already running"
            );
            let _ = store
                .update_status(&account.id, ChannelAccountStatus::Degraded)
                .await;
            continue;
        }

        let cred_json = match store.get_credential(&account.id).await {
            Ok(Some(cred)) => cred,
            Ok(None) => {
                warn!(
                    account_id = %account.id,
                    channel = %account.channel_type,
                    "no credential found for restorable API channel account"
                );
                let _ = store
                    .update_status(&account.id, ChannelAccountStatus::LoginRequired)
                    .await;
                continue;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    channel = %account.channel_type,
                    account_id = %account.id,
                    "failed to load credential for API channel account restore"
                );
                let _ = store
                    .update_status(&account.id, ChannelAccountStatus::Error)
                    .await;
                continue;
            }
        };

        let adapter = match encmind_channels::adapter_from_credentials(
            &account.channel_type,
            &config,
            &cred_json,
        ) {
            Ok(adapter) => adapter,
            Err(e) => {
                warn!(
                    error = %e,
                    channel = %account.channel_type,
                    account_id = %account.id,
                    "failed to construct channel adapter from stored credential"
                );
                let _ = store
                    .update_status(&account.id, ChannelAccountStatus::Error)
                    .await;
                continue;
            }
        };

        let target_status = match adapter.probe().await {
            Ok(()) => {
                let runtime_state = state.clone();
                let runtime_router = router.clone();
                let channel_name = account.channel_type.clone();
                let shutdown_token = state.channel_manager.global_shutdown().clone();
                match state
                    .channel_manager
                    .start_adapter(&account.channel_type, adapter, move |a, cancel| {
                        let inbound = a.inbound();
                        tokio::spawn(async move {
                            channel_inbound_loop(
                                runtime_state,
                                runtime_router,
                                a,
                                channel_name,
                                inbound,
                                shutdown_token,
                                cancel,
                            )
                            .await;
                        })
                    })
                    .await
                {
                    Ok(()) => ChannelAccountStatus::Active,
                    Err(e) => {
                        warn!(
                            error = %e,
                            channel = %account.channel_type,
                            account_id = %account.id,
                            "failed to start restored channel adapter"
                        );
                        ChannelAccountStatus::Error
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    channel = %account.channel_type,
                    account_id = %account.id,
                    "probe failed for restored channel adapter"
                );
                ChannelAccountStatus::Degraded
            }
        };

        let _ = store.update_status(&account.id, target_status).await;
    }
}

fn configured_inbound_channels(config: &AppConfig) -> Vec<&'static str> {
    let mut channels = Vec::new();
    if config.channels.telegram.is_some() {
        channels.push("telegram");
    }
    if config.channels.slack.is_some() {
        channels.push("slack");
    }
    if config.channels.gmail.is_some() {
        channels.push("gmail");
    }
    channels
}

fn gmail_boot_credential_json(
    config: &encmind_core::config::GmailConfig,
) -> Result<Option<String>, String> {
    let cid_env = config.client_id_env.trim();
    let csec_env = config.client_secret_env.trim();
    let rt_env = config.refresh_token_env.trim();

    if cid_env.is_empty() && csec_env.is_empty() && rt_env.is_empty() {
        return Ok(None);
    }
    if cid_env.is_empty() || csec_env.is_empty() || rt_env.is_empty() {
        return Err(
            "gmail env credential config is partial; set client_id_env, client_secret_env, and refresh_token_env together".to_string(),
        );
    }

    let read = |name: &str| -> Result<String, String> {
        match std::env::var(name) {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    Err(format!("env var {name} is set but empty"))
                } else {
                    Ok(trimmed.to_string())
                }
            }
            Err(_) => Err(format!("required env var {name} is not set")),
        }
    };

    let client_id = read(cid_env)?;
    let client_secret = read(csec_env)?;
    let refresh_token = read(rt_env)?;
    Ok(Some(
        serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        })
        .to_string(),
    ))
}

fn channel_policy_blocks_all(config: &AppConfig, active_channels: &[String]) -> bool {
    let policy = &config.channels.access_policy;
    if policy.default_action != AccessAction::Reject || !policy.allowlist.is_empty() {
        return false;
    }
    // Gmail can derive an effective inbound allowlist from `channels.gmail.allowed_senders`,
    // but only if a Gmail adapter is actually active.
    if active_channels.iter().any(|channel| channel == "gmail")
        && config
            .channels
            .gmail
            .as_ref()
            .is_some_and(|gmail| !gmail.allowed_senders.is_empty())
    {
        return false;
    }
    true
}

fn apply_gmail_allowlist_fallback(
    channel_name: &str,
    resolved_policy: &mut encmind_channels::router::ResolvedPolicy,
    global_policy: &encmind_core::config::InboundAccessPolicy,
    account_policy: Option<&encmind_core::types::ChannelPolicy>,
    gmail_allowed_senders: &[String],
) {
    if channel_name != "gmail" || gmail_allowed_senders.is_empty() {
        return;
    }
    let account_has_explicit_allowlist = account_policy.is_some_and(|p| !p.allowlist.is_empty());
    let global_has_explicit_allowlist = global_policy
        .allowlist
        .iter()
        .any(|entry| entry.channel == "gmail");
    if !account_has_explicit_allowlist && !global_has_explicit_allowlist {
        resolved_policy.allowlist = gmail_allowed_senders.to_vec();
        resolved_policy.default_action = AccessAction::Reject;
    }
}

async fn apply_channel_inbound_transform(
    state: &AppState,
    msg: InboundMessage,
) -> Option<InboundMessage> {
    let channel = msg.channel.clone();
    let transform_chain = {
        let chains = state.channel_transforms.read().await;
        chains.get(&channel).cloned()
    };
    let Some(chain) = transform_chain else {
        return Some(msg);
    };
    match chain.apply_inbound(msg).await {
        Ok(Some(transformed)) => Some(transformed),
        Ok(None) => {
            info!(channel = %channel, "inbound channel message dropped by transform");
            None
        }
        Err(e) => {
            warn!(
                channel = %channel,
                error = %e,
                "inbound channel transform failed"
            );
            None
        }
    }
}

async fn apply_channel_outbound_transform(
    state: &AppState,
    channel: &str,
    msg: OutboundMessage,
) -> Option<OutboundMessage> {
    let transform_chain = {
        let chains = state.channel_transforms.read().await;
        chains.get(channel).cloned()
    };
    let Some(chain) = transform_chain else {
        return Some(msg);
    };
    match chain.apply_outbound(msg).await {
        Ok(Some(transformed)) => Some(transformed),
        Ok(None) => {
            info!(channel = %channel, "outbound channel message dropped by transform");
            None
        }
        Err(e) => {
            warn!(
                channel = %channel,
                error = %e,
                "outbound channel transform failed"
            );
            None
        }
    }
}

pub(crate) async fn channel_inbound_loop(
    state: AppState,
    router: Arc<ChannelRouter>,
    adapter: Arc<dyn ChannelAdapter>,
    channel_name: String,
    mut inbound: Pin<Box<dyn futures::Stream<Item = InboundMessage> + Send>>,
    shutdown: CancellationToken,
    adapter_cancel: CancellationToken,
) {
    loop {
        tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = adapter_cancel.cancelled() => break,
                maybe_msg = inbound.next() => {
                    let Some(msg) = maybe_msg else { break; };

                    let Some(mut msg) = apply_channel_inbound_transform(&state, msg).await else {
                        continue;
                    };

                let account_policy = if let Some(store) = state.channel_account_store.as_ref() {
                    match store.get_account_by_type(&channel_name).await {
                        Ok(Some(account)) => account.policy,
                        Ok(None) => None,
                        Err(e) => {
                            warn!(
                                channel = %channel_name,
                                sender = %msg.sender_id,
                                error = %e,
                                "failed to load channel account policy; using global policy"
                            );
                            let _ = state.audit.append(
                                "channel_policy",
                                "lookup_error",
                                Some(&format!(
                                    "channel={} sender={} error={}",
                                    channel_name, msg.sender_id, e
                                )),
                                None,
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                let (global_policy, gmail_allowed_senders) = {
                    let cfg = state.config.read().await;
                    let global_policy = cfg.channels.access_policy.clone();
                    let gmail_allowed_senders = if channel_name == "gmail"
                        && account_policy
                            .as_ref()
                            .is_none_or(|policy| policy.allowlist.is_empty())
                        && !global_policy
                            .allowlist
                            .iter()
                            .any(|entry| entry.channel == "gmail")
                    {
                        cfg.channels
                            .gmail
                            .as_ref()
                            .map(|gmail| gmail.normalized_allowed_sender_ids())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    (global_policy, gmail_allowed_senders)
                };
                let resolved_policy = encmind_channels::router::resolve_policy(
                    &global_policy,
                    account_policy.as_ref(),
                    &channel_name,
                );
                let mut resolved_policy = resolved_policy;
                apply_gmail_allowlist_fallback(
                    &channel_name,
                    &mut resolved_policy,
                    &global_policy,
                    account_policy.as_ref(),
                    &gmail_allowed_senders,
                );
                match encmind_channels::router::check_policy(&msg, &resolved_policy) {
                    encmind_channels::router::PolicyDecision::Allow => {
                        // Hydrate binary attachments only for media-only messages.
                        // For text-bearing messages, keep a redacted metadata summary to avoid
                        // costly file downloads on the hot path.
                        let has_text = !extract_inbound_text(&msg).is_empty();
                        if has_text {
                            redact_inbound_file_refs(&mut msg.metadata);
                        } else {
                            let hydration_timeout_secs = {
                                let config = state.config.read().await;
                                channel_attachment_hydration_timeout_secs(&config, &channel_name)
                            };
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(hydration_timeout_secs),
                                adapter.hydrate_inbound_attachments(&mut msg),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    warn!(
                                        channel = %channel_name,
                                        sender = %msg.sender_id,
                                        error = %e,
                                        "failed to hydrate inbound attachments"
                                    );
                                    msg.metadata.insert(
                                        "attachment_hydration_note".to_string(),
                                        serde_json::Value::String(
                                            "attachment hydration failed".to_string(),
                                        ),
                                    );
                                    msg.metadata.remove("file_refs");
                                    msg.metadata.remove("file_refs_total_count");
                                    ensure_inbound_media_fallback(
                                        &mut msg,
                                        "attachment hydration failed",
                                    );
                                }
                                Err(_) => {
                                    warn!(
                                        channel = %channel_name,
                                        sender = %msg.sender_id,
                                        "timed out hydrating inbound attachments"
                                    );
                                    msg.metadata.insert(
                                        "attachment_hydration_note".to_string(),
                                        serde_json::Value::String(
                                            "attachment hydration timed out".to_string(),
                                        ),
                                    );
                                    msg.metadata.remove("file_refs");
                                    msg.metadata.remove("file_refs_total_count");
                                    ensure_inbound_media_fallback(
                                        &mut msg,
                                        "attachment hydration timed out",
                                    );
                                }
                            }
                        }
                    }
                    encmind_channels::router::PolicyDecision::Reject { reason } => {
                        info!(
                            channel = %channel_name,
                            sender = %msg.sender_id,
                            reason = %reason,
                            "inbound channel message rejected by access policy"
                        );
                        let _ = state.audit.append(
                            "channel_policy",
                            "reject",
                            Some(&format!(
                                "channel={} sender={} reason={}",
                                channel_name, msg.sender_id, reason
                            )),
                            None,
                        );
                        if should_send_policy_rejection_notice(&msg.channel, &resolved_policy) {
                            let target = ChannelTarget {
                                channel: msg.channel.clone(),
                                target_id: channel_reply_target_id(&msg.channel, &msg.sender_id),
                            };
                            let reply = OutboundMessage {
                                content: vec![ContentBlock::Text {
                                    text: "Not authorized.".into(),
                                }],
                                attachments: vec![],
                                thread_id: None,
                                reply_to_id: None,
                                subject: None,
                            };
                            if let Err(e) = adapter.send_message(&target, &reply).await {
                                warn!(
                                    channel = %channel_name,
                                    sender = %msg.sender_id,
                                    error = %e,
                                    "failed to send policy rejection notice"
                                );
                            }
                        }
                        continue;
                    }
                }

                let Some(msg) = apply_on_message_received_hook(&state, msg).await else {
                    continue;
                };
                let inbound_text = extract_inbound_text(&msg);

                // Command gating: if text starts with "/", check command_gates.
                if let Some(command) = normalize_slash_command(&inbound_text) {
                    let gates = &state.config.read().await.channels.command_gates;
                    if !encmind_channels::router::is_command_allowed(gates, &channel_name, &command)
                    {
                        info!(
                            channel = %channel_name,
                            sender = %msg.sender_id,
                            command = %command,
                            "inbound channel command blocked by command gate"
                        );
                        continue;
                    }
                }

                let prompt_text = compose_inbound_prompt(&msg);
                info!(
                    channel = %channel_name,
                    sender = %msg.sender_id,
                    text_len = inbound_text.len(),
                    attachment_count = msg.attachments.len(),
                    "received inbound channel message"
                );

                let session_id = match router
                    .resolve_session(&msg.channel, &msg.sender_id, msg.thread_id.as_deref())
                    .await
                {
                    Ok(session_id) => session_id,
                    Err(e) => {
                        warn!(
                            channel = %channel_name,
                            sender = %msg.sender_id,
                            error = %e,
                            "failed to resolve channel session"
                        );
                        continue;
                    }
                };

                if prompt_text.is_empty() {
                    info!(
                        channel = %channel_name,
                        sender = %msg.sender_id,
                        "skipping inbound channel message with empty text and no attachment context"
                    );
                    continue;
                }

                let auto_reply_enabled = {
                    let config = state.config.read().await;
                    channel_auto_reply_enabled(&config, &msg.channel, &msg.sender_id)
                };
                if !auto_reply_enabled {
                    let inbound_record = Message {
                        id: MessageId::new(),
                        role: Role::User,
                        content: vec![ContentBlock::Text {
                            text: prompt_text.clone(),
                        }],
                        created_at: chrono::Utc::now(),
                        token_count: None,
                    };
                    if let Err(e) = state
                        .session_store
                        .append_message(&session_id, &inbound_record)
                        .await
                    {
                        warn!(
                            channel = %channel_name,
                            sender = %msg.sender_id,
                            session_id = %session_id,
                            error = %e,
                            "failed to record inbound message while auto-reply is disabled"
                        );
                    }
                    info!(
                        channel = %channel_name,
                        sender = %msg.sender_id,
                        session_id = %session_id,
                        "channel auto-reply disabled; recorded inbound message without invoking chat runtime"
                    );
                    continue;
                }

                let req_id = format!("channel-{}", ulid::Ulid::new());
                let response = crate::handlers::chat::handle_send(
                    &state,
                    serde_json::json!({
                        "text": prompt_text,
                        "session_id": session_id.as_str(),
                    }),
                    &req_id,
                )
                .await;

                let Some(reply_text) = chat_response_text(response) else {
                    warn!(
                        channel = %channel_name,
                        sender = %msg.sender_id,
                        session_id = %session_id,
                        req_id = %req_id,
                        "channel handler returned non-text response"
                    );
                    continue;
                };
                if reply_text.trim().is_empty() {
                    info!(
                        channel = %channel_name,
                        sender = %msg.sender_id,
                        session_id = %session_id,
                        req_id = %req_id,
                        "channel handler returned empty response"
                    );
                    continue;
                }
                let reply_len = reply_text.len();

                let target = ChannelTarget {
                    channel: msg.channel.clone(),
                    target_id: channel_reply_target_id(&msg.channel, &msg.sender_id),
                };
                let outbound = OutboundMessage {
                    content: vec![ContentBlock::Text { text: reply_text }],
                    attachments: vec![],
                    thread_id: msg.thread_id.clone(),
                    reply_to_id: msg.reply_to_id.clone(),
                    subject: outbound_subject_for_channel(&msg),
                };
                let Some(outbound) =
                    apply_on_message_sending_hook(&state, &msg, &session_id, outbound).await
                else {
                    continue;
                };
                let Some(outbound) =
                    apply_channel_outbound_transform(&state, &msg.channel, outbound).await
                else {
                    continue;
                };
                if let Err(e) = adapter.send_message(&target, &outbound).await {
                    warn!(
                        channel = %channel_name,
                        sender = %msg.sender_id,
                        error = %e,
                        "failed to send channel response"
                    );
                } else {
                    info!(
                        channel = %channel_name,
                        sender = %msg.sender_id,
                        session_id = %session_id,
                        req_id = %req_id,
                        reply_len,
                        "channel response sent"
                    );
                }
            }
        }
    }
}

fn channel_auto_reply_enabled(config: &AppConfig, channel: &str, sender_id: &str) -> bool {
    match channel {
        "gmail" => config
            .channels
            .gmail
            .as_ref()
            .map(|gmail| gmail.sender_auto_reply_enabled(sender_id))
            .unwrap_or(false),
        _ => true,
    }
}

fn should_send_policy_rejection_notice(
    channel: &str,
    resolved_policy: &encmind_channels::router::ResolvedPolicy,
) -> bool {
    encmind_channels::router::should_send_rejection_notice(channel, resolved_policy.notify_rejected)
}

fn outbound_subject_for_channel(msg: &InboundMessage) -> Option<String> {
    if msg.channel != "gmail" {
        return None;
    }
    let raw_subject = msg
        .metadata
        .get("subject")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let lower = raw_subject.to_ascii_lowercase();
    if lower.starts_with("re:") || lower.starts_with("fw:") || lower.starts_with("fwd:") {
        Some(raw_subject.to_string())
    } else {
        Some(format!("Re: {raw_subject}"))
    }
}

fn auto_tls_dir_for_db_path(db_path: &Path) -> PathBuf {
    let db_parent = db_path.parent().unwrap_or_else(|| Path::new("."));

    // Keep installer/default layouts aligned at ~/.encmind/tls:
    // - ~/.encmind/data.db
    // - ~/.encmind/data/data.db
    if db_parent.file_name().and_then(|name| name.to_str()) == Some("data") {
        if let Some(root) = db_parent.parent() {
            return root.join("tls");
        }
    }

    db_parent.join("tls")
}

/// Resolve the effective skills directory from config.
///
/// Shared by gateway runtime and CLI diagnostics to keep behavior identical.
pub fn resolve_skills_dir(config: &AppConfig) -> PathBuf {
    if !config.skills.wasm_dir.as_os_str().is_empty() {
        return config.skills.wasm_dir.clone();
    }

    // Legacy fallback for empty/invalid config values.
    config
        .storage
        .db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("skills")
}

fn extract_inbound_text(msg: &InboundMessage) -> String {
    msg.content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn channel_attachment_hydration_timeout_secs(config: &AppConfig, channel: &str) -> u64 {
    let (download_timeout_secs, max_attachments_per_message) = match channel {
        "telegram" => config
            .channels
            .telegram
            .as_ref()
            .map(|c| (c.download_timeout_secs, c.max_attachments_per_message))
            .unwrap_or((4, 5)),
        "slack" => config
            .channels
            .slack
            .as_ref()
            .map(|c| (c.download_timeout_secs, c.max_attachments_per_message))
            .unwrap_or((4, 5)),
        _ => return 25,
    };

    let per_file = download_timeout_secs.max(1);
    let max_attachments = (max_attachments_per_message as u64).max(1);
    per_file
        .saturating_mul(max_attachments)
        .saturating_add(5)
        // Keep per-message hydration bounded so one media-heavy message does not
        // stall a channel loop for multiple minutes.
        .clamp(5, 90)
}

fn ensure_inbound_media_fallback(msg: &mut InboundMessage, note: &str) {
    if !extract_inbound_text(msg).is_empty() || !msg.attachments.is_empty() {
        return;
    }
    msg.content = vec![ContentBlock::Text {
        text: format!("Received a media message, but attachments could not be retrieved ({note})."),
    }];
}

fn sanitize_for_prompt(value: &str, max_chars: usize) -> String {
    let sanitized = value
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            ch if ch.is_control() => ' ',
            ch => ch,
        })
        .collect::<String>();
    let trimmed = sanitized.trim();
    let chars = trimmed.chars().count();
    if chars <= max_chars {
        return trimmed.to_string();
    }
    let truncated = trimmed.chars().take(max_chars).collect::<String>();
    format!("{truncated}...")
}

fn summarize_inbound_attachments(attachments: &[Attachment]) -> String {
    if attachments.is_empty() {
        return String::new();
    }

    let max_listed = 5usize;
    let mut lines = vec!["Inbound attachments:".to_string()];
    for attachment in attachments.iter().take(max_listed) {
        let name = sanitize_for_prompt(&attachment.name, 120);
        let media_type = sanitize_for_prompt(&attachment.media_type, 80);
        lines.push(format!(
            "- {} ({}, {} bytes)",
            name,
            media_type,
            attachment.data.len()
        ));
    }
    if attachments.len() > max_listed {
        lines.push(format!(
            "- and {} more attachment(s)",
            attachments.len() - max_listed
        ));
    }
    lines.join("\n")
}

fn summarize_inbound_attachment_refs(
    metadata: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    enum RefMode<'a> {
        FileRefs(&'a [serde_json::Value], usize),
        AttachmentIds(&'a [serde_json::Value], usize),
    }

    let mode = if let Some(refs) = metadata.get("file_refs").and_then(|v| v.as_array()) {
        if refs.is_empty() {
            return String::new();
        }
        let total_refs = metadata
            .get("file_refs_total_count")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(refs.len());
        RefMode::FileRefs(refs, total_refs)
    } else if let Some(ids) = metadata.get("attachment_ids").and_then(|v| v.as_array()) {
        if ids.is_empty() {
            return String::new();
        }
        RefMode::AttachmentIds(ids, ids.len())
    } else {
        return String::new();
    };

    let max_listed = 5usize;
    let mut lines = vec!["Inbound attachments (metadata only):".to_string()];
    let total_refs = match mode {
        RefMode::FileRefs(refs, total) => {
            for value in refs.iter().take(max_listed) {
                let name = value
                    .get("name")
                    .or_else(|| value.get("file_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("attachment");
                let media_type = value
                    .get("mimetype")
                    .or_else(|| value.get("mime_type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/octet-stream");
                lines.push(format!(
                    "- {} ({})",
                    sanitize_for_prompt(name, 120),
                    sanitize_for_prompt(media_type, 80)
                ));
            }
            total
        }
        RefMode::AttachmentIds(ids, total) => {
            for value in ids.iter().take(max_listed) {
                let id = value.as_str().unwrap_or("attachment");
                lines.push(format!("- {}", sanitize_for_prompt(id, 160)));
            }
            total
        }
    };
    if total_refs > max_listed {
        lines.push(format!(
            "- and {} more attachment(s)",
            total_refs - max_listed
        ));
    }
    lines.join("\n")
}

fn redact_inbound_file_refs(metadata: &mut std::collections::HashMap<String, serde_json::Value>) {
    const MAX_REDACTED_REFS: usize = 5;

    let Some(refs) = metadata.get("file_refs").and_then(|v| v.as_array()) else {
        return;
    };
    let total_refs = metadata
        .get("file_refs_total_count")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(refs.len())
        .max(refs.len());
    let redacted: Vec<serde_json::Value> = refs
        .iter()
        .take(MAX_REDACTED_REFS)
        .filter_map(|value| {
            let name = value
                .get("name")
                .or_else(|| value.get("file_name"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let media_type = value
                .get("mimetype")
                .or_else(|| value.get("mime_type"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if name.is_none() && media_type.is_none() {
                return None;
            }
            let mut obj = serde_json::Map::new();
            if let Some(name) = name {
                obj.insert("name".to_string(), serde_json::Value::String(name));
            }
            if let Some(media_type) = media_type {
                obj.insert(
                    "mimetype".to_string(),
                    serde_json::Value::String(media_type),
                );
            }
            Some(serde_json::Value::Object(obj))
        })
        .collect();

    if redacted.is_empty() {
        metadata.remove("file_refs");
        metadata.remove("file_refs_total_count");
    } else {
        metadata.insert("file_refs".to_string(), serde_json::Value::Array(redacted));
        if total_refs > MAX_REDACTED_REFS {
            metadata.insert(
                "file_refs_total_count".to_string(),
                serde_json::Value::from(total_refs as u64),
            );
        } else {
            metadata.remove("file_refs_total_count");
        }
    }
}

fn compose_inbound_prompt(msg: &InboundMessage) -> String {
    let text = extract_inbound_text(msg);
    let attachment_summary = if msg.attachments.is_empty() {
        summarize_inbound_attachment_refs(&msg.metadata)
    } else {
        summarize_inbound_attachments(&msg.attachments)
    };
    let hydration_note = msg
        .metadata
        .get("attachment_hydration_note")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let mut parts = Vec::new();
    if !text.is_empty() {
        parts.push(text);
    }
    if !attachment_summary.is_empty() {
        parts.push(attachment_summary);
    }
    // Keep hydration notes as supplemental context only; avoid creating
    // note-only prompts when the original message has no usable content.
    if !parts.is_empty() {
        if let Some(note) = hydration_note {
            parts.push(format!("Attachment processing note: {note}"));
        }
    }
    parts.join("\n\n")
}

fn normalize_slash_command(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?;
    if !token.starts_with('/') {
        return None;
    }
    let normalized = token.split_once('@').map(|(base, _)| base).unwrap_or(token);
    Some(normalized.to_string())
}

fn channel_reply_target_id(channel: &str, sender_id: &str) -> String {
    if channel == "telegram" || channel == "slack" {
        if let Some((channel_id, _)) = sender_id.split_once(':') {
            return channel_id.to_string();
        }
    }
    sender_id.to_string()
}

fn chat_response_text(response: crate::protocol::ServerMessage) -> Option<String> {
    match response {
        crate::protocol::ServerMessage::Res { result, .. } => result
            .get("response")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        crate::protocol::ServerMessage::Error { error, .. } => {
            warn!(error = %error.message, "channel chat request failed");
            Some(CHANNEL_GENERIC_ERROR_REPLY.to_string())
        }
        _ => None,
    }
}

async fn apply_on_message_received_hook(
    state: &AppState,
    msg: InboundMessage,
) -> Option<InboundMessage> {
    let registry_snapshot = { state.hook_registry.read().await.clone() };
    let original = msg.clone();
    let mut ctx = HookContext {
        session_id: None,
        agent_id: None,
        method: Some("channel.receive".to_string()),
        payload: serde_json::json!({ "message": msg }),
    };

    let payload = match registry_snapshot
        .execute(HookPoint::OnMessageReceived, &mut ctx)
        .await
    {
        Ok(HookResult::Continue) => ctx.payload,
        Ok(HookResult::Override(value)) => value,
        Ok(HookResult::Abort { reason }) => {
            info!(reason = %reason, "inbound message blocked by OnMessageReceived hook");
            return None;
        }
        Err(e) => {
            warn!(error = %e, "OnMessageReceived hook execution failed; using original message");
            return Some(original);
        }
    };

    let candidate = payload.get("message").cloned().unwrap_or(payload);
    match serde_json::from_value::<InboundMessage>(candidate) {
        Ok(overridden) => Some(overridden),
        Err(e) => {
            warn!(
                error = %e,
                "invalid OnMessageReceived hook payload override; using original message"
            );
            Some(original)
        }
    }
}

async fn apply_on_message_sending_hook(
    state: &AppState,
    inbound_msg: &InboundMessage,
    session_id: &encmind_core::types::SessionId,
    outbound: OutboundMessage,
) -> Option<OutboundMessage> {
    let registry_snapshot = { state.hook_registry.read().await.clone() };
    let original = outbound.clone();
    let mut ctx = HookContext {
        session_id: Some(session_id.clone()),
        agent_id: None,
        method: Some("channel.send".to_string()),
        payload: serde_json::json!({
            "channel": inbound_msg.channel.clone(),
            "sender_id": inbound_msg.sender_id.clone(),
            "message": outbound,
        }),
    };

    let payload = match registry_snapshot
        .execute(HookPoint::OnMessageSending, &mut ctx)
        .await
    {
        Ok(HookResult::Continue) => ctx.payload,
        Ok(HookResult::Override(value)) => value,
        Ok(HookResult::Abort { reason }) => {
            info!(reason = %reason, "outbound message blocked by OnMessageSending hook");
            return None;
        }
        Err(e) => {
            warn!(error = %e, "OnMessageSending hook execution failed; using original outbound");
            return Some(original);
        }
    };

    let candidate = payload.get("message").cloned().unwrap_or(payload);
    match serde_json::from_value::<OutboundMessage>(candidate) {
        Ok(overridden) => Some(overridden),
        Err(e) => {
            warn!(
                error = %e,
                "invalid OnMessageSending hook payload override; using original outbound"
            );
            Some(original)
        }
    }
}

async fn maintenance_loop(state: AppState, shutdown: CancellationToken, interval_ms: u64) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms.max(1000)));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                {
                    let mut cache = state.idempotency.lock().unwrap();
                    cache.cleanup();
                }
                state.session_rate_limiter.cleanup();
                state.nonce_store.cleanup_expired();
            }
        }
    }
}

async fn cron_loop(
    state: AppState,
    dispatcher: Arc<CronDispatcher>,
    shutdown: CancellationToken,
    check_interval_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(check_interval_secs.max(1)));
    ticker.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                let due_jobs = match dispatcher.dispatch_due_jobs().await {
                    Ok(jobs) => jobs,
                    Err(e) => {
                        warn!(error = %e, "cron dispatcher tick failed");
                        continue;
                    }
                };

                for job in due_jobs {
                    let state = state.clone();
                    let dispatcher = dispatcher.clone();
                    let fallback_delay_secs = check_interval_secs.max(1);
                    tokio::spawn(async move {
                        let run_result = AssertUnwindSafe(async {
                            match state.cron_store.clone() {
                                Some(cron_store) => {
                                    crate::handlers::cron::run_cron_job_once(
                                        &state,
                                        &cron_store,
                                        &job,
                                        fallback_delay_secs,
                                    )
                                    .await
                                }
                                None => Err("cron store unavailable".to_string()),
                            }
                        })
                        .catch_unwind()
                        .await;

                        match run_result {
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                warn!(job_id = %job.id, error = %e, "cron job execution failed");
                            }
                            Err(payload) => {
                                let panic_msg = if let Some(msg) = payload.downcast_ref::<&str>() {
                                    (*msg).to_string()
                                } else if let Some(msg) = payload.downcast_ref::<String>() {
                                    msg.clone()
                                } else {
                                    "unknown panic payload".to_string()
                                };
                                warn!(
                                    job_id = %job.id,
                                    panic = %panic_msg,
                                    "cron job task panicked"
                                );
                            }
                        }

                        dispatcher.mark_job_complete(job.id.as_str()).await;
                    });
                }
            }
        }
    }
}

fn cron_dispatch_parallelism(agent_parallelism: usize) -> usize {
    if agent_parallelism <= 1 {
        1
    } else {
        agent_parallelism - 1
    }
}

/// Build (or rebuild) the LLM backend by checking the DB key store first,
/// then falling back to environment variables.
pub async fn rebuild_llm_backend(
    config: &AppConfig,
    api_key_store: Option<Arc<dyn ApiKeyStore>>,
) -> Option<Arc<dyn LlmBackend>> {
    let provider_pool: Vec<&ApiProviderConfig> = match &config.llm.mode {
        InferenceMode::ApiProvider { provider } => {
            let found = config
                .llm
                .api_providers
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(provider));
            let Some(found) = found else {
                warn!(
                    provider = %provider,
                    "LLM disabled: mode references unknown provider"
                );
                return None;
            };
            vec![found]
        }
        InferenceMode::Local => {
            if config.llm.api_providers.is_empty() {
                warn!("LLM disabled: local inference unavailable and no API providers configured");
                return None;
            }
            config.llm.api_providers.iter().collect()
        }
    };

    let mut named_backends: Vec<(String, Box<dyn LlmBackend>)> = Vec::new();
    for provider in provider_pool {
        // Try DB key first, then env var
        let api_key = if let Some(ref store) = api_key_store {
            match store.get_key(&provider.name).await {
                Ok(Some(key)) => Some(key),
                Ok(None) => None,
                Err(e) => {
                    warn!(provider = %provider.name, error = %e, "failed to read API key from store");
                    None
                }
            }
        } else {
            None
        };

        let api_key = api_key.or_else(|| {
            let env_var = provider_api_key_env(&provider.name);
            std::env::var(&env_var).ok()
        });

        let Some(api_key) = api_key else {
            warn!(provider = %provider.name, "no API key available (DB or env)");
            continue;
        };

        match build_api_backend_with_key(provider, api_key) {
            Ok(backend) => named_backends.push((provider.name.clone(), backend)),
            Err(e) => warn!(
                provider = %provider.name,
                error = %e,
                "skipping misconfigured LLM provider"
            ),
        }
    }

    if named_backends.is_empty() {
        warn!("LLM disabled: no usable providers available");
        return None;
    }

    if named_backends.len() == 1 {
        let (_, backend) = named_backends.pop().expect("single backend exists");
        return Some(Arc::from(backend));
    }

    info!(
        providers = named_backends.len(),
        "LLM dispatcher enabled with failover"
    );
    Some(Arc::new(LlmDispatcher::new(named_backends)))
}

#[cfg(test)]
fn initialize_llm_backend(config: &AppConfig) -> Option<Arc<dyn LlmBackend>> {
    let provider_pool: Vec<&ApiProviderConfig> = match &config.llm.mode {
        InferenceMode::ApiProvider { provider } => {
            let found = config
                .llm
                .api_providers
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(provider));
            let Some(found) = found else {
                warn!(
                    provider = %provider,
                    "LLM disabled: mode references unknown provider"
                );
                return None;
            };
            vec![found]
        }
        InferenceMode::Local => {
            if config.llm.local.is_some() {
                warn!(
                    "LLM local inference is not implemented in this build; attempting API provider fallback"
                );
            } else {
                warn!(
                    "LLM mode is local without local config; falling back to configured API providers"
                );
            }
            if config.llm.api_providers.is_empty() {
                warn!(
                    "LLM disabled: local inference is unavailable and no API providers are configured"
                );
                return None;
            }
            config.llm.api_providers.iter().collect()
        }
    };

    let mut named_backends: Vec<(String, Box<dyn LlmBackend>)> = Vec::new();
    for provider in provider_pool {
        match build_api_backend(provider) {
            Ok(backend) => named_backends.push((provider.name.clone(), backend)),
            Err(e) => warn!(
                provider = %provider.name,
                error = %e,
                "skipping misconfigured LLM provider"
            ),
        }
    }

    if named_backends.is_empty() {
        warn!("LLM disabled: no usable providers available");
        return None;
    }

    if named_backends.len() == 1 {
        let (_, backend) = named_backends.pop().expect("single backend exists");
        return Some(Arc::from(backend));
    }

    info!(
        providers = named_backends.len(),
        "LLM dispatcher enabled with failover"
    );
    Some(Arc::new(LlmDispatcher::new(named_backends)))
}

/// Register tools available to both main agents and sub-agents.
/// When adding new tools (bash.exec, file operations, etc.), register them here
/// so spawned sub-agents automatically inherit them.
pub(crate) fn build_native_plugins(
    config: &AppConfig,
    browser_pool: Option<Arc<encmind_browser::pool::BrowserPool>>,
    firewall: Arc<EgressFirewall>,
    runtime: Arc<tokio::sync::RwLock<RuntimeResources>>,
) -> Vec<Box<dyn NativePlugin>> {
    let mut plugins: Vec<Box<dyn NativePlugin>> = Vec::new();

    if let Some(pool) = browser_pool {
        let required = matches!(
            config.browser.startup_policy,
            BrowserStartupPolicy::Required
        );
        let idle_timeout = std::time::Duration::from_secs(config.browser.idle_timeout_secs);
        let session_manager =
            encmind_browser::SessionBrowserManager::new(pool.clone(), idle_timeout);
        plugins.push(Box::new(encmind_browser::plugin::BrowserPlugin::new(
            pool,
            session_manager,
            firewall.clone(),
            config.token_optimization.screenshot_payload_mode,
            config.browser.clone(),
            required,
        )));
    }

    // NetProbe plugin (web search & fetch) — enabled by default, but can be disabled via config.
    let netprobe_config: encmind_core::config::NetProbeConfig = match config.plugins.get("netprobe")
    {
        Some(raw) => match serde_json::from_value(raw.clone()) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to parse plugins.netprobe config; falling back to defaults"
                );
                encmind_core::config::NetProbeConfig::default()
            }
        },
        None => encmind_core::config::NetProbeConfig::default(),
    };
    if netprobe_config.enabled {
        plugins.push(Box::new(crate::plugins::netprobe::NetProbePlugin::new(
            netprobe_config,
            firewall.clone(),
            runtime.clone(),
        )));
    } else {
        info!("netprobe plugin disabled by configuration");
    }

    // Digest plugin (summarize, PDF, transcribe) — enabled by default.
    let digest_config: encmind_core::config::DigestConfig = match config.plugins.get("digest") {
        Some(raw) => match serde_json::from_value(raw.clone()) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to parse plugins.digest config; falling back to defaults"
                );
                encmind_core::config::DigestConfig::default()
            }
        },
        None => encmind_core::config::DigestConfig::default(),
    };
    if digest_config.enabled {
        plugins.push(Box::new(crate::plugins::digest::DigestPlugin::new(
            digest_config,
            firewall,
            runtime,
        )));
    } else {
        info!("digest plugin disabled by configuration");
    }

    plugins
}

/// Resolve per-plugin config and state store, then build a `GatewayPluginApi` with them.
#[allow(dead_code, clippy::too_many_arguments)]
fn build_plugin_api_with_context<'a>(
    plugin_id: &str,
    config: &AppConfig,
    db_pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    tool_registry: &'a mut encmind_agent::tool_registry::ToolRegistry,
    hook_registry: &'a mut encmind_core::hooks::HookRegistry,
    method_handlers: &'a mut Vec<(
        String,
        std::sync::Arc<dyn encmind_core::plugin::GatewayMethodHandler>,
    )>,
    tool_snapshots: &'a mut Vec<crate::plugin_api::RegisteredPluginTool>,
    transform_snapshots: &'a mut Vec<crate::plugin_api::RegisteredPluginTransform>,
    timer_snapshots: &'a mut Vec<crate::plugin_api::RegisteredPluginTimer>,
) -> crate::plugin_api::GatewayPluginApi<'a> {
    let plugin_config = config.plugins.get(plugin_id).cloned();
    let state_store: Option<std::sync::Arc<dyn encmind_core::plugin::PluginStateStore>> =
        Some(std::sync::Arc::new(
            encmind_storage::plugin_state::SqlitePluginStateStore::new(db_pool.clone(), plugin_id),
        ));
    crate::plugin_api::GatewayPluginApi::new(
        plugin_id.to_string(),
        tool_registry,
        hook_registry,
        method_handlers,
        tool_snapshots,
        transform_snapshots,
        timer_snapshots,
    )
    .with_config(plugin_config)
    .with_state_store(state_store)
}

fn spawn_native_plugin_timer_tasks(
    timers: &[RegisteredPluginTimer],
    shutdown: CancellationToken,
) -> Vec<NativePluginTimerHandle> {
    timers
        .iter()
        .map(|timer| {
            let plugin_id = timer.plugin_id.clone();
            let timer_name = timer.name.clone();
            let interval_secs = timer.interval_secs.max(1);
            let handler = timer.handler.clone();
            let task_shutdown = shutdown.clone();
            let task_plugin_id = plugin_id.clone();
            let task_timer_name = timer_name.clone();

            let handle = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = task_shutdown.cancelled() => break,
                        _ = ticker.tick() => {
                            let tick_result = AssertUnwindSafe(handler.tick()).catch_unwind().await;
                            match tick_result {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => {
                                    warn!(
                                        plugin_id = %task_plugin_id,
                                        timer = %task_timer_name,
                                        error = %error,
                                        "native_plugin_timer.tick_failed"
                                    );
                                }
                                Err(payload) => {
                                    let panic_msg = if let Some(msg) = payload.downcast_ref::<&str>() {
                                        (*msg).to_string()
                                    } else if let Some(msg) = payload.downcast_ref::<String>() {
                                        msg.clone()
                                    } else {
                                        "unknown panic payload".to_string()
                                    };
                                    warn!(
                                        plugin_id = %task_plugin_id,
                                        timer = %task_timer_name,
                                        panic = %panic_msg,
                                        "native_plugin_timer.tick_panicked; disabling timer task"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            NativePluginTimerHandle {
                plugin_id,
                timer_name,
                handle,
            }
        })
        .collect()
}

/// Replace currently running native plugin timer tasks with a new timer set.
///
/// The old task set is cancelled and awaited (with timeout), then the new set starts.
pub(crate) async fn replace_native_plugin_timer_tasks(
    state: &AppState,
    timers: &[RegisteredPluginTimer],
) {
    const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
    let _replace_guard = state.native_timer_replace_lock.lock().await;

    let (old_handles, new_cancel) = {
        let mut runtime = state.native_plugin_timers.lock().await;
        runtime.cancel.cancel();
        let old_handles = std::mem::take(&mut runtime.handles);
        let new_cancel = CancellationToken::new();
        runtime.cancel = new_cancel.clone();
        (old_handles, new_cancel)
    };

    for (idx, mut timer_task) in old_handles.into_iter().enumerate() {
        match tokio::time::timeout(SHUTDOWN_JOIN_TIMEOUT, &mut timer_task.handle).await {
            Ok(_) => {}
            Err(_) => {
                warn!(
                    timer_task_index = idx,
                    plugin_id = %timer_task.plugin_id,
                    timer = %timer_task.timer_name,
                    timeout_ms = SHUTDOWN_JOIN_TIMEOUT.as_millis(),
                    "native_plugin_timer.task_shutdown_timeout; aborting task"
                );
                timer_task.handle.abort();
                let _ = timer_task.handle.await;
            }
        }
    }

    let mut runtime = state.native_plugin_timers.lock().await;
    runtime.handles = spawn_native_plugin_timer_tasks(timers, new_cancel);
}

/// Build the exposed tool name for a WASM skill tool.
///
/// Skill IDs may include `.` for operator UX, but tool names sent to LLM
/// providers must match `^[a-zA-Z0-9_-]+$` and be <= 128 chars.
///
/// The resulting name is deterministic and collision-resistant:
/// - invalid characters are replaced with `_`
/// - truncated/changed components get a short hash suffix
/// - final output is hard-capped at 128 chars
fn namespaced_wasm_tool_name(skill_id: &str, tool_name: &str) -> String {
    const MAX_TOOL_NAME_LEN: usize = 128;
    const PREFIX_MAX_LEN: usize = 48;
    const HASH_BYTES: usize = 8;
    const HASH_HEX_LEN: usize = HASH_BYTES * 2;

    let prefix = sanitize_tool_component(skill_id, "skill", PREFIX_MAX_LEN);
    let mut suffix =
        sanitize_tool_component(tool_name, "tool", MAX_TOOL_NAME_LEN - prefix.len() - 1);

    let mut out = format!("{}_{}", prefix, suffix);
    if out.len() <= MAX_TOOL_NAME_LEN {
        return out;
    }

    // Defensive fallback: squeeze suffix further and append hash so the final
    // tool name always satisfies registry/LLM constraints.
    let max_suffix = MAX_TOOL_NAME_LEN.saturating_sub(prefix.len() + 1);
    let keep = max_suffix.saturating_sub(HASH_HEX_LEN + 1);
    if suffix.len() > keep {
        suffix.truncate(keep);
    }
    let digest = Sha256::digest(format!("{skill_id}|{tool_name}").as_bytes());
    let hash = hash_hex_prefix(&digest, HASH_BYTES);
    suffix.push('_');
    suffix.push_str(&hash);
    out = format!("{}_{}", prefix, suffix);
    out.truncate(MAX_TOOL_NAME_LEN);
    out
}

/// Sanitize one tool-name component so it only contains `[A-Za-z0-9_-]`.
///
/// If sanitization changes characters (or truncates), append a 16-hex hash
/// suffix to preserve uniqueness across similar IDs.
fn sanitize_tool_component(raw: &str, fallback: &str, max_len: usize) -> String {
    const HASH_BYTES: usize = 8;
    const HASH_HEX_LEN: usize = HASH_BYTES * 2;

    let mut out = String::with_capacity(raw.len());
    let mut changed = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
            changed = true;
        }
    }
    if out.is_empty() {
        out.push_str(fallback);
        changed = true;
    }
    if out.len() > max_len {
        out.truncate(max_len);
        changed = true;
    }
    if changed {
        let digest = Sha256::digest(raw.as_bytes());
        let hash = hash_hex_prefix(&digest, HASH_BYTES);
        let keep = max_len.saturating_sub(HASH_HEX_LEN + 1);
        if out.len() > keep {
            out.truncate(keep);
        }
        out.push('_');
        out.push_str(&hash);
    }
    out
}

fn hash_hex_prefix(bytes: &[u8], count: usize) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(count.saturating_mul(2));
    for b in bytes.iter().take(count) {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

struct LoadWasmSkillsOutcome {
    summaries: Vec<LoadedSkillSummary>,
    runtime_specs: Vec<LoadedSkillRuntimeSpec>,
    known_skill_ids: HashSet<String>,
    hard_errors: Vec<String>,
}

pub(crate) struct LoadedWasmSkills {
    pub summaries: Vec<LoadedSkillSummary>,
    pub runtime_specs: Vec<LoadedSkillRuntimeSpec>,
    pub known_skill_ids: HashSet<String>,
}

struct NativePluginChannelTransformAdapter {
    name: String,
    handler: Arc<dyn encmind_core::plugin::NativeChannelTransform>,
}

#[async_trait::async_trait]
impl ChannelTransform for NativePluginChannelTransformAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn transform_inbound(
        &self,
        msg: InboundMessage,
    ) -> Result<Option<InboundMessage>, encmind_core::error::ChannelError> {
        self.handler
            .transform_inbound(msg)
            .await
            .map_err(|e| encmind_core::error::ChannelError::SendFailed(e.to_string()))
    }

    async fn transform_outbound(
        &self,
        msg: OutboundMessage,
    ) -> Result<Option<OutboundMessage>, encmind_core::error::ChannelError> {
        self.handler
            .transform_outbound(msg)
            .await
            .map_err(|e| encmind_core::error::ChannelError::SendFailed(e.to_string()))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_transform_chains(
    config: &AppConfig,
    runtime_specs: &[LoadedSkillRuntimeSpec],
    native_transforms: &[RegisteredPluginTransform],
    db_pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    http_client: Arc<reqwest::Client>,
    hook_registry: Arc<RwLock<HookRegistry>>,
    outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy>,
    approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter>,
    audit_logger: Arc<AuditLogger>,
) -> HashMap<String, TransformChain> {
    type TransformEntry = (i32, Arc<dyn ChannelTransform>);
    let mut by_channel: HashMap<String, Vec<TransformEntry>> = HashMap::new();

    for spec in runtime_specs {
        if spec.transforms.is_empty() {
            continue;
        }
        if spec.abi != encmind_wasm_host::SkillAbi::Native {
            warn!(
                skill_id = %spec.skill_id,
                abi = ?spec.abi,
                transforms = spec.transforms.len(),
                "skipping non-native skill transforms"
            );
            continue;
        }
        let invoker = Arc::new(encmind_wasm_host::invoker::SkillInvoker::new(
            spec.engine.clone(),
            spec.module.clone(),
            spec.abi,
            spec.skill_id.clone(),
            spec.capabilities.clone(),
            spec.resolved_limits.fuel_per_invocation,
            spec.max_memory_mb,
        ));
        for decl in &spec.transforms {
            let transform = WasmChannelTransform::new(
                spec.skill_id.clone(),
                decl.inbound_fn.clone(),
                decl.outbound_fn.clone(),
            )
            .with_channel_hint(decl.channel.clone())
            .with_runtime(WasmTransformRuntimeConfig {
                invoker: invoker.clone(),
                wall_clock_timeout: Duration::from_millis(
                    spec.resolved_limits.wall_clock_ms.max(1),
                ),
                deps: WasmTransformDependencies {
                    db_pool: Arc::new(db_pool.clone()),
                    http_client: http_client.clone(),
                    outbound_policy: outbound_policy.clone(),
                    hook_registry: hook_registry.clone(),
                    approval_prompter: approval_prompter.clone(),
                    audit_logger: Some(audit_logger.clone()),
                },
            });
            by_channel
                .entry(decl.channel.clone())
                .or_default()
                .push((decl.priority, Arc::new(transform)));
        }
    }

    for transform in native_transforms {
        let name = format!("{}_{}", transform.plugin_id, transform.transform_id);
        by_channel
            .entry(transform.channel.clone())
            .or_default()
            .push((
                transform.priority,
                Arc::new(NativePluginChannelTransformAdapter {
                    name,
                    handler: transform.handler.clone(),
                }),
            ));
    }

    let mut chains = HashMap::new();
    for (channel, mut transforms) in by_channel {
        transforms.sort_by(|(a_priority, a_handler), (b_priority, b_handler)| {
            b_priority
                .cmp(a_priority)
                .then_with(|| a_handler.name().cmp(b_handler.name()))
        });
        let handlers = transforms
            .into_iter()
            .map(|(_, handler)| handler)
            .collect::<Vec<_>>();
        chains.insert(
            channel,
            TransformChain::new(
                handlers,
                config.skill_error_policy.transform_inbound_fail_open,
                config.skill_error_policy.transform_outbound_fail_open,
            ),
        );
    }
    chains
}

pub(crate) fn build_timer_reconcile_data(
    runtime_specs: &[LoadedSkillRuntimeSpec],
) -> Vec<(
    String,
    Vec<encmind_wasm_host::manifest::TimerDeclaration>,
    String,
)> {
    runtime_specs
        .iter()
        .map(|spec| {
            if spec.abi != encmind_wasm_host::SkillAbi::Native && !spec.timers.is_empty() {
                warn!(
                    skill_id = %spec.skill_id,
                    abi = ?spec.abi,
                    timers = spec.timers.len(),
                    "excluding non-native skill timers from reconcile data"
                );
            }
            (
                spec.skill_id.clone(),
                if spec.abi == encmind_wasm_host::SkillAbi::Native {
                    spec.timers.clone()
                } else {
                    Vec::new()
                },
                spec.manifest_hash.clone(),
            )
        })
        .collect()
}

pub(crate) fn build_skill_timer_limits(
    runtime_specs: &[LoadedSkillRuntimeSpec],
) -> HashMap<String, SkillTimerLimits> {
    runtime_specs
        .iter()
        .filter_map(|spec| {
            if spec.timers.is_empty() {
                return None;
            }
            if spec.abi != encmind_wasm_host::SkillAbi::Native {
                warn!(
                    skill_id = %spec.skill_id,
                    abi = ?spec.abi,
                    timers = spec.timers.len(),
                    "skipping non-native skill timer limits"
                );
                return None;
            }
            Some((
                spec.skill_id.clone(),
                SkillTimerLimits {
                    max_concurrent: spec.resolved_limits.max_concurrent,
                    invocations_per_minute: spec.resolved_limits.invocations_per_minute,
                },
            ))
        })
        .collect()
}

pub(crate) fn build_skill_timer_runtime_specs(
    runtime_specs: &[LoadedSkillRuntimeSpec],
) -> HashMap<String, SkillTimerRuntimeSpec> {
    runtime_specs
        .iter()
        .filter_map(|spec| {
            if spec.timers.is_empty() {
                return None;
            }
            if spec.abi != encmind_wasm_host::SkillAbi::Native {
                warn!(
                    skill_id = %spec.skill_id,
                    abi = ?spec.abi,
                    timers = spec.timers.len(),
                    "skipping non-native skill timers"
                );
                return None;
            }
            let invoker = Arc::new(encmind_wasm_host::invoker::SkillInvoker::new(
                spec.engine.clone(),
                spec.module.clone(),
                spec.abi,
                spec.skill_id.clone(),
                spec.capabilities.clone(),
                spec.resolved_limits.fuel_per_invocation,
                spec.max_memory_mb,
            ));
            Some((
                spec.skill_id.clone(),
                SkillTimerRuntimeSpec {
                    invoker,
                    wall_clock_timeout: Duration::from_millis(
                        spec.resolved_limits.wall_clock_ms.max(1),
                    ),
                },
            ))
        })
        .collect()
}

fn summarize_hard_errors(errors: &[String]) -> String {
    const MAX_REPORTED: usize = 3;
    let mut parts = errors
        .iter()
        .take(MAX_REPORTED)
        .cloned()
        .collect::<Vec<_>>();
    if errors.len() > MAX_REPORTED {
        parts.push(format!("and {} more", errors.len() - MAX_REPORTED));
    }
    parts.join("; ")
}

fn skill_id_from_load_error_key(key: &str) -> Option<String> {
    let path = Path::new(key);
    if let Some(ext) = path.extension().and_then(|v| v.to_str()) {
        if ext.eq_ignore_ascii_case("wasm") || ext.eq_ignore_ascii_case("toml") {
            return path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| encmind_core::skill_id::is_valid_skill_id(s).then(|| s.to_string()));
        }
    }

    let plain = key.trim();
    if plain.is_empty() || plain.contains('/') || plain.contains('\\') {
        return None;
    }
    encmind_core::skill_id::is_valid_skill_id(plain).then(|| plain.to_string())
}

fn parse_manifest_skill_name(path: &Path) -> Option<String> {
    let manifest = std::fs::read_to_string(path).ok()?;
    let parsed = encmind_wasm_host::manifest::parse_manifest_full(&manifest).ok()?;
    Some(parsed.manifest.name)
}

/// Resolve candidate skill IDs from a loader error key/path.
///
/// Shared by gateway runtime and CLI diagnostics so disabled-skill suppression
/// uses identical matching logic.
pub fn resolve_load_error_skill_ids(error_key: &str, skills_dir: &Path) -> HashSet<String> {
    let mut ids = HashSet::new();
    let key_path = Path::new(error_key);

    if let Some(ext) = key_path.extension().and_then(|v| v.to_str()) {
        if ext.eq_ignore_ascii_case("wasm") || ext.eq_ignore_ascii_case("toml") {
            if ext.eq_ignore_ascii_case("toml") {
                let stem = key_path.file_stem().and_then(|s| s.to_str());
                if let Some(name) = parse_manifest_skill_name(key_path) {
                    if stem.is_some_and(|s| s == name) {
                        ids.insert(name.clone());
                    }
                    ids.insert(name);
                } else if let Some(stem) = stem {
                    ids.insert(stem.to_string());
                }
            } else {
                let stem = key_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string());
                let mut inserted_manifest_name = false;
                let sibling_toml = key_path.with_extension("toml");
                if sibling_toml.is_file() {
                    if let Some(name) = parse_manifest_skill_name(&sibling_toml) {
                        if stem.as_deref().is_some_and(|s| s == name) {
                            ids.insert(name.clone());
                        }
                        ids.insert(name);
                        inserted_manifest_name = true;
                    }
                } else if let Some(stem) = stem.as_deref() {
                    let local_toml = skills_dir.join(format!("{stem}.toml"));
                    if local_toml.is_file() {
                        if let Some(name) = parse_manifest_skill_name(&local_toml) {
                            if stem == name {
                                ids.insert(name.clone());
                            }
                            ids.insert(name);
                            inserted_manifest_name = true;
                        }
                    }
                }
                if !inserted_manifest_name {
                    if let Some(stem) = stem {
                        ids.insert(stem);
                    }
                }
            }
            return ids;
        }
    }

    if let Some(id) = skill_id_from_load_error_key(error_key) {
        let local_toml = skills_dir.join(format!("{id}.toml"));
        ids.insert(id);
        if local_toml.is_file() {
            if let Some(name) = parse_manifest_skill_name(&local_toml) {
                ids.insert(name);
            }
        }
    }
    ids
}

/// Returns true when a loader error should be suppressed because it only
/// resolves to disabled skills.
///
/// Suppression is intentionally strict: all resolved candidate IDs must be
/// disabled. Mixed active/disabled candidate sets are surfaced as errors.
pub fn should_suppress_load_error_for_disabled(
    candidate_ids: &HashSet<String>,
    disabled_skill_ids: &HashSet<String>,
) -> bool {
    !candidate_ids.is_empty()
        && candidate_ids
            .iter()
            .all(|candidate| disabled_skill_ids.contains(candidate))
}

#[derive(Debug, Default, Clone)]
struct SkillResourceOverrides {
    max_fuel_per_invocation: Option<u64>,
    max_wall_clock_ms: Option<u64>,
    max_invocations_per_minute: Option<u32>,
    max_concurrent: Option<u32>,
}

fn load_skill_resource_overrides(
    db_pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    skill_id: &str,
) -> SkillResourceOverrides {
    let conn = match db_pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            warn!(skill_id = %skill_id, error = %e, "failed to acquire DB connection for skill resource overrides");
            return SkillResourceOverrides::default();
        }
    };

    let raw = match conn.query_row(
        "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = '__resources'",
        rusqlite::params![skill_id],
        |row| row.get::<_, Vec<u8>>(0),
    ) {
        Ok(bytes) => bytes,
        Err(rusqlite::Error::QueryReturnedNoRows) => return SkillResourceOverrides::default(),
        Err(e) => {
            warn!(skill_id = %skill_id, error = %e, "failed to read persisted skill resource overrides");
            return SkillResourceOverrides::default();
        }
    };

    let parsed = match serde_json::from_slice::<serde_json::Value>(&raw) {
        Ok(v) => v,
        Err(e) => {
            warn!(skill_id = %skill_id, error = %e, "failed to parse persisted skill resource overrides JSON");
            return SkillResourceOverrides::default();
        }
    };

    let Some(obj) = parsed.as_object() else {
        warn!(skill_id = %skill_id, "ignoring non-object skill resource overrides payload");
        return SkillResourceOverrides::default();
    };

    SkillResourceOverrides {
        max_fuel_per_invocation: obj.get("max_fuel_per_invocation").and_then(|v| v.as_u64()),
        max_wall_clock_ms: obj.get("max_wall_clock_ms").and_then(|v| v.as_u64()),
        max_invocations_per_minute: obj
            .get("max_invocations_per_minute")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(u32::MAX as u64) as u32),
        max_concurrent: obj
            .get("max_concurrent")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(u32::MAX as u64) as u32),
    }
}

pub(crate) fn load_skill_runtime_config(
    db_pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    skill_id: &str,
) -> Option<serde_json::Value> {
    let conn = match db_pool.get() {
        Ok(conn) => conn,
        Err(e) => {
            warn!(skill_id = %skill_id, error = %e, "failed to acquire DB connection for skill config");
            return None;
        }
    };

    let mut stmt = match conn.prepare(
        "SELECT key, value FROM skill_kv WHERE skill_id = ?1 AND key LIKE 'config:%' ORDER BY key",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            warn!(skill_id = %skill_id, error = %e, "failed to prepare skill config query");
            return None;
        }
    };

    let rows = match stmt
        .query_map(rusqlite::params![skill_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(skill_id = %skill_id, error = %e, "failed to read skill config");
            return None;
        }
    };

    if rows.is_empty() {
        return None;
    }

    let mut config = serde_json::Map::new();
    for (key, value) in rows {
        let short_key = key.strip_prefix("config:").unwrap_or(&key);
        let parsed = match serde_json::from_slice::<serde_json::Value>(&value) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!(
                    skill_id = %skill_id,
                    key = %short_key,
                    error = %e,
                    "invalid skill config JSON payload; falling back to string"
                );
                serde_json::Value::String(String::from_utf8_lossy(&value).into())
            }
        };
        config.insert(short_key.to_string(), parsed);
    }
    Some(serde_json::Value::Object(config))
}

fn validate_required_skill_config_keys(
    skill_id: &str,
    required_keys: &[String],
    config: Option<&serde_json::Value>,
) -> Result<(), String> {
    if required_keys.is_empty() {
        return Ok(());
    }

    let object = config.and_then(|value| value.as_object());
    let missing = required_keys
        .iter()
        .filter(|key| {
            object
                .and_then(|cfg| cfg.get(*key))
                .is_none_or(|value| value.is_null())
        })
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(());
    }

    Err(format!(
        "skill '{skill_id}' missing required runtime config keys: {}",
        missing.join(", ")
    ))
}

async fn resolve_execution_context_for_session(
    session_store: &Arc<dyn SessionStore>,
    session_id: &encmind_core::types::SessionId,
) -> encmind_wasm_host::ExecutionContext {
    match session_store.get_session(session_id).await {
        Ok(Some(session)) if session.channel == "cron" => {
            encmind_wasm_host::ExecutionContext::CronJob
        }
        Ok(Some(_)) => encmind_wasm_host::ExecutionContext::Interactive,
        Ok(None) => {
            warn!(
                session_id = %session_id,
                "session missing while resolving WASM execution context; defaulting to non-interactive"
            );
            encmind_wasm_host::ExecutionContext::CronJob
        }
        Err(error) => {
            warn!(
                session_id = %session_id,
                error = %error,
                "failed to resolve WASM execution context from session; defaulting to non-interactive"
            );
            encmind_wasm_host::ExecutionContext::CronJob
        }
    }
}

async fn resolve_channel_for_session(
    session_store: &Arc<dyn SessionStore>,
    session_id: &encmind_core::types::SessionId,
) -> Option<String> {
    match session_store.get_session(session_id).await {
        Ok(Some(session)) => Some(session.channel),
        Ok(None) => {
            warn!(
                session_id = %session_id,
                "session missing while resolving WASM session channel"
            );
            None
        }
        Err(error) => {
            warn!(
                session_id = %session_id,
                error = %error,
                "failed to resolve WASM session channel"
            );
            None
        }
    }
}

const MAX_EXECUTION_CONTEXT_CACHE_ENTRIES: usize = 1024;

fn cache_execution_context(
    cache: &mut HashMap<encmind_core::types::SessionId, encmind_wasm_host::ExecutionContext>,
    session_id: encmind_core::types::SessionId,
    context: encmind_wasm_host::ExecutionContext,
) {
    if !cache.contains_key(&session_id) && cache.len() >= MAX_EXECUTION_CONTEXT_CACHE_ENTRIES {
        cache.clear();
    }
    cache.insert(session_id, context);
}

fn cache_session_channel(
    cache: &mut HashMap<encmind_core::types::SessionId, String>,
    session_id: encmind_core::types::SessionId,
    channel: String,
) {
    if !cache.contains_key(&session_id) && cache.len() >= MAX_EXECUTION_CONTEXT_CACHE_ENTRIES {
        cache.clear();
    }
    cache.insert(session_id, channel);
}

/// Load WASM skills at startup. Hook bindings are registered into the provided registry.
/// Startup is best-effort: hard errors are logged and startup continues.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn load_wasm_skills_startup(
    config: &AppConfig,
    skills_dir: &Path,
    tool_registry: &mut ToolRegistry,
    session_store: Arc<dyn SessionStore>,
    hook_registry: &mut HookRegistry,
    db_pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    firewall: Arc<EgressFirewall>,
    http_client: Arc<reqwest::Client>,
    pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
    skill_toggle_store: Option<Arc<dyn encmind_core::traits::SkillToggleStore>>,
    audit_logger: Option<Arc<AuditLogger>>,
    skill_metrics: Arc<RwLock<HashMap<String, Arc<SkillMetrics>>>>,
) -> LoadedWasmSkills {
    let outcome = load_wasm_skills_impl(
        config,
        skills_dir,
        tool_registry,
        session_store,
        Some(hook_registry),
        None,
        db_pool,
        firewall,
        http_client,
        pending_approvals,
        skill_toggle_store,
        audit_logger,
        skill_metrics,
    )
    .await;

    if !outcome.hard_errors.is_empty() {
        warn!(
            error_count = outcome.hard_errors.len(),
            "WASM skills loaded with hard errors; some tools/hooks were skipped"
        );
        for error in outcome.hard_errors.iter().take(5) {
            warn!(error = %error, "WASM skill load error");
        }
    }

    LoadedWasmSkills {
        summaries: outcome.summaries,
        runtime_specs: outcome.runtime_specs,
        known_skill_ids: outcome.known_skill_ids,
    }
}

/// Reload WASM skills for runtime refresh flows (e.g., key/mode changes).
/// Refresh is fail-closed: any hard error aborts refresh and callers should roll back.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn load_wasm_skills_refresh(
    config: &AppConfig,
    skills_dir: &Path,
    tool_registry: &mut ToolRegistry,
    session_store: Arc<dyn SessionStore>,
    hook_registry_for_registration: Option<&mut HookRegistry>,
    db_pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    firewall: Arc<EgressFirewall>,
    http_client: Arc<reqwest::Client>,
    pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
    handler_hook_registry: Arc<RwLock<HookRegistry>>,
    skill_toggle_store: Option<Arc<dyn encmind_core::traits::SkillToggleStore>>,
    audit_logger: Option<Arc<AuditLogger>>,
    skill_metrics: Arc<RwLock<HashMap<String, Arc<SkillMetrics>>>>,
) -> Result<LoadedWasmSkills, String> {
    let outcome = load_wasm_skills_impl(
        config,
        skills_dir,
        tool_registry,
        session_store,
        hook_registry_for_registration,
        Some(handler_hook_registry),
        db_pool,
        firewall,
        http_client,
        pending_approvals,
        skill_toggle_store,
        audit_logger,
        skill_metrics,
    )
    .await;

    if outcome.hard_errors.is_empty() {
        Ok(LoadedWasmSkills {
            summaries: outcome.summaries,
            runtime_specs: outcome.runtime_specs,
            known_skill_ids: outcome.known_skill_ids,
        })
    } else {
        Err(summarize_hard_errors(&outcome.hard_errors))
    }
}

#[allow(clippy::too_many_arguments)]
async fn load_wasm_skills_impl(
    config: &AppConfig,
    skills_dir: &Path,
    tool_registry: &mut ToolRegistry,
    session_store: Arc<dyn SessionStore>,
    mut hook_registry_for_registration: Option<&mut HookRegistry>,
    handler_hook_registry: Option<Arc<RwLock<HookRegistry>>>,
    db_pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    firewall: Arc<EgressFirewall>,
    http_client: Arc<reqwest::Client>,
    pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
    skill_toggle_store: Option<Arc<dyn encmind_core::traits::SkillToggleStore>>,
    audit_logger: Option<Arc<AuditLogger>>,
    skill_metrics: Arc<RwLock<HashMap<String, Arc<SkillMetrics>>>>,
) -> LoadWasmSkillsOutcome {
    use encmind_wasm_host::manifest::{validate_against_policy, validate_third_party};
    use encmind_wasm_host::skill_loader::{load_skills_from_dir, register_skill_hooks, LoadError};

    let mut loaded_summaries = Vec::new();
    let mut loaded_runtime_specs = Vec::new();
    let mut known_skill_ids = HashSet::new();
    let mut hard_errors = Vec::new();
    let mut disabled_load_error_skill_ids: HashSet<String> = HashSet::new();

    // Create a dedicated wasmtime engine with async support for skill loading
    let mut wasm_config = wasmtime::Config::new();
    wasm_config.async_support(true);
    wasm_config.consume_fuel(true);
    let engine = match wasmtime::Engine::new(&wasm_config) {
        Ok(e) => e,
        Err(e) => {
            let msg = format!("failed to create WASM engine for skill loading: {e}");
            warn!(error = %e, "failed to create WASM engine for skill loading");
            hard_errors.push(msg);
            return LoadWasmSkillsOutcome {
                summaries: loaded_summaries,
                runtime_specs: loaded_runtime_specs,
                known_skill_ids,
                hard_errors,
            };
        }
    };

    let disabled_skill_ids = if let Some(store) = skill_toggle_store.as_ref() {
        match store.list_disabled().await {
            Ok(ids) => ids
                .into_iter()
                .collect::<std::collections::HashSet<String>>(),
            Err(e) => {
                let msg = format!("failed to read skill toggle state: {e}");
                warn!(error = %e, "failed to read skill toggle state");
                hard_errors.push(msg);
                return LoadWasmSkillsOutcome {
                    summaries: loaded_summaries,
                    runtime_specs: loaded_runtime_specs,
                    known_skill_ids,
                    hard_errors,
                };
            }
        }
    } else {
        std::collections::HashSet::new()
    };

    let outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy> =
        Arc::new(GatewayOutboundPolicy {
            firewall: firewall.clone(),
        });
    let approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter> =
        Arc::new(GatewayApprovalPrompter {
            pending_approvals: pending_approvals.clone(),
        });

    let load_result = load_skills_from_dir(skills_dir, &engine);
    for error in &load_result.errors {
        let (error_key, error_message) = match error {
            LoadError::DirectoryUnreadable { dir, error } => {
                (dir.display().to_string(), error.clone())
            }
            LoadError::MissingManifest {
                skill_id,
                wasm_path,
            } => (
                wasm_path.display().to_string(),
                format!(
                    "missing manifest for skill '{}' ({})",
                    skill_id,
                    wasm_path.display()
                ),
            ),
            LoadError::SkillLoadFailed {
                skill_id,
                wasm_path,
                error,
            } => (
                wasm_path.display().to_string(),
                format!(
                    "failed to load skill '{}' ({}): {}",
                    skill_id,
                    wasm_path.display(),
                    error
                ),
            ),
        };
        let candidate_ids = resolve_load_error_skill_ids(&error_key, skills_dir);
        for candidate in &candidate_ids {
            known_skill_ids.insert(candidate.clone());
        }
        if should_suppress_load_error_for_disabled(&candidate_ids, &disabled_skill_ids) {
            for candidate in &candidate_ids {
                disabled_load_error_skill_ids.insert(candidate.clone());
            }
            info!(
                skill = %error_key,
                resolved_ids = ?candidate_ids,
                error = %error_message,
                "ignoring WASM load error for disabled skill"
            );
            continue;
        }
        warn!(
            skill = %error_key,
            error = %error_message,
            "failed to load WASM skill"
        );
        hard_errors.push(format!("{error_key}: {error_message}"));
    }

    // Reject duplicate manifest names up front. Runtime state and timer/transform
    // maps are keyed by `skill_id`; allowing duplicates would create last-write-
    // wins behavior and non-deterministic execution.
    let mut skill_id_counts: HashMap<String, usize> = HashMap::new();
    for skill in &load_result.skills {
        *skill_id_counts
            .entry(skill.manifest.manifest.name.clone())
            .or_insert(0) += 1;
    }
    let duplicate_skill_ids: HashSet<String> = skill_id_counts
        .into_iter()
        .filter_map(|(skill_id, count)| (count > 1).then_some(skill_id))
        .collect();
    let policy = PolicyEnforcer::new(config.plugin_policy.clone());
    let max_memory_mb = config.skills.resource_limits.max_memory_mb as usize;
    let mut accepted_skills = Vec::new();
    let mut total_hooks = 0usize;
    let mut total_tools = 0usize;
    let fallback_hook_registry = if handler_hook_registry.is_none() {
        hook_registry_for_registration
            .as_deref()
            .map(|registry| Arc::new(RwLock::new(registry.clone())))
    } else {
        None
    };

    // Enforce global skills.enabled allowlist
    let enabled_allowlist = &config.skills.enabled;
    let enforce_allowlist = !enabled_allowlist.is_empty();
    if enforce_allowlist {
        info!(skills_enabled = ?enabled_allowlist, "enforcing global skill allowlist");
    }

    if !duplicate_skill_ids.is_empty() {
        let mut duplicates = duplicate_skill_ids.iter().cloned().collect::<Vec<_>>();
        duplicates.sort();
        for duplicate in duplicates {
            known_skill_ids.insert(duplicate.clone());
            let in_scope = (!enforce_allowlist || enabled_allowlist.contains(&duplicate))
                && !disabled_skill_ids.contains(&duplicate);
            if in_scope {
                warn!(
                    skill_id = %duplicate,
                    "duplicate WASM skill ID detected; skipping all artifacts for this skill_id"
                );
                hard_errors.push(format!(
                    "duplicate skill_id '{duplicate}' declared by multiple artifacts; skill IDs must be unique"
                ));
            } else {
                info!(
                    skill_id = %duplicate,
                    "duplicate WASM skill ID ignored because skill is inactive (allowlist/disabled)"
                );
            }
        }
    }

    for skill in load_result.skills {
        let manifest = &skill.manifest.manifest;
        known_skill_ids.insert(manifest.name.clone());

        if duplicate_skill_ids.contains(&manifest.name) {
            continue;
        }

        // Skip skills not in the global allowlist
        if enforce_allowlist && !enabled_allowlist.contains(&manifest.name) {
            info!(skill = %manifest.name, "skipping skill not in skills.enabled allowlist");
            continue;
        }
        if disabled_skill_ids.contains(&manifest.name) {
            info!(skill = %manifest.name, "skipping skill registration: disabled via skills.toggle");
            // Keep disabled skills visible in skills.list so operators can re-enable
            // without needing to remember IDs out-of-band.
            loaded_summaries.push(LoadedSkillSummary {
                id: manifest.name.clone(),
                version: manifest.version.clone(),
                description: manifest.description.clone(),
                tool_name: skill
                    .manifest
                    .tool
                    .as_ref()
                    .map(|t| namespaced_wasm_tool_name(&manifest.name, &t.name)),
                hook_points: skill.manifest.hooks.bindings.keys().cloned().collect(),
                enabled: false,
                output_schema: skill
                    .manifest
                    .tool
                    .as_ref()
                    .and_then(|t| t.output_schema.clone()),
            });
            continue;
        }
        let resource_overrides = load_skill_resource_overrides(db_pool.as_ref(), &manifest.name);
        let resolved_limits = resolve_resource_limits(
            resource_overrides
                .max_fuel_per_invocation
                .or(skill.manifest.resources.max_fuel_per_invocation),
            resource_overrides
                .max_wall_clock_ms
                .or(skill.manifest.resources.max_wall_clock_ms),
            resource_overrides
                .max_invocations_per_minute
                .or(skill.manifest.resources.max_invocations_per_minute),
            resource_overrides
                .max_concurrent
                .or(skill.manifest.resources.max_concurrent),
            &config.plugin_policy.resource_ceiling,
        );
        let manifest_hash = format!("{}@{}", manifest.name, manifest.version);
        let startup_skill_config = load_skill_runtime_config(db_pool.as_ref(), &manifest.name);
        if let Err(reason) = validate_required_skill_config_keys(
            &manifest.name,
            &skill.manifest.required_config_keys,
            startup_skill_config.as_ref(),
        ) {
            warn!(skill = %manifest.name, reason = %reason, "rejecting WASM skill");
            hard_errors.push(reason);
            continue;
        }

        if let Err(e) = validate_third_party(manifest) {
            warn!(
                skill = %manifest.name,
                error = %e,
                "rejecting WASM skill due to third-party capability constraints"
            );
            continue;
        }

        match validate_against_policy(manifest, &policy) {
            Ok(PolicyDecision::Allowed) => {}
            Ok(PolicyDecision::NeedsPrompt(caps)) => {
                warn!(
                    skill = %manifest.name,
                    capabilities = %caps.join(","),
                    "rejecting WASM skill at startup: capabilities require interactive approval"
                );
                continue;
            }
            Ok(PolicyDecision::Denied(reason)) => {
                warn!(
                    skill = %manifest.name,
                    reason = %reason,
                    "rejecting WASM skill by operator policy"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    skill = %manifest.name,
                    error = %e,
                    "rejecting WASM skill: policy validation failed"
                );
                continue;
            }
        }

        let hook_points = skill.manifest.hooks.bindings.keys().cloned().collect();
        let output_schema = skill
            .manifest
            .tool
            .as_ref()
            .and_then(|t| t.output_schema.clone());
        let output_validator = match output_schema.as_ref() {
            Some(schema) => match jsonschema::validator_for(schema) {
                Ok(validator) => Some(Arc::new(validator)),
                Err(error) => {
                    warn!(
                        skill = %manifest.name,
                        error = %error,
                        "rejecting WASM skill: invalid output schema"
                    );
                    hard_errors.push(format!(
                        "output schema validation failed for skill '{}': {error}",
                        manifest.name
                    ));
                    continue;
                }
            },
            None => None,
        };

        if let Some(hook_registry) = hook_registry_for_registration.as_deref_mut() {
            if !skill.manifest.hooks.bindings.is_empty() {
                let hook_registry_for_bridge = handler_hook_registry
                    .as_ref()
                    .cloned()
                    .or_else(|| fallback_hook_registry.clone());
                match register_skill_hooks(
                    &skill,
                    hook_registry,
                    &engine,
                    resolved_limits.fuel_per_invocation,
                    max_memory_mb,
                    encmind_wasm_host::hook_bridge::HookRuntimeDeps {
                        db_pool: Some(db_pool.clone()),
                        http_client: Some(http_client.clone()),
                        outbound_policy: Some(outbound_policy.clone()),
                        hook_registry: hook_registry_for_bridge,
                        approval_prompter: Some(approval_prompter.clone()),
                        session_store: Some(session_store.clone()),
                    },
                ) {
                    Ok(count) => {
                        total_hooks += count;
                        if let Some(shared_hook_registry) = fallback_hook_registry.as_ref() {
                            // Keep startup hook bridges pointed at a single live
                            // registry snapshot that is updated as hooks register.
                            let snapshot = hook_registry.clone();
                            let mut guard = shared_hook_registry.write().await;
                            *guard = snapshot;
                        }
                    }
                    Err(e) => {
                        warn!(
                            skill = %manifest.name,
                            error = %e,
                            "failed to register hooks for WASM skill"
                        );
                        hard_errors.push(format!(
                            "hook registration failed for skill '{}': {e}",
                            manifest.name
                        ));
                    }
                }
            }
        }

        loaded_runtime_specs.push(LoadedSkillRuntimeSpec {
            skill_id: manifest.name.clone(),
            manifest_hash,
            engine: engine.clone(),
            module: skill.module.clone(),
            abi: skill.abi,
            capabilities: manifest.capabilities.clone(),
            timers: skill.manifest.timers.clone(),
            transforms: skill.manifest.transforms.clone(),
            resolved_limits: resolved_limits.clone(),
            max_memory_mb,
        });

        accepted_skills.push((
            skill,
            resolved_limits,
            hook_points,
            output_schema,
            output_validator,
        ));
    }

    let hook_registry_arc = if let Some(registry) = handler_hook_registry {
        registry
    } else if let Some(registry) = fallback_hook_registry {
        registry
    } else if let Some(registry) = hook_registry_for_registration.as_deref() {
        Arc::new(RwLock::new(registry.clone()))
    } else {
        // Guard against accidental misuse in future edits.
        hard_errors
            .push("WASM skill loader was called without a hook registry context".to_string());
        Arc::new(RwLock::new(HookRegistry::new()))
    };
    let accepted_skill_count = accepted_skills.len();
    for (skill, resolved_limits, hook_points, output_schema, output_validator) in accepted_skills {
        let manifest = &skill.manifest.manifest;
        let mut registered_tool_name = None;

        // Register tool if the manifest declares one
        if let Some(ref tool_def) = skill.manifest.tool {
            let invoker = Arc::new(encmind_wasm_host::invoker::SkillInvoker::new(
                engine.clone(),
                skill.module.clone(),
                skill.abi,
                manifest.name.clone(),
                manifest.capabilities.clone(),
                resolved_limits.fuel_per_invocation,
                max_memory_mb,
            ));
            let handler = WasmSkillToolHandler {
                invoker,
                wall_clock_timeout: Duration::from_millis(resolved_limits.wall_clock_ms.max(1)),
                session_store: session_store.clone(),
                db_pool: db_pool.clone(),
                http_client: http_client.clone(),
                hook_registry: hook_registry_arc.clone(),
                outbound_policy: outbound_policy.clone(),
                approval_prompter: approval_prompter.clone(),
                audit: audit_logger.clone(),
                skill_metrics: skill_metrics.clone(),
                execution_context_cache: Arc::new(RwLock::new(HashMap::new())),
                session_channel_cache: Arc::new(RwLock::new(HashMap::new())),
                output_validator,
            };

            let namespaced_tool = namespaced_wasm_tool_name(&manifest.name, &tool_def.name);
            if let Err(e) = tool_registry.register_skill_tool(
                &manifest.name,
                &namespaced_tool,
                &tool_def.description,
                tool_def.parameters.clone(),
                Arc::new(handler),
            ) {
                warn!(
                    skill = %manifest.name,
                    tool = %namespaced_tool,
                    error = %e,
                    "failed to register WASM skill tool"
                );
                hard_errors.push(format!(
                    "tool registration failed for skill '{}', tool '{}': {e}",
                    manifest.name, namespaced_tool
                ));
            } else {
                registered_tool_name = Some(namespaced_tool);
                total_tools += 1;
            }
        }

        loaded_summaries.push(LoadedSkillSummary {
            id: manifest.name.clone(),
            version: manifest.version.clone(),
            description: manifest.description.clone(),
            tool_name: registered_tool_name,
            hook_points,
            enabled: true,
            output_schema,
        });
    }

    // Keep disabled skills visible in skills.list even if they currently fail to
    // load (malformed wasm/manifest mismatch/etc.). This ensures operators can
    // discover and re-enable/remove them without out-of-band tracking.
    let existing_summary_ids: HashSet<String> =
        loaded_summaries.iter().map(|s| s.id.clone()).collect();
    for skill_id in disabled_load_error_skill_ids {
        if existing_summary_ids.contains(&skill_id) {
            continue;
        }
        loaded_summaries.push(LoadedSkillSummary {
            id: skill_id,
            version: "unknown".to_string(),
            description: "disabled skill (failed to load)".to_string(),
            tool_name: None,
            hook_points: Vec::new(),
            enabled: false,
            output_schema: None,
        });
    }

    if total_tools > 0 || total_hooks > 0 {
        info!(
            skills = accepted_skill_count,
            tools = total_tools,
            hooks = total_hooks,
            "WASM skills loaded"
        );
    }

    LoadWasmSkillsOutcome {
        summaries: loaded_summaries,
        runtime_specs: loaded_runtime_specs,
        known_skill_ids,
        hard_errors,
    }
}

/// Tool handler that invokes a WASM skill via the unified SkillInvoker.
struct WasmSkillToolHandler {
    invoker: Arc<encmind_wasm_host::invoker::SkillInvoker>,
    wall_clock_timeout: Duration,
    session_store: Arc<dyn SessionStore>,
    db_pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    http_client: Arc<reqwest::Client>,
    hook_registry: Arc<RwLock<HookRegistry>>,
    outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy>,
    approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter>,
    audit: Option<Arc<AuditLogger>>,
    skill_metrics: Arc<RwLock<HashMap<String, Arc<SkillMetrics>>>>,
    execution_context_cache:
        Arc<RwLock<HashMap<encmind_core::types::SessionId, encmind_wasm_host::ExecutionContext>>>,
    session_channel_cache: Arc<RwLock<HashMap<encmind_core::types::SessionId, String>>>,
    output_validator: Option<Arc<jsonschema::Validator>>,
}

pub(crate) struct GatewayOutboundPolicy {
    pub firewall: Arc<EgressFirewall>,
}

#[async_trait::async_trait]
impl encmind_wasm_host::OutboundPolicy for GatewayOutboundPolicy {
    async fn check_url(&self, url: &str) -> Result<(), String> {
        self.firewall
            .check_url(url)
            .await
            .map_err(|e| e.to_string())
    }
}

pub(crate) struct GatewayApprovalPrompter {
    pub pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
}

struct PendingApprovalDropGuard {
    pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
    request_id: String,
}

impl PendingApprovalDropGuard {
    fn new(
        pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
        request_id: String,
    ) -> Self {
        Self {
            pending_approvals,
            request_id,
        }
    }
}

impl Drop for PendingApprovalDropGuard {
    fn drop(&mut self) {
        let mut pending = self.pending_approvals.lock().unwrap();
        pending.remove(&self.request_id);
    }
}

#[async_trait::async_trait]
impl encmind_wasm_host::ApprovalPrompter for GatewayApprovalPrompter {
    async fn prompt(
        &self,
        request: SkillApprovalRequest,
        timeout: Duration,
    ) -> SkillApprovalResponse {
        let request_id = request.request_id.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<SkillApprovalResponse>();
        {
            let mut pending = self.pending_approvals.lock().unwrap();
            pending.insert(
                request_id.clone(),
                PendingSkillApproval {
                    request: request.clone(),
                    responder: tx,
                },
            );
        }
        let _cleanup =
            PendingApprovalDropGuard::new(self.pending_approvals.clone(), request_id.clone());

        info!(
            request_id = %request_id,
            skill_id = %request.skill_id,
            prompt = %request.prompt,
            "WASM skill approval requested"
        );

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => SkillApprovalResponse {
                request_id,
                approved: false,
                choice: None,
            },
            Err(_) => SkillApprovalResponse {
                request_id,
                approved: false,
                choice: None,
            },
        }
    }
}

#[async_trait::async_trait]
impl encmind_core::traits::InternalToolHandler for WasmSkillToolHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        session_id: &encmind_core::types::SessionId,
        agent_id: &encmind_core::types::AgentId,
    ) -> Result<String, encmind_core::error::AppError> {
        let invocation_id = ulid::Ulid::new().to_string();
        let started_at = std::time::Instant::now();
        let metric = {
            let mut metrics = self.skill_metrics.write().await;
            metrics
                .entry(self.invoker.skill_id().to_string())
                .or_insert_with(|| Arc::new(SkillMetrics::new()))
                .clone()
        };
        let execution_context = {
            let cached = self
                .execution_context_cache
                .read()
                .await
                .get(session_id)
                .copied();
            match cached {
                Some(ctx) => ctx,
                None => {
                    let resolved =
                        resolve_execution_context_for_session(&self.session_store, session_id)
                            .await;
                    let mut cache = self.execution_context_cache.write().await;
                    cache_execution_context(&mut cache, session_id.clone(), resolved);
                    resolved
                }
            }
        };
        let channel = {
            let cached = self
                .session_channel_cache
                .read()
                .await
                .get(session_id)
                .cloned();
            match cached {
                Some(channel) => Some(channel),
                None => {
                    let resolved =
                        resolve_channel_for_session(&self.session_store, session_id).await;
                    if let Some(ref channel) = resolved {
                        let mut cache = self.session_channel_cache.write().await;
                        cache_session_channel(&mut cache, session_id.clone(), channel.clone());
                    }
                    resolved
                }
            }
        };
        let deps = encmind_wasm_host::invoker::InvokeDeps {
            db_pool: Some(self.db_pool.clone()),
            http_client: Some(self.http_client.clone()),
            outbound_policy: Some(self.outbound_policy.clone()),
            hook_registry: Some(self.hook_registry.clone()),
            approval_prompter: Some(self.approval_prompter.clone()),
            skill_config: load_skill_runtime_config(self.db_pool.as_ref(), self.invoker.skill_id()),
            execution_context,
            session_id: Some(session_id.as_str().to_string()),
            agent_id: Some(agent_id.as_str().to_string()),
            channel,
            invocation_id: Some(invocation_id.clone()),
        };

        let result = self
            .invoker
            .invoke_json(&input, &deps, self.wall_clock_timeout)
            .await
            .and_then(|v| {
                if let Some(ref validator) = self.output_validator {
                    if !validator.is_valid(&v) {
                        let errors = validator
                            .iter_errors(&v)
                            .map(|err| err.to_string())
                            .take(3)
                            .collect::<Vec<_>>();
                        let detail = if errors.is_empty() {
                            "unknown validation error".to_string()
                        } else {
                            errors.join("; ")
                        };
                        return Err(encmind_core::error::WasmHostError::ExecutionFailed(
                            format!(
                                "skill '{}' output failed schema validation: {detail}",
                                self.invoker.skill_id()
                            ),
                        ));
                    }
                }
                Ok(v.to_string())
            })
            .map_err(encmind_core::error::AppError::WasmHost);
        metric
            .invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *metric.last_invoked_at.lock().unwrap() = Some(chrono::Utc::now().to_rfc3339());
        if result.is_err() {
            metric
                .errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Audit log the invocation (success and all error paths).
        if let Some(ref audit) = self.audit {
            let duration_ms = started_at.elapsed().as_millis();
            let status = if result.is_ok() { "ok" } else { "error" };
            let detail = serde_json::json!({
                "invocation_id": invocation_id,
                "session_id": session_id.as_str(),
                "agent_id": agent_id.as_str(),
                "status": status,
                "duration_ms": duration_ms,
                "error": result.as_ref().err().map(|e| e.to_string()),
            });
            if let Err(e) = audit.append(
                "skill",
                &format!("skill.{}.invoke", self.invoker.skill_id()),
                Some(&detail.to_string()),
                Some(agent_id.as_str()),
            ) {
                warn!(skill = %self.invoker.skill_id(), error = %e, "failed to write skill audit entry");
            }
        }

        result
    }
}

fn register_base_tools(
    registry: &mut ToolRegistry,
    config: &AppConfig,
    _browser_pool: &Option<Arc<encmind_browser::pool::BrowserPool>>,
    node_registry: Option<Arc<NodeRegistry>>,
    device_store: Option<Arc<dyn DeviceStore>>,
) {
    let local_policy_engine = Arc::new(LocalToolPolicyEngine::from_config(config));
    let local_policy_status = local_policy_engine.status();
    let node_tools_available = node_registry.is_some() && device_store.is_some();
    let local_prefix = if node_tools_available { "local_" } else { "" };

    // Always register local tools. If node tools are present, namespace local tools
    // so canonical names remain mapped to node_* for backward-compatible behavior.
    if let Err(e) = crate::local_tool_handler::register_local_tools_with_prefix(
        registry,
        local_policy_engine,
        60,
        local_prefix,
    ) {
        warn!(error = %e, "failed to register local tools");
    } else {
        info!(
            prefix = %local_prefix,
            bash_enabled = local_policy_status.bash_effective_enabled,
            "local tools registered (file_read, file_write, file_list, optional bash_exec)"
        );
    }

    // Optionally register node command tools for paired edge devices.
    // These use the `node_` prefix to avoid collision with local tools.
    if let (Some(node_reg), Some(dev_store)) = (node_registry, device_store) {
        let device_id_prop = serde_json::json!({
            "type": "string",
            "description": "Target device ID. Omit to use the first connected device."
        });
        for (command, tool_name, description, params_schema) in [
            (
                "file.read",
                "node_file_read",
                "Read a file from a connected edge device",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute file path to read" },
                        "device_id": device_id_prop.clone()
                    },
                    "required": ["path"]
                }),
            ),
            (
                "file.write",
                "node_file_write",
                "Write content to a file on a connected edge device",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute file path to write" },
                        "content": { "type": "string", "description": "Content to write to the file" },
                        "device_id": device_id_prop.clone()
                    },
                    "required": ["path", "content"]
                }),
            ),
            (
                "file.list",
                "node_file_list",
                "List files in a directory on a connected edge device",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute directory path to list" },
                        "device_id": device_id_prop.clone()
                    },
                    "required": ["path"]
                }),
            ),
            (
                "bash.exec",
                "node_bash_exec",
                "Execute a shell command on a connected edge device (30s timeout, 256KB output limit)",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to execute" },
                        "device_id": device_id_prop.clone()
                    },
                    "required": ["command"]
                }),
            ),
        ] {
            let handler = crate::node_command_handler::NodeCommandHandler::new(
                command.to_string(),
                node_reg.clone(),
                dev_store.clone(),
            );
            if let Err(e) =
                registry.register_internal(tool_name, description, params_schema, Arc::new(handler))
            {
                warn!(error = %e, tool = tool_name, "failed to register node command tool");
            }
        }
        info!("node command tools registered (node_file_read, node_file_write, node_file_list, node_bash_exec)");

        // Preserve historical semantics when a node is connected: canonical names
        // route to node-backed tools, while local tools remain explicitly available
        // as local_*.
        for (alias, target) in [
            ("file_read", "node_file_read"),
            ("file_write", "node_file_write"),
            ("file_list", "node_file_list"),
            ("bash_exec", "node_bash_exec"),
        ] {
            if let Err(e) = registry.register_alias(alias, target) {
                warn!(error = %e, alias, target, "failed to register node compatibility alias");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn initialize_tool_registry(
    config: &AppConfig,
    llm_backend: &Option<Arc<dyn LlmBackend>>,
    session_store: Arc<dyn SessionStore>,
    agent_registry: Arc<dyn AgentRegistry>,
    agent_pool: Arc<AgentPool>,
    firewall: Arc<EgressFirewall>,
    browser_pool: Option<Arc<encmind_browser::pool::BrowserPool>>,
    node_registry: Option<Arc<NodeRegistry>>,
    device_store: Option<Arc<dyn DeviceStore>>,
    shared_config: Option<Arc<RwLock<AppConfig>>>,
) -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_base_tools(
        &mut registry,
        config,
        &browser_pool,
        node_registry.clone(),
        device_store.clone(),
    );

    if let Some(llm) = llm_backend.clone() {
        let subagent_runtime_config = RuntimeConfig {
            max_tool_iterations: config.token_optimization.max_tool_iterations,
            max_tool_output_chars: config.token_optimization.max_tool_output_chars,
            per_tool_output_chars: config.token_optimization.per_tool_output_chars.clone(),
            context_config: ContextConfig {
                sliding_window_truncation_threshold: config
                    .token_optimization
                    .sliding_window_truncation_threshold,
                ..ContextConfig::default()
            },
            tool_calls_per_run: Some(config.security.rate_limit.tool_calls_per_run),
            ..RuntimeConfig::default()
        };

        let has_spawn_permissions = config
            .agents
            .list
            .iter()
            .any(|a| !a.subagents.allow_agents.is_empty());

        if has_spawn_permissions {
            let mut allow_map: HashMap<String, Vec<String>> = HashMap::new();
            for agent in &config.agents.list {
                allow_map.insert(agent.id.clone(), agent.subagents.allow_agents.clone());
            }

            let mut base_registry = ToolRegistry::new();
            register_base_tools(
                &mut base_registry,
                config,
                &None,
                node_registry,
                device_store,
            );
            let (approval_handler, approval_checker) =
                gateway_approval_policy(config.security.bash_mode.clone());

            let mut spawn_handler = SpawnAgentHandler::new(
                llm,
                session_store,
                agent_registry,
                agent_pool,
                Arc::new(base_registry),
                subagent_runtime_config,
            )
            .with_firewall(firewall)
            .with_approval(approval_handler, approval_checker)
            .with_allow_map(allow_map);

            if let Some(ref sc) = shared_config {
                spawn_handler = spawn_handler.with_config(sc.clone());
            }

            if let Err(e) = registry.register_internal(
                "agents_spawn",
                "Delegate a task to another configured agent",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string" },
                        "task": { "type": "string" }
                    },
                    "required": ["agent_id", "task"]
                }),
                Arc::new(spawn_handler),
            ) {
                warn!(error = %e, "failed to register agents_spawn tool");
            }
        } else {
            info!("agents_spawn tool not registered: no spawn permissions configured");
        }
    } else {
        warn!("tool registry initialized without agents_spawn because LLM backend is unavailable");
    }

    if registry.is_empty() {
        warn!("tool registry has no registered tools");
    } else {
        info!(tool_count = registry.len(), "tool registry initialized");
    }

    registry
}

#[cfg(test)]
fn build_api_backend(provider: &ApiProviderConfig) -> Result<Box<dyn LlmBackend>, LlmError> {
    let key_env = provider_api_key_env(&provider.name);
    let api_key = std::env::var(&key_env).map_err(|_| LlmError::NotConfigured)?;
    build_api_backend_with_key(provider, api_key)
}

fn build_api_backend_with_key(
    provider: &ApiProviderConfig,
    api_key: String,
) -> Result<Box<dyn LlmBackend>, LlmError> {
    let model = provider.model.clone();
    let base_url = provider.base_url.clone();

    if provider.name.eq_ignore_ascii_case("anthropic") {
        Ok(Box::new(AnthropicBackend::new(api_key, model, base_url)))
    } else if provider.name.eq_ignore_ascii_case("openai") {
        Ok(Box::new(OpenAiBackend::new(api_key, model, base_url)))
    } else {
        // Non-standard provider: require base_url to avoid accidentally sending
        // API keys to the wrong endpoint (default OpenAI URL).
        if base_url.is_none() {
            return Err(LlmError::NotConfigured);
        }
        info!(
            provider = %provider.name,
            "using OpenAI-compatible backend for custom provider"
        );
        Ok(Box::new(OpenAiBackend::new(api_key, model, base_url)))
    }
}

fn provider_api_key_env(provider_name: &str) -> String {
    if provider_name.eq_ignore_ascii_case("openai") {
        return "OPENAI_API_KEY".to_owned();
    }
    if provider_name.eq_ignore_ascii_case("anthropic") {
        return "ANTHROPIC_API_KEY".to_owned();
    }
    let normalized = provider_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{normalized}_API_KEY")
}

async fn initialize_memory_store(
    config: &AppConfig,
    pool: &r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
) -> Result<Option<Arc<MemoryStoreImpl>>, anyhow::Error> {
    if !config.memory.enabled {
        return Ok(None);
    }

    let mode_enforcer = EmbeddingModeEnforcer::new(config.memory.embedding_mode.clone());
    if let Err(e) =
        mode_enforcer.verify_firewall_consistency(&config.security.egress_firewall.global_allowlist)
    {
        warn!(
            error = %e,
            "memory embedding/firewall consistency check failed; continuing because enforcement happens at request-time firewall"
        );
    }

    let memory_cfg = config.memory.clone();
    let embedder: Arc<dyn Embedder> =
        tokio::task::spawn_blocking(move || mode_enforcer.create_embedder(&memory_cfg))
            .await
            .map_err(|e| {
                anyhow::anyhow!("memory initialization failed: embedder task panicked: {e}")
            })?
            .map_err(|e| {
                anyhow::anyhow!("memory initialization failed: cannot create embedder: {e}")
            })?;

    let vector_store: Arc<dyn VectorStore> = match &config.memory.vector_backend {
        VectorBackendConfig::Sqlite => Arc::new(SqliteVectorStore::new(pool.clone())),
        VectorBackendConfig::Qdrant { url, collection } => {
            #[cfg(feature = "qdrant")]
            {
                let store = encmind_memory::vector_store::QdrantVectorStore::connect(
                    url,
                    collection,
                    embedder.dimensions(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("memory initialization failed: qdrant connect: {e}")
                })?;
                Arc::new(store)
            }
            #[cfg(not(feature = "qdrant"))]
            {
                let _ = (url, collection);
                return Err(anyhow::anyhow!(
                    "memory.vector_backend=qdrant requires the 'qdrant' feature"
                ));
            }
        }
    };

    let metadata_store: Arc<dyn MemoryMetadataStore> =
        Arc::new(SqliteMemoryMetadataStore::new(pool.clone()));

    info!("memory subsystem enabled");
    Ok(Some(Arc::new(MemoryStoreImpl::new(
        embedder,
        vector_store,
        metadata_store,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use encmind_core::config::{AccessAction, AllowlistEntry, InboundAccessPolicy, SlackConfig};
    use encmind_core::error::{LlmError, PluginError};
    use encmind_core::hooks::{HookHandler, HookPoint, HookResult};
    use encmind_core::traits::{
        CompletionDelta, CompletionParams, FinishReason, LlmBackend, ModelInfo,
    };
    use encmind_core::types::{
        AgentId, Attachment, CronJob, CronJobId, InboundMessage, ResolvedResourceLimits, SessionId,
    };
    use futures::Stream;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    use crate::test_utils::make_test_state;

    struct AbortHook;
    #[async_trait::async_trait]
    impl HookHandler for AbortHook {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Abort {
                reason: "blocked".into(),
            })
        }
    }

    struct RewriteInboundHook;
    #[async_trait::async_trait]
    impl HookHandler for RewriteInboundHook {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Override(serde_json::json!({
                "message": {
                    "channel": "slack",
                    "sender_id": "C9:U9",
                    "content": [{"type":"text","text":"rewritten inbound"}],
                    "attachments": [],
                    "timestamp": "2026-01-01T00:00:00Z"
                }
            })))
        }
    }

    struct RewriteOutboundHook;
    #[async_trait::async_trait]
    impl HookHandler for RewriteOutboundHook {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Override(serde_json::json!({
                "message": {
                    "content": [{"type":"text","text":"rewritten outbound"}],
                    "attachments": []
                }
            })))
        }
    }

    struct NoopToolHandler;
    #[async_trait::async_trait]
    impl encmind_core::traits::InternalToolHandler for NoopToolHandler {
        async fn handle(
            &self,
            _input: serde_json::Value,
            _session_id: &SessionId,
            _agent_id: &AgentId,
        ) -> Result<String, encmind_core::error::AppError> {
            Ok("ok".to_string())
        }
    }

    fn example_skill_dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/skills")
            .join(name)
    }

    fn parse_tool_result(raw: &str) -> serde_json::Value {
        serde_json::from_str(raw).expect("tool result should be valid JSON object string")
    }

    #[test]
    fn channel_reply_target_id_for_telegram_uses_chat_id() {
        assert_eq!(super::channel_reply_target_id("telegram", "100:42"), "100");
    }

    #[test]
    fn channel_reply_target_id_for_slack_uses_channel_id() {
        assert_eq!(
            super::channel_reply_target_id("slack", "C12345:U67890"),
            "C12345"
        );
    }

    #[test]
    fn channel_reply_target_id_for_other_channels_uses_sender_id() {
        assert_eq!(
            super::channel_reply_target_id("email", "user@example.com"),
            "user@example.com"
        );
    }

    #[test]
    fn channel_auto_reply_enabled_defaults_gmail_to_false() {
        let config = AppConfig::default();
        assert!(!super::channel_auto_reply_enabled(
            &config,
            "gmail",
            "sender@example.com"
        ));
    }

    #[test]
    fn channel_auto_reply_enabled_honors_gmail_config() {
        let mut config = AppConfig::default();
        config.channels.gmail = Some(encmind_core::config::GmailConfig {
            auto_reply: true,
            ..Default::default()
        });
        assert!(super::channel_auto_reply_enabled(
            &config,
            "gmail",
            "sender@example.com"
        ));
    }

    #[test]
    fn channel_auto_reply_enabled_honors_gmail_allowed_senders() {
        let mut config = AppConfig::default();
        config.channels.gmail = Some(encmind_core::config::GmailConfig {
            auto_reply: true,
            allowed_senders: vec![encmind_core::config::GmailAllowedSender {
                sender_id: "owner@example.com".to_string(),
                auto_reply: None,
            }],
            ..Default::default()
        });
        assert!(super::channel_auto_reply_enabled(
            &config,
            "gmail",
            "owner@example.com"
        ));
        assert!(!super::channel_auto_reply_enabled(
            &config,
            "gmail",
            "other@example.com"
        ));
    }

    #[test]
    fn channel_auto_reply_enabled_non_gmail_true() {
        let config = AppConfig::default();
        assert!(super::channel_auto_reply_enabled(
            &config, "slack", "sender"
        ));
    }

    #[test]
    fn should_send_policy_rejection_notice_disables_gmail() {
        let policy = encmind_channels::router::ResolvedPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: true,
        };
        assert!(!super::should_send_policy_rejection_notice(
            "gmail", &policy
        ));
        assert!(super::should_send_policy_rejection_notice("slack", &policy));
    }

    #[test]
    fn outbound_subject_for_gmail_prefixes_re() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "subject".to_string(),
            serde_json::Value::String("Welcome update".to_string()),
        );
        let msg = InboundMessage {
            channel: "gmail".to_string(),
            sender_id: "sender@example.com".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: Some("thread-1".to_string()),
            reply_to_id: Some("<mid@example.com>".to_string()),
            metadata,
        };
        assert_eq!(
            super::outbound_subject_for_channel(&msg).as_deref(),
            Some("Re: Welcome update")
        );
    }

    #[test]
    fn outbound_subject_for_gmail_keeps_existing_reply_prefix() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "subject".to_string(),
            serde_json::Value::String("Re: Existing thread".to_string()),
        );
        let msg = InboundMessage {
            channel: "gmail".to_string(),
            sender_id: "sender@example.com".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: Some("thread-1".to_string()),
            reply_to_id: Some("<mid@example.com>".to_string()),
            metadata,
        };
        assert_eq!(
            super::outbound_subject_for_channel(&msg).as_deref(),
            Some("Re: Existing thread")
        );
    }

    #[test]
    fn outbound_subject_for_non_gmail_is_none() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "subject".to_string(),
            serde_json::Value::String("Should not be used".to_string()),
        );
        let msg = InboundMessage {
            channel: "slack".to_string(),
            sender_id: "C1:U1".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        assert_eq!(super::outbound_subject_for_channel(&msg), None);
    }

    #[test]
    fn outbound_subject_for_gmail_keeps_forward_prefix() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "subject".to_string(),
            serde_json::Value::String("Fwd: Existing forward".to_string()),
        );
        let msg = InboundMessage {
            channel: "gmail".to_string(),
            sender_id: "sender@example.com".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: Some("thread-1".to_string()),
            reply_to_id: Some("<mid@example.com>".to_string()),
            metadata,
        };
        assert_eq!(
            super::outbound_subject_for_channel(&msg).as_deref(),
            Some("Fwd: Existing forward")
        );
    }

    #[test]
    fn normalize_slash_command_keeps_plain_command() {
        assert_eq!(
            super::normalize_slash_command("/start arg").as_deref(),
            Some("/start")
        );
    }

    #[test]
    fn normalize_slash_command_strips_telegram_bot_suffix() {
        assert_eq!(
            super::normalize_slash_command("/start@my_bot arg").as_deref(),
            Some("/start")
        );
    }

    #[test]
    fn normalize_slash_command_ignores_non_commands() {
        assert_eq!(super::normalize_slash_command("hello"), None);
    }

    #[test]
    fn compose_inbound_prompt_includes_attachment_summary_for_media_only_message() {
        let msg = InboundMessage {
            channel: "telegram".into(),
            sender_id: "100:42".into(),
            content: vec![ContentBlock::Text {
                text: String::new(),
            }],
            attachments: vec![Attachment {
                name: "photo.jpg".into(),
                media_type: "image/jpeg".into(),
                data: vec![0u8; 512],
            }],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: std::collections::HashMap::new(),
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("Inbound attachments:"));
        assert!(prompt.contains("photo.jpg"));
        assert!(prompt.contains("image/jpeg"));
        assert!(prompt.contains("512 bytes"));
    }

    #[test]
    fn summarize_inbound_attachments_sanitizes_and_truncates_fields() {
        let noisy_name = "evil\nname\twith\rcontrols".to_string() + &"x".repeat(200);
        let noisy_type = "image/\nweird\tkind".to_string();
        let attachments = vec![Attachment {
            name: noisy_name,
            media_type: noisy_type,
            data: vec![0u8; 32],
        }];

        let summary = super::summarize_inbound_attachments(&attachments);
        assert!(summary.starts_with("Inbound attachments:\n- "));
        assert!(!summary.contains("evil\nname"));
        assert!(!summary.contains("image/\nweird"));
        assert!(!summary.contains('\t'));
        assert!(summary.contains("..."));
        assert!(summary.contains("32 bytes"));
    }

    #[test]
    fn compose_inbound_prompt_includes_hydration_note_when_present() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "attachment_hydration_note".to_string(),
            serde_json::Value::String("2 attachment(s) failed to download".to_string()),
        );
        let msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("hello"));
        assert!(prompt.contains("Attachment processing note: 2 attachment(s) failed to download"));
    }

    #[test]
    fn compose_inbound_prompt_ignores_note_without_primary_content() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "attachment_hydration_note".to_string(),
            serde_json::Value::String("attachment hydration timed out".to_string()),
        );
        let msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
            content: vec![ContentBlock::Text {
                text: String::new(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        assert_eq!(super::compose_inbound_prompt(&msg), "");
    }

    #[test]
    fn compose_inbound_prompt_includes_metadata_attachment_summary_when_not_hydrated() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "file_refs".to_string(),
            serde_json::json!([
                {
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "url": "https://files.slack.com/private"
                }
            ]),
        );
        let msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
            content: vec![ContentBlock::Text {
                text: "here is the file".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("here is the file"));
        assert!(prompt.contains("Inbound attachments (metadata only):"));
        assert!(prompt.contains("report.pdf"));
        assert!(prompt.contains("application/pdf"));
    }

    #[test]
    fn compose_inbound_prompt_includes_gmail_attachment_id_summary() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "attachment_ids".to_string(),
            serde_json::json!(["msg-1/att-1", "msg-1/att-2"]),
        );
        let msg = InboundMessage {
            channel: "gmail".into(),
            sender_id: "alice@example.com".into(),
            content: vec![ContentBlock::Text {
                text: "see attachments".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: Some("thread-1".into()),
            reply_to_id: None,
            metadata,
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("Inbound attachments (metadata only):"));
        assert!(prompt.contains("msg-1/att-1"));
        assert!(prompt.contains("msg-1/att-2"));
    }

    #[test]
    fn compose_inbound_prompt_sanitizes_metadata_attachment_fields() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "file_refs".to_string(),
            serde_json::json!([
                {
                    "name": "evil\nname\twith\rcontrols",
                    "mimetype": "image/\nweird\tkind"
                }
            ]),
        );
        let msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("Inbound attachments (metadata only):"));
        assert!(!prompt.contains("evil\nname"));
        assert!(!prompt.contains("image/\nweird"));
        assert!(!prompt.contains('\t'));
    }

    #[test]
    fn redact_inbound_file_refs_removes_sensitive_fields() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "file_refs".to_string(),
            serde_json::json!([
                {
                    "url": "https://files.slack.com/private",
                    "name": "a.txt",
                    "mimetype": "text/plain"
                },
                {
                    "file_id": "telegram-secret-id",
                    "file_name": "voice.ogg",
                    "mime_type": "audio/ogg"
                }
            ]),
        );
        super::redact_inbound_file_refs(&mut metadata);
        let refs = metadata
            .get("file_refs")
            .and_then(|v| v.as_array())
            .expect("expected redacted refs");
        assert_eq!(refs.len(), 2);
        assert!(refs[0].get("url").is_none());
        assert!(refs[1].get("file_id").is_none());
        assert_eq!(refs[0]["name"], "a.txt");
        assert_eq!(refs[1]["name"], "voice.ogg");
    }

    #[test]
    fn redact_inbound_file_refs_caps_metadata_and_tracks_total_count() {
        let refs: Vec<serde_json::Value> = (0..8)
            .map(|i| {
                serde_json::json!({
                    "name": format!("file-{i}.txt"),
                    "mimetype": "text/plain",
                    "url": format!("https://files.example/{i}"),
                })
            })
            .collect();
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("file_refs".to_string(), serde_json::Value::Array(refs));

        super::redact_inbound_file_refs(&mut metadata);

        let redacted = metadata
            .get("file_refs")
            .and_then(|v| v.as_array())
            .expect("expected redacted refs");
        assert_eq!(redacted.len(), 5);
        assert_eq!(
            metadata
                .get("file_refs_total_count")
                .and_then(|v| v.as_u64()),
            Some(8)
        );

        let msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("Inbound attachments (metadata only):"));
        assert!(prompt.contains("and 3 more attachment(s)"));
    }

    #[test]
    fn redact_inbound_file_refs_preserves_existing_total_count_hint() {
        let refs: Vec<serde_json::Value> = (0..5)
            .map(|i| {
                serde_json::json!({
                    "name": format!("file-{i}.txt"),
                    "mimetype": "text/plain",
                    "url": format!("https://files.example/{i}"),
                })
            })
            .collect();
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("file_refs".to_string(), serde_json::Value::Array(refs));
        metadata.insert(
            "file_refs_total_count".to_string(),
            serde_json::Value::from(12u64),
        );

        super::redact_inbound_file_refs(&mut metadata);

        assert_eq!(
            metadata
                .get("file_refs_total_count")
                .and_then(|v| v.as_u64()),
            Some(12)
        );
        let msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata,
        };
        let prompt = super::compose_inbound_prompt(&msg);
        assert!(prompt.contains("and 7 more attachment(s)"));
    }

    #[test]
    fn ensure_inbound_media_fallback_sets_text_when_message_would_be_empty() {
        let mut msg = InboundMessage {
            channel: "telegram".into(),
            sender_id: "100:42".into(),
            content: vec![ContentBlock::Text {
                text: String::new(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: std::collections::HashMap::new(),
        };

        super::ensure_inbound_media_fallback(&mut msg, "attachment hydration failed");
        let text = super::extract_inbound_text(&msg);
        assert!(text.contains("attachments could not be retrieved"));
    }

    #[test]
    fn channel_attachment_hydration_timeout_uses_configured_limits() {
        let mut config = AppConfig::default();
        config.channels.telegram = Some(encmind_core::config::TelegramConfig {
            download_timeout_secs: 3,
            max_attachments_per_message: 4,
            ..Default::default()
        });
        config.channels.slack = Some(encmind_core::config::SlackConfig {
            download_timeout_secs: 2,
            max_attachments_per_message: 6,
            ..Default::default()
        });

        assert_eq!(
            super::channel_attachment_hydration_timeout_secs(&config, "telegram"),
            17
        );
        assert_eq!(
            super::channel_attachment_hydration_timeout_secs(&config, "slack"),
            17
        );
        assert_eq!(
            super::channel_attachment_hydration_timeout_secs(&config, "unknown"),
            25
        );

        config.channels.telegram = Some(encmind_core::config::TelegramConfig {
            download_timeout_secs: 60,
            max_attachments_per_message: 10,
            ..Default::default()
        });
        assert_eq!(
            super::channel_attachment_hydration_timeout_secs(&config, "telegram"),
            90
        );
    }

    #[test]
    fn local_tool_policy_excludes_agent_workspaces() {
        let mut config = AppConfig::default();
        let workspace_a = std::env::temp_dir().join("encmind-agent-workspace-a");
        let workspace_b = std::env::temp_dir().join("encmind-agent-workspace-b");

        config.agents.list = vec![
            encmind_core::config::AgentConfigEntry {
                id: "a".into(),
                name: "A".into(),
                model: None,
                workspace: Some(workspace_a.clone()),
                system_prompt: None,
                skills: Vec::new(),
                subagents: encmind_core::config::SubagentRuntimeConfig::default(),
                is_default: false,
            },
            encmind_core::config::AgentConfigEntry {
                id: "b".into(),
                name: "B".into(),
                model: None,
                workspace: Some(workspace_b.clone()),
                system_prompt: None,
                skills: Vec::new(),
                subagents: encmind_core::config::SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];

        let policy =
            LocalToolPolicyEngine::from_config(&config).effective_policy(&AgentId::new("unknown"));
        assert!(!policy.allowed_roots.contains(&workspace_a));
        assert!(!policy.allowed_roots.contains(&workspace_b));
    }

    #[test]
    fn local_tool_policy_disables_bash_for_distinct_agent_workspaces() {
        let mut config = AppConfig::default();
        config.security.local_tools.mode = encmind_core::config::LocalToolsMode::IsolatedAgents;
        config.security.local_tools.bash_mode = encmind_core::config::LocalToolsBashMode::Disabled;
        config.agents.list = vec![
            encmind_core::config::AgentConfigEntry {
                id: "a".into(),
                name: "A".into(),
                model: None,
                workspace: Some(std::path::PathBuf::from("/tmp/workspace-a")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: encmind_core::config::SubagentRuntimeConfig::default(),
                is_default: false,
            },
            encmind_core::config::AgentConfigEntry {
                id: "b".into(),
                name: "B".into(),
                model: None,
                workspace: Some(std::path::PathBuf::from("/tmp/workspace-b")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: encmind_core::config::SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];

        let status = LocalToolPolicyEngine::from_config(&config).status();
        assert!(!status.bash_effective_enabled);
    }

    #[test]
    fn local_tool_policy_keeps_bash_for_shared_workspace() {
        let mut config = AppConfig::default();
        config.security.local_tools.mode = encmind_core::config::LocalToolsMode::SingleOperator;
        config.security.local_tools.bash_mode = encmind_core::config::LocalToolsBashMode::Host;
        config.agents.list = vec![
            encmind_core::config::AgentConfigEntry {
                id: "a".into(),
                name: "A".into(),
                model: None,
                workspace: Some(std::path::PathBuf::from("/tmp/workspace-shared")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: encmind_core::config::SubagentRuntimeConfig::default(),
                is_default: false,
            },
            encmind_core::config::AgentConfigEntry {
                id: "b".into(),
                name: "B".into(),
                model: None,
                workspace: Some(std::path::PathBuf::from("/tmp/workspace-shared")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: encmind_core::config::SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];

        let status = LocalToolPolicyEngine::from_config(&config).status();
        assert!(status.bash_effective_enabled);
    }

    #[test]
    fn chat_response_text_reads_response_field() {
        let msg = crate::protocol::ServerMessage::Res {
            id: "req-1".to_string(),
            result: serde_json::json!({
                "response": "hello from response"
            }),
        };
        assert_eq!(
            super::chat_response_text(msg).as_deref(),
            Some("hello from response")
        );
    }

    #[test]
    fn chat_response_text_uses_generic_error_for_error_response() {
        let msg = crate::protocol::ServerMessage::Error {
            id: Some("req-1".to_string()),
            error: crate::protocol::ErrorPayload::new(crate::protocol::ERR_INTERNAL, "boom"),
        };
        assert_eq!(
            super::chat_response_text(msg).as_deref(),
            Some(super::CHANNEL_GENERIC_ERROR_REPLY)
        );
    }

    #[test]
    fn configured_inbound_channels_includes_slack_when_present() {
        let mut config = AppConfig::default();
        config.channels.slack = Some(SlackConfig {
            bot_token_env: "SLACK_BOT_TOKEN".to_string(),
            app_token_env: "SLACK_APP_TOKEN".to_string(),
            ..Default::default()
        });

        let channels = super::configured_inbound_channels(&config);
        assert_eq!(channels, vec!["slack"]);
    }

    #[test]
    fn configured_inbound_channels_includes_gmail_when_present() {
        let mut config = AppConfig::default();
        config.channels.gmail = Some(encmind_core::config::GmailConfig::default());

        let channels = super::configured_inbound_channels(&config);
        assert_eq!(channels, vec!["gmail"]);
    }

    #[test]
    fn channel_policy_blocks_all_when_reject_with_empty_allowlist() {
        let mut config = AppConfig::default();
        config.channels.access_policy = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![],
            notify_rejected: false,
        };
        assert!(super::channel_policy_blocks_all(
            &config,
            &["slack".to_string()]
        ));
    }

    #[test]
    fn channel_policy_allows_when_allowlist_has_entries() {
        let mut config = AppConfig::default();
        config.channels.access_policy = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![AllowlistEntry {
                channel: "slack".to_string(),
                sender_id: "C1:U1".to_string(),
                label: None,
            }],
            notify_rejected: false,
        };
        assert!(!super::channel_policy_blocks_all(
            &config,
            &["slack".to_string()]
        ));
    }

    #[test]
    fn channel_policy_allows_when_gmail_allowed_senders_present() {
        let mut config = AppConfig::default();
        config.channels.access_policy = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![],
            notify_rejected: false,
        };
        config.channels.gmail = Some(encmind_core::config::GmailConfig {
            allowed_senders: vec![encmind_core::config::GmailAllowedSender {
                sender_id: "owner@example.com".to_string(),
                auto_reply: Some(true),
            }],
            ..Default::default()
        });
        assert!(!super::channel_policy_blocks_all(
            &config,
            &["gmail".to_string()]
        ));
    }

    #[test]
    fn channel_policy_blocks_all_when_gmail_not_active_even_if_configured() {
        let mut config = AppConfig::default();
        config.channels.access_policy = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![],
            notify_rejected: false,
        };
        config.channels.gmail = Some(encmind_core::config::GmailConfig {
            allowed_senders: vec![encmind_core::config::GmailAllowedSender {
                sender_id: "owner@example.com".to_string(),
                auto_reply: Some(true),
            }],
            ..Default::default()
        });
        assert!(super::channel_policy_blocks_all(
            &config,
            &["slack".to_string()]
        ));
    }

    #[test]
    fn gmail_allowlist_fallback_derives_sender_when_no_explicit_policy() {
        let mut resolved = encmind_channels::router::ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let global = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![],
            notify_rejected: false,
        };
        super::apply_gmail_allowlist_fallback(
            "gmail",
            &mut resolved,
            &global,
            None,
            &["owner@example.com".to_string()],
        );
        assert_eq!(resolved.default_action, AccessAction::Reject);
        assert_eq!(resolved.allowlist, vec!["owner@example.com".to_string()]);
    }

    #[test]
    fn gmail_allowlist_fallback_respects_explicit_gmail_policy() {
        let mut resolved = encmind_channels::router::ResolvedPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec!["global@example.com".to_string()],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let global = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![AllowlistEntry {
                channel: "gmail".to_string(),
                sender_id: "global@example.com".to_string(),
                label: None,
            }],
            notify_rejected: false,
        };
        super::apply_gmail_allowlist_fallback(
            "gmail",
            &mut resolved,
            &global,
            None,
            &["derived@example.com".to_string()],
        );
        assert_eq!(resolved.allowlist, vec!["global@example.com".to_string()]);
    }

    #[tokio::test]
    async fn on_message_received_hook_abort_blocks_message() {
        let state = make_test_state();
        {
            let mut hooks = state.hook_registry.write().await;
            hooks
                .register(
                    HookPoint::OnMessageReceived,
                    100,
                    "test",
                    Arc::new(AbortHook),
                    5000,
                )
                .unwrap();
        }
        let msg = InboundMessage {
            channel: "slack".to_string(),
            sender_id: "C1:U1".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        };
        let result = apply_on_message_received_hook(&state, msg).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn on_message_received_hook_override_rewrites_message() {
        let state = make_test_state();
        {
            let mut hooks = state.hook_registry.write().await;
            hooks
                .register(
                    HookPoint::OnMessageReceived,
                    100,
                    "test",
                    Arc::new(RewriteInboundHook),
                    5000,
                )
                .unwrap();
        }
        let msg = InboundMessage {
            channel: "slack".to_string(),
            sender_id: "C1:U1".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        };
        let result = apply_on_message_received_hook(&state, msg).await.unwrap();
        assert_eq!(result.sender_id, "C9:U9");
        let text = result
            .content
            .iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or("");
        assert_eq!(text, "rewritten inbound");
    }

    #[tokio::test]
    async fn on_message_sending_hook_override_rewrites_outbound() {
        let state = make_test_state();
        {
            let mut hooks = state.hook_registry.write().await;
            hooks
                .register(
                    HookPoint::OnMessageSending,
                    100,
                    "test",
                    Arc::new(RewriteOutboundHook),
                    5000,
                )
                .unwrap();
        }
        let inbound = InboundMessage {
            channel: "slack".to_string(),
            sender_id: "C1:U1".to_string(),
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        };
        let outbound = OutboundMessage {
            content: vec![ContentBlock::Text {
                text: "original outbound".to_string(),
            }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };
        let result = apply_on_message_sending_hook(&state, &inbound, &SessionId::new(), outbound)
            .await
            .unwrap();
        let text = result
            .content
            .iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or("");
        assert_eq!(text, "rewritten outbound");
    }

    #[test]
    fn auto_tls_dir_uses_home_root_for_default_db_layout() {
        let p = Path::new("/home/alice/.encmind/data.db");
        assert_eq!(
            super::auto_tls_dir_for_db_path(p),
            PathBuf::from("/home/alice/.encmind/tls")
        );
    }

    #[test]
    fn auto_tls_dir_uses_home_root_for_installer_data_layout() {
        let p = Path::new("/home/alice/.encmind/data/data.db");
        assert_eq!(
            super::auto_tls_dir_for_db_path(p),
            PathBuf::from("/home/alice/.encmind/tls")
        );
    }

    #[test]
    fn auto_tls_dir_uses_db_parent_for_custom_layout() {
        let p = Path::new("/var/lib/encmind/state.db");
        assert_eq!(
            super::auto_tls_dir_for_db_path(p),
            PathBuf::from("/var/lib/encmind/tls")
        );
    }

    #[test]
    fn resolve_skills_dir_prefers_configured_wasm_dir() {
        let mut config = AppConfig::default();
        config.storage.db_path = PathBuf::from("/var/lib/encmind/data.db");
        config.skills.wasm_dir = PathBuf::from("/opt/encmind/custom-skills");
        assert_eq!(
            super::resolve_skills_dir(&config),
            PathBuf::from("/opt/encmind/custom-skills")
        );
    }

    #[test]
    fn resolve_skills_dir_falls_back_to_db_parent_when_wasm_dir_empty() {
        let mut config = AppConfig::default();
        config.storage.db_path = PathBuf::from("/var/lib/encmind/data.db");
        config.skills.wasm_dir = PathBuf::new();
        assert_eq!(
            super::resolve_skills_dir(&config),
            PathBuf::from("/var/lib/encmind/skills")
        );
    }

    #[test]
    fn validate_required_skill_config_keys_accepts_present_values() {
        let config = serde_json::json!({
            "api_key": "secret",
            "base_url": "https://example.com"
        });
        let required = vec!["api_key".to_string(), "base_url".to_string()];
        let result =
            super::validate_required_skill_config_keys("skill-a", &required, Some(&config));
        assert!(result.is_ok(), "expected success, got {result:?}");
    }

    #[test]
    fn validate_required_skill_config_keys_rejects_missing_or_null_values() {
        let config = serde_json::json!({
            "api_key": null
        });
        let required = vec!["api_key".to_string(), "base_url".to_string()];
        let err = super::validate_required_skill_config_keys("skill-a", &required, Some(&config))
            .expect_err("expected missing required keys error");
        assert!(
            err.contains("api_key"),
            "error should include null key: {err}"
        );
        assert!(
            err.contains("base_url"),
            "error should include missing key: {err}"
        );
    }

    #[test]
    fn skill_id_from_load_error_key_extracts_file_stem() {
        assert_eq!(
            super::skill_id_from_load_error_key("/tmp/skills/broken.wasm"),
            Some("broken".to_string())
        );
        assert_eq!(
            super::skill_id_from_load_error_key("disk-only.toml"),
            Some("disk-only".to_string())
        );
    }

    #[test]
    fn skill_id_from_load_error_key_accepts_plain_skill_name() {
        assert_eq!(
            super::skill_id_from_load_error_key("skill_alpha-1"),
            Some("skill_alpha-1".to_string())
        );
    }

    #[test]
    fn skill_id_from_load_error_key_rejects_paths_and_empty() {
        assert_eq!(super::skill_id_from_load_error_key(""), None);
        assert_eq!(super::skill_id_from_load_error_key("a/b"), None);
        assert_eq!(super::skill_id_from_load_error_key(r"a\b"), None);
        assert_eq!(super::skill_id_from_load_error_key("bad key!"), None);
        assert_eq!(super::skill_id_from_load_error_key(".hidden"), None);
        assert_eq!(super::skill_id_from_load_error_key("trailing."), None);
    }

    #[test]
    fn resolve_load_error_skill_ids_includes_manifest_name_for_wasm_key() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();
        std::fs::write(
            skills_dir.join("foo.toml"),
            r#"[skill]
name = "bar"
version = "1.0.0"
"#,
        )
        .unwrap();
        let key = skills_dir.join("foo.wasm").display().to_string();
        let ids = super::resolve_load_error_skill_ids(&key, skills_dir);
        assert!(ids.contains("bar"));
        assert!(
            !ids.contains("foo"),
            "resolver should prefer canonical manifest skill_id over wasm stem aliases"
        );
    }

    #[test]
    fn resolve_load_error_skill_ids_includes_manifest_name_for_plain_key() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();
        std::fs::write(
            skills_dir.join("foo.toml"),
            r#"[skill]
name = "bar"
version = "1.0.0"
"#,
        )
        .unwrap();
        let ids = super::resolve_load_error_skill_ids("foo", skills_dir);
        assert!(ids.contains("foo"));
        assert!(ids.contains("bar"));
    }

    #[test]
    fn suppress_disabled_load_error_requires_all_candidates_disabled() {
        let candidates = std::collections::HashSet::from(["foo".to_string(), "bar".to_string()]);
        let disabled = std::collections::HashSet::from(["bar".to_string()]);
        assert!(!super::should_suppress_load_error_for_disabled(
            &candidates,
            &disabled
        ));
    }

    #[test]
    fn suppress_disabled_load_error_all_disabled_candidates() {
        let candidates = std::collections::HashSet::from(["foo".to_string(), "bar".to_string()]);
        let disabled = std::collections::HashSet::from([
            "foo".to_string(),
            "bar".to_string(),
            "baz".to_string(),
        ]);
        assert!(super::should_suppress_load_error_for_disabled(
            &candidates,
            &disabled
        ));
    }

    #[test]
    fn namespaced_wasm_tool_name_keeps_valid_skill_id_verbatim() {
        assert_eq!(
            super::namespaced_wasm_tool_name("echo_skill", "echo_tool"),
            "echo_skill_echo_tool"
        );
    }

    #[test]
    fn namespaced_wasm_tool_name_sanitizes_dotted_skill_id() {
        let tool = super::namespaced_wasm_tool_name("skill.echo", "run");
        assert!(tool.ends_with("_run"), "got: {tool}");
        assert!(tool.starts_with("skill_echo_"), "got: {tool}");
        assert!(
            tool.bytes().all(|b| matches!(
                b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'
            )),
            "tool name has invalid chars: {tool}"
        );
    }

    #[test]
    fn namespaced_wasm_tool_name_uses_16_hex_hash_suffix_when_sanitized() {
        let tool = super::namespaced_wasm_tool_name("skill.echo", "run");
        let without_tool = tool.strip_suffix("_run").expect("suffix _run");
        let hash = without_tool.rsplit('_').next().expect("hash segment");
        assert_eq!(hash.len(), 16, "expected 64-bit hash suffix: {tool}");
        assert!(
            hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "hash must be lowercase hex: {hash}"
        );
    }

    #[test]
    fn namespaced_wasm_tool_name_caps_length_and_keeps_valid_charset() {
        let long_skill = "skill.".to_string() + &"x".repeat(120);
        let long_tool = "tool.".to_string() + &"y".repeat(140);
        let tool = super::namespaced_wasm_tool_name(&long_skill, &long_tool);
        assert!(
            tool.len() <= 128,
            "tool name too long ({}): {tool}",
            tool.len()
        );
        assert!(
            tool.bytes().all(|b| matches!(
                b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'
            )),
            "tool name has invalid chars: {tool}"
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_omits_tool_name_when_tool_registration_fails() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();

        std::fs::write(
            skills_dir.join("echo.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("echo.toml"),
            r#"[skill]
name = "echo"
version = "1.0.0"
description = "Echo skill"

[tool]
name = "echo"
description = "Echoes input"
"#,
        )
        .unwrap();

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.to_path_buf();

        let mut registry = ToolRegistry::new();
        let namespaced = super::namespaced_wasm_tool_name("echo", "echo");
        registry
            .register_internal(
                &namespaced,
                "preexisting",
                serde_json::json!({}),
                Arc::new(NoopToolHandler),
            )
            .unwrap();
        let mut hook_registry = HookRegistry::new();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_startup(
            &config,
            skills_dir,
            &mut registry,
            session_store,
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        let summary = loaded
            .summaries
            .iter()
            .find(|s| s.id == "echo")
            .expect("echo summary should be present");
        assert!(summary.enabled);
        assert!(
            summary.tool_name.is_none(),
            "tool_name should reflect registration success, not manifest declaration"
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_dispatches_example_plugin_smoke_native() {
        let skills_dir = example_skill_dir("plugin-smoke-native");
        assert!(
            skills_dir.exists(),
            "example directory missing: {}",
            skills_dir.display()
        );

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.clone();
        config.skills.enabled = vec!["plugin-smoke-native".to_string()];
        config.plugin_policy.allow_risk_levels = vec![
            encmind_core::policy::CapabilityRiskLevel::Low,
            encmind_core::policy::CapabilityRiskLevel::Sensitive,
            encmind_core::policy::CapabilityRiskLevel::Critical,
        ];

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
            // plugin-smoke-native declares `required_keys = ["mode"]`
            conn.execute(
                "INSERT OR REPLACE INTO skill_kv(skill_id, key, value, updated_at) \
                 VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                rusqlite::params![
                    "plugin-smoke-native",
                    "config:mode",
                    serde_json::to_vec(&serde_json::json!("smoke")).unwrap()
                ],
            )
            .unwrap();
        }

        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_startup(
            &config,
            &skills_dir,
            &mut registry,
            session_store.clone(),
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        let summary = loaded
            .summaries
            .iter()
            .find(|s| s.id == "plugin-smoke-native")
            .expect("plugin-smoke-native summary should exist");
        assert!(summary.enabled);
        let tool_name = summary
            .tool_name
            .clone()
            .expect("plugin-smoke-native tool should be registered");
        assert_eq!(
            hook_registry.total_hooks(),
            2,
            "expected two registered hooks"
        );

        let runtime_spec = loaded
            .runtime_specs
            .iter()
            .find(|s| s.skill_id == "plugin-smoke-native")
            .expect("plugin-smoke-native runtime spec should exist");
        assert_eq!(runtime_spec.timers.len(), 2);
        assert_eq!(runtime_spec.transforms.len(), 1);

        let agent_id = AgentId::new("main");
        let session = session_store
            .create_session_for_agent("web", &agent_id)
            .await
            .expect("create web session");

        let first = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "kv_counter", "key": "smoke.counter" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("first kv_counter dispatch");
        let first_val = parse_tool_result(&first);
        assert_eq!(
            first_val.get("result").and_then(|v| v.as_str()),
            Some("counter=1")
        );

        let second = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "kv_counter", "key": "smoke.counter" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("second kv_counter dispatch");
        let second_val = parse_tool_result(&second);
        assert_eq!(
            second_val.get("result").and_then(|v| v.as_str()),
            Some("counter=2")
        );

        let listed = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "kv_list", "key": "smoke." }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("kv_list dispatch");
        let listed_val = parse_tool_result(&listed);
        let listed_result = listed_val
            .get("result")
            .and_then(|v| v.as_str())
            .expect("kv_list should return result text");
        assert!(
            listed_result.contains("smoke.counter"),
            "kv_list should include smoke.counter key, got: {listed_result}"
        );

        let config_probe = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "config_probe", "key": "mode" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("config_probe dispatch");
        let config_probe_val = parse_tool_result(&config_probe);
        let config_result = config_probe_val
            .get("result")
            .and_then(|v| v.as_str())
            .expect("config_probe should return result");
        assert!(
            config_result.contains("smoke"),
            "config_probe should resolve mode key, got: {config_result}"
        );

        let net_probe = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "net_probe", "url": "https://forbidden.invalid" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("net_probe dispatch");
        let net_probe_val = parse_tool_result(&net_probe);
        assert_eq!(
            net_probe_val.get("result").and_then(|v| v.as_str()),
            Some("net_error")
        );

        let emit_event = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "emit_event" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("emit_event dispatch");
        let emit_event_val = parse_tool_result(&emit_event);
        let emit_result = emit_event_val
            .get("result")
            .and_then(|v| v.as_str())
            .expect("emit_event should return result");
        assert!(
            emit_result.contains("\"emitted\":true"),
            "emit_event should report emitted=true, got: {emit_result}"
        );

        let context_raw = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "context_echo" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("context_echo dispatch");
        let context_outer = parse_tool_result(&context_raw);
        let context_json = context_outer
            .get("result")
            .and_then(|v| v.as_str())
            .expect("context_echo should return JSON string");
        let context: serde_json::Value =
            serde_json::from_str(context_json).expect("context JSON should parse");
        assert_eq!(
            context.get("session_id").and_then(|v| v.as_str()),
            Some(session.id.as_str())
        );
        assert_eq!(
            context.get("agent_id").and_then(|v| v.as_str()),
            Some(agent_id.as_str())
        );
        assert_eq!(context.get("channel").and_then(|v| v.as_str()), Some("web"));

        let bad = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "bad_output" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect_err("bad_output should fail output schema validation");
        assert!(
            bad.to_string().contains("output failed schema validation"),
            "unexpected bad_output error: {bad}"
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_dispatches_example_plugin_smoke_javy() {
        let skills_dir = example_skill_dir("plugin-smoke-javy");
        assert!(
            skills_dir.exists(),
            "example directory missing: {}",
            skills_dir.display()
        );

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.clone();
        config.skills.enabled = vec!["plugin-smoke-javy".to_string()];

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_startup(
            &config,
            &skills_dir,
            &mut registry,
            session_store.clone(),
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        let summary = loaded
            .summaries
            .iter()
            .find(|s| s.id == "plugin-smoke-javy")
            .expect("plugin-smoke-javy summary should exist");
        assert!(summary.enabled);
        let tool_name = summary
            .tool_name
            .clone()
            .expect("plugin-smoke-javy tool should be registered");
        assert_eq!(
            hook_registry.total_hooks(),
            0,
            "javy skill should not register hooks"
        );

        let runtime_spec = loaded
            .runtime_specs
            .iter()
            .find(|s| s.skill_id == "plugin-smoke-javy")
            .expect("plugin-smoke-javy runtime spec should exist");
        assert_eq!(runtime_spec.abi, encmind_wasm_host::abi::SkillAbi::Javy);
        assert!(runtime_spec.timers.is_empty());
        assert!(runtime_spec.transforms.is_empty());

        let agent_id = AgentId::new("main");
        let session = session_store
            .create_session_for_agent("web", &agent_id)
            .await
            .expect("create web session");

        let upper = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "upper", "message": "hello" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("upper dispatch");
        let upper_val = parse_tool_result(&upper);
        assert_eq!(
            upper_val.get("result").and_then(|v| v.as_str()),
            Some("HELLO")
        );

        let reverse = registry
            .dispatch(
                &tool_name,
                serde_json::json!({ "mode": "reverse", "message": "abc" }),
                &session.id,
                &agent_id,
            )
            .await
            .expect("reverse dispatch");
        let reverse_val = parse_tool_result(&reverse);
        assert_eq!(
            reverse_val.get("result").and_then(|v| v.as_str()),
            Some("cba")
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_rejects_invalid_output_schema_before_registration() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();

        std::fs::write(
            skills_dir.join("invalid-output.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
                (func (export "__on_before_tool_call") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("invalid-output.toml"),
            r#"[skill]
name = "invalid-output"
version = "1.0.0"
description = "Invalid output schema"

[tool]
name = "echo"
description = "Echoes input"

[output]
schema = { type = 123 }

[hooks]
before_tool_call = "__on_before_tool_call"
"#,
        )
        .unwrap();

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.to_path_buf();

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_startup(
            &config,
            skills_dir,
            &mut registry,
            session_store,
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        assert!(
            loaded.summaries.iter().all(|s| s.id != "invalid-output"),
            "skill with invalid output schema should not be exposed"
        );
        assert!(
            loaded
                .runtime_specs
                .iter()
                .all(|s| s.skill_id != "invalid-output"),
            "skill with invalid output schema should not register runtime specs"
        );
        assert_eq!(
            hook_registry.total_hooks(),
            0,
            "skill hooks should not be registered when output schema is invalid"
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_keeps_disabled_load_error_skill_visible() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();

        std::fs::write(skills_dir.join("broken.wasm"), b"not a wasm module").unwrap();
        std::fs::write(
            skills_dir.join("broken.toml"),
            r#"[skill]
name = "broken-skill"
version = "1.0.0"
description = "Broken skill"

[capabilities]
net_outbound = []
"#,
        )
        .unwrap();

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.to_path_buf();

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let toggle_store: Arc<dyn encmind_core::traits::SkillToggleStore> = Arc::new(
            encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool.clone()),
        );
        toggle_store
            .set_enabled("broken-skill", false)
            .await
            .expect("disable broken skill");
        let disabled = toggle_store
            .list_disabled()
            .await
            .expect("read disabled skills");
        assert!(
            disabled.iter().any(|id| id == "broken-skill"),
            "toggle store should report disabled skill"
        );
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_startup(
            &config,
            skills_dir,
            &mut registry,
            session_store,
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            Some(toggle_store),
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        let summary = loaded
            .summaries
            .iter()
            .find(|s| s.id == "broken-skill")
            .expect("disabled broken skill should remain visible");
        assert!(
            !summary.enabled,
            "broken disabled skill should be marked disabled"
        );
        assert_eq!(summary.version, "unknown");
        assert!(
            loaded.known_skill_ids.contains("broken-skill"),
            "broken skill should still be tracked as known"
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_skips_duplicate_skill_ids() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();

        let wasm = r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#;
        std::fs::write(skills_dir.join("dup-a.wasm"), wasm).unwrap();
        std::fs::write(skills_dir.join("dup-b.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("dup-a.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("dup-b.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.1"
"#,
        )
        .unwrap();

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.to_path_buf();

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_startup(
            &config,
            skills_dir,
            &mut registry,
            session_store,
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        assert!(
            loaded.summaries.iter().all(|s| s.id != "dup-skill"),
            "duplicate skill IDs should be skipped entirely"
        );
        assert!(
            loaded.known_skill_ids.contains("dup-skill"),
            "duplicate skill should still be tracked as known for operator UX"
        );
    }

    #[tokio::test]
    async fn load_wasm_skills_refresh_ignores_duplicate_skill_ids_outside_allowlist() {
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path();

        let wasm = r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#;
        std::fs::write(skills_dir.join("dup-a.wasm"), wasm).unwrap();
        std::fs::write(skills_dir.join("dup-b.wasm"), wasm).unwrap();
        std::fs::write(skills_dir.join("ok.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("dup-a.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("dup-b.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.1"
"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("ok.toml"),
            r#"[skill]
name = "ok-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.to_path_buf();
        config.skills.enabled = vec!["ok-skill".to_string()];

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let handler_hook_registry = Arc::new(RwLock::new(HookRegistry::new()));
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let loaded = super::load_wasm_skills_refresh(
            &config,
            skills_dir,
            &mut registry,
            session_store,
            Some(&mut hook_registry),
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            handler_hook_registry,
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await
        .expect("refresh should not fail for out-of-scope duplicates");

        assert!(loaded.summaries.iter().any(|s| s.id == "ok-skill"));
        assert!(loaded.summaries.iter().all(|s| s.id != "dup-skill"));
        assert!(loaded.known_skill_ids.contains("dup-skill"));
    }

    fn is_permission_denied(err: &anyhow::Error) -> bool {
        err.chain()
            .any(|cause| cause.to_string().contains("Operation not permitted"))
    }

    fn test_config() -> AppConfig {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        // Keep tempdir alive by leaking it (test only)
        std::mem::forget(dir);

        let mut config = AppConfig::default();
        config.server.host = "127.0.0.1".into();
        config.server.port = 0; // ephemeral port — validation allows 0 for tests
        config.storage.db_path = db_path;
        config.skills.wasm_dir = skills_dir;
        config.storage.key_source = encmind_core::config::KeySource::EnvVar {
            var_name: "TEST_GATEWAY_KEY".into(),
        };
        config.server.tls_cert_path = None;
        config.server.tls_key_path = None;
        // Provide a dummy LLM provider so config validation passes
        config
            .llm
            .api_providers
            .push(encmind_core::config::ApiProviderConfig {
                name: "test".into(),
                model: "test-model".into(),
                base_url: None,
            });
        config
    }

    fn write_test_tls_files() -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        // Keep files around for async test execution.
        std::mem::forget(dir);
        (cert_path, key_path)
    }

    struct MockLlm;
    struct PanickingLlm;
    struct SpawnBashProbeLlm {
        call_index: AtomicUsize,
    }

    impl SpawnBashProbeLlm {
        fn new() -> Self {
            Self {
                call_index: AtomicUsize::new(0),
            }
        }

        fn saw_denied_error(messages: &[encmind_core::types::Message]) -> bool {
            messages.iter().any(|msg| {
                msg.content.iter().any(|block| match block {
                    encmind_core::types::ContentBlock::ToolResult { content, .. } => {
                        content.contains("denied by security policy")
                    }
                    _ => false,
                })
            })
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for MockLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            let deltas = vec![
                Ok(CompletionDelta {
                    text: Some("cron-loop-response".to_string()),
                    thinking: None,
                    tool_use: None,
                    finish_reason: None,
                }),
                Ok(CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: None,
                    finish_reason: Some(FinishReason::Stop),
                }),
            ];
            Ok(Box::pin(futures::stream::iter(deltas)))
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "mock".into(),
                name: "mock".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for PanickingLlm {
        async fn complete(
            &self,
            _messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            panic!("intentional panic for cron panic-safety test");
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "panic".into(),
                name: "panic".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmBackend for SpawnBashProbeLlm {
        async fn complete(
            &self,
            messages: &[encmind_core::types::Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            let idx = self.call_index.fetch_add(1, Ordering::SeqCst);
            let deltas = if idx.is_multiple_of(2) {
                vec![Ok(CompletionDelta {
                    text: None,
                    thinking: None,
                    tool_use: Some(encmind_core::traits::ToolUseDelta {
                        id: format!("t{idx}"),
                        name: "bash_exec".to_string(),
                        input_json: r#"{"command":"ls"}"#.to_string(),
                    }),
                    finish_reason: Some(FinishReason::ToolUse),
                })]
            } else {
                let text = if Self::saw_denied_error(messages) {
                    "denied"
                } else {
                    "dispatched"
                };
                vec![Ok(CompletionDelta {
                    text: Some(text.to_string()),
                    thinking: None,
                    tool_use: None,
                    finish_reason: Some(FinishReason::Stop),
                })]
            };
            Ok(Box::pin(futures::stream::iter(deltas)))
        }

        async fn count_tokens(
            &self,
            _messages: &[encmind_core::types::Message],
        ) -> Result<u32, LlmError> {
            Ok(1)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: "spawn-bash-probe".into(),
                name: "spawn-bash-probe".into(),
                context_window: 8192,
                provider: "test".into(),
                supports_tools: true,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[tokio::test]
    async fn wasm_approval_prompt_cleans_up_pending_on_cancellation() {
        let pending: Arc<Mutex<HashMap<String, PendingSkillApproval>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let prompter = GatewayApprovalPrompter {
            pending_approvals: pending.clone(),
        };
        let request_id = "cancel-test-req".to_string();

        let handle = tokio::spawn(async move {
            encmind_wasm_host::ApprovalPrompter::prompt(
                &prompter,
                SkillApprovalRequest {
                    request_id: request_id.clone(),
                    skill_id: "skill.test".to_string(),
                    prompt: "allow?".to_string(),
                    options: vec!["yes".to_string(), "no".to_string()],
                },
                Duration::from_secs(30),
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pending.lock().unwrap().contains_key("cancel-test-req"));

        handle.abort();
        let _ = handle.await;

        assert!(!pending.lock().unwrap().contains_key("cancel-test-req"));
    }

    #[tokio::test]
    async fn health_integration() {
        // Set a 64-hex-char key for testing
        std::env::set_var("TEST_GATEWAY_KEY", "0".repeat(64));

        let config = test_config();
        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move { run_gateway(config, shutdown_clone).await });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.cancel();

        // Server should shut down gracefully when sockets are available.
        // Some sandboxes deny listener binds; allow that specific failure mode.
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("server task timed out")
            .expect("server task panicked");
        if let Err(ref e) = result {
            assert!(
                is_permission_denied(e),
                "unexpected gateway startup error: {e:#}"
            );
        }
    }

    #[tokio::test]
    async fn graceful_shutdown() {
        std::env::set_var("TEST_GATEWAY_KEY", "0".repeat(64));

        let config = test_config();
        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move { run_gateway(config, shutdown_clone).await });

        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("server task timed out")
            .expect("server task panicked");
        if let Err(ref e) = result {
            assert!(
                is_permission_denied(e),
                "unexpected gateway startup/shutdown error: {e:#}"
            );
        }
    }

    #[tokio::test]
    async fn tls_mode_starts_and_shuts_down() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        std::env::set_var("TEST_GATEWAY_KEY", "0".repeat(64));

        let mut config = test_config();
        let (cert_path, key_path) = write_test_tls_files();
        config.server.tls_cert_path = Some(cert_path);
        config.server.tls_key_path = Some(key_path);

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move { run_gateway(config, shutdown_clone).await });

        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("server task timed out")
            .expect("server task panicked");

        if let Err(ref e) = result {
            assert!(
                is_permission_denied(e),
                "unexpected TLS gateway startup/shutdown error: {e:#}"
            );
            assert!(
                !e.to_string()
                    .contains("TLS is configured but runtime TLS serving is not implemented yet"),
                "TLS branch should run native serving"
            );
        }
    }

    #[test]
    fn local_mode_with_local_config_falls_back_to_api_provider() {
        std::env::set_var("ACME_API_KEY", "test-key");

        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::Local;
        config.llm.local = Some(encmind_core::config::LocalLlmConfig {
            model_path: PathBuf::from("/tmp/mock.gguf"),
            model_name: "mock-local".into(),
            context_length: 4096,
            threads: Some(1),
            gpu_layers: None,
        });
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "acme".into(),
            model: "acme-chat".into(),
            base_url: Some("https://api.acme.example".into()),
        }];

        let backend = initialize_llm_backend(&config);
        std::env::remove_var("ACME_API_KEY");

        assert!(backend.is_some(), "expected API fallback backend");
    }

    #[test]
    fn local_mode_without_api_providers_disables_llm() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::Local;
        config.llm.local = Some(encmind_core::config::LocalLlmConfig {
            model_path: PathBuf::from("/tmp/mock.gguf"),
            model_name: "mock-local".into(),
            context_length: 4096,
            threads: None,
            gpu_layers: None,
        });
        config.llm.api_providers = vec![];

        let backend = initialize_llm_backend(&config);
        assert!(backend.is_none(), "expected no backend without fallback");
    }

    #[test]
    fn tool_registry_registers_spawn_tool_when_llm_available() {
        use encmind_core::config::{AgentConfigEntry, SubagentRuntimeConfig};

        std::env::set_var("ACME_API_KEY", "test-key");

        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "acme".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "acme".into(),
            model: "acme-chat".into(),
            base_url: Some("https://api.acme.example".into()),
        }];
        // At least one agent must have spawn permissions for the tool to register
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

        let llm_backend = initialize_llm_backend(&config);
        assert!(llm_backend.is_some(), "expected configured backend");

        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));
        let agent_registry: Arc<dyn AgentRegistry> = Arc::new(SqliteAgentRegistry::new(pool));
        let agent_pool = Arc::new(AgentPool::new(&config.agent_pool));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));

        let registry = initialize_tool_registry(
            &config,
            &llm_backend,
            session_store,
            agent_registry,
            agent_pool,
            firewall,
            None,
            None,
            None,
            None,
        );
        std::env::remove_var("ACME_API_KEY");

        assert!(registry.has_tool("agents_spawn"));
    }

    #[test]
    fn tool_registry_skips_spawn_when_no_permissions() {
        std::env::set_var("ACME_API_KEY", "test-key-2");

        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "acme".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "acme".into(),
            model: "acme-chat".into(),
            base_url: Some("https://api.acme.example".into()),
        }];
        // agents.list is empty (default) — no spawn permissions

        let llm_backend = initialize_llm_backend(&config);
        assert!(llm_backend.is_some());

        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));
        let agent_registry: Arc<dyn AgentRegistry> = Arc::new(SqliteAgentRegistry::new(pool));
        let agent_pool = Arc::new(AgentPool::new(&config.agent_pool));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));

        let registry = initialize_tool_registry(
            &config,
            &llm_backend,
            session_store,
            agent_registry,
            agent_pool,
            firewall,
            None,
            None,
            None,
            None,
        );
        std::env::remove_var("ACME_API_KEY");

        assert!(
            !registry.has_tool("agents_spawn"),
            "agents_spawn should not be registered without spawn permissions"
        );
    }

    #[tokio::test]
    async fn spawn_tool_reads_live_bash_mode_from_shared_config() {
        use encmind_core::config::{AgentConfigEntry, BashMode, SubagentRuntimeConfig};

        let mut config = AppConfig::default();
        config.security.bash_mode = BashMode::Allowlist {
            patterns: vec!["ls*".into()],
        };
        config.agents.list = vec![AgentConfigEntry {
            id: "main".into(),
            name: "Main".into(),
            model: None,
            workspace: None,
            system_prompt: None,
            skills: vec![],
            subagents: SubagentRuntimeConfig {
                allow_agents: vec!["researcher".into()],
                model: None,
            },
            is_default: true,
        }];

        let shared_config = Arc::new(RwLock::new(config.clone()));

        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));

        let agent_registry_impl = Arc::new(SqliteAgentRegistry::new(pool));
        agent_registry_impl
            .create_agent(encmind_core::types::AgentConfig {
                id: AgentId::new("researcher"),
                name: "Researcher".into(),
                model: None,
                workspace: None,
                system_prompt: None,
                skills: vec![],
                is_default: false,
            })
            .await
            .unwrap();
        let agent_registry: Arc<dyn AgentRegistry> = agent_registry_impl;
        let agent_pool = Arc::new(AgentPool::new(&config.agent_pool));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
        let llm_backend: Option<Arc<dyn LlmBackend>> = Some(Arc::new(SpawnBashProbeLlm::new()));

        let registry = initialize_tool_registry(
            &config,
            &llm_backend,
            session_store,
            agent_registry,
            agent_pool,
            firewall,
            None,
            None,
            None,
            Some(shared_config.clone()),
        );

        let first = registry
            .dispatch(
                "agents_spawn",
                serde_json::json!({
                    "agent_id": "researcher",
                    "task": "run bash"
                }),
                &SessionId::new(),
                &AgentId::new("main"),
            )
            .await
            .unwrap();
        assert_eq!(first, "dispatched");

        {
            let mut cfg = shared_config.write().await;
            cfg.security.bash_mode = BashMode::Deny;
        }

        let second = registry
            .dispatch(
                "agents_spawn",
                serde_json::json!({
                    "agent_id": "researcher",
                    "task": "run bash again"
                }),
                &SessionId::new(),
                &AgentId::new("main"),
            )
            .await
            .unwrap();
        assert_eq!(second, "denied");
    }

    #[tokio::test]
    async fn resolve_execution_context_maps_cron_sessions_to_non_interactive() {
        let state = crate::test_utils::make_test_state();
        let agent_id = AgentId::default();
        let cron_session = state
            .session_store
            .create_session_for_agent("cron", &agent_id)
            .await
            .expect("create cron session");
        let web_session = state
            .session_store
            .create_session_for_agent("web", &agent_id)
            .await
            .expect("create web session");

        let cron_ctx =
            super::resolve_execution_context_for_session(&state.session_store, &cron_session.id)
                .await;
        let web_ctx =
            super::resolve_execution_context_for_session(&state.session_store, &web_session.id)
                .await;

        assert_eq!(cron_ctx, encmind_wasm_host::ExecutionContext::CronJob);
        assert_eq!(web_ctx, encmind_wasm_host::ExecutionContext::Interactive);
    }

    #[tokio::test]
    async fn resolve_execution_context_defaults_to_non_interactive_when_session_missing() {
        let state = crate::test_utils::make_test_state();
        let missing = SessionId::new();
        let missing_ctx =
            super::resolve_execution_context_for_session(&state.session_store, &missing).await;
        assert_eq!(missing_ctx, encmind_wasm_host::ExecutionContext::CronJob);
    }

    #[test]
    fn cache_execution_context_bounds_entries() {
        let mut cache = HashMap::new();
        for i in 0..super::MAX_EXECUTION_CONTEXT_CACHE_ENTRIES {
            super::cache_execution_context(
                &mut cache,
                SessionId::from_string(format!("s-{i}")),
                encmind_wasm_host::ExecutionContext::Interactive,
            );
        }
        assert_eq!(cache.len(), super::MAX_EXECUTION_CONTEXT_CACHE_ENTRIES);

        let kept_id = SessionId::from_string("new-entry");
        super::cache_execution_context(
            &mut cache,
            kept_id.clone(),
            encmind_wasm_host::ExecutionContext::CronJob,
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.get(&kept_id),
            Some(&encmind_wasm_host::ExecutionContext::CronJob)
        );
    }

    #[test]
    fn cache_execution_context_updates_existing_entry_without_eviction() {
        let mut cache = HashMap::new();
        let session_id = SessionId::from_string("same-session");
        super::cache_execution_context(
            &mut cache,
            session_id.clone(),
            encmind_wasm_host::ExecutionContext::Interactive,
        );
        super::cache_execution_context(
            &mut cache,
            session_id.clone(),
            encmind_wasm_host::ExecutionContext::CronJob,
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.get(&session_id),
            Some(&encmind_wasm_host::ExecutionContext::CronJob)
        );
    }

    #[tokio::test]
    async fn cron_loop_executes_due_job_and_updates_next_run() {
        let state = crate::test_utils::make_test_state();
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(MockLlm));
        }

        let cron_store = state.cron_store.clone().expect("cron store configured");
        let job = CronJob {
            id: CronJobId::new(),
            name: "loop-job".into(),
            schedule: "* * * * *".into(),
            prompt: "run cron loop".into(),
            agent_id: AgentId::default(),
            model: None,
            max_concurrent_runs: 1,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        cron_store.create_job(&job).await.unwrap();

        let shutdown = CancellationToken::new();
        let dispatcher = Arc::new(CronDispatcher::new(cron_store.clone(), 2));
        let handle = tokio::spawn(cron_loop(state.clone(), dispatcher, shutdown.clone(), 1));

        tokio::time::sleep(Duration::from_millis(1700)).await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("cron loop task timeout");

        let updated = cron_store.get_job(&job.id).await.unwrap().unwrap();
        assert!(updated.last_run_at.is_some(), "job should have started");
        assert!(
            updated.next_run_at.is_some(),
            "job should have next run time"
        );
        assert!(
            updated.next_run_at.unwrap() > updated.last_run_at.unwrap(),
            "next_run_at should move forward"
        );
    }

    #[tokio::test]
    async fn cron_loop_releases_active_job_when_execution_panics() {
        let state = crate::test_utils::make_test_state();
        {
            let mut runtime = state.runtime.write().await;
            runtime.llm_backend = Some(Arc::new(PanickingLlm));
        }

        let cron_store = state.cron_store.clone().expect("cron store configured");
        let job = CronJob {
            id: CronJobId::new(),
            name: "panic-job".into(),
            schedule: "* * * * *".into(),
            prompt: "panic".into(),
            agent_id: AgentId::default(),
            model: None,
            max_concurrent_runs: 1,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        cron_store.create_job(&job).await.unwrap();

        let shutdown = CancellationToken::new();
        let dispatcher = Arc::new(CronDispatcher::new(cron_store.clone(), 1));
        let handle = tokio::spawn(cron_loop(
            state.clone(),
            dispatcher.clone(),
            shutdown.clone(),
            1,
        ));

        tokio::time::sleep(Duration::from_millis(1700)).await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("cron loop task timeout");

        assert!(
            !dispatcher.is_job_active(job.id.as_str()).await,
            "panic path must release active job permit"
        );
    }

    #[test]
    fn cron_dispatch_parallelism_reserves_interactive_headroom() {
        assert_eq!(cron_dispatch_parallelism(1), 1);
        assert_eq!(cron_dispatch_parallelism(2), 1);
        assert_eq!(cron_dispatch_parallelism(8), 7);
    }

    // ── rebuild_llm_backend tests ─────────────────────────────

    struct InMemoryApiKeyStore {
        keys: tokio::sync::Mutex<HashMap<String, String>>,
    }

    impl InMemoryApiKeyStore {
        fn new(keys: Vec<(&str, &str)>) -> Self {
            let map: HashMap<String, String> = keys
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Self {
                keys: tokio::sync::Mutex::new(map),
            }
        }
    }

    #[async_trait::async_trait]
    impl encmind_core::traits::ApiKeyStore for InMemoryApiKeyStore {
        async fn list_keys(
            &self,
        ) -> Result<Vec<encmind_core::types::ApiKeyRecord>, encmind_core::error::StorageError>
        {
            Ok(vec![])
        }
        async fn get_key(
            &self,
            provider: &str,
        ) -> Result<Option<String>, encmind_core::error::StorageError> {
            Ok(self.keys.lock().await.get(provider).cloned())
        }
        async fn set_key(
            &self,
            provider: &str,
            api_key: &str,
        ) -> Result<(), encmind_core::error::StorageError> {
            self.keys
                .lock()
                .await
                .insert(provider.to_owned(), api_key.to_owned());
            Ok(())
        }
        async fn delete_key(
            &self,
            provider: &str,
        ) -> Result<(), encmind_core::error::StorageError> {
            self.keys.lock().await.remove(provider);
            Ok(())
        }
    }

    #[tokio::test]
    async fn rebuild_with_db_key_overrides_env() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "acme".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "acme".into(),
            model: "acme-chat".into(),
            base_url: Some("https://api.acme.example".into()),
        }];

        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![("acme", "db-key")]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        assert!(backend.is_some(), "DB key should produce a backend");
    }

    #[tokio::test]
    async fn rebuild_no_keys_returns_none() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "acme".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "acme".into(),
            model: "acme-chat".into(),
            base_url: None,
        }];

        // No DB keys, remove env var if present
        std::env::remove_var("ACME_API_KEY");

        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        assert!(backend.is_none(), "no keys should produce None");
    }

    #[tokio::test]
    async fn rebuild_multiple_providers_creates_dispatcher() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::Local;
        config.llm.api_providers = vec![
            ApiProviderConfig {
                name: "openai".into(),
                model: "gpt-4".into(),
                base_url: Some("https://api.openai.example".into()),
            },
            ApiProviderConfig {
                name: "anthropic".into(),
                model: "claude-3".into(),
                base_url: Some("https://api.anthropic.example".into()),
            },
        ];

        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![
                ("openai", "sk-open"),
                ("anthropic", "sk-anth"),
            ]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        assert!(
            backend.is_some(),
            "multiple keys should produce a dispatcher backend"
        );
    }

    #[tokio::test]
    async fn read_after_write_sees_new_backend() {
        let llm_backend: Arc<tokio::sync::RwLock<Option<Arc<dyn LlmBackend>>>> =
            Arc::new(tokio::sync::RwLock::new(None));

        {
            let guard = llm_backend.read().await;
            assert!(guard.is_none());
        }

        {
            *llm_backend.write().await = Some(Arc::new(MockLlm));
        }

        {
            let guard = llm_backend.read().await;
            assert!(guard.is_some());
        }
    }

    #[tokio::test]
    async fn rebuild_falls_back_to_env() {
        std::env::set_var("FALLBACK_TEST_API_KEY", "env-key-fb");

        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "fallback_test".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "fallback_test".into(),
            model: "test-model".into(),
            base_url: Some("https://api.fallback.example".into()),
        }];

        // Empty DB store — should fall back to env
        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        std::env::remove_var("FALLBACK_TEST_API_KEY");
        assert!(backend.is_some(), "should fall back to env var");
    }

    #[tokio::test]
    async fn rebuild_skips_provider_without_key() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::Local;
        config.llm.api_providers = vec![
            ApiProviderConfig {
                name: "has_key".into(),
                model: "m1".into(),
                base_url: Some("https://api.haskey.example".into()),
            },
            ApiProviderConfig {
                name: "no_key".into(),
                model: "m2".into(),
                base_url: None,
            },
        ];

        std::env::remove_var("NO_KEY_API_KEY");

        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![("has_key", "sk-test")]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        assert!(backend.is_some(), "should use provider with key");
    }

    #[tokio::test]
    async fn custom_provider_without_base_url_is_rejected() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "custom_llm".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "custom_llm".into(),
            model: "custom-model".into(),
            base_url: None, // missing for non-standard provider
        }];

        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![("custom_llm", "sk-key")]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        assert!(
            backend.is_none(),
            "custom provider without base_url should fail"
        );
    }

    #[tokio::test]
    async fn custom_provider_with_base_url_succeeds() {
        let mut config = AppConfig::default();
        config.llm.mode = InferenceMode::ApiProvider {
            provider: "custom_llm".into(),
        };
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "custom_llm".into(),
            model: "custom-model".into(),
            base_url: Some("https://api.custom.example".into()),
        }];

        let store: Arc<dyn encmind_core::traits::ApiKeyStore> =
            Arc::new(InMemoryApiKeyStore::new(vec![("custom_llm", "sk-key")]));

        let backend = rebuild_llm_backend(&config, Some(store)).await;
        assert!(
            backend.is_some(),
            "custom provider with base_url should succeed"
        );
    }

    fn test_empty_capabilities() -> encmind_core::traits::CapabilitySet {
        encmind_core::traits::CapabilitySet {
            net_outbound: vec![],
            fs_read: vec![],
            fs_write: vec![],
            exec_shell: false,
            env_secrets: false,
            kv: false,
            prompt_user: false,
            emit_events: vec![],
            hooks: vec![],
            schedule_timers: false,
            schedule_transforms: vec![],
        }
    }

    fn test_runtime_spec(
        skill_id: &str,
        abi: encmind_wasm_host::SkillAbi,
        timers: Vec<encmind_wasm_host::manifest::TimerDeclaration>,
        transforms: Vec<encmind_wasm_host::manifest::TransformDeclaration>,
    ) -> LoadedSkillRuntimeSpec {
        let engine = wasmtime::Engine::default();
        let module = wasmtime::Module::new(&engine, "(module (memory (export \"memory\") 1))")
            .expect("test module should compile");
        LoadedSkillRuntimeSpec {
            skill_id: skill_id.to_string(),
            manifest_hash: "hash".to_string(),
            engine,
            module,
            abi,
            capabilities: test_empty_capabilities(),
            timers,
            transforms,
            resolved_limits: ResolvedResourceLimits {
                fuel_per_invocation: 1_000_000,
                wall_clock_ms: 5_000,
                invocations_per_minute: 60,
                max_concurrent: 2,
            },
            max_memory_mb: 64,
        }
    }

    #[test]
    fn build_skill_timer_runtime_specs_skips_javy_specs() {
        let timer = encmind_wasm_host::manifest::TimerDeclaration {
            name: "tick".into(),
            interval_secs: 60,
            export_fn: "__on_tick".into(),
            description: String::new(),
        };
        let native = test_runtime_spec(
            "native-skill",
            encmind_wasm_host::SkillAbi::Native,
            vec![timer.clone()],
            vec![],
        );
        let javy = test_runtime_spec(
            "javy-skill",
            encmind_wasm_host::SkillAbi::Javy,
            vec![timer],
            vec![],
        );

        let specs = super::build_skill_timer_runtime_specs(&[native, javy]);
        assert!(specs.contains_key("native-skill"));
        assert!(!specs.contains_key("javy-skill"));
    }

    #[test]
    fn build_timer_reconcile_data_excludes_javy_timers() {
        let timer = encmind_wasm_host::manifest::TimerDeclaration {
            name: "tick".into(),
            interval_secs: 60,
            export_fn: "__on_tick".into(),
            description: String::new(),
        };
        let native = test_runtime_spec(
            "native-skill",
            encmind_wasm_host::SkillAbi::Native,
            vec![timer.clone()],
            vec![],
        );
        let javy = test_runtime_spec(
            "javy-skill",
            encmind_wasm_host::SkillAbi::Javy,
            vec![timer],
            vec![],
        );

        let data = super::build_timer_reconcile_data(&[native, javy]);
        let native_entry = data
            .iter()
            .find(|(id, _, _)| id == "native-skill")
            .expect("native entry");
        assert_eq!(native_entry.1.len(), 1);
        let javy_entry = data
            .iter()
            .find(|(id, _, _)| id == "javy-skill")
            .expect("javy entry");
        assert!(
            javy_entry.1.is_empty(),
            "javy timers should be excluded from reconcile data"
        );
    }

    #[test]
    fn build_skill_timer_limits_skips_javy_specs() {
        let timer = encmind_wasm_host::manifest::TimerDeclaration {
            name: "tick".into(),
            interval_secs: 60,
            export_fn: "__on_tick".into(),
            description: String::new(),
        };
        let native = test_runtime_spec(
            "native-skill",
            encmind_wasm_host::SkillAbi::Native,
            vec![timer.clone()],
            vec![],
        );
        let javy = test_runtime_spec(
            "javy-skill",
            encmind_wasm_host::SkillAbi::Javy,
            vec![timer],
            vec![],
        );

        let limits = super::build_skill_timer_limits(&[native, javy]);
        assert!(limits.contains_key("native-skill"));
        assert!(!limits.contains_key("javy-skill"));
    }

    #[test]
    fn build_transform_chains_skips_javy_specs() {
        let native_transform = encmind_wasm_host::manifest::TransformDeclaration {
            channel: "native-channel".into(),
            inbound_fn: Some("__inbound".into()),
            outbound_fn: None,
            priority: 0,
        };
        let javy_transform = encmind_wasm_host::manifest::TransformDeclaration {
            channel: "javy-channel".into(),
            inbound_fn: Some("__inbound".into()),
            outbound_fn: None,
            priority: 0,
        };
        let native = test_runtime_spec(
            "native-skill",
            encmind_wasm_host::SkillAbi::Native,
            vec![],
            vec![native_transform],
        );
        let javy = test_runtime_spec(
            "javy-skill",
            encmind_wasm_host::SkillAbi::Javy,
            vec![],
            vec![javy_transform],
        );

        let config = AppConfig::default();
        let pool = encmind_storage::pool::create_test_pool();
        let hook_registry = Arc::new(RwLock::new(HookRegistry::new()));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
        let outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy> =
            Arc::new(super::GatewayOutboundPolicy { firewall });
        let approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter> =
            Arc::new(super::GatewayApprovalPrompter {
                pending_approvals: Arc::new(Mutex::new(std::collections::HashMap::new())),
            });
        let audit = Arc::new(AuditLogger::new(pool.clone()));

        let chains = super::build_transform_chains(
            &config,
            &[native, javy],
            &[],
            pool,
            Arc::new(reqwest::Client::new()),
            hook_registry,
            outbound_policy,
            approval_prompter,
            audit,
        );
        assert!(chains.contains_key("native-channel"));
        assert!(!chains.contains_key("javy-channel"));
    }

    #[test]
    fn build_transform_chains_includes_native_plugin_transforms() {
        struct NativeNoopTransform;

        #[async_trait::async_trait]
        impl encmind_core::plugin::NativeChannelTransform for NativeNoopTransform {
            fn name(&self) -> &str {
                "native-noop"
            }

            async fn transform_inbound(
                &self,
                msg: encmind_core::types::InboundMessage,
            ) -> Result<Option<encmind_core::types::InboundMessage>, PluginError> {
                Ok(Some(msg))
            }

            async fn transform_outbound(
                &self,
                msg: encmind_core::types::OutboundMessage,
            ) -> Result<Option<encmind_core::types::OutboundMessage>, PluginError> {
                Ok(Some(msg))
            }
        }

        let config = AppConfig::default();
        let pool = encmind_storage::pool::create_test_pool();
        let hook_registry = Arc::new(RwLock::new(HookRegistry::new()));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
        let outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy> =
            Arc::new(super::GatewayOutboundPolicy { firewall });
        let approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter> =
            Arc::new(super::GatewayApprovalPrompter {
                pending_approvals: Arc::new(Mutex::new(std::collections::HashMap::new())),
            });
        let audit = Arc::new(AuditLogger::new(pool.clone()));

        let native = crate::plugin_api::RegisteredPluginTransform {
            plugin_id: "native-plugin".to_string(),
            transform_id: "native-noop".to_string(),
            channel: "slack".to_string(),
            priority: 10,
            handler: Arc::new(NativeNoopTransform),
        };

        let chains = super::build_transform_chains(
            &config,
            &[],
            &[native],
            pool,
            Arc::new(reqwest::Client::new()),
            hook_registry,
            outbound_policy,
            approval_prompter,
            audit,
        );

        assert!(chains.contains_key("slack"));
    }

    #[tokio::test]
    async fn build_transform_chains_orders_equal_priority_by_transform_name() {
        struct AppendTransform {
            name: &'static str,
        }

        #[async_trait::async_trait]
        impl encmind_core::plugin::NativeChannelTransform for AppendTransform {
            fn name(&self) -> &str {
                self.name
            }

            async fn transform_inbound(
                &self,
                msg: encmind_core::types::InboundMessage,
            ) -> Result<Option<encmind_core::types::InboundMessage>, PluginError> {
                Ok(Some(msg))
            }

            async fn transform_outbound(
                &self,
                mut msg: encmind_core::types::OutboundMessage,
            ) -> Result<Option<encmind_core::types::OutboundMessage>, PluginError> {
                for block in &mut msg.content {
                    if let encmind_core::types::ContentBlock::Text { text } = block {
                        text.push_str(self.name);
                    }
                }
                Ok(Some(msg))
            }
        }

        let config = AppConfig::default();
        let pool = encmind_storage::pool::create_test_pool();
        let hook_registry = Arc::new(RwLock::new(HookRegistry::new()));
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
        let outbound_policy: Arc<dyn encmind_wasm_host::OutboundPolicy> =
            Arc::new(super::GatewayOutboundPolicy { firewall });
        let approval_prompter: Arc<dyn encmind_wasm_host::ApprovalPrompter> =
            Arc::new(super::GatewayApprovalPrompter {
                pending_approvals: Arc::new(Mutex::new(std::collections::HashMap::new())),
            });
        let audit = Arc::new(AuditLogger::new(pool.clone()));

        let native_transforms = vec![
            crate::plugin_api::RegisteredPluginTransform {
                plugin_id: "native-plugin".to_string(),
                transform_id: "zeta".to_string(),
                channel: "slack".to_string(),
                priority: 10,
                handler: Arc::new(AppendTransform { name: "zeta" }),
            },
            crate::plugin_api::RegisteredPluginTransform {
                plugin_id: "native-plugin".to_string(),
                transform_id: "alpha".to_string(),
                channel: "slack".to_string(),
                priority: 10,
                handler: Arc::new(AppendTransform { name: "alpha" }),
            },
        ];

        let chains = super::build_transform_chains(
            &config,
            &[],
            &native_transforms,
            pool,
            Arc::new(reqwest::Client::new()),
            hook_registry,
            outbound_policy,
            approval_prompter,
            audit,
        );
        let chain = chains
            .get("slack")
            .expect("slack chain should include native transforms");

        let outbound = encmind_core::types::OutboundMessage {
            content: vec![encmind_core::types::ContentBlock::Text {
                text: String::new(),
            }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };
        let transformed = chain
            .apply_outbound(outbound)
            .await
            .expect("transform chain should succeed")
            .expect("message should not be dropped");

        let text = transformed
            .content
            .into_iter()
            .find_map(|block| match block {
                encmind_core::types::ContentBlock::Text { text } => Some(text),
                _ => None,
            })
            .expect("expected text block");
        assert_eq!(text, "alphazeta");
    }

    #[tokio::test]
    async fn native_plugin_timer_tasks_tick_and_stop_on_shutdown() {
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

        let ticks = Arc::new(AtomicUsize::new(0));
        let timers = vec![crate::plugin_api::RegisteredPluginTimer {
            plugin_id: "native-plugin".to_string(),
            name: "heartbeat".to_string(),
            interval_secs: 1,
            handler: Arc::new(CountingTimer {
                ticks: ticks.clone(),
            }),
        }];

        let shutdown = CancellationToken::new();
        let handles = super::spawn_native_plugin_timer_tasks(&timers, shutdown.clone());

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            ticks.load(Ordering::SeqCst) >= 1,
            "timer should tick immediately after task start"
        );

        shutdown.cancel();
        for timer_task in handles {
            let _ = timer_task.handle.await;
        }

        let after_shutdown = ticks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after_shutdown,
            "timer should not tick after shutdown"
        );
    }

    #[tokio::test]
    async fn native_plugin_timer_tasks_disable_after_tick_panic() {
        struct PanicTimer;

        #[async_trait::async_trait]
        impl encmind_core::plugin::NativePluginTimer for PanicTimer {
            fn name(&self) -> &str {
                "panic-timer"
            }

            async fn tick(&self) -> Result<(), PluginError> {
                panic!("panic from timer tick");
            }
        }

        let timers = vec![crate::plugin_api::RegisteredPluginTimer {
            plugin_id: "native-plugin".to_string(),
            name: "panic-timer".to_string(),
            interval_secs: 1,
            handler: Arc::new(PanicTimer),
        }];

        let shutdown = CancellationToken::new();
        let mut handles = super::spawn_native_plugin_timer_tasks(&timers, shutdown.clone());
        tokio::time::sleep(Duration::from_millis(30)).await;

        assert!(
            handles[0].handle.is_finished(),
            "timer task should stop after panic to avoid log spam loops"
        );

        shutdown.cancel();
        for timer_task in handles.drain(..) {
            let _ = timer_task.handle.await;
        }
    }

    #[tokio::test]
    async fn replace_native_plugin_timer_tasks_replaces_running_timer_set() {
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
        let ticks_a = Arc::new(AtomicUsize::new(0));
        let ticks_b = Arc::new(AtomicUsize::new(0));

        let timers_a = vec![crate::plugin_api::RegisteredPluginTimer {
            plugin_id: "native-plugin-a".to_string(),
            name: "heartbeat-a".to_string(),
            interval_secs: 1,
            handler: Arc::new(CountingTimer {
                ticks: ticks_a.clone(),
            }),
        }];

        super::replace_native_plugin_timer_tasks(&state, &timers_a).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            ticks_a.load(Ordering::SeqCst) >= 1,
            "first timer set should tick"
        );

        let timers_b = vec![crate::plugin_api::RegisteredPluginTimer {
            plugin_id: "native-plugin-b".to_string(),
            name: "heartbeat-b".to_string(),
            interval_secs: 1,
            handler: Arc::new(CountingTimer {
                ticks: ticks_b.clone(),
            }),
        }];

        super::replace_native_plugin_timer_tasks(&state, &timers_b).await;
        let after_replace_a = ticks_a.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            ticks_b.load(Ordering::SeqCst) >= 1,
            "replacement timer set should tick"
        );
        assert_eq!(
            ticks_a.load(Ordering::SeqCst),
            after_replace_a,
            "old timer set should stop after replacement"
        );

        // Cleanup: stop active timers to avoid leaking background tasks in test.
        super::replace_native_plugin_timer_tasks(&state, &[]).await;
    }

    #[test]
    fn load_skill_runtime_config_reads_prefixed_keys() {
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().expect("db conn");
            encmind_storage::migrations::run_migrations(&conn).expect("migrations");
            conn.execute(
                "INSERT INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                rusqlite::params!["cfg-skill", "config:mode", b"fast".to_vec()],
            )
            .expect("insert config mode");
            conn.execute(
                "INSERT INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                rusqlite::params!["cfg-skill", "config:endpoint", b"https://example.test".to_vec()],
            )
            .expect("insert config endpoint");
            conn.execute(
                "INSERT INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                rusqlite::params!["cfg-skill", "__resources", b"{}".to_vec()],
            )
            .expect("insert unrelated key");
        }

        let config =
            super::load_skill_runtime_config(&pool, "cfg-skill").expect("config should be present");
        assert_eq!(config["mode"], "fast");
        assert_eq!(config["endpoint"], "https://example.test");
        assert!(config.get("__resources").is_none());
    }

    #[tokio::test]
    async fn load_wasm_skills_startup_applies_persisted_resource_overrides() {
        let temp = tempfile::tempdir().expect("tempdir");
        let skills_dir = temp.path();
        std::fs::write(
            skills_dir.join("resourceful.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .expect("write wasm");
        std::fs::write(
            skills_dir.join("resourceful.toml"),
            r#"[skill]
name = "resourceful"
version = "1.0.0"
description = "Resource override test"
"#,
        )
        .expect("write manifest");

        let mut config = AppConfig::default();
        config.skills.wasm_dir = skills_dir.to_path_buf();

        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().expect("db conn");
            encmind_storage::migrations::run_migrations(&conn).expect("migrations");
            let overrides = serde_json::json!({
                "max_fuel_per_invocation": 321_000u64,
                "max_wall_clock_ms": 1234u64,
                "max_invocations_per_minute": 7u32,
                "max_concurrent": 1u32
            });
            conn.execute(
                "INSERT INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, '__resources', ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                rusqlite::params!["resourceful", serde_json::to_vec(&overrides).expect("serialize overrides")],
            )
            .expect("insert overrides");
        }

        let mut registry = ToolRegistry::new();
        let mut hook_registry = HookRegistry::new();
        let key = [0u8; 32];
        let encryption = Arc::new(Aes256GcmAdapter::new(&key));
        let session_store: Arc<dyn SessionStore> =
            Arc::new(SqliteSessionStore::new(pool.clone(), encryption));
        let loaded = super::load_wasm_skills_startup(
            &config,
            skills_dir,
            &mut registry,
            session_store,
            &mut hook_registry,
            Arc::new(pool.clone()),
            Arc::new(EgressFirewall::new(&config.security.egress_firewall)),
            Arc::new(reqwest::Client::new()),
            Arc::new(Mutex::new(HashMap::new())),
            None,
            None,
            Arc::new(RwLock::new(HashMap::new())),
        )
        .await;

        let spec = loaded
            .runtime_specs
            .iter()
            .find(|s| s.skill_id == "resourceful")
            .expect("runtime spec should exist");
        assert_eq!(spec.resolved_limits.fuel_per_invocation, 321_000);
        assert_eq!(spec.resolved_limits.wall_clock_ms, 1234);
        assert_eq!(spec.resolved_limits.invocations_per_minute, 7);
        assert_eq!(spec.resolved_limits.max_concurrent, 1);
    }
}
