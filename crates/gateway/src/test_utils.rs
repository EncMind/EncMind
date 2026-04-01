use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use encmind_agent::firewall::EgressFirewall;
use encmind_agent::lockdown::LockdownManager;
use encmind_agent::pool::AgentPool;
use encmind_agent::registry::SqliteAgentRegistry;
use encmind_agent::tool_registry::ToolRegistry;
use encmind_core::config::{AgentPoolConfig, AppConfig, LockdownConfig};
use encmind_core::hooks::HookRegistry;
use encmind_core::traits::{AgentRegistry, DeviceStore, SessionStore};
use encmind_storage::audit::AuditLogger;
use encmind_storage::device_store::SqliteDeviceStore;
use encmind_storage::encryption::Aes256GcmAdapter;
use encmind_storage::migrations::run_migrations;
use encmind_storage::pool::create_test_pool;
use encmind_storage::session_store::SqliteSessionStore;
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::channel_manager::ChannelAdapterManager;
use crate::idempotency::IdempotencyCache;
use crate::node::NodeRegistry;
use crate::rate_limiter::SessionRateLimiter;
use crate::state::{AppState, NativePluginTimerRuntime, RuntimeResources};
use crate::{device_auth::NonceStore, pairing::PairingSession};

pub fn make_test_state() -> AppState {
    let pool = create_test_pool();
    {
        let conn = pool.get().unwrap();
        run_migrations(&conn).unwrap();
    }

    let key = [0u8; 32];
    let enc = Arc::new(Aes256GcmAdapter::new(&key));
    let session_store: Arc<dyn SessionStore> = Arc::new(SqliteSessionStore::new(pool.clone(), enc));
    let agent_registry: Arc<dyn AgentRegistry> = Arc::new(SqliteAgentRegistry::new(pool.clone()));
    let device_store: Arc<dyn DeviceStore> = Arc::new(SqliteDeviceStore::new(pool.clone()));
    let lockdown = Arc::new(LockdownManager::new(&LockdownConfig::default()));
    let agent_pool = Arc::new(AgentPool::new(&AgentPoolConfig::default()));
    let config = AppConfig::default();
    let channel_startup_intent = Arc::new(crate::state::compute_channel_startup_intent(&config));
    let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
    let audit = Arc::new(AuditLogger::new(pool.clone()));
    let node_registry = Arc::new(NodeRegistry::new());
    let connection_permits = Arc::new(Semaphore::new(config.gateway.max_connections as usize));
    let idempotency = Arc::new(Mutex::new(IdempotencyCache::new(
        config.gateway.idempotency_ttl_secs,
    )));
    let nonce_store = Arc::new(NonceStore::new());
    let pairing_sessions = Arc::new(Mutex::new(HashMap::<String, PairingSession>::new()));
    let admin_bootstrap_lock = Arc::new(AsyncMutex::new(()));
    let active_runs = Arc::new(Mutex::new(HashMap::<String, CancellationToken>::new()));
    let query_guard = Arc::new(crate::query_guard::QueryGuardRegistry::new(
        config.gateway.max_queued_per_session,
    ));

    let cron_store: Option<Arc<dyn encmind_core::traits::CronStore>> = Some(Arc::new(
        encmind_storage::cron_store::SqliteCronStore::new(pool.clone()),
    ));
    let cron_dispatcher = cron_store.as_ref().map(|store| {
        Arc::new(encmind_channels::cron_dispatcher::CronDispatcher::new(
            store.clone(),
            4,
        ))
    });

    AppState {
        session_store,
        agent_registry,
        device_store,
        lockdown,
        agent_pool,
        runtime: Arc::new(RwLock::new(RuntimeResources {
            llm_backend: None,
            tool_registry: Arc::new(ToolRegistry::new()),
        })),
        api_key_store: None,
        firewall,
        audit,
        config: Arc::new(RwLock::new(config)),
        tls: None,
        node_registry,
        connection_permits,
        idempotency,
        nonce_store,
        pairing_sessions,
        admin_bootstrap_lock,
        active_runs,
        query_guard,
        timeline_store: Some(Arc::new(
            encmind_storage::timeline_store::SqliteTimelineStore::new(pool.clone()),
        )),
        skill_timer_store: Some(Arc::new(
            encmind_storage::skill_timer_store::SqliteSkillTimerStore::new(pool.clone()),
        )),
        db_pool: pool.clone(),
        memory_store: None,
        cron_store,
        cron_dispatcher,
        channel_router: None,
        channel_manager: Arc::new(ChannelAdapterManager::new(CancellationToken::new())),
        backup_manager: None,
        browser_pool: None,
        hook_registry: Arc::new(RwLock::new(HookRegistry::new())),
        plugin_manager: Arc::new(RwLock::new(None)),
        loaded_skills: Arc::new(RwLock::new(Vec::new())),
        known_skill_ids: Arc::new(RwLock::new(HashSet::new())),
        pending_approvals: Arc::new(Mutex::new(HashMap::new())),
        wasm_http_client: Arc::new(reqwest::Client::new()),
        skill_timer_runner: None,
        channel_transforms: Arc::new(RwLock::new(std::collections::HashMap::new())),
        refresh_lock: Arc::new(RwLock::new(())),
        skill_toggle_store: Some(Arc::new(
            encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool.clone()),
        )),
        skill_toggle_lock: Arc::new(AsyncMutex::new(())),
        skill_resources_lock: Arc::new(AsyncMutex::new(())),
        skill_metrics: Arc::new(RwLock::new(std::collections::HashMap::new())),
        native_plugin_timers: Arc::new(AsyncMutex::new(NativePluginTimerRuntime {
            cancel: CancellationToken::new(),
            handles: Vec::new(),
        })),
        native_timer_replace_lock: Arc::new(AsyncMutex::new(())),
        session_rate_limiter: Arc::new(SessionRateLimiter::new(30)),
        api_budget_tracker: None,
        channel_account_store: Some(Arc::new(
            encmind_storage::channel_account_store::SqliteChannelAccountStore::new(
                pool.clone(),
                Arc::new(encmind_storage::encryption::Aes256GcmAdapter::new(&key)),
            ),
        )),
        channel_startup_intent,
    }
}
