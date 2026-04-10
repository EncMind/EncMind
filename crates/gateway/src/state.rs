use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use wasmtime::{Engine, Module};

use encmind_core::types::{SkillApprovalRequest, SkillApprovalResponse};
use encmind_wasm_host::SkillAbi;

use encmind_agent::firewall::EgressFirewall;
use encmind_agent::lockdown::LockdownManager;
use encmind_agent::pool::AgentPool;
use encmind_agent::tool_registry::ToolRegistry;
use encmind_browser::pool::BrowserPool;
use encmind_channels::cron_dispatcher::CronDispatcher;
use encmind_channels::router::ChannelRouter;
use encmind_channels::transform::TransformChain;
use encmind_core::config::AppConfig;
use encmind_core::hooks::HookRegistry;
use encmind_core::traits::{
    AgentRegistry, ApiKeyStore, ChannelAccountStore, CronStore, DeviceStore, LlmBackend,
    SessionStore, SkillTimerStore, SkillToggleStore, TimelineStore,
};

use crate::channel_manager::ChannelAdapterManager;
use encmind_core::types::ResolvedResourceLimits;
use encmind_memory::memory_store::MemoryStoreImpl;
use encmind_storage::audit::AuditLogger;
use encmind_storage::backup::BackupManager;
use encmind_wasm_host::manifest::{TimerDeclaration, TransformDeclaration};

use crate::budget::ApiBudgetTracker;
use crate::plugin_manager::PluginManager;
use crate::rate_limiter::SessionRateLimiter;
use crate::skill_timer::SkillTimerRunner;

use crate::device_auth::NonceStore;
use crate::idempotency::IdempotencyCache;
use crate::node::NodeRegistry;
use crate::pairing::PairingSession;
use crate::tls::TlsLifecycleManager;

#[derive(Clone)]
pub struct RuntimeResources {
    pub llm_backend: Option<Arc<dyn LlmBackend>>,
    pub tool_registry: Arc<ToolRegistry>,
}

#[derive(Debug, Clone)]
pub struct LoadedSkillSummary {
    pub id: String,
    pub version: String,
    pub description: String,
    pub tool_name: Option<String>,
    pub hook_points: Vec<String>,
    pub enabled: bool,
    pub output_schema: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct LoadedSkillRuntimeSpec {
    pub skill_id: String,
    pub manifest_hash: String,
    pub engine: Engine,
    pub module: Module,
    pub abi: SkillAbi,
    pub capabilities: encmind_core::traits::CapabilitySet,
    pub timers: Vec<TimerDeclaration>,
    pub transforms: Vec<TransformDeclaration>,
    pub resolved_limits: ResolvedResourceLimits,
    pub max_memory_mb: usize,
}

/// In-memory skill invocation metrics (reset on restart).
pub struct SkillMetrics {
    pub invocations: AtomicU64,
    pub errors: AtomicU64,
    pub last_invoked_at: Mutex<Option<String>>,
}

impl Default for SkillMetrics {
    fn default() -> Self {
        Self {
            invocations: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_invoked_at: Mutex::new(None),
        }
    }
}

impl SkillMetrics {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct PendingSkillApproval {
    pub request: SkillApprovalRequest,
    pub responder: tokio::sync::oneshot::Sender<SkillApprovalResponse>,
}

/// Runtime holder for native plugin timer tasks managed by reload lifecycle.
pub struct NativePluginTimerHandle {
    pub plugin_id: String,
    pub timer_name: String,
    pub handle: JoinHandle<()>,
}

/// Runtime holder for native plugin timer task lifecycle managed by reload.
pub struct NativePluginTimerRuntime {
    pub cancel: CancellationToken,
    pub handles: Vec<NativePluginTimerHandle>,
}

/// Shared application state threaded through all axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub session_store: Arc<dyn SessionStore>,
    pub agent_registry: Arc<dyn AgentRegistry>,
    pub device_store: Arc<dyn DeviceStore>,
    pub lockdown: Arc<LockdownManager>,
    pub agent_pool: Arc<AgentPool>,
    pub runtime: Arc<RwLock<RuntimeResources>>,
    pub api_key_store: Option<Arc<dyn ApiKeyStore>>,
    pub firewall: Arc<EgressFirewall>,
    pub audit: Arc<AuditLogger>,
    pub config: Arc<RwLock<AppConfig>>,
    pub tls: Option<Arc<TlsLifecycleManager>>,
    pub node_registry: Arc<NodeRegistry>,
    pub connection_permits: Arc<Semaphore>,
    pub idempotency: Arc<Mutex<IdempotencyCache>>,
    pub nonce_store: Arc<NonceStore>,
    pub pairing_sessions: Arc<Mutex<HashMap<String, PairingSession>>>,
    pub admin_bootstrap_lock: Arc<AsyncMutex<()>>,
    pub active_runs: Arc<Mutex<HashMap<String, CancellationToken>>>,
    /// Per-session query guard that serializes concurrent chat.send calls.
    pub query_guard: Arc<crate::query_guard::QueryGuardRegistry>,
    pub db_pool: Pool<SqliteConnectionManager>,
    pub memory_store: Option<Arc<MemoryStoreImpl>>,
    pub cron_store: Option<Arc<dyn CronStore>>,
    pub cron_dispatcher: Option<Arc<CronDispatcher>>,
    pub channel_router: Option<Arc<ChannelRouter>>,
    pub timeline_store: Option<Arc<dyn TimelineStore>>,
    pub backup_manager: Option<Arc<BackupManager>>,
    pub browser_pool: Option<Arc<BrowserPool>>,
    pub hook_registry: Arc<RwLock<HookRegistry>>,
    pub plugin_manager: Arc<RwLock<Option<Arc<PluginManager>>>>,
    pub loaded_skills: Arc<RwLock<Vec<LoadedSkillSummary>>>,
    /// Cached known skill IDs discovered during startup/refresh loading and
    /// refreshed during runtime skill-id validation paths.
    pub known_skill_ids: Arc<RwLock<HashSet<String>>>,
    /// Pending WASM skill approval requests awaiting user response.
    pub pending_approvals: Arc<Mutex<HashMap<String, PendingSkillApproval>>>,
    /// Shared HTTP client for WASM host outbound calls and refresh rebuilds.
    pub wasm_http_client: Arc<reqwest::Client>,
    /// Skill timer store for persistent timer management.
    pub skill_timer_store: Option<Arc<dyn SkillTimerStore>>,
    /// Background runner executing due skill timers.
    pub skill_timer_runner: Option<Arc<SkillTimerRunner>>,
    /// Per-channel transform chains, keyed by channel name.
    pub channel_transforms: Arc<RwLock<HashMap<String, TransformChain>>>,
    /// Lock serializing refresh operations (build→validate→commit).
    pub refresh_lock: Arc<RwLock<()>>,
    /// Skill toggle store for persistent enable/disable state.
    pub skill_toggle_store: Option<Arc<dyn SkillToggleStore>>,
    /// Lock serializing skills.toggle operations to avoid interleaved persistence/refresh races.
    pub skill_toggle_lock: Arc<AsyncMutex<()>>,
    /// Lock serializing skills.config.set + skills.resources.set refresh/rollback sequences.
    pub skill_resources_lock: Arc<AsyncMutex<()>>,
    /// In-memory per-skill invocation/error metrics, keyed by skill ID.
    pub skill_metrics: Arc<RwLock<HashMap<String, Arc<SkillMetrics>>>>,
    /// Native plugin timer lifecycle state (cancellation token + active task handles).
    pub native_plugin_timers: Arc<AsyncMutex<NativePluginTimerRuntime>>,
    /// Lock serializing native plugin timer replacement lifecycle.
    pub native_timer_replace_lock: Arc<AsyncMutex<()>>,
    /// Per-session sliding-window rate limiter.
    pub session_rate_limiter: Arc<SessionRateLimiter>,
    /// Optional daily API budget tracker.
    pub api_budget_tracker: Option<Arc<ApiBudgetTracker>>,
    /// Per-turn API usage recorder for cost attribution.
    /// One row per chat.send turn (completed, cancelled, or error).
    pub api_usage_store: Option<Arc<encmind_storage::api_usage::ApiUsageStore>>,
    /// Channel account store for managing channel accounts via API.
    pub channel_account_store: Option<Arc<dyn ChannelAccountStore>>,
    /// Runtime channel adapter manager for dynamic start/stop.
    pub channel_manager: Arc<ChannelAdapterManager>,
    /// Snapshot of config-channel startup intent computed at boot:
    /// channel names that signaled boot credential intent via env vars.
    ///
    /// For multi-field credentials (Slack, Gmail), this includes partial env
    /// presence so readiness can surface degraded startup/misconfiguration.
    pub channel_startup_intent: Arc<HashSet<String>>,
}

pub fn compute_channel_startup_intent(config: &AppConfig) -> HashSet<String> {
    let mut intent = HashSet::new();
    if config
        .channels
        .telegram
        .as_ref()
        .is_some_and(|tg| env_var_is_set(&tg.bot_token_env))
    {
        intent.insert("telegram".to_string());
    }
    if config
        .channels
        .slack
        .as_ref()
        .is_some_and(|sl| env_var_is_set(&sl.bot_token_env) || env_var_is_set(&sl.app_token_env))
    {
        intent.insert("slack".to_string());
    }
    if config.channels.gmail.as_ref().is_some_and(|gm| {
        let cid = gm.client_id_env.trim();
        let csec = gm.client_secret_env.trim();
        let rt = gm.refresh_token_env.trim();
        // Surface startup intent whenever env refs are declared, even if values
        // are missing, so readiness can report boot credential misconfiguration.
        !cid.is_empty() || !csec.is_empty() || !rt.is_empty()
    }) {
        intent.insert("gmail".to_string());
    }
    intent
}

fn env_var_is_set(name: &str) -> bool {
    std::env::var(name)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_agent::lockdown::LockdownManager;
    use encmind_agent::registry::SqliteAgentRegistry;
    use encmind_core::config::{AppConfig, GmailConfig, LockdownConfig, SlackConfig};
    use encmind_storage::device_store::SqliteDeviceStore;
    use encmind_storage::encryption::Aes256GcmAdapter;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;
    use encmind_storage::session_store::SqliteSessionStore;

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

    #[test]
    fn app_state_is_constructable() {
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
        let config = AppConfig::default();
        let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
        let audit = Arc::new(AuditLogger::new(pool.clone()));
        let node_registry = Arc::new(NodeRegistry::new());
        let connection_permits = Arc::new(Semaphore::new(config.gateway.max_connections as usize));
        let idempotency = Arc::new(Mutex::new(IdempotencyCache::new(
            config.gateway.idempotency_ttl_secs,
        )));
        let nonce_store = Arc::new(NonceStore::new());
        let pairing_sessions = Arc::new(Mutex::new(HashMap::new()));
        let admin_bootstrap_lock = Arc::new(AsyncMutex::new(()));
        let active_runs = Arc::new(Mutex::new(HashMap::new()));
        let query_guard = Arc::new(crate::query_guard::QueryGuardRegistry::new(
            config.gateway.max_queued_per_session,
        ));

        let _state = AppState {
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
            api_usage_store: None,
            channel_account_store: None,
            channel_startup_intent: Arc::new(HashSet::new()),
        };
    }

    #[test]
    fn compute_channel_startup_intent_flags_declared_gmail_env_refs_even_when_values_missing() {
        let mut config = AppConfig::default();
        config.channels.gmail = Some(GmailConfig {
            client_id_env: "ENCMIND_STATE_TEST_GMAIL_CID".to_string(),
            client_secret_env: "ENCMIND_STATE_TEST_GMAIL_CSEC".to_string(),
            refresh_token_env: "ENCMIND_STATE_TEST_GMAIL_RT".to_string(),
            ..Default::default()
        });
        std::env::remove_var("ENCMIND_STATE_TEST_GMAIL_CID");
        std::env::remove_var("ENCMIND_STATE_TEST_GMAIL_CSEC");
        std::env::remove_var("ENCMIND_STATE_TEST_GMAIL_RT");

        let intent = compute_channel_startup_intent(&config);
        assert!(
            intent.contains("gmail"),
            "declared gmail env refs should be in startup intent even when values are missing"
        );
    }

    #[test]
    fn compute_channel_startup_intent_flags_partial_gmail_env_presence() {
        let mut config = AppConfig::default();
        config.channels.gmail = Some(GmailConfig {
            client_id_env: "ENCMIND_STATE_TEST_GMAIL_CID_PARTIAL".to_string(),
            client_secret_env: "ENCMIND_STATE_TEST_GMAIL_CSEC_PARTIAL".to_string(),
            refresh_token_env: "ENCMIND_STATE_TEST_GMAIL_RT_PARTIAL".to_string(),
            ..Default::default()
        });
        let _guard = EnvVarGuard::set("ENCMIND_STATE_TEST_GMAIL_CID_PARTIAL", "cid");
        std::env::remove_var("ENCMIND_STATE_TEST_GMAIL_CSEC_PARTIAL");
        std::env::remove_var("ENCMIND_STATE_TEST_GMAIL_RT_PARTIAL");

        let intent = compute_channel_startup_intent(&config);
        assert!(
            intent.contains("gmail"),
            "partial gmail env credentials should surface startup intent"
        );
    }

    #[test]
    fn compute_channel_startup_intent_flags_partial_slack_env_presence() {
        let mut config = AppConfig::default();
        config.channels.slack = Some(SlackConfig {
            bot_token_env: "ENCMIND_STATE_TEST_SLACK_BOT_PARTIAL".to_string(),
            app_token_env: "ENCMIND_STATE_TEST_SLACK_APP_PARTIAL".to_string(),
            ..Default::default()
        });
        let _guard = EnvVarGuard::set("ENCMIND_STATE_TEST_SLACK_BOT_PARTIAL", "xoxb-test");
        std::env::remove_var("ENCMIND_STATE_TEST_SLACK_APP_PARTIAL");

        let intent = compute_channel_startup_intent(&config);
        assert!(
            intent.contains("slack"),
            "partial slack env credentials should surface startup intent"
        );
    }
}
