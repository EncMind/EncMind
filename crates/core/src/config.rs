use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::error::StorageError;
use crate::policy::{deny_rule_matches_capability, PluginPolicyConfig};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub tee: TeeConfig,
    #[serde(default)]
    pub channels: ChannelsConfig,
    #[serde(default)]
    pub skills: SkillsConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub agents: AgentsConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    #[serde(default)]
    pub agent_pool: AgentPoolConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub workflows: WorkflowConfig,
    #[serde(default)]
    pub retrieval_quality: RetrievalQualityConfig,
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub cron: CronConfig,
    #[serde(default)]
    pub browser: BrowserConfig,
    #[serde(default)]
    pub token_optimization: TokenOptimizationConfig,
    #[serde(default)]
    pub plugin_policy: PluginPolicyConfig,
    #[serde(default)]
    pub skill_error_policy: SkillErrorPolicy,
    /// Per-plugin configuration sections, keyed by plugin ID.
    /// Allows operators to pass arbitrary config to native plugins via `config.yaml`.
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,
}

/// Operator-tunable error handling for skill execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillErrorPolicy {
    #[serde(default = "default_true")]
    pub transform_inbound_fail_open: bool,
    #[serde(default = "default_true")]
    pub transform_outbound_fail_open: bool,
    #[serde(default = "default_timer_max_failures")]
    pub timer_max_consecutive_failures: u32,
    #[serde(default = "default_true")]
    pub timer_auto_disable: bool,
}

fn default_timer_max_failures() -> u32 {
    5
}

impl Default for SkillErrorPolicy {
    fn default() -> Self {
        Self {
            transform_inbound_fail_open: true,
            transform_outbound_fail_open: true,
            timer_max_consecutive_failures: default_timer_max_failures(),
            timer_auto_disable: true,
        }
    }
}

impl AppConfig {
    /// Validate the configuration for obvious errors.
    /// Returns a list of human-readable error strings; empty = valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.storage.db_path.as_os_str().is_empty() {
            errors.push("storage.db_path must not be empty".to_string());
        }

        // Must have at least one LLM source
        let has_local = self.llm.local.is_some();
        let has_api = !self.llm.api_providers.is_empty();
        if !has_local && !has_api {
            errors.push(
                "at least one LLM provider (llm.local or llm.api_providers) must be configured"
                    .to_string(),
            );
        }

        // Provider names must be non-empty and unique
        let mut seen_names = std::collections::HashSet::new();
        for provider in &self.llm.api_providers {
            if provider.name.trim().is_empty() {
                errors.push("llm.api_providers: provider name must not be empty".to_string());
            } else if !seen_names.insert(&provider.name) {
                errors.push(format!(
                    "llm.api_providers: duplicate provider name '{}'",
                    provider.name
                ));
            }
        }

        if self.security.rate_limit.messages_per_minute == 0 {
            errors.push("security.rate_limit.messages_per_minute must be > 0".to_string());
        }

        if self.security.rate_limit.tool_calls_per_run == 0 {
            errors.push("security.rate_limit.tool_calls_per_run must be > 0".to_string());
        }

        if let Some(budget) = self.security.rate_limit.api_budget_usd {
            if budget <= 0.0 {
                errors.push("security.rate_limit.api_budget_usd must be > 0 when set".to_string());
            }
        }

        if self.agent_pool.max_concurrent_agents == 0 {
            errors.push("agent_pool.max_concurrent_agents must be > 0".to_string());
        }
        if self.agent_pool.max_parallel_safe_tools == 0 {
            errors.push("agent_pool.max_parallel_safe_tools must be > 0".to_string());
        }

        for (channel, cap) in &self.token_optimization.per_channel_max_output_tokens {
            if channel.trim().is_empty() {
                errors.push(
                    "token_optimization.per_channel_max_output_tokens: channel key must not be empty"
                        .to_string(),
                );
            }
            if *cap == 0 {
                errors.push(format!(
                    "token_optimization.per_channel_max_output_tokens['{channel}'] must be > 0"
                ));
            }
        }

        if self.security.blocking_tool_cancel_grace_secs == 0 {
            errors.push("security.blocking_tool_cancel_grace_secs must be > 0".to_string());
        }
        let mut normalized_interrupt_tools: HashMap<String, String> = HashMap::new();
        for (tool_name, behavior) in &self.security.per_tool_interrupt_behavior {
            let canonical_tool_name = tool_name.trim().to_ascii_lowercase();
            if canonical_tool_name.is_empty() {
                errors.push(
                    "security.per_tool_interrupt_behavior: tool name must not be empty".to_string(),
                );
                continue;
            }
            if let Some(existing) =
                normalized_interrupt_tools.insert(canonical_tool_name, tool_name.clone())
            {
                errors.push(format!(
                    "security.per_tool_interrupt_behavior has duplicate keys after normalization: '{existing}' and '{tool_name}'"
                ));
            }
            let normalized = behavior.trim().to_ascii_lowercase();
            if normalized != "cancel" && normalized != "block" {
                errors.push(format!(
                    "security.per_tool_interrupt_behavior['{tool_name}'] must be 'cancel' or 'block'"
                ));
            }
        }

        // Workspace trust validation
        {
            let action = self
                .security
                .workspace_trust
                .untrusted_default
                .trim()
                .to_ascii_lowercase();
            if !["readonly", "deny", "allow"].contains(&action.as_str()) {
                errors.push(format!(
                    "security.workspace_trust.untrusted_default must be 'readonly', 'deny', or 'allow'; got '{action}'"
                ));
            }
            let no_workspace_action = self
                .security
                .workspace_trust
                .no_workspace_default
                .trim()
                .to_ascii_lowercase();
            if !["trusted", "readonly", "deny"].contains(&no_workspace_action.as_str()) {
                errors.push(format!(
                    "security.workspace_trust.no_workspace_default must be 'trusted', 'readonly', or 'deny'; got '{no_workspace_action}'"
                ));
            }
            // Note: when trusted_paths is empty and untrusted_default
            // is not "allow", the trust gate is effectively disabled
            // for backward compatibility (workspace_trust.rs returns
            // Trusted). A warn-once guard in evaluate_trust() fires
            // at runtime on first evaluation (see workspace_trust.rs
            // EMPTY_TRUSTED_PATHS_WARNED). We intentionally do NOT
            // log here — validate() should be side-effect-free so
            // tests, hot-reload checks, and tooling don't produce
            // spurious warnings.
        }

        if self.memory.enabled {
            if self.memory.embedding_dimensions == 0 {
                errors.push("memory.embedding_dimensions must be > 0".to_string());
            }
            match &self.memory.embedding_mode {
                EmbeddingMode::Private => {
                    if let Some(path) = &self.memory.local_model_path {
                        if !path.exists() {
                            errors.push(format!(
                                "memory.local_model_path does not exist: {}",
                                path.display()
                            ));
                        } else if !path.is_dir() {
                            errors.push(format!(
                                "memory.local_model_path must be a directory: {}",
                                path.display()
                            ));
                        }
                    }
                }
                EmbeddingMode::External {
                    provider,
                    api_base_url,
                } => {
                    if provider.trim().is_empty() {
                        errors.push(
                            "memory.embedding_mode.provider must not be empty when embedding_mode.type=external"
                                .to_string(),
                        );
                    }
                    if api_base_url.trim().is_empty() {
                        errors.push(
                            "memory.embedding_mode.api_base_url must not be empty when embedding_mode.type=external"
                                .to_string(),
                        );
                    }
                    if self.memory.local_model_path.is_some() {
                        errors.push(
                            "memory.local_model_path is only valid when memory.embedding_mode.type=private"
                                .to_string(),
                        );
                    }
                }
            }
        }

        if matches!(
            self.security.local_tools.mode,
            LocalToolsMode::IsolatedAgents
        ) {
            let missing: Vec<String> = self
                .agents
                .list
                .iter()
                .filter(|a| match a.workspace.as_ref() {
                    Some(w) => w.as_os_str().is_empty(),
                    None => true,
                })
                .map(|a| a.id.clone())
                .collect();

            if !missing.is_empty() {
                errors.push(format!(
                    "security.local_tools.mode=isolated_agents requires workspace for every agent; missing for: {}",
                    missing.join(", ")
                ));
            }

            if matches!(
                self.security.local_tools.bash_mode,
                LocalToolsBashMode::Host
            ) {
                errors.push(
                    "security.local_tools.bash_mode=host is not allowed when mode=isolated_agents; set security.local_tools.bash_mode=disabled"
                        .to_string(),
                );
            }
        }

        if self.browser.max_actions_per_call > 1 {
            errors.push(
                "browser.max_actions_per_call > 1 is not supported yet; use 0 (disable) or 1"
                    .to_string(),
            );
        }

        if self.server.public_webhooks.enabled {
            match self.server.public_webhooks.auth_mode {
                PublicWebhookAuthMode::SharedBearer => {
                    let env_name = self
                        .server
                        .public_webhooks
                        .auth_token_env
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("");
                    if env_name.is_empty() {
                        errors.push(
                            "server.public_webhooks.auth_token_env must be set when server.public_webhooks.enabled=true and auth_mode=shared_bearer"
                                .to_string(),
                        );
                    } else {
                        match std::env::var(env_name) {
                            Ok(value) if !value.trim().is_empty() => {}
                            Ok(_) => errors.push(format!(
                                "server.public_webhooks auth token env var {env_name} is set but empty"
                            )),
                            Err(_) => errors.push(format!(
                                "server.public_webhooks auth token env var {env_name} is not set"
                            )),
                        }
                    }
                }
                PublicWebhookAuthMode::GoogleOidc => {
                    let audience = self
                        .server
                        .public_webhooks
                        .google_oidc_audience
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("");
                    if audience.is_empty() {
                        errors.push(
                            "server.public_webhooks.google_oidc_audience must be set when server.public_webhooks.enabled=true and auth_mode=google_oidc"
                                .to_string(),
                        );
                    }
                }
            }

            if self.server.public_webhooks.require_tls {
                let tls_configured = self.server.auto_tls
                    || (self.server.tls_cert_path.is_some() && self.server.tls_key_path.is_some());
                if !tls_configured {
                    errors.push(
                        "server.public_webhooks.require_tls=true requires TLS listener configuration (server.auto_tls=true or server.tls_cert_path + server.tls_key_path)"
                            .to_string(),
                    );
                }
            }

            if let Some(bind_host) = self.server.public_webhooks.bind_host.as_deref() {
                let bind_host = bind_host.trim();
                if bind_host.is_empty() {
                    errors.push(
                        "server.public_webhooks.bind_host must not be empty when provided"
                            .to_string(),
                    );
                } else if bind_host != self.server.host.trim() {
                    errors.push(format!(
                        "server.public_webhooks.bind_host ({bind_host}) must match server.host ({}) in the current single-listener deployment",
                        self.server.host.trim()
                    ));
                }
            }
        }

        if let Some(gmail) = &self.channels.gmail {
            let cid = gmail.client_id_env.trim();
            let csec = gmail.client_secret_env.trim();
            let rt = gmail.refresh_token_env.trim();
            let set_count = [cid, csec, rt]
                .into_iter()
                .filter(|v| !v.is_empty())
                .count();

            if (1..3).contains(&set_count) {
                errors.push(
                    "channels.gmail env credential config is partial; set client_id_env, client_secret_env, and refresh_token_env together (or leave all empty for API login flow)".to_string(),
                );
            }
            if gmail.poll_interval_secs == 0 {
                errors.push("channels.gmail.poll_interval_secs must be > 0".to_string());
            }
            if gmail.max_attachments_per_message == 0 {
                errors.push("channels.gmail.max_attachments_per_message must be > 0".to_string());
            }
            if gmail.max_file_bytes == 0 {
                errors.push("channels.gmail.max_file_bytes must be > 0".to_string());
            }
            if gmail.label_filter.trim().is_empty() {
                errors.push("channels.gmail.label_filter must not be empty".to_string());
            }
            if !gmail.allowed_senders.is_empty() {
                let mut seen = HashSet::new();
                for (idx, sender) in gmail.allowed_senders.iter().enumerate() {
                    let raw = sender.sender_id.trim();
                    if raw.is_empty() {
                        errors.push(format!(
                            "channels.gmail.allowed_senders[{idx}].sender_id must not be empty"
                        ));
                        continue;
                    }
                    if !GmailConfig::is_valid_sender_id(raw) {
                        errors.push(format!(
                            "channels.gmail.allowed_senders[{idx}].sender_id must be an email address"
                        ));
                        continue;
                    }
                    let normalized = GmailConfig::normalize_sender_id(raw);
                    if normalized.is_empty() {
                        errors.push(format!(
                            "channels.gmail.allowed_senders[{idx}].sender_id must not be empty"
                        ));
                        continue;
                    }
                    if !seen.insert(normalized.clone()) {
                        errors.push(format!(
                            "channels.gmail.allowed_senders contains duplicate sender_id: {normalized}"
                        ));
                    }
                }

                let gmail_policy_senders: HashSet<String> = self
                    .channels
                    .access_policy
                    .allowlist
                    .iter()
                    .filter(|entry| entry.channel == "gmail")
                    .map(|entry| GmailConfig::normalize_sender_id(&entry.sender_id))
                    .filter(|sender| !sender.is_empty())
                    .collect();
                if !gmail_policy_senders.is_empty() {
                    let gmail_allowed_senders: HashSet<String> =
                        gmail.normalized_allowed_sender_ids().into_iter().collect();
                    if gmail_policy_senders != gmail_allowed_senders {
                        errors.push(
                            "channels.access_policy.allowlist for channel=gmail must match channels.gmail.allowed_senders when both are configured".to_string(),
                        );
                    }
                }
            }
        }

        if let Some(raw_netprobe) = self.plugins.get("netprobe") {
            match serde_json::from_value::<NetProbeConfig>(raw_netprobe.clone()) {
                Ok(netprobe) => {
                    if let Err(e) = netprobe.validate() {
                        errors.push(e);
                    }
                }
                Err(e) => {
                    errors.push(format!("plugins.netprobe config is invalid: {e}"));
                }
            }
        }

        if let Some(raw_digest) = self.plugins.get("digest") {
            match serde_json::from_value::<DigestConfig>(raw_digest.clone()) {
                Ok(digest) => {
                    if let Err(e) = digest.validate() {
                        errors.push(e);
                    }
                }
                Err(e) => {
                    errors.push(format!("plugins.digest config is invalid: {e}"));
                }
            }
        }

        errors
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub profile: ServerProfile,
    #[serde(default = "default_local_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    #[serde(default)]
    pub auto_tls: bool,
    #[serde(default)]
    pub public_webhooks: PublicWebhooksConfig,
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u32,
    /// Grace period (seconds) to wait for in-flight agent runs to
    /// complete before force-cancelling them on SIGTERM. During this
    /// window the server stops accepting new requests but lets
    /// active runs finish naturally. Runs still active after the
    /// drain timeout are cancelled. Default: 10s.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u32,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerProfile {
    #[default]
    Local,
    Remote,
    Domain,
}

fn default_local_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8443
}
fn default_shutdown_timeout_secs() -> u32 {
    30
}
fn default_drain_timeout_secs() -> u32 {
    10
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            profile: ServerProfile::Local,
            host: default_local_host(),
            port: default_port(),
            tls_cert_path: None,
            tls_key_path: None,
            auto_tls: false,
            public_webhooks: PublicWebhooksConfig::default(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            drain_timeout_secs: default_drain_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PublicWebhooksConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Hostname/IP reserved for dedicated webhook binding.
    /// Current deployment uses a single listener, so when set this must match `server.host`.
    pub bind_host: Option<String>,
    #[serde(default = "default_true")]
    /// Require TLS listener configuration before enabling public webhooks.
    pub require_tls: bool,
    /// Authentication mode for webhook ingress.
    #[serde(default)]
    pub auth_mode: PublicWebhookAuthMode,
    /// Env var name containing shared bearer token for webhook authentication.
    /// Required when `enabled=true` and `auth_mode=shared_bearer`.
    #[serde(default)]
    pub auth_token_env: Option<String>,
    /// Expected audience claim for Google OIDC JWT webhook auth.
    /// Required when `enabled=true` and `auth_mode=google_oidc`.
    #[serde(default)]
    pub google_oidc_audience: Option<String>,
    /// Optional expected service account email for Google OIDC JWT.
    #[serde(default)]
    pub google_oidc_email: Option<String>,
}

impl Default for PublicWebhooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_host: None,
            require_tls: true,
            auth_mode: PublicWebhookAuthMode::default(),
            auth_token_env: None,
            google_oidc_audience: None,
            google_oidc_email: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicWebhookAuthMode {
    #[default]
    SharedBearer,
    GoogleOidc,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    #[serde(default)]
    pub key_source: KeySource,
    pub backup_dir: Option<PathBuf>,
}

fn default_db_path() -> PathBuf {
    default_home_path(".encmind/data.db")
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            key_source: KeySource::default(),
            backup_dir: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum KeySource {
    Passphrase {
        passphrase_env: String,
    },
    TeeSeal,
    EnvVar {
        var_name: String,
    },
    ExternalVault {
        provider: VaultProvider,
        key_id: String,
    },
}

impl Default for KeySource {
    fn default() -> Self {
        Self::Passphrase {
            passphrase_env: "ENCMIND_PASSPHRASE".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LlmConfig {
    #[serde(default)]
    pub mode: InferenceMode,
    pub local: Option<LocalLlmConfig>,
    #[serde(default)]
    pub api_providers: Vec<ApiProviderConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum InferenceMode {
    #[default]
    Local,
    ApiProvider {
        provider: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalLlmConfig {
    pub model_path: PathBuf,
    pub model_name: String,
    #[serde(default = "default_context_length")]
    pub context_length: u32,
    pub threads: Option<u32>,
    pub gpu_layers: Option<u32>,
}

fn default_context_length() -> u32 {
    8192
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiProviderConfig {
    pub name: String,
    pub model: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub attestation_endpoint: bool,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            attestation_endpoint: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ChannelsConfig {
    pub telegram: Option<TelegramConfig>,
    pub slack: Option<SlackConfig>,
    pub gmail: Option<GmailConfig>,
    #[serde(default)]
    pub access_policy: InboundAccessPolicy,
    /// Per-channel allowed slash commands. Key = channel name, value = list of commands.
    /// Empty map means all commands are allowed on all channels.
    #[serde(default)]
    pub command_gates: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct InboundAccessPolicy {
    #[serde(default)]
    pub default_action: AccessAction,
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
    #[serde(default)]
    pub notify_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    Allow,
    #[default]
    Reject,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowlistEntry {
    pub channel: String,
    pub sender_id: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelegramConfig {
    pub bot_token_env: String,
    #[serde(default)]
    pub mode: TelegramMode,
    pub webhook_url: Option<String>,
    /// Max bytes per downloaded inbound attachment.
    #[serde(default = "default_channel_max_file_bytes")]
    pub max_file_bytes: usize,
    /// Max attachments attempted per inbound message.
    #[serde(default = "default_channel_max_attachments_per_message")]
    pub max_attachments_per_message: usize,
    /// Max total bytes across all downloaded attachments for a single message.
    #[serde(default = "default_channel_max_total_attachment_bytes")]
    pub max_total_attachment_bytes: usize,
    /// Per-file download timeout in seconds during inbound attachment hydration.
    #[serde(default = "default_channel_download_timeout_secs")]
    pub download_timeout_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelegramMode {
    #[default]
    Polling,
    Webhook,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlackConfig {
    pub bot_token_env: String,
    pub app_token_env: String,
    /// Max bytes per downloaded inbound attachment.
    #[serde(default = "default_channel_max_file_bytes")]
    pub max_file_bytes: usize,
    /// Max attachments attempted per inbound message.
    #[serde(default = "default_channel_max_attachments_per_message")]
    pub max_attachments_per_message: usize,
    /// Max total bytes across all downloaded attachments for a single message.
    #[serde(default = "default_channel_max_total_attachment_bytes")]
    pub max_total_attachment_bytes: usize,
    /// Per-file download timeout in seconds during inbound attachment hydration.
    #[serde(default = "default_channel_download_timeout_secs")]
    pub download_timeout_secs: u64,
}

fn default_channel_max_file_bytes() -> usize {
    20 * 1024 * 1024
}

fn default_channel_max_attachments_per_message() -> usize {
    5
}

fn default_channel_max_total_attachment_bytes() -> usize {
    25 * 1024 * 1024
}

fn default_channel_download_timeout_secs() -> u64 {
    4
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            bot_token_env: String::new(),
            mode: TelegramMode::default(),
            webhook_url: None,
            max_file_bytes: default_channel_max_file_bytes(),
            max_attachments_per_message: default_channel_max_attachments_per_message(),
            max_total_attachment_bytes: default_channel_max_total_attachment_bytes(),
            download_timeout_secs: default_channel_download_timeout_secs(),
        }
    }
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            bot_token_env: String::new(),
            app_token_env: String::new(),
            max_file_bytes: default_channel_max_file_bytes(),
            max_attachments_per_message: default_channel_max_attachments_per_message(),
            max_total_attachment_bytes: default_channel_max_total_attachment_bytes(),
            download_timeout_secs: default_channel_download_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GmailConfig {
    /// Env var name containing OAuth2 client ID for boot-time adapter start.
    /// Empty means no boot-time Gmail adapter credentials from env.
    #[serde(default = "default_gmail_client_id_env")]
    pub client_id_env: String,
    /// Env var name containing OAuth2 client secret for boot-time adapter start.
    #[serde(default = "default_gmail_client_secret_env")]
    pub client_secret_env: String,
    /// Env var name containing OAuth2 refresh token for boot-time adapter start.
    #[serde(default = "default_gmail_refresh_token_env")]
    pub refresh_token_env: String,
    /// Polling interval in seconds. Default: 30.
    #[serde(default = "default_gmail_poll_interval")]
    pub poll_interval_secs: u64,
    /// Max attachments per inbound message. Default: 5.
    #[serde(default = "default_channel_max_attachments_per_message")]
    pub max_attachments_per_message: usize,
    /// Max bytes per attachment. Default: 10 MiB.
    #[serde(default = "default_gmail_max_file_bytes")]
    pub max_file_bytes: usize,
    /// Gmail label to filter. Default: INBOX.
    #[serde(default = "default_gmail_label_filter")]
    pub label_filter: String,
    /// Whether the gateway should automatically send LLM-generated replies for
    /// inbound Gmail messages. Default: false.
    #[serde(default)]
    pub auto_reply: bool,
    /// Optional per-sender policy overrides.
    ///
    /// If non-empty, only configured senders are eligible for auto-reply.
    #[serde(default)]
    pub allowed_senders: Vec<GmailAllowedSender>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GmailAllowedSender {
    /// RFC 5322 sender mailbox address to match against the parsed `From` header.
    pub sender_id: String,
    /// Optional per-sender auto-reply override.
    /// `None` falls back to `GmailConfig.auto_reply`.
    #[serde(default)]
    pub auto_reply: Option<bool>,
}

fn default_gmail_poll_interval() -> u64 {
    30
}

fn default_gmail_client_id_env() -> String {
    String::new()
}

fn default_gmail_client_secret_env() -> String {
    String::new()
}

fn default_gmail_refresh_token_env() -> String {
    String::new()
}

fn default_gmail_max_file_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_gmail_label_filter() -> String {
    "INBOX".to_string()
}

impl Default for GmailConfig {
    fn default() -> Self {
        Self {
            client_id_env: default_gmail_client_id_env(),
            client_secret_env: default_gmail_client_secret_env(),
            refresh_token_env: default_gmail_refresh_token_env(),
            poll_interval_secs: default_gmail_poll_interval(),
            max_attachments_per_message: default_channel_max_attachments_per_message(),
            max_file_bytes: default_gmail_max_file_bytes(),
            label_filter: default_gmail_label_filter(),
            auto_reply: false,
            allowed_senders: Vec::new(),
        }
    }
}

impl GmailConfig {
    pub fn is_valid_sender_id(sender_id: &str) -> bool {
        let value = sender_id.trim();
        if value.is_empty() || value.contains(char::is_whitespace) {
            return false;
        }
        let Some((local, domain)) = value.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && !domain.is_empty()
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !domain.contains('@')
    }

    pub fn normalize_sender_id(sender_id: &str) -> String {
        let normalized = sender_id.trim().to_ascii_lowercase();
        let Some((local, domain)) = normalized.split_once('@') else {
            return normalized;
        };
        if domain == "gmail.com" || domain == "googlemail.com" {
            let local_base = local.split('+').next().unwrap_or(local).replace('.', "");
            return format!("{local_base}@gmail.com");
        }
        normalized
    }

    pub fn sender_policy(&self, sender_id: &str) -> Option<&GmailAllowedSender> {
        let normalized = Self::normalize_sender_id(sender_id);
        self.allowed_senders
            .iter()
            .find(|entry| Self::normalize_sender_id(&entry.sender_id) == normalized)
    }

    pub fn normalized_allowed_sender_ids(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut senders = Vec::new();
        for entry in &self.allowed_senders {
            let normalized = Self::normalize_sender_id(&entry.sender_id);
            if normalized.is_empty() || !seen.insert(normalized.clone()) {
                continue;
            }
            senders.push(normalized);
        }
        senders
    }

    /// Sender IDs suitable for Gmail API `from:` query clauses.
    ///
    /// Keeps raw mailbox forms (trimmed + lowercased) so Gmail query behavior
    /// is preserved; also adds normalized variants as fallback terms.
    pub fn query_allowed_sender_ids(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut senders = Vec::new();
        for entry in &self.allowed_senders {
            let raw = entry.sender_id.trim().to_ascii_lowercase();
            if !raw.is_empty() && seen.insert(raw.clone()) {
                senders.push(raw.clone());
            }

            let normalized = Self::normalize_sender_id(&raw);
            if !normalized.is_empty() && seen.insert(normalized.clone()) {
                senders.push(normalized);
            }
        }
        senders
    }

    pub fn sender_auto_reply_enabled(&self, sender_id: &str) -> bool {
        if self.allowed_senders.is_empty() {
            return self.auto_reply;
        }
        match self.sender_policy(sender_id) {
            Some(sender) => sender.auto_reply.unwrap_or(self.auto_reply),
            None => false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SkillsConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
    #[serde(default = "default_wasm_dir")]
    pub wasm_dir: PathBuf,
    #[serde(default)]
    pub resource_limits: ResourceLimits,
}

fn default_wasm_dir() -> PathBuf {
    default_home_path(".encmind/skills")
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            enabled: Vec::new(),
            wasm_dir: default_wasm_dir(),
            resource_limits: ResourceLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceLimits {
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u32,
    #[serde(default = "default_max_cpu_time_ms")]
    pub max_cpu_time_ms: u64,
    #[serde(default = "default_max_net_requests")]
    pub max_net_requests: u32,
}

fn default_max_memory_mb() -> u32 {
    64
}
fn default_max_cpu_time_ms() -> u64 {
    30000
}
fn default_max_net_requests() -> u32 {
    10
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: default_max_memory_mb(),
            max_cpu_time_ms: default_max_cpu_time_ms(),
            max_net_requests: default_max_net_requests(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpServerConfig {
    pub name: String,
    pub transport: McpTransport,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpTransport {
    Stdio { command: String, args: Vec<String> },
    Sse { url: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub bash_mode: BashMode,
    #[serde(default)]
    pub local_tools: LocalToolsConfig,
    #[serde(default = "default_true")]
    pub auto_lockdown_on_attestation_failure: bool,
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,
    #[serde(default)]
    pub egress_firewall: EgressFirewallConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub lockdown: LockdownConfig,
    #[serde(default)]
    pub key_rotation: KeyRotationConfig,
    #[serde(default)]
    pub tls_lifecycle: TlsLifecycleConfig,
    pub external_vault: Option<ExternalVaultConfig>,
    /// Per-tool interrupt behavior overrides. Keys are tool names, values are
    /// "cancel" or "block". Overrides the handler's declared behavior.
    #[serde(default)]
    pub per_tool_interrupt_behavior: HashMap<String, String>,
    /// Grace period (seconds) for Block-interrupt tools on cancellation.
    /// After this timeout, a synthetic error result is returned.
    #[serde(default = "default_blocking_tool_cancel_grace_secs")]
    pub blocking_tool_cancel_grace_secs: u64,
    /// Per-tool execution timeout in seconds. If a single tool call
    /// takes longer than this, a synthetic error result is produced
    /// and the tool future is dropped. Independent of the per-session
    /// timeout (which caps the entire run) and the interrupt behavior
    /// (Cancel/Block, which controls what happens on user abort).
    /// Set to 0 to disable (tool runs until session timeout). Default: 30s.
    #[serde(default = "default_per_tool_timeout_secs")]
    pub per_tool_timeout_secs: u64,
    /// Workspace trust settings. Controls which tools are available based on
    /// whether the session's workspace path is in the trusted set.
    #[serde(default)]
    pub workspace_trust: WorkspaceTrustConfig,
}

impl SecurityConfig {
    /// Whether bash execution is effectively enabled for **local** tools
    /// running on the gateway host itself.
    ///
    /// This is the single source of truth for the expression used by the
    /// chat handler, server init, and local tool policy. It is the
    /// conjunction of three gates:
    ///   - `bash_mode != Deny` (master switch — also applies to node)
    ///   - `local_tools.bash_mode != Disabled` (local-only toggle)
    ///   - `local_tools.mode != IsolatedAgents` (per-agent isolation forces local bash off)
    ///
    /// **Scope**: this value should only be used to gate tools that run
    /// on the gateway host. It must not be applied to node/remote bash
    /// tools, whose enablement is governed solely by `bash_mode`.
    pub fn local_bash_effectively_enabled(&self) -> bool {
        !matches!(self.bash_mode, BashMode::Deny)
            && !matches!(self.local_tools.bash_mode, LocalToolsBashMode::Disabled)
            && !matches!(self.local_tools.mode, LocalToolsMode::IsolatedAgents)
    }
}

/// Workspace trust configuration.
///
/// When a session operates in a workspace (directory), the trust gate checks
/// whether that path is in `trusted_paths`. Untrusted workspaces restrict
/// the tool set to built-in read-only tools — no plugin tools, no skills,
/// no MCP tools, no bash.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkspaceTrustConfig {
    /// Paths that are pre-trusted. Workspace paths under any of these are
    /// considered trusted without interactive prompt.
    #[serde(default)]
    pub trusted_paths: Vec<PathBuf>,
    /// Default action for untrusted workspaces.
    /// - "readonly": restrict to built-in read-only tools (default)
    /// - "deny": reject all tool calls
    /// - "allow": no trust restriction (disable the trust gate)
    #[serde(default = "default_untrusted_action")]
    pub untrusted_default: String,
    /// Action when a session has no workspace path set.
    /// - "trusted": treat no-workspace sessions as trusted (default)
    /// - "readonly": restrict to read-only tool allowlist
    /// - "deny": reject all tool calls
    #[serde(default = "default_no_workspace_action")]
    pub no_workspace_default: String,
}

fn default_untrusted_action() -> String {
    "readonly".to_string()
}

fn default_no_workspace_action() -> String {
    "trusted".to_string()
}

impl Default for WorkspaceTrustConfig {
    fn default() -> Self {
        Self {
            trusted_paths: Vec::new(),
            untrusted_default: default_untrusted_action(),
            no_workspace_default: default_no_workspace_action(),
        }
    }
}

fn default_audit_retention_days() -> u32 {
    7
}
fn default_per_tool_timeout_secs() -> u64 {
    30
}
fn default_blocking_tool_cancel_grace_secs() -> u64 {
    10
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            bash_mode: BashMode::default(),
            local_tools: LocalToolsConfig::default(),
            auto_lockdown_on_attestation_failure: true,
            audit_retention_days: default_audit_retention_days(),
            egress_firewall: EgressFirewallConfig::default(),
            rate_limit: RateLimitConfig::default(),
            lockdown: LockdownConfig::default(),
            key_rotation: KeyRotationConfig::default(),
            tls_lifecycle: TlsLifecycleConfig::default(),
            external_vault: None,
            per_tool_interrupt_behavior: HashMap::new(),
            blocking_tool_cancel_grace_secs: default_blocking_tool_cancel_grace_secs(),
            per_tool_timeout_secs: default_per_tool_timeout_secs(),
            workspace_trust: WorkspaceTrustConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BashMode {
    #[default]
    Ask,
    Allowlist {
        patterns: Vec<String>,
    },
    Deny,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalToolsMode {
    #[default]
    SingleOperator,
    IsolatedAgents,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalToolsBashMode {
    #[default]
    Host,
    Disabled,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LocalToolsConfig {
    #[serde(default)]
    pub mode: LocalToolsMode,
    #[serde(default)]
    pub bash_mode: LocalToolsBashMode,
    #[serde(default)]
    pub base_roots: Vec<PathBuf>,
    /// Operator-configured paths that are always denied for local tools,
    /// layered on top of the hardcoded defaults
    /// (`/etc/shadow`, `/etc/sudoers`, `~/.ssh`, `~/.gnupg`, `~/.aws`,
    /// `~/.encmind`, etc.). Defaults stay as a floor — operator entries
    /// can only add to the deny list, not remove from it.
    #[serde(default)]
    pub denied_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentsConfig {
    #[serde(default)]
    pub list: Vec<AgentConfigEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfigEntry {
    pub id: String,
    pub name: String,
    pub model: Option<String>,
    pub workspace: Option<PathBuf>,
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub subagents: SubagentRuntimeConfig,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SubagentRuntimeConfig {
    #[serde(default)]
    pub allow_agents: Vec<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeartbeatConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_heartbeat_interval")]
    pub interval_minutes: u32,
    pub active_hours: Option<ActiveHours>,
    pub model: Option<String>,
    #[serde(default)]
    pub target: HeartbeatTarget,
    #[serde(default = "default_dedup_window")]
    pub dedup_window_hours: u32,
    #[serde(default = "default_workspace_file")]
    pub workspace_file: String,
}

fn default_heartbeat_interval() -> u32 {
    30
}
fn default_dedup_window() -> u32 {
    24
}
fn default_workspace_file() -> String {
    "HEARTBEAT.md".into()
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: default_heartbeat_interval(),
            active_hours: None,
            model: None,
            target: HeartbeatTarget::default(),
            dedup_window_hours: default_dedup_window(),
            workspace_file: default_workspace_file(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveHours {
    pub start: String,
    pub end: String,
    pub timezone: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HeartbeatTarget {
    #[default]
    None,
    LastChannel,
    Channel {
        name: String,
        target: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentPoolConfig {
    #[serde(default = "default_max_concurrent_agents")]
    pub max_concurrent_agents: u32,
    #[serde(default = "default_session_timeout")]
    pub per_session_timeout_secs: u64,
    /// Maximum number of concurrent-safe tools to dispatch in parallel per turn.
    /// Independent of max_concurrent_agents (which limits concurrent sessions).
    #[serde(default = "default_max_parallel_safe_tools")]
    pub max_parallel_safe_tools: usize,
    /// Maximum consecutive interactive runs before the two-class scheduler
    /// forces one background run. 0 = strict priority (background may
    /// starve under continuous interactive load). Default: 4.
    #[serde(default = "default_scheduler_fairness_cap")]
    pub scheduler_fairness_cap: usize,
}

fn default_max_concurrent_agents() -> u32 {
    8
}
fn default_session_timeout() -> u64 {
    300
}
fn default_max_parallel_safe_tools() -> usize {
    4
}
fn default_scheduler_fairness_cap() -> usize {
    4
}

impl Default for AgentPoolConfig {
    fn default() -> Self {
        Self {
            max_concurrent_agents: default_max_concurrent_agents(),
            per_session_timeout_secs: default_session_timeout(),
            max_parallel_safe_tools: default_max_parallel_safe_tools(),
            scheduler_fairness_cap: default_scheduler_fairness_cap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    #[default]
    DenyByDefault,
    AllowPublicInternet,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EgressFirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: FirewallMode,
    #[serde(default)]
    pub global_allowlist: Vec<String>,
    #[serde(default = "default_true")]
    pub block_private_ranges: bool,
    #[serde(default)]
    pub per_agent_overrides: HashMap<String, Vec<String>>,
}

impl Default for EgressFirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: FirewallMode::default(),
            global_allowlist: Vec::new(),
            block_private_ranges: true,
            per_agent_overrides: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_messages_per_minute")]
    pub messages_per_minute: u32,
    #[serde(default = "default_tool_calls_per_run")]
    pub tool_calls_per_run: u32,
    pub api_budget_usd: Option<f64>,
    #[serde(default = "default_true")]
    pub auto_pause_on_spike: bool,
}

fn default_messages_per_minute() -> u32 {
    30
}
fn default_tool_calls_per_run() -> u32 {
    50
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            messages_per_minute: default_messages_per_minute(),
            tool_calls_per_run: default_tool_calls_per_run(),
            api_budget_usd: None,
            auto_pause_on_spike: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LockdownConfig {
    #[serde(default = "default_true")]
    pub persist_across_restarts: bool,
    #[serde(default)]
    pub auto_lockdown_triggers: Vec<String>,
}

impl Default for LockdownConfig {
    fn default() -> Self {
        Self {
            persist_across_restarts: true,
            auto_lockdown_triggers: vec!["attestation_failure".into()],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyRotationConfig {
    #[serde(default = "default_rotation_interval")]
    pub interval_days: u32,
    #[serde(default = "default_true")]
    pub auto_rotate: bool,
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
}

fn default_rotation_interval() -> u32 {
    90
}
fn default_batch_size() -> u32 {
    1000
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            interval_days: default_rotation_interval(),
            auto_rotate: true,
            batch_size: default_batch_size(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsLifecycleConfig {
    #[serde(default)]
    pub acme_enabled: bool,
    pub acme_email: Option<String>,
    pub acme_domain: Option<String>,
    #[serde(default = "default_renewal_days")]
    pub renewal_days_before_expiry: u32,
    #[serde(default = "default_true")]
    pub store_in_db: bool,
}

fn default_renewal_days() -> u32 {
    30
}

impl Default for TlsLifecycleConfig {
    fn default() -> Self {
        Self {
            acme_enabled: false,
            acme_email: None,
            acme_domain: None,
            renewal_days_before_expiry: default_renewal_days(),
            store_in_db: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalVaultConfig {
    pub provider: VaultProvider,
    pub key_id: String,
    #[serde(default = "default_vault_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_vault_cache_ttl() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultProvider {
    AzureKeyVault {
        vault_url: String,
    },
    AwsKms {
        region: String,
    },
    GcpKms {
        project: String,
        location: String,
        keyring: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_backup_schedule")]
    pub schedule: String,
    #[serde(default)]
    pub retention: BackupRetention,
    pub s3: Option<S3BackupConfig>,
    #[serde(default = "default_true")]
    pub encryption: bool,
}

fn default_backup_schedule() -> String {
    "0 * * * *".into()
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: default_backup_schedule(),
            retention: BackupRetention::default(),
            s3: None,
            encryption: true,
        }
    }
}

/// Backup retention policy.
///
/// Retention works by keeping the `daily + weekly` most recent backups and
/// deleting everything older. The two fields are **additive counts**, not
/// calendar-based buckets (i.e., this is *not* GFS rotation). With the
/// defaults (`daily = 7, weekly = 4`), the 11 newest backups are kept.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupRetention {
    /// Number of recent backups to keep (first tier). Default: 7.
    #[serde(default = "default_daily_retention")]
    pub daily: u32,
    /// Additional older backups to keep (second tier). Default: 4.
    #[serde(default = "default_weekly_retention")]
    pub weekly: u32,
}

fn default_daily_retention() -> u32 {
    7
}
fn default_weekly_retention() -> u32 {
    4
}

impl Default for BackupRetention {
    fn default() -> Self {
        Self {
            daily: default_daily_retention(),
            weekly: default_weekly_retention(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3BackupConfig {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: Option<String>,
    pub region: String,
    pub access_key_env: String,
    pub secret_key_env: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrowserConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_browser_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_browser_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub no_sandbox: bool,
    #[serde(default)]
    pub startup_policy: BrowserStartupPolicy,
    /// Allowed browser actions for browser_act. Empty = all allowed.
    /// Valid values: navigate, click, type, press, select, upload, wait, screenshot,
    /// get_text, eval, close
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Domain allowlist for browser_act. Empty = delegate to egress firewall.
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
    /// Whether JavaScript eval is allowed in browser_act. Default: false.
    #[serde(default)]
    pub eval_enabled: bool,
    /// Max actions declared in a single browser_act request.
    /// Setting to 0 disables browser_act. v1 supports exactly one action per call.
    /// Default: 1.
    #[serde(default = "default_max_actions_per_call")]
    pub max_actions_per_call: usize,
    /// Root directory for browser file uploads. Files outside this directory
    /// are rejected. None = upload action disabled entirely.
    #[serde(default)]
    pub upload_root: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStartupPolicy {
    #[default]
    Required,
    BestEffort,
}

fn default_browser_pool_size() -> usize {
    2
}

fn default_browser_idle_timeout() -> u64 {
    600
}

fn default_max_actions_per_call() -> usize {
    1
}

impl BrowserConfig {
    /// Check if a browser action is allowed by policy.
    /// If `allowed_actions` is empty, all actions are allowed.
    pub fn is_action_allowed(&self, action: &str) -> bool {
        if self.allowed_actions.is_empty() {
            return true;
        }
        self.allowed_actions.iter().any(|a| a == action)
    }

    /// Check if a domain is allowed by the browser domain allowlist.
    /// If `domain_allowlist` is empty, returns true (falls through to egress firewall).
    /// Matching is case-insensitive and supports subdomain matching: an allowlist
    /// entry "example.com" matches "example.com" and "sub.example.com".
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if self.domain_allowlist.is_empty() {
            return true;
        }
        let domain_lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.domain_allowlist.iter().any(|d| {
            let allowed = d.trim().trim_end_matches('.').to_ascii_lowercase();
            if allowed.is_empty() {
                return false;
            }
            domain_lower == allowed
                || (domain_lower.ends_with(&format!(".{allowed}"))
                    && domain_lower.len() > allowed.len() + 1)
        })
    }
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_size: default_browser_pool_size(),
            idle_timeout_secs: default_browser_idle_timeout(),
            no_sandbox: false,
            startup_policy: BrowserStartupPolicy::Required,
            allowed_actions: vec![],
            domain_allowlist: vec![],
            eval_enabled: false,
            max_actions_per_call: default_max_actions_per_call(),
            upload_root: None,
        }
    }
}

// ── NetProbe (web search & fetch) ─────────────────────────────────

/// Search provider backend for `netprobe_search`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchProvider {
    #[default]
    Tavily,
    Brave,
    Searxng,
}

/// Configuration for the NetProbe plugin (web search + URL fetch).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetProbeConfig {
    /// Whether NetProbe tools are registered.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Search provider to use.
    #[serde(default)]
    pub provider: SearchProvider,
    /// Name of the environment variable holding the provider API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Base URL for a self-hosted SearXNG instance.
    #[serde(default)]
    pub searxng_url: Option<String>,
    /// Whether to synthesize a concise answer from search results via LLM.
    #[serde(default = "default_true")]
    pub synthesize: bool,
    /// Maximum bytes to fetch per URL (default 512 KiB).
    #[serde(default = "default_max_fetch_bytes")]
    pub max_fetch_bytes: usize,
    /// Maximum provider API response body bytes parsed for search responses/errors (default 1 MiB).
    #[serde(default = "default_max_provider_body_bytes")]
    pub max_provider_body_bytes: usize,
    /// Maximum characters returned in netprobe_fetch `content` output.
    #[serde(default = "default_max_fetch_output_chars")]
    pub max_fetch_output_chars: usize,
    /// Maximum number of redirect hops to follow (default 5).
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
    /// Browser-compatible POST redirect behavior for 301/302.
    /// When true, 301/302 after POST switch to GET (legacy browser style).
    /// When false (default), POST semantics are preserved and only 303 switches to GET.
    #[serde(default)]
    pub post_redirect_compat_301_302_to_get: bool,
}

fn default_max_fetch_bytes() -> usize {
    524_288
}

fn default_max_provider_body_bytes() -> usize {
    1_048_576
}

fn default_max_fetch_output_chars() -> usize {
    20_000
}

fn default_max_redirects() -> usize {
    5
}

const NETPROBE_MAX_REDIRECTS_UPPER_BOUND: usize = 20;
const NETPROBE_MAX_FETCH_BYTES_UPPER_BOUND: usize = 16 * 1024 * 1024; // 16 MiB
const NETPROBE_MAX_PROVIDER_BODY_BYTES_UPPER_BOUND: usize = 8 * 1024 * 1024; // 8 MiB
const NETPROBE_MAX_FETCH_OUTPUT_CHARS_UPPER_BOUND: usize = 200_000;

impl Default for NetProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: SearchProvider::default(),
            api_key_env: None,
            searxng_url: None,
            synthesize: true,
            max_fetch_bytes: default_max_fetch_bytes(),
            max_provider_body_bytes: default_max_provider_body_bytes(),
            max_fetch_output_chars: default_max_fetch_output_chars(),
            max_redirects: default_max_redirects(),
            post_redirect_compat_301_302_to_get: false,
        }
    }
}

impl NetProbeConfig {
    /// Validate the config, returning an error string if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_fetch_bytes == 0 {
            return Err("netprobe: max_fetch_bytes must be > 0".to_string());
        }
        if self.max_fetch_bytes > NETPROBE_MAX_FETCH_BYTES_UPPER_BOUND {
            return Err(format!(
                "netprobe: max_fetch_bytes must be <= {NETPROBE_MAX_FETCH_BYTES_UPPER_BOUND}"
            ));
        }
        if self.max_provider_body_bytes == 0 {
            return Err("netprobe: max_provider_body_bytes must be > 0".to_string());
        }
        if self.max_provider_body_bytes > NETPROBE_MAX_PROVIDER_BODY_BYTES_UPPER_BOUND {
            return Err(format!(
                "netprobe: max_provider_body_bytes must be <= {NETPROBE_MAX_PROVIDER_BODY_BYTES_UPPER_BOUND}"
            ));
        }
        if self.max_fetch_output_chars == 0 {
            return Err("netprobe: max_fetch_output_chars must be > 0".to_string());
        }
        if self.max_fetch_output_chars > NETPROBE_MAX_FETCH_OUTPUT_CHARS_UPPER_BOUND {
            return Err(format!(
                "netprobe: max_fetch_output_chars must be <= {NETPROBE_MAX_FETCH_OUTPUT_CHARS_UPPER_BOUND}"
            ));
        }
        if self.max_redirects == 0 {
            return Err("netprobe: max_redirects must be > 0".to_string());
        }
        if self.max_redirects > NETPROBE_MAX_REDIRECTS_UPPER_BOUND {
            return Err(format!(
                "netprobe: max_redirects must be <= {NETPROBE_MAX_REDIRECTS_UPPER_BOUND}"
            ));
        }

        if self.provider == SearchProvider::Searxng {
            let raw_url = self
                .searxng_url
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    "netprobe: searxng provider requires searxng_url to be set".to_string()
                })?;

            let parsed = url::Url::parse(raw_url)
                .map_err(|e| format!("netprobe: invalid searxng_url '{raw_url}': {e}"))?;
            match parsed.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(format!(
                        "netprobe: searxng_url scheme '{other}' is not supported (use http/https)"
                    ))
                }
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(
                    "netprobe: searxng_url must not include URL userinfo (user:pass@)".to_string(),
                );
            }
            if parsed.host_str().is_none() {
                return Err("netprobe: searxng_url must include a host".to_string());
            }
            if parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(
                    "netprobe: searxng_url must not include query parameters or fragments"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

// ── Digest plugin config ─────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DigestConfig {
    /// Whether Digest tools are registered.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Token threshold for single-pass vs map-reduce summarization.
    #[serde(default = "default_max_single_pass_tokens")]
    pub max_single_pass_tokens: u32,
    /// Maximum chunks in map-reduce summarization.
    #[serde(default = "default_max_map_reduce_chunks")]
    pub max_map_reduce_chunks: u32,
    /// OpenAI Whisper model name.
    #[serde(default = "default_whisper_model")]
    pub whisper_model: String,
    /// Whether local file tools (`digest_file`, `digest_transcribe`) are registered.
    /// Defaults to false for secure-by-default local file access.
    #[serde(default)]
    pub enable_file_tools: bool,
    /// Maximum local file size in bytes accepted by digest_file/digest_transcribe.
    #[serde(default = "default_max_digest_file_bytes")]
    pub max_file_bytes: usize,
    /// Maximum PDF file size in bytes accepted by digest_file.
    #[serde(default = "default_max_pdf_file_bytes")]
    pub max_pdf_file_bytes: usize,
    /// Maximum audio file size in bytes (default 25 MiB).
    #[serde(default = "default_max_audio_bytes")]
    pub max_audio_bytes: usize,
    /// Maximum PDF pages to extract.
    #[serde(default = "default_max_pdf_pages")]
    pub max_pdf_pages: u32,
    /// Maximum extracted text size returned by digest_file.
    #[serde(default = "default_max_extracted_chars")]
    pub max_extracted_chars: usize,
    /// Maximum number of chunk summaries generated concurrently during map-reduce.
    #[serde(default = "default_max_parallel_chunk_summaries")]
    pub max_parallel_chunk_summaries: u32,
    /// Timeout for blocking PDF extraction work.
    #[serde(default = "default_pdf_extract_timeout_secs")]
    pub pdf_extract_timeout_secs: u64,
    /// HTTP timeout (seconds) for Whisper transcription requests.
    #[serde(default = "default_whisper_timeout_secs")]
    pub whisper_timeout_secs: u64,
    /// Timeout (seconds) for digest LLM completion requests.
    #[serde(default = "default_digest_llm_timeout_secs")]
    pub llm_timeout_secs: u64,
    /// Path traversal boundary for file access.
    /// Required when `enable_file_tools=true`.
    #[serde(default)]
    pub file_root: Option<PathBuf>,
    /// Maximum entries returned by digest_list_files.
    #[serde(default = "default_max_list_entries")]
    pub max_list_entries: usize,
    /// Maximum bytes to fetch per URL (reuses NetProbe helper default).
    #[serde(default = "default_max_fetch_bytes")]
    pub max_fetch_bytes: usize,
    /// Maximum redirect hops (reuses NetProbe helper default).
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
}

fn default_max_single_pass_tokens() -> u32 {
    8000
}

fn default_max_map_reduce_chunks() -> u32 {
    16
}

fn default_whisper_model() -> String {
    "whisper-1".to_string()
}

fn default_max_audio_bytes() -> usize {
    26_214_400 // 25 MiB
}

fn default_max_digest_file_bytes() -> usize {
    52_428_800 // 50 MiB
}

fn default_max_pdf_file_bytes() -> usize {
    20_971_520 // 20 MiB
}

fn default_max_pdf_pages() -> u32 {
    200
}

fn default_max_extracted_chars() -> usize {
    400_000
}

fn default_max_parallel_chunk_summaries() -> u32 {
    4
}

fn default_pdf_extract_timeout_secs() -> u64 {
    30
}

fn default_whisper_timeout_secs() -> u64 {
    180
}

fn default_digest_llm_timeout_secs() -> u64 {
    120
}

fn default_max_list_entries() -> usize {
    500
}

const DIGEST_MAX_LIST_ENTRIES_UPPER_BOUND: usize = 10_000;
const DIGEST_MAX_REDIRECTS_UPPER_BOUND: usize = 20;
const DIGEST_MAX_MAP_REDUCE_CHUNKS_UPPER_BOUND: u32 = 128;
const DIGEST_MAX_PARALLEL_CHUNK_SUMMARIES_UPPER_BOUND: u32 = 16;
const DIGEST_MIN_SINGLE_PASS_TOKENS: u32 = 448;
const DIGEST_MAX_PDF_EXTRACT_TIMEOUT_SECS_UPPER_BOUND: u64 = 300;
const DIGEST_MAX_WHISPER_TIMEOUT_SECS_UPPER_BOUND: u64 = 600;
const DIGEST_MAX_LLM_TIMEOUT_SECS_UPPER_BOUND: u64 = 600;
const DIGEST_MAX_FETCH_BYTES_UPPER_BOUND: usize = 16 * 1024 * 1024; // 16 MiB

impl Default for DigestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_single_pass_tokens: default_max_single_pass_tokens(),
            max_map_reduce_chunks: default_max_map_reduce_chunks(),
            whisper_model: default_whisper_model(),
            enable_file_tools: false,
            max_file_bytes: default_max_digest_file_bytes(),
            max_pdf_file_bytes: default_max_pdf_file_bytes(),
            max_audio_bytes: default_max_audio_bytes(),
            max_pdf_pages: default_max_pdf_pages(),
            max_extracted_chars: default_max_extracted_chars(),
            max_parallel_chunk_summaries: default_max_parallel_chunk_summaries(),
            pdf_extract_timeout_secs: default_pdf_extract_timeout_secs(),
            whisper_timeout_secs: default_whisper_timeout_secs(),
            llm_timeout_secs: default_digest_llm_timeout_secs(),
            file_root: None,
            max_list_entries: default_max_list_entries(),
            max_fetch_bytes: default_max_fetch_bytes(),
            max_redirects: default_max_redirects(),
        }
    }
}

impl DigestConfig {
    /// Validate the config, returning an error string if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_single_pass_tokens == 0 {
            return Err("digest: max_single_pass_tokens must be > 0".to_string());
        }
        if self.max_single_pass_tokens < DIGEST_MIN_SINGLE_PASS_TOKENS {
            return Err(format!(
                "digest: max_single_pass_tokens must be >= {DIGEST_MIN_SINGLE_PASS_TOKENS}"
            ));
        }
        if self.max_map_reduce_chunks == 0 {
            return Err("digest: max_map_reduce_chunks must be > 0".to_string());
        }
        if self.max_map_reduce_chunks > DIGEST_MAX_MAP_REDUCE_CHUNKS_UPPER_BOUND {
            return Err(format!(
                "digest: max_map_reduce_chunks must be <= {DIGEST_MAX_MAP_REDUCE_CHUNKS_UPPER_BOUND}"
            ));
        }
        if self.whisper_model.trim().is_empty() {
            return Err("digest: whisper_model must not be empty".to_string());
        }
        if self.max_file_bytes == 0 {
            return Err("digest: max_file_bytes must be > 0".to_string());
        }
        if self.max_audio_bytes == 0 {
            return Err("digest: max_audio_bytes must be > 0".to_string());
        }
        if self.max_audio_bytes > self.max_file_bytes {
            return Err("digest: max_audio_bytes must be <= max_file_bytes".to_string());
        }
        if self.max_pdf_file_bytes == 0 {
            return Err("digest: max_pdf_file_bytes must be > 0".to_string());
        }
        if self.max_pdf_file_bytes > self.max_file_bytes {
            return Err("digest: max_pdf_file_bytes must be <= max_file_bytes".to_string());
        }
        if self.max_pdf_pages == 0 {
            return Err("digest: max_pdf_pages must be > 0".to_string());
        }
        if self.max_extracted_chars == 0 {
            return Err("digest: max_extracted_chars must be > 0".to_string());
        }
        if self.max_parallel_chunk_summaries == 0 {
            return Err("digest: max_parallel_chunk_summaries must be > 0".to_string());
        }
        if self.max_parallel_chunk_summaries > DIGEST_MAX_PARALLEL_CHUNK_SUMMARIES_UPPER_BOUND {
            return Err(format!(
                "digest: max_parallel_chunk_summaries must be <= {DIGEST_MAX_PARALLEL_CHUNK_SUMMARIES_UPPER_BOUND}"
            ));
        }
        if self.pdf_extract_timeout_secs == 0 {
            return Err("digest: pdf_extract_timeout_secs must be > 0".to_string());
        }
        if self.pdf_extract_timeout_secs > DIGEST_MAX_PDF_EXTRACT_TIMEOUT_SECS_UPPER_BOUND {
            return Err(format!(
                "digest: pdf_extract_timeout_secs must be <= {DIGEST_MAX_PDF_EXTRACT_TIMEOUT_SECS_UPPER_BOUND}"
            ));
        }
        if self.whisper_timeout_secs == 0 {
            return Err("digest: whisper_timeout_secs must be > 0".to_string());
        }
        if self.whisper_timeout_secs > DIGEST_MAX_WHISPER_TIMEOUT_SECS_UPPER_BOUND {
            return Err(format!(
                "digest: whisper_timeout_secs must be <= {DIGEST_MAX_WHISPER_TIMEOUT_SECS_UPPER_BOUND}"
            ));
        }
        if self.llm_timeout_secs == 0 {
            return Err("digest: llm_timeout_secs must be > 0".to_string());
        }
        if self.llm_timeout_secs > DIGEST_MAX_LLM_TIMEOUT_SECS_UPPER_BOUND {
            return Err(format!(
                "digest: llm_timeout_secs must be <= {DIGEST_MAX_LLM_TIMEOUT_SECS_UPPER_BOUND}"
            ));
        }
        if self.max_list_entries == 0 {
            return Err("digest: max_list_entries must be > 0".to_string());
        }
        if self.max_list_entries > DIGEST_MAX_LIST_ENTRIES_UPPER_BOUND {
            return Err(format!(
                "digest: max_list_entries must be <= {DIGEST_MAX_LIST_ENTRIES_UPPER_BOUND}"
            ));
        }
        if self.max_fetch_bytes == 0 {
            return Err("digest: max_fetch_bytes must be > 0".to_string());
        }
        if self.max_fetch_bytes > DIGEST_MAX_FETCH_BYTES_UPPER_BOUND {
            return Err(format!(
                "digest: max_fetch_bytes must be <= {DIGEST_MAX_FETCH_BYTES_UPPER_BOUND}"
            ));
        }
        if self.max_redirects == 0 {
            return Err("digest: max_redirects must be > 0".to_string());
        }
        if self.max_redirects > DIGEST_MAX_REDIRECTS_UPPER_BOUND {
            return Err(format!(
                "digest: max_redirects must be <= {DIGEST_MAX_REDIRECTS_UPPER_BOUND}"
            ));
        }
        if self.enable_file_tools && self.file_root.is_none() {
            return Err("digest: file_root must be set when enable_file_tools=true".to_string());
        }
        if self.enable_file_tools {
            let root = self
                .file_root
                .as_ref()
                .expect("file_root checked above when enable_file_tools=true");
            if root.as_os_str().is_empty() {
                return Err("digest: file_root must not be empty when set".to_string());
            }
            let canonical = root.canonicalize().map_err(|e| {
                format!(
                    "digest: file_root '{}' is not accessible: {e}",
                    root.display()
                )
            })?;
            if !canonical.is_dir() {
                return Err(format!(
                    "digest: file_root '{}' must be an existing directory",
                    canonical.display()
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenOptimizationConfig {
    #[serde(default = "default_max_tool_iterations")]
    pub max_tool_iterations: u32,
    #[serde(default = "default_max_tool_output_chars")]
    pub max_tool_output_chars: usize,
    #[serde(default = "default_sliding_window_truncation_threshold")]
    pub sliding_window_truncation_threshold: usize,
    #[serde(default)]
    pub auto_title_enabled: bool,
    #[serde(default)]
    pub screenshot_payload_mode: ScreenshotPayloadMode,
    #[serde(default)]
    pub per_tool_output_chars: HashMap<String, usize>,
    /// Inject behavioral governance constraints into the system prompt.
    /// Default: true.
    #[serde(default = "default_true")]
    pub inject_behavioral_governance: bool,
    /// Inject tool usage grammar into the system prompt.
    /// Default: true.
    #[serde(default = "default_true")]
    pub inject_tool_usage_grammar: bool,
    /// Inject browser safety rules into the system prompt when browser tools
    /// are available. Default: true.
    #[serde(default = "default_true")]
    pub inject_browser_safety_rules: bool,
    /// Inject coordinator-mode guidance into the system prompt when the
    /// `agents_spawn` tool is available. Default: true.
    #[serde(default = "default_true")]
    pub inject_coordinator_mode: bool,
    /// Per-channel cap on output tokens (clamped to the session's
    /// reserved_output_tokens at dispatch time). Channels absent from
    /// this map fall through to the session default. Useful for
    /// bulk/cron channels that should produce shorter responses than
    /// interactive chat.
    ///
    /// Example:
    /// ```yaml
    /// token_optimization:
    ///   per_channel_max_output_tokens:
    ///     cron: 512
    ///     telegram: 2048
    /// ```
    #[serde(default)]
    pub per_channel_max_output_tokens: HashMap<String, u32>,
}

fn default_max_tool_iterations() -> u32 {
    20
}
fn default_max_tool_output_chars() -> usize {
    32_768
}
fn default_sliding_window_truncation_threshold() -> usize {
    4096
}

impl Default for TokenOptimizationConfig {
    fn default() -> Self {
        Self {
            max_tool_iterations: default_max_tool_iterations(),
            max_tool_output_chars: default_max_tool_output_chars(),
            sliding_window_truncation_threshold: default_sliding_window_truncation_threshold(),
            auto_title_enabled: false,
            screenshot_payload_mode: ScreenshotPayloadMode::default(),
            per_tool_output_chars: HashMap::new(),
            inject_behavioral_governance: true,
            inject_tool_usage_grammar: true,
            inject_browser_safety_rules: true,
            inject_coordinator_mode: true,
            per_channel_max_output_tokens: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotPayloadMode {
    #[default]
    Metadata,
    Base64Legacy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkflowConfig {
    #[serde(default = "default_max_concurrent_workflows")]
    pub max_concurrent_workflows: u32,
    #[serde(default = "default_step_timeout")]
    pub default_step_timeout_secs: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_true")]
    pub checkpoint_on_every_step: bool,
}

fn default_max_concurrent_workflows() -> u32 {
    4
}
fn default_step_timeout() -> u64 {
    600
}
fn default_max_retries() -> u32 {
    3
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workflows: default_max_concurrent_workflows(),
            default_step_timeout_secs: default_step_timeout(),
            max_retries: default_max_retries(),
            checkpoint_on_every_step: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetrievalQualityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_citation_score")]
    pub min_citation_score: f32,
    #[serde(default = "default_retrieval_precision")]
    pub min_retrieval_precision: f32,
    pub eval_set_path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub block_model_change_on_regression: bool,
}

fn default_citation_score() -> f32 {
    0.7
}
fn default_retrieval_precision() -> f32 {
    0.6
}

impl Default for RetrievalQualityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_citation_score: default_citation_score(),
            min_retrieval_precision: default_retrieval_precision(),
            eval_set_path: None,
            block_model_change_on_regression: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayConfig {
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,
    #[serde(default = "default_idempotency_ttl_secs")]
    pub idempotency_ttl_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default)]
    pub mdns_enabled: bool,
    /// Maximum total requests per session (1 active + N-1 queued) for the
    /// per-session query guard. Set to 0 for unlimited (not recommended).
    #[serde(default = "default_max_queued_per_session")]
    pub max_queued_per_session: usize,
    /// Default permissions granted to newly paired devices.
    /// Fields not specified default to `false`.
    /// The first paired device is always promoted to admin regardless of this setting.
    #[serde(default = "default_device_permissions")]
    pub default_device_permissions: crate::types::DevicePermissions,
}

fn default_heartbeat_interval_ms() -> u64 {
    30000
}
fn default_idempotency_ttl_secs() -> u64 {
    300
}
fn default_max_connections() -> u32 {
    64
}
fn default_max_queued_per_session() -> usize {
    5
}
fn default_device_permissions() -> crate::types::DevicePermissions {
    crate::types::DevicePermissions {
        chat: true,
        ..Default::default()
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            idempotency_ttl_secs: default_idempotency_ttl_secs(),
            max_connections: default_max_connections(),
            max_queued_per_session: default_max_queued_per_session(),
            mdns_enabled: false,
            default_device_permissions: default_device_permissions(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryConfig {
    pub enabled: bool,
    pub embedding_mode: EmbeddingMode,
    pub local_model_path: Option<PathBuf>,
    pub model_name: String,
    pub embedding_dimensions: usize,
    pub default_search_limit: usize,
    pub max_context_memories: usize,
    pub vector_backend: VectorBackendConfig,
}

fn default_embedding_model() -> String {
    "BAAI/bge-small-en-v1.5".into()
}
fn default_embedding_dimensions() -> usize {
    384
}
fn default_external_embedding_model() -> String {
    "text-embedding-3-small".into()
}
fn default_external_embedding_dimensions() -> usize {
    1536
}
fn default_search_limit() -> usize {
    10
}
fn default_max_context_memories() -> usize {
    5
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            embedding_mode: EmbeddingMode::default(),
            local_model_path: None,
            model_name: default_embedding_model(),
            embedding_dimensions: default_embedding_dimensions(),
            default_search_limit: default_search_limit(),
            max_context_memories: default_max_context_memories(),
            vector_backend: VectorBackendConfig::default(),
        }
    }
}

impl<'de> Deserialize<'de> for MemoryConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawMemoryConfig {
            #[serde(default)]
            enabled: bool,
            #[serde(default)]
            embedding_mode: EmbeddingMode,
            local_model_path: Option<PathBuf>,
            model_name: Option<String>,
            embedding_dimensions: Option<usize>,
            default_search_limit: Option<usize>,
            max_context_memories: Option<usize>,
            #[serde(default)]
            vector_backend: VectorBackendConfig,
        }

        let raw = RawMemoryConfig::deserialize(deserializer)?;

        let (default_model, default_dims) = match raw.embedding_mode {
            EmbeddingMode::Private => (default_embedding_model(), default_embedding_dimensions()),
            EmbeddingMode::External { .. } => (
                default_external_embedding_model(),
                default_external_embedding_dimensions(),
            ),
        };

        Ok(Self {
            enabled: raw.enabled,
            embedding_mode: raw.embedding_mode,
            local_model_path: raw.local_model_path,
            model_name: raw.model_name.unwrap_or(default_model),
            embedding_dimensions: raw.embedding_dimensions.unwrap_or(default_dims),
            default_search_limit: raw
                .default_search_limit
                .unwrap_or_else(default_search_limit),
            max_context_memories: raw
                .max_context_memories
                .unwrap_or_else(default_max_context_memories),
            vector_backend: raw.vector_backend,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmbeddingMode {
    #[default]
    Private,
    External {
        provider: String,
        api_base_url: String,
    },
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VectorBackendConfig {
    #[default]
    Sqlite,
    Qdrant {
        url: String,
        collection: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CronConfig {
    #[serde(default = "default_cron_check_interval")]
    pub check_interval_secs: u64,
}

fn default_cron_check_interval() -> u64 {
    60
}

impl Default for CronConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_cron_check_interval(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

fn default_home_path(relative: &str) -> PathBuf {
    home_dir()
        .map(|home| home.join(relative))
        .unwrap_or_else(|| PathBuf::from(format!("~/{relative}")))
}

/// Default directory for auto-generated TLS certificates.
pub fn default_tls_dir() -> PathBuf {
    default_home_path(".encmind/tls")
}

fn expand_tilde_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();

    if path_str == "~" {
        return home_dir().unwrap_or_else(|| path.to_path_buf());
    }

    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(stripped);
        }
    }

    path.to_path_buf()
}

fn expand_path_fields(config: &mut AppConfig) {
    config.storage.db_path = expand_tilde_path(&config.storage.db_path);
    config.skills.wasm_dir = expand_tilde_path(&config.skills.wasm_dir);
    config.security.local_tools.base_roots = config
        .security
        .local_tools
        .base_roots
        .iter()
        .map(|path| expand_tilde_path(path))
        .collect();
    config.security.local_tools.denied_paths = config
        .security
        .local_tools
        .denied_paths
        .iter()
        .map(|path| expand_tilde_path(path))
        .collect();
    config.security.workspace_trust.trusted_paths = config
        .security
        .workspace_trust
        .trusted_paths
        .iter()
        .map(|path| expand_tilde_path(path))
        .collect();

    if let Some(path) = config.storage.backup_dir.take() {
        config.storage.backup_dir = Some(expand_tilde_path(&path));
    }
    if let Some(path) = config.server.tls_cert_path.take() {
        config.server.tls_cert_path = Some(expand_tilde_path(&path));
    }
    if let Some(path) = config.server.tls_key_path.take() {
        config.server.tls_key_path = Some(expand_tilde_path(&path));
    }
    if let Some(path) = config.retrieval_quality.eval_set_path.take() {
        config.retrieval_quality.eval_set_path = Some(expand_tilde_path(&path));
    }
    if let Some(path) = config.memory.local_model_path.take() {
        config.memory.local_model_path = Some(expand_tilde_path(&path));
    }
    if let Some(local) = config.llm.local.as_mut() {
        local.model_path = expand_tilde_path(&local.model_path);
    }
    for agent in &mut config.agents.list {
        if let Some(path) = agent.workspace.take() {
            agent.workspace = Some(expand_tilde_path(&path));
        }
    }
}

fn has_config_path(value: &serde_yml::Value, path: &[&str]) -> bool {
    let mut current = value;
    for segment in path {
        let serde_yml::Value::Mapping(map) = current else {
            return false;
        };
        let key = serde_yml::Value::String((*segment).to_string());
        let Some(next) = map.get(&key) else {
            return false;
        };
        current = next;
    }
    true
}

fn apply_profile_defaults(config: &mut AppConfig, raw: &serde_yml::Value) {
    let host_explicit = has_config_path(raw, &["server", "host"]);
    let port_explicit = has_config_path(raw, &["server", "port"]);
    let auto_tls_explicit = has_config_path(raw, &["server", "auto_tls"]);
    let acme_enabled_explicit =
        has_config_path(raw, &["security", "tls_lifecycle", "acme_enabled"]);

    match config.server.profile {
        ServerProfile::Local => {
            if !host_explicit {
                config.server.host = "127.0.0.1".to_string();
            }
            if !port_explicit {
                config.server.port = 8443;
            }
            if !auto_tls_explicit {
                config.server.auto_tls = false;
            }
            if !acme_enabled_explicit {
                config.security.tls_lifecycle.acme_enabled = false;
            }
        }
        ServerProfile::Remote => {
            if !host_explicit {
                config.server.host = "0.0.0.0".to_string();
            }
            if !port_explicit {
                config.server.port = 8443;
            }
            if !auto_tls_explicit {
                config.server.auto_tls = true;
            }
            if !acme_enabled_explicit {
                config.security.tls_lifecycle.acme_enabled = false;
            }
        }
        ServerProfile::Domain => {
            if !host_explicit {
                config.server.host = "0.0.0.0".to_string();
            }
            if !port_explicit {
                config.server.port = 443;
            }
            if !auto_tls_explicit {
                config.server.auto_tls = false;
            }
            if !acme_enabled_explicit {
                config.security.tls_lifecycle.acme_enabled = true;
            }
        }
    }
}

fn validate_profile_constraints(config: &AppConfig) -> Result<(), StorageError> {
    let manual_tls = config.server.tls_cert_path.is_some() && config.server.tls_key_path.is_some();
    let partial_manual_tls =
        config.server.tls_cert_path.is_some() != config.server.tls_key_path.is_some();

    if partial_manual_tls {
        return Err(StorageError::InvalidData(
            "both server.tls_cert_path and server.tls_key_path must be set together".to_string(),
        ));
    }

    if config.server.profile == ServerProfile::Domain && !manual_tls {
        if !config.security.tls_lifecycle.acme_enabled {
            return Err(StorageError::InvalidData(
                "domain profile requires ACME enabled or manual TLS cert/key paths".to_string(),
            ));
        }

        let domain = config
            .security
            .tls_lifecycle
            .acme_domain
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if domain.is_empty() {
            return Err(StorageError::InvalidData(
                "domain profile requires security.tls_lifecycle.acme_domain when manual cert paths are not configured".to_string(),
            ));
        }

        let email = config
            .security
            .tls_lifecycle
            .acme_email
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if email.is_empty() {
            return Err(StorageError::InvalidData(
                "domain profile requires security.tls_lifecycle.acme_email when manual cert paths are not configured".to_string(),
            ));
        }
    }

    Ok(())
}

fn find_plugin_policy_deny_override_conflicts(config: &AppConfig) -> Vec<(String, String)> {
    let denied_caps: Vec<&str> = config
        .plugin_policy
        .deny_capabilities
        .iter()
        .map(|cap| cap.trim())
        .filter(|cap| !cap.is_empty())
        .collect();

    if denied_caps.is_empty() {
        return Vec::new();
    }

    let mut conflicts = Vec::new();
    for (skill, override_cfg) in &config.plugin_policy.skill_overrides {
        for cap in &override_cfg.allow_capabilities {
            let cap = cap.trim();
            if cap.is_empty() {
                continue;
            }
            if denied_caps
                .iter()
                .any(|rule| deny_rule_matches_capability(rule, cap))
            {
                conflicts.push((skill.clone(), cap.to_string()));
            }
        }
    }

    conflicts.sort_unstable();
    conflicts.dedup();
    conflicts
}

/// Expand environment variables in a string: `${VAR_NAME}` -> env value.
fn expand_env_vars(s: &str) -> String {
    let mut result = s.to_owned();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = std::env::var(var_name).unwrap_or_default();
            result = format!(
                "{}{}{}",
                &result[..start],
                value,
                &result[start + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

/// Load configuration from a YAML file, expanding environment variables.
pub fn load_config(path: &Path) -> Result<AppConfig, StorageError> {
    let content = std::fs::read_to_string(path).map_err(StorageError::Io)?;
    let expanded = expand_env_vars(&content);
    let raw: serde_yml::Value =
        serde_yml::from_str(&expanded).map_err(|e| StorageError::InvalidData(e.to_string()))?;
    let mut config: AppConfig =
        serde_yml::from_value(raw.clone()).map_err(|e| StorageError::InvalidData(e.to_string()))?;
    apply_profile_defaults(&mut config, &raw);
    validate_profile_constraints(&config)?;
    expand_path_fields(&mut config);
    for (skill, capability) in find_plugin_policy_deny_override_conflicts(&config) {
        tracing::warn!(
            skill = %skill,
            capability = %capability,
            "plugin_policy conflict: allow_capabilities entry is ignored because capability is globally denied"
        );
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_correct_values() {
        let config = AppConfig::default();
        assert_eq!(config.server.profile, ServerProfile::Local);
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(!config.server.auto_tls);
        assert_eq!(config.server.port, 8443);
        assert!(!config.server.public_webhooks.enabled);
        assert!(config.server.public_webhooks.require_tls);
        assert_eq!(config.security.audit_retention_days, 7);
        assert_eq!(
            config.security.local_tools.mode,
            LocalToolsMode::SingleOperator
        );
        assert_eq!(
            config.security.local_tools.bash_mode,
            LocalToolsBashMode::Host
        );
        assert_eq!(config.agent_pool.max_concurrent_agents, 8);
        assert_eq!(config.security.rate_limit.messages_per_minute, 30);
        assert!(config.security.egress_firewall.enabled);
        assert!(config.security.lockdown.persist_across_restarts);
        assert_eq!(config.security.key_rotation.interval_days, 90);
        assert!(!config.backup.enabled);
        // Gateway defaults
        assert_eq!(config.gateway.heartbeat_interval_ms, 30000);
        assert_eq!(config.gateway.idempotency_ttl_secs, 300);
        assert_eq!(config.gateway.max_connections, 64);
        assert!(!config.gateway.mdns_enabled);
        assert!(!config.browser.no_sandbox);
        assert_eq!(
            config.browser.startup_policy,
            BrowserStartupPolicy::Required
        );
    }

    #[test]
    fn parse_minimal_yaml() {
        let yaml = "server:\n  port: 9000\n";
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.server.port, 9000);
        // host should use default
        assert_eq!(config.server.host, "127.0.0.1");
    }

    #[test]
    fn parse_empty_yaml_uses_defaults() {
        let yaml = "{}";
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8443);
    }

    #[test]
    fn browser_startup_policy_serde() {
        let yaml = "enabled: true\nstartup_policy: best_effort\n";
        let browser: BrowserConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(browser.startup_policy, BrowserStartupPolicy::BestEffort);
    }

    #[test]
    fn expand_env_vars_works() {
        std::env::set_var("TEST_VAR_EXPAND", "hello");
        let result = expand_env_vars("prefix-${TEST_VAR_EXPAND}-suffix");
        assert_eq!(result, "prefix-hello-suffix");
        std::env::remove_var("TEST_VAR_EXPAND");
    }

    #[test]
    fn expand_env_vars_missing_var() {
        let result = expand_env_vars("${NONEXISTENT_VAR_12345}");
        assert_eq!(result, "");
    }

    #[test]
    fn key_source_passphrase_serde() {
        let yaml = "type: Passphrase\npassphrase_env: MY_PASS\n";
        let ks: KeySource = serde_yml::from_str(yaml).unwrap();
        match ks {
            KeySource::Passphrase { passphrase_env } => {
                assert_eq!(passphrase_env, "MY_PASS");
            }
            _ => panic!("Expected Passphrase variant"),
        }
    }

    #[test]
    fn key_source_env_var_serde() {
        let yaml = "type: EnvVar\nvar_name: MY_KEY\n";
        let ks: KeySource = serde_yml::from_str(yaml).unwrap();
        match ks {
            KeySource::EnvVar { var_name } => assert_eq!(var_name, "MY_KEY"),
            _ => panic!("Expected EnvVar variant"),
        }
    }

    #[test]
    fn load_config_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  host: "0.0.0.0"
  port: 9443
storage:
  db_path: "/data/encmind.db"
  key_source:
    type: EnvVar
    var_name: MASTER_KEY
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 9443);
        assert_eq!(config.storage.db_path, PathBuf::from("/data/encmind.db"));
    }

    #[test]
    fn load_config_profile_remote_applies_defaults_when_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: remote
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.server.profile, ServerProfile::Remote);
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8443);
        assert!(config.server.auto_tls);
        assert!(!config.security.tls_lifecycle.acme_enabled);
    }

    #[test]
    fn load_config_profile_domain_applies_defaults_and_requires_acme_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: domain
security:
  tls_lifecycle:
    acme_domain: assistant.example.com
    acme_email: me@example.com
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.server.profile, ServerProfile::Domain);
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
        assert!(!config.server.auto_tls);
        assert!(config.security.tls_lifecycle.acme_enabled);
    }

    #[test]
    fn load_config_domain_without_acme_domain_fails_when_manual_tls_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: domain
security:
  tls_lifecycle:
    acme_email: me@example.com
"#,
        )
        .unwrap();

        let err = load_config(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("acme_domain when manual cert paths are not configured"));
    }

    #[test]
    fn load_config_domain_without_acme_email_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: domain
security:
  tls_lifecycle:
    acme_domain: example.com
"#,
        )
        .unwrap();

        let err = load_config(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("acme_email when manual cert paths are not configured"));
    }

    #[test]
    fn load_config_domain_with_manual_tls_skips_acme_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: domain
  tls_cert_path: /tmp/cert.pem
  tls_key_path: /tmp/key.pem
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.server.profile, ServerProfile::Domain);
        assert_eq!(config.server.port, 443);
    }

    #[test]
    fn load_config_explicit_host_overrides_profile_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: remote
  host: 127.0.0.1
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.server.profile, ServerProfile::Remote);
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.server.auto_tls);
    }

    #[test]
    fn load_config_explicit_auto_tls_overrides_profile_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
server:
  profile: remote
  auto_tls: false
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.server.profile, ServerProfile::Remote);
        assert!(!config.server.auto_tls);
    }

    #[test]
    fn load_config_expands_tilde_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
storage:
  db_path: "~/.encmind/test.db"
skills:
  wasm_dir: "~/.encmind/skills"
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert!(!config.storage.db_path.to_string_lossy().starts_with("~/"));
        assert!(!config.skills.wasm_dir.to_string_lossy().starts_with("~/"));

        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            assert_eq!(config.storage.db_path, home.join(".encmind/test.db"));
            assert_eq!(config.skills.wasm_dir, home.join(".encmind/skills"));
        }
    }

    #[test]
    fn load_config_external_memory_applies_external_defaults_when_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
memory:
  enabled: true
  embedding_mode:
    type: external
    provider: openai
    api_base_url: https://api.openai.com
"#,
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert!(matches!(
            config.memory.embedding_mode,
            EmbeddingMode::External { .. }
        ));
        assert_eq!(config.memory.model_name, "text-embedding-3-small");
        assert_eq!(config.memory.embedding_dimensions, 1536);
    }

    #[test]
    fn serde_app_config_external_memory_uses_mode_aware_defaults() {
        let yaml = r#"
memory:
  enabled: true
  embedding_mode:
    type: external
    provider: openai
    api_base_url: https://api.openai.com
"#;
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert!(matches!(
            config.memory.embedding_mode,
            EmbeddingMode::External { .. }
        ));
        assert_eq!(config.memory.model_name, "text-embedding-3-small");
        assert_eq!(config.memory.embedding_dimensions, 1536);
    }

    #[test]
    fn inference_mode_serde() {
        let yaml = "type: ApiProvider\nprovider: anthropic\n";
        let mode: InferenceMode = serde_yml::from_str(yaml).unwrap();
        match mode {
            InferenceMode::ApiProvider { provider } => assert_eq!(provider, "anthropic"),
            _ => panic!("Expected ApiProvider"),
        }
    }

    #[test]
    fn gateway_config_yaml_parse() {
        let yaml = r#"
gateway:
  heartbeat_interval_ms: 15000
  idempotency_ttl_secs: 600
  max_connections: 128
  mdns_enabled: true
"#;
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.gateway.heartbeat_interval_ms, 15000);
        assert_eq!(config.gateway.idempotency_ttl_secs, 600);
        assert_eq!(config.gateway.max_connections, 128);
        assert!(config.gateway.mdns_enabled);
    }

    #[test]
    fn embedding_mode_serde() {
        let yaml = "type: external\nprovider: openai\napi_base_url: https://api.openai.com\n";
        let mode: EmbeddingMode = serde_yml::from_str(yaml).unwrap();
        match mode {
            EmbeddingMode::External {
                provider,
                api_base_url,
            } => {
                assert_eq!(provider, "openai");
                assert_eq!(api_base_url, "https://api.openai.com");
            }
            _ => panic!("expected External"),
        }
    }

    #[test]
    fn vector_backend_config_serde() {
        let yaml = "type: qdrant\nurl: http://localhost:6334\ncollection: memories\n";
        let cfg: VectorBackendConfig = serde_yml::from_str(yaml).unwrap();
        match cfg {
            VectorBackendConfig::Qdrant { url, collection } => {
                assert_eq!(url, "http://localhost:6334");
                assert_eq!(collection, "memories");
            }
            _ => panic!("expected Qdrant"),
        }
    }

    #[test]
    fn memory_config_defaults() {
        let config = MemoryConfig::default();
        assert!(!config.enabled);
        assert!(matches!(config.embedding_mode, EmbeddingMode::Private));
        assert_eq!(config.embedding_dimensions, 384);
        assert_eq!(config.default_search_limit, 10);
        assert_eq!(config.max_context_memories, 5);
        assert!(matches!(config.vector_backend, VectorBackendConfig::Sqlite));
    }

    #[test]
    fn app_config_includes_memory() {
        let config = AppConfig::default();
        assert!(!config.memory.enabled);
        assert_eq!(config.memory.model_name, "BAAI/bge-small-en-v1.5");
    }

    #[test]
    fn memory_enabled_defaults_false_when_omitted() {
        let yaml = r#"
memory:
  model_name: custom-embed
"#;
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert!(!config.memory.enabled);
        assert_eq!(config.memory.model_name, "custom-embed");
    }

    #[test]
    fn validate_rejects_missing_private_local_model_path() {
        let mut config = AppConfig::default();
        config.memory.enabled = true;
        config.memory.embedding_mode = EmbeddingMode::Private;
        let temp = tempfile::tempdir().unwrap();
        config.memory.local_model_path = Some(temp.path().join("missing-model"));

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("memory.local_model_path does not exist")),
            "errors={errors:?}"
        );
    }

    #[test]
    fn validate_rejects_local_model_path_in_external_mode() {
        let mut config = AppConfig::default();
        config.memory.enabled = true;
        config.memory.embedding_mode = EmbeddingMode::External {
            provider: "openai".to_string(),
            api_base_url: "https://api.openai.com".to_string(),
        };
        config.memory.local_model_path = Some(PathBuf::from("/tmp/local-model"));

        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains(
                "memory.local_model_path is only valid when memory.embedding_mode.type=private"
            )),
            "errors={errors:?}"
        );
    }

    #[test]
    fn access_action_default_is_reject() {
        let action = AccessAction::default();
        assert_eq!(action, AccessAction::Reject);
    }

    #[test]
    fn inbound_access_policy_default() {
        let policy = InboundAccessPolicy::default();
        assert_eq!(policy.default_action, AccessAction::Reject);
        assert!(policy.allowlist.is_empty());
        assert!(!policy.notify_rejected);
    }

    #[test]
    fn inbound_access_policy_serde_roundtrip() {
        let policy = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![AllowlistEntry {
                channel: "telegram".into(),
                sender_id: "12345".into(),
                label: Some("Alice".into()),
            }],
            notify_rejected: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: InboundAccessPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.default_action, AccessAction::Reject);
        assert_eq!(back.allowlist.len(), 1);
        assert_eq!(back.allowlist[0].sender_id, "12345");
        assert!(back.notify_rejected);
    }

    #[test]
    fn cron_config_defaults() {
        let config = CronConfig::default();
        assert_eq!(config.check_interval_secs, 60);
    }

    #[test]
    fn auto_tls_defaults_false_for_local_profile() {
        let yaml = "server:\n  port: 9000\n";
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert!(!config.server.auto_tls);
    }

    #[test]
    fn auto_tls_can_be_disabled() {
        let yaml = "server:\n  auto_tls: false\n";
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert!(!config.server.auto_tls);
    }

    #[test]
    fn channels_config_with_slack_parses_correctly() {
        let yaml = r#"
channels:
  slack:
    bot_token_env: "SLACK_BOT_TOKEN"
    app_token_env: "SLACK_APP_TOKEN"
  access_policy:
    default_action: allow
"#;
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert!(
            config.channels.slack.is_some(),
            "slack config should be Some"
        );
        let slack = config.channels.slack.unwrap();
        assert_eq!(slack.bot_token_env, "SLACK_BOT_TOKEN");
        assert_eq!(slack.app_token_env, "SLACK_APP_TOKEN");
    }

    #[test]
    fn mcp_transport_stdio_serde() {
        let yaml = "type: stdio\ncommand: npx\nargs: [\"-y\", \"@mcp/server\"]\n";
        let transport: McpTransport = serde_yml::from_str(yaml).unwrap();
        match transport {
            McpTransport::Stdio { command, args } => {
                assert_eq!(command, "npx");
                assert_eq!(args, vec!["-y", "@mcp/server"]);
            }
            _ => panic!("Expected Stdio"),
        }
    }

    #[test]
    fn token_optimization_defaults() {
        let config = TokenOptimizationConfig::default();
        assert_eq!(config.max_tool_iterations, 20);
        assert_eq!(config.max_tool_output_chars, 32_768);
        assert_eq!(config.sliding_window_truncation_threshold, 4096);
        assert!(!config.auto_title_enabled);
        assert!(config.inject_behavioral_governance);
        assert!(config.inject_tool_usage_grammar);
        assert!(config.inject_browser_safety_rules);
        assert!(config.inject_coordinator_mode);
        assert_eq!(
            config.screenshot_payload_mode,
            ScreenshotPayloadMode::Metadata
        );
        assert!(config.per_tool_output_chars.is_empty());
        // Also verify AppConfig default includes it
        let app = AppConfig::default();
        assert_eq!(app.token_optimization.max_tool_iterations, 20);
    }

    #[test]
    fn token_optimization_yaml_parse() {
        let yaml = r#"
token_optimization:
  max_tool_iterations: 10
  max_tool_output_chars: 4096
  sliding_window_truncation_threshold: 2048
  auto_title_enabled: true
  inject_behavioral_governance: false
  inject_tool_usage_grammar: false
  inject_browser_safety_rules: false
  inject_coordinator_mode: false
  screenshot_payload_mode: base64_legacy
  per_tool_output_chars:
    bash_exec: 1024
    file_read: 2048
"#;
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.token_optimization.max_tool_iterations, 10);
        assert_eq!(config.token_optimization.max_tool_output_chars, 4096);
        assert_eq!(
            config
                .token_optimization
                .sliding_window_truncation_threshold,
            2048
        );
        assert!(config.token_optimization.auto_title_enabled);
        assert!(!config.token_optimization.inject_behavioral_governance);
        assert!(!config.token_optimization.inject_tool_usage_grammar);
        assert!(!config.token_optimization.inject_browser_safety_rules);
        assert!(!config.token_optimization.inject_coordinator_mode);
        assert_eq!(
            config.token_optimization.screenshot_payload_mode,
            ScreenshotPayloadMode::Base64Legacy
        );
        assert_eq!(
            config
                .token_optimization
                .per_tool_output_chars
                .get("bash_exec"),
            Some(&1024)
        );
        assert_eq!(
            config
                .token_optimization
                .per_tool_output_chars
                .get("file_read"),
            Some(&2048)
        );
    }

    #[test]
    fn screenshot_payload_mode_serde() {
        let metadata: ScreenshotPayloadMode = serde_yml::from_str("\"metadata\"").unwrap();
        assert_eq!(metadata, ScreenshotPayloadMode::Metadata);
        let legacy: ScreenshotPayloadMode = serde_yml::from_str("\"base64_legacy\"").unwrap();
        assert_eq!(legacy, ScreenshotPayloadMode::Base64Legacy);
        // Roundtrip
        let json = serde_json::to_string(&ScreenshotPayloadMode::Metadata).unwrap();
        assert_eq!(json, "\"metadata\"");
        let json = serde_json::to_string(&ScreenshotPayloadMode::Base64Legacy).unwrap();
        assert_eq!(json, "\"base64_legacy\"");
    }

    #[test]
    fn plugin_policy_config_default_values() {
        let config = PluginPolicyConfig::default();
        assert_eq!(config.allow_risk_levels.len(), 2);
        assert!(config
            .allow_risk_levels
            .contains(&crate::policy::CapabilityRiskLevel::Low));
        assert!(config
            .allow_risk_levels
            .contains(&crate::policy::CapabilityRiskLevel::Sensitive));
        assert!(config.deny_capabilities.is_empty());
        assert!(config.deny_skills.is_empty());
        assert!(config.skill_overrides.is_empty());
    }

    #[test]
    fn plugin_policy_config_yaml_parse() {
        let yaml = r#"
plugin_policy:
  allow_risk_levels: [low]
  deny_capabilities: [exec_shell]
  deny_skills: [evil]
"#;
        let config: AppConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.plugin_policy.allow_risk_levels.len(), 1);
        assert_eq!(config.plugin_policy.deny_capabilities, vec!["exec_shell"]);
        assert_eq!(config.plugin_policy.deny_skills, vec!["evil"]);
    }

    #[test]
    fn app_config_with_plugin_policy_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.plugin_policy.allow_risk_levels.len(), 2);
        assert!(config.plugin_policy.deny_capabilities.is_empty());
    }

    #[test]
    fn plugin_policy_conflict_detection_finds_denied_capability_overrides() {
        let mut config = AppConfig::default();
        config.plugin_policy.deny_capabilities = vec!["exec_shell".into(), "fs_read".into()];
        config.plugin_policy.skill_overrides.insert(
            "trusted-skill".into(),
            crate::policy::SkillOverride {
                allow_capabilities: vec![
                    "exec_shell".into(),
                    "net_outbound:api.example.com".into(),
                ],
                deny_capabilities: vec![],
            },
        );
        config.plugin_policy.skill_overrides.insert(
            "reader-skill".into(),
            crate::policy::SkillOverride {
                allow_capabilities: vec!["fs_read".into()],
                deny_capabilities: vec![],
            },
        );

        let conflicts = find_plugin_policy_deny_override_conflicts(&config);
        assert_eq!(
            conflicts,
            vec![
                ("reader-skill".to_string(), "fs_read".to_string()),
                ("trusted-skill".to_string(), "exec_shell".to_string())
            ]
        );
    }

    #[test]
    fn plugin_policy_conflict_detection_ignores_non_conflicting_overrides() {
        let mut config = AppConfig::default();
        config.plugin_policy.deny_capabilities = vec!["exec_shell".into()];
        config.plugin_policy.skill_overrides.insert(
            "safe-skill".into(),
            crate::policy::SkillOverride {
                allow_capabilities: vec!["fs_read".into()],
                deny_capabilities: vec![],
            },
        );

        let conflicts = find_plugin_policy_deny_override_conflicts(&config);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn plugin_policy_conflict_detection_flags_scoped_allow_under_parent_deny() {
        let mut config = AppConfig::default();
        config.plugin_policy.deny_capabilities = vec!["net_outbound".into()];
        config.plugin_policy.skill_overrides.insert(
            "my-skill".into(),
            crate::policy::SkillOverride {
                allow_capabilities: vec!["net_outbound:api.example.com".into()],
                deny_capabilities: vec![],
            },
        );

        let conflicts = find_plugin_policy_deny_override_conflicts(&config);
        assert_eq!(
            conflicts,
            vec![(
                "my-skill".to_string(),
                "net_outbound:api.example.com".to_string()
            )]
        );
    }

    #[test]
    fn firewall_mode_default_is_deny_by_default() {
        assert_eq!(FirewallMode::default(), FirewallMode::DenyByDefault);
    }

    #[test]
    fn firewall_mode_serde_deny_by_default() {
        let yaml = "\"deny_by_default\"";
        let mode: FirewallMode = serde_yml::from_str(yaml).unwrap();
        assert_eq!(mode, FirewallMode::DenyByDefault);
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"deny_by_default\"");
    }

    #[test]
    fn firewall_mode_serde_allow_public_internet() {
        let yaml = "\"allow_public_internet\"";
        let mode: FirewallMode = serde_yml::from_str(yaml).unwrap();
        assert_eq!(mode, FirewallMode::AllowPublicInternet);
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"allow_public_internet\"");
    }

    #[test]
    fn egress_firewall_config_omitted_mode_defaults_to_deny() {
        let yaml = "enabled: true\nglobal_allowlist: []\n";
        let config: EgressFirewallConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.mode, FirewallMode::DenyByDefault);
    }

    #[test]
    fn egress_firewall_config_explicit_mode_roundtrip() {
        let config = EgressFirewallConfig {
            enabled: true,
            mode: FirewallMode::AllowPublicInternet,
            global_allowlist: vec!["example.com".into()],
            block_private_ranges: true,
            per_agent_overrides: HashMap::new(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: EgressFirewallConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, FirewallMode::AllowPublicInternet);
        assert_eq!(back.global_allowlist, vec!["example.com"]);
    }

    #[test]
    fn skill_error_policy_defaults() {
        let policy = SkillErrorPolicy::default();
        assert!(policy.transform_inbound_fail_open);
        assert!(policy.transform_outbound_fail_open);
        assert_eq!(policy.timer_max_consecutive_failures, 5);
        assert!(policy.timer_auto_disable);
    }

    #[test]
    fn skill_error_policy_custom_values() {
        let json = r#"{"transform_inbound_fail_open":false,"timer_max_consecutive_failures":10,"timer_auto_disable":false}"#;
        let policy: SkillErrorPolicy = serde_json::from_str(json).unwrap();
        assert!(!policy.transform_inbound_fail_open);
        assert!(policy.transform_outbound_fail_open); // default
        assert_eq!(policy.timer_max_consecutive_failures, 10);
        assert!(!policy.timer_auto_disable);
    }

    #[test]
    fn app_config_includes_skill_error_policy() {
        let config = AppConfig::default();
        assert!(config.skill_error_policy.transform_inbound_fail_open);
        assert_eq!(config.skill_error_policy.timer_max_consecutive_failures, 5);
    }

    // ── AppConfig::validate() tests ──────────────────────────────────────

    /// Helper: build a minimal valid config (one api provider, sane defaults).
    fn valid_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.llm.api_providers = vec![ApiProviderConfig {
            name: "openai".to_string(),
            model: "gpt-4o".to_string(),
            base_url: None,
        }];
        config
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = valid_config();
        assert!(
            config.validate().is_empty(),
            "expected no errors, got: {:?}",
            config.validate()
        );
    }

    #[test]
    fn validate_accepts_ephemeral_port() {
        let mut config = valid_config();
        config.server.port = 0; // ephemeral port is valid for OS binding
        let errors = config.validate();
        assert!(
            !errors.iter().any(|e| e.contains("server.port")),
            "port 0 (ephemeral) should be accepted, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_empty_db_path() {
        let mut config = valid_config();
        config.storage.db_path = PathBuf::from("");
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("storage.db_path")),
            "expected storage.db_path error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_no_llm() {
        let mut config = AppConfig::default();
        // default has no local and no api_providers
        config.llm.local = None;
        config.llm.api_providers = vec![];
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("LLM provider")),
            "expected LLM provider error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_duplicate_providers() {
        let mut config = valid_config();
        config.llm.api_providers = vec![
            ApiProviderConfig {
                name: "openai".to_string(),
                model: "gpt-4o".to_string(),
                base_url: None,
            },
            ApiProviderConfig {
                name: "openai".to_string(),
                model: "gpt-3.5-turbo".to_string(),
                base_url: None,
            },
        ];
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("duplicate provider name")),
            "expected duplicate provider name error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_zero_per_channel_max_output_tokens() {
        let mut config = valid_config();
        config
            .token_optimization
            .per_channel_max_output_tokens
            .insert("cron".to_string(), 0);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| {
                e.contains("token_optimization.per_channel_max_output_tokens['cron'] must be > 0")
            }),
            "expected per-channel max_output_tokens > 0 validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_empty_per_channel_max_output_tokens_key() {
        let mut config = valid_config();
        config
            .token_optimization
            .per_channel_max_output_tokens
            .insert("".to_string(), 512);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("channel key must not be empty")),
            "expected empty channel key validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_zero_rate_limit() {
        // messages_per_minute == 0
        let mut config = valid_config();
        config.security.rate_limit.messages_per_minute = 0;
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("messages_per_minute")),
            "expected messages_per_minute error, got: {:?}",
            errors
        );

        // tool_calls_per_run == 0
        let mut config2 = valid_config();
        config2.security.rate_limit.tool_calls_per_run = 0;
        let errors2 = config2.validate();
        assert!(
            errors2.iter().any(|e| e.contains("tool_calls_per_run")),
            "expected tool_calls_per_run error, got: {:?}",
            errors2
        );
    }

    #[test]
    fn validate_rejects_invalid_parallel_tool_and_interrupt_config() {
        let mut config = valid_config();
        config.agent_pool.max_parallel_safe_tools = 0;
        config.security.blocking_tool_cancel_grace_secs = 0;
        config
            .security
            .per_tool_interrupt_behavior
            .insert("netprobe_fetch".to_string(), "pause".to_string());
        config
            .security
            .per_tool_interrupt_behavior
            .insert("   ".to_string(), "cancel".to_string());

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("agent_pool.max_parallel_safe_tools")),
            "expected max_parallel_safe_tools error, got: {:?}",
            errors
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("blocking_tool_cancel_grace_secs")),
            "expected blocking_tool_cancel_grace_secs error, got: {:?}",
            errors
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("must be 'cancel' or 'block'")),
            "expected per_tool_interrupt_behavior value error, got: {:?}",
            errors
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("tool name must not be empty")),
            "expected per_tool_interrupt_behavior key error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_duplicate_interrupt_behavior_keys_after_normalization() {
        let mut config = valid_config();
        config
            .security
            .per_tool_interrupt_behavior
            .insert("netprobe_fetch".to_string(), "cancel".to_string());
        config
            .security
            .per_tool_interrupt_behavior
            .insert(" NetProbe_Fetch ".to_string(), "block".to_string());

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate keys after normalization")),
            "expected duplicate normalized key error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_isolated_local_tools_requires_workspace_for_all_agents() {
        let mut config = valid_config();
        config.security.local_tools.mode = LocalToolsMode::IsolatedAgents;
        config.security.local_tools.bash_mode = LocalToolsBashMode::Disabled;
        config.agents.list = vec![
            AgentConfigEntry {
                id: "a".into(),
                name: "A".into(),
                model: None,
                workspace: Some(PathBuf::from("/tmp/a")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
            AgentConfigEntry {
                id: "b".into(),
                name: "B".into(),
                model: None,
                workspace: None,
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("requires workspace")));
    }

    #[test]
    fn validate_isolated_local_tools_rejects_host_bash() {
        let mut config = valid_config();
        config.security.local_tools.mode = LocalToolsMode::IsolatedAgents;
        config.security.local_tools.bash_mode = LocalToolsBashMode::Host;
        config.agents.list = vec![AgentConfigEntry {
            id: "a".into(),
            name: "A".into(),
            model: None,
            workspace: Some(PathBuf::from("/tmp/a")),
            system_prompt: None,
            skills: Vec::new(),
            subagents: SubagentRuntimeConfig::default(),
            is_default: false,
        }];
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("bash_mode=host")));
    }

    #[test]
    fn validate_rejects_browser_batch_actions_gt_one() {
        let mut config = valid_config();
        config.browser.max_actions_per_call = 2;
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("browser.max_actions_per_call > 1")),
            "expected browser batch-action validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_enabled_public_webhooks_without_auth_env() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.auth_token_env = None;
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("server.public_webhooks.auth_token_env must be set when") }),
            "expected public webhook auth env validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_accepts_enabled_public_webhooks_with_non_empty_auth_env() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.require_tls = false;
        config.server.public_webhooks.auth_token_env =
            Some("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN".to_string());
        std::env::set_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN", "test-token");
        let errors = config.validate();
        std::env::remove_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN");
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("server.public_webhooks auth token env var")),
            "expected no public webhook auth env runtime error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_enabled_public_webhooks_require_tls_without_tls_listener() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.auth_token_env =
            Some("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_TLS".to_string());
        config.server.public_webhooks.require_tls = true;
        config.server.auto_tls = false;
        config.server.tls_cert_path = None;
        config.server.tls_key_path = None;

        std::env::set_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_TLS", "test-token");
        let errors = config.validate();
        std::env::remove_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_TLS");

        assert!(
            errors
                .iter()
                .any(|e| e.contains("server.public_webhooks.require_tls=true")),
            "expected webhook tls validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_public_webhooks_bind_host_mismatch() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.auth_token_env =
            Some("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_BIND".to_string());
        config.server.public_webhooks.require_tls = false;
        config.server.host = "127.0.0.1".to_string();
        config.server.public_webhooks.bind_host = Some("0.0.0.0".to_string());

        std::env::set_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_BIND", "test-token");
        let errors = config.validate();
        std::env::remove_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_BIND");

        assert!(
            errors
                .iter()
                .any(|e| e.contains("server.public_webhooks.bind_host")),
            "expected webhook bind_host validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_accepts_public_webhooks_bind_host_matching_server_host() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.auth_token_env =
            Some("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_BIND_OK".to_string());
        config.server.public_webhooks.require_tls = false;
        config.server.host = "127.0.0.1".to_string();
        config.server.public_webhooks.bind_host = Some("127.0.0.1".to_string());

        std::env::set_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_BIND_OK", "test-token");
        let errors = config.validate();
        std::env::remove_var("ENCMIND_TEST_WEBHOOK_AUTH_TOKEN_BIND_OK");

        assert!(
            !errors
                .iter()
                .any(|e| e.contains("server.public_webhooks.bind_host")),
            "expected bind_host validation to pass, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_google_oidc_webhooks_without_audience() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.require_tls = false;
        config.server.public_webhooks.auth_mode = PublicWebhookAuthMode::GoogleOidc;
        config.server.public_webhooks.google_oidc_audience = None;
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("server.public_webhooks.google_oidc_audience must be set")),
            "expected google_oidc audience validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_accepts_google_oidc_webhooks_with_audience() {
        let mut config = valid_config();
        config.server.public_webhooks.enabled = true;
        config.server.public_webhooks.require_tls = false;
        config.server.public_webhooks.auth_mode = PublicWebhookAuthMode::GoogleOidc;
        config.server.public_webhooks.google_oidc_audience =
            Some("https://example.push.endpoint/webhooks/gmail".to_string());
        let errors = config.validate();
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("server.public_webhooks.google_oidc_audience")),
            "expected no google_oidc audience validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_partial_gmail_env_config() {
        let mut config = valid_config();
        config.channels.gmail = Some(GmailConfig {
            client_id_env: "GMAIL_CLIENT_ID".to_string(),
            client_secret_env: String::new(),
            refresh_token_env: "GMAIL_REFRESH_TOKEN".to_string(),
            ..Default::default()
        });

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("channels.gmail env credential config is partial")),
            "expected partial gmail env validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_invalid_gmail_runtime_limits() {
        let mut config = valid_config();
        config.channels.gmail = Some(GmailConfig {
            poll_interval_secs: 0,
            max_attachments_per_message: 0,
            max_file_bytes: 0,
            label_filter: "   ".to_string(),
            ..Default::default()
        });

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("channels.gmail.poll_interval_secs must be > 0")),
            "expected gmail poll interval validation error, got: {:?}",
            errors
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("channels.gmail.max_attachments_per_message must be > 0")),
            "expected gmail max_attachments_per_message validation error, got: {:?}",
            errors
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("channels.gmail.max_file_bytes must be > 0")),
            "expected gmail max_file_bytes validation error, got: {:?}",
            errors
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("channels.gmail.label_filter must not be empty")),
            "expected gmail label_filter validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_invalid_gmail_allowed_senders() {
        let mut config = valid_config();
        config.channels.gmail = Some(GmailConfig {
            allowed_senders: vec![
                GmailAllowedSender {
                    sender_id: "  ".to_string(),
                    auto_reply: Some(true),
                },
                GmailAllowedSender {
                    sender_id: "Alice@Example.com".to_string(),
                    auto_reply: None,
                },
                GmailAllowedSender {
                    sender_id: "alice@example.com".to_string(),
                    auto_reply: Some(false),
                },
                GmailAllowedSender {
                    sender_id: "not-an-email".to_string(),
                    auto_reply: Some(false),
                },
            ],
            ..Default::default()
        });

        let errors = config.validate();
        assert!(
            errors.iter().any(
                |e| e.contains("channels.gmail.allowed_senders[0].sender_id must not be empty")
            ),
            "expected empty sender validation error, got: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains(
                "channels.gmail.allowed_senders contains duplicate sender_id: alice@example.com"
            )),
            "expected duplicate sender validation error, got: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e
                .contains("channels.gmail.allowed_senders[3].sender_id must be an email address")),
            "expected sender email format validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_mismatched_gmail_sender_sources() {
        let mut config = valid_config();
        config.channels.gmail = Some(GmailConfig {
            allowed_senders: vec![GmailAllowedSender {
                sender_id: "owner@example.com".to_string(),
                auto_reply: Some(true),
            }],
            ..Default::default()
        });
        config.channels.access_policy.allowlist = vec![AllowlistEntry {
            channel: "gmail".to_string(),
            sender_id: "other@example.com".to_string(),
            label: None,
        }];

        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains(
                "channels.access_policy.allowlist for channel=gmail must match channels.gmail.allowed_senders when both are configured"
            )),
            "expected mismatched gmail sender source validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_invalid_netprobe_plugin_config() {
        let mut config = valid_config();
        config.plugins.insert(
            "netprobe".to_string(),
            serde_json::json!({
                "provider": "searxng"
            }),
        );

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("searxng provider requires searxng_url")),
            "expected netprobe searxng validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_unparseable_netprobe_plugin_config() {
        let mut config = valid_config();
        config.plugins.insert(
            "netprobe".to_string(),
            serde_json::json!({
                "provider": true
            }),
        );

        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("plugins.netprobe config is invalid")),
            "expected netprobe parse validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn gmail_config_auto_reply_defaults_to_false() {
        let cfg = GmailConfig::default();
        assert!(!cfg.auto_reply);
    }

    #[test]
    fn gmail_config_sender_auto_reply_uses_per_sender_overrides() {
        let mut cfg = GmailConfig {
            auto_reply: true,
            allowed_senders: vec![
                GmailAllowedSender {
                    sender_id: "owner@example.com".to_string(),
                    auto_reply: None,
                },
                GmailAllowedSender {
                    sender_id: "vip@example.com".to_string(),
                    auto_reply: Some(false),
                },
            ],
            ..Default::default()
        };
        assert!(cfg.sender_auto_reply_enabled("OWNER@EXAMPLE.COM"));
        assert!(!cfg.sender_auto_reply_enabled("vip@example.com"));
        assert!(!cfg.sender_auto_reply_enabled("other@example.com"));

        cfg.allowed_senders.clear();
        assert!(cfg.sender_auto_reply_enabled("anyone@example.com"));
    }

    #[test]
    fn gmail_config_normalize_sender_id_canonicalizes_gmail_aliases() {
        assert_eq!(
            GmailConfig::normalize_sender_id("User.Name+tag@googlemail.com"),
            "username@gmail.com"
        );
        assert_eq!(
            GmailConfig::normalize_sender_id("User.Name+tag@gmail.com"),
            "username@gmail.com"
        );
        assert_eq!(
            GmailConfig::normalize_sender_id("admin@example.com"),
            "admin@example.com"
        );
    }

    #[test]
    fn gmail_config_is_valid_sender_id_rejects_non_email_values() {
        assert!(GmailConfig::is_valid_sender_id("owner@example.com"));
        assert!(!GmailConfig::is_valid_sender_id("owner"));
        assert!(!GmailConfig::is_valid_sender_id("owner@"));
        assert!(!GmailConfig::is_valid_sender_id("@example.com"));
        assert!(!GmailConfig::is_valid_sender_id("owner@@example.com"));
    }

    #[test]
    fn gmail_query_allowed_sender_ids_preserves_raw_and_includes_normalized_fallback() {
        let cfg = GmailConfig {
            allowed_senders: vec![GmailAllowedSender {
                sender_id: "User.Name+tag@googlemail.com".to_string(),
                auto_reply: Some(true),
            }],
            ..Default::default()
        };
        let ids = cfg.query_allowed_sender_ids();
        assert!(ids.contains(&"user.name+tag@googlemail.com".to_string()));
        assert!(ids.contains(&"username@gmail.com".to_string()));
    }

    #[test]
    fn channels_config_serde_with_command_gates() {
        let yaml = r#"
access_policy:
  default_action: allow
command_gates:
  telegram:
    - /start
    - /help
  slack:
    - /status
"#;
        let config: ChannelsConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.command_gates.len(), 2);
        assert_eq!(
            config.command_gates.get("telegram").unwrap(),
            &vec!["/start".to_string(), "/help".to_string()]
        );
        assert_eq!(
            config.command_gates.get("slack").unwrap(),
            &vec!["/status".to_string()]
        );
    }

    #[test]
    fn channels_config_serde_default_command_gates() {
        let yaml = r#"
access_policy:
  default_action: reject
"#;
        let config: ChannelsConfig = serde_yml::from_str(yaml).unwrap();
        assert!(config.command_gates.is_empty());
    }

    #[test]
    fn browser_config_is_action_allowed_empty_permits_all() {
        let config = BrowserConfig::default();
        assert!(config.is_action_allowed("click"));
        assert!(config.is_action_allowed("type"));
        assert!(config.is_action_allowed("anything"));
    }

    #[test]
    fn browser_config_is_action_allowed_restricted() {
        let config = BrowserConfig {
            allowed_actions: vec!["click".into(), "type".into()],
            ..Default::default()
        };
        assert!(config.is_action_allowed("click"));
        assert!(config.is_action_allowed("type"));
        assert!(!config.is_action_allowed("select"));
        assert!(!config.is_action_allowed("press"));
    }

    #[test]
    fn browser_config_is_domain_allowed_empty_permits_all() {
        let config = BrowserConfig::default();
        assert!(config.is_domain_allowed("example.com"));
        assert!(config.is_domain_allowed("evil.com"));
    }

    #[test]
    fn browser_config_is_domain_allowed_restricted() {
        let config = BrowserConfig {
            domain_allowlist: vec!["example.com".into(), "trusted.org".into()],
            ..Default::default()
        };
        assert!(config.is_domain_allowed("example.com"));
        assert!(config.is_domain_allowed("Example.COM")); // case-insensitive
        assert!(config.is_domain_allowed("trusted.org"));
        assert!(config.is_domain_allowed("sub.example.com")); // subdomain match
        assert!(config.is_domain_allowed("deep.sub.trusted.org"));
        assert!(!config.is_domain_allowed("evil.com"));
        assert!(!config.is_domain_allowed("notexample.com")); // not a subdomain
    }

    #[test]
    fn browser_config_is_domain_allowed_trims_allowlist_entries() {
        let config = BrowserConfig {
            domain_allowlist: vec!["  example.com.  ".into()],
            ..Default::default()
        };
        assert!(config.is_domain_allowed("example.com"));
        assert!(config.is_domain_allowed("sub.example.com"));
        assert!(!config.is_domain_allowed("evil.com"));
    }

    #[test]
    fn browser_config_new_fields_serde_roundtrip() {
        let config = BrowserConfig {
            enabled: true,
            pool_size: 4,
            idle_timeout_secs: 300,
            no_sandbox: true,
            startup_policy: BrowserStartupPolicy::BestEffort,
            allowed_actions: vec!["click".into(), "type".into()],
            domain_allowlist: vec!["example.com".into()],
            eval_enabled: true,
            max_actions_per_call: 1,
            upload_root: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: BrowserConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.allowed_actions, vec!["click", "type"]);
        assert_eq!(back.domain_allowlist, vec!["example.com"]);
        assert!(back.eval_enabled);
        assert_eq!(back.max_actions_per_call, 1);
    }

    #[test]
    fn netprobe_config_defaults() {
        let config = NetProbeConfig::default();
        assert!(config.enabled);
        assert_eq!(config.provider, SearchProvider::Tavily);
        assert!(config.synthesize);
        assert_eq!(config.max_fetch_bytes, 524_288);
        assert_eq!(config.max_provider_body_bytes, 1_048_576);
        assert_eq!(config.max_fetch_output_chars, 20_000);
        assert_eq!(config.max_redirects, 5);
        assert!(!config.post_redirect_compat_301_302_to_get);
        assert!(config.api_key_env.is_none());
        assert!(config.searxng_url.is_none());
    }

    #[test]
    fn netprobe_config_searxng_requires_url() {
        let config = NetProbeConfig {
            provider: SearchProvider::Searxng,
            searxng_url: None,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config_ok = NetProbeConfig {
            provider: SearchProvider::Searxng,
            searxng_url: Some("http://localhost:8888".into()),
            ..Default::default()
        };
        assert!(config_ok.validate().is_ok());
    }

    #[test]
    fn netprobe_config_disabled_skips_provider_specific_validation() {
        let disabled = NetProbeConfig {
            enabled: false,
            provider: SearchProvider::Searxng,
            searxng_url: None,
            ..Default::default()
        };
        assert!(disabled.validate().is_ok());
    }

    #[test]
    fn netprobe_config_rejects_invalid_numeric_limits() {
        let zero_fetch = NetProbeConfig {
            max_fetch_bytes: 0,
            ..Default::default()
        };
        assert!(zero_fetch.validate().is_err());

        let too_large_fetch = NetProbeConfig {
            max_fetch_bytes: NETPROBE_MAX_FETCH_BYTES_UPPER_BOUND + 1,
            ..Default::default()
        };
        assert!(too_large_fetch.validate().is_err());

        let zero_provider_body = NetProbeConfig {
            max_provider_body_bytes: 0,
            ..Default::default()
        };
        assert!(zero_provider_body.validate().is_err());

        let too_large_provider_body = NetProbeConfig {
            max_provider_body_bytes: NETPROBE_MAX_PROVIDER_BODY_BYTES_UPPER_BOUND + 1,
            ..Default::default()
        };
        assert!(too_large_provider_body.validate().is_err());

        let zero_fetch_output_chars = NetProbeConfig {
            max_fetch_output_chars: 0,
            ..Default::default()
        };
        assert!(zero_fetch_output_chars.validate().is_err());

        let too_large_fetch_output_chars = NetProbeConfig {
            max_fetch_output_chars: NETPROBE_MAX_FETCH_OUTPUT_CHARS_UPPER_BOUND + 1,
            ..Default::default()
        };
        assert!(too_large_fetch_output_chars.validate().is_err());

        let zero_redirects = NetProbeConfig {
            max_redirects: 0,
            ..Default::default()
        };
        assert!(zero_redirects.validate().is_err());

        let too_many_redirects = NetProbeConfig {
            max_redirects: NETPROBE_MAX_REDIRECTS_UPPER_BOUND + 1,
            ..Default::default()
        };
        assert!(too_many_redirects.validate().is_err());
    }

    #[test]
    fn netprobe_config_searxng_url_must_be_http_or_https() {
        let invalid_scheme = NetProbeConfig {
            provider: SearchProvider::Searxng,
            searxng_url: Some("ftp://localhost:8888".into()),
            ..Default::default()
        };
        assert!(invalid_scheme.validate().is_err());

        let invalid_url = NetProbeConfig {
            provider: SearchProvider::Searxng,
            searxng_url: Some("not a url".into()),
            ..Default::default()
        };
        assert!(invalid_url.validate().is_err());
    }

    #[test]
    fn netprobe_config_serde_roundtrip() {
        let config = NetProbeConfig {
            enabled: false,
            provider: SearchProvider::Brave,
            api_key_env: Some("BRAVE_API_KEY".into()),
            searxng_url: None,
            synthesize: false,
            max_fetch_bytes: 1_048_576,
            max_provider_body_bytes: 2_097_152,
            max_fetch_output_chars: 12_000,
            max_redirects: 3,
            post_redirect_compat_301_302_to_get: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: NetProbeConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.enabled);
        assert_eq!(back.provider, SearchProvider::Brave);
        assert!(!back.synthesize);
        assert_eq!(back.max_fetch_bytes, 1_048_576);
        assert_eq!(back.max_provider_body_bytes, 2_097_152);
        assert_eq!(back.max_fetch_output_chars, 12_000);
        assert_eq!(back.max_redirects, 3);
        assert!(back.post_redirect_compat_301_302_to_get);
    }

    #[test]
    fn search_provider_serde_roundtrip() {
        let providers = vec![
            SearchProvider::Tavily,
            SearchProvider::Brave,
            SearchProvider::Searxng,
        ];
        for p in providers {
            let json = serde_json::to_string(&p).unwrap();
            let back: SearchProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn telegram_and_slack_attachment_limits_default_values() {
        let tg = TelegramConfig::default();
        assert_eq!(tg.max_file_bytes, 20 * 1024 * 1024);
        assert_eq!(tg.max_attachments_per_message, 5);
        assert_eq!(tg.max_total_attachment_bytes, 25 * 1024 * 1024);
        assert_eq!(tg.download_timeout_secs, 4);

        let slack = SlackConfig::default();
        assert_eq!(slack.max_file_bytes, 20 * 1024 * 1024);
        assert_eq!(slack.max_attachments_per_message, 5);
        assert_eq!(slack.max_total_attachment_bytes, 25 * 1024 * 1024);
        assert_eq!(slack.download_timeout_secs, 4);
    }

    // ── DigestConfig tests ────────────────────────────────────────────

    #[test]
    fn digest_config_defaults() {
        let config = DigestConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_single_pass_tokens, 8000);
        assert_eq!(config.max_map_reduce_chunks, 16);
        assert_eq!(config.whisper_model, "whisper-1");
        assert!(!config.enable_file_tools);
        assert_eq!(config.max_file_bytes, 52_428_800);
        assert_eq!(config.max_pdf_file_bytes, 20_971_520);
        assert_eq!(config.max_audio_bytes, 26_214_400);
        assert_eq!(config.max_pdf_pages, 200);
        assert_eq!(config.max_extracted_chars, 400_000);
        assert_eq!(config.max_parallel_chunk_summaries, 4);
        assert_eq!(config.pdf_extract_timeout_secs, 30);
        assert_eq!(config.whisper_timeout_secs, 180);
        assert_eq!(config.llm_timeout_secs, 120);
        assert!(config.file_root.is_none());
        assert_eq!(config.max_list_entries, 500);
        assert_eq!(config.max_fetch_bytes, 524_288);
        assert_eq!(config.max_redirects, 5);
    }

    #[test]
    fn digest_config_disabled_skips_validation() {
        let config = DigestConfig {
            enabled: false,
            max_single_pass_tokens: 0, // would fail if enabled
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn digest_config_zero_tokens_fails() {
        let config = DigestConfig {
            max_single_pass_tokens: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_single_pass_tokens"), "err = {err}");
    }

    #[test]
    fn digest_config_too_small_single_pass_tokens_fails() {
        let config = DigestConfig {
            max_single_pass_tokens: DIGEST_MIN_SINGLE_PASS_TOKENS - 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_single_pass_tokens"), "err = {err}");
    }

    #[test]
    fn digest_config_zero_chunks_fails() {
        let config = DigestConfig {
            max_map_reduce_chunks: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_map_reduce_chunks"), "err = {err}");
    }

    #[test]
    fn digest_config_too_many_chunks_fails() {
        let config = DigestConfig {
            max_map_reduce_chunks: DIGEST_MAX_MAP_REDUCE_CHUNKS_UPPER_BOUND + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_map_reduce_chunks"), "err = {err}");
    }

    #[test]
    fn digest_config_zero_max_list_entries_fails() {
        let config = DigestConfig {
            max_list_entries: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_list_entries"), "err = {err}");
    }

    #[test]
    fn digest_config_too_large_max_list_entries_fails() {
        let config = DigestConfig {
            max_list_entries: DIGEST_MAX_LIST_ENTRIES_UPPER_BOUND + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_list_entries"), "err = {err}");
    }

    #[test]
    fn digest_config_zero_pdf_file_bytes_fails() {
        let config = DigestConfig {
            max_pdf_file_bytes: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_pdf_file_bytes"), "err = {err}");
    }

    #[test]
    fn digest_config_pdf_file_bytes_cannot_exceed_global_file_bytes() {
        let config = DigestConfig {
            max_file_bytes: 1_000_000,
            max_audio_bytes: 1_000_000,
            max_pdf_file_bytes: 1_000_001,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("max_pdf_file_bytes must be <= max_file_bytes"),
            "err = {err}"
        );
    }

    #[test]
    fn digest_config_audio_bytes_cannot_exceed_global_file_bytes() {
        let config = DigestConfig {
            max_file_bytes: 1_000_000,
            max_audio_bytes: 1_000_001,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("max_audio_bytes must be <= max_file_bytes"),
            "err = {err}"
        );
    }

    #[test]
    fn digest_config_empty_whisper_model_fails() {
        let config = DigestConfig {
            whisper_model: "   ".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("whisper_model"), "err = {err}");
    }

    #[test]
    fn digest_config_zero_pdf_extract_timeout_fails() {
        let config = DigestConfig {
            pdf_extract_timeout_secs: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("pdf_extract_timeout_secs"), "err = {err}");
    }

    #[test]
    fn digest_config_zero_llm_timeout_fails() {
        let config = DigestConfig {
            llm_timeout_secs: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("llm_timeout_secs"), "err = {err}");
    }

    #[test]
    fn digest_config_too_large_llm_timeout_fails() {
        let config = DigestConfig {
            llm_timeout_secs: DIGEST_MAX_LLM_TIMEOUT_SECS_UPPER_BOUND + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("llm_timeout_secs"), "err = {err}");
    }

    #[test]
    fn digest_config_too_large_fetch_bytes_fails() {
        let config = DigestConfig {
            max_fetch_bytes: DIGEST_MAX_FETCH_BYTES_UPPER_BOUND + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_fetch_bytes"), "err = {err}");
    }

    #[test]
    fn digest_config_enable_file_tools_requires_file_root() {
        let config = DigestConfig {
            enable_file_tools: true,
            file_root: None,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("file_root"), "err = {err}");
    }

    #[test]
    fn digest_config_enable_file_tools_requires_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing-digest-file-root");
        let config = DigestConfig {
            enable_file_tools: true,
            file_root: Some(missing),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("not accessible"), "err = {err}");
    }

    #[test]
    fn digest_config_enable_file_tools_rejects_file_root_that_is_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not_a_dir.txt");
        std::fs::write(&file, "x").unwrap();
        let config = DigestConfig {
            enable_file_tools: true,
            file_root: Some(file),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("existing directory"), "err = {err}");
    }

    #[test]
    fn digest_config_serde_roundtrip() {
        let config = DigestConfig {
            enabled: false,
            max_single_pass_tokens: 4000,
            max_map_reduce_chunks: 8,
            whisper_model: "whisper-2".to_string(),
            enable_file_tools: true,
            max_file_bytes: 20_000_000,
            max_pdf_file_bytes: 8_000_000,
            max_audio_bytes: 10_000_000,
            max_pdf_pages: 50,
            max_extracted_chars: 123_456,
            max_parallel_chunk_summaries: 3,
            pdf_extract_timeout_secs: 45,
            whisper_timeout_secs: 240,
            llm_timeout_secs: 90,
            file_root: Some(PathBuf::from("/data/files")),
            max_list_entries: 250,
            max_fetch_bytes: 1_048_576,
            max_redirects: 3,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: DigestConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.enabled);
        assert_eq!(back.max_single_pass_tokens, 4000);
        assert_eq!(back.max_map_reduce_chunks, 8);
        assert_eq!(back.whisper_model, "whisper-2");
        assert!(back.enable_file_tools);
        assert_eq!(back.max_file_bytes, 20_000_000);
        assert_eq!(back.max_pdf_file_bytes, 8_000_000);
        assert_eq!(back.max_audio_bytes, 10_000_000);
        assert_eq!(back.max_pdf_pages, 50);
        assert_eq!(back.max_extracted_chars, 123_456);
        assert_eq!(back.max_parallel_chunk_summaries, 3);
        assert_eq!(back.pdf_extract_timeout_secs, 45);
        assert_eq!(back.whisper_timeout_secs, 240);
        assert_eq!(back.llm_timeout_secs, 90);
        assert_eq!(back.file_root, Some(PathBuf::from("/data/files")));
        assert_eq!(back.max_list_entries, 250);
        assert_eq!(back.max_fetch_bytes, 1_048_576);
        assert_eq!(back.max_redirects, 3);
    }

    #[test]
    fn validate_rejects_invalid_digest_plugin_config() {
        let mut config = valid_config();
        config.plugins.insert(
            "digest".to_string(),
            serde_json::json!({
                "max_single_pass_tokens": 0
            }),
        );
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("max_single_pass_tokens")),
            "expected digest validation error, got: {:?}",
            errors
        );
    }

    #[test]
    fn validate_rejects_unparseable_digest_plugin_config() {
        let mut config = valid_config();
        config.plugins.insert(
            "digest".to_string(),
            serde_json::json!({
                "enabled": "not_a_bool"
            }),
        );
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("plugins.digest config is invalid")),
            "expected digest parse error, got: {:?}",
            errors
        );
    }

    #[test]
    fn expand_path_fields_expands_workspace_trust_trusted_paths_tilde() {
        let Some(home) = home_dir() else {
            return;
        };

        let mut config = AppConfig::default();
        config.security.workspace_trust.trusted_paths = vec![PathBuf::from("~/trusted-workspace")];

        expand_path_fields(&mut config);

        assert_eq!(
            config.security.workspace_trust.trusted_paths,
            vec![home.join("trusted-workspace")]
        );
    }

    #[test]
    fn expand_path_fields_expands_local_tools_paths_tilde() {
        let Some(home) = home_dir() else {
            return;
        };

        let mut config = AppConfig::default();
        config.security.local_tools.base_roots = vec![PathBuf::from("~/workspace-root")];
        config.security.local_tools.denied_paths = vec![PathBuf::from("~/.secret-dir")];

        expand_path_fields(&mut config);

        assert_eq!(
            config.security.local_tools.base_roots,
            vec![home.join("workspace-root")]
        );
        assert_eq!(
            config.security.local_tools.denied_paths,
            vec![home.join(".secret-dir")]
        );
    }

    #[test]
    fn validate_rejects_invalid_workspace_trust_no_workspace_default() {
        let mut config = AppConfig::default();
        config.security.workspace_trust.no_workspace_default = "invalid".to_string();
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains(
                "security.workspace_trust.no_workspace_default must be 'trusted', 'readonly', or 'deny'"
            )),
            "expected validation error, got: {:?}",
            errors
        );
    }
}
