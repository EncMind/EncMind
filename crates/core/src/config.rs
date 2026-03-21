use serde::{Deserialize, Serialize};
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
}

fn default_audit_retention_days() -> u32 {
    7
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
}

fn default_max_concurrent_agents() -> u32 {
    8
}
fn default_session_timeout() -> u64 {
    300
}

impl Default for AgentPoolConfig {
    fn default() -> Self {
        Self {
            max_concurrent_agents: default_max_concurrent_agents(),
            per_session_timeout_secs: default_session_timeout(),
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
    /// Maximum number of redirect hops to follow (default 5).
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
}

fn default_max_fetch_bytes() -> usize {
    524_288
}

fn default_max_redirects() -> usize {
    5
}

const NETPROBE_MAX_REDIRECTS_UPPER_BOUND: usize = 20;

impl Default for NetProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: SearchProvider::default(),
            api_key_env: None,
            searxng_url: None,
            synthesize: true,
            max_fetch_bytes: default_max_fetch_bytes(),
            max_redirects: default_max_redirects(),
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
            mdns_enabled: false,
            default_device_permissions: default_device_permissions(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub embedding_mode: EmbeddingMode,
    pub local_model_path: Option<PathBuf>,
    #[serde(default = "default_embedding_model")]
    pub model_name: String,
    #[serde(default = "default_embedding_dimensions")]
    pub embedding_dimensions: usize,
    #[serde(default = "default_search_limit")]
    pub default_search_limit: usize,
    #[serde(default = "default_max_context_memories")]
    pub max_context_memories: usize,
    #[serde(default)]
    pub vector_backend: VectorBackendConfig,
}

fn default_embedding_model() -> String {
    "text-embedding-3-small".into()
}
fn default_embedding_dimensions() -> usize {
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
        assert_eq!(config.embedding_dimensions, 1536);
        assert_eq!(config.default_search_limit, 10);
        assert_eq!(config.max_context_memories, 5);
        assert!(matches!(config.vector_backend, VectorBackendConfig::Sqlite));
    }

    #[test]
    fn app_config_includes_memory() {
        let config = AppConfig::default();
        assert!(!config.memory.enabled);
        assert_eq!(config.memory.model_name, "text-embedding-3-small");
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
        assert_eq!(config.max_redirects, 5);
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
            max_redirects: 3,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: NetProbeConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.enabled);
        assert_eq!(back.provider, SearchProvider::Brave);
        assert!(!back.synthesize);
        assert_eq!(back.max_fetch_bytes, 1_048_576);
        assert_eq!(back.max_redirects, 3);
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
}
