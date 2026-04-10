use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use chrono::{DateTime, Utc};

use crate::error::*;
use crate::types::*;

#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Stream a completion. Returns a stream of deltas.
    async fn complete(
        &self,
        messages: &[Message],
        params: CompletionParams,
        cancel: CancellationToken,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>;

    /// Count tokens for the given messages (approximate).
    async fn count_tokens(&self, messages: &[Message]) -> Result<u32, LlmError>;

    /// Model metadata (name, context window, capabilities).
    fn model_info(&self) -> ModelInfo;
}

#[derive(Debug, Clone)]
pub struct CompletionParams {
    pub model: Option<String>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub stop_sequences: Vec<String>,
    pub tools: Vec<ToolDefinition>,
    pub thinking: Option<ThinkingConfig>,
    /// Optional idempotency key for dedup at the provider. Generated
    /// once per logical request by the dispatcher and reused across
    /// retries, so a retried request after a network timeout isn't
    /// processed twice. Backend implementations should attach it as
    /// an HTTP header (e.g. `X-Request-Id` or provider-specific
    /// idempotency header). Backends that don't support it ignore it.
    pub request_id: Option<String>,
}

impl Default for CompletionParams {
    fn default() -> Self {
        Self {
            model: None,
            max_tokens: 4096,
            temperature: 0.7,
            stop_sequences: Vec::new(),
            tools: Vec::new(),
            thinking: None,
            request_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThinkingConfig {
    pub enabled: bool,
    pub budget_tokens: u32,
}

#[derive(Debug, Clone)]
pub struct CompletionDelta {
    pub text: Option<String>,
    pub thinking: Option<String>,
    pub tool_use: Option<ToolUseDelta>,
    pub finish_reason: Option<FinishReason>,
}

#[derive(Debug, Clone)]
pub struct ToolUseDelta {
    pub id: String,
    pub name: String,
    pub input_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    Length,
    ToolUse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub context_window: u32,
    pub provider: String,
    pub supports_tools: bool,
    pub supports_streaming: bool,
    pub supports_thinking: bool,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, channel: &str) -> Result<Session, StorageError>;
    async fn create_session_for_agent(
        &self,
        channel: &str,
        _agent_id: &AgentId,
    ) -> Result<Session, StorageError> {
        self.create_session(channel).await
    }
    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StorageError>;
    async fn list_sessions(&self, filter: SessionFilter) -> Result<Vec<Session>, StorageError>;
    async fn rename_session(&self, id: &SessionId, title: &str) -> Result<(), StorageError>;
    async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError>;
    async fn append_message(
        &self,
        session_id: &SessionId,
        msg: &Message,
    ) -> Result<(), StorageError>;
    async fn get_messages(
        &self,
        session_id: &SessionId,
        pagination: Pagination,
    ) -> Result<Vec<Message>, StorageError>;
    async fn compact_session(
        &self,
        session_id: &SessionId,
        keep_last: usize,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait TeeProvider: Send + Sync {
    /// Whether we are running inside a TEE (e.g. SEV-SNP detected).
    fn is_available(&self) -> bool;

    /// Get a remote attestation report (TEE only).
    async fn get_attestation_report(&self) -> Result<AttestationReport, TeeError>;

    /// Seal a key to the TEE measurement (TEE only).
    async fn seal_key(&self, key: &[u8]) -> Result<Vec<u8>, TeeError>;

    /// Unseal a previously sealed key (TEE only).
    async fn unseal_key(&self, sealed: &[u8]) -> Result<Vec<u8>, TeeError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub platform: String,
    pub measurement: Vec<u8>,
    pub report_data: Vec<u8>,
    pub raw_report: Vec<u8>,
}

pub trait EncryptionAdapter: Send + Sync {
    /// Encrypt plaintext, returns (ciphertext, nonce).
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), StorageError>;

    /// Decrypt ciphertext with the given nonce.
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, StorageError>;

    /// Encrypt with Associated Authenticated Data (AAD).
    /// AAD is authenticated but not encrypted — tampering with the AAD causes
    /// decryption to fail. Use this to bind ciphertext to a context (e.g. a
    /// provider name) so encrypted blobs cannot be swapped between rows.
    fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
        // Default: ignore AAD for backward compatibility.
        let _ = aad;
        self.encrypt(plaintext)
    }

    /// Decrypt with Associated Authenticated Data (AAD).
    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        // Default: ignore AAD for backward compatibility.
        let _ = aad;
        self.decrypt(ciphertext, nonce)
    }
}

#[async_trait]
pub trait Skill: Send + Sync {
    fn definition(&self) -> SkillDefinition;
    fn manifest(&self) -> SkillManifest;
    async fn invoke(
        &self,
        input: serde_json::Value,
        ctx: SkillContext,
    ) -> Result<SkillOutput, WasmHostError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default = "default_host_abi")]
    pub host_abi: String,
    pub capabilities: CapabilitySet,
}

pub const SKILL_HOST_ABI_V1: &str = "v1";
pub const SKILL_HOST_ABI_JAVY: &str = "javy";

fn default_host_abi() -> String {
    SKILL_HOST_ABI_V1.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub net_outbound: Vec<String>,
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub exec_shell: bool,
    pub env_secrets: bool,
    #[serde(default)]
    pub kv: bool,
    #[serde(default)]
    pub prompt_user: bool,
    #[serde(default)]
    pub emit_events: Vec<String>,
    #[serde(default)]
    pub hooks: Vec<String>,
    #[serde(default)]
    pub schedule_timers: bool,
    #[serde(default)]
    pub schedule_transforms: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SkillContext {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    /// Unique ID for this invocation (ULID).
    pub invocation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillOutput {
    pub content: String,
    pub artifacts: Vec<serde_json::Value>,
}

#[async_trait]
pub trait McpClient: Send + Sync {
    async fn connect(&mut self, config: &crate::config::McpServerConfig) -> Result<(), McpError>;
    async fn disconnect(&mut self) -> Result<(), McpError>;
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, McpError>;
    async fn call_tool(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, McpError>;
    fn is_connected(&self) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[async_trait]
pub trait ApprovalHandler: Send + Sync {
    /// Request approval for a tool invocation. Returns the decision.
    async fn request_approval(&self, request: ApprovalRequest) -> ApprovalDecision;
}

#[async_trait]
pub trait ChannelAdapter: Send + Sync {
    async fn start(&self) -> Result<(), ChannelError>;
    async fn stop(&self) -> Result<(), ChannelError>;
    async fn send_message(
        &self,
        target: &ChannelTarget,
        msg: &OutboundMessage,
    ) -> Result<(), ChannelError>;
    fn inbound(&self) -> Pin<Box<dyn Stream<Item = InboundMessage> + Send>>;

    /// Report current health status. Default: Active.
    fn health_status(&self) -> ChannelAccountStatus {
        ChannelAccountStatus::Active
    }

    /// Actively probe the remote service. Default: Ok.
    async fn probe(&self) -> Result<(), ChannelError> {
        Ok(())
    }

    /// Populate inbound attachments after policy gating.
    /// Default is no-op for channels that do not support deferred media fetching.
    async fn hydrate_inbound_attachments(
        &self,
        _msg: &mut InboundMessage,
    ) -> Result<(), ChannelError> {
        Ok(())
    }

    /// Handle an inbound webhook/push notification payload for this adapter.
    /// Default is unsupported.
    async fn handle_webhook(&self, _payload: serde_json::Value) -> Result<(), ChannelError> {
        Err(ChannelError::NotConfigured(
            "webhook/push is not supported for this channel adapter".to_string(),
        ))
    }
}

#[async_trait]
pub trait DeviceStore: Send + Sync {
    async fn list_devices(&self) -> Result<Vec<PairedDevice>, StorageError>;
    async fn get_device(&self, id: &str) -> Result<Option<PairedDevice>, StorageError>;
    async fn add_device(&self, device: &PairedDevice) -> Result<(), StorageError>;
    async fn update_permissions(
        &self,
        id: &str,
        permissions: &DevicePermissions,
    ) -> Result<(), StorageError>;
    async fn update_last_seen(
        &self,
        id: &str,
        last_seen: DateTime<Utc>,
    ) -> Result<(), StorageError>;
    async fn remove_device(&self, id: &str) -> Result<(), StorageError>;
}

/// Trait for embedding text into vectors.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Embed a text string into a vector of floats.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, MemoryError>;
    /// The dimensionality of the embedding vectors.
    fn dimensions(&self) -> usize;
    /// The name of the embedding model.
    fn model_name(&self) -> &str;
}

/// Trait for storing and searching vectors.
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Insert or update a vector with the given point ID.
    async fn upsert(&self, point_id: &str, vector: Vec<f32>) -> Result<(), MemoryError>;
    /// Search for the top-k most similar vectors to the query.
    async fn search(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorSearchResult>, MemoryError>;
    /// Delete a vector by point ID.
    async fn delete(&self, point_id: &str) -> Result<(), MemoryError>;
    /// Return the total number of stored vectors.
    async fn count(&self) -> Result<usize, MemoryError>;
}

/// Trait for persisting memory entry metadata and FTS.
#[async_trait]
pub trait MemoryMetadataStore: Send + Sync {
    async fn insert_entry(&self, entry: &MemoryEntry) -> Result<(), MemoryError>;
    async fn get_entry(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, MemoryError>;
    async fn delete_entry(&self, id: &MemoryId) -> Result<(), MemoryError>;
    async fn list_entries(
        &self,
        filter: &MemoryFilter,
        pagination: &Pagination,
    ) -> Result<Vec<MemoryEntry>, MemoryError>;
    async fn get_entries_by_vector_ids(
        &self,
        ids: &[String],
    ) -> Result<Vec<MemoryEntry>, MemoryError>;
    async fn count_entries(&self) -> Result<usize, MemoryError>;
    /// Full-text search on memory summaries.
    async fn fts_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(MemoryId, f32)>, MemoryError>;
}

/// Trait used by the agent crate to search memory for context augmentation.
#[async_trait]
pub trait MemorySearchProvider: Send + Sync {
    async fn search_for_context(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemoryResult>, MemoryError>;
}

#[async_trait]
pub trait CronStore: Send + Sync {
    async fn list_jobs(&self) -> Result<Vec<CronJob>, StorageError>;
    async fn get_job(&self, id: &CronJobId) -> Result<Option<CronJob>, StorageError>;
    async fn create_job(&self, job: &CronJob) -> Result<(), StorageError>;
    async fn update_job(&self, job: &CronJob) -> Result<(), StorageError>;
    async fn delete_job(&self, id: &CronJobId) -> Result<(), StorageError>;
    async fn list_due_jobs(&self, now: DateTime<Utc>) -> Result<Vec<CronJob>, StorageError>;
    async fn mark_run_started(
        &self,
        id: &CronJobId,
        started_at: DateTime<Utc>,
    ) -> Result<(), StorageError>;
    async fn mark_run_completed(
        &self,
        id: &CronJobId,
        next_run_at: DateTime<Utc>,
    ) -> Result<(), StorageError>;
}

#[async_trait]
pub trait TimelineStore: Send + Sync {
    async fn insert_event(&self, event: &TimelineEvent) -> Result<(), StorageError>;
    async fn query_events(
        &self,
        filter: &TimelineFilter,
        pagination: &Pagination,
    ) -> Result<Vec<TimelineEvent>, StorageError>;
}

/// Handler for internal (non-WASM, non-MCP) tools like `agents_spawn`.
/// Defined in core so that PluginRegistrar can reference it without depending
/// on the agent crate. The agent crate re-exports this for backward compat.
#[async_trait]
pub trait InternalToolHandler: Send + Sync {
    async fn handle(
        &self,
        input: serde_json::Value,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError>;

    /// Whether this tool is safe for concurrent execution with other safe tools.
    ///
    /// Read-only tools (search, fetch, file read, list) should return `true`.
    /// Destructive tools (file write, bash, git commit) should return `false`.
    /// Default is `false` (sequential execution).
    fn is_concurrent_safe(&self) -> bool {
        false
    }

    /// How this tool behaves when the user cancels an in-flight run.
    ///
    /// - `Cancel`: pending executions may be short-circuited with a synthetic
    ///   cancelled result.
    /// - `Block`: once scheduled, runtime waits for completion and persists the
    ///   real tool result before finishing cancellation.
    ///
    /// Default is `Cancel` to preserve legacy behavior.
    fn interrupt_behavior(&self) -> ToolInterruptBehavior {
        ToolInterruptBehavior::Cancel
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolInterruptBehavior {
    Cancel,
    Block,
}

#[async_trait]
pub trait SkillTimerStore: Send + Sync {
    async fn list_timers(&self) -> Result<Vec<SkillTimer>, StorageError>;
    async fn list_enabled_due(&self, now: DateTime<Utc>) -> Result<Vec<SkillTimer>, StorageError>;
    async fn upsert_timer(&self, timer: &SkillTimer) -> Result<(), StorageError>;
    async fn delete_timers_for_skill(&self, skill_id: &str) -> Result<u64, StorageError>;
    async fn delete_stale_timers(
        &self,
        skill_id: &str,
        keep_names: &[&str],
    ) -> Result<u64, StorageError>;
    async fn delete_timers_not_in_skills(
        &self,
        active_skill_ids: &[&str],
    ) -> Result<u64, StorageError>;
    async fn mark_tick(
        &self,
        id: &str,
        ticked_at: DateTime<Utc>,
        next_tick_at: DateTime<Utc>,
    ) -> Result<(), StorageError>;
    async fn increment_failures(&self, id: &str) -> Result<u32, StorageError>;
    async fn reset_failures(&self, id: &str) -> Result<(), StorageError>;
    async fn disable_timer(&self, id: &str) -> Result<(), StorageError>;
    async fn enable_timer(&self, id: &str, next_tick_at: DateTime<Utc>)
        -> Result<(), StorageError>;
}

#[async_trait]
pub trait SkillToggleStore: Send + Sync {
    /// Check if a skill is enabled. Returns `true` if no row exists (default enabled).
    async fn is_enabled(&self, skill_id: &str) -> Result<bool, StorageError>;
    /// Persist enabled/disabled state for a skill.
    async fn set_enabled(&self, skill_id: &str, enabled: bool) -> Result<(), StorageError>;
    /// List all explicitly disabled skill IDs.
    async fn list_disabled(&self) -> Result<Vec<String>, StorageError>;
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, StorageError>;
    async fn get_key(&self, provider: &str) -> Result<Option<String>, StorageError>;
    async fn set_key(&self, provider: &str, api_key: &str) -> Result<(), StorageError>;
    async fn delete_key(&self, provider: &str) -> Result<(), StorageError>;
}

#[async_trait]
pub trait ChannelAccountStore: Send + Sync {
    async fn list_accounts(&self) -> Result<Vec<ChannelAccount>, StorageError>;
    async fn get_account(
        &self,
        id: &ChannelAccountId,
    ) -> Result<Option<ChannelAccount>, StorageError>;
    async fn get_account_by_type(
        &self,
        channel_type: &str,
    ) -> Result<Option<ChannelAccount>, StorageError>;
    async fn create_account(&self, account: &ChannelAccount) -> Result<(), StorageError>;
    async fn update_account(&self, account: &ChannelAccount) -> Result<(), StorageError>;
    async fn delete_account(&self, id: &ChannelAccountId) -> Result<(), StorageError>;
    async fn update_status(
        &self,
        id: &ChannelAccountId,
        status: ChannelAccountStatus,
    ) -> Result<(), StorageError>;
    async fn store_credential(
        &self,
        id: &ChannelAccountId,
        credential_json: &str,
    ) -> Result<(), StorageError>;
    async fn get_credential(&self, id: &ChannelAccountId) -> Result<Option<String>, StorageError>;
    async fn delete_credential(&self, id: &ChannelAccountId) -> Result<(), StorageError>;
}

#[async_trait]
pub trait WorkflowStore: Send + Sync {
    async fn list_runs(
        &self,
        status_filter: Option<WorkflowRunStatus>,
        limit: usize,
    ) -> Result<Vec<WorkflowRun>, StorageError>;
    async fn get_run(&self, id: &str) -> Result<Option<WorkflowRun>, StorageError>;
    async fn cancel_run(&self, id: &str) -> Result<bool, StorageError>;
}

#[async_trait]
pub trait AgentRegistry: Send + Sync {
    async fn list_agents(&self) -> Result<Vec<AgentConfig>, StorageError>;
    async fn get_agent(&self, id: &AgentId) -> Result<Option<AgentConfig>, StorageError>;
    async fn resolve_agent(&self, session_id: &SessionId) -> Result<AgentId, StorageError>;
    async fn create_agent(&self, config: AgentConfig) -> Result<(), StorageError>;
    async fn update_agent(&self, id: &AgentId, config: AgentConfig) -> Result<(), StorageError>;
    async fn delete_agent(&self, id: &AgentId) -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_store_is_object_safe() {
        // Compile-time check: dyn ApiKeyStore must be valid
        fn _assert_object_safe(_: &dyn ApiKeyStore) {}
    }

    #[test]
    fn channel_account_store_is_object_safe() {
        fn _assert_object_safe(_: &dyn ChannelAccountStore) {}
    }

    #[test]
    fn workflow_store_is_object_safe() {
        fn _assert_object_safe(_: &dyn WorkflowStore) {}
    }

    #[test]
    fn skill_context_has_invocation_id() {
        let ctx = SkillContext {
            session_id: SessionId::from_string("s1"),
            agent_id: AgentId::new("main"),
            invocation_id: "test-invocation-id".to_string(),
        };
        assert_eq!(ctx.invocation_id, "test-invocation-id");
    }
}
