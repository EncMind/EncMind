use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

macro_rules! ulid_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub String);

        impl $name {
            pub fn new() -> Self {
                Self(ulid::Ulid::new().to_string())
            }

            pub fn from_string(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = std::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(s.to_owned()))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

ulid_id!(SessionId);
ulid_id!(MessageId);
ulid_id!(TaskId);
ulid_id!(CronJobId);
ulid_id!(MemoryId);
ulid_id!(ChannelAccountId);

/// A stored memory entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: MemoryId,
    pub session_id: Option<SessionId>,
    pub vector_point_id: String,
    pub summary: String,
    pub source_channel: Option<String>,
    pub source_device: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// The source that contributed to a memory search result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySource {
    Vector,
    FullText,
    Hybrid,
}

/// A search result combining a memory entry with its relevance score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryResult {
    pub entry: MemoryEntry,
    pub score: f32,
    pub source: MemorySource,
}

/// Filters for querying memory entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryFilter {
    pub source_channel: Option<String>,
    pub source_device: Option<String>,
    pub session_id: Option<SessionId>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// A vector search result before joining with metadata.
#[derive(Debug, Clone)]
pub struct VectorSearchResult {
    pub point_id: String,
    pub score: f32,
}

/// A golden example for retrieval quality evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenExample {
    pub query: String,
    pub expected_memory_ids: Vec<String>,
    #[serde(default)]
    pub expected_not_ids: Vec<String>,
}

/// Citation quality score for a single memory reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationScore {
    pub memory_id: MemoryId,
    pub relevance: f32,
    pub faithfulness: f32,
}

/// A scheduled cron job definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    pub id: CronJobId,
    pub name: String,
    pub schedule: String,
    pub prompt: String,
    pub agent_id: AgentId,
    pub model: Option<String>,
    pub max_concurrent_runs: u32,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A file or media attachment on a channel message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub media_type: String,
    pub data: Vec<u8>,
}

ulid_id!(TimelineEventId);

/// A unified timeline event recording activity across channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: TimelineEventId,
    pub event_type: String,
    pub source: String,
    pub session_id: Option<SessionId>,
    pub agent_id: AgentId,
    pub summary: String,
    pub detail: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// Filters for querying timeline events.
#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    pub event_type: Option<String>,
    pub source: Option<String>,
    pub agent_id: Option<AgentId>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// Metadata for a stored API key (never includes the key value itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub provider: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Resource limits after applying operator ceiling.
/// Effective = min(skill_requested, operator_ceiling) per field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedResourceLimits {
    pub fuel_per_invocation: u64,
    pub wall_clock_ms: u64,
    pub invocations_per_minute: u32,
    pub max_concurrent: u32,
}

/// A persisted skill timer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillTimer {
    pub id: String,
    pub skill_id: String,
    pub timer_name: String,
    pub interval_secs: u64,
    pub export_fn: String,
    pub enabled: bool,
    pub last_tick_at: Option<DateTime<Utc>>,
    pub next_tick_at: Option<DateTime<Utc>>,
    pub source_manifest_hash: Option<String>,
    pub consecutive_failures: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A workflow execution run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: String,
    pub workflow_name: String,
    pub agent_id: String,
    pub status: WorkflowRunStatus,
    pub current_step: i64,
    pub total_steps: Option<i64>,
    pub error_detail: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRunStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl WorkflowRunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            WorkflowRunStatus::Running => "running",
            WorkflowRunStatus::Completed => "completed",
            WorkflowRunStatus::Failed => "failed",
            WorkflowRunStatus::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for WorkflowRunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

impl FromStr for WorkflowRunStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "running" => Ok(WorkflowRunStatus::Running),
            "completed" => Ok(WorkflowRunStatus::Completed),
            "failed" => Ok(WorkflowRunStatus::Failed),
            "cancelled" => Ok(WorkflowRunStatus::Cancelled),
            other => Err(format!("unknown workflow status: {other}")),
        }
    }
}

/// Agent IDs use human-readable slugs (e.g. "main", "researcher"), not ULIDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(slug: impl Into<String>) -> Self {
        Self(slug.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AgentId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new("main")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    System,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    Thinking {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
    Image {
        media_type: String,
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
}

/// Serde helper for base64-encoded byte vectors.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        // Store as JSON array of bytes for simplicity; could use base64 in production
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub role: Role,
    pub content: Vec<ContentBlock>,
    pub created_at: DateTime<Utc>,
    pub token_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub title: Option<String>,
    pub channel: String,
    pub agent_id: AgentId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub archived: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    pub channel: Option<String>,
    pub agent_id: Option<AgentId>,
    pub archived: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Pagination {
    pub offset: u32,
    pub limit: u32,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundMessage {
    pub channel: String,
    pub sender_id: String,
    pub content: Vec<ContentBlock>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    pub timestamp: DateTime<Utc>,
    /// Whether the message was sent in a DM (private conversation).
    #[serde(default)]
    pub is_dm: Option<bool>,
    /// Whether the message is an explicit mention of the bot.
    #[serde(default)]
    pub is_mention: bool,
    /// Thread identifier for threaded conversations.
    #[serde(default)]
    pub thread_id: Option<String>,
    /// ID of the message being replied to.
    #[serde(default)]
    pub reply_to_id: Option<String>,
    /// Arbitrary per-message metadata (sender name, language, etc.).
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub content: Vec<ContentBlock>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Thread identifier — reply goes to this thread when present.
    #[serde(default)]
    pub thread_id: Option<String>,
    /// ID of the message being replied to.
    #[serde(default)]
    pub reply_to_id: Option<String>,
    /// Optional message subject (used by channels that support it, e.g. email).
    #[serde(default)]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelTarget {
    pub channel: String,
    pub target_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub id: AgentId,
    pub name: String,
    pub model: Option<String>,
    pub workspace: Option<String>,
    pub system_prompt: Option<String>,
    pub skills: Vec<String>,
    pub is_default: bool,
}

/// A request for user/system approval before executing a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub session_id: SessionId,
    pub agent_id: AgentId,
}

/// The decision made in response to an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Denied { reason: String },
}

/// A WASM skill's request for user confirmation at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillApprovalRequest {
    pub request_id: String,
    pub skill_id: String,
    pub prompt: String,
    #[serde(default)]
    pub options: Vec<String>,
}

/// The response to a skill's approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillApprovalResponse {
    pub request_id: String,
    pub approved: bool,
    #[serde(default)]
    pub choice: Option<String>,
}

/// Permissions granted to a paired device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePermissions {
    #[serde(default)]
    pub file_read: bool,
    #[serde(default)]
    pub file_write: bool,
    #[serde(default)]
    pub file_list: bool,
    #[serde(default)]
    pub bash_exec: bool,
    #[serde(default)]
    pub chat: bool,
    /// Administrative access: security settings, config, device management.
    #[serde(default)]
    pub admin: bool,
}

/// A device that has been paired with the assistant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub permissions: DevicePermissions,
    pub paired_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Status of a channel account lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelAccountStatus {
    Active,
    Degraded,
    Stopped,
    LoginRequired,
    Error,
}

/// Where the channel account configuration originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    ConfigFile,
    Api,
}

/// A denylist entry matching a sender identity pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenylistEntry {
    pub sender_id: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// Per-channel policy overriding the global access policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelPolicy {
    #[serde(default)]
    pub default_action: Option<String>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub denylist: Vec<DenylistEntry>,
    #[serde(default)]
    pub dm_only: bool,
    #[serde(default)]
    pub mention_gating: bool,
    #[serde(default)]
    pub notify_rejected: Option<bool>,
}

/// A managed channel account (Telegram bot, Slack workspace, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAccount {
    pub id: ChannelAccountId,
    pub channel_type: String,
    pub label: String,
    pub enabled: bool,
    pub status: ChannelAccountStatus,
    pub config_source: ConfigSource,
    #[serde(default)]
    pub policy: Option<ChannelPolicy>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_ids_are_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn ulid_ids_are_ordered() {
        let a = SessionId::new();
        // Small sleep to ensure different ULID timestamp
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = SessionId::new();
        assert!(
            b.as_str() > a.as_str(),
            "Later ULID should sort after earlier"
        );
    }

    #[test]
    fn agent_id_uses_slug() {
        let id = AgentId::new("researcher");
        assert_eq!(id.as_str(), "researcher");
        assert_eq!(id.to_string(), "researcher");
    }

    #[test]
    fn role_serde_roundtrip() {
        let role = Role::Assistant;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"assistant\"");
        let back: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(back, role);
    }

    #[test]
    fn content_block_serde_roundtrip() {
        let block = ContentBlock::Text {
            text: "Hello, world!".into(),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, block);
    }

    #[test]
    fn tool_use_block_serde_roundtrip() {
        let block = ContentBlock::ToolUse {
            id: "tool-1".into(),
            name: "web_search".into(),
            input: serde_json::json!({"query": "rust async"}),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, block);
    }

    #[test]
    fn message_serde_roundtrip() {
        let msg = Message {
            id: MessageId::from_string("test-id"),
            role: Role::User,
            content: vec![ContentBlock::Text { text: "Hi".into() }],
            created_at: Utc::now(),
            token_count: Some(5),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, msg.id);
        assert_eq!(back.role, msg.role);
    }

    #[test]
    fn session_id_from_str() {
        let id: SessionId = "my-session".parse().unwrap();
        assert_eq!(id.as_str(), "my-session");
    }

    #[test]
    fn device_permissions_default_all_false() {
        let perms = DevicePermissions::default();
        assert!(!perms.file_read);
        assert!(!perms.file_write);
        assert!(!perms.file_list);
        assert!(!perms.bash_exec);
        assert!(!perms.chat);
        assert!(!perms.admin);
    }

    #[test]
    fn device_permissions_serde_roundtrip() {
        let perms = DevicePermissions {
            file_read: true,
            file_write: false,
            file_list: true,
            bash_exec: false,
            chat: true,
            admin: false,
        };
        let json = serde_json::to_string(&perms).unwrap();
        let back: DevicePermissions = serde_json::from_str(&json).unwrap();
        assert_eq!(back, perms);
    }

    #[test]
    fn memory_id_uniqueness() {
        let a = MemoryId::new();
        let b = MemoryId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn memory_entry_serde_roundtrip() {
        let entry = MemoryEntry {
            id: MemoryId::new(),
            session_id: Some(SessionId::new()),
            vector_point_id: "pt-1".into(),
            summary: "User prefers dark mode".into(),
            source_channel: Some("web".into()),
            source_device: Some("laptop".into()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: MemoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, entry.id);
        assert_eq!(back.summary, entry.summary);
        assert_eq!(back.source_device, Some("laptop".into()));
    }

    #[test]
    fn memory_filter_default() {
        let filter = MemoryFilter::default();
        assert!(filter.source_channel.is_none());
        assert!(filter.source_device.is_none());
        assert!(filter.session_id.is_none());
        assert!(filter.since.is_none());
        assert!(filter.until.is_none());
    }

    #[test]
    fn golden_example_serde() {
        let example = GoldenExample {
            query: "What color theme?".into(),
            expected_memory_ids: vec!["mem-1".into()],
            expected_not_ids: vec!["mem-2".into()],
        };
        let json = serde_json::to_string(&example).unwrap();
        let back: GoldenExample = serde_json::from_str(&json).unwrap();
        assert_eq!(back.query, "What color theme?");
        assert_eq!(back.expected_memory_ids.len(), 1);
    }

    #[test]
    fn cron_job_serde_roundtrip() {
        let job = CronJob {
            id: CronJobId::new(),
            name: "daily-summary".into(),
            schedule: "0 9 * * *".into(),
            prompt: "Summarize today's events".into(),
            agent_id: AgentId::default(),
            model: Some("gpt-4".into()),
            max_concurrent_runs: 2,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&job).unwrap();
        let back: CronJob = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, job.id);
        assert_eq!(back.name, "daily-summary");
        assert_eq!(back.schedule, "0 9 * * *");
        assert_eq!(back.max_concurrent_runs, 2);
        assert!(back.enabled);
    }

    #[test]
    fn timeline_event_serde_roundtrip() {
        let event = TimelineEvent {
            id: TimelineEventId::new(),
            event_type: "message".into(),
            source: "telegram".into(),
            session_id: Some(SessionId::new()),
            agent_id: AgentId::default(),
            summary: "Sent message in Telegram".into(),
            detail: Some(serde_json::json!({"chat_id": "123"})),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: TimelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, event.id);
        assert_eq!(back.event_type, "message");
        assert_eq!(back.source, "telegram");
    }

    #[test]
    fn attachment_serde_roundtrip() {
        let att = Attachment {
            name: "photo.jpg".into(),
            media_type: "image/jpeg".into(),
            data: vec![0xFF, 0xD8, 0xFF],
        };
        let json = serde_json::to_string(&att).unwrap();
        let back: Attachment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "photo.jpg");
        assert_eq!(back.media_type, "image/jpeg");
        assert_eq!(back.data, vec![0xFF, 0xD8, 0xFF]);
    }

    #[test]
    fn inbound_message_attachments_default_empty() {
        let json =
            r#"{"channel":"web","sender_id":"u1","content":[],"timestamp":"2026-01-01T00:00:00Z"}"#;
        let msg: InboundMessage = serde_json::from_str(json).unwrap();
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn api_key_record_serde_roundtrip() {
        let record = ApiKeyRecord {
            provider: "openai".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ApiKeyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, "openai");
    }

    #[test]
    fn api_key_record_has_no_key_field() {
        let record = ApiKeyRecord {
            provider: "anthropic".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&record).unwrap();
        // Must never contain a key value
        assert!(!json.contains("api_key"));
        assert!(!json.contains("key_blob"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn api_key_record_default_fields() {
        let now = Utc::now();
        let record = ApiKeyRecord {
            provider: "test".into(),
            created_at: now,
            updated_at: now,
        };
        assert_eq!(record.provider, "test");
        assert_eq!(record.created_at, now);
        assert_eq!(record.updated_at, now);
    }

    #[test]
    fn paired_device_serde_roundtrip() {
        let dev = PairedDevice {
            id: "dev-1".into(),
            name: "My Laptop".into(),
            public_key: vec![1, 2, 3],
            permissions: DevicePermissions {
                chat: true,
                ..Default::default()
            },
            paired_at: Utc::now(),
            last_seen: None,
        };
        let json = serde_json::to_string(&dev).unwrap();
        let back: PairedDevice = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, dev.id);
        assert_eq!(back.name, dev.name);
        assert!(back.permissions.chat);
    }

    #[test]
    fn channel_account_id_uniqueness() {
        let a = ChannelAccountId::new();
        let b = ChannelAccountId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn channel_account_status_serde_roundtrip() {
        for status in [
            ChannelAccountStatus::Active,
            ChannelAccountStatus::Degraded,
            ChannelAccountStatus::Stopped,
            ChannelAccountStatus::LoginRequired,
            ChannelAccountStatus::Error,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: ChannelAccountStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn workflow_run_status_serde_roundtrip() {
        for status in [
            WorkflowRunStatus::Running,
            WorkflowRunStatus::Completed,
            WorkflowRunStatus::Failed,
            WorkflowRunStatus::Cancelled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: WorkflowRunStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn workflow_run_status_parse_and_display() {
        let status: WorkflowRunStatus = "running".parse().unwrap();
        assert_eq!(status, WorkflowRunStatus::Running);
        assert_eq!(status.to_string(), "running");
        assert!("bogus".parse::<WorkflowRunStatus>().is_err());
    }

    #[test]
    fn config_source_serde_roundtrip() {
        let src = ConfigSource::Api;
        let json = serde_json::to_string(&src).unwrap();
        assert_eq!(json, "\"api\"");
        let back: ConfigSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ConfigSource::Api);

        let src2 = ConfigSource::ConfigFile;
        let json2 = serde_json::to_string(&src2).unwrap();
        assert_eq!(json2, "\"config_file\"");
    }

    #[test]
    fn channel_policy_serde_defaults() {
        let json = "{}";
        let policy: ChannelPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.allowlist.is_empty());
        assert!(policy.denylist.is_empty());
        assert!(!policy.dm_only);
        assert!(!policy.mention_gating);
        assert!(policy.default_action.is_none());
        assert!(policy.notify_rejected.is_none());
    }

    #[test]
    fn channel_account_serde_roundtrip() {
        let account = ChannelAccount {
            id: ChannelAccountId::new(),
            channel_type: "telegram".into(),
            label: "My Bot".into(),
            enabled: true,
            status: ChannelAccountStatus::Active,
            config_source: ConfigSource::Api,
            policy: Some(ChannelPolicy {
                dm_only: true,
                denylist: vec![DenylistEntry {
                    sender_id: "spammer".into(),
                    label: Some("Known spammer".into()),
                }],
                ..Default::default()
            }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&account).unwrap();
        let back: ChannelAccount = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, account.id);
        assert_eq!(back.channel_type, "telegram");
        assert_eq!(back.label, "My Bot");
        assert!(back.enabled);
        assert_eq!(back.status, ChannelAccountStatus::Active);
        assert_eq!(back.config_source, ConfigSource::Api);
        let policy = back.policy.unwrap();
        assert!(policy.dm_only);
        assert_eq!(policy.denylist.len(), 1);
        assert_eq!(policy.denylist[0].sender_id, "spammer");
    }

    #[test]
    fn denylist_entry_serde_roundtrip() {
        let entry = DenylistEntry {
            sender_id: "bad_user".into(),
            label: Some("Blocked".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DenylistEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sender_id, "bad_user");
        assert_eq!(back.label, Some("Blocked".into()));
    }

    #[test]
    fn channel_account_without_policy_roundtrip() {
        let account = ChannelAccount {
            id: ChannelAccountId::new(),
            channel_type: "slack".into(),
            label: "Work Slack".into(),
            enabled: false,
            status: ChannelAccountStatus::Stopped,
            config_source: ConfigSource::ConfigFile,
            policy: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&account).unwrap();
        let back: ChannelAccount = serde_json::from_str(&json).unwrap();
        assert!(back.policy.is_none());
        assert!(!back.enabled);
        assert_eq!(back.status, ChannelAccountStatus::Stopped);
    }

    #[test]
    fn inbound_message_serde_backward_compat() {
        // Old-format JSON without is_dm/is_mention should deserialize with defaults
        let json = r#"{"channel":"telegram","sender_id":"100:42","content":[{"type":"text","text":"hi"}],"timestamp":"2024-01-01T00:00:00Z"}"#;
        let msg: InboundMessage = serde_json::from_str(json).unwrap();
        assert!(msg.is_dm.is_none());
        assert!(!msg.is_mention);
    }

    #[test]
    fn inbound_message_serde_with_new_fields() {
        let json = r#"{"channel":"slack","sender_id":"D123:U1","content":[{"type":"text","text":"hi"}],"timestamp":"2024-01-01T00:00:00Z","is_dm":true,"is_mention":true}"#;
        let msg: InboundMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.is_dm, Some(true));
        assert!(msg.is_mention);
    }

    #[test]
    fn inbound_message_serde_backward_compat_thread_metadata() {
        // Old-format JSON without thread_id/reply_to_id/metadata should deserialize
        let json = r#"{"channel":"telegram","sender_id":"100:42","content":[{"type":"text","text":"hi"}],"timestamp":"2024-01-01T00:00:00Z"}"#;
        let msg: InboundMessage = serde_json::from_str(json).unwrap();
        assert!(msg.thread_id.is_none());
        assert!(msg.reply_to_id.is_none());
        assert!(msg.metadata.is_empty());
    }

    #[test]
    fn inbound_message_serde_with_thread_and_metadata() {
        let json = r#"{"channel":"telegram","sender_id":"100:42","content":[{"type":"text","text":"hi"}],"timestamp":"2024-01-01T00:00:00Z","thread_id":"999","reply_to_id":"555","metadata":{"username":"alice"}}"#;
        let msg: InboundMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.thread_id.as_deref(), Some("999"));
        assert_eq!(msg.reply_to_id.as_deref(), Some("555"));
        assert_eq!(
            msg.metadata.get("username").and_then(|v| v.as_str()),
            Some("alice")
        );
    }

    #[test]
    fn outbound_message_serde_backward_compat() {
        let json = r#"{"content":[{"type":"text","text":"hi"}]}"#;
        let msg: OutboundMessage = serde_json::from_str(json).unwrap();
        assert!(msg.thread_id.is_none());
        assert!(msg.reply_to_id.is_none());
    }

    #[test]
    fn outbound_message_serde_with_thread() {
        let json = r#"{"content":[{"type":"text","text":"hi"}],"thread_id":"123.456","reply_to_id":"msg-1"}"#;
        let msg: OutboundMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.thread_id.as_deref(), Some("123.456"));
        assert_eq!(msg.reply_to_id.as_deref(), Some("msg-1"));
    }

    #[test]
    fn inbound_message_metadata_roundtrip() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), serde_json::json!("value1"));
        metadata.insert("key2".to_string(), serde_json::json!(42));
        let msg = InboundMessage {
            channel: "test".into(),
            sender_id: "u1".into(),
            content: vec![],
            attachments: vec![],
            timestamp: chrono::Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: metadata.clone(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: InboundMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg2.metadata, metadata);
    }
}
