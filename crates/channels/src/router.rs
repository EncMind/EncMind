use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use encmind_core::config::{AccessAction, GmailConfig, InboundAccessPolicy};
use encmind_core::error::ChannelError;
use encmind_core::traits::{ChannelAdapter, SessionStore};
use encmind_core::types::{
    ChannelPolicy, ChannelTarget, ContentBlock, InboundMessage, OutboundMessage, SessionId,
};
use tracing::warn;

/// Bound sender->session cache to avoid unbounded memory growth from high-cardinality senders.
const MAX_SENDER_SESSION_CACHE: usize = 10_000;

/// Routes inbound messages to sessions based on access policy.
/// Returns `Option<SessionId>` — does NOT execute the agent.
pub struct ChannelRouter {
    adapters: HashMap<String, Arc<dyn ChannelAdapter>>,
    access_policy: InboundAccessPolicy,
    session_store: Arc<dyn SessionStore>,
    /// Maps (channel, scoped_sender_key) → SessionId for session reuse.
    sender_sessions: Mutex<HashMap<(String, String), SessionId>>,
}

impl ChannelRouter {
    pub fn new(access_policy: InboundAccessPolicy, session_store: Arc<dyn SessionStore>) -> Self {
        Self {
            adapters: HashMap::new(),
            access_policy,
            session_store,
            sender_sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_adapter(&mut self, name: impl Into<String>, adapter: Arc<dyn ChannelAdapter>) {
        self.adapters.insert(name.into(), adapter);
    }

    /// Map inbound sender identity to an outbound target ID for rejection notices.
    fn rejection_target_id(channel: &str, sender_id: &str) -> String {
        // Telegram and Slack sender IDs are "{channel_id}:{user_id}" but
        // send_message expects the channel/chat ID only.
        if channel == "telegram" || channel == "slack" {
            if let Some((channel_id, _)) = sender_id.split_once(':') {
                return channel_id.to_string();
            }
        }
        sender_id.to_string()
    }

    pub fn is_sender_allowed(&self, channel: &str, sender_id: &str) -> bool {
        for entry in &self.access_policy.allowlist {
            if entry.channel == channel && sender_matches(channel, &entry.sender_id, sender_id) {
                return true;
            }
        }
        self.access_policy.default_action == AccessAction::Allow
    }

    pub async fn resolve_session(
        &self,
        channel: &str,
        sender_id: &str,
        thread_id: Option<&str>,
    ) -> Result<SessionId, ChannelError> {
        let key = (
            channel.to_string(),
            session_scope_sender_key(channel, sender_id, thread_id),
        );

        let cached_session = {
            let sessions = self.sender_sessions.lock().await;
            sessions.get(&key).cloned()
        };

        if let Some(sid) = cached_session {
            match self.session_store.get_session(&sid).await {
                Ok(Some(_)) => return Ok(sid),
                Ok(None) => {
                    let mut sessions = self.sender_sessions.lock().await;
                    if sessions.get(&key) == Some(&sid) {
                        sessions.remove(&key);
                    }
                }
                Err(e) => return Err(ChannelError::ConnectionFailed(e.to_string())),
            }
        }

        let session = self
            .session_store
            .create_session(channel)
            .await
            .map_err(|e| ChannelError::ConnectionFailed(e.to_string()))?;

        let sid = session.id.clone();
        let mut sessions = self.sender_sessions.lock().await;
        if let Some(existing) = sessions.get(&key) {
            let existing = existing.clone();
            drop(sessions);

            // Another task resolved this sender concurrently; clean up the extra
            // session best-effort so we do not leak orphan sessions.
            if let Err(e) = self.session_store.delete_session(&sid).await {
                warn!(
                    session_id = %sid,
                    channel = %channel,
                    sender_id = %sender_id,
                    thread_id = ?thread_id,
                    error = %e,
                    "failed to delete duplicate session created during concurrent routing"
                );
            }
            return Ok(existing);
        }

        if sessions.len() >= MAX_SENDER_SESSION_CACHE {
            if let Some(evicted_key) = sessions.keys().next().cloned() {
                sessions.remove(&evicted_key);
            }
        }
        sessions.insert(key, sid.clone());
        Ok(sid)
    }

    /// Route an inbound message. Returns Some(session_id) if allowed, None if rejected.
    /// When `notify_rejected` is true and the sender is not allowed, sends a
    /// "Not authorized." reply via the channel adapter before returning None
    /// (except Gmail, which stays silent).
    pub async fn route_inbound(
        &self,
        msg: &InboundMessage,
    ) -> Result<Option<SessionId>, ChannelError> {
        if !self.is_sender_allowed(&msg.channel, &msg.sender_id) {
            if should_send_rejection_notice(&msg.channel, self.access_policy.notify_rejected) {
                if let Some(adapter) = self.adapters.get(&msg.channel) {
                    let target = ChannelTarget {
                        channel: msg.channel.clone(),
                        target_id: Self::rejection_target_id(&msg.channel, &msg.sender_id),
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
                    // Best-effort: don't fail the route if the notification fails.
                    if let Err(e) = adapter.send_message(&target, &reply).await {
                        warn!(
                            channel = %msg.channel,
                            sender = %msg.sender_id,
                            error = %e,
                            "failed to send rejection notification"
                        );
                    }
                }
            }
            return Ok(None);
        }
        let sid = self
            .resolve_session(&msg.channel, &msg.sender_id, msg.thread_id.as_deref())
            .await?;
        Ok(Some(sid))
    }

    pub fn should_notify_rejected(&self) -> bool {
        self.access_policy.notify_rejected
    }

    pub fn get_adapter(&self, channel: &str) -> Option<&Arc<dyn ChannelAdapter>> {
        self.adapters.get(channel)
    }
}

/// Result of merging a per-channel policy with the global access policy.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub default_action: AccessAction,
    pub allowlist: Vec<String>,
    pub denylist: Vec<String>,
    pub dm_only: bool,
    pub mention_gating: bool,
    pub notify_rejected: bool,
}

/// Outcome of a per-message policy check.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Reject { reason: String },
}

/// Merge a per-account `ChannelPolicy` with the global `InboundAccessPolicy`.
/// Per-account fields override globals when present.
pub fn resolve_policy(
    global: &InboundAccessPolicy,
    account_policy: Option<&ChannelPolicy>,
    channel: &str,
) -> ResolvedPolicy {
    let default_action = account_policy
        .and_then(|p| p.default_action.as_deref())
        .map(|s| match s {
            "allow" => AccessAction::Allow,
            _ => AccessAction::Reject,
        })
        .unwrap_or(global.default_action.clone());

    let allowlist = account_policy
        .map(|p| p.allowlist.clone())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| {
            global
                .allowlist
                .iter()
                .filter(|e| e.channel == channel)
                .map(|e| e.sender_id.clone())
                .collect()
        });

    let denylist = account_policy
        .map(|p| p.denylist.iter().map(|d| d.sender_id.clone()).collect())
        .unwrap_or_default();

    let dm_only = account_policy.map(|p| p.dm_only).unwrap_or(false);
    let mention_gating = account_policy.map(|p| p.mention_gating).unwrap_or(false);
    let notify_rejected = account_policy
        .and_then(|p| p.notify_rejected)
        .unwrap_or(global.notify_rejected);

    ResolvedPolicy {
        default_action,
        allowlist,
        denylist,
        dm_only,
        mention_gating,
        notify_rejected,
    }
}

/// Check a message against a resolved policy.
/// Returns Allow or Reject with a reason string.
pub fn check_policy(msg: &InboundMessage, policy: &ResolvedPolicy) -> PolicyDecision {
    // Denylist takes highest precedence
    if policy
        .denylist
        .iter()
        .any(|d| sender_matches(&msg.channel, d, &msg.sender_id))
    {
        return PolicyDecision::Reject {
            reason: "denylist".into(),
        };
    }

    // Allowlist check: if allowlist is non-empty, only listed senders pass
    let sender_allowed = if !policy.allowlist.is_empty() {
        policy
            .allowlist
            .iter()
            .any(|a| sender_matches(&msg.channel, a, &msg.sender_id))
    } else {
        policy.default_action == AccessAction::Allow
    };

    if !sender_allowed {
        return PolicyDecision::Reject {
            reason: "default_reject".into(),
        };
    }

    // DM-only filter
    if policy.dm_only && msg.is_dm != Some(true) {
        return PolicyDecision::Reject {
            reason: "dm_only".into(),
        };
    }

    // Mention gating
    if policy.mention_gating && !msg.is_mention {
        return PolicyDecision::Reject {
            reason: "mention_gating".into(),
        };
    }

    PolicyDecision::Allow
}

fn sender_matches(channel: &str, policy_sender: &str, sender_id: &str) -> bool {
    if channel == "gmail" {
        GmailConfig::normalize_sender_id(policy_sender)
            == GmailConfig::normalize_sender_id(sender_id)
    } else {
        policy_sender == sender_id
    }
}

fn session_scope_sender_key(channel: &str, sender_id: &str, thread_id: Option<&str>) -> String {
    if channel == "gmail" {
        let normalized_sender = GmailConfig::normalize_sender_id(sender_id);
        let sender_key = if normalized_sender.is_empty() {
            sender_id.trim().to_string()
        } else {
            normalized_sender
        };
        if let Some(thread) = thread_id.map(str::trim).filter(|v| !v.is_empty()) {
            return format!("{sender_key}|thread:{thread}");
        }
        return sender_key;
    }
    sender_id.to_string()
}

/// Whether a rejection notice should be sent for an inbound policy reject.
///
/// Gmail remains silent by default to avoid unsolicited outbound email.
pub fn should_send_rejection_notice(channel: &str, notify_rejected: bool) -> bool {
    notify_rejected && channel != "gmail"
}

/// Check if a slash command is allowed on the given channel.
/// If `command_gates` is empty, all commands are allowed everywhere.
/// If the channel has an explicit gate entry, only listed commands are allowed.
/// If the channel has no entry but others do, the command is allowed (ungated channel).
pub fn is_command_allowed(
    command_gates: &std::collections::HashMap<String, Vec<String>>,
    channel: &str,
    command: &str,
) -> bool {
    if command_gates.is_empty() {
        return true;
    }
    match command_gates.get(channel) {
        Some(allowed) => allowed.iter().any(|c| c == command),
        None => true, // ungated channel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use encmind_core::config::{AccessAction, AllowlistEntry, InboundAccessPolicy};
    use encmind_core::types::{ContentBlock, InboundMessage};
    use std::collections::HashMap as StdHashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use std::sync::Mutex as StdMutex;
    use tokio::time::Duration;

    // Minimal mock session store
    use async_trait::async_trait;
    use encmind_core::error::StorageError;
    use encmind_core::types::{Message, Pagination, Session, SessionFilter, SessionId};

    struct MockSessionStore {
        sessions: StdMutex<StdHashMap<SessionId, Session>>,
    }

    impl MockSessionStore {
        fn new() -> Self {
            Self {
                sessions: StdMutex::new(StdHashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SessionStore for MockSessionStore {
        async fn create_session(&self, channel: &str) -> Result<Session, StorageError> {
            let session = Session {
                id: SessionId::new(),
                title: None,
                channel: channel.to_string(),
                agent_id: Default::default(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                archived: false,
            };
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }
        async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StorageError> {
            Ok(self.sessions.lock().unwrap().get(id).cloned())
        }
        async fn list_sessions(
            &self,
            _filter: SessionFilter,
        ) -> Result<Vec<Session>, StorageError> {
            Ok(vec![])
        }
        async fn rename_session(&self, _id: &SessionId, _title: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError> {
            self.sessions.lock().unwrap().remove(id);
            Ok(())
        }
        async fn append_message(
            &self,
            _session_id: &SessionId,
            _msg: &Message,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        async fn get_messages(
            &self,
            _session_id: &SessionId,
            _pagination: Pagination,
        ) -> Result<Vec<Message>, StorageError> {
            Ok(vec![])
        }
        async fn compact_session(
            &self,
            _session_id: &SessionId,
            _keep_last: usize,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    struct DelayedSessionStore {
        create_calls: AtomicUsize,
        delete_calls: AtomicUsize,
        sessions: StdMutex<StdHashMap<SessionId, Session>>,
    }

    impl DelayedSessionStore {
        fn new() -> Self {
            Self {
                create_calls: AtomicUsize::new(0),
                delete_calls: AtomicUsize::new(0),
                sessions: StdMutex::new(StdHashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SessionStore for DelayedSessionStore {
        async fn create_session(&self, channel: &str) -> Result<Session, StorageError> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(25)).await;
            let session = Session {
                id: SessionId::new(),
                title: None,
                channel: channel.to_string(),
                agent_id: Default::default(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                archived: false,
            };
            self.sessions
                .lock()
                .unwrap()
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }

        async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, StorageError> {
            Ok(self.sessions.lock().unwrap().get(id).cloned())
        }
        async fn list_sessions(
            &self,
            _filter: SessionFilter,
        ) -> Result<Vec<Session>, StorageError> {
            Ok(vec![])
        }
        async fn rename_session(&self, _id: &SessionId, _title: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            self.sessions.lock().unwrap().remove(id);
            Ok(())
        }
        async fn append_message(
            &self,
            _session_id: &SessionId,
            _msg: &Message,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        async fn get_messages(
            &self,
            _session_id: &SessionId,
            _pagination: Pagination,
        ) -> Result<Vec<Message>, StorageError> {
            Ok(vec![])
        }
        async fn compact_session(
            &self,
            _session_id: &SessionId,
            _keep_last: usize,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn make_msg(channel: &str, sender_id: &str) -> InboundMessage {
        InboundMessage {
            channel: channel.into(),
            sender_id: sender_id.into(),
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn reject_policy_blocks_unknown() {
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![],
                notify_rejected: false,
            },
            StdArc::new(MockSessionStore::new()),
        );
        let msg = make_msg("telegram", "unknown-user");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn allow_policy_permits_any() {
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            StdArc::new(MockSessionStore::new()),
        );
        let msg = make_msg("telegram", "anyone");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn allowlisted_sender_gets_session() {
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![AllowlistEntry {
                    channel: "telegram".into(),
                    sender_id: "alice".into(),
                    label: Some("Alice".into()),
                }],
                notify_rejected: false,
            },
            StdArc::new(MockSessionStore::new()),
        );
        let msg = make_msg("telegram", "alice");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn same_sender_reuses_session() {
        let store = StdArc::new(MockSessionStore::new());
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            store,
        );
        let msg = make_msg("telegram", "bob");
        let sid1 = router.route_inbound(&msg).await.unwrap().unwrap();
        let sid2 = router.route_inbound(&msg).await.unwrap().unwrap();
        assert_eq!(sid1, sid2);
    }

    #[tokio::test]
    async fn stale_cached_session_is_recreated() {
        let store = StdArc::new(MockSessionStore::new());
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            store.clone(),
        );
        let msg = make_msg("telegram", "carol");
        let sid1 = router.route_inbound(&msg).await.unwrap().unwrap();
        store.delete_session(&sid1).await.unwrap();

        let sid2 = router.route_inbound(&msg).await.unwrap().unwrap();
        assert_ne!(sid1, sid2, "stale cache entry should be replaced");
    }

    #[tokio::test]
    async fn gmail_thread_id_scopes_session() {
        let store = StdArc::new(MockSessionStore::new());
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            store,
        );
        let mut msg1 = make_msg("gmail", "owner@gmail.com");
        msg1.thread_id = Some("thread-a".to_string());
        let mut msg2 = make_msg("gmail", "owner@gmail.com");
        msg2.thread_id = Some("thread-b".to_string());

        let sid1 = router.route_inbound(&msg1).await.unwrap().unwrap();
        let sid2 = router.route_inbound(&msg2).await.unwrap().unwrap();
        assert_ne!(
            sid1, sid2,
            "different gmail threads should not share a session"
        );
    }

    #[tokio::test]
    async fn gmail_thread_id_reuses_session_for_sender_aliases() {
        let store = StdArc::new(MockSessionStore::new());
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            store,
        );
        let mut msg1 = make_msg("gmail", "User.Name+tag@googlemail.com");
        msg1.thread_id = Some("thread-alias".to_string());
        let mut msg2 = make_msg("gmail", "username@gmail.com");
        msg2.thread_id = Some("thread-alias".to_string());

        let sid1 = router.route_inbound(&msg1).await.unwrap().unwrap();
        let sid2 = router.route_inbound(&msg2).await.unwrap().unwrap();
        assert_eq!(
            sid1, sid2,
            "canonicalized gmail sender aliases in same thread should reuse session"
        );
    }

    use encmind_core::types::{ChannelTarget, OutboundMessage};
    struct RecordingAdapter {
        sent: StdMutex<Vec<(String, String)>>,
    }

    impl RecordingAdapter {
        fn new() -> Self {
            Self {
                sent: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ChannelAdapter for RecordingAdapter {
        async fn start(&self) -> Result<(), ChannelError> {
            Ok(())
        }
        async fn stop(&self) -> Result<(), ChannelError> {
            Ok(())
        }
        async fn send_message(
            &self,
            target: &ChannelTarget,
            msg: &OutboundMessage,
        ) -> Result<(), ChannelError> {
            let text = msg
                .content
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<String>();
            self.sent
                .lock()
                .unwrap()
                .push((target.target_id.clone(), text));
            Ok(())
        }
        fn inbound(&self) -> std::pin::Pin<Box<dyn futures::Stream<Item = InboundMessage> + Send>> {
            Box::pin(futures::stream::empty())
        }
    }

    #[tokio::test]
    async fn notify_rejected_sends_reply() {
        let adapter = StdArc::new(RecordingAdapter::new());
        let mut router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![],
                notify_rejected: true,
            },
            StdArc::new(MockSessionStore::new()),
        );
        router.register_adapter("telegram", adapter.clone());

        let msg = make_msg("telegram", "stranger");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_none());

        let sent = adapter.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "stranger");
        assert_eq!(sent[0].1, "Not authorized.");
    }

    #[tokio::test]
    async fn notify_rejected_false_is_silent() {
        let adapter = StdArc::new(RecordingAdapter::new());
        let mut router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![],
                notify_rejected: false,
            },
            StdArc::new(MockSessionStore::new()),
        );
        router.register_adapter("telegram", adapter.clone());

        let msg = make_msg("telegram", "stranger");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_none());

        let sent = adapter.sent.lock().unwrap();
        assert!(
            sent.is_empty(),
            "should not send when notify_rejected is false"
        );
    }

    #[tokio::test]
    async fn notify_rejected_telegram_uses_chat_id_target() {
        let adapter = StdArc::new(RecordingAdapter::new());
        let mut router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![],
                notify_rejected: true,
            },
            StdArc::new(MockSessionStore::new()),
        );
        router.register_adapter("telegram", adapter.clone());

        let msg = make_msg("telegram", "100:42");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_none());

        let sent = adapter.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "100");
        assert_eq!(sent[0].1, "Not authorized.");
    }

    #[tokio::test]
    async fn notify_rejected_does_not_send_for_gmail() {
        let adapter = StdArc::new(RecordingAdapter::new());
        let mut router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![],
                notify_rejected: true,
            },
            StdArc::new(MockSessionStore::new()),
        );
        router.register_adapter("gmail", adapter.clone());

        let msg = make_msg("gmail", "stranger@example.com");
        let result = router.route_inbound(&msg).await.unwrap();
        assert!(result.is_none());

        let sent = adapter.sent.lock().unwrap();
        assert!(sent.is_empty(), "gmail should not emit rejection notices");
    }

    #[test]
    fn should_send_rejection_notice_disables_gmail() {
        assert!(!should_send_rejection_notice("gmail", true));
        assert!(should_send_rejection_notice("slack", true));
        assert!(!should_send_rejection_notice("slack", false));
    }

    #[tokio::test]
    async fn concurrent_same_sender_resolves_single_session_mapping() {
        let store = StdArc::new(DelayedSessionStore::new());
        let router = StdArc::new(ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            store.clone(),
        ));

        let msg = make_msg("telegram", "race-user");
        let (r1, r2) = tokio::join!(router.route_inbound(&msg), router.route_inbound(&msg));
        let sid1 = r1.unwrap().unwrap();
        let sid2 = r2.unwrap().unwrap();

        assert_eq!(
            sid1, sid2,
            "concurrent routes should reuse one mapped session"
        );

        let creates = store.create_calls.load(Ordering::SeqCst);
        let deletes = store.delete_calls.load(Ordering::SeqCst);
        assert!(
            creates == 1 || creates == 2,
            "unexpected create count: {creates}"
        );
        if creates == 2 {
            assert_eq!(
                deletes, 1,
                "duplicate session should be cleaned up when races occur"
            );
        }
    }

    #[tokio::test]
    async fn sender_session_cache_is_bounded() {
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Allow,
                allowlist: vec![],
                notify_rejected: false,
            },
            StdArc::new(MockSessionStore::new()),
        );

        for idx in 0..(MAX_SENDER_SESSION_CACHE + 64) {
            let msg = make_msg("telegram", &format!("sender-{idx}"));
            let _ = router.route_inbound(&msg).await.unwrap();
        }

        let size = router.sender_sessions.lock().await.len();
        assert!(
            size <= MAX_SENDER_SESSION_CACHE,
            "cache size exceeded bound: {size}"
        );
    }

    // ---- Per-channel policy enforcement tests ----

    use encmind_core::types::DenylistEntry;

    #[test]
    fn resolve_policy_uses_global_defaults() {
        let global = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![AllowlistEntry {
                channel: "telegram".into(),
                sender_id: "alice".into(),
                label: Some("Alice".into()),
            }],
            notify_rejected: true,
        };
        let resolved = resolve_policy(&global, None, "telegram");
        assert_eq!(resolved.default_action, AccessAction::Reject);
        assert_eq!(resolved.allowlist, vec!["alice".to_string()]);
        assert!(resolved.denylist.is_empty());
        assert!(!resolved.dm_only);
        assert!(!resolved.mention_gating);
        assert!(resolved.notify_rejected);
    }

    #[test]
    fn resolve_policy_filters_global_allowlist_by_channel() {
        let global = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![
                AllowlistEntry {
                    channel: "telegram".into(),
                    sender_id: "alice".into(),
                    label: None,
                },
                AllowlistEntry {
                    channel: "gmail".into(),
                    sender_id: "bob@example.com".into(),
                    label: None,
                },
            ],
            notify_rejected: false,
        };

        let telegram_resolved = resolve_policy(&global, None, "telegram");
        assert_eq!(telegram_resolved.allowlist, vec!["alice".to_string()]);

        let gmail_resolved = resolve_policy(&global, None, "gmail");
        assert_eq!(
            gmail_resolved.allowlist,
            vec!["bob@example.com".to_string()]
        );
    }

    #[test]
    fn resolve_policy_account_overrides_global() {
        let global = InboundAccessPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec![],
            notify_rejected: false,
        };
        let policy = ChannelPolicy {
            default_action: Some("allow".into()),
            allowlist: vec!["bob".into()],
            denylist: vec![DenylistEntry {
                sender_id: "eve".into(),
                label: None,
            }],
            dm_only: true,
            mention_gating: true,
            notify_rejected: Some(true),
        };
        let resolved = resolve_policy(&global, Some(&policy), "telegram");
        assert_eq!(resolved.default_action, AccessAction::Allow);
        assert_eq!(resolved.allowlist, vec!["bob".to_string()]);
        assert_eq!(resolved.denylist, vec!["eve".to_string()]);
        assert!(resolved.dm_only);
        assert!(resolved.mention_gating);
        assert!(resolved.notify_rejected);
    }

    #[test]
    fn check_policy_denylist_takes_precedence() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec!["eve".into()],
            denylist: vec!["eve".into()],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let msg = make_msg("telegram", "eve");
        assert_eq!(
            check_policy(&msg, &policy),
            PolicyDecision::Reject {
                reason: "denylist".into()
            }
        );
    }

    #[test]
    fn check_policy_allowlist_allows_listed() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec!["alice".into()],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let msg = make_msg("telegram", "alice");
        assert_eq!(check_policy(&msg, &policy), PolicyDecision::Allow);
    }

    #[test]
    fn check_policy_gmail_allowlist_matches_canonical_aliases() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec!["username@gmail.com".into()],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let msg = make_msg("gmail", "user.name+tag@googlemail.com");
        assert_eq!(check_policy(&msg, &policy), PolicyDecision::Allow);
    }

    #[test]
    fn is_sender_allowed_gmail_allowlist_matches_canonical_aliases() {
        let router = ChannelRouter::new(
            InboundAccessPolicy {
                default_action: AccessAction::Reject,
                allowlist: vec![AllowlistEntry {
                    channel: "gmail".into(),
                    sender_id: "username@gmail.com".into(),
                    label: None,
                }],
                notify_rejected: false,
            },
            StdArc::new(MockSessionStore::new()),
        );
        assert!(router.is_sender_allowed("gmail", "user.name+tag@googlemail.com"));
    }

    #[test]
    fn check_policy_rejects_unlisted_sender() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Reject,
            allowlist: vec!["alice".into()],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let msg = make_msg("telegram", "bob");
        assert_eq!(
            check_policy(&msg, &policy),
            PolicyDecision::Reject {
                reason: "default_reject".into()
            }
        );
    }

    #[test]
    fn check_policy_dm_only_rejects_non_dm() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: true,
            mention_gating: false,
            notify_rejected: false,
        };
        let mut msg = make_msg("telegram", "alice");
        msg.is_dm = Some(false);
        assert_eq!(
            check_policy(&msg, &policy),
            PolicyDecision::Reject {
                reason: "dm_only".into()
            }
        );
    }

    #[test]
    fn check_policy_dm_only_allows_dm() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: true,
            mention_gating: false,
            notify_rejected: false,
        };
        let mut msg = make_msg("telegram", "alice");
        msg.is_dm = Some(true);
        assert_eq!(check_policy(&msg, &policy), PolicyDecision::Allow);
    }

    #[test]
    fn check_policy_mention_gating_rejects_non_mention() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: false,
            mention_gating: true,
            notify_rejected: false,
        };
        let msg = make_msg("telegram", "alice");
        assert_eq!(
            check_policy(&msg, &policy),
            PolicyDecision::Reject {
                reason: "mention_gating".into()
            }
        );
    }

    #[test]
    fn check_policy_mention_gating_allows_mention() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: false,
            mention_gating: true,
            notify_rejected: false,
        };
        let mut msg = make_msg("telegram", "alice");
        msg.is_mention = true;
        assert_eq!(check_policy(&msg, &policy), PolicyDecision::Allow);
    }

    #[test]
    fn check_policy_combined_dm_and_mention() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: true,
            mention_gating: true,
            notify_rejected: false,
        };
        // DM + mention → allow
        let mut msg = make_msg("slack", "D123:user");
        msg.is_dm = Some(true);
        msg.is_mention = true;
        assert_eq!(check_policy(&msg, &policy), PolicyDecision::Allow);

        // DM + no mention → reject (mention_gating)
        let mut msg2 = make_msg("slack", "D123:user");
        msg2.is_dm = Some(true);
        assert_eq!(
            check_policy(&msg2, &policy),
            PolicyDecision::Reject {
                reason: "mention_gating".into()
            }
        );
    }

    #[test]
    fn check_policy_empty_allowlist_uses_default_allow() {
        let policy = ResolvedPolicy {
            default_action: AccessAction::Allow,
            allowlist: vec![],
            denylist: vec![],
            dm_only: false,
            mention_gating: false,
            notify_rejected: false,
        };
        let msg = make_msg("telegram", "anyone");
        assert_eq!(check_policy(&msg, &policy), PolicyDecision::Allow);
    }

    // --- ChannelAdapter default methods ---

    #[test]
    fn health_status_default_is_active() {
        let adapter = RecordingAdapter::new();
        assert_eq!(
            adapter.health_status(),
            encmind_core::types::ChannelAccountStatus::Active
        );
    }

    #[tokio::test]
    async fn probe_default_is_ok() {
        let adapter = RecordingAdapter::new();
        assert!(adapter.probe().await.is_ok());
    }

    // --- Command gating tests ---

    #[test]
    fn command_gating_empty_gates_allows_all() {
        let gates = StdHashMap::new();
        assert!(is_command_allowed(&gates, "telegram", "/start"));
        assert!(is_command_allowed(&gates, "slack", "/help"));
    }

    #[test]
    fn command_gating_allows_listed_command() {
        let mut gates = StdHashMap::new();
        gates.insert(
            "telegram".to_string(),
            vec!["/start".to_string(), "/help".to_string()],
        );
        assert!(is_command_allowed(&gates, "telegram", "/start"));
        assert!(is_command_allowed(&gates, "telegram", "/help"));
    }

    #[test]
    fn command_gating_rejects_unlisted_command() {
        let mut gates = StdHashMap::new();
        gates.insert("telegram".to_string(), vec!["/start".to_string()]);
        assert!(!is_command_allowed(&gates, "telegram", "/admin"));
    }

    #[test]
    fn command_gating_ungated_channel_allows_all() {
        let mut gates = StdHashMap::new();
        gates.insert("telegram".to_string(), vec!["/start".to_string()]);
        // "slack" has no entry in gates — should be allowed
        assert!(is_command_allowed(&gates, "slack", "/anything"));
    }
}
