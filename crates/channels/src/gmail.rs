use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use encmind_core::config::GmailConfig;
use encmind_core::error::ChannelError;
use encmind_core::traits::ChannelAdapter;
use encmind_core::types::{
    ChannelAccountStatus, ChannelTarget, ContentBlock, InboundMessage, OutboundMessage,
};
use futures::Stream;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

/// Gmail channel adapter.
///
/// Polls Gmail REST API for unread messages using OAuth2 bearer tokens.
/// Supports outbound text replies via Gmail `users.messages.send`.
impl std::fmt::Debug for GmailAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmailAdapter")
            .field("client_id", &self.client_id)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

pub struct GmailAdapter {
    config: GmailConfig,
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    refresh_token: String,
    access_token: Arc<tokio::sync::RwLock<Option<(String, Instant)>>>,
    inbound_tx: StdMutex<mpsc::Sender<InboundMessage>>,
    inbound_rx: StdMutex<Option<mpsc::Receiver<InboundMessage>>>,
    cancel: AsyncMutex<CancellationToken>,
    poll_handle: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
    running: Arc<AtomicBool>,
    poll_lock: Arc<AsyncMutex<()>>,
    mark_read_retry_dedupe: Arc<AsyncMutex<HashMap<String, Instant>>>,
    scope_insufficient: Arc<AtomicBool>,
}

const MARK_READ_RETRY_DEDUPE_TTL: Duration = Duration::from_secs(10 * 60);
const MARK_READ_RETRY_DEDUPE_MAX: usize = 2048;
const GMAIL_LIST_PAGE_SIZE: usize = 10;
const GMAIL_MAX_LIST_PAGES: usize = 5;
const GMAIL_MAX_POLL_BACKOFF_MULTIPLIER: u64 = 8;
const GMAIL_TOKEN_REFRESH_BUFFER_SECS: u64 = 60;

struct RunningFlagGuard {
    running: Arc<AtomicBool>,
    disarmed: bool,
}

impl RunningFlagGuard {
    fn new(running: Arc<AtomicBool>) -> Self {
        Self {
            running,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for RunningFlagGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            self.running.store(false, Ordering::SeqCst);
        }
    }
}

impl GmailAdapter {
    /// Construct a `GmailAdapter` from config and stored credential JSON.
    ///
    /// The credential JSON must contain `client_id`, `client_secret`, and
    /// `refresh_token` fields.
    pub fn from_config_and_credentials(
        config: GmailConfig,
        cred_json: &str,
    ) -> Result<Self, ChannelError> {
        fn required_credential_field(
            cred: &serde_json::Value,
            key: &str,
        ) -> Result<String, ChannelError> {
            let value = cred
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ChannelError::NotConfigured(format!("missing or empty {key} in credentials"))
                })?;
            Ok(value.to_string())
        }

        let cred: serde_json::Value = serde_json::from_str(cred_json)
            .map_err(|e| ChannelError::NotConfigured(format!("invalid credential JSON: {e}")))?;

        let client_id = required_credential_field(&cred, "client_id")?;
        let client_secret = required_credential_field(&cred, "client_secret")?;
        let refresh_token = required_credential_field(&cred, "refresh_token")?;

        let (tx, rx) = mpsc::channel(64);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ChannelError::NotConfigured(format!("HTTP client build failed: {e}")))?;

        Ok(Self {
            config,
            client,
            client_id,
            client_secret,
            refresh_token,
            access_token: Arc::new(tokio::sync::RwLock::new(None)),
            inbound_tx: StdMutex::new(tx),
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            poll_handle: AsyncMutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            poll_lock: Arc::new(AsyncMutex::new(())),
            mark_read_retry_dedupe: Arc::new(AsyncMutex::new(HashMap::new())),
            scope_insufficient: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Refresh the OAuth2 access token using the stored refresh_token.
    async fn refresh_access_token(&self) -> Result<String, ChannelError> {
        refresh_token_request(
            &self.client,
            &self.client_id,
            &self.client_secret,
            &self.refresh_token,
            &self.access_token,
        )
        .await
    }

    /// Get a valid access token, refreshing if needed.
    async fn get_access_token(&self) -> Result<String, ChannelError> {
        {
            let guard = self.access_token.read().await;
            if let Some((ref tok, expiry)) = *guard {
                if Instant::now() < expiry {
                    return Ok(tok.clone());
                }
            }
        }
        self.refresh_access_token().await
    }

    /// Reset inbound sender/receiver pair for a new adapter start cycle.
    fn reset_inbound_channel(&self) -> Result<mpsc::Sender<InboundMessage>, ChannelError> {
        let (tx, rx) = mpsc::channel(64);
        let mut tx_guard = self
            .inbound_tx
            .lock()
            .map_err(|_| ChannelError::ReceiveFailed("inbound tx lock poisoned".to_string()))?;
        let mut rx_guard = self
            .inbound_rx
            .lock()
            .map_err(|_| ChannelError::ReceiveFailed("inbound rx lock poisoned".to_string()))?;
        *tx_guard = tx.clone();
        *rx_guard = Some(rx);
        Ok(tx)
    }

    /// Parse a Gmail message JSON into an `InboundMessage`.
    pub fn parse_message(msg: &serde_json::Value) -> Option<InboundMessage> {
        Self::parse_message_with_limits(msg, usize::MAX, usize::MAX)
    }

    fn parse_message_with_limits(
        msg: &serde_json::Value,
        max_attachments_per_message: usize,
        max_file_bytes: usize,
    ) -> Option<InboundMessage> {
        let id = msg.get("id").and_then(|v: &serde_json::Value| v.as_str())?;
        let thread_id = msg
            .get("threadId")
            .and_then(|v: &serde_json::Value| v.as_str())
            .unwrap_or("")
            .to_string();

        let headers = msg
            .pointer("/payload/headers")
            .and_then(|v: &serde_json::Value| v.as_array())?;

        let mut from = String::new();
        let mut subject = String::new();
        let mut date = String::new();
        let mut rfc822_message_id = String::new();

        for h in headers {
            let name = h
                .get("name")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("");
            let value = h
                .get("value")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("");
            match name.to_lowercase().as_str() {
                "from" => from = value.to_string(),
                "subject" => subject = value.to_string(),
                "date" => date = value.to_string(),
                "message-id" => rfc822_message_id = value.to_string(),
                _ => {}
            }
        }

        // Extract body text from payload.
        let body = extract_body_text(msg.get("payload")?);

        let mut content_text = if subject.is_empty() {
            body.clone()
        } else if body.is_empty() {
            subject.clone()
        } else {
            format!("{subject}\n\n{body}")
        };

        // Collect attachment metadata.
        let mut attachment_refs: Vec<GmailAttachmentRef> = Vec::new();
        collect_attachment_refs(msg.get("payload")?, id, &mut attachment_refs);
        let total_attachment_count = attachment_refs.len();
        let mut kept_attachment_ids = Vec::new();
        let mut dropped_due_count = 0usize;
        let mut dropped_due_size = 0usize;
        for attachment in attachment_refs {
            if attachment.size_bytes > max_file_bytes {
                dropped_due_size += 1;
                continue;
            }
            if kept_attachment_ids.len() >= max_attachments_per_message {
                dropped_due_count += 1;
                continue;
            }
            kept_attachment_ids.push(attachment.ref_id);
        }

        let timestamp = parse_gmail_date_header(&date).unwrap_or_else(chrono::Utc::now);
        let mut metadata = HashMap::new();
        metadata.insert(
            "message_id".to_string(),
            serde_json::Value::String(id.into()),
        );
        metadata.insert(
            "thread_id".to_string(),
            serde_json::Value::String(thread_id.clone()),
        );
        metadata.insert("from".to_string(), serde_json::Value::String(from.clone()));
        metadata.insert("subject".to_string(), serde_json::Value::String(subject));
        metadata.insert("date".to_string(), serde_json::Value::String(date));
        if !rfc822_message_id.trim().is_empty() {
            metadata.insert(
                "rfc822_message_id".to_string(),
                serde_json::Value::String(rfc822_message_id.clone()),
            );
        }
        if !kept_attachment_ids.is_empty() {
            metadata.insert(
                "attachment_ids".to_string(),
                serde_json::Value::Array(
                    kept_attachment_ids
                        .iter()
                        .map(|r| serde_json::Value::String(r.clone()))
                        .collect(),
                ),
            );
            if total_attachment_count > kept_attachment_ids.len() {
                metadata.insert(
                    "attachment_ids_total_count".to_string(),
                    serde_json::Value::from(total_attachment_count as u64),
                );
            }
            if content_text.trim().is_empty() {
                content_text = format!(
                    "Email with {} attachment(s); content unavailable",
                    kept_attachment_ids.len()
                );
            }
        }
        if dropped_due_count > 0 || dropped_due_size > 0 {
            let mut notes = Vec::new();
            if dropped_due_count > 0 {
                notes.push(format!(
                    "{dropped_due_count} attachment(s) omitted by max_attachments_per_message"
                ));
            }
            if dropped_due_size > 0 {
                notes.push(format!(
                    "{dropped_due_size} attachment(s) omitted by max_file_bytes"
                ));
            }
            metadata.insert(
                "attachment_filter_note".to_string(),
                serde_json::Value::String(notes.join("; ")),
            );
            if content_text.trim().is_empty() && kept_attachment_ids.is_empty() {
                content_text = "Email with attachment(s) omitted by policy".to_string();
            }
        }

        if content_text.trim().is_empty() && kept_attachment_ids.is_empty() {
            return None;
        }

        // Extract sender email address.
        let sender_id = extract_email_address(&from);

        Some(InboundMessage {
            channel: "gmail".to_string(),
            sender_id,
            content: vec![ContentBlock::Text { text: content_text }],
            attachments: Vec::new(),
            timestamp,
            is_dm: Some(true),
            is_mention: false,
            thread_id: if thread_id.trim().is_empty() {
                None
            } else {
                Some(thread_id)
            },
            reply_to_id: if rfc822_message_id.trim().is_empty() {
                None
            } else {
                Some(rfc822_message_id)
            },
            metadata,
        })
    }
}

#[derive(Debug, Clone)]
struct GmailAttachmentRef {
    ref_id: String,
    size_bytes: usize,
}

fn parse_gmail_date_header(date: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = date.trim();
    if trimmed.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc2822(trimmed)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(trimmed))
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok()
}

/// Extract the plain-text body from a Gmail payload, recursing through MIME parts.
fn extract_body_text(payload: &serde_json::Value) -> String {
    // Try direct body data on this part.
    let mime_type = payload
        .get("mimeType")
        .and_then(|v: &serde_json::Value| v.as_str())
        .unwrap_or("");

    if mime_type == "text/plain" {
        if let Some(data) = payload
            .pointer("/body/data")
            .and_then(|v: &serde_json::Value| v.as_str())
        {
            if let Ok(decoded) = base64_url_decode(data) {
                return decoded;
            }
        }
    }

    // Recurse into parts.
    if let Some(parts) = payload.get("parts").and_then(|v| v.as_array()) {
        // Prefer text/plain over text/html.
        for part in parts {
            let part_mime = part.get("mimeType").and_then(|v| v.as_str()).unwrap_or("");
            if part_mime == "text/plain" {
                if let Some(data) = part.pointer("/body/data").and_then(|v| v.as_str()) {
                    if let Ok(decoded) = base64_url_decode(data) {
                        return decoded;
                    }
                }
            }
            // Recurse for multipart/*
            if part_mime.starts_with("multipart/") {
                let nested = extract_body_text(part);
                if !nested.is_empty() {
                    return nested;
                }
            }
        }
        // Fallback: try text/html
        for part in parts {
            let part_mime = part.get("mimeType").and_then(|v| v.as_str()).unwrap_or("");
            if part_mime == "text/html" {
                if let Some(data) = part.pointer("/body/data").and_then(|v| v.as_str()) {
                    if let Ok(decoded) = base64_url_decode(data) {
                        return strip_html_tags(&decoded);
                    }
                }
            }
        }
    }

    String::new()
}

fn strip_html_tags(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        raw.to_string()
    } else {
        collapsed
    }
}

/// Collect attachment IDs from a Gmail message payload.
fn collect_attachment_refs(
    payload: &serde_json::Value,
    message_id: &str,
    refs: &mut Vec<GmailAttachmentRef>,
) {
    if let Some(filename) = payload.get("filename").and_then(|v| v.as_str()) {
        if !filename.is_empty() {
            if let Some(att_id) = payload
                .pointer("/body/attachmentId")
                .and_then(|v| v.as_str())
            {
                let size_bytes = payload
                    .pointer("/body/size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_default() as usize;
                refs.push(GmailAttachmentRef {
                    ref_id: format!("{message_id}/{att_id}"),
                    size_bytes,
                });
            }
        }
    }
    if let Some(parts) = payload.get("parts").and_then(|v| v.as_array()) {
        for part in parts {
            collect_attachment_refs(part, message_id, refs);
        }
    }
}

/// Decode base64url-encoded data (Gmail's encoding).
fn base64_url_decode(data: &str) -> Result<String, ChannelError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| ChannelError::ReceiveFailed(format!("base64url decode failed: {e}")))?;
    String::from_utf8(bytes)
        .map_err(|e| ChannelError::ReceiveFailed(format!("UTF-8 decode failed: {e}")))
}

/// Minimal percent-encoding for URL query/form values.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn build_unread_query(label: &str, allowed_senders: &[String]) -> String {
    let label = label.trim();
    let mut query = if label.is_empty() || label.eq_ignore_ascii_case("UNREAD") {
        "is:unread".to_string()
    } else if looks_like_query_expression(label) {
        let lower = label.to_ascii_lowercase();
        if lower.contains("is:unread") {
            label.to_string()
        } else {
            format!("is:unread {label}")
        }
    } else {
        format!("is:unread {}", build_label_filter_clause(label))
    };

    if !allowed_senders.is_empty() {
        let sender_filter = if allowed_senders.len() == 1 {
            format!("from:{}", allowed_senders[0].trim())
        } else {
            let joined = allowed_senders
                .iter()
                .map(|sender| format!("from:{}", sender.trim()))
                .collect::<Vec<_>>()
                .join(" OR ");
            format!("({joined})")
        };
        query.push(' ');
        query.push_str(&sender_filter);
    }
    query
}

fn looks_like_query_expression(filter: &str) -> bool {
    filter.contains(':') || filter.contains('(') || filter.contains(')')
}

fn build_label_filter_clause(label: &str) -> String {
    if label.chars().any(char::is_whitespace) || label.contains('"') || label.contains('\\') {
        format!("label:\"{}\"", escape_query_phrase(label))
    } else {
        format!("label:{label}")
    }
}

fn escape_query_phrase(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn sender_is_allowed(allowed_senders: &[String], sender_id: &str) -> bool {
    if allowed_senders.is_empty() {
        return true;
    }
    let normalized = GmailConfig::normalize_sender_id(sender_id);
    allowed_senders.iter().any(|s| s == &normalized)
}

/// Extract email address from a "From" header value like "Name <email@example.com>".
fn extract_email_address(from: &str) -> String {
    if let Some(start) = from.rfind('<') {
        if let Some(end) = from.rfind('>') {
            if end > start {
                return from[start + 1..end].trim().to_ascii_lowercase();
            }
        }
    }
    from.trim().to_ascii_lowercase()
}

fn extract_outbound_text(msg: &OutboundMessage) -> String {
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

fn validate_header_value(value: &str, field: &str) -> Result<String, ChannelError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(ChannelError::SendFailed(format!(
            "invalid {field}: header injection attempt"
        )));
    }
    Ok(value.trim().to_string())
}

fn build_raw_mime_email(
    target_email: &str,
    body_text: &str,
    reply_to_id: Option<&str>,
    subject: Option<&str>,
) -> Result<String, ChannelError> {
    use base64::Engine;

    let to = validate_header_value(target_email, "target email")?;
    if to.is_empty() {
        return Err(ChannelError::SendFailed(
            "target email must not be empty".to_string(),
        ));
    }
    let body = body_text.trim();
    if body.is_empty() {
        return Err(ChannelError::SendFailed(
            "gmail outbound message has no text content".to_string(),
        ));
    }
    let subject = validate_header_value(
        subject
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("EncMind reply"),
        "subject",
    )?;

    let mut headers = vec![
        format!("To: {to}"),
        format!("Subject: {subject}"),
        "MIME-Version: 1.0".to_string(),
        "Content-Type: text/plain; charset=\"UTF-8\"".to_string(),
        "Content-Transfer-Encoding: 8bit".to_string(),
    ];
    if let Some(reply) = reply_to_id.map(str::trim).filter(|s| !s.is_empty()) {
        let clean = validate_header_value(reply, "reply_to_id")?;
        headers.push(format!("In-Reply-To: {clean}"));
        headers.push(format!("References: {clean}"));
    }
    headers.push(String::new());
    headers.push(body.to_string());

    let mime = headers.join("\r\n");
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mime.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GmailPushNotification {
    email_address: Option<String>,
    history_id: Option<String>,
}

fn parse_gmail_push_notification(
    payload: &serde_json::Value,
) -> Result<GmailPushNotification, ChannelError> {
    fn from_notification_json(
        value: &serde_json::Value,
    ) -> Result<GmailPushNotification, ChannelError> {
        let email_address = value
            .get("emailAddress")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let history_id = value
            .get("historyId")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                value
                    .get("historyId")
                    .and_then(|v| v.as_u64())
                    .map(|v| v.to_string())
            });

        if email_address.is_none() && history_id.is_none() {
            return Err(ChannelError::ReceiveFailed(
                "invalid gmail push payload: missing emailAddress/historyId".to_string(),
            ));
        }

        Ok(GmailPushNotification {
            email_address,
            history_id,
        })
    }

    if payload.get("message").is_some() {
        let message = payload
            .get("message")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                ChannelError::ReceiveFailed(
                    "invalid gmail push payload: message is not object".to_string(),
                )
            })?;
        if let Some(data) = message.get("data").and_then(|v| v.as_str()) {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(data)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data))
                .map_err(|e| {
                    ChannelError::ReceiveFailed(format!(
                        "invalid gmail push payload: failed to decode message.data: {e}"
                    ))
                })?;
            let body = serde_json::from_slice::<serde_json::Value>(&decoded).map_err(|e| {
                ChannelError::ReceiveFailed(format!(
                    "invalid gmail push payload: message.data is not JSON: {e}"
                ))
            })?;
            return from_notification_json(&body);
        }
        return Err(ChannelError::ReceiveFailed(
            "invalid gmail push payload: message.data is missing".to_string(),
        ));
    }

    from_notification_json(payload)
}

#[async_trait::async_trait]
impl ChannelAdapter for GmailAdapter {
    async fn start(&self) -> Result<(), ChannelError> {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ChannelError::ReceiveFailed(
                "Gmail adapter already running".into(),
            ));
        }
        let mut running_guard = RunningFlagGuard::new(self.running.clone());
        self.scope_insufficient.store(false, Ordering::SeqCst);
        {
            let mut dedupe = self.mark_read_retry_dedupe.lock().await;
            dedupe.clear();
        }

        // Create a fresh inbound channel on each start to make stop/start reuse safe.
        let tx = self.reset_inbound_channel()?;

        let cancel = CancellationToken::new();
        let poll_cancel = cancel.clone();
        let client = self.client.clone();
        let access_token = self.access_token.clone();
        let client_id = self.client_id.clone();
        let client_secret = self.client_secret.clone();
        let refresh_token_val = self.refresh_token.clone();
        let poll_secs = self.config.poll_interval_secs;
        let label = self.config.label_filter.clone();
        let query_allowed_senders = self.config.query_allowed_sender_ids();
        let allowed_senders = self.config.normalized_allowed_sender_ids();
        let max_attachments_per_message = self.config.max_attachments_per_message;
        let max_file_bytes = self.config.max_file_bytes;
        let running = self.running.clone();
        let poll_lock = self.poll_lock.clone();
        let mark_read_retry_dedupe = self.mark_read_retry_dedupe.clone();
        let scope_insufficient = self.scope_insufficient.clone();

        {
            let mut cancel_slot = self.cancel.lock().await;
            *cancel_slot = cancel.clone();
        }

        let handle = tokio::spawn(async move {
            let _task_running_guard = RunningFlagGuard::new(running.clone());
            let mut backoff_multiplier = 1u64;
            let poll_params = GmailPollParams {
                access_token: &access_token,
                client_id: &client_id,
                client_secret: &client_secret,
                refresh_token: &refresh_token_val,
                label: &label,
                query_allowed_senders: &query_allowed_senders,
                allowed_senders: &allowed_senders,
                tx: &tx,
                cancel: Some(&poll_cancel),
                mark_read_retry_dedupe: &mark_read_retry_dedupe,
                max_attachments_per_message,
                max_file_bytes,
            };
            if let Err(e) = poll_gmail_with_lock(&client, &poll_params, &poll_lock).await {
                tracing::warn!("Gmail initial poll error: {e}");
                if is_scope_insufficient_message(&e.to_string()) {
                    scope_insufficient.store(true, Ordering::SeqCst);
                    tracing::warn!(
                        "Gmail polling stopped due to insufficient OAuth scopes; re-login with gmail.modify and gmail.send scopes"
                    );
                    return;
                }
                if is_rate_limited_message(&e.to_string()) {
                    backoff_multiplier = 2;
                    tracing::warn!(
                        backoff_seconds = poll_secs.saturating_mul(backoff_multiplier),
                        "gmail polling backing off after rate-limit response"
                    );
                }
            }
            loop {
                let sleep_for =
                    Duration::from_secs(poll_secs.saturating_mul(backoff_multiplier.max(1)));
                tokio::select! {
                    _ = poll_cancel.cancelled() => {
                        tracing::info!("Gmail poll loop cancelled");
                        break;
                    }
                    _ = tokio::time::sleep(sleep_for) => {
                        let poll_params = GmailPollParams {
                            access_token: &access_token,
                            client_id: &client_id,
                            client_secret: &client_secret,
                            refresh_token: &refresh_token_val,
                            label: &label,
                            query_allowed_senders: &query_allowed_senders,
                            allowed_senders: &allowed_senders,
                            tx: &tx,
                            cancel: Some(&poll_cancel),
                            mark_read_retry_dedupe: &mark_read_retry_dedupe,
                            max_attachments_per_message,
                            max_file_bytes,
                        };
                        match poll_gmail_with_lock(&client, &poll_params, &poll_lock)
                        .await {
                            Ok(()) => {
                                if backoff_multiplier > 1 {
                                    tracing::info!("gmail polling recovered; resetting backoff");
                                }
                                backoff_multiplier = 1;
                            }
                            Err(e) => {
                                tracing::warn!("Gmail poll error: {e}");
                                if is_scope_insufficient_message(&e.to_string()) {
                                    scope_insufficient.store(true, Ordering::SeqCst);
                                    tracing::warn!(
                                        "Gmail polling stopped due to insufficient OAuth scopes; re-login with gmail.modify and gmail.send scopes"
                                    );
                                    break;
                                }
                                if is_rate_limited_message(&e.to_string()) {
                                    backoff_multiplier = (backoff_multiplier * 2)
                                        .min(GMAIL_MAX_POLL_BACKOFF_MULTIPLIER);
                                    tracing::warn!(
                                        backoff_seconds = poll_secs.saturating_mul(backoff_multiplier),
                                        "gmail polling backing off after rate-limit response"
                                    );
                                } else {
                                    backoff_multiplier = 1;
                                }
                            }
                        }
                    }
                }
            }
        });

        *self.poll_handle.lock().await = Some(handle);
        running_guard.disarm();
        Ok(())
    }

    async fn stop(&self) -> Result<(), ChannelError> {
        {
            let cancel = self.cancel.lock().await;
            cancel.cancel();
        }
        let maybe_handle = self.poll_handle.lock().await.take();
        if let Some(h) = maybe_handle {
            let _ = h.await;
        }
        Ok(())
    }

    async fn send_message(
        &self,
        target: &ChannelTarget,
        msg: &OutboundMessage,
    ) -> Result<(), ChannelError> {
        let text = extract_outbound_text(msg);
        let raw = build_raw_mime_email(
            &target.target_id,
            &text,
            msg.reply_to_id.as_deref(),
            msg.subject.as_deref(),
        )?;
        let token = self.get_access_token().await?;

        let mut body = serde_json::json!({
            "raw": raw,
        });
        if let Some(thread_id) = msg
            .thread_id
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            body["threadId"] = serde_json::Value::String(thread_id.to_string());
        }

        let resp = self
            .client
            .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ChannelError::SendFailed(format!("Gmail send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if is_scope_insufficient_message(&body) {
                self.scope_insufficient.store(true, Ordering::SeqCst);
            }
            return Err(ChannelError::SendFailed(format!(
                "Gmail send failed (HTTP {status}): {body}"
            )));
        }

        Ok(())
    }

    fn inbound(&self) -> Pin<Box<dyn Stream<Item = InboundMessage> + Send>> {
        let mut guard = match self.inbound_rx.lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::warn!("inbound rx lock poisoned; returning inert gmail stream");
                let (_tx, rx) = mpsc::channel(1);
                return Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx));
            }
        };
        match guard.take() {
            Some(rx) => Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)),
            None => {
                tracing::warn!(
                    "gmail inbound stream requested with no active receiver; returning inert stream"
                );
                let (_tx, rx) = mpsc::channel(1);
                Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
            }
        }
    }

    fn health_status(&self) -> ChannelAccountStatus {
        if self.scope_insufficient.load(Ordering::SeqCst) {
            return ChannelAccountStatus::Degraded;
        }
        if self.running.load(Ordering::SeqCst) {
            ChannelAccountStatus::Active
        } else {
            ChannelAccountStatus::Stopped
        }
    }

    async fn probe(&self) -> Result<(), ChannelError> {
        let token = self.get_access_token().await?;
        let result = probe_gmail(&self.client, &token).await;
        if let Err(e) = &result {
            if is_scope_insufficient_message(&e.to_string()) {
                self.scope_insufficient.store(true, Ordering::SeqCst);
            }
        }
        result
    }

    async fn handle_webhook(&self, payload: serde_json::Value) -> Result<(), ChannelError> {
        let notification = parse_gmail_push_notification(&payload)?;
        tracing::info!(
            email = ?notification.email_address,
            history_id = ?notification.history_id,
            "received gmail push notification; polling for updates"
        );
        let Ok(_guard) = self.poll_lock.try_lock() else {
            tracing::debug!("gmail webhook poll skipped; poll loop already in progress");
            return Ok(());
        };
        let tx = {
            let tx_guard = self
                .inbound_tx
                .lock()
                .map_err(|_| ChannelError::ReceiveFailed("inbound tx lock poisoned".to_string()))?;
            tx_guard.clone()
        };
        let query_allowed_senders = self.config.query_allowed_sender_ids();
        let allowed_senders = self.config.normalized_allowed_sender_ids();
        let poll_params = GmailPollParams {
            access_token: &self.access_token,
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            refresh_token: &self.refresh_token,
            label: &self.config.label_filter,
            query_allowed_senders: &query_allowed_senders,
            allowed_senders: &allowed_senders,
            tx: &tx,
            cancel: None,
            mark_read_retry_dedupe: &self.mark_read_retry_dedupe,
            max_attachments_per_message: self.config.max_attachments_per_message,
            max_file_bytes: self.config.max_file_bytes,
        };
        poll_gmail(&self.client, &poll_params).await
    }
}

fn is_scope_insufficient_message(message: &str) -> bool {
    message.contains("ACCESS_TOKEN_SCOPE_INSUFFICIENT")
        || message.contains("insufficientPermissions")
        || message.contains("Insufficient Permission")
}

fn is_rate_limited_message(message: &str) -> bool {
    message.contains("HTTP 429")
        || message.contains("Too Many Requests")
        || message.contains("\"code\": 429")
}

fn compute_token_cache_ttl_secs(expires_in: u64) -> u64 {
    let refresh_buffer = GMAIL_TOKEN_REFRESH_BUFFER_SECS.min(expires_in.saturating_div(2));
    expires_in.saturating_sub(refresh_buffer).max(1)
}

async fn should_skip_mark_read_retry(
    dedupe: &AsyncMutex<HashMap<String, Instant>>,
    msg_id: &str,
) -> bool {
    let now = Instant::now();
    let mut cache = dedupe.lock().await;
    cache.retain(|_, seen_at| now.duration_since(*seen_at) < MARK_READ_RETRY_DEDUPE_TTL);
    cache
        .get(msg_id)
        .is_some_and(|seen_at| now.duration_since(*seen_at) < MARK_READ_RETRY_DEDUPE_TTL)
}

async fn record_mark_read_retry(dedupe: &AsyncMutex<HashMap<String, Instant>>, msg_id: &str) {
    let now = Instant::now();
    let mut cache = dedupe.lock().await;
    cache.retain(|_, seen_at| now.duration_since(*seen_at) < MARK_READ_RETRY_DEDUPE_TTL);
    if cache.len() >= MARK_READ_RETRY_DEDUPE_MAX {
        let mut oldest_key: Option<String> = None;
        let mut oldest_seen = now;
        for (key, seen) in cache.iter() {
            if *seen <= oldest_seen {
                oldest_seen = *seen;
                oldest_key = Some(key.clone());
            }
        }
        if let Some(key) = oldest_key {
            cache.remove(&key);
        }
    }
    cache.insert(msg_id.to_string(), now);
}

async fn mark_message_read_or_defer(
    client: &reqwest::Client,
    token: &str,
    msg_id: &str,
    dedupe: &AsyncMutex<HashMap<String, Instant>>,
) -> Result<(), ChannelError> {
    match mark_message_read(client, token, msg_id).await {
        Ok(()) => {
            tracing::debug!("Gmail mark-as-read succeeded for {msg_id}");
            Ok(())
        }
        Err(e) => {
            if is_scope_insufficient_message(&e.to_string()) {
                return Err(e);
            }
            record_mark_read_retry(dedupe, msg_id).await;
            tracing::warn!(
                "Gmail mark-as-read deferred for {msg_id}; retrying after cooldown: {e}"
            );
            Ok(())
        }
    }
}

struct GmailPollParams<'a> {
    access_token: &'a tokio::sync::RwLock<Option<(String, Instant)>>,
    client_id: &'a str,
    client_secret: &'a str,
    refresh_token: &'a str,
    label: &'a str,
    query_allowed_senders: &'a [String],
    allowed_senders: &'a [String],
    tx: &'a mpsc::Sender<InboundMessage>,
    cancel: Option<&'a CancellationToken>,
    mark_read_retry_dedupe: &'a AsyncMutex<HashMap<String, Instant>>,
    max_attachments_per_message: usize,
    max_file_bytes: usize,
}

/// Verify Gmail API access by calling the profile endpoint.
async fn probe_gmail(client: &reqwest::Client, token: &str) -> Result<(), ChannelError> {
    let resp = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/profile")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| ChannelError::ReceiveFailed(format!("Gmail probe failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body: String = resp.text().await.unwrap_or_default();
        return Err(ChannelError::ReceiveFailed(format!(
            "Gmail probe failed (HTTP {status}): {body}"
        )));
    }
    Ok(())
}

/// Poll Gmail for unread messages and send them to the inbound channel.
async fn poll_gmail(
    client: &reqwest::Client,
    params: &GmailPollParams<'_>,
) -> Result<(), ChannelError> {
    // Get or refresh token.
    let token = {
        let guard = params.access_token.read().await;
        if let Some((ref tok, expiry)) = *guard {
            if Instant::now() < expiry {
                tok.clone()
            } else {
                drop(guard);
                refresh_token_request(
                    client,
                    params.client_id,
                    params.client_secret,
                    params.refresh_token,
                    params.access_token,
                )
                .await?
            }
        } else {
            drop(guard);
            refresh_token_request(
                client,
                params.client_id,
                params.client_secret,
                params.refresh_token,
                params.access_token,
            )
            .await?
        }
    };

    // List unread messages (build query string manually since reqwest "query" feature is not enabled).
    let raw_query = build_unread_query(params.label, params.query_allowed_senders);
    tracing::debug!(
        query = %raw_query,
        query_allowed_senders = ?params.query_allowed_senders,
        allowed_senders = ?params.allowed_senders,
        "gmail unread poll query"
    );
    let q = percent_encode(&raw_query);
    let mut message_ids: Vec<String> = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..GMAIL_MAX_LIST_PAGES {
        let mut list_url = format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?q={q}&maxResults={GMAIL_LIST_PAGE_SIZE}"
        );
        if let Some(token_value) = page_token.as_ref() {
            list_url.push_str("&pageToken=");
            list_url.push_str(&percent_encode(token_value));
        }
        let list_resp = client
            .get(&list_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(format!("Gmail list failed: {e}")))?;

        if !list_resp.status().is_success() {
            let status = list_resp.status();
            let body = list_resp.text().await.unwrap_or_default();
            return Err(ChannelError::ReceiveFailed(format!(
                "Gmail list failed (HTTP {status}): {body}"
            )));
        }

        let list_json = list_resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(format!("Gmail list parse failed: {e}")))?;

        if let Some(messages) = list_json
            .get("messages")
            .and_then(|v: &serde_json::Value| v.as_array())
        {
            for msg_ref in messages {
                if let Some(msg_id) = msg_ref
                    .get("id")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    message_ids.push(msg_id.to_string());
                }
            }
        }

        page_token = list_json
            .get("nextPageToken")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        if page_token.is_none() {
            break;
        }
    }
    if page_token.is_some() {
        tracing::warn!(
            page_cap = GMAIL_MAX_LIST_PAGES,
            page_size = GMAIL_LIST_PAGE_SIZE,
            fetched_message_ids = message_ids.len(),
            "gmail unread pagination capped; remaining unread messages will be processed in later polls"
        );
    }

    if message_ids.is_empty() {
        return Ok(());
    }

    for msg_id in message_ids {
        if params.cancel.is_some_and(|c| c.is_cancelled()) {
            tracing::debug!("gmail poll loop cancellation observed during message batch");
            break;
        }
        let msg_id = msg_id.as_str();

        if should_skip_mark_read_retry(params.mark_read_retry_dedupe, msg_id).await {
            tracing::debug!("skipping Gmail message {msg_id} due to mark-as-read retry cooldown");
            continue;
        }

        // Fetch full message.
        let msg_url =
            format!("https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full");
        let msg_resp = client
            .get(&msg_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(format!("Gmail fetch msg failed: {e}")))?;

        if !msg_resp.status().is_success() {
            let status = msg_resp.status();
            tracing::warn!("Gmail fetch message {msg_id} failed: HTTP {}", status);
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let body = msg_resp.text().await.unwrap_or_default();
                return Err(ChannelError::ReceiveFailed(format!(
                    "Gmail fetch message rate-limited (HTTP {status}): {body}"
                )));
            }
            // Ack non-retryable client-side fetch failures to avoid infinite loops
            // on permanently bad message IDs/payload availability.
            if status.is_client_error() {
                if let Err(e) = mark_message_read_or_defer(
                    client,
                    &token,
                    msg_id,
                    params.mark_read_retry_dedupe,
                )
                .await
                {
                    tracing::warn!("Gmail mark-as-read failed for {msg_id}: {e}");
                    if is_scope_insufficient_message(&e.to_string()) {
                        return Err(ChannelError::ReceiveFailed(format!(
                            "Gmail polling halted due to insufficient OAuth scopes: {e}"
                        )));
                    }
                }
            }
            continue;
        }

        let msg_json: serde_json::Value = match msg_resp.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Gmail parse message {msg_id} failed: {e}");
                // Ack permanently malformed message payloads to avoid repeated retries.
                if let Err(mark_err) = mark_message_read_or_defer(
                    client,
                    &token,
                    msg_id,
                    params.mark_read_retry_dedupe,
                )
                .await
                {
                    tracing::warn!("Gmail mark-as-read failed for {msg_id}: {mark_err}");
                    if is_scope_insufficient_message(&mark_err.to_string()) {
                        return Err(ChannelError::ReceiveFailed(format!(
                            "Gmail polling halted due to insufficient OAuth scopes: {mark_err}"
                        )));
                    }
                }
                continue;
            }
        };

        let mut should_mark_read = false;

        if let Some(inbound) = GmailAdapter::parse_message_with_limits(
            &msg_json,
            params.max_attachments_per_message,
            params.max_file_bytes,
        ) {
            if !sender_is_allowed(params.allowed_senders, &inbound.sender_id) {
                // Sender filtering is an intake policy decision. Acknowledge as read
                // to avoid endless re-fetch loops for non-allowed senders.
                tracing::debug!(
                    sender = %inbound.sender_id,
                    msg_id = %msg_id,
                    "skipping Gmail message from non-allowed sender"
                );
                if let Err(e) = mark_message_read_or_defer(
                    client,
                    &token,
                    msg_id,
                    params.mark_read_retry_dedupe,
                )
                .await
                {
                    tracing::warn!("Gmail mark-as-read failed for {msg_id}: {e}");
                    if is_scope_insufficient_message(&e.to_string()) {
                        return Err(ChannelError::ReceiveFailed(format!(
                            "Gmail polling halted due to insufficient OAuth scopes: {e}"
                        )));
                    }
                }
                continue;
            }
            match params.tx.send(inbound).await {
                Ok(()) => {
                    should_mark_read = true;
                }
                Err(e) => {
                    tracing::warn!("Gmail enqueue message {msg_id} failed: {e}");
                }
            }
        } else {
            tracing::warn!("Gmail parse message {msg_id} produced empty/invalid message");
            // Prevent endless retry loops for malformed/empty messages.
            should_mark_read = true;
        }

        if should_mark_read {
            if let Err(e) =
                mark_message_read_or_defer(client, &token, msg_id, params.mark_read_retry_dedupe)
                    .await
            {
                tracing::warn!("Gmail mark-as-read failed for {msg_id}: {e}");
                if is_scope_insufficient_message(&e.to_string()) {
                    return Err(ChannelError::ReceiveFailed(format!(
                        "Gmail polling halted due to insufficient OAuth scopes: {e}"
                    )));
                }
            }
        }
    }

    Ok(())
}

async fn poll_gmail_with_lock(
    client: &reqwest::Client,
    params: &GmailPollParams<'_>,
    poll_lock: &AsyncMutex<()>,
) -> Result<(), ChannelError> {
    let _guard = poll_lock.lock().await;
    poll_gmail(client, params).await
}

async fn mark_message_read(
    client: &reqwest::Client,
    token: &str,
    msg_id: &str,
) -> Result<(), ChannelError> {
    let modify_url =
        format!("https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/modify");
    let modify_body = serde_json::json!({ "removeLabelIds": ["UNREAD"] });
    let resp = client
        .post(&modify_url)
        .bearer_auth(token)
        .json(&modify_body)
        .send()
        .await
        .map_err(|e| ChannelError::ReceiveFailed(format!("mark-as-read request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ChannelError::ReceiveFailed(format!(
            "mark-as-read failed (HTTP {status}): {body}"
        )));
    }

    Ok(())
}

/// Standalone token refresh for use inside the poll loop.
async fn refresh_token_request(
    client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
    token_cache: &tokio::sync::RwLock<Option<(String, Instant)>>,
) -> Result<String, ChannelError> {
    // Build URL-encoded form body manually (reqwest "form" feature not enabled).
    let form_body = format!(
        "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
        percent_encode(client_id),
        percent_encode(client_secret),
        percent_encode(refresh_token),
    );
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await
        .map_err(|e| ChannelError::ReceiveFailed(format!("token refresh failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ChannelError::ReceiveFailed(format!(
            "token refresh failed (HTTP {status}): {body}"
        )));
    }

    let json = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|e| ChannelError::ReceiveFailed(format!("token parse failed: {e}")))?;

    let token = json["access_token"]
        .as_str()
        .ok_or_else(|| ChannelError::ReceiveFailed("missing access_token in response".into()))?
        .to_string();

    let expires_in = json["expires_in"].as_u64().unwrap_or(3600);
    let cache_ttl = compute_token_cache_ttl_secs(expires_in);
    let expiry = Instant::now() + Duration::from_secs(cache_ttl);
    *token_cache.write().await = Some((token.clone(), expiry));
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_credentials() -> String {
        serde_json::json!({
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "refresh_token": "test-refresh-token"
        })
        .to_string()
    }

    #[test]
    fn from_config_and_credentials_parses_valid() {
        let config = GmailConfig::default();
        let adapter = GmailAdapter::from_config_and_credentials(config, &sample_credentials());
        assert!(adapter.is_ok());
        let a = adapter.unwrap();
        assert_eq!(a.client_id, "test-client-id");
        assert_eq!(a.client_secret, "test-client-secret");
        assert_eq!(a.refresh_token, "test-refresh-token");
    }

    #[test]
    fn from_config_and_credentials_rejects_missing_refresh_token() {
        let cred = serde_json::json!({
            "client_id": "cid",
            "client_secret": "csec"
        })
        .to_string();
        let config = GmailConfig::default();
        let result = GmailAdapter::from_config_and_credentials(config, &cred);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing or empty refresh_token"));
    }

    #[test]
    fn from_config_and_credentials_rejects_missing_client_id() {
        let cred = serde_json::json!({
            "client_secret": "csec",
            "refresh_token": "rt"
        })
        .to_string();
        let config = GmailConfig::default();
        let result = GmailAdapter::from_config_and_credentials(config, &cred);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing or empty client_id"));
    }

    #[test]
    fn from_config_and_credentials_rejects_empty_client_secret() {
        let cred = serde_json::json!({
            "client_id": "cid",
            "client_secret": "   ",
            "refresh_token": "rt"
        })
        .to_string();
        let config = GmailConfig::default();
        let result = GmailAdapter::from_config_and_credentials(config, &cred);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing or empty client_secret"));
    }

    #[test]
    fn parse_message_extracts_fields() {
        let msg = serde_json::json!({
            "id": "msg123",
            "threadId": "thread456",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    { "name": "From", "value": "Alice <alice@example.com>" },
                    { "name": "Subject", "value": "Hello World" },
                    { "name": "Date", "value": "Mon, 1 Jan 2026 00:00:00 +0000" }
                ],
                "body": {
                    "data": "SGVsbG8gZnJvbSBHbWFpbA"
                }
            }
        });
        let inbound = GmailAdapter::parse_message(&msg).expect("should parse");
        assert_eq!(inbound.sender_id, "alice@example.com");
        assert_eq!(inbound.channel, "gmail");
        assert_eq!(inbound.is_dm, Some(true));
        let text = match &inbound.content[0] {
            ContentBlock::Text { text } => text.clone(),
            _ => panic!("expected Text content block"),
        };
        assert!(text.contains("Hello World"));
        assert!(text.contains("Hello from Gmail"));
        let meta = &inbound.metadata;
        assert_eq!(
            meta.get("message_id")
                .and_then(|v: &serde_json::Value| v.as_str()),
            Some("msg123")
        );
        assert_eq!(
            meta.get("thread_id")
                .and_then(|v: &serde_json::Value| v.as_str()),
            Some("thread456")
        );
    }

    #[test]
    fn parse_message_uses_date_header_for_timestamp() {
        let msg = serde_json::json!({
            "id": "msg-date",
            "threadId": "thread-date",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    { "name": "From", "value": "Alice <alice@example.com>" },
                    { "name": "Subject", "value": "Timestamp test" },
                    { "name": "Date", "value": "Mon, 01 Jan 2024 10:20:30 +0000" }
                ],
                "body": { "data": "aGVsbG8" }
            }
        });
        let inbound = GmailAdapter::parse_message(&msg).expect("should parse");
        assert_eq!(
            inbound.timestamp,
            chrono::DateTime::parse_from_rfc2822("Mon, 01 Jan 2024 10:20:30 +0000")
                .unwrap()
                .with_timezone(&chrono::Utc)
        );
    }

    #[test]
    fn parse_message_enforces_attachment_limits() {
        let msg = serde_json::json!({
            "id": "msg-limits",
            "threadId": "thread-limits",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    { "name": "From", "value": "Alice <alice@example.com>" },
                    { "name": "Subject", "value": "Attachment limits" }
                ],
                "parts": [
                    {
                        "mimeType": "application/pdf",
                        "filename": "first.pdf",
                        "body": { "attachmentId": "att-1", "size": 128 }
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "second.pdf",
                        "body": { "attachmentId": "att-2", "size": 256 }
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "large.pdf",
                        "body": { "attachmentId": "att-3", "size": 999999 }
                    }
                ]
            }
        });

        let inbound = GmailAdapter::parse_message_with_limits(&msg, 1, 1024).expect("should parse");
        let attachment_ids = inbound
            .metadata
            .get("attachment_ids")
            .and_then(|v| v.as_array())
            .expect("attachment ids metadata");
        assert_eq!(attachment_ids.len(), 1);
        assert_eq!(attachment_ids[0].as_str(), Some("msg-limits/att-1"));
        assert_eq!(
            inbound
                .metadata
                .get("attachment_ids_total_count")
                .and_then(|v| v.as_u64()),
            Some(3)
        );
        assert!(inbound
            .metadata
            .get("attachment_filter_note")
            .and_then(|v| v.as_str())
            .is_some_and(|note| note.contains("max_attachments_per_message")));
    }

    #[test]
    fn parse_message_sets_reply_to_id_from_message_id_header() {
        let msg = serde_json::json!({
            "id": "msg-reply",
            "threadId": "thread-reply",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    { "name": "From", "value": "Alice <alice@example.com>" },
                    { "name": "Message-ID", "value": "<abc123@example.com>" }
                ],
                "body": {
                    "data": "SGVsbG8"
                }
            }
        });
        let inbound = GmailAdapter::parse_message(&msg).expect("should parse");
        assert_eq!(inbound.reply_to_id.as_deref(), Some("<abc123@example.com>"));
        assert_eq!(
            inbound
                .metadata
                .get("rfc822_message_id")
                .and_then(|v| v.as_str()),
            Some("<abc123@example.com>")
        );
    }

    #[test]
    fn parse_message_with_attachment_metadata() {
        let msg = serde_json::json!({
            "id": "msg789",
            "threadId": "t1",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    { "name": "From", "value": "bob@example.com" },
                    { "name": "Subject", "value": "File attached" }
                ],
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": { "data": "Qm9keQ" },
                        "filename": ""
                    },
                    {
                        "mimeType": "application/pdf",
                        "filename": "doc.pdf",
                        "body": {
                            "attachmentId": "att-001",
                            "size": 12345
                        }
                    }
                ]
            }
        });
        let inbound = GmailAdapter::parse_message(&msg).expect("should parse");
        let meta = &inbound.metadata;
        let att_ids = meta
            .get("attachment_ids")
            .and_then(|v: &serde_json::Value| v.as_array())
            .expect("should have attachment_ids");
        assert_eq!(att_ids.len(), 1);
        assert_eq!(att_ids[0].as_str().unwrap(), "msg789/att-001");
    }

    #[test]
    fn parse_message_attachment_only_gets_fallback_text() {
        let msg = serde_json::json!({
            "id": "msg-att-only",
            "threadId": "t-att",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    { "name": "From", "value": "noreply@example.com" }
                ],
                "parts": [
                    {
                        "mimeType": "application/pdf",
                        "filename": "doc.pdf",
                        "body": { "attachmentId": "att-xyz" }
                    }
                ]
            }
        });
        let inbound = GmailAdapter::parse_message(&msg).expect("should parse");
        let text = match &inbound.content[0] {
            ContentBlock::Text { text } => text,
            _ => panic!("expected Text content block"),
        };
        assert!(text.contains("attachment"));
        let att_ids = inbound
            .metadata
            .get("attachment_ids")
            .and_then(|v| v.as_array())
            .expect("should have attachment metadata");
        assert_eq!(att_ids.len(), 1);
    }

    #[test]
    fn parse_message_html_fallback() {
        let msg = serde_json::json!({
            "id": "msg-html",
            "threadId": "t2",
            "payload": {
                "mimeType": "multipart/alternative",
                "headers": [
                    { "name": "From", "value": "carol@example.com" },
                    { "name": "Subject", "value": "HTML only" }
                ],
                "parts": [
                    {
                        "mimeType": "text/html",
                        "body": { "data": "PGI-SFRNTDwvYj4" },
                        "filename": ""
                    }
                ]
            }
        });
        let inbound = GmailAdapter::parse_message(&msg).expect("should parse");
        let text = match &inbound.content[0] {
            ContentBlock::Text { text } => text.clone(),
            _ => panic!("expected Text content block"),
        };
        // Should contain the decoded HTML content (fallback).
        assert!(text.contains("HTML only"));
    }

    #[test]
    fn parse_message_empty_content_without_attachments_returns_none() {
        let msg = serde_json::json!({
            "id": "msg-empty",
            "threadId": "t-empty",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    { "name": "From", "value": "empty@example.com" }
                ],
                "parts": []
            }
        });
        let parsed = GmailAdapter::parse_message(&msg);
        assert!(parsed.is_none());
    }

    #[test]
    fn extract_email_address_from_angle_brackets() {
        assert_eq!(
            extract_email_address("Alice <alice@example.com>"),
            "alice@example.com"
        );
    }

    #[test]
    fn extract_email_address_plain() {
        assert_eq!(extract_email_address("bob@example.com"), "bob@example.com");
    }

    #[test]
    fn extract_email_address_normalizes_case_and_whitespace() {
        assert_eq!(
            extract_email_address("  Alice <Alice.Example@Example.COM>  "),
            "alice.example@example.com"
        );
    }

    #[test]
    fn build_unread_query_without_allowed_senders() {
        assert_eq!(build_unread_query("INBOX", &[]), "is:unread label:INBOX");
    }

    #[test]
    fn build_unread_query_for_unread_label_uses_is_unread_only() {
        assert_eq!(build_unread_query("UNREAD", &[]), "is:unread");
    }

    #[test]
    fn build_unread_query_with_raw_expression_preserves_expression() {
        assert_eq!(
            build_unread_query("category:primary -label:trash", &[]),
            "is:unread category:primary -label:trash"
        );
    }

    #[test]
    fn build_unread_query_with_existing_is_unread_does_not_duplicate() {
        assert_eq!(
            build_unread_query("is:unread in:inbox", &[]),
            "is:unread in:inbox"
        );
    }

    #[test]
    fn build_unread_query_with_allowed_senders() {
        assert_eq!(
            build_unread_query(
                "UNREAD",
                &[
                    "alice@example.com".to_string(),
                    "bob@example.com".to_string()
                ]
            ),
            "is:unread (from:alice@example.com OR from:bob@example.com)"
        );
    }

    #[test]
    fn build_unread_query_with_hyphenated_label_uses_label_filter() {
        assert_eq!(
            build_unread_query("my-label", &[]),
            "is:unread label:my-label"
        );
    }

    #[test]
    fn build_unread_query_with_spaced_label_quotes_label_filter() {
        assert_eq!(
            build_unread_query("My Label", &[]),
            "is:unread label:\"My Label\""
        );
    }

    #[test]
    fn build_unread_query_with_quoted_label_escapes_phrase() {
        assert_eq!(
            build_unread_query("my \"label\"", &[]),
            "is:unread label:\"my \\\"label\\\"\""
        );
    }

    #[test]
    fn sender_is_allowed_empty_allows_any_sender() {
        assert!(sender_is_allowed(&[], "any@example.com"));
    }

    #[test]
    fn sender_is_allowed_matches_case_insensitively() {
        let allowed = vec!["owner@example.com".to_string()];
        assert!(sender_is_allowed(&allowed, "OWNER@EXAMPLE.COM"));
        assert!(!sender_is_allowed(&allowed, "other@example.com"));
    }

    #[test]
    fn build_raw_mime_email_encodes_message() {
        use base64::Engine;
        let raw = build_raw_mime_email(
            "user@example.com",
            "hello from encmind",
            Some("<reply-1@example.com>"),
            Some("Re: hello"),
        )
        .expect("should build raw mime");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .expect("should decode raw");
        let mime = String::from_utf8(decoded).expect("utf8");
        assert!(mime.contains("To: user@example.com"));
        assert!(mime.contains("In-Reply-To: <reply-1@example.com>"));
        assert!(mime.contains("hello from encmind"));
    }

    #[test]
    fn build_raw_mime_email_rejects_header_injection() {
        let err = build_raw_mime_email(
            "user@example.com\r\nBcc:evil@example.com",
            "hello",
            None,
            None,
        )
        .expect_err("should reject injected header");
        assert!(err.to_string().contains("header injection"));
    }

    #[test]
    fn parse_gmail_push_notification_direct_json() {
        let payload = serde_json::json!({
            "emailAddress": "alerts@example.com",
            "historyId": "987654321"
        });
        let parsed = parse_gmail_push_notification(&payload).expect("should parse");
        assert_eq!(parsed.email_address.as_deref(), Some("alerts@example.com"));
        assert_eq!(parsed.history_id.as_deref(), Some("987654321"));
    }

    #[test]
    fn parse_gmail_push_notification_pubsub_envelope() {
        use base64::Engine;
        let body = serde_json::json!({
            "emailAddress": "alerts@example.com",
            "historyId": "12345"
        })
        .to_string();
        let encoded = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
        let payload = serde_json::json!({
            "message": {
                "data": encoded
            }
        });
        let parsed = parse_gmail_push_notification(&payload).expect("should parse");
        assert_eq!(parsed.email_address.as_deref(), Some("alerts@example.com"));
        assert_eq!(parsed.history_id.as_deref(), Some("12345"));
    }

    #[test]
    fn parse_gmail_push_notification_rejects_invalid_payload() {
        let payload = serde_json::json!({"unexpected": true});
        let err = parse_gmail_push_notification(&payload).expect_err("should reject");
        assert!(err.to_string().contains("invalid gmail push payload"));
    }

    #[test]
    fn parse_gmail_push_notification_rejects_pubsub_without_data() {
        let payload = serde_json::json!({
            "message": {
                "messageId": "123"
            }
        });
        let err = parse_gmail_push_notification(&payload).expect_err("should reject");
        assert!(err.to_string().contains("message.data is missing"));
    }

    #[test]
    fn scope_insufficient_detection_matches_google_error_markers() {
        assert!(is_scope_insufficient_message(
            "ACCESS_TOKEN_SCOPE_INSUFFICIENT"
        ));
        assert!(is_scope_insufficient_message("insufficientPermissions"));
        assert!(is_scope_insufficient_message("Insufficient Permission"));
        assert!(!is_scope_insufficient_message("network timeout"));
    }

    #[test]
    fn rate_limited_detection_matches_google_error_markers() {
        assert!(is_rate_limited_message("HTTP 429"));
        assert!(is_rate_limited_message("Too Many Requests"));
        assert!(is_rate_limited_message(r#""code": 429"#));
        assert!(!is_rate_limited_message("HTTP 403"));
    }

    #[test]
    fn compute_token_cache_ttl_uses_half_lifetime_for_short_tokens() {
        assert_eq!(compute_token_cache_ttl_secs(10), 5);
        assert_eq!(compute_token_cache_ttl_secs(1), 1);
    }

    #[test]
    fn compute_token_cache_ttl_applies_default_refresh_buffer() {
        assert_eq!(compute_token_cache_ttl_secs(3600), 3540);
    }

    #[test]
    fn inbound_second_call_does_not_panic() {
        let config = GmailConfig::default();
        let adapter = GmailAdapter::from_config_and_credentials(config, &sample_credentials())
            .expect("should construct");
        let _first = adapter.inbound();
        let _second = adapter.inbound();
    }

    #[tokio::test]
    async fn reset_inbound_channel_supports_restart_like_stream_reopen() {
        let config = GmailConfig::default();
        let adapter = GmailAdapter::from_config_and_credentials(config, &sample_credentials())
            .expect("should construct");

        let tx_first = adapter
            .reset_inbound_channel()
            .expect("first reset should succeed");
        let mut inbound_first = adapter.inbound();
        tx_first
            .send(InboundMessage {
                channel: "gmail".to_string(),
                sender_id: "first@example.com".to_string(),
                content: vec![ContentBlock::Text {
                    text: "first".to_string(),
                }],
                attachments: vec![],
                timestamp: chrono::Utc::now(),
                is_dm: Some(true),
                is_mention: false,
                thread_id: Some("thread-1".to_string()),
                reply_to_id: None,
                metadata: HashMap::new(),
            })
            .await
            .expect("first send should succeed");
        let first_msg = futures::StreamExt::next(&mut inbound_first)
            .await
            .expect("first inbound message");
        assert_eq!(first_msg.sender_id, "first@example.com");

        let tx_second = adapter
            .reset_inbound_channel()
            .expect("second reset should succeed");
        let mut inbound_second = adapter.inbound();
        tx_second
            .send(InboundMessage {
                channel: "gmail".to_string(),
                sender_id: "second@example.com".to_string(),
                content: vec![ContentBlock::Text {
                    text: "second".to_string(),
                }],
                attachments: vec![],
                timestamp: chrono::Utc::now(),
                is_dm: Some(true),
                is_mention: false,
                thread_id: Some("thread-2".to_string()),
                reply_to_id: None,
                metadata: HashMap::new(),
            })
            .await
            .expect("second send should succeed");
        let second_msg = futures::StreamExt::next(&mut inbound_second)
            .await
            .expect("second inbound message");
        assert_eq!(second_msg.sender_id, "second@example.com");
    }

    #[test]
    fn mark_read_retry_dedupe_cools_down_retries() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dedupe = AsyncMutex::new(HashMap::new());
            assert!(!should_skip_mark_read_retry(&dedupe, "m1").await);
            record_mark_read_retry(&dedupe, "m1").await;
            assert!(should_skip_mark_read_retry(&dedupe, "m1").await);
            assert!(!should_skip_mark_read_retry(&dedupe, "m2").await);
        });
    }

    #[test]
    fn mark_read_retry_dedupe_expires_old_entries() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dedupe = AsyncMutex::new(HashMap::from([(
                "m1".to_string(),
                Instant::now() - MARK_READ_RETRY_DEDUPE_TTL - Duration::from_secs(1),
            )]));
            assert!(!should_skip_mark_read_retry(&dedupe, "m1").await);
            let guard = dedupe.lock().await;
            assert!(guard.get("m1").is_none());
        });
    }

    #[test]
    fn access_token_caching() {
        let config = GmailConfig::default();
        let adapter = GmailAdapter::from_config_and_credentials(config, &sample_credentials())
            .expect("should construct");
        // Token cache starts empty.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let guard = adapter.access_token.read().await;
            assert!(guard.is_none());
        });
    }
}
