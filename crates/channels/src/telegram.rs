use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures::{Stream, StreamExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::util;
use encmind_core::config::TelegramConfig;
use encmind_core::error::ChannelError;
use encmind_core::traits::ChannelAdapter;
use encmind_core::types::{
    Attachment, ChannelTarget, ContentBlock, InboundMessage, OutboundMessage,
};

const TELEGRAM_MAX_MESSAGE_LEN: usize = 4096;
const ATTACHMENT_HYDRATION_NOTE_KEY: &str = "attachment_hydration_note";

/// A reference to a Telegram file extracted during parsing.
#[derive(Debug, Clone)]
struct TelegramFileRef {
    file_id: String,
    file_name: Option<String>,
    mime_type: Option<String>,
}

fn hydration_note(total_refs: usize, downloaded: usize, max_attempted: usize) -> Option<String> {
    let attempted = total_refs.min(max_attempted);
    let truncated = total_refs.saturating_sub(attempted);
    let failed = attempted.saturating_sub(downloaded);
    if truncated == 0 && failed == 0 {
        return None;
    }
    let mut parts = Vec::new();
    if truncated > 0 {
        parts.push(format!(
            "{truncated} attachment(s) skipped by per-message cap"
        ));
    }
    if failed > 0 {
        parts.push(format!("{failed} attachment(s) failed to download"));
    }
    Some(parts.join("; "))
}

pub struct TelegramAdapter {
    #[allow(dead_code)]
    config: TelegramConfig,
    client: reqwest::Client,
    bot_token: String,
    inbound_tx: mpsc::Sender<InboundMessage>,
    inbound_rx: StdMutex<Option<mpsc::Receiver<InboundMessage>>>,
    cancel: AsyncMutex<CancellationToken>,
    runtime_shutdown: AsyncMutex<Option<CancellationToken>>,
    poll_handle: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TelegramAdapter {
    async fn read_body_with_limit(
        resp: reqwest::Response,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ChannelError> {
        if let Some(len) = resp.content_length() {
            if len as usize > max_bytes {
                return Err(ChannelError::ReceiveFailed(format!(
                    "file too large: {} bytes (max {})",
                    len, max_bytes
                )));
            }
        }

        let mut data = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(next) = stream.next().await {
            let chunk = next
                .map_err(|e| ChannelError::ReceiveFailed(format!("file body read failed: {e}")))?;
            if data.len() + chunk.len() > max_bytes {
                return Err(ChannelError::ReceiveFailed(format!(
                    "file too large: more than {} bytes",
                    max_bytes
                )));
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }

    fn safe_chunk_boundary(input: &str, max_bytes: usize) -> usize {
        if input.len() <= max_bytes {
            return input.len();
        }

        let mut end = 0usize;
        for ch in input.chars() {
            let next = end + ch.len_utf8();
            if next > max_bytes {
                break;
            }
            end = next;
        }

        if end == 0 {
            // Ensure forward progress even if max_bytes is smaller than the first scalar.
            return input.chars().next().map(|ch| ch.len_utf8()).unwrap_or(0);
        }
        end
    }

    pub fn new(config: TelegramConfig) -> Result<Self, ChannelError> {
        let bot_token = std::env::var(&config.bot_token_env).map_err(|_| {
            ChannelError::NotConfigured(format!("env var {} not set", config.bot_token_env))
        })?;

        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(256);

        Ok(Self {
            config,
            client,
            bot_token,
            inbound_tx: tx,
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            runtime_shutdown: AsyncMutex::new(None),
            poll_handle: AsyncMutex::new(None),
        })
    }

    /// Construct an adapter from config + credential JSON (e.g. `{"bot_token": "..."}`).
    /// Used by the channel manager for runtime adapter construction from stored credentials.
    pub fn from_config_and_credentials(
        config: TelegramConfig,
        cred_json: &str,
    ) -> Result<Self, ChannelError> {
        let cred: serde_json::Value = serde_json::from_str(cred_json)
            .map_err(|e| ChannelError::NotConfigured(format!("invalid credential JSON: {e}")))?;
        let bot_token = cred
            .get("bot_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChannelError::NotConfigured("missing bot_token in credentials".into()))?
            .to_string();

        if bot_token.trim().is_empty() {
            return Err(ChannelError::NotConfigured("bot_token is empty".into()));
        }

        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(256);

        Ok(Self {
            config,
            client,
            bot_token,
            inbound_tx: tx,
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            runtime_shutdown: AsyncMutex::new(None),
            poll_handle: AsyncMutex::new(None),
        })
    }

    /// Configure an external shutdown token so polling stops when the runtime exits.
    pub async fn set_runtime_shutdown(&self, shutdown: CancellationToken) {
        *self.runtime_shutdown.lock().await = Some(shutdown);
    }

    async fn api_call(
        client: &reqwest::Client,
        token: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ChannelError> {
        let url = format!("https://api.telegram.org/bot{token}/{method}");
        let resp = client
            .post(&url)
            .json(&params)
            .send()
            .await
            .map_err(|e| ChannelError::SendFailed(e.to_string()))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(e.to_string()))?;

        // Telegram wraps every response in {"ok": true/false, ...}
        if !status.is_success() {
            let description = body
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(ChannelError::SendFailed(format!(
                "Telegram API {method} returned HTTP {status}: {description}"
            )));
        }
        if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let description = body
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(ChannelError::SendFailed(format!(
                "Telegram API {method} returned ok=false: {description}"
            )));
        }

        Ok(body)
    }

    /// Extract file references from a Telegram message (photo, document, audio, video, voice).
    fn extract_file_refs(message: &serde_json::Value) -> Vec<TelegramFileRef> {
        let mut refs = Vec::new();

        // photo: array of PhotoSize, pick the last (highest resolution)
        if let Some(photos) = message.get("photo").and_then(|v| v.as_array()) {
            if let Some(largest) = photos.last() {
                if let Some(file_id) = largest.get("file_id").and_then(|v| v.as_str()) {
                    refs.push(TelegramFileRef {
                        file_id: file_id.to_string(),
                        file_name: None,
                        mime_type: Some("image/jpeg".to_string()),
                    });
                }
            }
        }

        // document, audio, video, voice — each has file_id at top level
        for kind in &["document", "audio", "video", "voice"] {
            if let Some(obj) = message.get(*kind) {
                if let Some(file_id) = obj.get("file_id").and_then(|v| v.as_str()) {
                    refs.push(TelegramFileRef {
                        file_id: file_id.to_string(),
                        file_name: obj
                            .get("file_name")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        mime_type: obj
                            .get("mime_type")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    });
                }
            }
        }

        refs
    }

    /// Parse a Telegram update object into an InboundMessage.
    ///
    /// Extracts text/caption and media file references. Messages with media but no
    /// text/caption are accepted (with empty text). File references are stored in
    /// metadata for later download.
    pub fn parse_update(update: &serde_json::Value) -> Option<InboundMessage> {
        let message = update.get("message")?;
        let chat_id = message.get("chat")?.get("id")?.as_i64()?.to_string();
        let from = message.get("from")?;
        let sender_id = from.get("id")?.as_i64()?.to_string();

        let text = message
            .get("text")
            .and_then(|v| v.as_str())
            .or_else(|| message.get("caption").and_then(|v| v.as_str()));

        // Extract media file references
        let file_refs = Self::extract_file_refs(message);

        // Require at least text or media to produce a message
        if text.is_none() && file_refs.is_empty() {
            return None;
        }

        let text = text.unwrap_or("");

        let timestamp = message
            .get("date")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .unwrap_or_else(chrono::Utc::now);

        let chat_type = message
            .get("chat")
            .and_then(|c| c.get("type"))
            .and_then(|v| v.as_str());
        let is_dm = chat_type.map(|t| t == "private");

        let thread_id = message
            .get("message_thread_id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string());
        let reply_to_id = message
            .get("reply_to_message")
            .and_then(|r| r.get("message_id"))
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string());

        let mut metadata = std::collections::HashMap::new();
        if let Some(username) = from.get("username").and_then(|v| v.as_str()) {
            metadata.insert(
                "username".into(),
                serde_json::Value::String(username.into()),
            );
        }
        if let Some(first_name) = from.get("first_name").and_then(|v| v.as_str()) {
            metadata.insert(
                "first_name".into(),
                serde_json::Value::String(first_name.into()),
            );
        }
        if let Some(lang) = from.get("language_code").and_then(|v| v.as_str()) {
            metadata.insert(
                "language_code".into(),
                serde_json::Value::String(lang.into()),
            );
        }

        // Store file refs in metadata for later download
        if !file_refs.is_empty() {
            let refs_json: Vec<serde_json::Value> = file_refs
                .iter()
                .map(|r| {
                    let mut obj = serde_json::json!({ "file_id": r.file_id });
                    if let Some(ref name) = r.file_name {
                        obj["file_name"] = serde_json::Value::String(name.clone());
                    }
                    if let Some(ref mime) = r.mime_type {
                        obj["mime_type"] = serde_json::Value::String(mime.clone());
                    }
                    obj
                })
                .collect();
            metadata.insert("file_refs".into(), serde_json::Value::Array(refs_json));
        }

        Some(InboundMessage {
            channel: "telegram".into(),
            sender_id: format!("{chat_id}:{sender_id}"),
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
            attachments: vec![],
            timestamp,
            is_dm,
            is_mention: false,
            thread_id,
            reply_to_id,
            metadata,
        })
    }

    /// Download a file from Telegram by file_id. Returns `(bytes, file_path)`.
    ///
    /// Uses the Bot API `getFile` + file download endpoint. Enforces the
    /// configured per-file size limit.
    pub async fn download_file(&self, file_id: &str) -> Result<(Vec<u8>, String), ChannelError> {
        let body = Self::api_call(
            &self.client,
            &self.bot_token,
            "getFile",
            serde_json::json!({ "file_id": file_id }),
        )
        .await?;

        let file_path = body
            .get("result")
            .and_then(|r| r.get("file_path"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ChannelError::ReceiveFailed("missing file_path in getFile response".into())
            })?;

        let download_url = format!(
            "https://api.telegram.org/file/bot{}/{}",
            self.bot_token, file_path
        );
        let resp = self
            .client
            .get(&download_url)
            .send()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(format!("file download failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(ChannelError::ReceiveFailed(format!(
                "file download returned HTTP {}",
                resp.status()
            )));
        }

        let bytes = Self::read_body_with_limit(resp, self.config.max_file_bytes.max(1)).await?;
        Ok((bytes, file_path.to_string()))
    }

    /// Download file refs from metadata and convert them to Attachments.
    async fn download_attachments(
        &self,
        metadata: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Vec<Attachment> {
        let file_refs = match metadata.get("file_refs").and_then(|v| v.as_array()) {
            Some(refs) => refs,
            None => return vec![],
        };

        let max_attachments = self.config.max_attachments_per_message;
        let max_file_bytes = self.config.max_file_bytes.max(1);
        let max_total_attachment_bytes = self.config.max_total_attachment_bytes.max(1);
        let file_download_timeout_secs = self.config.download_timeout_secs.max(1);

        let mut attachments = Vec::new();
        let mut total_bytes = 0usize;
        for ref_val in file_refs.iter().take(max_attachments) {
            let file_id = match ref_val.get("file_id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => continue,
            };

            let downloaded =
                tokio::time::timeout(Duration::from_secs(file_download_timeout_secs), async {
                    let body = Self::api_call(
                        &self.client,
                        &self.bot_token,
                        "getFile",
                        serde_json::json!({ "file_id": file_id }),
                    )
                    .await?;
                    let file_path = body
                        .get("result")
                        .and_then(|r| r.get("file_path"))
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            ChannelError::ReceiveFailed(
                                "missing file_path in getFile response".to_string(),
                            )
                        })?
                        .to_string();
                    let download_url = format!(
                        "https://api.telegram.org/file/bot{}/{file_path}",
                        self.bot_token
                    );
                    let resp = self.client.get(&download_url).send().await.map_err(|e| {
                        ChannelError::ReceiveFailed(format!("file download failed: {e}"))
                    })?;
                    if !resp.status().is_success() {
                        return Err(ChannelError::ReceiveFailed(format!(
                            "file download returned HTTP {}",
                            resp.status()
                        )));
                    }
                    let bytes = Self::read_body_with_limit(resp, max_file_bytes).await?;
                    Ok::<(Vec<u8>, String), ChannelError>((bytes, file_path))
                })
                .await;

            let (bytes, file_path) = match downloaded {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    tracing::warn!("telegram file download failed for {file_id}: {e}");
                    continue;
                }
                Err(_) => {
                    tracing::warn!(
                        "telegram file download timed out for {file_id} after {}s",
                        file_download_timeout_secs
                    );
                    continue;
                }
            };

            if bytes.is_empty() {
                continue;
            }
            if total_bytes.saturating_add(bytes.len()) > max_total_attachment_bytes {
                tracing::warn!(
                    "telegram inbound attachment budget exceeded (max {} bytes); skipping {}",
                    max_total_attachment_bytes,
                    file_id
                );
                continue;
            }
            total_bytes += bytes.len();

            let name = ref_val
                .get("file_name")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| {
                    // Use last segment of file_path as name
                    file_path
                        .rsplit('/')
                        .next()
                        .unwrap_or("attachment")
                        .to_string()
                });
            let media_type = ref_val
                .get("mime_type")
                .and_then(|v| v.as_str())
                .unwrap_or("application/octet-stream")
                .to_string();

            attachments.push(Attachment {
                name,
                media_type,
                data: bytes,
            });
        }
        if file_refs.len() > max_attachments {
            tracing::warn!(
                "telegram inbound attachments truncated: {} -> {}",
                file_refs.len(),
                max_attachments
            );
        }
        attachments
    }

    /// Split outbound text at ~4096-char boundaries, preferring newline breaks.
    pub fn format_outbound(msg: &OutboundMessage) -> Vec<String> {
        let full_text: String = msg
            .content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");

        if full_text.is_empty() {
            return vec![];
        }

        if full_text.len() <= TELEGRAM_MAX_MESSAGE_LEN {
            return vec![full_text];
        }

        let mut chunks = Vec::new();
        let mut remaining = full_text.as_str();

        while !remaining.is_empty() {
            if remaining.len() <= TELEGRAM_MAX_MESSAGE_LEN {
                chunks.push(remaining.to_string());
                break;
            }

            let safe_end = Self::safe_chunk_boundary(remaining, TELEGRAM_MAX_MESSAGE_LEN);
            let boundary = &remaining[..safe_end];
            let split_at = boundary.rfind('\n').unwrap_or(safe_end);
            let split_at = if split_at == 0 { safe_end } else { split_at };

            chunks.push(remaining[..split_at].to_string());
            remaining = remaining[split_at..].trim_start_matches('\n');
        }

        chunks
    }

    async fn polling_loop(
        client: Arc<reqwest::Client>,
        token: String,
        tx: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
        runtime_shutdown: Option<CancellationToken>,
    ) {
        let runtime_shutdown = runtime_shutdown.unwrap_or_default();
        let mut offset: i64 = 0;
        let mut backoff_secs: u64 = 1;
        const MAX_BACKOFF_SECS: u64 = 30;

        loop {
            if cancel.is_cancelled() || runtime_shutdown.is_cancelled() {
                break;
            }

            let params = serde_json::json!({
                "offset": offset,
                "timeout": 30,
            });

            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = runtime_shutdown.cancelled() => break,
                r = Self::api_call(&client, &token, "getUpdates", params) => r,
            };

            match result {
                Ok(body) => {
                    backoff_secs = 1; // reset on success
                    if let Some(updates) = body.get("result").and_then(|v| v.as_array()) {
                        for update in updates {
                            if let Some(uid) = update.get("update_id").and_then(|v| v.as_i64()) {
                                offset = uid + 1;
                            }
                            if let Some(msg) = Self::parse_update(update) {
                                let _ = tx.send(msg).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Telegram poll error: {e}");
                    // Jitter: 50-100% of backoff
                    let jitter_ms = (backoff_secs * 500)
                        + (std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .subsec_millis() as u64
                            % (backoff_secs * 500).max(1));
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = runtime_shutdown.cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)) => {},
                    }
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for TelegramAdapter {
    async fn start(&self) -> Result<(), ChannelError> {
        // Guard against duplicate polling loops.
        {
            let guard = self.poll_handle.lock().await;
            if let Some(handle) = guard.as_ref() {
                if !handle.is_finished() {
                    return Err(ChannelError::ConnectionFailed(
                        "telegram adapter already running".to_string(),
                    ));
                }
            }
        }

        // Clean up a finished handle (if any) before starting a new loop.
        if let Some(handle) = self.poll_handle.lock().await.take() {
            let _ = handle.await;
        }

        // Replace the cancellation token so a previously-stopped adapter can restart
        let new_cancel = CancellationToken::new();
        let cancel = new_cancel.clone();
        *self.cancel.lock().await = new_cancel;

        let client = Arc::new(self.client.clone());
        let token = self.bot_token.clone();
        let tx = self.inbound_tx.clone();
        let runtime_shutdown = self.runtime_shutdown.lock().await.clone();

        let handle = tokio::spawn(Self::polling_loop(
            client,
            token,
            tx,
            cancel,
            runtime_shutdown,
        ));
        *self.poll_handle.lock().await = Some(handle);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ChannelError> {
        self.cancel.lock().await.cancel();
        if let Some(handle) = self.poll_handle.lock().await.take() {
            let _ = handle.await;
        }
        Ok(())
    }

    async fn send_message(
        &self,
        target: &ChannelTarget,
        msg: &OutboundMessage,
    ) -> Result<(), ChannelError> {
        let chunks = Self::format_outbound(msg);
        for chunk in chunks {
            let mut params = serde_json::json!({
                "chat_id": target.target_id,
                "text": chunk,
            });
            if let Some(ref thread_id) = msg.thread_id {
                params["message_thread_id"] = serde_json::Value::String(thread_id.clone());
            }
            if let Some(ref reply_id) = msg.reply_to_id {
                params["reply_to_message_id"] = serde_json::Value::String(reply_id.clone());
            }
            Self::api_call(&self.client, &self.bot_token, "sendMessage", params).await?;
        }
        Ok(())
    }

    async fn probe(&self) -> Result<(), ChannelError> {
        Self::api_call(
            &self.client,
            &self.bot_token,
            "getMe",
            serde_json::json!({}),
        )
        .await?;
        Ok(())
    }

    async fn hydrate_inbound_attachments(
        &self,
        msg: &mut InboundMessage,
    ) -> Result<(), ChannelError> {
        if msg.channel != "telegram" || !msg.metadata.contains_key("file_refs") {
            return Ok(());
        }
        let total_refs = msg
            .metadata
            .get("file_refs_total_count")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or_else(|| {
                msg.metadata
                    .get("file_refs")
                    .and_then(|v| v.as_array())
                    .map_or(0usize, |refs| refs.len())
            });
        let file_refs_len = msg
            .metadata
            .get("file_refs")
            .and_then(|v| v.as_array())
            .map_or(0usize, |refs| refs.len());
        let attachments = self.download_attachments(&msg.metadata).await;
        let note = hydration_note(
            total_refs.max(file_refs_len),
            attachments.len(),
            self.config.max_attachments_per_message,
        );
        if let Some(ref note) = note {
            msg.metadata.insert(
                ATTACHMENT_HYDRATION_NOTE_KEY.to_string(),
                serde_json::Value::String(note.clone()),
            );
        }
        msg.attachments.extend(attachments);
        if let Some(note) = note.as_deref() {
            util::set_media_unavailable_fallback(msg, note);
        }
        msg.metadata.remove("file_refs");
        msg.metadata.remove("file_refs_total_count");
        Ok(())
    }

    fn inbound(&self) -> Pin<Box<dyn Stream<Item = InboundMessage> + Send>> {
        // Take the receiver out — only callable once
        let rx = self
            .inbound_rx
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());

        match rx {
            Some(rx) => Box::pin(ReceiverStream::new(rx)),
            None => Box::pin(futures::stream::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_core::config::{TelegramConfig, TelegramMode};

    #[test]
    fn parse_update_text_message() {
        let update = serde_json::json!({
            "update_id": 123,
            "message": {
                "message_id": 1,
                "from": {"id": 42, "first_name": "Alice"},
                "chat": {"id": 100},
                "date": 1700000000,
                "text": "Hello bot"
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        assert_eq!(msg.channel, "telegram");
        assert_eq!(msg.sender_id, "100:42");
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello bot"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn parse_update_with_caption() {
        let update = serde_json::json!({
            "update_id": 124,
            "message": {
                "message_id": 2,
                "from": {"id": 43, "first_name": "Bob"},
                "chat": {"id": 101},
                "date": 1700000001,
                "caption": "Photo caption"
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Photo caption"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn format_outbound_splits_long_messages() {
        // Build a message > 4096 chars
        let long_text = "a".repeat(3000) + "\n" + &"b".repeat(3000);
        let msg = OutboundMessage {
            content: vec![ContentBlock::Text { text: long_text }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };
        let chunks = TelegramAdapter::format_outbound(&msg);
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            assert!(chunk.len() <= TELEGRAM_MAX_MESSAGE_LEN);
        }
    }

    #[test]
    fn format_outbound_handles_multibyte_without_panicking() {
        // 2000 * 4-byte emoji + 1 newline + 2000 * 4-byte emoji = 16_001 bytes
        let long_text = "😀".repeat(2000) + "\n" + &"🚀".repeat(2000);
        let msg = OutboundMessage {
            content: vec![ContentBlock::Text {
                text: long_text.clone(),
            }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };

        let chunks = TelegramAdapter::format_outbound(&msg);
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            assert!(chunk.len() <= TELEGRAM_MAX_MESSAGE_LEN);
            assert!(std::str::from_utf8(chunk.as_bytes()).is_ok());
        }
    }

    #[test]
    fn parse_update_handles_start_command() {
        let update = serde_json::json!({
            "update_id": 125,
            "message": {
                "message_id": 3,
                "from": {"id": 44, "first_name": "Carol"},
                "chat": {"id": 102},
                "date": 1700000002,
                "text": "/start"
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "/start"),
            _ => panic!("expected text"),
        }
    }

    fn make_adapter_for_test() -> TelegramAdapter {
        let (tx, rx) = mpsc::channel(8);
        TelegramAdapter {
            config: TelegramConfig {
                bot_token_env: "TEST_TELEGRAM_BOT_TOKEN".to_string(),
                mode: TelegramMode::Polling,
                webhook_url: None,
                ..Default::default()
            },
            client: reqwest::Client::new(),
            bot_token: "test-token".to_string(),
            inbound_tx: tx,
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            runtime_shutdown: AsyncMutex::new(None),
            poll_handle: AsyncMutex::new(None),
        }
    }

    #[tokio::test]
    async fn start_rejects_when_already_running() {
        let adapter = make_adapter_for_test();

        let running = tokio::spawn(async {
            futures::future::pending::<()>().await;
        });
        *adapter.poll_handle.lock().await = Some(running);

        let err = adapter.start().await.unwrap_err();
        match err {
            ChannelError::ConnectionFailed(msg) => {
                assert!(msg.contains("already running"));
            }
            other => panic!("unexpected error: {other}"),
        }

        let handle = { adapter.poll_handle.lock().await.take() };
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    #[test]
    fn parse_update_private_chat_is_dm() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100, "type": "private" },
                "from": { "id": 42 },
                "text": "hello",
                "date": 1700000000
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        assert_eq!(msg.is_dm, Some(true));
    }

    #[test]
    fn parse_update_extracts_thread_id_and_reply_to_id() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42, "first_name": "Alice", "username": "alice42", "language_code": "en" },
                "text": "threaded message",
                "date": 1700000000,
                "message_thread_id": 999,
                "reply_to_message": { "message_id": 555 }
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        assert_eq!(msg.thread_id.as_deref(), Some("999"));
        assert_eq!(msg.reply_to_id.as_deref(), Some("555"));
    }

    #[test]
    fn parse_update_extracts_sender_metadata() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42, "first_name": "Alice", "username": "alice42", "language_code": "en" },
                "text": "hi",
                "date": 1700000000
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        assert_eq!(
            msg.metadata.get("username").and_then(|v| v.as_str()),
            Some("alice42")
        );
        assert_eq!(
            msg.metadata.get("first_name").and_then(|v| v.as_str()),
            Some("Alice")
        );
        assert_eq!(
            msg.metadata.get("language_code").and_then(|v| v.as_str()),
            Some("en")
        );
    }

    #[test]
    fn parse_update_no_thread_fields_yields_none() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42 },
                "text": "plain message",
                "date": 1700000000
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        assert!(msg.thread_id.is_none());
        assert!(msg.reply_to_id.is_none());
    }

    #[test]
    fn parse_update_group_chat_is_not_dm() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100, "type": "supergroup" },
                "from": { "id": 42 },
                "text": "hello",
                "date": 1700000000
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        assert_eq!(msg.is_dm, Some(false));
        assert!(!msg.is_mention);
    }

    #[test]
    fn from_config_and_credentials_valid() {
        let config = TelegramConfig {
            bot_token_env: String::new(),
            mode: TelegramMode::Polling,
            webhook_url: None,
            ..Default::default()
        };
        let cred = r#"{"bot_token": "123:ABC"}"#;
        let adapter = TelegramAdapter::from_config_and_credentials(config, cred).unwrap();
        assert_eq!(adapter.bot_token, "123:ABC");
    }

    #[test]
    fn from_config_and_credentials_missing_token() {
        let config = TelegramConfig {
            bot_token_env: String::new(),
            mode: TelegramMode::Polling,
            webhook_url: None,
            ..Default::default()
        };
        let cred = r#"{"app_token": "foo"}"#;
        match TelegramAdapter::from_config_and_credentials(config, cred) {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("missing bot_token"));
            }
            Err(other) => panic!("expected NotConfigured, got different error: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn from_config_and_credentials_invalid_json() {
        let config = TelegramConfig {
            bot_token_env: String::new(),
            mode: TelegramMode::Polling,
            webhook_url: None,
            ..Default::default()
        };
        match TelegramAdapter::from_config_and_credentials(config, "not json") {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("invalid credential JSON"));
            }
            Err(other) => panic!("expected NotConfigured, got different error: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn parse_update_photo_extracts_file_ref() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42 },
                "date": 1700000000,
                "caption": "Check this out",
                "photo": [
                    { "file_id": "small_id", "width": 90, "height": 90 },
                    { "file_id": "medium_id", "width": 320, "height": 320 },
                    { "file_id": "large_id", "width": 800, "height": 800 }
                ]
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Check this out"),
            _ => panic!("expected text"),
        }
        let refs = msg.metadata.get("file_refs").unwrap().as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0]["file_id"], "large_id");
        assert_eq!(refs[0]["mime_type"], "image/jpeg");
    }

    #[test]
    fn parse_update_document_extracts_file_ref() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42 },
                "date": 1700000000,
                "caption": "A document",
                "document": {
                    "file_id": "doc_file_id",
                    "file_name": "report.pdf",
                    "mime_type": "application/pdf"
                }
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        let refs = msg.metadata.get("file_refs").unwrap().as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0]["file_id"], "doc_file_id");
        assert_eq!(refs[0]["file_name"], "report.pdf");
        assert_eq!(refs[0]["mime_type"], "application/pdf");
    }

    #[test]
    fn parse_update_media_only_no_text_returns_message() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42 },
                "date": 1700000000,
                "voice": {
                    "file_id": "voice_file_id",
                    "mime_type": "audio/ogg"
                }
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        // Text should be empty when only media is present
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, ""),
            _ => panic!("expected text"),
        }
        let refs = msg.metadata.get("file_refs").unwrap().as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0]["file_id"], "voice_file_id");
    }

    #[test]
    fn parse_update_text_and_document_both_present() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42 },
                "date": 1700000000,
                "text": "Here is a file",
                "document": {
                    "file_id": "doc_id",
                    "file_name": "data.csv",
                    "mime_type": "text/csv"
                }
            }
        });
        let msg = TelegramAdapter::parse_update(&update).unwrap();
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Here is a file"),
            _ => panic!("expected text"),
        }
        let refs = msg.metadata.get("file_refs").unwrap().as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0]["file_name"], "data.csv");
    }

    #[test]
    fn parse_update_no_text_no_media_returns_none() {
        let update = serde_json::json!({
            "message": {
                "chat": { "id": 100 },
                "from": { "id": 42 },
                "date": 1700000000
            }
        });
        assert!(TelegramAdapter::parse_update(&update).is_none());
    }

    #[test]
    fn download_file_url_construction() {
        // Verify the URL format for getFile and download
        let token = "123:ABC";
        let file_id = "test_file_id";
        let get_file_url = format!("https://api.telegram.org/bot{token}/getFile");
        assert_eq!(get_file_url, "https://api.telegram.org/bot123:ABC/getFile");
        let file_path = "photos/file_42.jpg";
        let download_url = format!("https://api.telegram.org/file/bot{token}/{file_path}");
        assert_eq!(
            download_url,
            "https://api.telegram.org/file/bot123:ABC/photos/file_42.jpg"
        );
        let _ = file_id; // used to verify we'd pass it as param
    }

    #[test]
    fn hydration_note_reports_truncated_and_failed_counts() {
        let note = super::hydration_note(9, 2, 5).expect("note should be present");
        assert!(note.contains("4 attachment(s) skipped"));
        assert!(note.contains("3 attachment(s) failed"));
    }

    #[test]
    fn set_media_unavailable_fallback_adds_text_for_media_only_message() {
        let mut msg = InboundMessage {
            channel: "telegram".into(),
            sender_id: "100:42".into(),
            content: vec![ContentBlock::Text {
                text: String::new(),
            }],
            attachments: vec![],
            timestamp: chrono::Utc::now(),
            is_dm: Some(true),
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: std::collections::HashMap::new(),
        };
        util::set_media_unavailable_fallback(&mut msg, "2 attachment(s) failed to download");
        let text = msg
            .content
            .iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or_default();
        assert!(text.contains("attachments could not be retrieved"));
    }
}
