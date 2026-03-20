use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures::{Stream, StreamExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::util;
use encmind_core::config::SlackConfig;
use encmind_core::error::ChannelError;
use encmind_core::traits::ChannelAdapter;
use encmind_core::types::{
    Attachment, ChannelTarget, ContentBlock, InboundMessage, OutboundMessage,
};

const SLACK_MAX_MESSAGE_LEN: usize = 4000;
const ATTACHMENT_HYDRATION_NOTE_KEY: &str = "attachment_hydration_note";
const SLACK_WS_BACKOFF_MAX_SECS: u64 = 30;
const SLACK_WS_PING_INTERVAL_SECS: u64 = 20;
const SLACK_WS_STABLE_RESET_SECS: u64 = 60;

/// Compute a jittered backoff duration: 50–100% of the given base seconds.
fn jittered_backoff(base_secs: u64) -> std::time::Duration {
    let half_ms = base_secs * 500;
    let jitter_range = half_ms.max(1);
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis() as u64
        % jitter_range;
    std::time::Duration::from_millis(half_ms + jitter)
}

fn next_backoff_secs(current_secs: u64) -> u64 {
    current_secs
        .max(1)
        .saturating_mul(2)
        .min(SLACK_WS_BACKOFF_MAX_SECS)
}

fn update_backoff_after_disconnect(current_secs: u64, connected_for: Duration) -> u64 {
    if connected_for >= Duration::from_secs(SLACK_WS_STABLE_RESET_SECS) {
        1
    } else {
        next_backoff_secs(current_secs)
    }
}

pub struct SlackAdapter {
    #[allow(dead_code)]
    config: SlackConfig,
    client: reqwest::Client,
    bot_token: String,
    app_token: String,
    inbound_tx: mpsc::Sender<InboundMessage>,
    inbound_rx: StdMutex<Option<mpsc::Receiver<InboundMessage>>>,
    cancel: AsyncMutex<CancellationToken>,
    runtime_shutdown: AsyncMutex<Option<CancellationToken>>,
    ws_handle: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

/// A reference to a Slack file for deferred download.
#[derive(Debug, Clone)]
pub struct SlackFileRef {
    pub url: String,
    pub name: String,
    pub mimetype: String,
}

/// Parsed inbound event from a Socket Mode envelope.
#[derive(Debug)]
pub struct ParsedEvent {
    pub channel_id: String,
    pub user: String,
    pub text: String,
    pub ts: Option<f64>,
    pub is_dm: bool,
    pub is_mention: bool,
    pub thread_ts: Option<String>,
    pub file_refs: Vec<SlackFileRef>,
    pub file_refs_total_count: usize,
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

impl SlackAdapter {
    fn read_required_env(var_name: &str) -> Result<String, ChannelError> {
        let value = std::env::var(var_name)
            .map_err(|_| ChannelError::NotConfigured(format!("env var {var_name} not set")))?;
        if value.trim().is_empty() {
            return Err(ChannelError::NotConfigured(format!(
                "env var {var_name} is empty"
            )));
        }
        Ok(value)
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
            return input.chars().next().map(|ch| ch.len_utf8()).unwrap_or(0);
        }
        end
    }

    fn validate_download_url(raw: &str) -> Result<reqwest::Url, ChannelError> {
        let url = reqwest::Url::parse(raw)
            .map_err(|e| ChannelError::ReceiveFailed(format!("invalid file download URL: {e}")))?;
        if url.scheme() != "https" {
            return Err(ChannelError::ReceiveFailed(
                "file download URL must use https".to_string(),
            ));
        }
        let host = url.host_str().ok_or_else(|| {
            ChannelError::ReceiveFailed("file download URL missing host".to_string())
        })?;
        if host == "files.slack.com" || host.ends_with(".slack.com") {
            Ok(url)
        } else {
            Err(ChannelError::ReceiveFailed(format!(
                "file download URL host not allowed: {host}"
            )))
        }
    }

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

    pub fn new(config: SlackConfig) -> Result<Self, ChannelError> {
        let bot_token = Self::read_required_env(&config.bot_token_env)?;
        let app_token = Self::read_required_env(&config.app_token_env)?;

        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(256);

        Ok(Self {
            config,
            client,
            bot_token,
            app_token,
            inbound_tx: tx,
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            runtime_shutdown: AsyncMutex::new(None),
            ws_handle: AsyncMutex::new(None),
        })
    }

    /// Construct an adapter from config + credential JSON (e.g. `{"bot_token": "...", "app_token": "..."}`).
    /// Used by the channel manager for runtime adapter construction from stored credentials.
    pub fn from_config_and_credentials(
        config: SlackConfig,
        cred_json: &str,
    ) -> Result<Self, ChannelError> {
        let cred: serde_json::Value = serde_json::from_str(cred_json)
            .map_err(|e| ChannelError::NotConfigured(format!("invalid credential JSON: {e}")))?;
        let bot_token = cred
            .get("bot_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChannelError::NotConfigured("missing bot_token in credentials".into()))?
            .to_string();
        let app_token = cred
            .get("app_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChannelError::NotConfigured("missing app_token in credentials".into()))?
            .to_string();

        if bot_token.trim().is_empty() {
            return Err(ChannelError::NotConfigured("bot_token is empty".into()));
        }
        if app_token.trim().is_empty() {
            return Err(ChannelError::NotConfigured("app_token is empty".into()));
        }

        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(256);

        Ok(Self {
            config,
            client,
            bot_token,
            app_token,
            inbound_tx: tx,
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            runtime_shutdown: AsyncMutex::new(None),
            ws_handle: AsyncMutex::new(None),
        })
    }

    /// Configure an external shutdown token so the WS loop stops when the runtime exits.
    pub async fn set_runtime_shutdown(&self, shutdown: CancellationToken) {
        *self.runtime_shutdown.lock().await = Some(shutdown);
    }

    /// Parse a Socket Mode envelope into a `ParsedEvent`.
    ///
    /// Accepts `type == "events_api"` envelopes where `payload.event.type` is
    /// `"message"` (no subtype, no bot_id) or `"app_mention"`.
    pub fn parse_event(envelope: &serde_json::Value) -> Option<ParsedEvent> {
        let event = envelope.get("payload")?.get("event")?;
        let event_type = event.get("type")?.as_str()?;

        match event_type {
            "message" => {
                // Skip bot messages
                if event.get("bot_id").is_some() {
                    return None;
                }

                let subtype = event.get("subtype").and_then(|v| v.as_str());

                // Allow file_share subtype; skip all other subtypes
                match subtype {
                    None | Some("file_share") => {}
                    Some(_) => return None,
                }

                let channel_id = event.get("channel")?.as_str()?.to_string();
                let user = event.get("user")?.as_str()?.to_string();

                // text is optional for file_share messages
                let text = event
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Extract file references from file_share messages
                let (file_refs, file_refs_total_count) = Self::extract_slack_file_refs(event);

                // Require at least text or file refs
                if text.is_empty() && file_refs.is_empty() {
                    return None;
                }

                let ts = event.get("ts").and_then(|v| {
                    v.as_str()
                        .and_then(|s| s.parse::<f64>().ok())
                        .or_else(|| v.as_f64())
                });
                let is_dm = channel_id.starts_with('D');
                let thread_ts = event
                    .get("thread_ts")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Some(ParsedEvent {
                    channel_id,
                    user,
                    text,
                    ts,
                    is_dm,
                    is_mention: false,
                    thread_ts,
                    file_refs,
                    file_refs_total_count,
                })
            }
            "app_mention" => {
                let channel_id = event.get("channel")?.as_str()?.to_string();
                let user = event.get("user")?.as_str()?.to_string();
                let text = event
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let (file_refs, file_refs_total_count) = Self::extract_slack_file_refs(event);
                if text.is_empty() && file_refs.is_empty() {
                    return None;
                }
                let ts = event.get("ts").and_then(|v| {
                    v.as_str()
                        .and_then(|s| s.parse::<f64>().ok())
                        .or_else(|| v.as_f64())
                });
                let is_dm = channel_id.starts_with('D');
                let thread_ts = event
                    .get("thread_ts")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                Some(ParsedEvent {
                    channel_id,
                    user,
                    text,
                    ts,
                    is_dm,
                    is_mention: true,
                    thread_ts,
                    file_refs,
                    file_refs_total_count,
                })
            }
            _ => None,
        }
    }

    /// Extract file references from a Slack event's `files` array.
    fn extract_slack_file_refs(event: &serde_json::Value) -> (Vec<SlackFileRef>, usize) {
        let files = match event.get("files").and_then(|v| v.as_array()) {
            Some(f) => f,
            None => return (vec![], 0),
        };

        let mut refs = Vec::new();
        let mut total = 0usize;
        for f in files {
            let Some(url) = f
                .get("url_private_download")
                .and_then(|v| v.as_str())
                .map(str::to_string)
            else {
                continue;
            };
            total += 1;
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("attachment")
                .to_string();
            let mimetype = f
                .get("mimetype")
                .and_then(|v| v.as_str())
                .unwrap_or("application/octet-stream")
                .to_string();
            refs.push(SlackFileRef {
                url,
                name,
                mimetype,
            });
        }
        (refs, total)
    }

    /// Download a file from Slack using its private download URL.
    /// Requires the bot token for authorization.
    pub async fn download_file(&self, url: &str) -> Result<Vec<u8>, ChannelError> {
        let url = Self::validate_download_url(url)?;
        let resp = self
            .client
            .get(url.as_str())
            .header("Authorization", format!("Bearer {}", self.bot_token))
            .send()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(format!("file download failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(ChannelError::ReceiveFailed(format!(
                "file download returned HTTP {}",
                resp.status()
            )));
        }

        Self::read_body_with_limit(resp, self.config.max_file_bytes.max(1)).await
    }

    /// Download file refs from a parsed event and convert to Attachments.
    async fn download_attachments_from_refs(&self, file_refs: &[SlackFileRef]) -> Vec<Attachment> {
        let max_attachments = self.config.max_attachments_per_message;
        let max_file_bytes = self.config.max_file_bytes.max(1);
        let max_total_attachment_bytes = self.config.max_total_attachment_bytes.max(1);
        let file_download_timeout_secs = self.config.download_timeout_secs.max(1);

        let mut attachments = Vec::new();
        let mut total_bytes = 0usize;
        for file_ref in file_refs.iter().take(max_attachments) {
            let downloaded =
                tokio::time::timeout(Duration::from_secs(file_download_timeout_secs), async {
                    let validated_url = Self::validate_download_url(&file_ref.url)?;
                    let resp = self
                        .client
                        .get(validated_url.as_str())
                        .header("Authorization", format!("Bearer {}", self.bot_token))
                        .send()
                        .await
                        .map_err(|e| {
                            ChannelError::ReceiveFailed(format!("file download failed: {e}"))
                        })?;

                    if !resp.status().is_success() {
                        return Err(ChannelError::ReceiveFailed(format!(
                            "file download returned HTTP {}",
                            resp.status()
                        )));
                    }

                    Self::read_body_with_limit(resp, max_file_bytes).await
                })
                .await;

            let bytes = match downloaded {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => {
                    tracing::warn!("slack file download failed for {}: {e}", file_ref.name);
                    continue;
                }
                Err(_) => {
                    tracing::warn!(
                        "slack file download timed out for {} after {}s",
                        file_ref.name,
                        file_download_timeout_secs
                    );
                    continue;
                }
            };

            if total_bytes.saturating_add(bytes.len()) > max_total_attachment_bytes {
                tracing::warn!(
                    "slack inbound attachment budget exceeded (max {} bytes); skipping {}",
                    max_total_attachment_bytes,
                    file_ref.name
                );
                continue;
            }
            total_bytes += bytes.len();

            attachments.push(Attachment {
                name: file_ref.name.clone(),
                media_type: file_ref.mimetype.clone(),
                data: bytes,
            });
        }
        if file_refs.len() > max_attachments {
            tracing::warn!(
                "slack inbound attachments truncated: {} -> {}",
                file_refs.len(),
                max_attachments
            );
        }
        attachments
    }

    fn file_refs_from_metadata(
        metadata: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Vec<SlackFileRef> {
        metadata
            .get("file_refs")
            .and_then(|v| v.as_array())
            .map(|refs| {
                refs.iter()
                    .filter_map(|value| {
                        let url = value.get("url").and_then(|v| v.as_str())?.to_string();
                        let name = value
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("attachment")
                            .to_string();
                        let mimetype = value
                            .get("mimetype")
                            .and_then(|v| v.as_str())
                            .unwrap_or("application/octet-stream")
                            .to_string();
                        Some(SlackFileRef {
                            url,
                            name,
                            mimetype,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Build the ack JSON for a Socket Mode envelope.
    pub fn envelope_ack(envelope_id: &str) -> serde_json::Value {
        serde_json::json!({ "envelope_id": envelope_id })
    }

    /// Split outbound text at ~4000-char boundaries, preferring newline breaks.
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

        if full_text.len() <= SLACK_MAX_MESSAGE_LEN {
            return vec![full_text];
        }

        let mut chunks = Vec::new();
        let mut remaining = full_text.as_str();

        while !remaining.is_empty() {
            if remaining.len() <= SLACK_MAX_MESSAGE_LEN {
                chunks.push(remaining.to_string());
                break;
            }

            let safe_end = Self::safe_chunk_boundary(remaining, SLACK_MAX_MESSAGE_LEN);
            let boundary = &remaining[..safe_end];
            let split_at = boundary.rfind('\n').unwrap_or(safe_end);
            let split_at = if split_at == 0 { safe_end } else { split_at };

            chunks.push(remaining[..split_at].to_string());
            remaining = remaining[split_at..].trim_start_matches('\n');
        }

        chunks
    }

    async fn ws_loop(
        client: Arc<reqwest::Client>,
        app_token: String,
        tx: mpsc::Sender<InboundMessage>,
        cancel: CancellationToken,
        runtime_shutdown: Option<CancellationToken>,
    ) {
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let runtime_shutdown = runtime_shutdown.unwrap_or_default();
        let mut backoff_secs: u64 = 1;

        loop {
            if cancel.is_cancelled() || runtime_shutdown.is_cancelled() {
                break;
            }

            // Request a WebSocket URL via apps.connections.open
            let ws_url = match Self::request_ws_url(&client, &app_token).await {
                Ok(url) => url,
                Err(e) => {
                    tracing::warn!("Slack apps.connections.open failed: {e}");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = runtime_shutdown.cancelled() => break,
                        _ = tokio::time::sleep(jittered_backoff(backoff_secs)) => {},
                    }
                    backoff_secs = next_backoff_secs(backoff_secs);
                    continue;
                }
            };

            // Connect WebSocket
            let ws_stream = match tokio_tungstenite::connect_async(&ws_url).await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!("Slack WS connect failed: {e}");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = runtime_shutdown.cancelled() => break,
                        _ = tokio::time::sleep(jittered_backoff(backoff_secs)) => {},
                    }
                    backoff_secs = next_backoff_secs(backoff_secs);
                    continue;
                }
            };

            tracing::info!("Slack Socket Mode connected");
            let (mut ws_sink, mut ws_stream_rx) = futures::StreamExt::split(ws_stream);
            let connected_at = std::time::Instant::now();
            let mut ping_interval =
                tokio::time::interval(Duration::from_secs(SLACK_WS_PING_INTERVAL_SECS));
            ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the initial immediate tick so keepalive pings start after the interval.
            ping_interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = runtime_shutdown.cancelled() => return,
                    _ = ping_interval.tick() => {
                        use futures::SinkExt;
                        if let Err(e) = ws_sink.send(WsMessage::Ping(Default::default())).await {
                            tracing::warn!("Slack WS keepalive ping failed: {e}");
                            break;
                        }
                    }
                    maybe_msg = futures::StreamExt::next(&mut ws_stream_rx) => {
                        let Some(result) = maybe_msg else {
                            tracing::warn!("Slack WS stream ended");
                            break;
                        };
                        match result {
                            Ok(WsMessage::Text(text)) => {
                                Self::handle_ws_text(&text, &mut ws_sink, &tx).await;
                            }
                            Ok(WsMessage::Ping(data)) => {
                                use futures::SinkExt;
                                let _ = ws_sink.send(WsMessage::Pong(data)).await;
                            }
                            Ok(WsMessage::Close(_)) => {
                                tracing::info!("Slack WS closed by server");
                                break;
                            }
                            Ok(_) => {} // Binary, Pong — ignore
                            Err(e) => {
                                tracing::warn!("Slack WS error: {e}");
                                break;
                            }
                        }
                    }
                }
            }

            let connected_for = connected_at.elapsed();
            let previous_backoff = backoff_secs;
            backoff_secs = update_backoff_after_disconnect(backoff_secs, connected_for);
            tracing::debug!(
                connected_for_secs = connected_for.as_secs(),
                previous_backoff_secs = previous_backoff,
                next_backoff_secs = backoff_secs,
                "Slack Socket Mode reconnect backoff updated"
            );

            // Reconnect with backoff
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = runtime_shutdown.cancelled() => break,
                _ = tokio::time::sleep(jittered_backoff(backoff_secs)) => {},
            }
        }
    }

    async fn request_ws_url(
        client: &reqwest::Client,
        app_token: &str,
    ) -> Result<String, ChannelError> {
        let resp = client
            .post("https://slack.com/api/apps.connections.open")
            .header("Authorization", format!("Bearer {app_token}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await
            .map_err(|e| ChannelError::ConnectionFailed(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ChannelError::ConnectionFailed(e.to_string()))?;

        if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let err_msg = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(ChannelError::ConnectionFailed(format!(
                "apps.connections.open: {err_msg}"
            )));
        }

        body.get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ChannelError::ConnectionFailed("missing url in connections.open response".into())
            })
    }

    async fn handle_ws_text<S>(text: &str, ws_sink: &mut S, tx: &mpsc::Sender<InboundMessage>)
    where
        S: futures::Sink<
                tokio_tungstenite::tungstenite::Message,
                Error = tokio_tungstenite::tungstenite::Error,
            > + Unpin,
    {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let Ok(envelope) = serde_json::from_str::<serde_json::Value>(text) else {
            return;
        };

        // Always ack the envelope immediately
        if let Some(envelope_id) = envelope.get("envelope_id").and_then(|v| v.as_str()) {
            let ack = Self::envelope_ack(envelope_id);
            let _ = ws_sink.send(WsMessage::Text(ack.to_string())).await;
        }

        // Only process events_api envelopes
        let envelope_type = envelope.get("type").and_then(|v| v.as_str());
        if envelope_type != Some("events_api") {
            return;
        }

        if let Some(parsed) = Self::parse_event(&envelope) {
            let timestamp = parsed
                .ts
                .and_then(|ts| chrono::DateTime::from_timestamp(ts as i64, 0))
                .unwrap_or_else(chrono::Utc::now);

            let mut metadata = std::collections::HashMap::new();
            if !parsed.file_refs.is_empty() {
                let refs_json: Vec<serde_json::Value> = parsed
                    .file_refs
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "url": r.url,
                            "name": r.name,
                            "mimetype": r.mimetype,
                        })
                    })
                    .collect();
                metadata.insert("file_refs".into(), serde_json::Value::Array(refs_json));
                if parsed.file_refs_total_count > parsed.file_refs.len() {
                    metadata.insert(
                        "file_refs_total_count".into(),
                        serde_json::Value::from(parsed.file_refs_total_count as u64),
                    );
                }
            }

            let msg = InboundMessage {
                channel: "slack".into(),
                sender_id: format!("{}:{}", parsed.channel_id, parsed.user),
                content: vec![ContentBlock::Text { text: parsed.text }],
                attachments: vec![],
                timestamp,
                is_dm: Some(parsed.is_dm),
                is_mention: parsed.is_mention,
                thread_id: parsed.thread_ts,
                reply_to_id: None,
                metadata,
            };
            let _ = tx.send(msg).await;
        }
    }
}

#[async_trait::async_trait]
impl ChannelAdapter for SlackAdapter {
    async fn start(&self) -> Result<(), ChannelError> {
        // Guard against duplicate WS loops.
        {
            let guard = self.ws_handle.lock().await;
            if let Some(handle) = guard.as_ref() {
                if !handle.is_finished() {
                    return Err(ChannelError::ConnectionFailed(
                        "slack adapter already running".to_string(),
                    ));
                }
            }
        }

        // Clean up a finished handle (if any) before starting a new loop.
        if let Some(handle) = self.ws_handle.lock().await.take() {
            let _ = handle.await;
        }

        // Replace the cancellation token so a previously-stopped adapter can restart
        let new_cancel = CancellationToken::new();
        let cancel = new_cancel.clone();
        *self.cancel.lock().await = new_cancel;

        let client = Arc::new(self.client.clone());
        let app_token = self.app_token.clone();
        let tx = self.inbound_tx.clone();
        let runtime_shutdown = self.runtime_shutdown.lock().await.clone();

        let handle = tokio::spawn(Self::ws_loop(
            client,
            app_token,
            tx,
            cancel,
            runtime_shutdown,
        ));
        *self.ws_handle.lock().await = Some(handle);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ChannelError> {
        self.cancel.lock().await.cancel();
        if let Some(handle) = self.ws_handle.lock().await.take() {
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
                "channel": target.target_id,
                "text": chunk,
            });
            if let Some(ref thread_ts) = msg.thread_id {
                params["thread_ts"] = serde_json::Value::String(thread_ts.clone());
            }
            let resp = self
                .client
                .post("https://slack.com/api/chat.postMessage")
                .header("Authorization", format!("Bearer {}", self.bot_token))
                .json(&params)
                .send()
                .await
                .map_err(|e| ChannelError::SendFailed(e.to_string()))?;

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ChannelError::SendFailed(e.to_string()))?;

            if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                let err_msg = body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                return Err(ChannelError::SendFailed(format!(
                    "chat.postMessage: {err_msg}"
                )));
            }
        }
        Ok(())
    }

    async fn probe(&self) -> Result<(), ChannelError> {
        let resp = self
            .client
            .post("https://slack.com/api/auth.test")
            .header("Authorization", format!("Bearer {}", self.bot_token))
            .send()
            .await
            .map_err(|e| ChannelError::ConnectionFailed(e.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ChannelError::ReceiveFailed(e.to_string()))?;
        if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let err_msg = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(ChannelError::ConnectionFailed(format!(
                "auth.test failed: {err_msg}"
            )));
        }
        Ok(())
    }

    async fn hydrate_inbound_attachments(
        &self,
        msg: &mut InboundMessage,
    ) -> Result<(), ChannelError> {
        if msg.channel != "slack" || !msg.metadata.contains_key("file_refs") {
            return Ok(());
        }
        let file_refs = Self::file_refs_from_metadata(&msg.metadata);
        if file_refs.is_empty() {
            msg.metadata.remove("file_refs");
            msg.metadata.remove("file_refs_total_count");
            return Ok(());
        }
        let total_refs = msg
            .metadata
            .get("file_refs_total_count")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(file_refs.len());
        let downloaded = self.download_attachments_from_refs(&file_refs).await;
        let note = hydration_note(
            total_refs,
            downloaded.len(),
            self.config.max_attachments_per_message,
        );
        if let Some(ref note) = note {
            msg.metadata.insert(
                ATTACHMENT_HYDRATION_NOTE_KEY.to_string(),
                serde_json::Value::String(note.clone()),
            );
        }
        msg.attachments.extend(downloaded);
        if let Some(note) = note.as_deref() {
            util::set_media_unavailable_fallback(msg, note);
        }
        msg.metadata.remove("file_refs");
        msg.metadata.remove("file_refs_total_count");
        Ok(())
    }

    fn inbound(&self) -> Pin<Box<dyn Stream<Item = InboundMessage> + Send>> {
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
    use encmind_core::config::SlackConfig;

    fn make_socket_mode_envelope(event: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "envelope_id": "abc123",
            "type": "events_api",
            "payload": {
                "event": event
            }
        })
    }

    #[test]
    fn parse_event_text_message() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "C12345",
            "user": "U67890",
            "text": "Hello from Slack",
            "ts": "1700000000.000100"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert_eq!(parsed.channel_id, "C12345");
        assert_eq!(parsed.user, "U67890");
        assert_eq!(parsed.text, "Hello from Slack");
        assert!(parsed.ts.is_some());
    }

    #[test]
    fn parse_event_ignores_bot_messages() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "C12345",
            "user": "U67890",
            "bot_id": "B11111",
            "text": "Bot message",
            "ts": "1700000000.000100"
        });
        let envelope = make_socket_mode_envelope(event);
        assert!(SlackAdapter::parse_event(&envelope).is_none());
    }

    #[test]
    fn parse_event_ignores_subtypes() {
        let event = serde_json::json!({
            "type": "message",
            "subtype": "message_changed",
            "channel": "C12345",
            "user": "U67890",
            "text": "Edited message",
            "ts": "1700000000.000100"
        });
        let envelope = make_socket_mode_envelope(event);
        assert!(SlackAdapter::parse_event(&envelope).is_none());
    }

    #[test]
    fn parse_event_app_mention() {
        let event = serde_json::json!({
            "type": "app_mention",
            "channel": "C99999",
            "user": "U11111",
            "text": "<@U_BOT> help me",
            "ts": "1700000001.000200"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert_eq!(parsed.channel_id, "C99999");
        assert_eq!(parsed.user, "U11111");
        assert_eq!(parsed.text, "<@U_BOT> help me");
    }

    #[test]
    fn parse_event_missing_text() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "C12345",
            "user": "U67890"
        });
        let envelope = make_socket_mode_envelope(event);
        assert!(SlackAdapter::parse_event(&envelope).is_none());
    }

    #[test]
    fn format_outbound_short_message() {
        let msg = OutboundMessage {
            content: vec![ContentBlock::Text {
                text: "Short message".into(),
            }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };
        let chunks = SlackAdapter::format_outbound(&msg);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "Short message");
    }

    #[test]
    fn format_outbound_splits_at_4000() {
        let long_text = "a".repeat(3000) + "\n" + &"b".repeat(3000);
        let msg = OutboundMessage {
            content: vec![ContentBlock::Text { text: long_text }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };
        let chunks = SlackAdapter::format_outbound(&msg);
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            assert!(chunk.len() <= SLACK_MAX_MESSAGE_LEN);
        }
    }

    #[test]
    fn format_outbound_multibyte_safe() {
        // 1500 * 4-byte emoji + newline + 1500 * 4-byte emoji = 12_001 bytes
        let long_text = "😀".repeat(1500) + "\n" + &"🚀".repeat(1500);
        let msg = OutboundMessage {
            content: vec![ContentBlock::Text {
                text: long_text.clone(),
            }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };

        let chunks = SlackAdapter::format_outbound(&msg);
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            assert!(chunk.len() <= SLACK_MAX_MESSAGE_LEN);
            assert!(std::str::from_utf8(chunk.as_bytes()).is_ok());
        }
    }

    #[test]
    fn format_outbound_empty() {
        let msg = OutboundMessage {
            content: vec![ContentBlock::Text { text: "".into() }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        };
        let chunks = SlackAdapter::format_outbound(&msg);
        assert!(chunks.is_empty());
    }

    fn make_adapter_for_test() -> SlackAdapter {
        let (tx, rx) = mpsc::channel(8);
        SlackAdapter {
            config: SlackConfig {
                bot_token_env: "TEST_SLACK_BOT_TOKEN".to_string(),
                app_token_env: "TEST_SLACK_APP_TOKEN".to_string(),
                ..Default::default()
            },
            client: reqwest::Client::new(),
            bot_token: "xoxb-test-token".to_string(),
            app_token: "xapp-test-token".to_string(),
            inbound_tx: tx,
            inbound_rx: StdMutex::new(Some(rx)),
            cancel: AsyncMutex::new(CancellationToken::new()),
            runtime_shutdown: AsyncMutex::new(None),
            ws_handle: AsyncMutex::new(None),
        }
    }

    #[tokio::test]
    async fn start_rejects_when_already_running() {
        let adapter = make_adapter_for_test();

        let running = tokio::spawn(async {
            futures::future::pending::<()>().await;
        });
        *adapter.ws_handle.lock().await = Some(running);

        let err = adapter.start().await.unwrap_err();
        match err {
            ChannelError::ConnectionFailed(msg) => {
                assert!(msg.contains("already running"));
            }
            other => panic!("unexpected error: {other}"),
        }

        let handle = { adapter.ws_handle.lock().await.take() };
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    #[test]
    fn envelope_ack_format() {
        let ack = SlackAdapter::envelope_ack("env-id-42");
        assert_eq!(ack["envelope_id"], "env-id-42");
        // Must be a flat object with exactly one key
        let obj = ack.as_object().unwrap();
        assert_eq!(obj.len(), 1);
    }

    #[test]
    fn new_missing_bot_token_env() {
        // Ensure the env vars are NOT set
        std::env::remove_var("SLACK_TEST_MISSING_BOT");
        std::env::remove_var("SLACK_TEST_MISSING_APP");

        let config = SlackConfig {
            bot_token_env: "SLACK_TEST_MISSING_BOT".to_string(),
            app_token_env: "SLACK_TEST_MISSING_APP".to_string(),
            ..Default::default()
        };
        match SlackAdapter::new(config) {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("SLACK_TEST_MISSING_BOT"));
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("expected NotConfigured error"),
        }
    }

    #[test]
    fn new_empty_bot_token_env() {
        std::env::set_var("SLACK_TEST_EMPTY_BOT", "   ");
        std::env::set_var("SLACK_TEST_EMPTY_APP", "xapp-valid");

        let config = SlackConfig {
            bot_token_env: "SLACK_TEST_EMPTY_BOT".to_string(),
            app_token_env: "SLACK_TEST_EMPTY_APP".to_string(),
            ..Default::default()
        };

        match SlackAdapter::new(config) {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("SLACK_TEST_EMPTY_BOT"));
                assert!(msg.contains("empty"));
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("expected NotConfigured error"),
        }

        std::env::remove_var("SLACK_TEST_EMPTY_BOT");
        std::env::remove_var("SLACK_TEST_EMPTY_APP");
    }

    #[test]
    fn parse_event_dm_channel_sets_is_dm() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "D12345",
            "user": "U67890",
            "text": "hello in DM",
            "ts": "1700000000.000100"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert!(parsed.is_dm);
        assert!(!parsed.is_mention);
    }

    #[test]
    fn parse_event_public_channel_not_dm() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "C12345",
            "user": "U67890",
            "text": "hello in channel",
            "ts": "1700000000.000100"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert!(!parsed.is_dm);
        assert!(!parsed.is_mention);
    }

    #[test]
    fn parse_event_extracts_thread_ts() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "C12345",
            "user": "U67890",
            "text": "threaded reply",
            "ts": "1700000000.000100",
            "thread_ts": "1699999999.000050"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert_eq!(parsed.thread_ts.as_deref(), Some("1699999999.000050"));
    }

    #[test]
    fn parse_event_no_thread_ts_yields_none() {
        let event = serde_json::json!({
            "type": "message",
            "channel": "C12345",
            "user": "U67890",
            "text": "top-level message",
            "ts": "1700000000.000100"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert!(parsed.thread_ts.is_none());
    }

    #[test]
    fn jittered_backoff_bounded() {
        for base in [1u64, 2, 4, 8, 16, 30] {
            let dur = super::jittered_backoff(base);
            let ms = dur.as_millis() as u64;
            // Should be between 50% and 100% of base seconds
            assert!(
                ms >= base * 500,
                "jittered_backoff({base}) = {ms}ms < {}ms",
                base * 500
            );
            assert!(
                ms < base * 1000,
                "jittered_backoff({base}) = {ms}ms >= {}ms",
                base * 1000
            );
        }
    }

    #[test]
    fn next_backoff_secs_doubles_and_caps() {
        assert_eq!(super::next_backoff_secs(1), 2);
        assert_eq!(super::next_backoff_secs(2), 4);
        assert_eq!(
            super::next_backoff_secs(SLACK_WS_BACKOFF_MAX_SECS),
            SLACK_WS_BACKOFF_MAX_SECS
        );
        assert_eq!(
            super::next_backoff_secs(SLACK_WS_BACKOFF_MAX_SECS - 1),
            SLACK_WS_BACKOFF_MAX_SECS
        );
    }

    #[test]
    fn update_backoff_after_disconnect_resets_after_stable_connection() {
        assert_eq!(
            super::update_backoff_after_disconnect(8, Duration::from_secs(5)),
            16
        );
        assert_eq!(
            super::update_backoff_after_disconnect(
                8,
                Duration::from_secs(SLACK_WS_STABLE_RESET_SECS)
            ),
            1
        );
    }

    #[test]
    fn parse_event_app_mention_sets_is_mention() {
        let event = serde_json::json!({
            "type": "app_mention",
            "channel": "C99999",
            "user": "U11111",
            "text": "<@U_BOT> help me",
            "ts": "1700000001.000200"
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert!(parsed.is_mention);
        assert!(!parsed.is_dm);
    }

    #[test]
    fn from_config_and_credentials_valid() {
        let config = SlackConfig {
            bot_token_env: String::new(),
            app_token_env: String::new(),
            ..Default::default()
        };
        let cred = r#"{"bot_token": "xoxb-test", "app_token": "xapp-test"}"#;
        let adapter = SlackAdapter::from_config_and_credentials(config, cred).unwrap();
        assert_eq!(adapter.bot_token, "xoxb-test");
        assert_eq!(adapter.app_token, "xapp-test");
    }

    #[test]
    fn from_config_and_credentials_missing_bot_token() {
        let config = SlackConfig {
            bot_token_env: String::new(),
            app_token_env: String::new(),
            ..Default::default()
        };
        let cred = r#"{"app_token": "xapp-test"}"#;
        match SlackAdapter::from_config_and_credentials(config, cred) {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("missing bot_token"));
            }
            Err(other) => panic!("expected NotConfigured, got different error: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn from_config_and_credentials_missing_app_token() {
        let config = SlackConfig {
            bot_token_env: String::new(),
            app_token_env: String::new(),
            ..Default::default()
        };
        let cred = r#"{"bot_token": "xoxb-test"}"#;
        match SlackAdapter::from_config_and_credentials(config, cred) {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("missing app_token"));
            }
            Err(other) => panic!("expected NotConfigured, got different error: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn from_config_and_credentials_invalid_json() {
        let config = SlackConfig {
            bot_token_env: String::new(),
            app_token_env: String::new(),
            ..Default::default()
        };
        match SlackAdapter::from_config_and_credentials(config, "not json") {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("invalid credential JSON"));
            }
            Err(other) => panic!("expected NotConfigured, got different error: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn parse_event_file_share_extracts_file_refs() {
        let event = serde_json::json!({
            "type": "message",
            "subtype": "file_share",
            "channel": "C12345",
            "user": "U67890",
            "text": "uploaded a file",
            "ts": "1700000000.000100",
            "files": [
                {
                    "url_private_download": "https://files.slack.com/files-pri/T1/download/report.pdf",
                    "name": "report.pdf",
                    "mimetype": "application/pdf",
                    "size": 1024
                }
            ]
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert_eq!(parsed.text, "uploaded a file");
        assert_eq!(parsed.file_refs.len(), 1);
        assert_eq!(parsed.file_refs[0].name, "report.pdf");
        assert_eq!(parsed.file_refs[0].mimetype, "application/pdf");
        assert!(parsed.file_refs[0].url.contains("download/report.pdf"));
    }

    #[test]
    fn parse_event_still_skips_other_subtypes() {
        for subtype in &[
            "channel_join",
            "message_changed",
            "message_deleted",
            "bot_message",
        ] {
            let event = serde_json::json!({
                "type": "message",
                "subtype": subtype,
                "channel": "C12345",
                "user": "U67890",
                "text": "some text",
                "ts": "1700000000.000100"
            });
            let envelope = make_socket_mode_envelope(event);
            assert!(
                SlackAdapter::parse_event(&envelope).is_none(),
                "subtype '{subtype}' should be skipped"
            );
        }
    }

    #[test]
    fn parse_event_file_share_with_text_and_multiple_files() {
        let event = serde_json::json!({
            "type": "message",
            "subtype": "file_share",
            "channel": "C12345",
            "user": "U67890",
            "text": "two files",
            "ts": "1700000000.000100",
            "files": [
                {
                    "url_private_download": "https://files.slack.com/f1",
                    "name": "image.png",
                    "mimetype": "image/png"
                },
                {
                    "url_private_download": "https://files.slack.com/f2",
                    "name": "doc.txt",
                    "mimetype": "text/plain"
                }
            ]
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert_eq!(parsed.text, "two files");
        assert_eq!(parsed.file_refs.len(), 2);
        assert_eq!(parsed.file_refs[0].name, "image.png");
        assert_eq!(parsed.file_refs[1].name, "doc.txt");
    }

    #[test]
    fn parse_event_file_share_caps_stored_refs_but_tracks_total() {
        let files: Vec<serde_json::Value> = (0..8)
            .map(|i| {
                serde_json::json!({
                    "url_private_download": format!("https://files.slack.com/f{i}"),
                    "name": format!("file-{i}.txt"),
                    "mimetype": "text/plain"
                })
            })
            .collect();
        let event = serde_json::json!({
            "type": "message",
            "subtype": "file_share",
            "channel": "C12345",
            "user": "U67890",
            "text": "many files",
            "ts": "1700000000.000100",
            "files": files
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert_eq!(parsed.file_refs.len(), 8);
        assert_eq!(parsed.file_refs_total_count, 8);
    }

    #[test]
    fn parse_event_app_mention_extracts_file_refs() {
        let event = serde_json::json!({
            "type": "app_mention",
            "channel": "C12345",
            "user": "U67890",
            "text": "<@Ubot> see file",
            "ts": "1700000000.000100",
            "files": [
                {
                    "url_private_download": "https://files.slack.com/f1",
                    "name": "note.txt",
                    "mimetype": "text/plain"
                }
            ]
        });
        let envelope = make_socket_mode_envelope(event);
        let parsed = SlackAdapter::parse_event(&envelope).unwrap();
        assert!(parsed.is_mention);
        assert_eq!(parsed.file_refs.len(), 1);
        assert_eq!(parsed.file_refs[0].name, "note.txt");
    }

    #[test]
    fn hydration_note_reports_truncated_and_failed_counts() {
        let note = super::hydration_note(8, 3, 5).expect("note should be present");
        assert!(note.contains("3 attachment(s) skipped"));
        assert!(note.contains("2 attachment(s) failed"));
    }

    #[test]
    fn file_refs_from_metadata_parses_expected_entries() {
        let metadata = std::collections::HashMap::from([(
            "file_refs".to_string(),
            serde_json::json!([
                {
                    "url": "https://files.slack.com/a",
                    "name": "a.txt",
                    "mimetype": "text/plain"
                },
                {
                    "url": "https://files.slack.com/b"
                }
            ]),
        )]);
        let refs = SlackAdapter::file_refs_from_metadata(&metadata);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "a.txt");
        assert_eq!(refs[0].mimetype, "text/plain");
        assert_eq!(refs[1].name, "attachment");
        assert_eq!(refs[1].mimetype, "application/octet-stream");
    }

    #[test]
    fn validate_download_url_accepts_slack_hosts() {
        let url = SlackAdapter::validate_download_url(
            "https://files.slack.com/files-pri/T1/download/report.pdf",
        )
        .expect("files.slack.com should be allowed");
        assert_eq!(url.host_str(), Some("files.slack.com"));
    }

    #[test]
    fn validate_download_url_rejects_non_slack_hosts() {
        let err = SlackAdapter::validate_download_url("https://example.com/file.bin")
            .expect_err("non-slack host should be rejected");
        assert!(err.to_string().contains("host not allowed"));
    }

    #[test]
    fn set_media_unavailable_fallback_adds_text_for_media_only_message() {
        let mut msg = InboundMessage {
            channel: "slack".into(),
            sender_id: "C1:U1".into(),
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
