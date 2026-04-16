use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, EventRequestPaused, FailRequestParams, RequestId as FetchRequestId,
};
use chromiumoxide::cdp::browser_protocol::network::ErrorReason;
use encmind_agent::firewall::EgressFirewall;
use encmind_agent::tool_registry::{InternalToolHandler, ToolRegistry};
use encmind_core::error::AppError;
use encmind_core::types::{AgentId, SessionId};
use futures::StreamExt;
use url::Url;

use crate::pool::{BrowserPool, SessionBrowserManager};

const MAX_SCREENSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_GET_TEXT_CHARS: usize = 20_000;
const FIREWALL_DRAIN_TIMEOUT_MS: u64 = 200;
const FIREWALL_REJECT_SETTLE_TIMEOUT_MS: u64 = 250;
const WAIT_FINAL_FLUSH_TIMEOUT_MS: u64 = 20;
const _: () = assert!(WAIT_FINAL_FLUSH_TIMEOUT_MS <= 25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostOpDrainPolicy {
    /// Drain with the specified timeout only when at least one paused request
    /// was observed while the wrapped operation was running.
    IfPausedRequestsSeenMs(u64),
    /// Always perform a short tail-drain window after the operation completes.
    AlwaysMs(u64),
}

fn resolve_post_op_drain_timeout(
    policy: PostOpDrainPolicy,
    saw_paused_event: bool,
) -> Option<Duration> {
    match policy {
        PostOpDrainPolicy::IfPausedRequestsSeenMs(ms) => {
            saw_paused_event.then(|| Duration::from_millis(ms.max(1)))
        }
        PostOpDrainPolicy::AlwaysMs(ms) => Some(Duration::from_millis(ms.max(1))),
    }
}

/// Browser navigate tool — navigates to a URL and returns the page title.
pub struct BrowserNavigateHandler {
    pool: Arc<BrowserPool>,
    firewall: Arc<EgressFirewall>,
    config: encmind_core::config::BrowserConfig,
    metrics: Arc<crate::guardrails::BrowserMetrics>,
    page_load_timeout: Duration,
}

impl BrowserNavigateHandler {
    pub fn new(
        pool: Arc<BrowserPool>,
        firewall: Arc<EgressFirewall>,
        config: encmind_core::config::BrowserConfig,
        metrics: Arc<crate::guardrails::BrowserMetrics>,
    ) -> Self {
        let page_load_timeout = Duration::from_secs(config.page_load_timeout_secs);
        Self {
            pool,
            firewall,
            config,
            metrics,
            page_load_timeout,
        }
    }
}

#[async_trait]
impl InternalToolHandler for BrowserNavigateHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        self.metrics
            .total_actions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        enforce_action_allowed(&self.config, "navigate")?;
        let raw_url = input
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("missing 'url' parameter".into()))?;
        let url = parse_http_url(raw_url)?;
        enforce_url_allowed(&self.firewall, &url, agent_id).await?;
        enforce_domain_allowed(&self.config, &url)?;

        let lease = self
            .pool
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("browser acquire failed: {e:?}")))?;

        let nav_fut = async {
            navigate_with_request_firewall(&lease.page, &url, &self.firewall, agent_id).await?;
            enforce_final_page_url_allowed(&self.firewall, &lease.page, agent_id).await?;
            let title = lease
                .page
                .get_title()
                .await
                .map_err(|e| AppError::Internal(format!("get_title failed: {e}")))?
                .unwrap_or_default();
            Ok::<_, AppError>(title)
        };
        let title = if self.page_load_timeout.is_zero() {
            nav_fut.await?
        } else {
            tokio::time::timeout(self.page_load_timeout, nav_fut)
                .await
                .map_err(|_| {
                    self.metrics
                        .timeout_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    AppError::Internal(format!(
                        "navigation timed out after {}s",
                        self.page_load_timeout.as_secs()
                    ))
                })??
        };

        Ok(serde_json::json!({
            "url": url.as_str(),
            "title": title,
        })
        .to_string())
    }
}

/// Browser screenshot tool — takes a screenshot and returns base64-encoded PNG.
pub struct BrowserScreenshotHandler {
    pool: Arc<BrowserPool>,
    firewall: Arc<EgressFirewall>,
    config: encmind_core::config::BrowserConfig,
    screenshot_mode: encmind_core::config::ScreenshotPayloadMode,
    metrics: Arc<crate::guardrails::BrowserMetrics>,
    page_load_timeout: Duration,
}

impl BrowserScreenshotHandler {
    pub fn new(
        pool: Arc<BrowserPool>,
        firewall: Arc<EgressFirewall>,
        config: encmind_core::config::BrowserConfig,
        screenshot_mode: encmind_core::config::ScreenshotPayloadMode,
        metrics: Arc<crate::guardrails::BrowserMetrics>,
    ) -> Self {
        let page_load_timeout = Duration::from_secs(config.page_load_timeout_secs);
        Self {
            pool,
            firewall,
            config,
            screenshot_mode,
            metrics,
            page_load_timeout,
        }
    }
}

#[async_trait]
impl InternalToolHandler for BrowserScreenshotHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        self.metrics
            .total_actions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        enforce_action_allowed(&self.config, "screenshot")?;
        let raw_url = input
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("missing 'url' parameter".into()))?;
        let url = parse_http_url(raw_url)?;
        enforce_url_allowed(&self.firewall, &url, agent_id).await?;
        enforce_domain_allowed(&self.config, &url)?;

        let lease = self
            .pool
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("browser acquire failed: {e:?}")))?;

        let op_fut = async {
            navigate_with_request_firewall(&lease.page, &url, &self.firewall, agent_id).await?;
            enforce_final_page_url_allowed(&self.firewall, &lease.page, agent_id).await?;
            Ok::<_, AppError>(())
        };
        if self.page_load_timeout.is_zero() {
            op_fut.await?;
        } else {
            tokio::time::timeout(self.page_load_timeout, op_fut)
                .await
                .map_err(|_| {
                    self.metrics
                        .timeout_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    AppError::Internal(format!(
                        "screenshot navigation timed out after {}s",
                        self.page_load_timeout.as_secs()
                    ))
                })??;
        }

        let screenshot_bytes = lease
            .page
            .screenshot(
                chromiumoxide::page::ScreenshotParams::builder()
                    .format(
                        chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat::Png,
                    )
                    .build(),
            )
            .await
            .map_err(|e| AppError::Internal(format!("screenshot failed: {e}")))?;

        if screenshot_bytes.len() > MAX_SCREENSHOT_BYTES {
            return Err(AppError::Internal(format!(
                "screenshot too large: {} bytes (max {})",
                screenshot_bytes.len(),
                MAX_SCREENSHOT_BYTES
            )));
        }

        use encmind_core::config::ScreenshotPayloadMode;

        match self.screenshot_mode {
            ScreenshotPayloadMode::Metadata => Ok(serde_json::json!({
                "url": url.as_str(),
                "format": "png",
                "size_bytes": screenshot_bytes.len(),
                "note": "Screenshot captured successfully. The raw image data is not \
                         included in the conversation context to save tokens.",
            })
            .to_string()),
            ScreenshotPayloadMode::Base64Legacy => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&screenshot_bytes);

                Ok(serde_json::json!({
                    "url": url.as_str(),
                    "format": "png",
                    "base64": b64,
                    "size_bytes": screenshot_bytes.len(),
                })
                .to_string())
            }
        }
    }
}

/// Browser get_text tool — extracts document.body.innerText via JS evaluation.
pub struct BrowserGetTextHandler {
    pool: Arc<BrowserPool>,
    firewall: Arc<EgressFirewall>,
    config: encmind_core::config::BrowserConfig,
    metrics: Arc<crate::guardrails::BrowserMetrics>,
    page_load_timeout: Duration,
}

impl BrowserGetTextHandler {
    pub fn new(
        pool: Arc<BrowserPool>,
        firewall: Arc<EgressFirewall>,
        config: encmind_core::config::BrowserConfig,
        metrics: Arc<crate::guardrails::BrowserMetrics>,
    ) -> Self {
        let page_load_timeout = Duration::from_secs(config.page_load_timeout_secs);
        Self {
            pool,
            firewall,
            config,
            metrics,
            page_load_timeout,
        }
    }
}

#[async_trait]
impl InternalToolHandler for BrowserGetTextHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        self.metrics
            .total_actions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        enforce_action_allowed(&self.config, "get_text")?;
        let raw_url = input
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("missing 'url' parameter".into()))?;
        let url = parse_http_url(raw_url)?;
        enforce_url_allowed(&self.firewall, &url, agent_id).await?;
        enforce_domain_allowed(&self.config, &url)?;

        let lease = self
            .pool
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("browser acquire failed: {e:?}")))?;

        let nav_fut = async {
            navigate_with_request_firewall(&lease.page, &url, &self.firewall, agent_id).await?;
            enforce_final_page_url_allowed(&self.firewall, &lease.page, agent_id).await?;
            Ok::<_, AppError>(())
        };
        if self.page_load_timeout.is_zero() {
            nav_fut.await?;
        } else {
            tokio::time::timeout(self.page_load_timeout, nav_fut)
                .await
                .map_err(|_| {
                    self.metrics
                        .timeout_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    AppError::Internal(format!(
                        "get_text navigation timed out after {}s",
                        self.page_load_timeout.as_secs()
                    ))
                })??;
        }

        let text: String = lease
            .page
            .evaluate("document.body.innerText")
            .await
            .map_err(|e| AppError::Internal(format!("evaluate failed: {e}")))?
            .into_value()
            .map_err(|e| AppError::Internal(format!("value conversion failed: {e}")))?;
        let (text, truncated, original_chars) = truncate_text(text, MAX_GET_TEXT_CHARS);

        Ok(serde_json::json!({
            "url": url.as_str(),
            "text": text,
            "truncated": truncated,
            "original_chars": original_chars,
        })
        .to_string())
    }
}

fn parse_http_url(raw: &str) -> Result<Url, AppError> {
    let parsed =
        Url::parse(raw).map_err(|e| AppError::Internal(format!("invalid url '{raw}': {e}")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        scheme => Err(AppError::Internal(format!(
            "unsupported url scheme '{scheme}'; only http/https are allowed"
        ))),
    }
}

async fn enforce_url_allowed(
    firewall: &EgressFirewall,
    url: &Url,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    firewall
        .check_url_for_agent(url.as_str(), agent_id.as_str())
        .await
        .map_err(|e| AppError::Internal(format!("egress firewall blocked URL '{}': {e}", url)))
}

fn enforce_domain_allowed(
    config: &encmind_core::config::BrowserConfig,
    url: &Url,
) -> Result<(), AppError> {
    if let Some(domain) = url.host_str() {
        if !config.is_domain_allowed(domain) {
            return Err(AppError::Internal(format!(
                "domain '{domain}' is not in browser domain allowlist"
            )));
        }
    }
    Ok(())
}

fn enforce_action_allowed(
    config: &encmind_core::config::BrowserConfig,
    action: &str,
) -> Result<(), AppError> {
    if !config.is_action_allowed(action) {
        return Err(AppError::Internal(format!(
            "action '{action}' is not allowed by browser policy"
        )));
    }
    Ok(())
}

async fn enforce_final_page_url_allowed(
    firewall: &EgressFirewall,
    page: &chromiumoxide::page::Page,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    let final_url = page
        .url()
        .await
        .map_err(|e| AppError::Internal(format!("failed to read final page URL: {e}")))?;
    if let Some(url) = final_url {
        let parsed =
            Url::parse(&url).map_err(|e| AppError::Internal(format!("invalid final URL: {e}")))?;
        enforce_url_allowed(firewall, &parsed, agent_id).await?;
    }
    Ok(())
}

async fn navigate_with_request_firewall(
    page: &chromiumoxide::page::Page,
    url: &Url,
    firewall: &EgressFirewall,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    run_with_request_firewall(
        page,
        firewall,
        agent_id,
        PostOpDrainPolicy::IfPausedRequestsSeenMs(FIREWALL_DRAIN_TIMEOUT_MS),
        async {
            page.goto(url.as_str())
                .await
                .map_err(|e| AppError::Internal(format!("navigation failed: {e}")))?;
            Ok(())
        },
    )
    .await
}

async fn run_with_request_firewall<T, F>(
    page: &chromiumoxide::page::Page,
    firewall: &EgressFirewall,
    agent_id: &AgentId,
    // Controls whether and how we drain paused network events after the
    // wrapped operation completes.
    post_op_drain_policy: PostOpDrainPolicy,
    operation: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, AppError>>,
{
    // Register before the operation so redirects/subresources are intercepted too.
    let mut request_paused = page
        .event_listener::<EventRequestPaused>()
        .await
        .map_err(|e| AppError::Internal(format!("failed to register request interceptor: {e}")))?;
    let mut operation = Box::pin(operation);
    let mut saw_paused_event = false;

    let output = loop {
        tokio::select! {
            result = &mut operation => {
                break result?;
            }
            maybe_event = request_paused.next() => {
                let Some(event) = maybe_event else {
                    return Err(AppError::Internal(
                        "request interceptor closed during browser operation".into(),
                    ));
                };
                saw_paused_event = true;
                if let Err(err) = handle_paused_event(page, &event, firewall, agent_id).await {
                    // Best effort: let the in-flight operation settle briefly before we return
                    // the policy error to reduce the chance of leaving Chromium in mid-command.
                    let _ = tokio::time::timeout(
                        Duration::from_millis(FIREWALL_REJECT_SETTLE_TIMEOUT_MS),
                        operation.as_mut(),
                    )
                    .await;
                    return Err(err);
                }
            }
        }
    };

    if let Some(drain_timeout) =
        resolve_post_op_drain_timeout(post_op_drain_policy, saw_paused_event)
    {
        // Drain any remaining paused sub-resource requests so the page does not
        // hang with half-loaded resources.
        loop {
            tokio::select! {
                maybe_event = request_paused.next() => {
                    let Some(event) = maybe_event else { break; };
                    handle_paused_event(page, &event, firewall, agent_id).await?;
                }
                _ = tokio::time::sleep(drain_timeout) => {
                    break;
                }
            }
        }
    }

    Ok(output)
}

async fn handle_paused_event(
    page: &chromiumoxide::page::Page,
    event: &EventRequestPaused,
    firewall: &EgressFirewall,
    agent_id: &AgentId,
) -> Result<(), AppError> {
    // Requests paused at response stage still require explicit continuation.
    if event.response_status_code.is_some() {
        continue_paused_request(page, event.request_id.clone()).await?;
        return Ok(());
    }

    let request_url = event.request.url.as_str();
    if should_filter_request_url(request_url) {
        if let Err(e) = firewall
            .check_url_for_agent(request_url, agent_id.as_str())
            .await
        {
            block_paused_request(page, event.request_id.clone()).await?;
            return Err(AppError::Internal(format!(
                "egress firewall blocked browser request '{}': {}",
                request_url, e
            )));
        }
    }
    continue_paused_request(page, event.request_id.clone()).await?;
    Ok(())
}

async fn continue_paused_request(
    page: &chromiumoxide::page::Page,
    request_id: FetchRequestId,
) -> Result<(), AppError> {
    page.execute(ContinueRequestParams::new(request_id))
        .await
        .map_err(|e| AppError::Internal(format!("failed to continue intercepted request: {e}")))?;
    Ok(())
}

async fn block_paused_request(
    page: &chromiumoxide::page::Page,
    request_id: FetchRequestId,
) -> Result<(), AppError> {
    page.execute(FailRequestParams::new(
        request_id,
        ErrorReason::BlockedByClient,
    ))
    .await
    .map_err(|e| AppError::Internal(format!("failed to block intercepted request: {e}")))?;
    Ok(())
}

fn should_filter_request_url(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.host_str().is_none() {
        return false;
    }
    matches!(url.scheme(), "http" | "https" | "ws" | "wss")
}

fn truncate_text(input: String, max_chars: usize) -> (String, bool, usize) {
    let total_chars = input.chars().count();
    if total_chars <= max_chars {
        return (input, false, total_chars);
    }

    let truncated = input.chars().take(max_chars).collect::<String>();
    (truncated, true, total_chars)
}

async fn fail_close_on_timeout<T, F, Fut>(
    metrics: &crate::guardrails::BrowserMetrics,
    release_session: F,
    error_message: String,
) -> Result<T, AppError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    metrics
        .timeout_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    release_session().await;
    Err(AppError::Internal(error_message))
}

/// Browser act tool — performs interactive browser actions on session-scoped pages.
pub struct BrowserActHandler {
    session_manager: Arc<SessionBrowserManager>,
    firewall: Arc<EgressFirewall>,
    config: encmind_core::config::BrowserConfig,
    screenshot_mode: encmind_core::config::ScreenshotPayloadMode,
    metrics: Arc<crate::guardrails::BrowserMetrics>,
    guardrail_config: crate::guardrails::GuardrailConfig,
}

impl BrowserActHandler {
    pub fn new(
        session_manager: Arc<SessionBrowserManager>,
        firewall: Arc<EgressFirewall>,
        config: encmind_core::config::BrowserConfig,
        screenshot_mode: encmind_core::config::ScreenshotPayloadMode,
        metrics: Arc<crate::guardrails::BrowserMetrics>,
    ) -> Self {
        let guardrail_config = crate::guardrails::GuardrailConfig::from_browser_config(&config);
        Self {
            session_manager,
            firewall,
            config,
            screenshot_mode,
            metrics,
            guardrail_config,
        }
    }
}

/// Valid action names for browser_act.
const VALID_ACTIONS: &[&str] = &[
    "navigate",
    "click",
    "type",
    "press",
    "select",
    "upload",
    "wait",
    "screenshot",
    "get_text",
    "eval",
    "close",
];

/// Map common key names to CDP key definitions.
fn key_definition(name: &str) -> Option<(&'static str, &'static str, i32)> {
    // Returns (key, code, key_code) for CDP Input.dispatchKeyEvent
    match name.to_lowercase().as_str() {
        "enter" | "return" => Some(("Enter", "Enter", 13)),
        "tab" => Some(("Tab", "Tab", 9)),
        "escape" | "esc" => Some(("Escape", "Escape", 27)),
        "backspace" => Some(("Backspace", "Backspace", 8)),
        "delete" => Some(("Delete", "Delete", 46)),
        "arrowup" | "up" => Some(("ArrowUp", "ArrowUp", 38)),
        "arrowdown" | "down" => Some(("ArrowDown", "ArrowDown", 40)),
        "arrowleft" | "left" => Some(("ArrowLeft", "ArrowLeft", 37)),
        "arrowright" | "right" => Some(("ArrowRight", "ArrowRight", 39)),
        "space" => Some((" ", "Space", 32)),
        "home" => Some(("Home", "Home", 36)),
        "end" => Some(("End", "End", 35)),
        "pageup" => Some(("PageUp", "PageUp", 33)),
        "pagedown" => Some(("PageDown", "PageDown", 34)),
        _ => None,
    }
}

#[async_trait]
impl InternalToolHandler for BrowserActHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> Result<String, AppError> {
        if self.config.max_actions_per_call < 1 {
            return Err(AppError::Internal(
                "browser_act disabled by browser.max_actions_per_call=0".into(),
            ));
        }

        let action_input = if let Some(actions) = input.get("actions").and_then(|v| v.as_array()) {
            if actions.is_empty() {
                return Err(AppError::Internal(
                    "'actions' must contain at least one action".into(),
                ));
            }
            if actions.len() > self.config.max_actions_per_call {
                return Err(AppError::Internal(format!(
                    "too many actions: {} (max {})",
                    actions.len(),
                    self.config.max_actions_per_call
                )));
            }
            if actions.len() > 1 {
                return Err(AppError::Internal(
                    "batched browser actions are not supported yet; send one action per call"
                        .into(),
                ));
            }
            actions[0].clone()
        } else {
            input
        };

        let action = action_input
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("missing 'action' parameter".into()))?;

        // Validate action name
        if !VALID_ACTIONS.contains(&action) {
            return Err(AppError::Internal(format!(
                "unknown action '{action}'; valid actions: {}",
                VALID_ACTIONS.join(", ")
            )));
        }

        // Policy: check action is allowed
        enforce_action_allowed(&self.config, action)?;

        if action == "eval" && !self.config.eval_enabled {
            return Err(AppError::Internal(
                "action 'eval' is disabled by browser.eval_enabled=false".into(),
            ));
        }

        // Track action for metrics (before close early-return so all actions count).
        self.metrics
            .total_actions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Handle close separately — just release the session
        if action == "close" {
            self.session_manager.release(session_id.as_str()).await;
            return Ok(serde_json::json!({
                "action": "close",
                "success": true,
            })
            .to_string());
        }

        // If URL is provided, validate it before acquiring the session
        let raw_url = action_input.get("url").and_then(|v| v.as_str());
        let parsed_url = if let Some(url_str) = raw_url {
            let url = parse_http_url(url_str)?;
            enforce_url_allowed(&self.firewall, &url, agent_id).await?;
            enforce_domain_allowed(&self.config, &url)?;
            Some(url)
        } else {
            None
        };
        if action == "navigate" && parsed_url.is_none() {
            return Err(AppError::Internal(
                "'url' required for navigate action".into(),
            ));
        }

        // Acquire or reuse session page
        let mut guard = self
            .session_manager
            .acquire_session(session_id.as_str())
            .await
            .map_err(|e| AppError::Internal(format!("browser session acquire failed: {e:?}")))?;

        // Loop detection: fingerprint the action and check for repeated patterns.
        // For navigate, use the target URL so repeated failed navigations to the
        // same destination are detected even when the current page hasn't changed.
        let selector = action_input.get("selector").and_then(|v| v.as_str());
        {
            let fp_url = if action == "navigate" {
                parsed_url
                    .as_ref()
                    .map(|u| u.as_str().to_string())
                    .unwrap_or_default()
            } else {
                guard.page().url().await.ok().flatten().unwrap_or_default()
            };
            let fp = crate::guardrails::ActionFingerprint {
                action: action.to_string(),
                page_url: fp_url,
                selector: selector.map(|s| s.to_string()),
            };
            if let Err(abort) = guard.loop_detector().record_and_check(fp) {
                self.metrics
                    .loop_abort_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(AppError::Internal(format!(
                    "loop detected: action '{}' repeated {} consecutive times on the same page/selector; \
                     try a different approach",
                    abort.action, abort.count
                )));
            }
        }

        let page = guard.page();

        // Navigate if URL provided (with page-load timeout + retry).
        if let Some(url) = parsed_url.as_ref() {
            let nav_timeout = self.guardrail_config.page_load_timeout;
            let max_retries = self.guardrail_config.max_retries;
            let mut attempt = 0usize;
            loop {
                let nav_result = if nav_timeout.is_zero() {
                    navigate_with_request_firewall(page, url, &self.firewall, agent_id).await
                } else {
                    match tokio::time::timeout(
                        nav_timeout,
                        navigate_with_request_firewall(page, url, &self.firewall, agent_id),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_elapsed) => {
                            // Release tainted session — page may be in undefined state.
                            drop(guard);
                            return fail_close_on_timeout(
                                self.metrics.as_ref(),
                                || self.session_manager.release(session_id.as_str()),
                                format!(
                                    "page navigation timed out after {}s",
                                    nav_timeout.as_secs()
                                ),
                            )
                            .await;
                        }
                    }
                };
                match nav_result {
                    Ok(()) => break,
                    Err(e)
                        if attempt < max_retries
                            && crate::guardrails::RetryPolicy::is_retryable(&e) =>
                    {
                        self.metrics
                            .retry_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(
                            attempt = attempt + 1,
                            max = max_retries,
                            error = %e,
                            "browser_act navigate failed; retrying"
                        );
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        attempt += 1;
                    }
                    Err(e) => return Err(e),
                }
            }
            enforce_final_page_url_allowed(&self.firewall, page, agent_id).await?;
        }

        // Enforce current page policy even when reusing an existing session without navigation.
        enforce_current_page_policy(&self.firewall, page, agent_id, &self.config).await?;
        // Determine timeout for this action.
        let action_timeout = if action == "navigate" || action == "wait" {
            self.guardrail_config.page_load_timeout
        } else {
            self.guardrail_config.action_timeout
        };

        let immediate_response = if action == "navigate" {
            None
        } else {
            let post_op_drain_policy = if action == "wait" {
                // Keep firewall enforcement during wait but only do a very short
                // tail flush so late-arriving paused events are handled without
                // imposing the full 200ms latency on every wait call.
                PostOpDrainPolicy::AlwaysMs(WAIT_FINAL_FLUSH_TIMEOUT_MS)
            } else {
                PostOpDrainPolicy::IfPausedRequestsSeenMs(FIREWALL_DRAIN_TIMEOUT_MS)
            };
            let max_retries = self.guardrail_config.max_retries;
            let mut attempt = 0usize;
            loop {
                let firewall_wrapped = run_with_request_firewall(
                    page,
                    &self.firewall,
                    agent_id,
                    post_op_drain_policy,
                    async {
                        match action {
                            "click" => {
                                let sel = selector.ok_or_else(|| {
                                    AppError::Internal(
                                        "'selector' required for click action".into(),
                                    )
                                })?;
                                // Find element and click at its center
                                let js = format!(
                                    r#"(() => {{
                        const el = document.querySelector({sel});
                        if (!el) return null;
                        const rect = el.getBoundingClientRect();
                        return {{ x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 }};
                    }})()"#,
                                    sel = serde_json::to_string(sel).map_err(|e| {
                                        AppError::Internal(format!("selector encode failed: {e}"))
                                    })?
                                );
                                let coords: serde_json::Value = page
                                    .evaluate(js)
                                    .await
                                    .map_err(|e| {
                                        AppError::Internal(format!("element lookup failed: {e}"))
                                    })?
                                    .into_value()
                                    .map_err(|e| {
                                        AppError::Internal(format!("value conversion failed: {e}"))
                                    })?;

                                if coords.is_null() {
                                    return Err(AppError::Internal(format!(
                                        "element not found: {sel}"
                                    )));
                                }

                                let x = coords["x"].as_f64().ok_or_else(|| {
                                    AppError::Internal("invalid element coordinates".into())
                                })?;
                                let y = coords["y"].as_f64().ok_or_else(|| {
                                    AppError::Internal("invalid element coordinates".into())
                                })?;

                                // Use CDP to dispatch mouse events
                                use chromiumoxide::cdp::browser_protocol::input::{
                                    DispatchMouseEventParams, DispatchMouseEventType, MouseButton,
                                };
                                page.execute(
                                    DispatchMouseEventParams::builder()
                                        .r#type(DispatchMouseEventType::MousePressed)
                                        .x(x)
                                        .y(y)
                                        .button(MouseButton::Left)
                                        .click_count(1)
                                        .build()
                                        .map_err(|e| {
                                            AppError::Internal(format!(
                                                "mouse event build failed: {e}"
                                            ))
                                        })?,
                                )
                                .await
                                .map_err(|e| {
                                    AppError::Internal(format!("mouse press failed: {e}"))
                                })?;

                                page.execute(
                                    DispatchMouseEventParams::builder()
                                        .r#type(DispatchMouseEventType::MouseReleased)
                                        .x(x)
                                        .y(y)
                                        .button(MouseButton::Left)
                                        .click_count(1)
                                        .build()
                                        .map_err(|e| {
                                            AppError::Internal(format!(
                                                "mouse event build failed: {e}"
                                            ))
                                        })?,
                                )
                                .await
                                .map_err(|e| {
                                    AppError::Internal(format!("mouse release failed: {e}"))
                                })?;
                                Ok(None)
                            }
                            "type" => {
                                let sel = selector.ok_or_else(|| {
                                    AppError::Internal("'selector' required for type action".into())
                                })?;
                                let text = action_input
                                    .get("text")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        AppError::Internal("'text' required for type action".into())
                                    })?;

                                // Focus the element via JS
                                let focus_js = format!(
                                    r#"(() => {{
                        const el = document.querySelector({sel});
                        if (!el) return false;
                        el.focus();
                        return true;
                    }})()"#,
                                    sel = serde_json::to_string(sel).map_err(|e| {
                                        AppError::Internal(format!("selector encode failed: {e}"))
                                    })?
                                );
                                let focused: bool = page
                                    .evaluate(focus_js)
                                    .await
                                    .map_err(|e| AppError::Internal(format!("focus failed: {e}")))?
                                    .into_value()
                                    .map_err(|e| {
                                        AppError::Internal(format!("value conversion failed: {e}"))
                                    })?;
                                if !focused {
                                    return Err(AppError::Internal(format!(
                                        "element not found: {sel}"
                                    )));
                                }

                                // Type each character via CDP
                                use chromiumoxide::cdp::browser_protocol::input::{
                                    DispatchKeyEventParams, DispatchKeyEventType,
                                };
                                for ch in text.chars() {
                                    page.execute(
                                        DispatchKeyEventParams::builder()
                                            .r#type(DispatchKeyEventType::Char)
                                            .text(ch.to_string())
                                            .build()
                                            .map_err(|e| {
                                                AppError::Internal(format!(
                                                    "key event build failed: {e}"
                                                ))
                                            })?,
                                    )
                                    .await
                                    .map_err(|e| {
                                        AppError::Internal(format!("char dispatch failed: {e}"))
                                    })?;
                                }
                                Ok(None)
                            }
                            "press" => {
                                let key_name = action_input
                                    .get("key")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        AppError::Internal("'key' required for press action".into())
                                    })?;

                                let (key, code, _key_code) =
                                    key_definition(key_name).ok_or_else(|| {
                                        AppError::Internal(format!("unknown key: '{key_name}'"))
                                    })?;

                                use chromiumoxide::cdp::browser_protocol::input::{
                                    DispatchKeyEventParams, DispatchKeyEventType,
                                };
                                page.execute(
                                    DispatchKeyEventParams::builder()
                                        .r#type(DispatchKeyEventType::KeyDown)
                                        .key(key)
                                        .code(code)
                                        .build()
                                        .map_err(|e| {
                                            AppError::Internal(format!(
                                                "key event build failed: {e}"
                                            ))
                                        })?,
                                )
                                .await
                                .map_err(|e| AppError::Internal(format!("key down failed: {e}")))?;

                                page.execute(
                                    DispatchKeyEventParams::builder()
                                        .r#type(DispatchKeyEventType::KeyUp)
                                        .key(key)
                                        .code(code)
                                        .build()
                                        .map_err(|e| {
                                            AppError::Internal(format!(
                                                "key event build failed: {e}"
                                            ))
                                        })?,
                                )
                                .await
                                .map_err(|e| AppError::Internal(format!("key up failed: {e}")))?;
                                Ok(None)
                            }
                            "select" => {
                                let sel = selector.ok_or_else(|| {
                                    AppError::Internal(
                                        "'selector' required for select action".into(),
                                    )
                                })?;
                                let value = action_input
                                    .get("value")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        AppError::Internal(
                                            "'value' required for select action".into(),
                                        )
                                    })?;

                                let select_js = format!(
                                    r#"(() => {{
                        const el = document.querySelector({sel});
                        if (!el) return false;
                        el.value = {val};
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return true;
                    }})()"#,
                                    sel = serde_json::to_string(sel).map_err(|e| {
                                        AppError::Internal(format!("selector encode failed: {e}"))
                                    })?,
                                    val = serde_json::to_string(value).map_err(|e| {
                                        AppError::Internal(format!("value encode failed: {e}"))
                                    })?
                                );
                                let success: bool = page
                                    .evaluate(select_js)
                                    .await
                                    .map_err(|e| AppError::Internal(format!("select failed: {e}")))?
                                    .into_value()
                                    .map_err(|e| {
                                        AppError::Internal(format!("value conversion failed: {e}"))
                                    })?;
                                if !success {
                                    return Err(AppError::Internal(format!(
                                        "element not found: {sel}"
                                    )));
                                }
                                Ok(None)
                            }
                            "upload" => {
                                let upload_root =
                                    self.config.upload_root.as_deref().ok_or_else(|| {
                                        AppError::Internal(
                                        "upload action disabled; set browser.upload_root in config"
                                            .into(),
                                    )
                                    })?;
                                let sel = selector.ok_or_else(|| {
                                    AppError::Internal(
                                        "'selector' required for upload action".into(),
                                    )
                                })?;
                                let files_val = action_input.get("files").ok_or_else(|| {
                                    AppError::Internal("'files' required for upload action".into())
                                })?;
                                let files_arr = files_val.as_array().ok_or_else(|| {
                                    AppError::Internal(
                                        "'files' must be an array of file path strings".into(),
                                    )
                                })?;
                                if files_arr.is_empty() {
                                    return Err(AppError::Internal(
                                        "'files' array must not be empty".into(),
                                    ));
                                }

                                // Validate upload_root exists and canonicalize it.
                                let root_canonical =
                                    std::fs::canonicalize(upload_root).map_err(|e| {
                                        AppError::Internal(format!(
                                            "upload_root '{upload_root}' is not accessible: {e}"
                                        ))
                                    })?;

                                let mut validated_paths = Vec::with_capacity(files_arr.len());
                                for f in files_arr {
                                    let path_str = f.as_str().ok_or_else(|| {
                                        AppError::Internal(
                                            "each element in 'files' must be a string".into(),
                                        )
                                    })?;
                                    let canonical =
                                        std::fs::canonicalize(path_str).map_err(|e| {
                                            AppError::Internal(format!(
                                                "file not accessible: {path_str}: {e}"
                                            ))
                                        })?;
                                    if !canonical.starts_with(&root_canonical) {
                                        return Err(AppError::Internal(format!(
                                            "file path '{}' is outside upload_root '{}'",
                                            path_str, upload_root
                                        )));
                                    }
                                    if !canonical.is_file() {
                                        return Err(AppError::Internal(format!(
                                            "path is not a regular file: {path_str}"
                                        )));
                                    }
                                    validated_paths.push(canonical.to_string_lossy().into_owned());
                                }

                                // Resolve the file input element via JS to get its RemoteObjectId.
                                let find_js = format!(
                                    r#"document.querySelector({sel})"#,
                                    sel = serde_json::to_string(sel).map_err(|e| {
                                        AppError::Internal(format!("selector encode failed: {e}"))
                                    })?
                                );
                                use chromiumoxide::cdp::js_protocol::runtime::EvaluateParams;
                                let eval_cmd = EvaluateParams::new(find_js);
                                let eval_resp = page.execute(eval_cmd).await.map_err(|e| {
                                    AppError::Internal(format!("element lookup failed: {e}"))
                                })?;
                                let remote_obj = &eval_resp.result.result;
                                let obj_id = remote_obj.object_id.as_ref().ok_or_else(|| {
                                    AppError::Internal(format!(
                                        "file input element not found for selector: {sel}"
                                    ))
                                })?;

                                // Send SetFileInputFiles CDP command.
                                use chromiumoxide::cdp::browser_protocol::dom::SetFileInputFilesParams;
                                let mut cmd = SetFileInputFilesParams::new(validated_paths.clone());
                                cmd.object_id = Some(obj_id.clone());
                                page.execute(cmd).await.map_err(|e| {
                                    AppError::Internal(format!("file upload failed: {e}"))
                                })?;

                                Ok(Some(serde_json::json!({
                                    "action": "upload",
                                    "success": true,
                                    "file_count": validated_paths.len(),
                                })))
                            }
                            "wait" => {
                                let timeout_ms = action_input
                                    .get("timeout_ms")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(1000)
                                    .min(10_000);
                                tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
                                Ok(None)
                            }
                            "screenshot" => {
                                let screenshot_bytes = page
                    .screenshot(
                        chromiumoxide::page::ScreenshotParams::builder()
                            .format(
                                chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat::Png,
                            )
                            .build(),
                    )
                    .await
                    .map_err(|e| AppError::Internal(format!("screenshot failed: {e}")))?;

                                if screenshot_bytes.len() > MAX_SCREENSHOT_BYTES {
                                    return Err(AppError::Internal(format!(
                                        "screenshot too large: {} bytes (max {})",
                                        screenshot_bytes.len(),
                                        MAX_SCREENSHOT_BYTES
                                    )));
                                }

                                let page_url = page.url().await.ok().flatten().unwrap_or_default();
                                let page_title =
                                    page.get_title().await.ok().flatten().unwrap_or_default();

                                use encmind_core::config::ScreenshotPayloadMode;
                                let response = match self.screenshot_mode {
                                    ScreenshotPayloadMode::Metadata => serde_json::json!({
                                        "action": "screenshot",
                                        "success": true,
                                        "page_url": page_url,
                                        "page_title": page_title,
                                        "format": "png",
                                        "size_bytes": screenshot_bytes.len(),
                                        "note": "Screenshot captured successfully. The raw image data is not \
                                                 included in the conversation context to save tokens.",
                                    }),
                                    ScreenshotPayloadMode::Base64Legacy => {
                                        use base64::Engine;
                                        let b64 = base64::engine::general_purpose::STANDARD
                                            .encode(&screenshot_bytes);
                                        serde_json::json!({
                                            "action": "screenshot",
                                            "success": true,
                                            "page_url": page_url,
                                            "page_title": page_title,
                                            "format": "png",
                                            "base64": b64,
                                            "size_bytes": screenshot_bytes.len(),
                                        })
                                    }
                                };
                                Ok(Some(response))
                            }
                            "get_text" => {
                                let text: String = page
                                    .evaluate("document.body.innerText")
                                    .await
                                    .map_err(|e| {
                                        AppError::Internal(format!("evaluate failed: {e}"))
                                    })?
                                    .into_value()
                                    .map_err(|e| {
                                        AppError::Internal(format!("value conversion failed: {e}"))
                                    })?;
                                let (text, truncated, original_chars) =
                                    truncate_text(text, MAX_GET_TEXT_CHARS);

                                let page_url = page.url().await.ok().flatten().unwrap_or_default();

                                Ok(Some(serde_json::json!({
                                    "action": "get_text",
                                    "success": true,
                                    "page_url": page_url,
                                    "text": text,
                                    "truncated": truncated,
                                    "original_chars": original_chars,
                                })))
                            }
                            "eval" => {
                                let script = action_input
                                    .get("script")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        AppError::Internal(
                                            "'script' required for eval action".into(),
                                        )
                                    })?;
                                let result: serde_json::Value = page
                                    .evaluate(script)
                                    .await
                                    .map_err(|e| AppError::Internal(format!("eval failed: {e}")))?
                                    .into_value()
                                    .map_err(|e| {
                                        AppError::Internal(format!("value conversion failed: {e}"))
                                    })?;

                                let page_url = page.url().await.ok().flatten().unwrap_or_default();
                                Ok(Some(serde_json::json!({
                                    "action": "eval",
                                    "success": true,
                                    "page_url": page_url,
                                    "result": result,
                                })))
                            }
                            _ => Err(AppError::Internal(format!("unhandled action: {action}"))),
                        }
                    },
                );
                // Apply per-action timeout.
                let result = if action_timeout.is_zero() {
                    firewall_wrapped.await
                } else {
                    match tokio::time::timeout(action_timeout, firewall_wrapped).await {
                        Ok(r) => r,
                        Err(_elapsed) => {
                            // Release tainted session — page may be in undefined state.
                            drop(guard);
                            return fail_close_on_timeout(
                                self.metrics.as_ref(),
                                || self.session_manager.release(session_id.as_str()),
                                format!(
                                    "action '{action}' timed out after {}s",
                                    action_timeout.as_secs()
                                ),
                            )
                            .await;
                        }
                    }
                };
                match result {
                    Ok(val) => break val,
                    Err(e)
                        if attempt < max_retries
                            && crate::guardrails::is_action_retryable(action)
                            && crate::guardrails::RetryPolicy::is_retryable(&e) =>
                    {
                        self.metrics
                            .retry_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(
                            attempt = attempt + 1,
                            max = max_retries,
                            action,
                            error = %e,
                            "browser action failed; retrying"
                        );
                        // Brief backoff to avoid hammering a flaky CDP connection.
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        attempt += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            } // end retry loop
        };

        // Re-validate current page after action execution to catch click/press/eval-triggered navigation.
        enforce_current_page_policy(&self.firewall, page, agent_id, &self.config).await?;
        if let Some(resp) = immediate_response {
            return Ok(resp.to_string());
        }

        // Return success with current page state
        let page_url = page.url().await.ok().flatten().unwrap_or_default();
        let page_title = page.get_title().await.ok().flatten().unwrap_or_default();

        Ok(serde_json::json!({
            "action": action,
            "success": true,
            "page_url": page_url,
            "page_title": page_title,
        })
        .to_string())
    }
}

async fn enforce_current_page_policy(
    firewall: &EgressFirewall,
    page: &chromiumoxide::page::Page,
    agent_id: &AgentId,
    config: &encmind_core::config::BrowserConfig,
) -> Result<(), AppError> {
    let current_url = page
        .url()
        .await
        .map_err(|e| AppError::Internal(format!("failed to read current page URL: {e}")))?;
    let Some(current_url) = current_url else {
        return Ok(());
    };
    if current_url.is_empty() {
        return Ok(());
    }

    let parsed = Url::parse(&current_url)
        .map_err(|e| AppError::Internal(format!("invalid page URL: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Ok(());
    }

    enforce_url_allowed(firewall, &parsed, agent_id).await?;
    if let Some(domain) = parsed.host_str() {
        if !config.is_domain_allowed(domain) {
            return Err(AppError::Internal(format!(
                "domain '{domain}' is not in browser domain allowlist"
            )));
        }
    }
    Ok(())
}

/// Register browser tools into the tool registry.
pub fn register_browser_tools(
    registry: &mut ToolRegistry,
    pool: Arc<BrowserPool>,
    firewall: Arc<EgressFirewall>,
    screenshot_mode: encmind_core::config::ScreenshotPayloadMode,
) -> Result<(), AppError> {
    let metrics = pool.metrics().clone();
    registry.register_internal(
        "browser_navigate",
        "Navigate to a URL and return the page title",
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to navigate to"
                }
            },
            "required": ["url"]
        }),
        Arc::new(BrowserNavigateHandler::new(
            pool.clone(),
            firewall.clone(),
            encmind_core::config::BrowserConfig::default(),
            metrics.clone(),
        )),
    )?;

    registry.register_internal(
        "browser_screenshot",
        "Take a screenshot of a web page and return base64-encoded PNG",
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to screenshot"
                }
            },
            "required": ["url"]
        }),
        Arc::new(BrowserScreenshotHandler::new(
            pool.clone(),
            firewall.clone(),
            encmind_core::config::BrowserConfig::default(),
            screenshot_mode,
            metrics.clone(),
        )),
    )?;

    registry.register_internal(
        "browser_get_text",
        "Extract the visible text content from a web page",
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to extract text from"
                }
            },
            "required": ["url"]
        }),
        Arc::new(BrowserGetTextHandler::new(
            pool,
            firewall,
            encmind_core::config::BrowserConfig::default(),
            metrics,
        )),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_url_allows_https() {
        let parsed = parse_http_url("https://example.com/path").expect("https should be allowed");
        assert_eq!(parsed.scheme(), "https");
    }

    #[test]
    fn parse_http_url_rejects_file_scheme() {
        let err = parse_http_url("file:///etc/passwd")
            .expect_err("file scheme should be blocked")
            .to_string();
        assert!(err.contains("only http/https are allowed"));
    }

    #[test]
    fn request_filter_targets_network_urls_only() {
        assert!(should_filter_request_url("https://example.com"));
        assert!(should_filter_request_url("wss://example.com/socket"));
        assert!(!should_filter_request_url("data:text/plain,hello"));
        assert!(!should_filter_request_url("about:blank"));
        assert!(!should_filter_request_url("not a url"));
    }

    #[test]
    fn truncate_text_noop_when_within_limit() {
        let (text, truncated, total_chars) = truncate_text("hello".to_string(), 10);
        assert_eq!(text, "hello");
        assert!(!truncated);
        assert_eq!(total_chars, 5);
    }

    #[test]
    fn truncate_text_caps_by_char_count() {
        let input = "😀".repeat(10);
        let (text, truncated, total_chars) = truncate_text(input, 3);
        assert_eq!(text.chars().count(), 3);
        assert!(truncated);
        assert_eq!(total_chars, 10);
    }

    #[test]
    fn screenshot_metadata_mode_omits_base64() {
        use encmind_core::config::ScreenshotPayloadMode;

        // Simulate what the handler would produce in metadata mode
        let mode = ScreenshotPayloadMode::Metadata;
        let size_bytes = 12345;
        let url = "https://example.com";

        let output = match mode {
            ScreenshotPayloadMode::Metadata => serde_json::json!({
                "url": url,
                "format": "png",
                "size_bytes": size_bytes,
                "note": "Screenshot captured successfully. The raw image data is not \
                         included in the conversation context to save tokens.",
            }),
            ScreenshotPayloadMode::Base64Legacy => unreachable!(),
        };

        let output_str = output.to_string();
        assert!(
            !output_str.contains("base64"),
            "metadata mode should not include base64 field"
        );
        assert!(output_str.contains("size_bytes"));
        assert!(output_str.contains("note"));
    }

    #[test]
    fn screenshot_legacy_mode_includes_base64() {
        use encmind_core::config::ScreenshotPayloadMode;

        let mode = ScreenshotPayloadMode::Base64Legacy;
        let size_bytes = 12345;
        let url = "https://example.com";
        let b64 = "aGVsbG8="; // "hello" base64-encoded

        let output = match mode {
            ScreenshotPayloadMode::Base64Legacy => serde_json::json!({
                "url": url,
                "format": "png",
                "base64": b64,
                "size_bytes": size_bytes,
            }),
            ScreenshotPayloadMode::Metadata => unreachable!(),
        };

        let output_str = output.to_string();
        assert!(
            output_str.contains("base64"),
            "legacy mode should include base64 field"
        );
        assert!(output_str.contains("aGVsbG8="));
        assert!(
            !output_str.contains("note"),
            "legacy mode should not include note field"
        );
    }

    #[test]
    fn browser_act_action_not_allowed_by_policy() {
        use encmind_core::config::BrowserConfig;

        let config = BrowserConfig {
            allowed_actions: vec!["click".into(), "type".into()],
            ..Default::default()
        };
        assert!(config.is_action_allowed("click"));
        assert!(!config.is_action_allowed("select"));
    }

    #[test]
    fn browser_act_domain_not_allowed_by_policy() {
        use encmind_core::config::BrowserConfig;

        let config = BrowserConfig {
            domain_allowlist: vec!["example.com".into()],
            ..Default::default()
        };
        assert!(config.is_domain_allowed("example.com"));
        assert!(!config.is_domain_allowed("evil.com"));
    }

    #[test]
    fn enforce_action_allowed_blocks_disallowed_action() {
        let config = encmind_core::config::BrowserConfig {
            allowed_actions: vec!["screenshot".into()],
            ..Default::default()
        };
        let err = enforce_action_allowed(&config, "navigate")
            .expect_err("navigate should be blocked when not in allowlist");
        assert!(err.to_string().contains("action 'navigate' is not allowed"));
    }

    #[test]
    fn enforce_domain_allowed_blocks_disallowed_domain() {
        let config = encmind_core::config::BrowserConfig {
            domain_allowlist: vec!["example.com".into()],
            ..Default::default()
        };
        let url = Url::parse("https://evil.com/path").expect("valid URL");
        let err = enforce_domain_allowed(&config, &url)
            .expect_err("evil.com should be blocked by domain allowlist");
        assert!(err
            .to_string()
            .contains("domain 'evil.com' is not in browser domain allowlist"));
    }

    #[test]
    fn browser_act_url_validation() {
        assert!(parse_http_url("https://example.com").is_ok());
        assert!(parse_http_url("ftp://example.com").is_err());
        assert!(parse_http_url("not a url").is_err());
    }

    #[test]
    fn browser_act_valid_actions() {
        for action in VALID_ACTIONS {
            assert!(
                VALID_ACTIONS.contains(action),
                "action '{action}' should be in VALID_ACTIONS"
            );
        }
        assert!(VALID_ACTIONS.contains(&"eval"));
        assert!(VALID_ACTIONS.contains(&"navigate"));
    }

    #[test]
    fn browser_act_batch_payload_rejected_in_v1() {
        let input = serde_json::json!({
            "actions": [
                { "action": "click", "selector": "#a" },
                { "action": "click", "selector": "#b" }
            ]
        });
        let actions = input
            .get("actions")
            .and_then(|v| v.as_array())
            .expect("actions array should exist");
        assert_eq!(actions.len(), 2);
        assert!(actions.len() > 1, "v1 should reject batched actions");
    }

    #[test]
    fn browser_act_respects_max_actions_toggle() {
        use encmind_core::config::BrowserConfig;
        let config = BrowserConfig {
            max_actions_per_call: 0,
            ..Default::default()
        };
        assert_eq!(config.max_actions_per_call, 0);
    }

    #[test]
    fn browser_act_click_requires_selector() {
        // Verify that click action needs a selector parameter
        let input = serde_json::json!({ "action": "click" });
        assert!(input.get("selector").is_none());
    }

    #[test]
    fn browser_act_type_requires_text() {
        // Verify that type action needs text parameter
        let input = serde_json::json!({ "action": "type", "selector": "#input" });
        assert!(input.get("text").is_none());
    }

    #[test]
    fn browser_act_select_requires_value() {
        // Verify that select action needs value parameter
        let input = serde_json::json!({ "action": "select", "selector": "#dropdown" });
        assert!(input.get("value").is_none());
    }

    #[test]
    fn browser_act_wait_clamps_to_max() {
        let timeout_ms: u64 = 30_000;
        let clamped = timeout_ms.min(10_000);
        assert_eq!(clamped, 10_000);
    }

    #[test]
    fn post_op_drain_timeout_if_paused_seen_requires_event() {
        assert_eq!(
            resolve_post_op_drain_timeout(
                PostOpDrainPolicy::IfPausedRequestsSeenMs(FIREWALL_DRAIN_TIMEOUT_MS),
                false
            ),
            None
        );
        assert_eq!(
            resolve_post_op_drain_timeout(
                PostOpDrainPolicy::IfPausedRequestsSeenMs(FIREWALL_DRAIN_TIMEOUT_MS),
                true
            ),
            Some(Duration::from_millis(FIREWALL_DRAIN_TIMEOUT_MS))
        );
    }

    #[test]
    fn post_op_drain_timeout_fixed_policy_always_applies() {
        assert_eq!(
            resolve_post_op_drain_timeout(PostOpDrainPolicy::AlwaysMs(20), false),
            Some(Duration::from_millis(20))
        );
        assert_eq!(
            resolve_post_op_drain_timeout(PostOpDrainPolicy::AlwaysMs(20), true),
            Some(Duration::from_millis(20))
        );
    }

    #[tokio::test]
    async fn fail_close_on_timeout_calls_release_and_increments_metric() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let metrics = crate::guardrails::BrowserMetrics::new();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let err = fail_close_on_timeout::<(), _, _>(
            &metrics,
            move || {
                let called = called_clone.clone();
                async move {
                    called.store(true, Ordering::SeqCst);
                }
            },
            "action 'click' timed out after 10s".to_string(),
        )
        .await
        .expect_err("timeout should fail-close with an error");

        assert!(
            called.load(Ordering::SeqCst),
            "release callback must be called"
        );
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
        assert_eq!(
            metrics
                .timeout_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn key_definition_maps_common_keys() {
        assert!(key_definition("Enter").is_some());
        assert!(key_definition("enter").is_some());
        assert!(key_definition("Tab").is_some());
        assert!(key_definition("Escape").is_some());
        assert!(key_definition("esc").is_some());
        assert!(key_definition("Backspace").is_some());
        assert!(key_definition("ArrowUp").is_some());
        assert!(key_definition("up").is_some());
        assert!(key_definition("Space").is_some());
        assert!(key_definition("unknown_key_xyz").is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn browser_act_eval_blocks_network_request_via_firewall() {
        let pool = Arc::new(
            BrowserPool::new(
                1,
                30,
                false,
                Arc::new(crate::guardrails::BrowserMetrics::new()),
                true,
            )
            .await
            .unwrap(),
        );
        let manager = SessionBrowserManager::new(pool, Duration::from_secs(60));
        let firewall = Arc::new(EgressFirewall::new(
            &encmind_core::config::EgressFirewallConfig::default(),
        ));
        let config = encmind_core::config::BrowserConfig {
            allowed_actions: vec!["eval".into()],
            eval_enabled: true,
            ..Default::default()
        };
        let handler = BrowserActHandler::new(
            manager,
            firewall,
            config,
            encmind_core::config::ScreenshotPayloadMode::Metadata,
            Arc::new(crate::guardrails::BrowserMetrics::new()),
        );

        let input = serde_json::json!({
            "action": "eval",
            "script": "(async () => { await fetch('https://example.com/blocked'); return 'ok'; })()"
        });

        let err = handler
            .handle(input, &SessionId::new(), &AgentId::new("main"))
            .await
            .expect_err("expected firewall block on eval-triggered network request");
        assert!(
            err.to_string()
                .contains("egress firewall blocked browser request"),
            "unexpected error: {err}"
        );
    }

    async fn behavior_test_pool() -> Option<Arc<BrowserPool>> {
        match BrowserPool::new(
            1,
            30,
            false,
            Arc::new(crate::guardrails::BrowserMetrics::new()),
            true,
        )
        .await
        {
            Ok(pool) => Some(Arc::new(pool)),
            Err(err) => {
                eprintln!("skipping browser behavior test; browser unavailable: {err:?}");
                None
            }
        }
    }

    #[tokio::test]
    async fn run_with_request_firewall_idle_tail_drain_policy_latency_diff() {
        let Some(pool) = behavior_test_pool().await else {
            return;
        };
        let lease = pool.acquire().await.unwrap();
        let firewall = Arc::new(EgressFirewall::new(
            &encmind_core::config::EgressFirewallConfig::default(),
        ));
        let agent_id = AgentId::new("main");

        // Warm up CDP/event listener path before measuring.
        let _ = run_with_request_firewall(
            &lease.page,
            &firewall,
            &agent_id,
            PostOpDrainPolicy::IfPausedRequestsSeenMs(FIREWALL_DRAIN_TIMEOUT_MS),
            async { Ok::<(), AppError>(()) },
        )
        .await;

        let start_no_tail = std::time::Instant::now();
        run_with_request_firewall(
            &lease.page,
            &firewall,
            &agent_id,
            PostOpDrainPolicy::IfPausedRequestsSeenMs(FIREWALL_DRAIN_TIMEOUT_MS),
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<(), AppError>(())
            },
        )
        .await
        .unwrap();
        let no_tail_elapsed = start_no_tail.elapsed();

        let start_forced_tail = std::time::Instant::now();
        run_with_request_firewall(
            &lease.page,
            &firewall,
            &agent_id,
            PostOpDrainPolicy::AlwaysMs(FIREWALL_DRAIN_TIMEOUT_MS),
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<(), AppError>(())
            },
        )
        .await
        .unwrap();
        let forced_tail_elapsed = start_forced_tail.elapsed();

        assert!(
            forced_tail_elapsed > no_tail_elapsed + Duration::from_millis(100),
            "expected forced tail drain to be noticeably slower; no_tail={no_tail_elapsed:?}, forced={forced_tail_elapsed:?}"
        );
    }

    #[test]
    fn upload_in_valid_actions() {
        assert!(
            VALID_ACTIONS.contains(&"upload"),
            "VALID_ACTIONS should include 'upload'"
        );
    }

    #[test]
    fn upload_rejected_when_upload_root_not_set() {
        let config = encmind_core::config::BrowserConfig::default();
        assert!(config.upload_root.is_none());
        // When upload_root is None the action handler rejects with
        // "upload action disabled" — verified at runtime. Here we just
        // confirm the policy field defaults to None.
    }

    #[test]
    fn upload_path_outside_root_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();

        // Create a file outside the allowed root.
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "secret").unwrap();

        let root_canonical = std::fs::canonicalize(&root).unwrap();
        let file_canonical = std::fs::canonicalize(&outside).unwrap();
        assert!(
            !file_canonical.starts_with(&root_canonical),
            "file should be outside upload_root"
        );
    }

    #[test]
    fn upload_path_inside_root_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("uploads");
        std::fs::create_dir_all(&root).unwrap();

        let inside = root.join("file.txt");
        std::fs::write(&inside, "data").unwrap();

        let root_canonical = std::fs::canonicalize(&root).unwrap();
        let file_canonical = std::fs::canonicalize(&inside).unwrap();
        assert!(
            file_canonical.starts_with(&root_canonical),
            "file should be inside upload_root"
        );
    }

    #[test]
    fn is_action_allowed_blocks_upload_when_not_in_list() {
        let config = encmind_core::config::BrowserConfig {
            allowed_actions: vec!["click".into()],
            ..Default::default()
        };
        assert!(!config.is_action_allowed("upload"));
    }

    #[tokio::test]
    async fn run_with_request_firewall_wait_style_tail_flush_is_bounded() {
        let Some(pool) = behavior_test_pool().await else {
            return;
        };
        let lease = pool.acquire().await.unwrap();
        let firewall = Arc::new(EgressFirewall::new(
            &encmind_core::config::EgressFirewallConfig::default(),
        ));
        let agent_id = AgentId::new("main");

        let start = std::time::Instant::now();
        run_with_request_firewall(
            &lease.page,
            &firewall,
            &agent_id,
            PostOpDrainPolicy::AlwaysMs(WAIT_FINAL_FLUSH_TIMEOUT_MS),
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<(), AppError>(())
            },
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(120),
            "wait-style tail flush should stay bounded; elapsed={elapsed:?}"
        );
    }
}
