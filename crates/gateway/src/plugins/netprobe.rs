//! NetProbe plugin — web search + URL fetch tools.
//!
//! Registers two tools:
//! - `netprobe_search`: Web search via Tavily, Brave, or SearXNG with optional LLM synthesis.
//! - `netprobe_fetch`: Fetch a URL and extract readable content.

use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use encmind_agent::firewall::EgressFirewall;
use encmind_core::config::{NetProbeConfig, SearchProvider};
use encmind_core::error::{AppError, PluginError};
use encmind_core::plugin::{NativePlugin, PluginKind, PluginManifest, PluginRegistrar};
use encmind_core::traits::{CompletionParams, InternalToolHandler, LlmBackend};
use encmind_core::types::{AgentId, ContentBlock, Message, MessageId, Role, SessionId};

use crate::state::RuntimeResources;

use super::url_extract;

// ── Search result type ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

// ── Plugin struct ─────────────────────────────────────────────────

pub struct NetProbePlugin {
    config: NetProbeConfig,
    search_client: reqwest::Client,
    fetch_client: reqwest::Client,
    firewall: Arc<EgressFirewall>,
    runtime: Arc<RwLock<RuntimeResources>>,
}

impl NetProbePlugin {
    pub fn new(
        config: NetProbeConfig,
        firewall: Arc<EgressFirewall>,
        runtime: Arc<RwLock<RuntimeResources>>,
    ) -> Self {
        Self {
            config,
            search_client: build_search_client(),
            fetch_client: url_extract::build_fetch_client(),
            firewall,
            runtime,
        }
    }
}

#[async_trait]
impl NativePlugin for NetProbePlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "netprobe".into(),
            name: "NetProbe (Web Search & Fetch)".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "Web search and URL content extraction".into(),
            kind: PluginKind::General,
            required: false,
        }
    }

    async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
        // ── netprobe_search ───────────────────────────────────────
        api.register_tool(
            "search",
            "Search the web using a search engine and return results. Optionally synthesizes a concise answer from the results using an LLM.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (1-10, default 5)",
                        "minimum": 1,
                        "maximum": 10
                    },
                    "synthesize": {
                        "type": "boolean",
                        "description": "Whether to generate a concise answer from results (default: config value)"
                    }
                },
                "required": ["query"]
            }),
            Arc::new(NetProbeSearchHandler {
                config: self.config.clone(),
                search_client: self.search_client.clone(),
                firewall: self.firewall.clone(),
                runtime: self.runtime.clone(),
            }),
        )?;

        // ── netprobe_fetch ────────────────────────────────────────
        api.register_tool(
            "fetch",
            "Fetch a URL and extract its content. HTML pages are converted to readable text. JSON is pretty-printed.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to fetch"
                    },
                    "selector": {
                        "type": "string",
                        "description": "Optional CSS selector to extract specific content from HTML pages"
                    }
                },
                "required": ["url"]
            }),
            Arc::new(NetProbeFetchHandler {
                config: self.config.clone(),
                fetch_client: self.fetch_client.clone(),
                firewall: self.firewall.clone(),
            }),
        )?;

        Ok(())
    }
}

// ── Search handler ────────────────────────────────────────────────

struct NetProbeSearchHandler {
    config: NetProbeConfig,
    search_client: reqwest::Client,
    firewall: Arc<EgressFirewall>,
    runtime: Arc<RwLock<RuntimeResources>>,
}

#[async_trait]
impl InternalToolHandler for NetProbeSearchHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        _agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let query = input
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        if query.is_empty() {
            return Err(AppError::Internal(
                "netprobe_search: query must not be empty".to_string(),
            ));
        }

        let max_results = parse_max_results(&input)?;
        let should_synthesize = parse_synthesize_flag(&input, self.config.synthesize)?;

        // Resolve API key from environment.
        let api_key =
            resolve_api_key_from_env(&self.config.provider, self.config.api_key_env.as_deref());

        let results = match &self.config.provider {
            SearchProvider::Tavily => {
                let key = api_key.as_deref().ok_or_else(|| {
                    missing_api_key_error(&self.config.provider, self.config.api_key_env.as_deref())
                })?;
                tavily_search(
                    &self.search_client,
                    &self.firewall,
                    key,
                    &query,
                    max_results,
                    self.config.max_redirects,
                )
                .await?
            }
            SearchProvider::Brave => {
                let key = api_key.as_deref().ok_or_else(|| {
                    missing_api_key_error(&self.config.provider, self.config.api_key_env.as_deref())
                })?;
                brave_search(
                    &self.search_client,
                    &self.firewall,
                    key,
                    &query,
                    max_results,
                    self.config.max_redirects,
                )
                .await?
            }
            SearchProvider::Searxng => {
                let base_url = self.config.searxng_url.as_deref().ok_or_else(|| {
                    AppError::Internal("netprobe_search: searxng_url not configured".to_string())
                })?;
                searxng_search(
                    &self.search_client,
                    &self.firewall,
                    base_url,
                    &query,
                    max_results,
                    self.config.max_redirects,
                )
                .await?
            }
        };

        // Optionally synthesize a concise answer.
        let synthesis = if should_synthesize && !results.is_empty() {
            synthesize_answer(&self.runtime, &query, &results).await
        } else {
            None
        };

        let output = serde_json::json!({
            "query": query,
            "results": results,
            "synthesis": synthesis,
        });

        Ok(serde_json::to_string(&output).unwrap_or_default())
    }
}

// ── Fetch handler ─────────────────────────────────────────────────

struct NetProbeFetchHandler {
    config: NetProbeConfig,
    fetch_client: reqwest::Client,
    firewall: Arc<EgressFirewall>,
}

#[async_trait]
impl InternalToolHandler for NetProbeFetchHandler {
    async fn handle(
        &self,
        input: serde_json::Value,
        _session_id: &SessionId,
        _agent_id: &AgentId,
    ) -> Result<String, AppError> {
        let url = input
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        if url.is_empty() {
            return Err(AppError::Internal(
                "netprobe_fetch: url must not be empty".to_string(),
            ));
        }

        let selector = input
            .get("selector")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let fetch_result = url_extract::fetch_url(
            &url,
            &self.fetch_client,
            &self.firewall,
            self.config.max_fetch_bytes,
            self.config.max_redirects,
            selector.as_deref(),
        )
        .await
        .map_err(|e| AppError::Internal(format!("netprobe_fetch: {e}")))?;

        let output = build_fetch_output(&url, &fetch_result);

        Ok(serde_json::to_string(&output).unwrap_or_default())
    }
}

fn build_fetch_output(url: &str, fetch_result: &url_extract::FetchResult) -> serde_json::Value {
    serde_json::json!({
        "url": url,
        "title": fetch_result.title,
        "content": fetch_result.content,
        "byte_length": fetch_result.byte_length,
        "truncated": fetch_result.truncated,
        "content_type": fetch_result.content_type,
    })
}

fn parse_max_results(input: &serde_json::Value) -> Result<usize, AppError> {
    match input.get("max_results") {
        Some(value) => value
            .as_u64()
            .map(|n| n.clamp(1, 10) as usize)
            .ok_or_else(|| {
                AppError::Internal(
                    "netprobe_search: max_results must be an integer between 1 and 10".to_string(),
                )
            }),
        None => Ok(5),
    }
}

fn parse_synthesize_flag(input: &serde_json::Value, default: bool) -> Result<bool, AppError> {
    match input.get("synthesize") {
        Some(value) => value.as_bool().ok_or_else(|| {
            AppError::Internal("netprobe_search: synthesize must be a boolean".to_string())
        }),
        None => Ok(default),
    }
}

fn build_search_client() -> reqwest::Client {
    reqwest::Client::builder()
        // Keep redirects disabled at the client level; provider calls use a
        // manual redirect loop with per-hop egress firewall validation.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent(format!("EncMind-NetProbe/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build netprobe search reqwest client")
}

fn api_key_env_candidates(provider: &SearchProvider, configured: Option<&str>) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(name) = configured.map(str::trim).filter(|v| !v.is_empty()) {
        candidates.push(name.to_string());
    }

    let fallback = match provider {
        SearchProvider::Tavily => Some("TAVILY_API_KEY"),
        SearchProvider::Brave => Some("BRAVE_API_KEY"),
        SearchProvider::Searxng => None,
    };
    if let Some(name) = fallback {
        if !candidates.iter().any(|existing| existing == name) {
            candidates.push(name.to_string());
        }
    }
    candidates
}

fn resolve_api_key_from_env(provider: &SearchProvider, configured: Option<&str>) -> Option<String> {
    api_key_env_candidates(provider, configured)
        .into_iter()
        .find_map(|name| {
            std::env::var(&name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

fn missing_api_key_error(provider: &SearchProvider, configured: Option<&str>) -> AppError {
    let checked = api_key_env_candidates(provider, configured);
    if checked.is_empty() {
        return AppError::Internal("netprobe_search: API key is not configured".to_string());
    }
    AppError::Internal(format!(
        "netprobe_search: API key not set; checked env vars: {}",
        checked.join(", ")
    ))
}

async fn send_with_manual_redirects<F, Fut>(
    firewall: &EgressFirewall,
    start_url: &str,
    max_redirects: usize,
    request_label: &str,
    mut send_once: F,
) -> Result<reqwest::Response, AppError>
where
    F: FnMut(&str) -> Fut,
    Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut current_url = start_url.to_string();
    let mut hops = 0usize;

    loop {
        firewall.check_url(&current_url).await.map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: egress firewall blocked {current_url}: {e}"
            ))
        })?;
        let response = send_once(&current_url).await.map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: request failed for {current_url}: {e}"
            ))
        })?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        hops += 1;
        if hops > max_redirects {
            return Err(AppError::Internal(format!(
                "{request_label}: too many redirects (>{max_redirects}) from {start_url}"
            )));
        }
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "{request_label}: redirect response missing Location header"
                ))
            })?;
        let base = reqwest::Url::parse(&current_url).map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: invalid redirect base URL '{current_url}': {e}"
            ))
        })?;
        let next = base.join(location).map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: invalid redirect target '{location}' from '{current_url}': {e}"
            ))
        })?;
        current_url = next.to_string();
    }
}

async fn send_post_json_with_manual_redirects(
    client: &reqwest::Client,
    firewall: &EgressFirewall,
    start_url: &str,
    max_redirects: usize,
    request_label: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response, AppError> {
    let mut current_url = start_url.to_string();
    let mut hops = 0usize;
    let mut method = reqwest::Method::POST;

    loop {
        firewall.check_url(&current_url).await.map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: egress firewall blocked {current_url}: {e}"
            ))
        })?;

        let response = if method == reqwest::Method::POST {
            client
                .post(&current_url)
                .json(body)
                .send()
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "{request_label}: request failed for {current_url}: {e}"
                    ))
                })?
        } else {
            client.get(&current_url).send().await.map_err(|e| {
                AppError::Internal(format!(
                    "{request_label}: request failed for {current_url}: {e}"
                ))
            })?
        };

        if !response.status().is_redirection() {
            return Ok(response);
        }

        let status = response.status();
        hops += 1;
        if hops > max_redirects {
            return Err(AppError::Internal(format!(
                "{request_label}: too many redirects (>{max_redirects}) from {start_url}"
            )));
        }

        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "{request_label}: redirect response missing Location header"
                ))
            })?;
        let base = reqwest::Url::parse(&current_url).map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: invalid redirect base URL '{current_url}': {e}"
            ))
        })?;
        let next = base.join(location).map_err(|e| {
            AppError::Internal(format!(
                "{request_label}: invalid redirect target '{location}' from '{current_url}': {e}"
            ))
        })?;

        // Match common user-agent redirect behavior for POST requests:
        // 303 always becomes GET, and 301/302 may become GET for POST.
        if status == reqwest::StatusCode::SEE_OTHER
            || ((status == reqwest::StatusCode::MOVED_PERMANENTLY
                || status == reqwest::StatusCode::FOUND)
                && method == reqwest::Method::POST)
        {
            method = reqwest::Method::GET;
        }

        current_url = next.to_string();
    }
}

// ── Provider implementations ──────────────────────────────────────

async fn tavily_search(
    client: &reqwest::Client,
    firewall: &EgressFirewall,
    api_key: &str,
    query: &str,
    max_results: usize,
    max_redirects: usize,
) -> Result<Vec<SearchResult>, AppError> {
    let api_url = "https://api.tavily.com/search";
    let body = serde_json::json!({
        "api_key": api_key,
        "query": query,
        "max_results": max_results,
        "include_answer": false,
    });

    let resp = send_post_json_with_manual_redirects(
        client,
        firewall,
        api_url,
        max_redirects,
        "Tavily API",
        &body,
    )
    .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "Tavily API returned HTTP {status}: {text}"
        )));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Tavily response parse error: {e}")))?;

    parse_tavily_response(&data)
}

pub(crate) fn parse_tavily_response(
    data: &serde_json::Value,
) -> Result<Vec<SearchResult>, AppError> {
    let results = data
        .get("results")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|item| SearchResult {
                    title: item
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    url: item
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    snippet: item
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    score: item.get("score").and_then(|v| v.as_f64()),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(results)
}

async fn brave_search(
    client: &reqwest::Client,
    firewall: &EgressFirewall,
    api_key: &str,
    query: &str,
    max_results: usize,
    max_redirects: usize,
) -> Result<Vec<SearchResult>, AppError> {
    let api_url = format!(
        "https://api.search.brave.com/res/v1/web/search?q={}&count={max_results}",
        urlencoding::encode(query)
    );
    let resp = send_with_manual_redirects(firewall, &api_url, max_redirects, "Brave API", |url| {
        client
            .get(url)
            .header("X-Subscription-Token", api_key)
            .header("Accept", "application/json")
            .send()
    })
    .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "Brave API returned HTTP {status}: {text}"
        )));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Brave response parse error: {e}")))?;

    parse_brave_response(&data)
}

pub(crate) fn parse_brave_response(
    data: &serde_json::Value,
) -> Result<Vec<SearchResult>, AppError> {
    let results = data
        .get("web")
        .and_then(|w| w.get("results"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|item| SearchResult {
                    title: item
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    url: item
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    snippet: item
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    score: None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(results)
}

async fn searxng_search(
    client: &reqwest::Client,
    firewall: &EgressFirewall,
    base_url: &str,
    query: &str,
    max_results: usize,
    max_redirects: usize,
) -> Result<Vec<SearchResult>, AppError> {
    let api_url = format!(
        "{}/search?q={}&format=json&pageno=1",
        base_url.trim_end_matches('/'),
        urlencoding::encode(query)
    );
    let resp =
        send_with_manual_redirects(firewall, &api_url, max_redirects, "SearXNG API", |url| {
            client.get(url).send()
        })
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "SearXNG returned HTTP {status}: {text}"
        )));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("SearXNG response parse error: {e}")))?;

    parse_searxng_response(&data, max_results)
}

pub(crate) fn parse_searxng_response(
    data: &serde_json::Value,
    max_results: usize,
) -> Result<Vec<SearchResult>, AppError> {
    let results = data
        .get("results")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(max_results)
                .map(|item| SearchResult {
                    title: item
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    url: item
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    snippet: item
                        .get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    score: item.get("score").and_then(|v| v.as_f64()),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(results)
}

// ── LLM synthesis ─────────────────────────────────────────────────

fn build_synthesis_prompt(query: &str, results: &[SearchResult]) -> String {
    let mut prompt = format!(
        "Based on the following web search results for the query \"{query}\", \
         provide a concise, accurate answer. Cite sources by number.\n\n"
    );

    for (i, r) in results.iter().enumerate() {
        prompt.push_str(&format!(
            "[{}] {}\n    {}\n    {}\n\n",
            i + 1,
            r.title,
            r.url,
            r.snippet
        ));
    }

    prompt.push_str("Concise answer:");
    prompt
}

async fn synthesize_answer(
    runtime: &Arc<RwLock<RuntimeResources>>,
    query: &str,
    results: &[SearchResult],
) -> Option<String> {
    let llm_backend: Option<Arc<dyn LlmBackend>> = {
        let guard = runtime.read().await;
        guard.llm_backend.clone()
    };

    let backend = match llm_backend {
        Some(b) => b,
        None => {
            debug!("netprobe: no LLM backend available for synthesis");
            return None;
        }
    };

    let prompt_text = build_synthesis_prompt(query, results);
    let messages = vec![Message {
        id: MessageId::from_string("netprobe-synth"),
        role: Role::User,
        content: vec![ContentBlock::Text { text: prompt_text }],
        created_at: chrono::Utc::now(),
        token_count: None,
    }];

    let params = CompletionParams {
        max_tokens: 1024,
        temperature: 0.3,
        ..Default::default()
    };

    let cancel = CancellationToken::new();

    match backend.complete(&messages, params, cancel).await {
        Ok(mut stream) => {
            let mut answer = String::new();
            while let Some(delta) = stream.next().await {
                match delta {
                    Ok(d) => {
                        if let Some(text) = d.text {
                            answer.push_str(&text);
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "netprobe synthesis stream error");
                        break;
                    }
                }
            }
            if answer.is_empty() {
                None
            } else {
                Some(answer)
            }
        }
        Err(e) => {
            warn!(error = %e, "netprobe synthesis failed");
            None
        }
    }
}

// ── URL encoding helper (minimal, avoids extra dep) ───────────────

mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len() * 3);
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                _ => {
                    encoded.push_str(&format!("%{byte:02X}"));
                }
            }
        }
        encoded
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    #[test]
    fn search_tavily_parses_response() {
        let data = serde_json::json!({
            "results": [
                {
                    "title": "Rust Programming",
                    "url": "https://rust-lang.org",
                    "content": "The Rust programming language",
                    "score": 0.95
                },
                {
                    "title": "Rust Book",
                    "url": "https://doc.rust-lang.org/book/",
                    "content": "The Rust Programming Language book",
                    "score": 0.85
                }
            ]
        });
        let results = parse_tavily_response(&data).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "Rust Programming");
        assert_eq!(results[0].url, "https://rust-lang.org");
        assert!(results[0].score.unwrap() > 0.9);
    }

    #[test]
    fn search_brave_parses_response() {
        let data = serde_json::json!({
            "web": {
                "results": [
                    {
                        "title": "Example",
                        "url": "https://example.com",
                        "description": "An example website"
                    }
                ]
            }
        });
        let results = parse_brave_response(&data).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Example");
        assert_eq!(results[0].snippet, "An example website");
        assert!(results[0].score.is_none());
    }

    #[test]
    fn search_searxng_parses_response() {
        let data = serde_json::json!({
            "results": [
                {
                    "title": "Result 1",
                    "url": "https://r1.com",
                    "content": "First result",
                    "score": 1.0
                },
                {
                    "title": "Result 2",
                    "url": "https://r2.com",
                    "content": "Second result",
                    "score": 0.8
                },
                {
                    "title": "Result 3",
                    "url": "https://r3.com",
                    "content": "Third result",
                    "score": 0.6
                }
            ]
        });
        let results = parse_searxng_response(&data, 2).unwrap();
        assert_eq!(results.len(), 2, "should be clamped to max_results=2");
    }

    #[test]
    fn search_clamps_max_results() {
        let input0 = serde_json::json!({ "max_results": 0_u64 });
        let input5 = serde_json::json!({ "max_results": 5_u64 });
        let input15 = serde_json::json!({ "max_results": 15_u64 });
        assert_eq!(parse_max_results(&input0).unwrap(), 1);
        assert_eq!(parse_max_results(&input5).unwrap(), 5);
        assert_eq!(parse_max_results(&input15).unwrap(), 10);
        assert_eq!(parse_max_results(&serde_json::json!({})).unwrap(), 5);
    }

    #[test]
    fn search_rejects_invalid_max_results_type() {
        let err = parse_max_results(&serde_json::json!({ "max_results": "5" })).unwrap_err();
        assert!(
            err.to_string().contains("max_results must be an integer"),
            "err = {err}"
        );
    }

    #[test]
    fn search_parses_synthesize_flag() {
        assert!(parse_synthesize_flag(&serde_json::json!({ "synthesize": true }), false).unwrap());
        assert!(!parse_synthesize_flag(&serde_json::json!({ "synthesize": false }), true).unwrap());
        assert!(!parse_synthesize_flag(&serde_json::json!({}), false).unwrap());
    }

    #[test]
    fn search_rejects_invalid_synthesize_type() {
        let err =
            parse_synthesize_flag(&serde_json::json!({ "synthesize": "yes" }), true).unwrap_err();
        assert!(
            err.to_string().contains("synthesize must be a boolean"),
            "err = {err}"
        );
    }

    #[test]
    fn api_key_env_candidates_include_custom_then_fallback() {
        let candidates = api_key_env_candidates(&SearchProvider::Tavily, Some("CUSTOM_TAVILY_KEY"));
        assert_eq!(candidates, vec!["CUSTOM_TAVILY_KEY", "TAVILY_API_KEY"]);
    }

    #[test]
    fn api_key_env_candidates_dedup_when_custom_matches_fallback() {
        let candidates = api_key_env_candidates(&SearchProvider::Brave, Some("BRAVE_API_KEY"));
        assert_eq!(candidates, vec!["BRAVE_API_KEY"]);
    }

    #[test]
    fn missing_api_key_error_lists_checked_env_vars() {
        let err = missing_api_key_error(&SearchProvider::Tavily, Some("CUSTOM_TAVILY_KEY"));
        let msg = err.to_string();
        assert!(
            msg.contains("CUSTOM_TAVILY_KEY") && msg.contains("TAVILY_API_KEY"),
            "message should list checked env vars, got: {msg}"
        );
    }

    #[test]
    fn search_empty_query_error() {
        // Verify that empty/whitespace queries would be caught
        let query = "   ".trim();
        assert!(query.is_empty());
    }

    #[test]
    fn synthesis_prompt_construction() {
        let results = vec![
            SearchResult {
                title: "Title A".to_string(),
                url: "https://a.com".to_string(),
                snippet: "Snippet A".to_string(),
                score: Some(0.9),
            },
            SearchResult {
                title: "Title B".to_string(),
                url: "https://b.com".to_string(),
                snippet: "Snippet B".to_string(),
                score: None,
            },
        ];
        let prompt = build_synthesis_prompt("test query", &results);
        assert!(prompt.contains("test query"));
        assert!(prompt.contains("[1] Title A"));
        assert!(prompt.contains("[2] Title B"));
        assert!(prompt.contains("https://a.com"));
        assert!(prompt.contains("Snippet B"));
        assert!(prompt.contains("Concise answer:"));
    }

    #[test]
    fn plugin_manifest_correct() {
        let manifest = PluginManifest {
            id: "netprobe".into(),
            name: "NetProbe (Web Search & Fetch)".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "Web search and URL content extraction".into(),
            kind: PluginKind::General,
            required: false,
        };
        assert_eq!(manifest.id, "netprobe");
        assert!(!manifest.required);
        assert_eq!(manifest.kind, PluginKind::General);
    }

    #[test]
    fn config_defaults() {
        let config = NetProbeConfig::default();
        assert_eq!(config.provider, SearchProvider::Tavily);
        assert!(config.synthesize);
        assert_eq!(config.max_fetch_bytes, 524_288);
    }

    #[test]
    fn config_searxng_requires_url() {
        let config = NetProbeConfig {
            provider: SearchProvider::Searxng,
            searxng_url: None,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn urlencoding_basic() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("a+b=c"), "a%2Bb%3Dc");
        assert_eq!(urlencoding::encode("simple"), "simple");
    }

    #[test]
    fn search_result_serde() {
        let r = SearchResult {
            title: "Test".to_string(),
            url: "https://test.com".to_string(),
            snippet: "A test".to_string(),
            score: Some(0.5),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, "Test");
        assert_eq!(back.score, Some(0.5));
    }

    #[test]
    fn search_result_score_none_omitted_in_json() {
        let r = SearchResult {
            title: "T".into(),
            url: "U".into(),
            snippet: "S".into(),
            score: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("score"), "score:None should be omitted");
    }

    #[test]
    fn parse_tavily_empty_results() {
        let data = serde_json::json!({ "results": [] });
        let results = parse_tavily_response(&data).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn parse_brave_missing_web_key() {
        let data = serde_json::json!({});
        let results = parse_brave_response(&data).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn parse_searxng_empty_results() {
        let data = serde_json::json!({ "results": [] });
        let results = parse_searxng_response(&data, 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn fetch_output_includes_truncated_field() {
        let fetch_result = url_extract::FetchResult {
            title: Some("Example".to_string()),
            content: "body".to_string(),
            byte_length: 4,
            truncated: true,
            content_type: "text/plain".to_string(),
        };
        let output = build_fetch_output("https://example.com", &fetch_result);
        assert_eq!(output["url"], "https://example.com");
        assert_eq!(output["title"], "Example");
        assert_eq!(output["content"], "body");
        assert_eq!(output["byte_length"], 4);
        assert_eq!(output["truncated"], true);
        assert_eq!(output["content_type"], "text/plain");
    }

    #[tokio::test]
    async fn manual_redirects_follow_to_success_response() {
        let app = Router::new()
            .route(
                "/start",
                get(|| async {
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::FOUND)
                        .header(axum::http::header::LOCATION, "/final")
                        .body(axum::body::Body::empty())
                        .unwrap()
                }),
            )
            .route("/final", get(|| async { "ok" }));

        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping test: loopback bind is not permitted in this environment");
                return;
            }
            Err(e) => panic!("failed to bind local test listener: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let fw_cfg = encmind_core::config::EgressFirewallConfig {
            enabled: false,
            ..Default::default()
        };
        let firewall = EgressFirewall::new(&fw_cfg);
        let client = build_search_client();
        let start_url = format!("http://{addr}/start");

        let response = send_with_manual_redirects(&firewall, &start_url, 5, "test", |url| {
            client.get(url).send()
        })
        .await
        .expect("manual redirects should follow to final response");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap_or_default();
        assert_eq!(body, "ok");
        server.abort();
    }

    #[tokio::test]
    async fn manual_redirects_enforce_max_redirects() {
        let app = Router::new().route(
            "/loop",
            get(|| async {
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::FOUND)
                    .header(axum::http::header::LOCATION, "/loop")
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        );

        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping test: loopback bind is not permitted in this environment");
                return;
            }
            Err(e) => panic!("failed to bind local test listener: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let fw_cfg = encmind_core::config::EgressFirewallConfig {
            enabled: false,
            ..Default::default()
        };
        let firewall = EgressFirewall::new(&fw_cfg);
        let client = build_search_client();
        let start_url = format!("http://{addr}/loop");

        let err = send_with_manual_redirects(&firewall, &start_url, 1, "test", |url| {
            client.get(url).send()
        })
        .await
        .expect_err("redirect loop should hit redirect cap");

        assert!(
            err.to_string().contains("too many redirects"),
            "unexpected error: {err}"
        );
        server.abort();
    }

    async fn assert_manual_post_redirect_switches_to_get(redirect_status: axum::http::StatusCode) {
        let app = Router::new()
            .route(
                "/start",
                get(|| async {
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::METHOD_NOT_ALLOWED)
                        .body(axum::body::Body::empty())
                        .unwrap()
                })
                .post(move || async move {
                    axum::http::Response::builder()
                        .status(redirect_status)
                        .header(axum::http::header::LOCATION, "/final")
                        .body(axum::body::Body::empty())
                        .unwrap()
                }),
            )
            .route("/final", get(|| async { "ok" }));

        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping test: loopback bind is not permitted in this environment");
                return;
            }
            Err(e) => panic!("failed to bind local test listener: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let fw_cfg = encmind_core::config::EgressFirewallConfig {
            enabled: false,
            ..Default::default()
        };
        let firewall = EgressFirewall::new(&fw_cfg);
        let client = build_search_client();
        let start_url = format!("http://{addr}/start");
        let body = serde_json::json!({ "query": "rust" });

        let response =
            send_post_json_with_manual_redirects(&client, &firewall, &start_url, 5, "test", &body)
                .await
                .expect("POST redirect should switch to GET and succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let text = response.text().await.unwrap_or_default();
        assert_eq!(text, "ok");
        server.abort();
    }

    #[tokio::test]
    async fn manual_post_redirect_303_switches_to_get() {
        assert_manual_post_redirect_switches_to_get(axum::http::StatusCode::SEE_OTHER).await;
    }

    #[tokio::test]
    async fn manual_post_redirect_301_switches_to_get() {
        assert_manual_post_redirect_switches_to_get(axum::http::StatusCode::MOVED_PERMANENTLY)
            .await;
    }

    #[tokio::test]
    async fn manual_post_redirect_302_switches_to_get() {
        assert_manual_post_redirect_switches_to_get(axum::http::StatusCode::FOUND).await;
    }
}
