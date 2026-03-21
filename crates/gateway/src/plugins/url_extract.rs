//! Shared URL safety validation and HTML content extraction.
//!
//! Reusable by any plugin that needs to retrieve web content (NetProbe, Digest, etc.).

use std::sync::Arc;

use encmind_agent::firewall::EgressFirewall;
use futures::StreamExt;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Result of a URL fetch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResult {
    pub title: Option<String>,
    pub content: String,
    pub byte_length: usize,
    pub truncated: bool,
    pub content_type: String,
}

/// Validate a URL for safety before fetching.
///
/// Checks:
/// - Scheme must be http or https
/// - No userinfo (user:pass@ in URL)
/// - Firewall check (private IP, allowlist)
pub async fn validate_url(url_str: &str, firewall: &EgressFirewall) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url_str).map_err(|e| format!("invalid URL '{url_str}': {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "unsupported scheme '{other}': only http/https allowed"
            ))
        }
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URLs with userinfo (user:pass@) are not allowed".to_string());
    }

    firewall
        .check_url(url_str)
        .await
        .map_err(|e| e.to_string())?;

    Ok(parsed)
}

/// Fetch a URL with redirect following and size limits.
///
/// - Manual redirect following (re-validates each hop via firewall)
/// - Truncates response body at `max_bytes`
/// - Routes on Content-Type:
///   - HTML → extracted text
///   - JSON → pretty-print
///   - text/* → raw text
///   - others → rejected as unsupported
pub async fn fetch_url(
    url_str: &str,
    client: &reqwest::Client,
    firewall: &Arc<EgressFirewall>,
    max_bytes: usize,
    max_redirects: usize,
    selector: Option<&str>,
) -> Result<FetchResult, String> {
    let mut current_url = validate_url(url_str, firewall).await?;
    let mut hops = 0;

    loop {
        debug!(url = %current_url, hop = hops, "fetch_url");
        let resp = client
            .get(current_url.as_str())
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        let status = resp.status();

        if status.is_redirection() {
            hops += 1;
            if hops > max_redirects {
                return Err(format!("too many redirects (>{max_redirects})"));
            }
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| "redirect without Location header".to_string())?;

            // Resolve relative redirects against the current URL.
            let next = current_url
                .join(location)
                .map_err(|e| format!("invalid redirect URL '{location}': {e}"))?;

            // Re-validate the redirect target through the firewall.
            validate_url(next.as_str(), firewall).await?;
            current_url = next;
            continue;
        }

        if !status.is_success() {
            return Err(format!("HTTP {status} for {current_url}"));
        }

        let content_type_header = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let content_type = content_type_header
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let mime = content_type_header
            .as_deref()
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        let supported_mime = mime == "text/html"
            || mime == "application/xhtml+xml"
            || mime == "application/json"
            || mime.ends_with("+json")
            || mime.starts_with("text/");
        if content_type_header.is_some() && !supported_mime {
            return Err(format!(
                "unsupported content-type '{content_type}'; only HTML, JSON, and text/* are supported"
            ));
        }

        let mut body = Vec::new();
        let mut truncated = false;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("failed to read response body: {e}"))?;
            let remaining = max_bytes.saturating_sub(body.len());
            if remaining == 0 {
                truncated = true;
                break;
            }
            if chunk.len() <= remaining {
                body.extend_from_slice(&chunk);
            } else {
                body.extend_from_slice(&chunk[..remaining]);
                truncated = true;
                break;
            }
        }
        let byte_length = body.len();

        let (title, content) = if (mime == "text/html" || mime == "application/xhtml+xml")
            || (content_type_header.is_none() && looks_like_html(&body))
        {
            let html = String::from_utf8_lossy(&body).to_string();
            let (t, text) = html_to_text(&html, selector)
                .map_err(|e| format!("HTML extraction failed: {e}"))?;
            (t, text)
        } else if mime == "application/json"
            || mime.ends_with("+json")
            || (content_type_header.is_none() && looks_like_json(&body))
        {
            let text = String::from_utf8_lossy(&body).to_string();
            let pretty = serde_json::from_str::<serde_json::Value>(&text)
                .map(|v| serde_json::to_string_pretty(&v).unwrap_or_else(|_| text.clone()))
                .unwrap_or(text);
            (None, pretty)
        } else {
            if content_type_header.is_none() && !looks_like_text(&body) {
                return Err(
                    "unsupported content-type 'application/octet-stream'; missing Content-Type header and body is not recognized as text"
                        .to_string(),
                );
            }
            let text = String::from_utf8_lossy(&body).to_string();
            (None, text)
        };

        return Ok(FetchResult {
            title,
            content,
            byte_length,
            truncated,
            content_type,
        });
    }
}

/// Convert HTML to readable text, stripping navigation/script/style elements.
///
/// If `selector` is provided, extracts only elements matching the CSS selector.
/// Returns `(title, extracted_text)`.
pub fn html_to_text(
    html: &str,
    selector: Option<&str>,
) -> Result<(Option<String>, String), String> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);

    // Extract <title>.
    let title = Selector::parse("title")
        .ok()
        .and_then(|sel| document.select(&sel).next())
        .map(|el| el.text().collect::<String>().trim().to_string())
        .filter(|t| !t.is_empty());

    let working_html = if let Some(css) = selector {
        // Extract only the selected elements.
        let sel = Selector::parse(css).map_err(|e| format!("invalid CSS selector '{css}': {e}"))?;
        let fragments: Vec<String> = document.select(&sel).map(|el| el.html()).collect();
        if fragments.is_empty() {
            return Err(format!("selector '{css}' matched no elements"));
        } else {
            fragments.join("\n")
        }
    } else {
        html.to_string()
    };

    // Strip unwanted elements: script, style, nav, footer, header, aside.
    let text = strip_tags(
        &working_html,
        &[
            "script", "style", "nav", "footer", "noscript", "aside", "header",
        ],
    );

    Ok((title, text))
}

/// Remove all occurrences of the given HTML tags and their content, then
/// return a normalized text representation.
fn strip_tags(html: &str, tags: &[&str]) -> String {
    use scraper::{Html, Selector};
    use std::collections::HashSet;

    let document = Html::parse_document(html);
    let mut removed_ids = HashSet::new();

    for tag in tags {
        if let Ok(sel) = Selector::parse(tag) {
            for el in document.select(&sel) {
                removed_ids.insert(el.id());
                for desc in el.descendants() {
                    removed_ids.insert(desc.id());
                }
            }
        }
    }

    let mut out = String::new();

    // Prefer body-only text so <head>/<title> content does not leak into
    // extracted body content.
    if let Ok(body_sel) = Selector::parse("body") {
        if let Some(body) = document.select(&body_sel).next() {
            for node in body.descendants() {
                if removed_ids.contains(&node.id()) {
                    continue;
                }
                if let scraper::Node::Text(text) = node.value() {
                    append_normalized_text(&mut out, text);
                }
            }
            return out.trim().to_string();
        }
    }

    for node in document.tree.nodes() {
        if !removed_ids.contains(&node.id()) {
            if let scraper::Node::Text(text) = node.value() {
                append_normalized_text(&mut out, text);
            }
        }
    }

    out.trim().to_string()
}

fn append_normalized_text(out: &mut String, text: &str) {
    for token in text.split_whitespace() {
        if !out.is_empty() && !out.ends_with(char::is_whitespace) {
            out.push(' ');
        }
        out.push_str(token);
    }
}

fn looks_like_html(bytes: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let s = text.trim_start();
        starts_with_ignore_ascii_case(s, "<!doctype html")
            || starts_with_ignore_ascii_case(s, "<html")
            || starts_with_ignore_ascii_case(s, "<body")
            || starts_with_ignore_ascii_case(s, "<article")
            || starts_with_ignore_ascii_case(s, "<main")
    } else {
        false
    }
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn looks_like_json(bytes: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(bytes) {
        serde_json::from_str::<serde_json::Value>(text).is_ok()
    } else {
        false
    }
}

fn looks_like_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if bytes.contains(&0) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut total = 0usize;
    let mut bad = 0usize;
    for ch in text.chars() {
        total += 1;
        if ch.is_control() && !ch.is_whitespace() {
            bad += 1;
        }
    }
    if total == 0 {
        return true;
    }
    (bad as f64 / total as f64) < 0.02
}

/// Build a reqwest client suitable for URL fetching.
///
/// - Manual redirect policy (no automatic following)
/// - 30s timeout
/// - Custom User-Agent
pub fn build_fetch_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent(format!("EncMind-NetProbe/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build reqwest client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    #[test]
    fn validate_url_rejects_ftp() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fw = EgressFirewall::new(&encmind_core::config::EgressFirewallConfig::default());
        let result = rt.block_on(validate_url("ftp://example.com/file", &fw));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported scheme"));
    }

    #[test]
    fn validate_url_rejects_userinfo() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fw = EgressFirewall::new(&encmind_core::config::EgressFirewallConfig::default());
        let result = rt.block_on(validate_url("http://user:pass@example.com", &fw));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("userinfo"));
    }

    #[test]
    fn html_to_text_basic() {
        let html = r#"
            <html>
            <head><title>Test Page</title></head>
            <body>
                <h1>Hello World</h1>
                <p>This is a <a href="https://example.com">link</a>.</p>
            </body>
            </html>
        "#;
        let (title, md) = html_to_text(html, None).expect("html should parse");
        assert_eq!(title.as_deref(), Some("Test Page"));
        assert!(md.contains("Hello World"), "md = {md}");
        assert!(md.contains("link"), "md = {md}");
        assert!(
            !md.contains("Test Page"),
            "body text should not include title"
        );
    }

    #[test]
    fn html_to_text_strips_scripts() {
        let html = r#"
            <html>
            <body>
                <script>alert('xss')</script>
                <style>body { color: red; }</style>
                <nav>Navigation</nav>
                <p>Content</p>
                <footer>Footer</footer>
            </body>
            </html>
        "#;
        let (_, md) = html_to_text(html, None).expect("html should parse");
        assert!(md.contains("Content"), "md = {md}");
        assert!(
            !md.contains("alert"),
            "script should be stripped: md = {md}"
        );
        assert!(
            !md.contains("color: red"),
            "style should be stripped: md = {md}"
        );
        assert!(
            !md.contains("Navigation"),
            "nav should be stripped: md = {md}"
        );
        assert!(
            !md.contains("Footer"),
            "footer should be stripped: md = {md}"
        );
    }

    #[test]
    fn html_to_text_with_selector() {
        let html = r#"
            <html>
            <body>
                <div class="sidebar">Sidebar</div>
                <article class="main">
                    <h2>Article Title</h2>
                    <p>Article body text.</p>
                </article>
            </body>
            </html>
        "#;
        let (_, md) = html_to_text(html, Some("article.main")).expect("selector should parse");
        assert!(md.contains("Article Title"), "md = {md}");
        assert!(md.contains("Article body text"), "md = {md}");
    }

    #[test]
    fn html_to_text_rejects_invalid_selector() {
        let html = "<html><body><article>hello</article></body></html>";
        let err = html_to_text(html, Some("article[")).unwrap_err();
        assert!(err.contains("invalid CSS selector"), "err = {err}");
    }

    #[test]
    fn html_to_text_rejects_selector_when_no_matches() {
        let html = "<html><body><article>hello</article></body></html>";
        let err = html_to_text(html, Some("main.content")).unwrap_err();
        assert!(err.contains("matched no elements"), "err = {err}");
    }

    #[tokio::test]
    async fn fetch_truncates_at_max_bytes() {
        let app = Router::new().route("/big", get(|| async move { "x".repeat(2000) }));
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
        let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
        let client = build_fetch_client();
        let result = fetch_url(
            &format!("http://{addr}/big"),
            &client,
            &firewall,
            100,
            2,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.byte_length, 100);
        assert!(result.truncated);
        server.abort();
    }

    #[tokio::test]
    async fn fetch_html_with_selector_extracts_selected_content() {
        let html = r#"
            <html><body>
                <aside>Sidebar content</aside>
                <article class="main"><h1>Title</h1><p>Body text.</p></article>
            </body></html>
        "#;
        let html_owned = html.to_string();
        let app = Router::new().route(
            "/doc",
            get(move || {
                let html = html_owned.clone();
                async move { ([("content-type", "text/html")], html) }
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
        let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
        let client = build_fetch_client();
        let result = fetch_url(
            &format!("http://{addr}/doc"),
            &client,
            &firewall,
            4096,
            2,
            Some("article.main"),
        )
        .await
        .unwrap();

        assert!(result.content.contains("Title"));
        assert!(result.content.contains("Body text"));
        assert!(!result.content.contains("Sidebar content"));
        assert!(!result.truncated);
        server.abort();
    }

    #[tokio::test]
    async fn fetch_rejects_unsupported_binary_content_types() {
        let app = Router::new().route(
            "/img",
            get(|| async move { ([("content-type", "image/png")], vec![0_u8, 1_u8, 2_u8]) }),
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
        let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
        let client = build_fetch_client();
        let err = fetch_url(
            &format!("http://{addr}/img"),
            &client,
            &firewall,
            4096,
            2,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.contains("unsupported content-type"), "err = {err}");
        server.abort();
    }

    #[tokio::test]
    async fn fetch_missing_content_type_sniffs_html() {
        let html = "<html><head><title>T</title></head><body><p>Hello</p></body></html>";
        let html_owned = html.to_string();
        let app = Router::new().route(
            "/no-ct-html",
            get(move || {
                let html = html_owned.clone();
                async move {
                    axum::http::Response::builder()
                        .status(200)
                        .body(axum::body::Body::from(html))
                        .unwrap()
                }
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
        let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
        let client = build_fetch_client();
        let result = fetch_url(
            &format!("http://{addr}/no-ct-html"),
            &client,
            &firewall,
            4096,
            2,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.content_type, "application/octet-stream");
        assert!(
            result.content.contains("Hello"),
            "content = {}",
            result.content
        );
        server.abort();
    }

    #[tokio::test]
    async fn fetch_missing_content_type_rejects_binary() {
        let app = Router::new().route(
            "/no-ct-bin",
            get(|| async move {
                axum::http::Response::builder()
                    .status(200)
                    .body(axum::body::Body::from(vec![0_u8, 159_u8, 146_u8, 150_u8]))
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
        let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
        let client = build_fetch_client();
        let err = fetch_url(
            &format!("http://{addr}/no-ct-bin"),
            &client,
            &firewall,
            4096,
            2,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("missing Content-Type header"),
            "unexpected error: {err}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn fetch_missing_content_type_sniffs_uppercase_doctype_html() {
        let html = "<!DOCTYPE HTML><HTML><BODY><p>Hello</p></BODY></HTML>";
        let html_owned = html.to_string();
        let app = Router::new().route(
            "/no-ct-uppercase-html",
            get(move || {
                let html = html_owned.clone();
                async move {
                    axum::http::Response::builder()
                        .status(200)
                        .body(axum::body::Body::from(html))
                        .unwrap()
                }
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
        let firewall = Arc::new(EgressFirewall::new(&fw_cfg));
        let client = build_fetch_client();
        let result = fetch_url(
            &format!("http://{addr}/no-ct-uppercase-html"),
            &client,
            &firewall,
            4096,
            2,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.content_type, "application/octet-stream");
        assert!(
            result.content.contains("Hello"),
            "content = {}",
            result.content
        );
        server.abort();
    }

    #[test]
    fn strip_tags_removes_script_blocks() {
        let html = "<div><script>var x = 1;</script><p>Keep</p></div>";
        let cleaned = strip_tags(html, &["script"]);
        assert!(!cleaned.contains("var x"), "cleaned = {cleaned}");
        assert!(cleaned.contains("Keep"), "cleaned = {cleaned}");
    }

    #[test]
    fn build_fetch_client_succeeds() {
        let _client = build_fetch_client();
    }
}
