use std::path::Path;
use std::time::Duration;

use encmind_core::config::AppConfig;
use tracing::debug;

/// Status information about the EncMind system.
#[derive(Debug)]
pub struct StatusInfo {
    pub config_exists: bool,
    pub config_path: String,
    pub db_exists: bool,
    pub db_path: String,
    pub session_count: Option<i64>,
    pub agent_count: Option<i64>,
    pub audit_chain_valid: Option<bool>,
}

/// Collect system status.
pub fn collect_status(config_path: &str) -> StatusInfo {
    let config_exists = Path::new(config_path).exists();

    let mut info = StatusInfo {
        config_exists,
        config_path: config_path.to_owned(),
        db_exists: false,
        db_path: String::new(),
        session_count: None,
        agent_count: None,
        audit_chain_valid: None,
    };

    if !config_exists {
        return info;
    }

    // Try to load config and check DB
    let config = match encmind_core::config::load_config(Path::new(config_path)) {
        Ok(c) => c,
        Err(_) => return info,
    };

    let db_path = config.storage.db_path;
    info.db_path = db_path.to_string_lossy().into_owned();
    info.db_exists = db_path.exists();

    if !info.db_exists {
        return info;
    }

    // Try to connect and read counts
    let pool = match encmind_storage::pool::create_pool(&db_path) {
        Ok(p) => p,
        Err(_) => return info,
    };

    let conn = match pool.get() {
        Ok(c) => c,
        Err(_) => return info,
    };

    // Session count
    if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| {
        row.get::<_, i64>(0)
    }) {
        info.session_count = Some(count);
    }

    // Agent count
    if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM agents", [], |row| {
        row.get::<_, i64>(0)
    }) {
        info.agent_count = Some(count);
    }

    // Audit chain verification
    let logger = encmind_storage::audit::AuditLogger::new(pool);
    if let Ok(errors) = logger.verify_chain() {
        info.audit_chain_valid = Some(errors.is_empty());
    }

    info
}

/// Load the application config from the given path, returning `None` on any failure.
pub fn load_config_for_status(config_path: &str) -> Option<AppConfig> {
    encmind_core::config::load_config(Path::new(config_path)).ok()
}

/// Make an HTTP GET to the runtime health endpoint and return the parsed JSON,
/// or `None` if the server is unreachable or the response is not valid JSON.
pub async fn collect_runtime_status(config: &AppConfig) -> Option<serde_json::Value> {
    let host = normalize_probe_host(&config.server.host);
    let port = config.server.port;
    let mut urls = Vec::new();
    let tls_configured = config.server.auto_tls
        || config.server.tls_cert_path.is_some()
        || config.server.tls_key_path.is_some();
    if tls_configured {
        urls.push(format!("https://{host}:{port}/health?detail=true"));
    }
    // Fallback probe for local/plain deployments.
    urls.push(format!("http://{host}:{port}/health?detail=true"));

    let timeout = Duration::from_secs(3);
    let http_client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(error) => {
            debug!(%error, "failed to build HTTP client for runtime status probe");
            return None;
        }
    };
    let allow_insecure_https = is_loopback_probe_host(&host);
    let https_client = if tls_configured {
        let mut builder = reqwest::Client::builder().timeout(timeout);
        if allow_insecure_https {
            builder = builder.danger_accept_invalid_certs(true);
        }
        match builder.build() {
            Ok(client) => Some(client),
            Err(error) => {
                debug!(%error, "failed to build HTTPS client for runtime status probe");
                None
            }
        }
    } else {
        None
    };

    for url in urls {
        let client = if url.starts_with("https://") {
            // Status probe is diagnostic-only; allow local/self-signed certs.
            match https_client.as_ref() {
                Some(client) => client,
                None => {
                    debug!(url = %url, "skipping HTTPS runtime status probe due to missing HTTPS client");
                    continue;
                }
            }
        } else {
            &http_client
        };

        let resp = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(error) => {
                debug!(url = %url, %error, "runtime status probe request failed");
                continue;
            }
        };
        match resp.json::<serde_json::Value>().await {
            Ok(json) => return Some(json),
            Err(error) => {
                debug!(url = %url, %error, "runtime status probe response was not valid JSON");
            }
        }
    }
    None
}

fn normalize_probe_host(host: &str) -> String {
    normalize_probe_host_pub(host)
}

/// Normalize wildcard bind addresses to localhost for probing.
pub fn normalize_probe_host_pub(host: &str) -> String {
    match host.trim() {
        "0.0.0.0" | "::" | "[::]" => "127.0.0.1".to_string(),
        other => other.to_string(),
    }
}

fn is_loopback_probe_host(host: &str) -> bool {
    matches!(
        host.trim().trim_start_matches('[').trim_end_matches(']'),
        "127.0.0.1" | "::1" | "localhost"
    )
}

/// Print status info to stdout.
pub async fn print_status(info: &StatusInfo) {
    println!("EncMind Status");
    println!("==============");
    println!(
        "Config:     {} ({})",
        if info.config_exists {
            "found"
        } else {
            "NOT FOUND"
        },
        info.config_path
    );
    println!(
        "Database:   {} ({})",
        if info.db_exists { "found" } else { "NOT FOUND" },
        info.db_path
    );
    if let Some(count) = info.session_count {
        println!("Sessions:   {count}");
    }
    if let Some(count) = info.agent_count {
        println!("Agents:     {count}");
    }
    if let Some(valid) = info.audit_chain_valid {
        println!("Audit log:  {}", if valid { "VALID" } else { "INVALID" });
    }
    let config = load_config_for_status(&info.config_path);
    println!(
        "Tools:      {}",
        local_tools_inventory_line(config.as_ref())
    );

    // Try runtime check
    if let Some(config) = config {
        match collect_runtime_status(&config).await {
            Some(report) => {
                println!("Runtime:    CONNECTED");
                if let Some(llm) = report
                    .get("llm")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                {
                    println!("  LLM:       {llm}");
                }
                if let Some(api_key) = report
                    .get("api_key")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                {
                    println!("  API key:   {api_key}");
                }
                if let Some(detail) = report
                    .get("tools")
                    .and_then(|v| v.get("detail"))
                    .and_then(|v| v.as_str())
                {
                    println!("  Tools:     {detail}");
                }
                if let Some(skills) = report.get("skills") {
                    let status = skills
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let detail = skills.get("detail").and_then(|v| v.as_str());
                    if let Some(detail) = detail {
                        println!("  Skills:    {status} ({detail})");
                    } else {
                        println!("  Skills:    {status}");
                    }
                }
                if let Some(status) = report
                    .get("memory")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                {
                    println!("  Memory:    {status}");
                }
                if let Some(status) = report
                    .get("browser")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                {
                    println!("  Browser:   {status}");
                }
                if let Some(status) = report
                    .get("channels")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                {
                    println!("  Channels:  {status}");
                }
                if let Some(status) = report
                    .get("plugins")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                {
                    println!("  Plugins:   {status}");
                }
                if let Some(rl) = report.get("rate_limiting") {
                    let mpm = rl
                        .get("messages_per_minute")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let tpr = rl
                        .get("tool_calls_per_run")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    println!("  Limits:    {mpm} msg/min, {tpr} tool calls/run");
                }
                if let Some(lp) = report.get("local_tools_policy") {
                    let mode = lp.get("mode").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let bash = lp
                        .get("bash_effective_enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    println!(
                        "  Local:     mode={mode}, bash={}",
                        if bash { "enabled" } else { "disabled" }
                    );
                }
            }
            None => {
                println!("Runtime:    NOT RUNNING (start with: encmind-core serve)");
            }
        }
    }
}

fn local_tools_inventory_line(config: Option<&AppConfig>) -> String {
    let mut tools = vec!["file_read", "file_write", "file_list"];
    let bash_enabled = config.is_some_and(|cfg| {
        !matches!(
            cfg.security.local_tools.mode,
            encmind_core::config::LocalToolsMode::IsolatedAgents
        ) && !matches!(
            cfg.security.local_tools.bash_mode,
            encmind_core::config::LocalToolsBashMode::Disabled
        ) && !matches!(cfg.security.bash_mode, encmind_core::config::BashMode::Deny)
    });
    if bash_enabled {
        tools.push("bash_exec");
    }
    format!("{} (local)", tools.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_inventory_hides_bash_when_disabled() {
        let mut cfg = AppConfig::default();
        cfg.security.local_tools.bash_mode = encmind_core::config::LocalToolsBashMode::Disabled;
        let line = local_tools_inventory_line(Some(&cfg));
        assert_eq!(line, "file_read, file_write, file_list (local)");
    }

    #[test]
    fn tool_inventory_shows_bash_when_enabled() {
        let cfg = AppConfig::default();
        let line = local_tools_inventory_line(Some(&cfg));
        assert_eq!(line, "file_read, file_write, file_list, bash_exec (local)");
    }

    #[test]
    fn tool_inventory_without_config_is_conservative() {
        let line = local_tools_inventory_line(None);
        assert_eq!(line, "file_read, file_write, file_list (local)");
    }

    #[test]
    fn collect_status_missing_config() {
        let info = collect_status("/nonexistent/config.yaml");
        assert!(!info.config_exists);
        assert!(!info.db_exists);
        assert!(info.session_count.is_none());
    }

    #[test]
    fn collect_status_with_config_no_db() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("nonexistent.db");

        let yaml = format!("storage:\n  db_path: \"{}\"\n", db_path.display());
        std::fs::write(&config_path, &yaml).unwrap();

        let info = collect_status(config_path.to_str().unwrap());
        assert!(info.config_exists);
        assert!(!info.db_exists);
    }

    #[test]
    fn collect_status_with_db() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");

        // Create DB first
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        let conn = pool.get().unwrap();
        encmind_storage::migrations::run_migrations(&conn).unwrap();
        drop(conn);
        drop(pool);

        let yaml = format!("storage:\n  db_path: \"{}\"\n", db_path.display());
        std::fs::write(&config_path, &yaml).unwrap();

        let info = collect_status(config_path.to_str().unwrap());
        assert!(info.config_exists);
        assert!(info.db_exists);
        // Migration creates default 'main' agent
        assert_eq!(info.agent_count, Some(1));
        assert_eq!(info.session_count, Some(0));
        assert_eq!(info.audit_chain_valid, Some(true));
    }

    #[tokio::test]
    async fn print_status_does_not_panic() {
        let info = StatusInfo {
            config_exists: true,
            config_path: "/test/config.yaml".into(),
            db_exists: true,
            db_path: "/test/data.db".into(),
            session_count: Some(5),
            agent_count: Some(2),
            audit_chain_valid: Some(true),
        };
        // Just verify it doesn't panic
        print_status(&info).await;
    }

    #[tokio::test]
    async fn status_shows_tool_inventory() {
        // print_status should include the tool inventory line without panicking.
        // We can't easily capture stdout in a unit test, so we verify the function
        // completes successfully with the new code path exercised.
        let info = StatusInfo {
            config_exists: false,
            config_path: "/nonexistent/config.yaml".into(),
            db_exists: false,
            db_path: String::new(),
            session_count: None,
            agent_count: None,
            audit_chain_valid: None,
        };
        // This exercises the tool inventory println; config doesn't exist so
        // the runtime check branch is skipped.
        print_status(&info).await;
        // The tool inventory line is always printed — if we got here, it works.
    }

    #[tokio::test]
    async fn runtime_status_graceful_when_not_running() {
        // Point at a port that is almost certainly not listening.
        let config = AppConfig {
            server: encmind_core::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 19999,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = collect_runtime_status(&config).await;
        assert!(
            result.is_none(),
            "Expected None when runtime is not running"
        );
    }

    #[tokio::test]
    async fn runtime_status_normalizes_wildcard_bind_host() {
        let config = AppConfig {
            server: encmind_core::config::ServerConfig {
                host: "0.0.0.0".into(),
                port: 19999,
                ..Default::default()
            },
            ..Default::default()
        };
        // Should not panic; probe host normalization maps wildcard to localhost.
        let _ = collect_runtime_status(&config).await;
    }
}
