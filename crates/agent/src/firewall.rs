use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use encmind_core::config::{EgressFirewallConfig, FirewallMode};
use encmind_core::error::AppError;

use encmind_storage::audit::AuditLogger;

/// Egress firewall that checks outbound URLs against a domain allowlist
/// and blocks private IP ranges.
pub struct EgressFirewall {
    enabled: bool,
    mode: FirewallMode,
    allowed_domains: Vec<String>,
    block_private_ranges: bool,
    per_agent_allowlists: HashMap<String, Vec<String>>,
    audit: Option<Arc<AuditLogger>>,
}

impl EgressFirewall {
    pub fn new(config: &EgressFirewallConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: config.mode.clone(),
            allowed_domains: config.global_allowlist.clone(),
            block_private_ranges: config.block_private_ranges,
            per_agent_allowlists: config.per_agent_overrides.clone(),
            audit: None,
        }
    }

    /// Attach an audit logger. Returns `self` for builder chaining.
    pub fn with_audit(mut self, audit: Arc<AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    const DNS_TIMEOUT: Duration = Duration::from_secs(5);

    /// Check whether a URL is allowed by the firewall (global allowlist only).
    /// Returns `Ok(())` if allowed, or an error if blocked.
    pub async fn check_url(&self, url_str: &str) -> Result<(), AppError> {
        self.check_url_with_domains(url_str, &self.allowed_domains, None)
            .await
    }

    /// Check whether a URL is allowed for a specific agent.
    /// Merges the agent's per-agent overrides with the global allowlist.
    pub async fn check_url_for_agent(&self, url_str: &str, agent_id: &str) -> Result<(), AppError> {
        let mut merged = self.allowed_domains.clone();
        if let Some(agent_domains) = self.per_agent_allowlists.get(agent_id) {
            merged.extend(agent_domains.iter().cloned());
        }
        self.check_url_with_domains(url_str, &merged, Some(agent_id))
            .await
    }

    async fn check_url_with_domains(
        &self,
        url_str: &str,
        allowed: &[String],
        agent_id: Option<&str>,
    ) -> Result<(), AppError> {
        if !self.enabled {
            return Ok(());
        }

        let parsed = url::Url::parse(url_str)
            .map_err(|e| AppError::Internal(format!("invalid URL '{url_str}': {e}")))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| AppError::Internal(format!("URL has no host: {url_str}")))?;

        // Check whether host is an IP literal. Still enforce allowlist below.
        let ip_literal = if let Ok(ip) = host.parse::<IpAddr>() {
            if self.block_private_ranges && Self::is_private_ip(&ip) {
                self.emit_audit_blocked(url_str, host, agent_id);
                return Err(AppError::Internal(format!(
                    "egress blocked: private IP {ip}"
                )));
            }
            true
        } else if let Some(ip_str) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if self.block_private_ranges && Self::is_private_ip(&ip) {
                    self.emit_audit_blocked(url_str, host, agent_id);
                    return Err(AppError::Internal(format!(
                        "egress blocked: private IP {ip}"
                    )));
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        if self.mode != FirewallMode::AllowPublicInternet
            && !Self::is_domain_allowed_in(host, allowed)
        {
            self.emit_audit_blocked(url_str, host, agent_id);
            return Err(AppError::Internal(format!(
                "egress blocked: domain '{host}' not in allowlist"
            )));
        }

        // For IP literals, allowlist + private-range checks above are sufficient.
        if ip_literal {
            return Ok(());
        }

        if self.block_private_ranges && Self::is_local_hostname(host) {
            self.emit_audit_blocked(url_str, host, agent_id);
            return Err(AppError::Internal(format!(
                "egress blocked: local hostname '{host}'"
            )));
        }

        // Resolve DNS and verify none of the addresses are private (fail-closed).
        if self.block_private_ranges {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let lookup_target = format!("{host}:{port}");

            let addrs =
                tokio::time::timeout(Self::DNS_TIMEOUT, tokio::net::lookup_host(&lookup_target))
                    .await
                    .map_err(|_| {
                        self.emit_audit_blocked(url_str, host, agent_id);
                        AppError::Internal(format!(
                            "egress blocked: DNS lookup for '{host}' timed out"
                        ))
                    })?
                    .map_err(|e| {
                        self.emit_audit_blocked(url_str, host, agent_id);
                        AppError::Internal(format!(
                            "egress blocked: DNS lookup for '{host}' failed: {e}"
                        ))
                    })?;

            for addr in addrs {
                if Self::is_private_ip(&addr.ip()) {
                    self.emit_audit_blocked(url_str, host, agent_id);
                    return Err(AppError::Internal(format!(
                        "egress blocked: domain '{host}' resolves to private IP"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Check if a domain matches the global allowlist.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        Self::is_domain_allowed_in(domain, &self.allowed_domains)
    }

    /// Check if a domain matches any entry in the given allowlist.
    /// Supports wildcard patterns: `*.example.com` matches `sub.example.com`.
    fn is_domain_allowed_in(domain: &str, allowed: &[String]) -> bool {
        if allowed.is_empty() {
            return false;
        }

        let domain_lower = domain.to_lowercase();

        for pattern in allowed {
            let pattern_lower = pattern.to_lowercase();

            if let Some(suffix) = pattern_lower.strip_prefix("*.") {
                if domain_lower == suffix || domain_lower.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if domain_lower == pattern_lower {
                return true;
            }
        }

        false
    }

    /// Check if an IP address is in a private/reserved range.
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 10.0.0.0/8
                octets[0] == 10
                // 172.16.0.0/12
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                // 192.168.0.0/16
                || (octets[0] == 192 && octets[1] == 168)
                // 127.0.0.0/8 (loopback)
                || octets[0] == 127
                // 169.254.0.0/16 (link-local)
                || (octets[0] == 169 && octets[1] == 254)
                // 0.0.0.0
                || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                // ::1 (loopback)
                v6.is_loopback()
                // :: (unspecified)
                || v6.is_unspecified()
                // fe80::/10 (link-local)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // fc00::/7 (unique local)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    fn emit_audit_blocked(&self, url: &str, host: &str, agent_id: Option<&str>) {
        if let Some(ref audit) = self.audit {
            let detail = format!("url={url} host={host}");
            let _ = audit.append("security", "egress.blocked", Some(&detail), agent_id);
        }
    }

    fn is_local_hostname(host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        host == "localhost" || host.ends_with(".localhost")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(enabled: bool, domains: Vec<&str>, block_private: bool) -> EgressFirewallConfig {
        EgressFirewallConfig {
            enabled,
            mode: FirewallMode::default(),
            global_allowlist: domains.into_iter().map(String::from).collect(),
            block_private_ranges: block_private,
            per_agent_overrides: HashMap::new(),
        }
    }

    fn make_config_with_agents(
        enabled: bool,
        domains: Vec<&str>,
        block_private: bool,
        overrides: HashMap<String, Vec<String>>,
    ) -> EgressFirewallConfig {
        EgressFirewallConfig {
            enabled,
            mode: FirewallMode::default(),
            global_allowlist: domains.into_iter().map(String::from).collect(),
            block_private_ranges: block_private,
            per_agent_overrides: overrides,
        }
    }

    fn make_config_allow_public(
        enabled: bool,
        domains: Vec<&str>,
        block_private: bool,
    ) -> EgressFirewallConfig {
        EgressFirewallConfig {
            enabled,
            mode: FirewallMode::AllowPublicInternet,
            global_allowlist: domains.into_iter().map(String::from).collect(),
            block_private_ranges: block_private,
            per_agent_overrides: HashMap::new(),
        }
    }

    // ── Sync tests (no DNS involved) ────────────────────────────────

    #[test]
    fn blocks_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(EgressFirewall::is_private_ip(&ip));
    }

    #[test]
    fn blocks_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(EgressFirewall::is_private_ip(&ip));
    }

    #[test]
    fn blocks_ipv6_unique_local() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(EgressFirewall::is_private_ip(&ip));
    }

    #[test]
    fn domain_allowlist_exact_match() {
        let fw = EgressFirewall::new(&make_config(true, vec!["api.openai.com"], true));
        assert!(fw.is_domain_allowed("api.openai.com"));
        assert!(!fw.is_domain_allowed("evil.com"));
    }

    #[test]
    fn domain_allowlist_wildcard() {
        let fw = EgressFirewall::new(&make_config(true, vec!["*.example.com"], true));
        assert!(fw.is_domain_allowed("sub.example.com"));
        assert!(fw.is_domain_allowed("example.com"));
        assert!(fw.is_domain_allowed("deep.sub.example.com"));
        assert!(!fw.is_domain_allowed("notexample.com"));
    }

    #[test]
    fn domain_allowlist_case_insensitive() {
        let fw = EgressFirewall::new(&make_config(true, vec!["API.OpenAI.com"], true));
        assert!(fw.is_domain_allowed("api.openai.com"));
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let fw: EgressFirewall = EgressFirewall::new(&make_config(true, vec![], true));
        assert!(!fw.is_domain_allowed("anything.com"));
    }

    #[test]
    fn is_local_hostname_detects_localhost() {
        assert!(EgressFirewall::is_local_hostname("localhost"));
        assert!(EgressFirewall::is_local_hostname("sub.localhost"));
        assert!(EgressFirewall::is_local_hostname("LOCALHOST"));
        assert!(!EgressFirewall::is_local_hostname("localhostx.com"));
    }

    // ── Async tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn disabled_firewall_allows_everything() {
        let fw: EgressFirewall = EgressFirewall::new(&make_config(false, vec![], false));
        assert!(fw.check_url("http://evil.com/steal").await.is_ok());
        assert!(fw.check_url("http://192.168.1.1").await.is_ok());
    }

    #[tokio::test]
    async fn enabled_empty_allowlist_blocks_everything() {
        let fw: EgressFirewall = EgressFirewall::new(&make_config(true, vec![], true));
        assert!(fw.check_url("https://example.com").await.is_err());
    }

    #[tokio::test]
    async fn blocks_private_ipv4_10() {
        let fw = EgressFirewall::new(&make_config(true, vec!["10.0.0.1"], true));
        let result = fw.check_url("http://10.0.0.1/admin").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("private IP"),
            "expected private IP error: {err}"
        );
    }

    #[tokio::test]
    async fn blocks_private_ipv4_172() {
        let fw = EgressFirewall::new(&make_config(true, vec!["172.16.0.1"], true));
        assert!(fw.check_url("http://172.16.0.1").await.is_err());
    }

    #[tokio::test]
    async fn blocks_private_ipv4_192() {
        let fw = EgressFirewall::new(&make_config(true, vec!["192.168.1.1"], true));
        assert!(fw.check_url("http://192.168.1.1").await.is_err());
    }

    #[tokio::test]
    async fn blocks_loopback_ipv4() {
        let fw = EgressFirewall::new(&make_config(true, vec!["127.0.0.1"], true));
        assert!(fw.check_url("http://127.0.0.1:8080").await.is_err());
    }

    #[tokio::test]
    async fn blocks_link_local_ipv4() {
        let fw = EgressFirewall::new(&make_config(true, vec!["169.254.1.1"], true));
        assert!(fw.check_url("http://169.254.1.1").await.is_err());
    }

    #[tokio::test]
    async fn allows_public_ip() {
        let fw = EgressFirewall::new(&make_config(true, vec!["8.8.8.8"], false));
        assert!(fw.check_url("http://8.8.8.8/dns").await.is_ok());
    }

    #[tokio::test]
    async fn blocks_public_ip_not_in_allowlist() {
        let fw = EgressFirewall::new(&make_config(true, vec!["api.openai.com"], false));
        let result = fw.check_url("http://8.8.8.8/dns").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not in allowlist"),
            "expected allowlist error: {err}"
        );
    }

    #[tokio::test]
    async fn invalid_url_returns_error() {
        let fw = EgressFirewall::new(&make_config(true, vec!["example.com"], true));
        assert!(fw.check_url("not a url").await.is_err());
    }

    #[tokio::test]
    async fn private_range_blocking_disabled() {
        let fw = EgressFirewall::new(&make_config(true, vec!["192.168.1.1"], false));
        // Private range blocking disabled, and IP is in allowlist
        assert!(fw.check_url("http://192.168.1.1").await.is_ok());
    }

    #[tokio::test]
    async fn blocks_localhost_hostname() {
        let fw = EgressFirewall::new(&make_config(true, vec!["localhost"], true));
        let result = fw.check_url("http://localhost:8080").await;
        assert!(result.is_err(), "localhost should be blocked");
    }

    #[tokio::test]
    async fn dns_failure_blocks_request() {
        // A domain that passes the allowlist but cannot resolve
        let fw = EgressFirewall::new(&make_config(true, vec!["nonexistent.invalid"], true));
        let result = fw.check_url("https://nonexistent.invalid/path").await;
        assert!(result.is_err(), "unresolvable domain should be blocked");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("DNS lookup") && err.contains("failed"),
            "expected DNS failure error: {err}"
        );
    }

    #[tokio::test]
    async fn localhost_resolves_to_private_ip() {
        // Even if localhost somehow passed the local hostname check
        // (e.g. block_private_ranges=false then re-enabled), the DNS
        // resolution should catch 127.0.0.1. Test with block_private=true.
        let fw = EgressFirewall::new(&make_config(true, vec!["localhost"], true));
        let result = fw.check_url("http://localhost:9999").await;
        assert!(result.is_err());
    }

    // ── Per-agent override tests ──────────────────────────────────

    #[tokio::test]
    async fn agent_override_allows_extra_domain() {
        let mut overrides = HashMap::new();
        overrides.insert("researcher".into(), vec!["extra.example.com".into()]);
        let config = make_config_with_agents(true, vec!["api.openai.com"], false, overrides);
        let fw = EgressFirewall::new(&config);

        // Global domain works for the agent
        assert!(fw
            .check_url_for_agent("https://api.openai.com/v1", "researcher")
            .await
            .is_ok());
        // Agent-specific domain works
        assert!(fw
            .check_url_for_agent("https://extra.example.com/data", "researcher")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn agent_override_doesnt_affect_other_agents() {
        let mut overrides = HashMap::new();
        overrides.insert("researcher".into(), vec!["extra.example.com".into()]);
        let config = make_config_with_agents(true, vec!["api.openai.com"], false, overrides);
        let fw = EgressFirewall::new(&config);

        // Another agent should NOT have access to researcher's extra domain
        assert!(fw
            .check_url_for_agent("https://extra.example.com/data", "main")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn agent_without_overrides_falls_back_to_global() {
        let overrides = HashMap::new();
        let config = make_config_with_agents(true, vec!["api.openai.com"], false, overrides);
        let fw = EgressFirewall::new(&config);

        assert!(fw
            .check_url_for_agent("https://api.openai.com/v1", "main")
            .await
            .is_ok());
        assert!(fw
            .check_url_for_agent("https://evil.com", "main")
            .await
            .is_err());
    }

    // ── Audit event tests ─────────────────────────────────────────

    #[tokio::test]
    async fn blocked_request_logged_to_audit() {
        use encmind_storage::audit::{AuditFilter, AuditLogger};
        use encmind_storage::migrations::run_migrations;
        use encmind_storage::pool::create_test_pool;

        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let audit = Arc::new(AuditLogger::new(pool));

        let fw = EgressFirewall::new(&make_config(true, vec![], true)).with_audit(audit.clone());

        let _ = fw.check_url("https://evil.com/steal").await;

        let entries = audit
            .query(
                AuditFilter {
                    category: Some("security".into()),
                    action: Some("egress.blocked".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].detail.as_deref().unwrap().contains("evil.com"));
    }

    #[tokio::test]
    async fn allowed_request_not_logged() {
        use encmind_storage::audit::{AuditFilter, AuditLogger};
        use encmind_storage::migrations::run_migrations;
        use encmind_storage::pool::create_test_pool;

        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let audit = Arc::new(AuditLogger::new(pool));

        let fw = EgressFirewall::new(&make_config(true, vec!["8.8.8.8"], false))
            .with_audit(audit.clone());

        let _ = fw.check_url("http://8.8.8.8/dns").await;

        let entries = audit
            .query(
                AuditFilter {
                    category: Some("security".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert!(entries.is_empty(), "allowed request should not be logged");
    }

    // ── AllowPublicInternet mode tests ──────────────────────────

    #[tokio::test]
    async fn allow_public_allows_any_public_domain() {
        // Disable private-range checks in this specific test to avoid DNS lookups,
        // so we validate only allow_public_internet allowlist behavior.
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], false));
        assert!(
            fw.check_url("https://google.com/search").await.is_ok(),
            "allow_public_internet should allow public domains without allowlist"
        );
    }

    #[tokio::test]
    async fn allow_public_allows_public_ip() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], false));
        assert!(
            fw.check_url("http://8.8.8.8/dns").await.is_ok(),
            "allow_public_internet should allow public IPs"
        );
    }

    #[tokio::test]
    async fn allow_public_blocks_private_ip_10() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], true));
        let result = fw.check_url("http://10.0.0.1/admin").await;
        assert!(result.is_err(), "should still block private 10.x IPs");
        assert!(result.unwrap_err().to_string().contains("private IP"));
    }

    #[tokio::test]
    async fn allow_public_blocks_private_ip_192() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], true));
        assert!(
            fw.check_url("http://192.168.1.1").await.is_err(),
            "should still block private 192.168.x IPs"
        );
    }

    #[tokio::test]
    async fn allow_public_blocks_loopback() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], true));
        assert!(
            fw.check_url("http://127.0.0.1:8080").await.is_err(),
            "should still block loopback"
        );
    }

    #[tokio::test]
    async fn allow_public_blocks_localhost() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], true));
        let result = fw.check_url("http://localhost:8080").await;
        assert!(result.is_err(), "should still block localhost hostname");
    }

    #[tokio::test]
    async fn allow_public_blocks_link_local() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], true));
        assert!(
            fw.check_url("http://169.254.1.1").await.is_err(),
            "should still block link-local IPs"
        );
    }

    #[tokio::test]
    async fn allow_public_blocks_private_ip_172() {
        let fw = EgressFirewall::new(&make_config_allow_public(true, vec![], true));
        assert!(
            fw.check_url("http://172.16.0.1").await.is_err(),
            "should still block private 172.16.x IPs"
        );
    }
}
