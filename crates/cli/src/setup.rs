use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SetupProfile {
    Local,
    Remote,
    Domain,
}

impl SetupProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Domain => "domain",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SetupOptions<'a> {
    pub profile: SetupProfile,
    pub acme_domain: Option<&'a str>,
    pub acme_email: Option<&'a str>,
    pub tls_cert_path: Option<&'a str>,
    pub tls_key_path: Option<&'a str>,
}

impl<'a> SetupOptions<'a> {
    #[cfg(test)]
    fn for_profile(profile: SetupProfile) -> Self {
        Self {
            profile,
            acme_domain: None,
            acme_email: None,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Generate a default YAML configuration with sensible defaults.
#[cfg(test)]
fn generate_default_config() -> String {
    generate_default_config_for_path(
        Path::new("~/.encmind/config.yaml"),
        SetupOptions::for_profile(SetupProfile::Local),
    )
}

fn yaml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn generate_default_config_for_path(config_path: &Path, options: SetupOptions<'_>) -> String {
    let base_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("~/.encmind"));
    let db_path = yaml_escape(&base_dir.join("data.db").to_string_lossy());
    let wasm_dir = yaml_escape(&base_dir.join("skills").to_string_lossy());
    let tls_block = match (options.tls_cert_path, options.tls_key_path) {
        (Some(cert), Some(key)) => format!(
            "  tls_cert_path: \"{}\"\n  tls_key_path: \"{}\"\n",
            yaml_escape(cert),
            yaml_escape(key)
        ),
        _ => String::new(),
    };
    let acme_block = match (options.acme_domain, options.acme_email) {
        (Some(domain), Some(email)) => format!(
            "  tls_lifecycle:\n    acme_enabled: true\n    acme_domain: \"{}\"\n    acme_email: \"{}\"\n",
            yaml_escape(domain),
            yaml_escape(email)
        ),
        _ => String::new(),
    };
    let port = match options.profile {
        SetupProfile::Domain => "443",
        SetupProfile::Local | SetupProfile::Remote => "8443",
    };

    r#"# EncMind Configuration
server:
  profile: __PROFILE__
  port: __PORT__
__TLS_BLOCK__

storage:
  db_path: "__DB_PATH__"
  key_source:
    type: Passphrase
    passphrase_env: "ENCMIND_PASSPHRASE"

llm:
  mode:
    type: Local
  api_providers: []

memory:
  enabled: false
  embedding_mode:
    type: private
  vector_backend:
    type: sqlite

tee:
  enabled: true

channels: {}

skills:
  enabled: []
  wasm_dir: "__WASM_DIR__"

mcp:
  servers: []

security:
  bash_mode: ask
  egress_firewall:
    enabled: true
    global_allowlist: []
    block_private_ranges: true
  rate_limit:
    messages_per_minute: 30
    tool_calls_per_run: 50
__ACME_BLOCK__

agents:
  list: []

agent_pool:
  max_concurrent_agents: 8
  per_session_timeout_secs: 300

backup:
  enabled: false
  schedule: "0 * * * *"
  encryption: true
  retention:
    daily: 7
    weekly: 4

browser:
  enabled: false
  pool_size: 2
  idle_timeout_secs: 600
  no_sandbox: false
  startup_policy: required

gateway:
  heartbeat_interval_ms: 30000
  idempotency_ttl_secs: 300
  max_connections: 64
  mdns_enabled: false
"#
    .replace("__PROFILE__", options.profile.as_str())
    .replace("__PORT__", port)
    .replace("__TLS_BLOCK__", &tls_block)
    .replace("__ACME_BLOCK__", &acme_block)
    .replace("__DB_PATH__", &db_path)
    .replace("__WASM_DIR__", &wasm_dir)
}

/// Run the setup wizard: create config directory, write default config, create DB.
pub fn run_setup(config_path: &str, options: SetupOptions<'_>) -> Result<(), anyhow::Error> {
    validate_setup_options(options)?;

    let path = Path::new(config_path);
    let config_preexisted = path.exists();

    // Create parent directory
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            println!("Created directory: {}", parent.display());
        }
    }

    // Write default config if not exists
    if config_preexisted {
        println!("Config already exists at: {config_path}");
    } else {
        let config_content = generate_default_config_for_path(path, options);
        std::fs::write(path, &config_content)?;
        println!(
            "Created config: {config_path} (profile: {})",
            options.profile.as_str()
        );
    }

    // Determine DB path from config
    let config = encmind_core::config::load_config(path)?;
    let db_path = &config.storage.db_path;
    let skills_dir = &config.skills.wasm_dir;
    let effective_profile = config.server.profile;

    if config_preexisted {
        let requested = options.profile.as_str();
        let actual = match effective_profile {
            encmind_core::config::ServerProfile::Local => "local",
            encmind_core::config::ServerProfile::Remote => "remote",
            encmind_core::config::ServerProfile::Domain => "domain",
        };
        if requested != actual {
            println!(
                "Note: existing config profile is '{actual}' (requested '{requested}' was not applied)."
            );
        }
    }

    // Create DB directory
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            println!("Created DB directory: {}", parent.display());
        }
    }

    // Ensure the configured skills directory exists.
    if skills_dir.exists() {
        if !skills_dir.is_dir() {
            return Err(anyhow::anyhow!(
                "configured skills.wasm_dir is not a directory: {}",
                skills_dir.display()
            ));
        }
    } else {
        std::fs::create_dir_all(skills_dir)?;
        println!("Created skills directory: {}", skills_dir.display());
    }

    // Create pool and run migrations
    let pool = encmind_storage::pool::create_pool(db_path)?;
    let conn = pool
        .get()
        .map_err(|e| anyhow::anyhow!("failed to get DB connection: {e}"))?;
    encmind_storage::migrations::run_migrations(&conn)?;
    println!("Database initialized at: {}", db_path.display());

    println!("\nSetup complete! Next steps:");
    println!("  1. Set the ENCMIND_PASSPHRASE environment variable");

    // Readiness checks
    println!();
    println!("Readiness:");
    let passphrase_set = std::env::var("ENCMIND_PASSPHRASE").is_ok();
    println!(
        "  Passphrase:    {}",
        if passphrase_set {
            "SET"
        } else {
            "NOT SET (required)"
        }
    );
    let has_providers = !config.llm.api_providers.is_empty();
    println!(
        "  LLM providers: {}",
        if has_providers {
            "configured"
        } else {
            "NOT CONFIGURED"
        }
    );
    println!("  Local tools:   available (file_read, file_write, file_list, bash_exec)");

    match effective_profile {
        encmind_core::config::ServerProfile::Local => {
            println!("  2. Run: encmind-core --config {config_path} serve");
            println!("  3. From a client: encmind-edge --gateway ws://localhost:8443 pair");
        }
        encmind_core::config::ServerProfile::Remote => {
            println!("  2. Open port 8443 in your firewall");
            println!("  3. Run: encmind-core --config {config_path} serve");
            println!("     (auto-TLS will generate a certificate and print the fingerprint)");
            println!(
                "  4. From a client: encmind-edge --gateway wss://<server-ip>:8443 --fingerprint <fp> pair"
            );
        }
        encmind_core::config::ServerProfile::Domain => {
            let port = config.server.port;
            let gateway = config
                .security
                .tls_lifecycle
                .acme_domain
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|domain| {
                    if port == 443 {
                        format!("wss://{domain}")
                    } else {
                        format!("wss://{domain}:{port}")
                    }
                })
                .unwrap_or_else(|| {
                    if port == 443 {
                        "wss://<domain-or-ip>".to_string()
                    } else {
                        format!("wss://<domain-or-ip>:{port}")
                    }
                });
            println!("  2. Ensure DNS and firewall rules are configured for your domain");
            println!("  3. Run: encmind-core --config {config_path} serve");
            println!("  4. From a client: encmind-edge --gateway {gateway} pair");
        }
    }

    Ok(())
}

fn validate_setup_options(options: SetupOptions<'_>) -> Result<(), anyhow::Error> {
    let has_partial_acme = options.acme_domain.is_some() ^ options.acme_email.is_some();
    if has_partial_acme {
        anyhow::bail!("both --acme-domain and --acme-email must be set together");
    }

    let has_partial_manual_tls = options.tls_cert_path.is_some() ^ options.tls_key_path.is_some();
    if has_partial_manual_tls {
        anyhow::bail!("both --tls-cert-path and --tls-key-path must be set together");
    }

    let has_acme = options.acme_domain.is_some() && options.acme_email.is_some();
    let has_manual_tls = options.tls_cert_path.is_some() && options.tls_key_path.is_some();

    if has_acme && has_manual_tls {
        anyhow::bail!(
            "ACME flags and manual TLS flags are mutually exclusive; choose one certificate mode"
        );
    }

    match options.profile {
        SetupProfile::Local | SetupProfile::Remote => {
            if has_acme || has_manual_tls {
                anyhow::bail!(
                    "--acme-* and --tls-*-path flags can only be used with --profile domain"
                );
            }
        }
        SetupProfile::Domain => {
            if !has_acme && !has_manual_tls {
                anyhow::bail!(
                    "profile 'domain' requires either (--acme-domain + --acme-email) or (--tls-cert-path + --tls-key-path)"
                );
            }
        }
    }

    if let Some(domain) = options.acme_domain {
        if domain.trim().is_empty() {
            anyhow::bail!("--acme-domain cannot be empty");
        }
    }
    if let Some(email) = options.acme_email {
        if email.trim().is_empty() {
            anyhow::bail!("--acme-email cannot be empty");
        }
    }
    if let Some(cert_path) = options.tls_cert_path {
        if cert_path.trim().is_empty() {
            anyhow::bail!("--tls-cert-path cannot be empty");
        }
    }
    if let Some(key_path) = options.tls_key_path {
        if key_path.trim().is_empty() {
            anyhow::bail!("--tls-key-path cannot be empty");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn generate_default_config_is_valid_yaml() {
        let yaml = generate_default_config();
        let _: serde_yml::Value =
            serde_yml::from_str(&yaml).expect("default config should be valid YAML");
    }

    #[test]
    fn generate_default_config_parses_as_app_config() {
        let yaml = generate_default_config();
        let config: encmind_core::config::AppConfig =
            serde_yml::from_str(&yaml).expect("default config should parse as AppConfig");
        assert_eq!(config.server.port, 8443);
        assert_eq!(config.agent_pool.max_concurrent_agents, 8);
    }

    #[test]
    fn run_setup_creates_config_and_db() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_str = config_path.to_str().unwrap();

        // Write a config that uses a DB path inside our temp dir
        let db_path = dir.path().join("data.db");
        let skills_path = dir.path().join("skills");
        let yaml = format!(
            r#"
storage:
  db_path: "{}"
  key_source:
    type: Passphrase
    passphrase_env: "ENCMIND_PASSPHRASE"
skills:
  wasm_dir: "{}"
"#,
            db_path.display(),
            skills_path.display()
        );
        std::fs::write(&config_path, &yaml).unwrap();

        // Now run setup — it should detect existing config and just set up DB
        run_setup(config_str, SetupOptions::for_profile(SetupProfile::Local)).unwrap();

        assert!(db_path.exists());
        assert!(skills_path.is_dir());
    }

    #[test]
    fn run_setup_creates_dirs_and_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("subdir/nested/config.yaml");
        let config_str = config_path.to_str().unwrap();

        // Setup should create the directory and default config
        run_setup(config_str, SetupOptions::for_profile(SetupProfile::Local)).unwrap();

        assert!(config_path.exists());
        assert!(config_path.parent().unwrap().join("skills").is_dir());
    }

    #[test]
    fn generate_remote_config_parses_as_app_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let yaml = generate_default_config_for_path(
            &config_path,
            SetupOptions::for_profile(SetupProfile::Remote),
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let config = encmind_core::config::load_config(&config_path)
            .expect("remote config should parse as AppConfig");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8443);
        assert!(config.server.auto_tls);
    }

    #[test]
    fn generate_domain_acme_config_parses_as_app_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let yaml = generate_default_config_for_path(
            &config_path,
            SetupOptions {
                profile: SetupProfile::Domain,
                acme_domain: Some("assistant.example.com"),
                acme_email: Some("ops@example.com"),
                tls_cert_path: None,
                tls_key_path: None,
            },
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let config = encmind_core::config::load_config(&config_path)
            .expect("domain ACME config should parse as AppConfig");
        assert_eq!(
            config.server.profile,
            encmind_core::config::ServerProfile::Domain
        );
        assert_eq!(config.server.port, 443);
        assert_eq!(
            config.security.tls_lifecycle.acme_domain.as_deref(),
            Some("assistant.example.com")
        );
        assert_eq!(
            config.security.tls_lifecycle.acme_email.as_deref(),
            Some("ops@example.com")
        );
    }

    #[test]
    fn generate_domain_manual_tls_config_parses_as_app_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let yaml = generate_default_config_for_path(
            &config_path,
            SetupOptions {
                profile: SetupProfile::Domain,
                acme_domain: None,
                acme_email: None,
                tls_cert_path: Some("/etc/ssl/cert.pem"),
                tls_key_path: Some("/etc/ssl/key.pem"),
            },
        );
        std::fs::write(&config_path, &yaml).unwrap();
        let config = encmind_core::config::load_config(&config_path)
            .expect("domain manual TLS config should parse as AppConfig");
        assert_eq!(
            config.server.profile,
            encmind_core::config::ServerProfile::Domain
        );
        assert_eq!(config.server.port, 443);
        assert_eq!(
            config.server.tls_cert_path.as_deref(),
            Some(Path::new("/etc/ssl/cert.pem"))
        );
        assert_eq!(
            config.server.tls_key_path.as_deref(),
            Some(Path::new("/etc/ssl/key.pem"))
        );
    }

    #[test]
    fn run_setup_rejects_domain_without_tls_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_str = config_path.to_str().unwrap();
        let err =
            run_setup(config_str, SetupOptions::for_profile(SetupProfile::Domain)).unwrap_err();
        assert!(err.to_string().contains("profile 'domain' requires either"));
    }

    #[test]
    fn setup_prints_readiness_checks() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("subdir/config.yaml");
        let config_str = config_path.to_str().unwrap();
        // Should not panic; readiness output goes to stdout.
        run_setup(config_str, SetupOptions::for_profile(SetupProfile::Local)).unwrap();
    }

    #[test]
    fn run_setup_rejects_domain_flags_for_local_profile() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let config_str = config_path.to_str().unwrap();
        let err = run_setup(
            config_str,
            SetupOptions {
                profile: SetupProfile::Local,
                acme_domain: Some("assistant.example.com"),
                acme_email: Some("ops@example.com"),
                tls_cert_path: None,
                tls_key_path: None,
            },
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("can only be used with --profile domain"));
    }
}
