mod serve;
mod setup;
mod status;

use clap::{Parser, Subcommand};
use encmind_core::channel_credentials::{
    is_supported_channel_type, merge_and_validate_channel_credentials,
};
use encmind_core::traits::{SkillToggleStore, WorkflowStore};
use encmind_core::types::{WorkflowRun, WorkflowRunStatus};

#[derive(Parser)]
#[command(name = "encmind-core", about = "EncMind AI assistant", version)]
struct Cli {
    /// Path to config file
    #[arg(short, long, global = true, default_value = "~/.encmind/config.yaml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the EncMind server
    Serve,
    /// Run the initial setup wizard
    Setup {
        /// Server profile
        #[arg(long, value_enum, default_value_t = setup::SetupProfile::Local)]
        profile: setup::SetupProfile,
        /// ACME domain for profile=domain (requires --acme-email)
        #[arg(
            long,
            requires = "acme_email",
            conflicts_with_all = ["tls_cert_path", "tls_key_path"]
        )]
        acme_domain: Option<String>,
        /// ACME email for profile=domain (requires --acme-domain)
        #[arg(
            long,
            requires = "acme_domain",
            conflicts_with_all = ["tls_cert_path", "tls_key_path"]
        )]
        acme_email: Option<String>,
        /// Manual TLS cert path for profile=domain (requires --tls-key-path)
        #[arg(
            long,
            requires = "tls_key_path",
            conflicts_with_all = ["acme_domain", "acme_email"]
        )]
        tls_cert_path: Option<String>,
        /// Manual TLS key path for profile=domain (requires --tls-cert-path)
        #[arg(
            long,
            requires = "tls_cert_path",
            conflicts_with_all = ["acme_domain", "acme_email"]
        )]
        tls_key_path: Option<String>,
    },
    /// Show system status
    Status,
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Security operations
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },
    /// Manage LLM models
    Models {
        #[command(subcommand)]
        action: ModelsAction,
    },
    /// Backup and restore operations
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Manage encryption keys
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Memory and RAG operations
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },
    /// Skill operations
    Skill {
        #[command(subcommand)]
        action: SkillAction,
    },
    /// Workflow management
    Workflow {
        #[command(subcommand)]
        action: WorkflowAction,
    },
    /// Manage channel accounts (Telegram, Slack)
    Channel {
        #[command(subcommand)]
        action: ChannelAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Get a config value
    Get {
        /// Config key (dot-separated path)
        key: String,
    },
    /// Set a config value
    Set {
        /// Config key (dot-separated path)
        key: String,
        /// Value to set
        value: String,
    },
}

#[derive(Subcommand)]
enum SecurityAction {
    /// Run a security audit
    Audit {
        /// Verify the audit log hash chain
        #[arg(long, default_value_t = false)]
        verify_chain: bool,
    },
}

#[derive(Subcommand)]
enum ModelsAction {
    /// List available models
    List,
    /// Download a model
    Download {
        /// Model name or identifier
        name: String,
    },
    /// Show info about a specific model
    Info {
        /// Model name or identifier
        name: String,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Create a backup now
    Now,
    /// List existing backups
    List,
    /// Restore from a backup
    Restore {
        /// Backup identifier or path
        backup_id: String,
    },
}

#[derive(Subcommand)]
enum KeysAction {
    /// Rotate the encryption key
    Rotate,
    /// Show current key status
    Status,
}

#[derive(Subcommand)]
enum MemoryAction {
    /// Show memory index status
    Status,
    /// Rebuild the memory index
    Rebuild,
    /// Search the memory store
    Search {
        /// Search query
        query: String,
    },
    /// Run retrieval quality evaluation
    Eval {
        /// Path to a JSON evaluation set file
        #[arg(long)]
        eval_set: Option<String>,
    },
}

#[derive(Subcommand)]
enum SkillAction {
    /// Validate installed skills (manifest/ABI/loadability)
    Doctor,
    /// Install a WASM skill from a .tar.gz package or directory
    Install {
        /// Path to .tar.gz skill package or directory containing .wasm + .toml
        source: String,
        /// Do not prune/replace stale existing artifacts for matching incoming skill IDs
        #[arg(long)]
        no_prune: bool,
    },
    /// Remove an installed WASM skill
    Remove {
        /// Skill ID to remove
        skill_id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// List all installed WASM skills
    List,
}

#[derive(Subcommand)]
enum WorkflowAction {
    /// List running workflows
    List,
    /// Show details of a workflow run
    Show {
        /// Workflow run ID
        run_id: String,
    },
    /// Cancel a running workflow
    Cancel {
        /// Workflow run ID
        run_id: String,
    },
}

#[derive(Subcommand)]
enum ChannelAction {
    /// List all channel accounts
    List,
    /// Add a new channel account
    Add {
        /// Channel type (e.g. telegram, slack)
        channel_type: String,
        /// Display label for the account
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a channel account
    Remove {
        /// Account ID
        id: String,
    },
    /// Store channel credentials
    Login {
        /// Account ID or channel type
        id_or_type: String,
        /// Bot token credential
        #[arg(long)]
        bot_token: Option<String>,
        /// App token credential (Slack)
        #[arg(long)]
        app_token: Option<String>,
        /// OAuth2 client ID (Gmail)
        #[arg(long)]
        client_id: Option<String>,
        /// OAuth2 client secret (Gmail)
        #[arg(long)]
        client_secret: Option<String>,
        /// OAuth2 refresh token (Gmail)
        #[arg(long)]
        refresh_token: Option<String>,
    },
    /// Delete stored channel credentials
    Logout {
        /// Account ID or channel type
        id_or_type: String,
    },
    /// Show status of a channel account
    Status {
        /// Account ID or channel type (omit for all)
        id_or_type: Option<String>,
        /// Probe connectivity
        #[arg(long)]
        probe: bool,
    },
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}{}", home.to_string_lossy(), &path[1..]);
        }
    }
    path.to_owned()
}

fn format_workflow_step(current_step: i64, total_steps: Option<i64>) -> String {
    match total_steps {
        Some(total) => format!("{current_step}/{total}"),
        None => current_step.to_string(),
    }
}

async fn workflow_list_active_runs(store: &dyn WorkflowStore) -> anyhow::Result<Vec<WorkflowRun>> {
    store
        .list_runs(Some(WorkflowRunStatus::Running), 50)
        .await
        .map_err(anyhow::Error::from)
}

async fn workflow_get_run(
    store: &dyn WorkflowStore,
    run_id: &str,
) -> anyhow::Result<Option<WorkflowRun>> {
    store.get_run(run_id).await.map_err(anyhow::Error::from)
}

async fn workflow_cancel_running_run(
    store: &dyn WorkflowStore,
    run_id: &str,
) -> anyhow::Result<bool> {
    store.cancel_run(run_id).await.map_err(anyhow::Error::from)
}

fn render_workflow_list(runs: &[WorkflowRun]) -> String {
    if runs.is_empty() {
        return "No running workflow runs found.\n".to_string();
    }

    let mut out = String::new();
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "{:<28} {:<20} {:<12} {:<8} {:<20}\n",
            "ID", "WORKFLOW", "STATUS", "STEP", "UPDATED"
        ),
    );
    for run in runs {
        let step = format_workflow_step(run.current_step, run.total_steps);
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{:<28} {:<20} {:<12} {:<8} {:<20}\n",
                run.id, run.workflow_name, run.status, step, run.updated_at
            ),
        );
    }
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\n{} run(s) total.\n", runs.len()));
    out
}

fn render_workflow_show(run: &WorkflowRun) -> String {
    let mut out = String::new();
    let step = format_workflow_step(run.current_step, run.total_steps);
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("ID:            {}\n", run.id));
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("Workflow:      {}\n", run.workflow_name),
    );
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("Agent:         {}\n", run.agent_id));
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("Status:        {}\n", run.status));
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("Step:          {}\n", step));
    if let Some(ref err) = run.error_detail {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("Error:         {}\n", err));
    }
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("Created:       {}\n", run.created_at),
    );
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("Updated:       {}\n", run.updated_at),
    );
    if let Some(ref completed) = run.completed_at {
        let _ =
            std::fmt::Write::write_fmt(&mut out, format_args!("Completed:     {}\n", completed));
    }
    out
}

fn render_workflow_cancel(run_id: &str, cancelled: bool) -> String {
    if cancelled {
        format!("Workflow run '{run_id}' cancelled.\n")
    } else {
        format!("Could not cancel '{run_id}' (not found or not running).\n")
    }
}

async fn derive_backup_key(config: &encmind_core::config::AppConfig) -> anyhow::Result<[u8; 32]> {
    let tee = encmind_tee::detect_tee();
    // Canonicalize db_path to an absolute *file* path so key derivation is
    // deterministic and not affected by the process CWD.
    let abs_db_path = resolve_absolute_db_path(&config.storage.db_path);
    let data_dir = abs_db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/"));
    let key = encmind_storage::key_derivation::derive_key(
        &config.storage.key_source,
        tee.as_ref(),
        data_dir,
    )
    .await?;
    Ok(key)
}

fn resolve_absolute_db_path(db_path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(abs) = std::fs::canonicalize(db_path) {
        return abs;
    }

    let fallback = if db_path.is_absolute() {
        db_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(db_path)
    };

    let file_name = fallback.file_name().map(|name| name.to_os_string());
    if let Some(abs_parent) = fallback
        .parent()
        .and_then(|p| std::fs::canonicalize(p).ok())
    {
        if let Some(file_name) = file_name {
            return abs_parent.join(file_name);
        }
    }

    fallback
}

/// Result of verifying the audit log hash chain.
#[derive(Debug)]
struct ChainVerifyResult {
    valid: bool,
    error_count: usize,
    error_entry_ids: Vec<i64>,
}

/// Load config, open the database, and verify the audit hash chain.
fn verify_audit_chain(config_path: &str) -> anyhow::Result<ChainVerifyResult> {
    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
    let logger = encmind_storage::audit::AuditLogger::new(pool);
    let errors = logger.verify_chain()?;
    Ok(ChainVerifyResult {
        valid: errors.is_empty(),
        error_count: errors.len(),
        error_entry_ids: errors.iter().map(|e| e.entry_id).collect(),
    })
}

fn parse_config_set_value(raw: &str) -> serde_yml::Value {
    serde_yml::from_str::<serde_yml::Value>(raw)
        .unwrap_or_else(|_| serde_yml::Value::String(raw.to_string()))
}

fn set_yaml_path(
    root: &mut serde_yml::Value,
    dotted_key: &str,
    value: serde_yml::Value,
) -> anyhow::Result<()> {
    let segments: Vec<&str> = dotted_key.split('.').map(str::trim).collect();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(anyhow::anyhow!("invalid key path: '{dotted_key}'"));
    }

    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let serde_yml::Value::Mapping(map) = current else {
            return Err(anyhow::anyhow!(
                "cannot set '{}': parent path '{}' is not a mapping",
                dotted_key,
                segment
            ));
        };
        let map_key = serde_yml::Value::String((*segment).to_string());
        if !map.contains_key(&map_key) {
            map.insert(
                map_key.clone(),
                serde_yml::Value::Mapping(serde_yml::Mapping::new()),
            );
        }
        current = map
            .get_mut(&map_key)
            .ok_or_else(|| anyhow::anyhow!("failed to access path segment '{segment}'"))?;
        if !matches!(current, serde_yml::Value::Mapping(_)) {
            return Err(anyhow::anyhow!(
                "cannot set '{}': path segment '{}' is not a mapping",
                dotted_key,
                segment
            ));
        }
    }

    let serde_yml::Value::Mapping(map) = current else {
        return Err(anyhow::anyhow!(
            "cannot set '{}': target parent is not a mapping",
            dotted_key
        ));
    };

    let last = segments
        .last()
        .ok_or_else(|| anyhow::anyhow!("invalid key path: '{dotted_key}'"))?;
    map.insert(serde_yml::Value::String((*last).to_string()), value);
    Ok(())
}

fn mutate_config_file<F>(config_path: &str, mutator: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut serde_yml::Value) -> anyhow::Result<()>,
{
    let path = std::path::Path::new(config_path);
    let baseline_errors: std::collections::HashSet<String> =
        match encmind_core::config::load_config(path) {
            Ok(cfg) => cfg.validate().into_iter().collect(),
            Err(_) => std::collections::HashSet::new(),
        };

    let original = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {e}", path.display()))?;

    let mut raw: serde_yml::Value = serde_yml::from_str(&original)
        .map_err(|e| anyhow::anyhow!("failed to parse config YAML '{}': {e}", path.display()))?;
    mutator(&mut raw)?;

    let updated = serde_yml::to_string(&raw).map_err(|e| {
        anyhow::anyhow!(
            "failed to serialize updated config '{}': {e}",
            path.display()
        )
    })?;
    std::fs::write(path, &updated)
        .map_err(|e| anyhow::anyhow!("failed to write updated config '{}': {e}", path.display()))?;

    let validation = (|| -> anyhow::Result<()> {
        let parsed = encmind_core::config::load_config(path)
            .map_err(|e| anyhow::anyhow!("updated config failed to load/validate: {e}"))?;
        let errors: Vec<String> = parsed
            .validate()
            .into_iter()
            .filter(|err| !baseline_errors.contains(err))
            .collect();
        if !errors.is_empty() {
            return Err(anyhow::anyhow!(
                "updated config failed validation: {}",
                errors.join("; ")
            ));
        }
        Ok(())
    })();

    if let Err(err) = validation {
        let _ = std::fs::write(path, original);
        return Err(anyhow::anyhow!("{err} (rolled back to previous config)"));
    }

    Ok(())
}

fn run_config_set(config_path: &str, key: &str, value: &str) -> anyhow::Result<()> {
    let parsed_value = parse_config_set_value(value);
    mutate_config_file(config_path, |raw| {
        set_yaml_path(raw, key, parsed_value.clone())
    })?;
    println!(
        "Updated config: {key} = {}",
        serde_json::to_string(&parsed_value)?
    );
    Ok(())
}

fn run_models_download(config_path: &str, name: &str) -> anyhow::Result<()> {
    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    if !config.llm.api_providers.iter().any(|p| p.name == name) {
        let available = if config.llm.api_providers.is_empty() {
            "(none configured)".to_string()
        } else {
            config
                .llm
                .api_providers
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(anyhow::anyhow!(
            "provider '{}' not found in llm.api_providers (available: {})",
            name,
            available
        ));
    }

    mutate_config_file(config_path, |raw| {
        let mode_value = serde_yml::to_value(encmind_core::config::InferenceMode::ApiProvider {
            provider: name.to_string(),
        })
        .map_err(|e| anyhow::anyhow!("failed to serialize provider mode: {e}"))?;
        set_yaml_path(raw, "llm.mode", mode_value)
    })?;

    let env_var = format!("{}_API_KEY", name.to_uppercase());
    let api_key_set = std::env::var(&env_var)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    println!("Configured llm.mode to provider '{name}'.");
    println!(
        "Expected API key env var: {} ({})",
        env_var,
        if api_key_set { "set" } else { "not set" }
    );
    Ok(())
}

async fn run_keys_rotate(config_path: &str) -> anyhow::Result<()> {
    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    // Validate key source availability by deriving the active key material.
    let _key = derive_backup_key(&config).await?;

    let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
    {
        let conn = pool.get()?;
        encmind_storage::migrations::run_migrations(&conn)?;
    }
    let logger = encmind_storage::audit::AuditLogger::new(pool);
    let detail = format!(
        "manual rotation check requested (interval_days={} auto_rotate={} batch_size={})",
        config.security.key_rotation.interval_days,
        config.security.key_rotation.auto_rotate,
        config.security.key_rotation.batch_size
    );
    let _ = logger.append(
        "security",
        "key_rotation.check",
        Some(detail.as_str()),
        Some("cli"),
    );

    println!("Key material check: OK");
    println!(
        "Rotation policy: interval_days={} auto_rotate={} batch_size={}",
        config.security.key_rotation.interval_days,
        config.security.key_rotation.auto_rotate,
        config.security.key_rotation.batch_size
    );
    println!(
        "To rotate key material, update the configured key source secret and restart the gateway."
    );
    Ok(())
}

async fn run_skill_doctor(config_path: &str) -> anyhow::Result<()> {
    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    let skills_dir = encmind_gateway::server::resolve_skills_dir(&config);
    let policy = encmind_core::policy::PolicyEnforcer::new(config.plugin_policy.clone());
    let disabled_skill_ids = if config.storage.db_path.exists() {
        match encmind_storage::pool::create_pool(&config.storage.db_path) {
            Ok(pool) => {
                if let Ok(conn) = pool.get() {
                    if let Err(e) = encmind_storage::migrations::run_migrations(&conn) {
                        println!(
                            "  Warning: failed to run migrations before reading disabled skills; ignoring toggle state ({e})"
                        );
                        std::collections::HashSet::new()
                    } else {
                        // Release the migration connection before async store calls.
                        // This avoids holding a pooled connection across `.await`.
                        drop(conn);
                        let store =
                            encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool);
                        match store.list_disabled().await {
                            Ok(ids) => ids.into_iter().collect::<std::collections::HashSet<_>>(),
                            Err(e) => {
                                println!(
                                    "  Warning: failed to read disabled skills; ignoring toggle state ({e})"
                                );
                                std::collections::HashSet::new()
                            }
                        }
                    }
                } else {
                    println!(
                        "  Warning: failed to acquire DB connection for disabled-skill lookup; ignoring toggle state"
                    );
                    std::collections::HashSet::new()
                }
            }
            Err(e) => {
                println!("  Warning: failed to open storage DB; ignoring toggle state ({e})");
                std::collections::HashSet::new()
            }
        }
    } else {
        std::collections::HashSet::new()
    };

    let mut wasm_config = wasmtime::Config::new();
    wasm_config.async_support(true);
    let engine = wasmtime::Engine::new(&wasm_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize WASM engine: {e}"))?;

    let result = encmind_wasm_host::skill_loader::load_skills_from_dir(&skills_dir, &engine);
    if result.skills.is_empty() && result.errors.is_empty() {
        println!("No skills found in {}", skills_dir.display());
        return Ok(());
    }

    let enforce_allowlist = !config.skills.enabled.is_empty();
    let mut skill_id_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for skill in &result.skills {
        *skill_id_counts
            .entry(skill.manifest.manifest.name.clone())
            .or_insert(0) += 1;
    }
    let duplicate_skill_ids: std::collections::HashSet<String> = skill_id_counts
        .into_iter()
        .filter_map(|(skill_id, count)| (count > 1).then_some(skill_id))
        .collect();

    println!("Skill doctor report");
    println!("  Skills dir: {}", skills_dir.display());
    println!("  Loaded: {}", result.skills.len());
    println!("  Disabled: {}", disabled_skill_ids.len());
    println!("  Signature validation: unavailable in this build (skipped)");
    let mut acceptance_issues = 0usize;
    if !duplicate_skill_ids.is_empty() {
        let mut duplicate_ids: Vec<_> = duplicate_skill_ids.iter().cloned().collect();
        duplicate_ids.sort();
        println!("  Duplicate skill IDs: {}", duplicate_ids.len());
        for duplicate_id in duplicate_ids {
            let in_scope = (!enforce_allowlist || config.skills.enabled.contains(&duplicate_id))
                && !disabled_skill_ids.contains(&duplicate_id);
            if in_scope {
                acceptance_issues += 1;
                println!(
                    "    ISSUE duplicate skill_id '{}' detected across artifacts; gateway will skip all artifacts for this skill_id",
                    duplicate_id
                );
            } else {
                println!(
                    "    SKIP  duplicate skill_id '{}' (inactive by allowlist/disabled)",
                    duplicate_id
                );
            }
        }
    }
    for skill in &result.skills {
        if duplicate_skill_ids.contains(&skill.manifest.manifest.name) {
            continue;
        }
        if disabled_skill_ids.contains(&skill.manifest.manifest.name) {
            println!(
                "    SKIP  {} v{} (disabled via skills.toggle)",
                skill.manifest.manifest.name, skill.manifest.manifest.version
            );
            continue;
        }
        let (status, has_issue) =
            match encmind_wasm_host::manifest::validate_third_party(&skill.manifest.manifest) {
                Err(e) => (format!("third_party=denied({e})"), true),
                Ok(()) => match encmind_wasm_host::manifest::validate_against_policy(
                    &skill.manifest.manifest,
                    &policy,
                ) {
                    Ok(encmind_core::policy::PolicyDecision::Allowed) => {
                        ("policy=allowed".to_string(), false)
                    }
                    Ok(encmind_core::policy::PolicyDecision::NeedsPrompt(caps)) => {
                        (format!("policy=needs_prompt({})", caps.join(",")), true)
                    }
                    Ok(encmind_core::policy::PolicyDecision::Denied(reason)) => {
                        (format!("policy=denied({reason})"), true)
                    }
                    Err(e) => (format!("policy=error({e})"), true),
                },
            };
        if has_issue {
            acceptance_issues += 1;
        };
        println!(
            "    {}  {} v{} (host_abi={}, {})",
            if has_issue { "ISSUE" } else { "OK" },
            skill.manifest.manifest.name,
            skill.manifest.manifest.version,
            skill.manifest.manifest.host_abi,
            status
        );
    }

    if result.errors.is_empty() && acceptance_issues == 0 {
        println!("  Issues: 0");
        return Ok(());
    }

    let mut hard_error_count = 0usize;
    for error in &result.errors {
        let (error_key, summary) = match error {
            encmind_wasm_host::skill_loader::LoadError::DirectoryUnreadable { dir, error } => (
                dir.display().to_string(),
                format!("directory unreadable: {} ({error})", dir.display()),
            ),
            encmind_wasm_host::skill_loader::LoadError::MissingManifest {
                skill_id,
                wasm_path,
            } => (
                wasm_path.display().to_string(),
                format!(
                    "missing manifest for skill '{skill_id}' ({})",
                    wasm_path.display()
                ),
            ),
            encmind_wasm_host::skill_loader::LoadError::SkillLoadFailed {
                skill_id,
                wasm_path,
                error,
            } => (
                wasm_path.display().to_string(),
                format!(
                    "failed to load '{skill_id}' ({}): {error}",
                    wasm_path.display()
                ),
            ),
        };
        let candidate_ids =
            encmind_gateway::server::resolve_load_error_skill_ids(&error_key, &skills_dir);
        if encmind_gateway::server::should_suppress_load_error_for_disabled(
            &candidate_ids,
            &disabled_skill_ids,
        ) {
            println!(
                "    SKIP  {} (disabled via skills.toggle, resolved_ids={:?})",
                summary, candidate_ids
            );
            continue;
        }
        hard_error_count += 1;
        println!("    ERROR {summary}");
    }

    let total_issues = hard_error_count + acceptance_issues;
    println!("  Issues: {total_issues}");

    if total_issues == 0 {
        return Ok(());
    }

    if acceptance_issues > 0 {
        println!("  Startup acceptance issues: {acceptance_issues} (see per-skill status above)");
    }

    Err(anyhow::anyhow!(
        "skill doctor found {} issue(s)",
        total_issues
    ))
}

async fn run_skill_install(
    config_path: &str,
    source: &str,
    prune_existing: bool,
) -> anyhow::Result<()> {
    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    let skills_dir = encmind_gateway::server::resolve_skills_dir(&config);
    std::fs::create_dir_all(&skills_dir)?;

    let source_path = std::path::Path::new(source);
    if !source_path.exists() {
        return Err(anyhow::anyhow!("source path does not exist: {source}"));
    }

    let artifacts = collect_skill_artifacts(source_path, source)?;
    if artifacts.is_empty() {
        return Err(anyhow::anyhow!(
            "no .wasm or .toml files found in {}",
            source_path.display()
        ));
    }

    let incoming_skill_ids = incoming_manifest_skill_ids(&artifacts);
    let incoming_artifact_names: std::collections::HashSet<std::ffi::OsString> =
        artifacts.iter().map(|(name, _)| name.clone()).collect();
    let incoming_artifact_stems = incoming_artifact_stems(&artifacts);
    let mut stale_artifacts = if prune_existing {
        find_replaced_skill_artifacts(
            &skills_dir,
            &incoming_skill_ids,
            &incoming_artifact_names,
            &incoming_artifact_stems,
        )?
    } else {
        Vec::new()
    };
    stale_artifacts.sort();

    // Persist artifacts into the runtime skills directory with rollback metadata.
    // If validation fails later, previous on-disk contents are restored.
    let mut backups: Vec<(std::path::PathBuf, Option<Vec<u8>>)> =
        Vec::with_capacity(artifacts.len() + stale_artifacts.len());
    for stale in &stale_artifacts {
        let previous = if stale.exists() {
            Some(std::fs::read(stale)?)
        } else {
            None
        };
        backups.push((stale.clone(), previous));
        if stale.exists() {
            if let Err(remove_err) = std::fs::remove_file(stale) {
                let rollback_errors = rollback_skill_install(&backups);
                let rollback_note = if rollback_errors.is_empty() {
                    String::new()
                } else {
                    format!("; rollback issues: {}", rollback_errors.join("; "))
                };
                return Err(anyhow::anyhow!(
                    "failed to replace existing artifact {}: {remove_err}{rollback_note}",
                    stale.display()
                ));
            }
        }
    }

    let mut installed_files: Vec<std::path::PathBuf> = Vec::with_capacity(artifacts.len());
    for (file_name, bytes) in &artifacts {
        let dest = skills_dir.join(file_name);
        installed_files.push(dest.clone());
        let previous = if dest.exists() {
            Some(std::fs::read(&dest)?)
        } else {
            None
        };
        backups.push((dest.clone(), previous));
        if let Err(write_err) = std::fs::write(&dest, bytes) {
            let rollback_errors = rollback_skill_install(&backups);
            let rollback_note = if rollback_errors.is_empty() {
                String::new()
            } else {
                format!("; rollback issues: {}", rollback_errors.join("; "))
            };
            return Err(anyhow::anyhow!(
                "failed to install artifact {}: {write_err}{rollback_note}",
                dest.display()
            ));
        }
    }
    let installed_wasm_names: std::collections::HashSet<std::ffi::OsString> = artifacts
        .iter()
        .filter_map(|(name, _)| {
            (std::path::Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                == Some("wasm"))
            .then_some(name.clone())
        })
        .collect();

    // Validate the installed skill
    let mut wasm_config = wasmtime::Config::new();
    wasm_config.async_support(true);
    let engine = wasmtime::Engine::new(&wasm_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize WASM engine: {e}"))?;
    let result = encmind_wasm_host::skill_loader::load_skills_from_dir(&skills_dir, &engine);

    let policy = encmind_core::policy::PolicyEnforcer::new(config.plugin_policy.clone());
    let mut skill_id_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for skill in &result.skills {
        *skill_id_counts
            .entry(skill.manifest.manifest.name.clone())
            .or_insert(0) += 1;
    }
    let duplicate_skill_ids: std::collections::HashSet<String> = skill_id_counts
        .into_iter()
        .filter_map(|(skill_id, count)| (count > 1).then_some(skill_id))
        .collect();

    let mut validated = false;
    let mut matched_wasm_names: std::collections::HashSet<std::ffi::OsString> =
        std::collections::HashSet::new();
    let mut validation_rejections = Vec::new();
    let mut install_logs = Vec::new();
    for skill in &result.skills {
        // Match validation against actual installed WASM filenames, not manifest
        // skill names. Manifest names and file stems may legitimately differ.
        let matches_installed = skill
            .wasm_path
            .file_name()
            .is_some_and(|name| installed_wasm_names.contains(name));
        if matches_installed {
            if let Some(file_name) = skill.wasm_path.file_name() {
                matched_wasm_names.insert(file_name.to_os_string());
            }
            if duplicate_skill_ids.contains(&skill.manifest.manifest.name) {
                validation_rejections.push(format!(
                    "{}: duplicate skill_id detected across artifacts; gateway will skip this skill_id at runtime",
                    skill.manifest.manifest.name
                ));
                continue;
            }
            if let Err(e) =
                encmind_wasm_host::manifest::validate_third_party(&skill.manifest.manifest)
            {
                validation_rejections.push(format!(
                    "{}: third-party capability validation failed: {e}",
                    skill.manifest.manifest.name
                ));
                continue;
            }
            match encmind_wasm_host::manifest::validate_against_policy(
                &skill.manifest.manifest,
                &policy,
            ) {
                Ok(encmind_core::policy::PolicyDecision::Allowed) => {
                    install_logs.push(format!(
                        "Installed {} v{} (ABI: {}, policy: allowed)",
                        skill.manifest.manifest.name,
                        skill.manifest.manifest.version,
                        skill.manifest.manifest.host_abi,
                    ));
                    validated = true;
                }
                Ok(encmind_core::policy::PolicyDecision::NeedsPrompt(caps)) => {
                    validation_rejections.push(format!(
                        "{}: capabilities require interactive approval ({})",
                        skill.manifest.manifest.name,
                        caps.join(", ")
                    ));
                }
                Ok(encmind_core::policy::PolicyDecision::Denied(reason)) => {
                    validation_rejections
                        .push(format!("{}: {reason}", skill.manifest.manifest.name));
                }
                Err(e) => {
                    validation_rejections.push(format!(
                        "{}: policy validation failed: {e}",
                        skill.manifest.manifest.name
                    ));
                }
            }
        }
    }

    let mut unresolved_wasm: Vec<String> = installed_wasm_names
        .difference(&matched_wasm_names)
        .map(|name| name.to_string_lossy().to_string())
        .collect();
    unresolved_wasm.sort();
    if !unresolved_wasm.is_empty() {
        let rollback_errors = rollback_skill_install(&backups);
        let rollback_note = if rollback_errors.is_empty() {
            String::new()
        } else {
            format!("; rollback issues: {}", rollback_errors.join("; "))
        };
        return Err(anyhow::anyhow!(
            "installed WASM artifact(s) failed to load/validate: {}{rollback_note}",
            unresolved_wasm.join(", ")
        ));
    }

    if !validation_rejections.is_empty() {
        let rollback_errors = rollback_skill_install(&backups);
        let rollback_note = if rollback_errors.is_empty() {
            String::new()
        } else {
            format!("; rollback issues: {}", rollback_errors.join("; "))
        };
        return Err(anyhow::anyhow!(
            "installed skill artifact(s) rejected during validation: {}{rollback_note}",
            validation_rejections.join("; ")
        ));
    }

    if !validated {
        let rollback_errors = rollback_skill_install(&backups);
        let rollback_note = if rollback_errors.is_empty() {
            String::new()
        } else {
            format!("; rollback issues: {}", rollback_errors.join("; "))
        };
        let files = installed_files
            .iter()
            .map(|f| f.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow::anyhow!(
            "installed files but could not validate any skill manifest; refusing install: {files}{rollback_note}"
        ));
    }

    for line in install_logs {
        println!("{line}");
    }
    if !stale_artifacts.is_empty() {
        let mut names: Vec<String> = stale_artifacts
            .iter()
            .map(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| path.display().to_string())
            })
            .collect();
        names.sort();
        names.dedup();
        println!("Replaced stale artifact(s): {}", names.join(", "));
    }

    Ok(())
}

fn collect_skill_artifacts(
    source_path: &std::path::Path,
    source: &str,
) -> anyhow::Result<Vec<(std::ffi::OsString, Vec<u8>)>> {
    fn is_supported_artifact(path: &std::path::Path) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("wasm" | "toml")
        )
    }

    let mut artifacts: Vec<(std::ffi::OsString, Vec<u8>)> = Vec::new();
    let mut seen_names: std::collections::HashSet<std::ffi::OsString> =
        std::collections::HashSet::new();

    if source_path.is_dir() {
        for entry in std::fs::read_dir(source_path)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || !is_supported_artifact(&path) {
                continue;
            }
            let Some(file_name) = path.file_name() else {
                continue;
            };
            if file_name == std::ffi::OsStr::new(".") || file_name == std::ffi::OsStr::new("..") {
                continue;
            }
            let file_name = file_name.to_owned();
            if !seen_names.insert(file_name.clone()) {
                return Err(anyhow::anyhow!(
                    "duplicate artifact filename in source directory: {}",
                    file_name.to_string_lossy()
                ));
            }
            artifacts.push((file_name, std::fs::read(&path)?));
        }
        return Ok(artifacts);
    }

    if source.ends_with(".tar.gz") || source.ends_with(".tgz") {
        let file = std::fs::File::open(source_path)?;
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        for entry in archive.entries()? {
            use std::io::Read;
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path()?.into_owned();
            if !is_supported_artifact(&path) {
                continue;
            }
            let Some(file_name) = path.file_name() else {
                continue;
            };
            if file_name == std::ffi::OsStr::new(".") || file_name == std::ffi::OsStr::new("..") {
                continue;
            }
            let file_name = file_name.to_owned();
            if !seen_names.insert(file_name.clone()) {
                return Err(anyhow::anyhow!(
                    "duplicate artifact filename in archive: {}",
                    file_name.to_string_lossy()
                ));
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            artifacts.push((file_name, bytes));
        }
        return Ok(artifacts);
    }

    Err(anyhow::anyhow!(
        "unsupported source format: expected directory or .tar.gz file"
    ))
}

fn incoming_manifest_skill_ids(
    artifacts: &[(std::ffi::OsString, Vec<u8>)],
) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    for (file_name, bytes) in artifacts {
        if std::path::Path::new(file_name)
            .extension()
            .and_then(|e| e.to_str())
            != Some("toml")
        {
            continue;
        }
        let Ok(contents) = std::str::from_utf8(bytes) else {
            continue;
        };
        let Ok(parsed) = encmind_wasm_host::manifest::parse_manifest_full(contents) else {
            continue;
        };
        ids.insert(parsed.manifest.name);
    }
    ids
}

fn incoming_artifact_stems(
    artifacts: &[(std::ffi::OsString, Vec<u8>)],
) -> std::collections::HashSet<String> {
    artifacts
        .iter()
        .filter_map(|(file_name, _)| {
            std::path::Path::new(file_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
        })
        .collect()
}

fn find_replaced_skill_artifacts(
    skills_dir: &std::path::Path,
    incoming_skill_ids: &std::collections::HashSet<String>,
    incoming_artifact_names: &std::collections::HashSet<std::ffi::OsString>,
    incoming_artifact_stems: &std::collections::HashSet<String>,
) -> anyhow::Result<Vec<std::path::PathBuf>> {
    if (incoming_skill_ids.is_empty() && incoming_artifact_stems.is_empty()) || !skills_dir.exists()
    {
        return Ok(Vec::new());
    }

    let mut replaced = std::collections::HashSet::new();
    for entry in std::fs::read_dir(skills_dir)? {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|ext| ext.to_str());
        if ext != Some("toml") && ext != Some("wasm") {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        if incoming_artifact_names.contains(file_name) {
            continue;
        }
        let stem_matches_target = path
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|stem| {
                incoming_artifact_stems.contains(stem) || incoming_skill_ids.contains(stem)
            });
        if ext == Some("wasm") {
            let sidecar = path.with_extension("toml");
            if !sidecar.exists() {
                if stem_matches_target {
                    replaced.insert(path.clone());
                }
                continue;
            }

            let sidecar_matches_target = manifest_skill_id_for_prune(&sidecar)
                .as_deref()
                .is_some_and(|id| incoming_skill_ids.contains(id))
                || stem_matches_target
                || sidecar
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|stem| {
                        incoming_artifact_stems.contains(stem) || incoming_skill_ids.contains(stem)
                    });
            if sidecar_matches_target {
                replaced.insert(path.clone());
                if let Some(sidecar_name) = sidecar.file_name() {
                    if !incoming_artifact_names.contains(sidecar_name) {
                        replaced.insert(sidecar);
                    }
                }
            }
            continue;
        }

        let manifest_skill_id = manifest_skill_id_for_prune(&path);
        let matches_incoming = manifest_skill_id
            .as_deref()
            .is_some_and(|id| incoming_skill_ids.contains(id))
            || path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|stem| {
                    incoming_artifact_stems.contains(stem) || incoming_skill_ids.contains(stem)
                });
        if !matches_incoming {
            continue;
        }

        replaced.insert(path.clone());
        let wasm_path = path.with_extension("wasm");
        if let Some(wasm_name) = wasm_path.file_name() {
            if !incoming_artifact_names.contains(wasm_name) {
                replaced.insert(wasm_path);
            }
        }
    }

    Ok(replaced.into_iter().collect())
}

fn manifest_skill_id_for_prune(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    if let Ok(parsed) = encmind_wasm_host::manifest::parse_manifest_full(&text) {
        return Some(parsed.manifest.name);
    }
    extract_skill_name_lenient(&text)
}

fn extract_skill_name_lenient(manifest: &str) -> Option<String> {
    let mut in_skill_section = false;
    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_skill_section = line == "[skill]";
            continue;
        }
        if !in_skill_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "name" {
            continue;
        }
        let quoted = value.trim();
        let unquoted = quoted
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| quoted.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(quoted)
            .trim();
        if encmind_core::skill_id::is_valid_skill_id(unquoted) {
            return Some(unquoted.to_string());
        }
    }
    None
}

fn rollback_skill_install(backups: &[(std::path::PathBuf, Option<Vec<u8>>)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (path, previous) in backups.iter().rev() {
        let result = match previous {
            Some(bytes) => std::fs::write(path, bytes),
            None => {
                if path.exists() {
                    std::fs::remove_file(path)
                } else {
                    Ok(())
                }
            }
        };
        if let Err(e) = result {
            errors.push(format!("{}: {e}", path.display()));
        }
    }
    errors
}

async fn run_skill_remove(config_path: &str, skill_id: &str, force: bool) -> anyhow::Result<()> {
    let skill_id = skill_id.trim();
    encmind_core::skill_id::validate_skill_id(skill_id)
        .map_err(|reason| anyhow::anyhow!("invalid skill_id: {reason}"))?;

    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    let skills_dir = encmind_gateway::server::resolve_skills_dir(&config);
    let mut remove_paths: std::collections::HashSet<std::path::PathBuf> =
        std::collections::HashSet::new();

    let parse_manifest_name = |path: &std::path::Path| -> Option<String> {
        let manifest = std::fs::read_to_string(path).ok()?;
        let parsed = encmind_wasm_host::manifest::parse_manifest_full(&manifest).ok()?;
        Some(parsed.manifest.name)
    };

    let direct_wasm = skills_dir.join(format!("{skill_id}.wasm"));
    let direct_toml = skills_dir.join(format!("{skill_id}.toml"));
    if direct_wasm.exists() {
        remove_paths.insert(direct_wasm);
    }
    if direct_toml.exists() {
        remove_paths.insert(direct_toml);
    }

    if skills_dir.exists() {
        let mut wasm_config = wasmtime::Config::new();
        wasm_config.async_support(true);
        let engine = wasmtime::Engine::new(&wasm_config)
            .map_err(|e| anyhow::anyhow!("failed to initialize WASM engine: {e}"))?;
        let load_result =
            encmind_wasm_host::skill_loader::load_skills_from_dir(&skills_dir, &engine);
        for skill in load_result.skills {
            if skill.manifest.manifest.name == skill_id {
                remove_paths.insert(skill.wasm_path.clone());
                remove_paths.insert(skill.wasm_path.with_extension("toml"));
            }
        }

        // Fallback for broken/malformed skills that don't appear in load_result.skills:
        // scan manifests directly so removal still works by manifest name.
        if let Ok(entries) = std::fs::read_dir(&skills_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|v| v.to_str()) != Some("toml") {
                    continue;
                }
                let stem_matches = path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .is_some_and(|stem| stem == skill_id);
                let manifest_matches = parse_manifest_name(&path).as_deref() == Some(skill_id);
                if stem_matches || manifest_matches {
                    remove_paths.insert(path.clone());
                    remove_paths.insert(path.with_extension("wasm"));
                }
            }
        }
    }

    if remove_paths.is_empty() {
        if !force {
            print!(
                "No artifacts found for '{skill_id}'. Remove persisted runtime state only? [y/N] "
            );
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }

        let mut cleanup_skill_ids = std::collections::HashSet::new();
        cleanup_skill_ids.insert(skill_id.to_string());
        let purged = cleanup_removed_skill_runtime_state(&config, &cleanup_skill_ids)?;
        if purged > 0 {
            println!(
                "No skill artifacts found for '{skill_id}'. Removed {purged} persisted runtime state row(s)."
            );
            return Ok(());
        }

        return Err(anyhow::anyhow!(
            "skill '{skill_id}' not found in {} and no persisted runtime state exists",
            skills_dir.display()
        ));
    }
    let cleanup_skill_ids = derive_skill_ids_for_removal(skill_id, &remove_paths);

    if !force {
        print!("Remove skill '{skill_id}'? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let mut removed: Vec<std::path::PathBuf> = remove_paths
        .into_iter()
        .filter(|path| path.exists())
        .collect();
    removed.sort();

    for path in &removed {
        std::fs::remove_file(path)?;
    }
    let _ = cleanup_removed_skill_runtime_state(&config, &cleanup_skill_ids)?;

    println!("Removed skill '{skill_id}':");
    for f in &removed {
        println!("  {}", f.display());
    }

    Ok(())
}

fn derive_skill_ids_for_removal(
    requested_skill_id: &str,
    remove_paths: &std::collections::HashSet<std::path::PathBuf>,
) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    ids.insert(requested_skill_id.to_string());

    for path in remove_paths {
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if encmind_core::skill_id::is_valid_skill_id(stem) {
                ids.insert(stem.to_string());
            }
        }
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Ok(manifest_str) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(parsed) = encmind_wasm_host::manifest::parse_manifest_full(&manifest_str) else {
            continue;
        };
        if encmind_core::skill_id::is_valid_skill_id(&parsed.manifest.name) {
            ids.insert(parsed.manifest.name);
        }
    }
    ids
}

fn cleanup_removed_skill_runtime_state(
    config: &encmind_core::config::AppConfig,
    skill_ids: &std::collections::HashSet<String>,
) -> anyhow::Result<u64> {
    if skill_ids.is_empty() || !config.storage.db_path.exists() {
        return Ok(0);
    }

    let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
    {
        let conn = pool.get()?;
        encmind_storage::migrations::run_migrations(&conn)?;
    }
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;
    let mut affected = 0u64;

    for skill_id in skill_ids {
        affected += tx.execute(
            "DELETE FROM skill_toggle_state WHERE skill_id = ?1",
            [skill_id],
        )? as u64;
        affected += tx.execute("DELETE FROM skill_kv WHERE skill_id = ?1", [skill_id])? as u64;
        affected += tx.execute("DELETE FROM skill_timers WHERE skill_id = ?1", [skill_id])? as u64;
    }
    tx.commit()?;

    Ok(affected)
}

async fn run_skill_list(config_path: &str) -> anyhow::Result<()> {
    let config = encmind_core::config::load_config(std::path::Path::new(config_path))?;
    let skills_dir = encmind_gateway::server::resolve_skills_dir(&config);

    if !skills_dir.exists() {
        println!("Skills directory does not exist: {}", skills_dir.display());
        return Ok(());
    }

    let mut wasm_config = wasmtime::Config::new();
    wasm_config.async_support(true);
    let engine = wasmtime::Engine::new(&wasm_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize WASM engine: {e}"))?;

    let result = encmind_wasm_host::skill_loader::load_skills_from_dir(&skills_dir, &engine);

    // Load disabled state
    let disabled_skill_ids = if config.storage.db_path.exists() {
        match encmind_storage::pool::create_pool(&config.storage.db_path) {
            Ok(pool) => {
                if let Ok(conn) = pool.get() {
                    if encmind_storage::migrations::run_migrations(&conn).is_ok() {
                        drop(conn);
                        let store =
                            encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool);
                        store
                            .list_disabled()
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .collect::<std::collections::HashSet<_>>()
                    } else {
                        std::collections::HashSet::new()
                    }
                } else {
                    std::collections::HashSet::new()
                }
            }
            Err(_) => std::collections::HashSet::new(),
        }
    } else {
        std::collections::HashSet::new()
    };

    let summarize_load_error =
        |error: &encmind_wasm_host::skill_loader::LoadError| -> (String, String) {
            match error {
                encmind_wasm_host::skill_loader::LoadError::DirectoryUnreadable { dir, error } => (
                    dir.display().to_string(),
                    format!("directory unreadable: {} ({error})", dir.display()),
                ),
                encmind_wasm_host::skill_loader::LoadError::MissingManifest {
                    skill_id,
                    wasm_path,
                } => (
                    wasm_path.display().to_string(),
                    format!(
                        "missing manifest for skill '{skill_id}' ({})",
                        wasm_path.display()
                    ),
                ),
                encmind_wasm_host::skill_loader::LoadError::SkillLoadFailed {
                    skill_id,
                    wasm_path,
                    error,
                } => (
                    wasm_path.display().to_string(),
                    format!(
                        "failed to load '{skill_id}' ({}): {error}",
                        wasm_path.display()
                    ),
                ),
            }
        };

    let mut reportable_errors: Vec<String> = Vec::new();
    let mut skipped_disabled_errors: Vec<String> = Vec::new();
    for error in &result.errors {
        let (error_key, summary) = summarize_load_error(error);
        let candidate_ids =
            encmind_gateway::server::resolve_load_error_skill_ids(&error_key, &skills_dir);
        if encmind_gateway::server::should_suppress_load_error_for_disabled(
            &candidate_ids,
            &disabled_skill_ids,
        ) {
            skipped_disabled_errors.push(format!(
                "{} (disabled via skills.toggle, resolved_ids={:?})",
                summary, candidate_ids
            ));
            continue;
        }
        reportable_errors.push(summary);
    }

    let enforce_allowlist = !config.skills.enabled.is_empty();
    let mut skill_id_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for skill in &result.skills {
        *skill_id_counts
            .entry(skill.manifest.manifest.name.clone())
            .or_insert(0) += 1;
    }
    let duplicate_skill_ids: std::collections::HashSet<String> = skill_id_counts
        .into_iter()
        .filter_map(|(skill_id, count)| (count > 1).then_some(skill_id))
        .collect();
    let mut duplicate_issues = Vec::new();
    let mut duplicate_skipped = Vec::new();
    if !duplicate_skill_ids.is_empty() {
        let mut ids: Vec<_> = duplicate_skill_ids.iter().cloned().collect();
        ids.sort();
        for skill_id in ids {
            let in_scope = (!enforce_allowlist || config.skills.enabled.contains(&skill_id))
                && !disabled_skill_ids.contains(&skill_id);
            if in_scope {
                duplicate_issues.push(skill_id);
            } else {
                duplicate_skipped.push(skill_id);
            }
        }
    }

    if result.skills.is_empty() {
        if reportable_errors.is_empty() && duplicate_issues.is_empty() {
            println!("No skills found in {}", skills_dir.display());
            if !skipped_disabled_errors.is_empty() {
                println!(
                    "Skipped disabled-skill load errors: {}",
                    skipped_disabled_errors.len()
                );
                for skipped in &skipped_disabled_errors {
                    println!("  - {skipped}");
                }
            }
            if !duplicate_skipped.is_empty() {
                println!("Skipped duplicate skill IDs: {}", duplicate_skipped.len());
                for skill_id in &duplicate_skipped {
                    println!("  - {skill_id}");
                }
            }
            return Ok(());
        }

        println!("No valid skills loaded from {}", skills_dir.display());
        println!("Load errors: {}", reportable_errors.len());
        for summary in &reportable_errors {
            println!("  - {summary}");
        }
        if !skipped_disabled_errors.is_empty() {
            println!(
                "Skipped disabled-skill load errors: {}",
                skipped_disabled_errors.len()
            );
            for skipped in &skipped_disabled_errors {
                println!("  - {skipped}");
            }
        }
        if !duplicate_issues.is_empty() {
            println!(
                "Duplicate skill IDs (runtime will skip): {}",
                duplicate_issues.len()
            );
            for skill_id in &duplicate_issues {
                println!("  - {skill_id}");
            }
        }
        if !duplicate_skipped.is_empty() {
            println!("Skipped duplicate skill IDs: {}", duplicate_skipped.len());
            for skill_id in &duplicate_skipped {
                println!("  - {skill_id}");
            }
        }
        return Err(anyhow::anyhow!(
            "skill list found {} load error(s) and {} duplicate skill_id issue(s)",
            reportable_errors.len(),
            duplicate_issues.len()
        ));
    }

    println!(
        "{:<30} {:<10} {:<10} {:<30} {:<8}",
        "SKILL ID", "VERSION", "ABI", "TOOL NAME", "ENABLED"
    );
    println!("{}", "-".repeat(88));
    for skill in &result.skills {
        let sid = &skill.manifest.manifest.name;
        if duplicate_skill_ids.contains(sid) {
            continue;
        }
        let enabled = !disabled_skill_ids.contains(sid);
        let tool_name = skill
            .manifest
            .tool
            .as_ref()
            .map(|t| t.name.as_str())
            .unwrap_or("-");
        println!(
            "{:<30} {:<10} {:<10} {:<30} {:<8}",
            sid,
            skill.manifest.manifest.version,
            skill.manifest.manifest.host_abi,
            tool_name,
            if enabled { "yes" } else { "no" },
        );
    }

    if !duplicate_issues.is_empty() {
        println!(
            "\nDuplicate skill IDs (runtime will skip): {}",
            duplicate_issues.len()
        );
        for skill_id in &duplicate_issues {
            println!("  - {skill_id}");
        }
    }
    if !duplicate_skipped.is_empty() {
        println!("\nSkipped duplicate skill IDs: {}", duplicate_skipped.len());
        for skill_id in &duplicate_skipped {
            println!("  - {skill_id}");
        }
    }

    if !reportable_errors.is_empty() {
        println!("\nLoad errors: {}", reportable_errors.len());
        for summary in &reportable_errors {
            println!("  - {summary}");
        }
        if !skipped_disabled_errors.is_empty() {
            println!(
                "Skipped disabled-skill load errors: {}",
                skipped_disabled_errors.len()
            );
            for skipped in &skipped_disabled_errors {
                println!("  - {skipped}");
            }
        }
        return Err(anyhow::anyhow!(
            "skill list found {} load error(s)",
            reportable_errors.len()
        ));
    }

    if !duplicate_issues.is_empty() {
        return Err(anyhow::anyhow!(
            "skill list found {} duplicate skill_id issue(s)",
            duplicate_issues.len()
        ));
    }

    if !skipped_disabled_errors.is_empty() {
        println!(
            "\nSkipped disabled-skill load errors: {}",
            skipped_disabled_errors.len()
        );
        for skipped in &skipped_disabled_errors {
            println!("  - {skipped}");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = expand_tilde(&cli.config);

    match cli.command {
        Commands::Serve => {
            serve::run_serve(&config_path).await?;
        }
        Commands::Setup {
            profile,
            acme_domain,
            acme_email,
            tls_cert_path,
            tls_key_path,
        } => {
            let options = setup::SetupOptions {
                profile,
                acme_domain: acme_domain.as_deref(),
                acme_email: acme_email.as_deref(),
                tls_cert_path: tls_cert_path.as_deref(),
                tls_key_path: tls_key_path.as_deref(),
            };
            setup::run_setup(&config_path, options)?;
        }
        Commands::Status => {
            let info = status::collect_status(&config_path);
            status::print_status(&info).await;
        }
        Commands::Config { action } => match action {
            ConfigAction::Get { key } => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                let json = serde_json::to_value(&config)
                    .map_err(|e| anyhow::anyhow!("serialization error: {e}"))?;
                let parts: Vec<&str> = key.split('.').collect();
                let mut current = &json;
                for part in &parts {
                    current = current.get(part).unwrap_or(&serde_json::Value::Null);
                }
                println!("{}", serde_json::to_string_pretty(current)?);
            }
            ConfigAction::Set { key, value } => {
                run_config_set(&config_path, &key, &value)?;
            }
        },
        Commands::Security { action } => match action {
            SecurityAction::Audit { verify_chain } => {
                if verify_chain {
                    println!("Verifying audit log hash chain...");
                    let result = verify_audit_chain(&config_path)?;
                    if result.valid {
                        println!("Audit chain: VALID");
                    } else {
                        println!("Audit chain: INVALID ({} errors found)", result.error_count);
                        for id in &result.error_entry_ids {
                            println!("  Entry {id}: hash mismatch");
                        }
                        return Err(anyhow::anyhow!(
                            "audit chain verification failed ({} errors)",
                            result.error_count
                        ));
                    }
                } else {
                    println!("Run with --verify-chain to verify the audit log integrity.");
                }
            }
        },
        Commands::Models { action } => match action {
            ModelsAction::List => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                print_models_list(&config);
            }
            ModelsAction::Download { name } => {
                run_models_download(&config_path, &name)?;
            }
            ModelsAction::Info { name } => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                print_model_info(&config, &name);
            }
        },
        Commands::Backup { action } => {
            let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
            let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;

            let backup_dir = config.storage.backup_dir.clone().unwrap_or_else(|| {
                config
                    .storage
                    .db_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("backups")
            });

            let make_manager = |enc: Option<Box<dyn encmind_core::traits::EncryptionAdapter>>| {
                encmind_storage::backup::BackupManager::new(
                    pool.clone(),
                    backup_dir.clone(),
                    enc,
                    config.backup.retention.clone(),
                )
            };

            match action {
                BackupAction::Now => {
                    let enc: Option<Box<dyn encmind_core::traits::EncryptionAdapter>> =
                        if config.backup.encryption {
                            let key = derive_backup_key(&config).await?;
                            Some(Box::new(
                                encmind_storage::encryption::Aes256GcmAdapter::new(&key),
                            ))
                        } else {
                            None
                        };
                    let mgr = make_manager(enc)?;
                    let info = mgr.create_backup()?;
                    println!("Backup created: {}", info.id);
                    println!("  File: {}", info.filename);
                    println!("  Size: {} bytes", info.size_bytes);
                    println!("  Encrypted: {}", info.encrypted);
                    let deleted = mgr.apply_retention().map_err(|e| {
                        anyhow::anyhow!(
                            "backup '{}' created but retention cleanup failed: {e}",
                            info.id
                        )
                    })?;
                    if deleted > 0 {
                        println!("  Retention: {deleted} old backup(s) removed");
                    }
                }
                BackupAction::List => {
                    let mgr = make_manager(None)?;
                    let backups = mgr.list_backups()?;
                    if backups.is_empty() {
                        println!("No backups found.");
                    } else {
                        println!("{:<30} {:>12} {:>10}", "ID", "SIZE", "ENCRYPTED");
                        for b in &backups {
                            println!(
                                "{:<30} {:>9} KB {:>10}",
                                b.id,
                                b.size_bytes.div_ceil(1024), // round up so sub-1K files show 1 KB
                                if b.encrypted { "yes" } else { "no" }
                            );
                        }
                    }
                }
                BackupAction::Restore { backup_id } => {
                    // Probe for the backup metadata first so we know whether
                    // we need to derive an encryption key.
                    let probe_mgr = make_manager(None)?;
                    let backup = probe_mgr
                        .list_backups()?
                        .into_iter()
                        .find(|b| b.id == backup_id)
                        .ok_or_else(|| anyhow::anyhow!("backup not found: {backup_id}"))?;
                    let enc: Option<Box<dyn encmind_core::traits::EncryptionAdapter>> =
                        if backup.encrypted {
                            let key = derive_backup_key(&config).await?;
                            Some(Box::new(
                                encmind_storage::encryption::Aes256GcmAdapter::new(&key),
                            ))
                        } else {
                            None
                        };
                    // Drop all pool connections before overwriting the database file.
                    drop(probe_mgr);
                    drop(pool);
                    println!("WARNING: The server must be stopped before restoring a backup.");
                    println!(
                        "Restoring backup '{backup_id}' to {:?}...",
                        config.storage.db_path
                    );
                    encmind_storage::backup::restore_backup_file(
                        &backup_dir,
                        &backup_id,
                        &config.storage.db_path,
                        enc.as_deref(),
                    )?;
                    println!("Restore complete. You may now start the server.");
                }
            }
        }
        Commands::Keys { action } => match action {
            KeysAction::Rotate => {
                run_keys_rotate(&config_path).await?;
            }
            KeysAction::Status => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                print_key_status(&config);
            }
        },
        Commands::Memory { action } => match action {
            MemoryAction::Status => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                if !config.memory.enabled {
                    println!("Memory is disabled. Enable it in config.yaml under memory.enabled.");
                } else {
                    println!("Memory: enabled");
                    println!("  Model: {}", config.memory.model_name);
                    println!("  Dimensions: {}", config.memory.embedding_dimensions);
                    println!(
                        "  Max context memories: {}",
                        config.memory.max_context_memories
                    );
                    println!("  Embedding mode: {:?}", config.memory.embedding_mode);
                }
            }
            MemoryAction::Rebuild => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                if !config.memory.enabled {
                    return Err(anyhow::anyhow!(
                        "Memory is disabled. Enable it in config.yaml under memory.enabled."
                    ));
                }

                let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
                {
                    let conn = pool.get()?;
                    encmind_storage::migrations::run_migrations(&conn)?;
                }

                let mode_enforcer = encmind_memory::embedding_mode::EmbeddingModeEnforcer::new(
                    config.memory.embedding_mode.clone(),
                );
                if let Err(e) = mode_enforcer
                    .verify_firewall_consistency(&config.security.egress_firewall.global_allowlist)
                {
                    return Err(anyhow::anyhow!(
                        "memory rebuild failed: invalid firewall/embedding mode combination: {e}"
                    ));
                }

                let embedder: std::sync::Arc<dyn encmind_core::traits::Embedder> =
                    mode_enforcer.create_embedder(&config.memory).map_err(|e| {
                        anyhow::anyhow!("memory rebuild failed: cannot create embedder: {e}")
                    })?;

                let vector_store: std::sync::Arc<dyn encmind_core::traits::VectorStore> =
                    std::sync::Arc::new(encmind_memory::vector_store::SqliteVectorStore::new(
                        pool.clone(),
                    ));

                let metadata_store: std::sync::Arc<dyn encmind_core::traits::MemoryMetadataStore> =
                    std::sync::Arc::new(
                        encmind_storage::memory_metadata::SqliteMemoryMetadataStore::new(
                            pool.clone(),
                        ),
                    );

                let memory_store = encmind_memory::memory_store::MemoryStoreImpl::new(
                    embedder,
                    vector_store,
                    metadata_store,
                );

                println!("Rebuilding memory vectors...");
                let stats = memory_store.rebuild().await?;
                println!(
                    "Rebuilt {}/{} entries ({} failures)",
                    stats.succeeded, stats.total, stats.failed
                );
                if stats.failed > 0 {
                    return Err(anyhow::anyhow!(
                        "memory rebuild completed with {} failed entr{}",
                        stats.failed,
                        if stats.failed == 1 { "y" } else { "ies" }
                    ));
                }
            }
            MemoryAction::Search { query } => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                if !config.memory.enabled {
                    println!("Memory is disabled. Enable it in config.yaml under memory.enabled.");
                } else {
                    println!("Searching memory for: {query}");
                    println!("Note: CLI memory search requires a running server. Use the gateway API for full search.");
                }
            }
            MemoryAction::Eval { eval_set } => {
                let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
                if !config.memory.enabled {
                    println!("Memory is disabled. Enable it in config.yaml under memory.enabled.");
                } else {
                    match eval_set {
                        Some(path) => {
                            println!("Running retrieval quality evaluation with eval set: {path}");
                            let mut gate =
                                encmind_memory::quality_gate::RetrievalQualityGate::new(0.5, 0.7);
                            match gate.load_eval_set(std::path::Path::new(&path)) {
                                Ok(()) => {
                                    println!("Loaded {} evaluation examples.", gate.eval_set_len());
                                    println!("Note: full evaluation requires a running memory store. Use the gateway API.");
                                }
                                Err(e) => {
                                    println!("Failed to load eval set: {e}");
                                }
                            }
                        }
                        None => {
                            println!("No eval set provided. Use --eval-set <path> to specify a JSON evaluation file.");
                        }
                    }
                }
            }
        },
        Commands::Skill { action } => match action {
            SkillAction::Doctor => {
                run_skill_doctor(&config_path).await?;
            }
            SkillAction::Install { source, no_prune } => {
                run_skill_install(&config_path, &source, !no_prune).await?;
            }
            SkillAction::Remove { skill_id, force } => {
                run_skill_remove(&config_path, &skill_id, force).await?;
            }
            SkillAction::List => {
                run_skill_list(&config_path).await?;
            }
        },
        Commands::Workflow { action } => {
            let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
            let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
            {
                let conn = pool.get()?;
                encmind_storage::migrations::run_migrations(&conn)?;
            }
            let store = encmind_storage::workflow_store::SqliteWorkflowStore::new(pool);

            match action {
                WorkflowAction::List => {
                    let runs = workflow_list_active_runs(&store).await?;
                    print!("{}", render_workflow_list(&runs));
                }
                WorkflowAction::Show { run_id } => match workflow_get_run(&store, &run_id).await? {
                    Some(run) => {
                        print!("{}", render_workflow_show(&run));
                    }
                    None => {
                        println!("Workflow run '{run_id}' not found.");
                    }
                },
                WorkflowAction::Cancel { run_id } => {
                    let cancelled = workflow_cancel_running_run(&store, &run_id).await?;
                    print!("{}", render_workflow_cancel(&run_id, cancelled));
                }
            }
        }
        Commands::Channel { action } => {
            let config = encmind_core::config::load_config(std::path::Path::new(&config_path))?;
            let tee = encmind_tee::detect_tee();
            let abs_db_path = resolve_absolute_db_path(&config.storage.db_path);
            let data_dir = abs_db_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/"));
            let key = encmind_storage::key_derivation::derive_key(
                &config.storage.key_source,
                tee.as_ref(),
                data_dir,
            )
            .await?;
            let pool = encmind_storage::pool::create_pool(&config.storage.db_path)?;
            {
                let conn = pool.get()?;
                encmind_storage::migrations::run_migrations(&conn)?;
            }
            let enc = std::sync::Arc::new(encmind_storage::encryption::Aes256GcmAdapter::new(&key));
            let store = encmind_storage::channel_account_store::SqliteChannelAccountStore::new(
                pool.clone(),
                enc,
            );
            use encmind_core::traits::ChannelAccountStore;
            match action {
                ChannelAction::List => {
                    let accounts = store.list_accounts().await?;
                    if accounts.is_empty() {
                        println!("No channel accounts configured.");
                    } else {
                        println!(
                            "{:<28} {:<12} {:<16} {:<10}",
                            "ID", "TYPE", "LABEL", "STATUS"
                        );
                        for a in &accounts {
                            println!(
                                "{:<28} {:<12} {:<16} {:<10}",
                                a.id.as_str(),
                                a.channel_type,
                                a.label,
                                format!("{:?}", a.status).to_lowercase(),
                            );
                        }
                    }
                }
                ChannelAction::Add {
                    channel_type,
                    label,
                } => {
                    ensure_supported_channel_type(&channel_type)?;
                    let label = label.unwrap_or_else(|| channel_type.clone());
                    let account = encmind_core::types::ChannelAccount {
                        id: encmind_core::types::ChannelAccountId::new(),
                        channel_type: channel_type.clone(),
                        label: label.clone(),
                        enabled: true,
                        status: encmind_core::types::ChannelAccountStatus::Stopped,
                        config_source: encmind_core::types::ConfigSource::Api,
                        policy: None,
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                    };
                    store.create_account(&account).await?;
                    println!(
                        "Created channel account: id={} type={} label={}",
                        account.id.as_str(),
                        channel_type,
                        label,
                    );
                }
                ChannelAction::Remove { id } => {
                    let account_id = encmind_core::types::ChannelAccountId::from_string(&id);
                    match store.get_account(&account_id).await? {
                        Some(account) => {
                            match gateway_rpc_call(
                                &config,
                                "channels.remove",
                                serde_json::json!({ "id": account.id.as_str() }),
                            )
                            .await
                            {
                                Ok(_) => {
                                    println!("Removed channel account: {}", account.id.as_str());
                                }
                                Err(e) if is_gateway_unreachable_error(&e) => {
                                    store.delete_account(&account_id).await?;
                                    println!(
                                        "Removed channel account: {id} (store only; gateway unavailable)"
                                    );
                                }
                                Err(e) => return Err(anyhow::anyhow!(e)),
                            }
                        }
                        None => {
                            println!("Account not found: {id}");
                        }
                    }
                }
                ChannelAction::Login {
                    id_or_type,
                    bot_token,
                    app_token,
                    client_id,
                    client_secret,
                    refresh_token,
                } => {
                    let provided_any = bot_token.is_some()
                        || app_token.is_some()
                        || client_id.is_some()
                        || client_secret.is_some()
                        || refresh_token.is_some();
                    let account = resolve_channel_account(&store, &id_or_type).await?;
                    ensure_supported_channel_type(&account.channel_type)?;
                    let mut incoming_cred = serde_json::Map::new();
                    if let Some(bt) = bot_token {
                        incoming_cred.insert("bot_token".into(), serde_json::Value::String(bt));
                    }
                    if let Some(at) = app_token {
                        incoming_cred.insert("app_token".into(), serde_json::Value::String(at));
                    }
                    if let Some(ci) = client_id {
                        incoming_cred.insert("client_id".into(), serde_json::Value::String(ci));
                    }
                    if let Some(cs) = client_secret {
                        incoming_cred.insert("client_secret".into(), serde_json::Value::String(cs));
                    }
                    if let Some(rt) = refresh_token {
                        incoming_cred.insert("refresh_token".into(), serde_json::Value::String(rt));
                    }
                    let existing = store.get_credential(&account.id).await?;
                    if !provided_any && existing.is_none() {
                        return Err(anyhow::anyhow!(
                            "at least one credential flag is required (--bot-token, --app-token, --client-id, --client-secret, --refresh-token) on first login"
                        ));
                    }
                    let merged = merge_and_validate_channel_credentials(
                        &account.channel_type,
                        existing.as_deref(),
                        incoming_cred,
                    )
                    .map_err(anyhow::Error::msg)?;
                    let cred_json = serde_json::to_string(&merged)?;
                    store.store_credential(&account.id, &cred_json).await?;
                    println!(
                        "Credentials stored: id={} type={}",
                        account.id.as_str(),
                        account.channel_type,
                    );
                    let mut rpc_params = merged.clone();
                    rpc_params.insert(
                        "id".into(),
                        serde_json::Value::String(account.id.as_str().to_string()),
                    );
                    // Attempt live activation via gateway RPC.
                    attempt_gateway_rpc(
                        &config,
                        "channels.login",
                        serde_json::Value::Object(rpc_params),
                        "Adapter activated",
                    )
                    .await;
                }
                ChannelAction::Logout { id_or_type } => {
                    let account = resolve_channel_account(&store, &id_or_type).await?;
                    // Attempt live deactivation first. If gateway is reachable but rejects
                    // logout, do not delete persisted credentials.
                    match gateway_rpc_call(
                        &config,
                        "channels.logout",
                        serde_json::json!({ "id": account.id.as_str() }),
                    )
                    .await
                    {
                        Ok(_) => println!("  Adapter deactivated"),
                        Err(e) if is_gateway_unreachable_error(&e) => println!("  {e}"),
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "gateway logout failed: {e}; credentials were not deleted"
                            ))
                        }
                    }
                    store.delete_credential(&account.id).await?;
                    println!(
                        "Credentials deleted: id={} type={}",
                        account.id.as_str(),
                        account.channel_type,
                    );
                }
                ChannelAction::Status { id_or_type, probe } => {
                    if let Some(ref id_or_type) = id_or_type {
                        let account = resolve_channel_account(&store, id_or_type).await?;
                        println!("ID:      {}", account.id.as_str());
                        println!("Type:    {}", account.channel_type);
                        println!("Label:   {}", account.label);
                        println!(
                            "Status:  {}",
                            format!("{:?}", account.status).to_lowercase()
                        );
                        println!("Enabled: {}", account.enabled);
                        if probe {
                            match gateway_rpc_call(
                                &config,
                                "channels.status",
                                serde_json::json!({
                                    "id": account.id.as_str(),
                                    "probe": true
                                }),
                            )
                            .await
                            {
                                Ok(result) => {
                                    if let Some(status) =
                                        result.get("status").and_then(|v| v.as_str())
                                    {
                                        println!("Runtime status: {status}");
                                    }
                                    if let Some(running) =
                                        result.get("running").and_then(|v| v.as_bool())
                                    {
                                        println!("Running: {}", if running { "yes" } else { "no" });
                                    }
                                    if let Some(probe_obj) = result.get("probe") {
                                        let ok = probe_obj
                                            .get("ok")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(false);
                                        if ok {
                                            println!("Probe:   ok");
                                        } else {
                                            let err = probe_obj
                                                .get("error")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("probe failed");
                                            println!("Probe:   failed ({err})");
                                        }
                                    } else {
                                        println!("Probe:   no probe detail returned by gateway");
                                    }
                                }
                                Err(e) => {
                                    println!("Probe:   {e}");
                                }
                            }
                        }
                    } else {
                        // No ID → list all
                        let accounts = store.list_accounts().await?;
                        if accounts.is_empty() {
                            println!("No channel accounts configured.");
                        } else {
                            println!(
                                "{:<28} {:<12} {:<16} {:<10}",
                                "ID", "TYPE", "LABEL", "STATUS"
                            );
                            for a in &accounts {
                                println!(
                                    "{:<28} {:<12} {:<16} {:<10}",
                                    a.id.as_str(),
                                    a.channel_type,
                                    a.label,
                                    format!("{:?}", a.status).to_lowercase(),
                                );
                            }
                        }
                        if probe {
                            println!(
                                "Probe:   specify an account ID/type to run connectivity probe"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Print a table of configured API providers.
fn print_models_list(config: &encmind_core::config::AppConfig) {
    if config.llm.api_providers.is_empty() {
        println!(
            "No API providers configured. Add providers in config.yaml under llm.api_providers."
        );
        return;
    }
    println!("Configured API Providers:");
    println!("{:<14} {:<22} BASE URL", "NAME", "MODEL");
    for p in &config.llm.api_providers {
        let base_url = p.base_url.as_deref().unwrap_or("(default)");
        println!("{:<14} {:<22} {}", p.name, p.model, base_url);
    }
}

/// Print details for a single named API provider.
fn print_model_info(config: &encmind_core::config::AppConfig, name: &str) {
    match config.llm.api_providers.iter().find(|p| p.name == name) {
        Some(p) => {
            println!("Provider: {}", p.name);
            println!("  Model:    {}", p.model);
            println!(
                "  Base URL: {}",
                p.base_url.as_deref().unwrap_or("(default)")
            );
        }
        None => {
            println!("Provider not found: {name}");
        }
    }
}

/// Print key/env-var status for the current configuration.
fn print_key_status(config: &encmind_core::config::AppConfig) {
    let passphrase_set = std::env::var("ENCMIND_PASSPHRASE").is_ok();
    println!(
        "  ENCMIND_PASSPHRASE:    {}",
        if passphrase_set {
            "SET"
        } else {
            "NOT SET (required)"
        }
    );
    for p in &config.llm.api_providers {
        let env_var = format!("{}_API_KEY", p.name.to_uppercase());
        let is_set = std::env::var(&env_var).is_ok();
        println!(
            "  {:22} {}",
            format!("{env_var}:"),
            if is_set { "SET" } else { "NOT SET" }
        );
    }
    println!("  Inference mode:        {:?}", config.llm.mode);
}

fn ensure_supported_channel_type(channel_type: &str) -> anyhow::Result<()> {
    if is_supported_channel_type(channel_type) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("unsupported channel_type: {channel_type}"))
    }
}

/// Build candidate base URLs for gateway RPC probing.
fn build_gateway_rpc_base_urls(config: &encmind_core::config::AppConfig) -> Vec<String> {
    let host = crate::status::normalize_probe_host_pub(&config.server.host);
    let port = config.server.port;

    let tls_configured = config.server.auto_tls
        || config.server.tls_cert_path.is_some()
        || config.server.tls_key_path.is_some();

    let schemes: Vec<&str> = if tls_configured {
        vec!["https", "http"]
    } else {
        vec!["http"]
    };

    schemes
        .into_iter()
        .map(|scheme| format!("{scheme}://{host}:{port}"))
        .collect()
}

async fn gateway_rpc_call(
    config: &encmind_core::config::AppConfig,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let base_urls = build_gateway_rpc_base_urls(config);
    if base_urls.is_empty() {
        return Err("gateway client could not be built from current config".to_string());
    }

    let timeout = std::time::Duration::from_secs(5);
    let http_client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to build gateway client: {e}"))?;
    let allow_insecure_https = should_allow_insecure_https_for_urls(&base_urls);
    let https_client = if base_urls.iter().any(|u| u.starts_with("https://")) {
        let mut builder = reqwest::Client::builder().timeout(timeout);
        if allow_insecure_https {
            // Allow self-signed certs only for loopback RPC targets.
            builder = builder.danger_accept_invalid_certs(true);
        }
        Some(
            builder
                .build()
                .map_err(|e| format!("failed to build gateway TLS client: {e}"))?,
        )
    } else {
        None
    };

    let body = serde_json::json!({ "method": method, "params": params });
    let mut last_transport_error: Option<String> = None;

    for base_url in base_urls {
        let client = if base_url.starts_with("https://") {
            match https_client.as_ref() {
                Some(c) => c,
                None => {
                    last_transport_error =
                        Some("gateway TLS client unavailable for HTTPS probe".to_string());
                    continue;
                }
            }
        } else {
            &http_client
        };

        let url = format!("{base_url}/rpc");
        let resp = match client.post(&url).json(&body).send().await {
            Ok(resp) => resp,
            Err(e) => {
                last_transport_error = Some(e.to_string());
                continue;
            }
        };

        if !resp.status().is_success() {
            return Err(format!("gateway returned HTTP {}", resp.status()));
        }

        let json = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e| format!("failed to parse gateway response JSON: {e}"))?;

        if json.get("type").and_then(|v| v.as_str()) == Some("error") {
            let message = json
                .get("error")
                .and_then(|v| v.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("gateway RPC error: {message}"));
        }

        if let Some(error_obj) = json.get("error") {
            let message = error_obj
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("gateway RPC error: {message}"));
        }

        if json.get("type").and_then(|v| v.as_str()) == Some("res") {
            return Ok(json
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null));
        }

        return Ok(json);
    }

    if let Some(last) = last_transport_error {
        Err(format!(
            "gateway not running; start the server for live adapter activation ({last})"
        ))
    } else {
        Err("gateway not running; start the server for live adapter activation".to_string())
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.trim().trim_start_matches('[').trim_end_matches(']'),
        "127.0.0.1" | "::1" | "localhost"
    )
}

fn should_allow_insecure_https_for_urls(base_urls: &[String]) -> bool {
    let https_urls: Vec<&str> = base_urls
        .iter()
        .filter(|url| url.starts_with("https://"))
        .map(String::as_str)
        .collect();
    !https_urls.is_empty()
        && https_urls.iter().all(|url| {
            reqwest::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(is_loopback_host))
                .unwrap_or(false)
        })
}

/// Best-effort gateway RPC call. Prints result or a warning if the gateway
/// is unreachable.
async fn attempt_gateway_rpc(
    config: &encmind_core::config::AppConfig,
    method: &str,
    params: serde_json::Value,
    success_msg: &str,
) {
    match gateway_rpc_call(config, method, params).await {
        Ok(_) => println!("  {success_msg}"),
        Err(e) => println!("  {e}"),
    }
}

fn is_gateway_unreachable_error(err: &str) -> bool {
    err.contains("gateway not running") || err.contains("failed to build gateway client")
}

async fn resolve_channel_account(
    store: &encmind_storage::channel_account_store::SqliteChannelAccountStore,
    id_or_type: &str,
) -> anyhow::Result<encmind_core::types::ChannelAccount> {
    use encmind_core::traits::ChannelAccountStore;

    // Try ID first
    let account_id = encmind_core::types::ChannelAccountId::from_string(id_or_type);
    if let Some(a) = store.get_account(&account_id).await? {
        return Ok(a);
    }
    // Fall back to type lookup
    if let Some(a) = store.get_account_by_type(id_or_type).await? {
        return Ok(a);
    }
    Err(anyhow::anyhow!("channel account not found: {id_or_type}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn create_skill_tarball(
        source_dir: &std::path::Path,
        tarball_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let file = std::fs::File::create(tarball_path)?;
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for entry in std::fs::read_dir(source_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if ext != "wasm" && ext != "toml" {
                continue;
            }
            let Some(name) = path.file_name() else {
                continue;
            };
            builder.append_path_with_name(&path, name)?;
        }
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    #[test]
    fn cli_parses_serve() {
        let cli = Cli::try_parse_from(["encmind-core", "serve"]).unwrap();
        assert!(matches!(cli.command, Commands::Serve));
    }

    #[test]
    fn cli_parses_setup() {
        let cli = Cli::try_parse_from(["encmind-core", "setup"]).unwrap();
        match cli.command {
            Commands::Setup {
                profile,
                acme_domain,
                acme_email,
                tls_cert_path,
                tls_key_path,
            } => {
                assert_eq!(profile, setup::SetupProfile::Local);
                assert!(acme_domain.is_none());
                assert!(acme_email.is_none());
                assert!(tls_cert_path.is_none());
                assert!(tls_key_path.is_none());
            }
            _ => panic!("Expected Setup"),
        }
    }

    #[test]
    fn cli_parses_setup_with_remote_profile() {
        let cli = Cli::try_parse_from(["encmind-core", "setup", "--profile", "remote"]).unwrap();
        match cli.command {
            Commands::Setup { profile, .. } => assert_eq!(profile, setup::SetupProfile::Remote),
            _ => panic!("Expected Setup"),
        }
    }

    #[test]
    fn cli_parses_setup_with_domain_acme() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "setup",
            "--profile",
            "domain",
            "--acme-domain",
            "assistant.example.com",
            "--acme-email",
            "ops@example.com",
        ])
        .unwrap();
        match cli.command {
            Commands::Setup {
                profile,
                acme_domain,
                acme_email,
                ..
            } => {
                assert_eq!(profile, setup::SetupProfile::Domain);
                assert_eq!(acme_domain.as_deref(), Some("assistant.example.com"));
                assert_eq!(acme_email.as_deref(), Some("ops@example.com"));
            }
            _ => panic!("Expected Setup"),
        }
    }

    #[test]
    fn cli_rejects_orphan_acme_domain_flag() {
        let err = Cli::try_parse_from(["encmind-core", "setup", "--acme-domain", "example.com"])
            .err()
            .expect("orphan --acme-domain should fail");
        let msg = err.to_string();
        assert!(msg.contains("--acme-email"));
    }

    #[test]
    fn cli_rejects_mixed_acme_and_manual_tls_flags() {
        let err = Cli::try_parse_from([
            "encmind-core",
            "setup",
            "--profile",
            "domain",
            "--acme-domain",
            "assistant.example.com",
            "--acme-email",
            "ops@example.com",
            "--tls-cert-path",
            "/etc/ssl/cert.pem",
            "--tls-key-path",
            "/etc/ssl/key.pem",
        ])
        .err()
        .expect("mixed ACME and manual TLS flags should fail");
        let msg = err.to_string();
        assert!(msg.contains("cannot be used with"));
    }

    #[test]
    fn cli_rejects_unknown_setup_profile() {
        let err = Cli::try_parse_from(["encmind-core", "setup", "--profile", "invalid"])
            .err()
            .expect("invalid setup profile should fail");
        let msg = err.to_string();
        assert!(msg.contains("possible values"));
    }

    #[test]
    fn cli_parses_setup_with_domain_manual_tls() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "setup",
            "--profile",
            "domain",
            "--tls-cert-path",
            "/etc/ssl/cert.pem",
            "--tls-key-path",
            "/etc/ssl/key.pem",
        ])
        .unwrap();
        match cli.command {
            Commands::Setup {
                profile,
                tls_cert_path,
                tls_key_path,
                ..
            } => {
                assert_eq!(profile, setup::SetupProfile::Domain);
                assert_eq!(tls_cert_path.as_deref(), Some("/etc/ssl/cert.pem"));
                assert_eq!(tls_key_path.as_deref(), Some("/etc/ssl/key.pem"));
            }
            _ => panic!("Expected Setup"),
        }
    }

    #[test]
    fn cli_parses_status() {
        let cli = Cli::try_parse_from(["encmind-core", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn cli_parses_config_with_custom_path() {
        let cli = Cli::try_parse_from(["encmind-core", "--config", "/tmp/my-config.yaml", "serve"])
            .unwrap();
        assert_eq!(cli.config, "/tmp/my-config.yaml");
    }

    #[test]
    fn cli_parses_config_after_subcommand() {
        let cli = Cli::try_parse_from(["encmind-core", "serve", "--config", "/tmp/my-config.yaml"])
            .unwrap();
        assert_eq!(cli.config, "/tmp/my-config.yaml");
    }

    #[test]
    fn cli_default_config_path() {
        let cli = Cli::try_parse_from(["encmind-core", "serve"]).unwrap();
        assert_eq!(cli.config, "~/.encmind/config.yaml");
    }

    #[test]
    fn expand_tilde_works() {
        if std::env::var_os("HOME").is_some() {
            let expanded = expand_tilde("~/test/path");
            assert!(!expanded.starts_with("~"));
            assert!(expanded.ends_with("/test/path"));
        }
    }

    #[test]
    fn cli_parses_models_list() {
        let cli = Cli::try_parse_from(["encmind-core", "models", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Models {
                action: ModelsAction::List
            }
        ));
    }

    #[test]
    fn cli_parses_backup_now() {
        let cli = Cli::try_parse_from(["encmind-core", "backup", "now"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Backup {
                action: BackupAction::Now
            }
        ));
    }

    #[test]
    fn cli_parses_keys_rotate() {
        let cli = Cli::try_parse_from(["encmind-core", "keys", "rotate"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Keys {
                action: KeysAction::Rotate
            }
        ));
    }

    #[test]
    fn cli_parses_memory_search() {
        let cli = Cli::try_parse_from(["encmind-core", "memory", "search", "test query"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Memory {
                action: MemoryAction::Search { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_memory_eval() {
        let cli = Cli::try_parse_from(["encmind-core", "memory", "eval"]).unwrap();
        match cli.command {
            Commands::Memory {
                action: MemoryAction::Eval { eval_set },
            } => {
                assert!(eval_set.is_none());
            }
            _ => panic!("Expected Memory Eval"),
        }
    }

    #[test]
    fn cli_parses_memory_eval_with_eval_set() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "memory",
            "eval",
            "--eval-set",
            "/tmp/golden.json",
        ])
        .unwrap();
        match cli.command {
            Commands::Memory {
                action: MemoryAction::Eval { eval_set },
            } => {
                assert_eq!(eval_set, Some("/tmp/golden.json".to_string()));
            }
            _ => panic!("Expected Memory Eval with eval_set"),
        }
    }

    #[test]
    fn cli_parses_skill_doctor() {
        let cli = Cli::try_parse_from(["encmind-core", "skill", "doctor"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Skill {
                action: SkillAction::Doctor
            }
        ));
    }

    #[test]
    fn cli_parses_skill_install() {
        let cli =
            Cli::try_parse_from(["encmind-core", "skill", "install", "/tmp/my-skill"]).unwrap();
        match cli.command {
            Commands::Skill {
                action: SkillAction::Install { source, no_prune },
            } => {
                assert_eq!(source, "/tmp/my-skill");
                assert!(!no_prune);
            }
            _ => panic!("Expected Skill Install"),
        }
    }

    #[test]
    fn cli_parses_skill_install_no_prune() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "skill",
            "install",
            "/tmp/my-skill",
            "--no-prune",
        ])
        .unwrap();
        match cli.command {
            Commands::Skill {
                action: SkillAction::Install { source, no_prune },
            } => {
                assert_eq!(source, "/tmp/my-skill");
                assert!(no_prune);
            }
            _ => panic!("Expected Skill Install with --no-prune"),
        }
    }

    #[test]
    fn cli_parses_skill_remove() {
        let cli = Cli::try_parse_from(["encmind-core", "skill", "remove", "my-skill"]).unwrap();
        match cli.command {
            Commands::Skill {
                action: SkillAction::Remove { skill_id, force },
            } => {
                assert_eq!(skill_id, "my-skill");
                assert!(!force);
            }
            _ => panic!("Expected Skill Remove"),
        }
    }

    #[test]
    fn cli_parses_skill_remove_force() {
        let cli = Cli::try_parse_from(["encmind-core", "skill", "remove", "my-skill", "--force"])
            .unwrap();
        match cli.command {
            Commands::Skill {
                action: SkillAction::Remove { skill_id, force },
            } => {
                assert_eq!(skill_id, "my-skill");
                assert!(force);
            }
            _ => panic!("Expected Skill Remove with --force"),
        }
    }

    #[test]
    fn cli_parses_skill_list() {
        let cli = Cli::try_parse_from(["encmind-core", "skill", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Skill {
                action: SkillAction::List
            }
        ));
    }

    #[test]
    fn cli_parses_workflow_list() {
        let cli = Cli::try_parse_from(["encmind-core", "workflow", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Workflow {
                action: WorkflowAction::List
            }
        ));
    }

    #[test]
    fn format_workflow_step_with_total() {
        assert_eq!(super::format_workflow_step(3, Some(7)), "3/7");
    }

    #[test]
    fn format_workflow_step_without_total() {
        assert_eq!(super::format_workflow_step(5, None), "5");
    }

    #[test]
    fn render_workflow_list_output_includes_headers_and_rows() {
        let run = WorkflowRun {
            id: "r1".to_string(),
            workflow_name: "wf1".to_string(),
            agent_id: "main".to_string(),
            status: WorkflowRunStatus::Running,
            current_step: 1,
            total_steps: Some(3),
            error_detail: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:01Z".to_string(),
            completed_at: None,
        };
        let out = super::render_workflow_list(&[run]);
        assert!(out.contains("ID"));
        assert!(out.contains("WORKFLOW"));
        assert!(out.contains("r1"));
        assert!(out.contains("running"));
        assert!(out.contains("1 run(s) total."));
    }

    #[test]
    fn render_workflow_show_output_includes_fields() {
        let run = WorkflowRun {
            id: "r2".to_string(),
            workflow_name: "deploy".to_string(),
            agent_id: "ops".to_string(),
            status: WorkflowRunStatus::Failed,
            current_step: 2,
            total_steps: Some(4),
            error_detail: Some("boom".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:10:00Z".to_string(),
            completed_at: Some("2026-01-01T00:10:00Z".to_string()),
        };
        let out = super::render_workflow_show(&run);
        assert!(out.contains("ID:            r2"));
        assert!(out.contains("Status:        failed"));
        assert!(out.contains("Step:          2/4"));
        assert!(out.contains("Error:         boom"));
        assert!(out.contains("Completed:     2026-01-01T00:10:00Z"));
    }

    #[test]
    fn render_workflow_cancel_output_messages() {
        assert_eq!(
            super::render_workflow_cancel("abc", true),
            "Workflow run 'abc' cancelled.\n"
        );
        assert_eq!(
            super::render_workflow_cancel("abc", false),
            "Could not cancel 'abc' (not found or not running).\n"
        );
    }

    #[tokio::test]
    async fn workflow_list_helper_filters_non_running() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("workflow_list.db");
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
            conn.execute(
                "INSERT INTO workflow_runs (id, workflow_name, agent_id, status, current_step) VALUES ('r1','wf1','main','running',0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workflow_runs (id, workflow_name, agent_id, status, current_step) VALUES ('r2','wf2','main','completed',0)",
                [],
            )
            .unwrap();
        }
        let store = encmind_storage::workflow_store::SqliteWorkflowStore::new(pool);
        let runs = super::workflow_list_active_runs(&store).await.unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, "r1");
        assert_eq!(runs[0].status, WorkflowRunStatus::Running);
    }

    #[tokio::test]
    async fn workflow_get_helper_returns_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("workflow_get.db");
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
            conn.execute(
                "INSERT INTO workflow_runs (id, workflow_name, agent_id, status, current_step) VALUES ('r1','wf1','main','running',0)",
                [],
            )
            .unwrap();
        }
        let store = encmind_storage::workflow_store::SqliteWorkflowStore::new(pool);
        let run = super::workflow_get_run(&store, "r1").await.unwrap();
        assert!(run.is_some());
        assert_eq!(run.unwrap().workflow_name, "wf1");
    }

    #[tokio::test]
    async fn workflow_cancel_helper_only_cancels_running() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("workflow_cancel.db");
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
            conn.execute(
                "INSERT INTO workflow_runs (id, workflow_name, agent_id, status, current_step) VALUES ('r1','wf1','main','running',0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workflow_runs (id, workflow_name, agent_id, status, current_step) VALUES ('r2','wf2','main','completed',0)",
                [],
            )
            .unwrap();
        }
        let store = encmind_storage::workflow_store::SqliteWorkflowStore::new(pool);
        assert!(super::workflow_cancel_running_run(&store, "r1")
            .await
            .unwrap());
        assert!(!super::workflow_cancel_running_run(&store, "r2")
            .await
            .unwrap());
    }

    #[test]
    fn verify_chain_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");

        // Create DB and run migrations (which insert audit entries).
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        let conn = pool.get().unwrap();
        encmind_storage::migrations::run_migrations(&conn).unwrap();
        drop(conn);
        drop(pool);

        let yaml = format!("storage:\n  db_path: \"{}\"\n", db_path.display());
        std::fs::write(&config_path, &yaml).unwrap();

        let result = verify_audit_chain(config_path.to_str().unwrap()).unwrap();
        assert!(result.valid);
        assert_eq!(result.error_count, 0);
        assert!(result.error_entry_ids.is_empty());
    }

    #[test]
    fn verify_chain_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");

        // Create DB and run migrations.
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        let conn = pool.get().unwrap();
        encmind_storage::migrations::run_migrations(&conn).unwrap();
        drop(conn);

        // Insert audit entries so the chain has content to verify.
        let logger = encmind_storage::audit::AuditLogger::new(pool.clone());
        logger.append("test", "action1", None, None).unwrap();
        logger.append("test", "action2", None, None).unwrap();

        // Tamper with the second entry's prev_hash to break the chain.
        let conn = pool.get().unwrap();
        conn.execute(
            "UPDATE audit_log SET prev_hash = X'DEADBEEF' WHERE id = (SELECT MAX(id) FROM audit_log)",
            [],
        )
        .unwrap();
        drop(conn);
        drop(pool);

        let yaml = format!("storage:\n  db_path: \"{}\"\n", db_path.display());
        std::fs::write(&config_path, &yaml).unwrap();

        let result = verify_audit_chain(config_path.to_str().unwrap()).unwrap();
        assert!(!result.valid);
        assert!(result.error_count > 0);
        assert!(!result.error_entry_ids.is_empty());
    }

    #[tokio::test]
    async fn skill_doctor_returns_ok_when_only_disabled_skill_errors_exist() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        // Create a loader error: wasm exists but manifest is missing.
        std::fs::write(skills_dir.join("broken.wasm"), b"(module)").unwrap();

        // Prepare DB and mark the broken skill disabled via skills.toggle state.
        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let toggle_store = encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool);
        encmind_core::traits::SkillToggleStore::set_enabled(&toggle_store, "broken", false)
            .await
            .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let result = run_skill_doctor(config_path.to_str().unwrap()).await;
        assert!(
            result.is_ok(),
            "doctor should succeed when all loader errors are for disabled skills: {result:?}"
        );
    }

    #[tokio::test]
    async fn skill_doctor_reports_duplicate_skill_ids() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(skills_dir.join("one.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("one.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();
        std::fs::write(skills_dir.join("two.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("two.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_doctor(config_path.to_str().unwrap())
            .await
            .expect_err("doctor should fail when duplicate skill IDs are detected");
        assert!(
            err.to_string().contains("skill doctor found"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn skill_install_fails_when_no_installed_skill_validates() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        std::fs::write(source_dir.join("broken.wasm"), b"not-a-wasm-module").unwrap();
        std::fs::write(source_dir.join("broken.toml"), "not = [valid = toml").unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("failed to load/validate"));
    }

    #[tokio::test]
    async fn skill_install_accepts_manifest_name_different_from_filename() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        std::fs::write(
            source_dir.join("file-stem.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            source_dir.join("file-stem.toml"),
            r#"[skill]
name = "manifest-name"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        assert!(skills_dir.join("file-stem.wasm").exists());
        assert!(skills_dir.join("file-stem.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_replaces_existing_artifacts_when_skill_id_matches() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(skills_dir.join("existing.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("existing.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        std::fs::write(source_dir.join("incoming.wasm"), wasm).unwrap();
        std::fs::write(
            source_dir.join("incoming.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        assert!(!skills_dir.join("existing.wasm").exists());
        assert!(!skills_dir.join("existing.toml").exists());
        assert!(skills_dir.join("incoming.wasm").exists());
        assert!(skills_dir.join("incoming.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_prunes_malformed_and_orphan_artifacts_for_matching_skill() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;

        std::fs::write(skills_dir.join("legacy.wasm"), b"broken-wasm").unwrap();
        std::fs::write(
            skills_dir.join("legacy.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
tool = ["broken
"#,
        )
        .unwrap();
        std::fs::write(skills_dir.join("dup-skill.wasm"), b"orphaned-binary").unwrap();

        std::fs::write(source_dir.join("incoming.wasm"), wasm).unwrap();
        std::fs::write(
            source_dir.join("incoming.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        assert!(!skills_dir.join("legacy.wasm").exists());
        assert!(!skills_dir.join("legacy.toml").exists());
        assert!(!skills_dir.join("dup-skill.wasm").exists());
        assert!(skills_dir.join("incoming.wasm").exists());
        assert!(skills_dir.join("incoming.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_no_prune_keeps_matching_existing_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(skills_dir.join("existing.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("existing.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        std::fs::write(source_dir.join("incoming.wasm"), wasm).unwrap();
        std::fs::write(
            source_dir.join("incoming.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            false,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("duplicate skill_id"),
            "unexpected error: {err}"
        );

        assert!(skills_dir.join("existing.wasm").exists());
        assert!(skills_dir.join("existing.toml").exists());
        assert!(!skills_dir.join("incoming.wasm").exists());
        assert!(!skills_dir.join("incoming.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_tarball_prunes_matching_existing_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        let package_path = dir.path().join("dup-skill.tgz");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(skills_dir.join("existing.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("existing.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        std::fs::write(source_dir.join("incoming.wasm"), wasm).unwrap();
        std::fs::write(
            source_dir.join("incoming.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();
        create_skill_tarball(&source_dir, &package_path).unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_install(
            config_path.to_str().unwrap(),
            package_path.to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        assert!(!skills_dir.join("existing.wasm").exists());
        assert!(!skills_dir.join("existing.toml").exists());
        assert!(skills_dir.join("incoming.wasm").exists());
        assert!(skills_dir.join("incoming.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_tarball_no_prune_keeps_matching_existing_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        let package_path = dir.path().join("dup-skill.tgz");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(skills_dir.join("existing.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("existing.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        std::fs::write(source_dir.join("incoming.wasm"), wasm).unwrap();
        std::fs::write(
            source_dir.join("incoming.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();
        create_skill_tarball(&source_dir, &package_path).unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_install(
            config_path.to_str().unwrap(),
            package_path.to_str().unwrap(),
            false,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("duplicate skill_id"),
            "unexpected error: {err}"
        );

        assert!(skills_dir.join("existing.wasm").exists());
        assert!(skills_dir.join("existing.toml").exists());
        assert!(!skills_dir.join("incoming.wasm").exists());
        assert!(!skills_dir.join("incoming.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_tarball_prunes_malformed_and_orphan_artifacts_for_matching_skill() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        let package_path = dir.path().join("dup-skill.tgz");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;

        std::fs::write(skills_dir.join("legacy.wasm"), b"broken-wasm").unwrap();
        std::fs::write(
            skills_dir.join("legacy.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
tool = ["broken
"#,
        )
        .unwrap();
        std::fs::write(skills_dir.join("dup-skill.wasm"), b"orphaned-binary").unwrap();

        std::fs::write(source_dir.join("incoming.wasm"), wasm).unwrap();
        std::fs::write(
            source_dir.join("incoming.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();
        create_skill_tarball(&source_dir, &package_path).unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_install(
            config_path.to_str().unwrap(),
            package_path.to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        assert!(!skills_dir.join("legacy.wasm").exists());
        assert!(!skills_dir.join("legacy.toml").exists());
        assert!(!skills_dir.join("dup-skill.wasm").exists());
        assert!(skills_dir.join("incoming.wasm").exists());
        assert!(skills_dir.join("incoming.toml").exists());
    }

    #[tokio::test]
    async fn skill_remove_resolves_manifest_name_not_just_file_stem() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        std::fs::write(
            skills_dir.join("file-stem.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("file-stem.toml"),
            r#"[skill]
name = "manifest-name"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_remove(config_path.to_str().unwrap(), "manifest-name", true)
            .await
            .unwrap();

        assert!(!skills_dir.join("file-stem.wasm").exists());
        assert!(!skills_dir.join("file-stem.toml").exists());
    }

    #[tokio::test]
    async fn skill_remove_resolves_manifest_name_for_broken_wasm() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        std::fs::write(skills_dir.join("file-stem.wasm"), b"broken-wasm").unwrap();
        std::fs::write(
            skills_dir.join("file-stem.toml"),
            r#"[skill]
name = "manifest-name"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        run_skill_remove(config_path.to_str().unwrap(), "manifest-name", true)
            .await
            .unwrap();

        assert!(!skills_dir.join("file-stem.wasm").exists());
        assert!(!skills_dir.join("file-stem.toml").exists());
    }

    #[tokio::test]
    async fn skill_remove_cleans_runtime_state() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        std::fs::write(
            skills_dir.join("file-stem.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("file-stem.toml"),
            r#"[skill]
name = "manifest-name"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
            conn.execute(
                "INSERT INTO skill_toggle_state (skill_id, enabled, updated_at) VALUES (?1, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                ["manifest-name"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, 'config:foo', ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                (&"manifest-name", &br#"{"bar":1}"#.to_vec()),
            )
            .unwrap();
            conn.execute(
                "INSERT INTO skill_timers (id, skill_id, timer_name, interval_secs, export_fn, enabled, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                (&"manifest-name:heartbeat", &"manifest-name", &"heartbeat", &60i64, &"tick"),
            )
            .unwrap();
        }

        run_skill_remove(config_path.to_str().unwrap(), "manifest-name", true)
            .await
            .unwrap();

        let conn = pool.get().unwrap();
        let toggle_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_toggle_state WHERE skill_id = ?1",
                ["manifest-name"],
                |row| row.get(0),
            )
            .unwrap();
        let kv_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_kv WHERE skill_id = ?1",
                ["manifest-name"],
                |row| row.get(0),
            )
            .unwrap();
        let timer_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_timers WHERE skill_id = ?1",
                ["manifest-name"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(toggle_count, 0);
        assert_eq!(kv_count, 0);
        assert_eq!(timer_count, 0);
    }

    #[tokio::test]
    async fn skill_remove_rejects_invalid_skill_id() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "").unwrap();

        let result = run_skill_remove(config_path.to_str().unwrap(), "../bad", true).await;
        let err = result.expect_err("invalid skill_id should be rejected");
        assert!(
            err.to_string().contains("invalid skill_id"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn skill_remove_cleans_state_when_artifacts_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
            conn.execute(
                "INSERT INTO skill_toggle_state (skill_id, enabled, updated_at) VALUES (?1, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                ["missing-skill"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, 'config:foo', ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                (&"missing-skill", &br#"{"bar":1}"#.to_vec()),
            )
            .unwrap();
        }

        run_skill_remove(config_path.to_str().unwrap(), "missing-skill", true)
            .await
            .unwrap();

        let conn = pool.get().unwrap();
        let toggle_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_toggle_state WHERE skill_id = ?1",
                ["missing-skill"],
                |row| row.get(0),
            )
            .unwrap();
        let kv_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skill_kv WHERE skill_id = ?1",
                ["missing-skill"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(toggle_count, 0);
        assert_eq!(kv_count, 0);
    }

    #[tokio::test]
    async fn skill_install_rolls_back_when_any_installed_wasm_fails_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        std::fs::write(
            source_dir.join("good.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            source_dir.join("good.toml"),
            r#"[skill]
name = "good"
version = "1.0.0"
"#,
        )
        .unwrap();

        std::fs::write(source_dir.join("bad.wasm"), b"not-a-wasm-module").unwrap();
        std::fs::write(
            source_dir.join("bad.toml"),
            r#"[skill]
name = "bad"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("failed to load/validate"));
        assert!(!skills_dir.join("good.wasm").exists());
        assert!(!skills_dir.join("good.toml").exists());
        assert!(!skills_dir.join("bad.wasm").exists());
        assert!(!skills_dir.join("bad.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_rolls_back_when_policy_denies_skill() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        std::fs::write(
            source_dir.join("blocked.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            source_dir.join("blocked.toml"),
            r#"[skill]
name = "blocked-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\nplugin_policy:\n  deny_skills:\n    - blocked-skill\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("rejected during validation"));
        assert!(err.contains("blocked-skill"));
        assert!(!skills_dir.join("blocked.wasm").exists());
        assert!(!skills_dir.join("blocked.toml").exists());
    }

    #[tokio::test]
    async fn skill_install_rolls_back_when_third_party_validation_denies_skill() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        let source_dir = dir.path().join("source");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::create_dir_all(&source_dir).unwrap();

        std::fs::write(
            source_dir.join("blocked.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            source_dir.join("blocked.toml"),
            r#"[skill]
name = "blocked-third-party"
version = "1.0.0"

[capabilities]
exec_shell = true
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_install(
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("third-party capability validation failed"));
        assert!(!skills_dir.join("blocked.wasm").exists());
        assert!(!skills_dir.join("blocked.toml").exists());
    }

    #[tokio::test]
    async fn skill_list_errors_when_all_artifacts_fail_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        std::fs::write(skills_dir.join("broken.wasm"), b"not-a-wasm-module").unwrap();
        std::fs::write(
            skills_dir.join("broken.toml"),
            r#"[skill]
name = "broken"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_list(config_path.to_str().unwrap())
            .await
            .expect_err("list should fail when only broken artifacts exist");
        assert!(err.to_string().contains("skill list found"));
    }

    #[tokio::test]
    async fn skill_list_errors_when_partial_load_failures_exist() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        std::fs::write(
            skills_dir.join("good.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("good.toml"),
            r#"[skill]
name = "good"
version = "1.0.0"
"#,
        )
        .unwrap();

        std::fs::write(skills_dir.join("bad.wasm"), b"not-a-wasm-module").unwrap();
        std::fs::write(
            skills_dir.join("bad.toml"),
            r#"[skill]
name = "bad"
version = "1.0.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_list(config_path.to_str().unwrap())
            .await
            .expect_err("list should fail when any load errors exist");
        assert!(err.to_string().contains("skill list found"));
    }

    #[tokio::test]
    async fn skill_list_errors_when_duplicate_skill_ids_are_in_scope() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        let wasm = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(skills_dir.join("dup-a.wasm"), wasm).unwrap();
        std::fs::write(skills_dir.join("dup-b.wasm"), wasm).unwrap();
        std::fs::write(
            skills_dir.join("dup-a.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.0.0"
"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("dup-b.toml"),
            r#"[skill]
name = "dup-skill"
version = "1.1.0"
"#,
        )
        .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let err = run_skill_list(config_path.to_str().unwrap())
            .await
            .expect_err("list should fail when duplicate skill IDs are in scope");
        assert!(err.to_string().contains("duplicate skill_id issue"));
    }

    #[tokio::test]
    async fn skill_list_ignores_disabled_skill_load_errors_when_no_active_skills() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        // Broken skill artifact: missing manifest.
        std::fs::write(skills_dir.join("broken.wasm"), b"(module)").unwrap();

        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let toggle_store = encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool);
        encmind_core::traits::SkillToggleStore::set_enabled(&toggle_store, "broken", false)
            .await
            .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let result = run_skill_list(config_path.to_str().unwrap()).await;
        assert!(
            result.is_ok(),
            "list should succeed when all load errors are for disabled skills: {result:?}"
        );
    }

    #[tokio::test]
    async fn skill_list_ignores_disabled_skill_load_errors_with_active_skills_present() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let skills_dir = dir.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();

        std::fs::write(
            skills_dir.join("good.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("good.toml"),
            r#"[skill]
name = "good"
version = "1.0.0"
"#,
        )
        .unwrap();

        // Broken skill artifact: missing manifest.
        std::fs::write(skills_dir.join("broken.wasm"), b"(module)").unwrap();

        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let toggle_store = encmind_storage::skill_toggle_store::SqliteSkillToggleStore::new(pool);
        encmind_core::traits::SkillToggleStore::set_enabled(&toggle_store, "broken", false)
            .await
            .unwrap();

        let yaml = format!(
            "storage:\n  db_path: \"{}\"\nskills:\n  wasm_dir: \"{}\"\n",
            db_path.display(),
            skills_dir.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let result = run_skill_list(config_path.to_str().unwrap()).await;
        assert!(
            result.is_ok(),
            "list should succeed when only disabled skills have load errors: {result:?}"
        );
    }

    #[test]
    fn models_list_shows_configured_providers() {
        let mut config = encmind_core::config::AppConfig::default();
        config.llm.api_providers = vec![
            encmind_core::config::ApiProviderConfig {
                name: "anthropic".to_string(),
                model: "claude-3-opus".to_string(),
                base_url: Some("https://api.anthropic.com".to_string()),
            },
            encmind_core::config::ApiProviderConfig {
                name: "openai".to_string(),
                model: "gpt-4".to_string(),
                base_url: None,
            },
        ];
        // Should not panic; output goes to stdout.
        print_models_list(&config);
    }

    #[test]
    fn key_status_reports_env_var_absence() {
        let config = encmind_core::config::AppConfig::default();
        // Should not panic even when env vars are not set.
        print_key_status(&config);
    }

    #[test]
    fn cli_parses_channel_list() {
        let cli = Cli::try_parse_from(["encmind-core", "channel", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Channel {
                action: ChannelAction::List
            }
        ));
    }

    #[test]
    fn cli_parses_channel_add() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "channel",
            "add",
            "telegram",
            "--label",
            "MyBot",
        ])
        .unwrap();
        match cli.command {
            Commands::Channel {
                action:
                    ChannelAction::Add {
                        channel_type,
                        label,
                    },
            } => {
                assert_eq!(channel_type, "telegram");
                assert_eq!(label.as_deref(), Some("MyBot"));
            }
            _ => panic!("Expected Channel Add"),
        }
    }

    #[test]
    fn cli_parses_channel_remove() {
        let cli = Cli::try_parse_from(["encmind-core", "channel", "remove", "abc123"]).unwrap();
        match cli.command {
            Commands::Channel {
                action: ChannelAction::Remove { id },
            } => assert_eq!(id, "abc123"),
            _ => panic!("Expected Channel Remove"),
        }
    }

    #[test]
    fn cli_parses_channel_login() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "channel",
            "login",
            "telegram",
            "--bot-token",
            "tok123",
        ])
        .unwrap();
        match cli.command {
            Commands::Channel {
                action:
                    ChannelAction::Login {
                        id_or_type,
                        bot_token,
                        app_token,
                        ..
                    },
            } => {
                assert_eq!(id_or_type, "telegram");
                assert_eq!(bot_token.as_deref(), Some("tok123"));
                assert!(app_token.is_none());
            }
            _ => panic!("Expected Channel Login"),
        }
    }

    #[test]
    fn cli_parses_channel_logout() {
        let cli = Cli::try_parse_from(["encmind-core", "channel", "logout", "telegram"]).unwrap();
        match cli.command {
            Commands::Channel {
                action: ChannelAction::Logout { id_or_type },
            } => assert_eq!(id_or_type, "telegram"),
            _ => panic!("Expected Channel Logout"),
        }
    }

    #[test]
    fn cli_parses_channel_status() {
        let cli = Cli::try_parse_from(["encmind-core", "channel", "status", "telegram", "--probe"])
            .unwrap();
        match cli.command {
            Commands::Channel {
                action: ChannelAction::Status { id_or_type, probe },
            } => {
                assert_eq!(id_or_type.as_deref(), Some("telegram"));
                assert!(probe);
            }
            _ => panic!("Expected Channel Status"),
        }
    }

    #[test]
    fn ensure_supported_channel_type_accepts_builtin() {
        assert!(ensure_supported_channel_type("telegram").is_ok());
        assert!(ensure_supported_channel_type("slack").is_ok());
    }

    #[test]
    fn ensure_supported_channel_type_rejects_unknown() {
        let err = ensure_supported_channel_type("discord").unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported channel_type: discord"));
    }

    #[test]
    fn merge_channel_credentials_slack_preserves_existing_required_field() {
        let existing = r#"{"bot_token":"xoxb-old","app_token":"xapp-old"}"#;
        let mut incoming = serde_json::Map::new();
        incoming.insert(
            "bot_token".to_string(),
            serde_json::Value::String("xoxb-new".to_string()),
        );
        let merged =
            merge_and_validate_channel_credentials("slack", Some(existing), incoming).unwrap();
        assert_eq!(
            merged.get("bot_token").and_then(|v| v.as_str()),
            Some("xoxb-new")
        );
        assert_eq!(
            merged.get("app_token").and_then(|v| v.as_str()),
            Some("xapp-old")
        );
    }

    #[test]
    fn merge_channel_credentials_slack_requires_both_fields() {
        let mut incoming = serde_json::Map::new();
        incoming.insert(
            "bot_token".to_string(),
            serde_json::Value::String("xoxb-only".to_string()),
        );
        let err = merge_and_validate_channel_credentials("slack", None, incoming).unwrap_err();
        assert!(err
            .to_string()
            .contains("missing required credential field: app_token"));
    }

    #[test]
    fn merge_channel_credentials_telegram_requires_bot_token() {
        let incoming = serde_json::Map::new();
        let err = merge_and_validate_channel_credentials("telegram", None, incoming).unwrap_err();
        assert!(err
            .to_string()
            .contains("missing required credential field: bot_token"));
    }

    #[test]
    fn merge_channel_credentials_rejects_unexpected_field() {
        let mut incoming = serde_json::Map::new();
        incoming.insert(
            "bot_token".to_string(),
            serde_json::Value::String("token".to_string()),
        );
        incoming.insert(
            "extra".to_string(),
            serde_json::Value::String("value".to_string()),
        );
        let err = merge_and_validate_channel_credentials("telegram", None, incoming).unwrap_err();
        assert!(err
            .to_string()
            .contains("unexpected credential field: extra"));
    }

    #[test]
    fn build_gateway_rpc_base_urls_normalizes_wildcard_host() {
        let config = encmind_core::config::AppConfig {
            server: encmind_core::config::ServerConfig {
                host: "0.0.0.0".into(),
                port: 19999,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = build_gateway_rpc_base_urls(&config);
        assert!(!result.is_empty());
        let base_url = &result[0];
        assert!(
            base_url.contains("127.0.0.1"),
            "wildcard host should be normalized to 127.0.0.1"
        );
    }

    #[test]
    fn build_gateway_rpc_base_urls_prefers_https_with_http_fallback_when_tls_configured() {
        let config = encmind_core::config::AppConfig {
            server: encmind_core::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 8443,
                auto_tls: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let urls = build_gateway_rpc_base_urls(&config);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].starts_with("https://"));
        assert!(urls[1].starts_with("http://"));
    }

    #[test]
    fn is_loopback_host_recognizes_expected_values() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("10.0.0.5"));
    }

    #[test]
    fn should_allow_insecure_https_for_urls_rejects_empty_https_set() {
        let urls = vec!["http://127.0.0.1:8443".to_string()];
        assert!(!should_allow_insecure_https_for_urls(&urls));
    }

    #[test]
    fn should_allow_insecure_https_for_urls_accepts_loopback_https() {
        let urls = vec![
            "https://127.0.0.1:8443".to_string(),
            "http://127.0.0.1:8443".to_string(),
        ];
        assert!(should_allow_insecure_https_for_urls(&urls));
    }

    #[test]
    fn should_allow_insecure_https_for_urls_rejects_non_loopback_https() {
        let urls = vec!["https://10.0.0.5:8443".to_string()];
        assert!(!should_allow_insecure_https_for_urls(&urls));
    }

    #[tokio::test]
    async fn attempt_gateway_rpc_graceful_when_not_running() {
        let config = encmind_core::config::AppConfig {
            server: encmind_core::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 19999,
                ..Default::default()
            },
            ..Default::default()
        };
        // Should not panic — prints warning to stdout.
        attempt_gateway_rpc(
            &config,
            "channels.login",
            serde_json::json!({"id": "test"}),
            "Adapter activated",
        )
        .await;
    }

    #[tokio::test]
    async fn gateway_rpc_call_returns_error_when_gateway_unreachable() {
        let config = encmind_core::config::AppConfig {
            server: encmind_core::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 19999,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = gateway_rpc_call(&config, "channels.status", serde_json::json!({}))
            .await
            .expect_err("expected RPC call to fail when gateway is down");
        assert!(err.contains("gateway"));
    }

    #[test]
    fn config_set_updates_value_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let mut cfg = encmind_core::config::AppConfig::default();
        cfg.storage.db_path = dir.path().join("data.db");
        cfg.llm.api_providers = vec![encmind_core::config::ApiProviderConfig {
            name: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            base_url: None,
        }];
        std::fs::write(&config_path, serde_yml::to_string(&cfg).unwrap()).unwrap();

        run_config_set(config_path.to_str().unwrap(), "server.port", "9443").unwrap();

        let loaded = encmind_core::config::load_config(&config_path).unwrap();
        assert_eq!(loaded.server.port, 9443);
    }

    #[test]
    fn config_set_rolls_back_on_validation_failure() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let mut cfg = encmind_core::config::AppConfig::default();
        cfg.storage.db_path = dir.path().join("data.db");
        cfg.llm.api_providers = vec![encmind_core::config::ApiProviderConfig {
            name: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            base_url: None,
        }];
        std::fs::write(&config_path, serde_yml::to_string(&cfg).unwrap()).unwrap();

        let err = run_config_set(
            config_path.to_str().unwrap(),
            "server.public_webhooks.enabled",
            "true",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("rolled back"));

        let loaded = encmind_core::config::load_config(&config_path).unwrap();
        assert!(!loaded.server.public_webhooks.enabled);
    }

    #[test]
    fn models_download_sets_active_provider_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let mut cfg = encmind_core::config::AppConfig::default();
        cfg.storage.db_path = dir.path().join("data.db");
        cfg.llm.api_providers = vec![encmind_core::config::ApiProviderConfig {
            name: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            base_url: None,
        }];
        std::fs::write(&config_path, serde_yml::to_string(&cfg).unwrap()).unwrap();

        run_models_download(config_path.to_str().unwrap(), "openai").unwrap();

        let loaded = encmind_core::config::load_config(&config_path).unwrap();
        match loaded.llm.mode {
            encmind_core::config::InferenceMode::ApiProvider { provider } => {
                assert_eq!(provider, "openai");
            }
            other => panic!("expected api provider mode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keys_rotate_runs_key_check_and_writes_audit_event() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");
        let mut cfg = encmind_core::config::AppConfig::default();
        cfg.storage.db_path = db_path.clone();
        cfg.llm.api_providers = vec![encmind_core::config::ApiProviderConfig {
            name: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            base_url: None,
        }];
        cfg.storage.key_source = encmind_core::config::KeySource::EnvVar {
            var_name: "ENCMIND_TEST_ROTATE_KEY".to_string(),
        };
        std::fs::write(&config_path, serde_yml::to_string(&cfg).unwrap()).unwrap();
        std::env::set_var("ENCMIND_TEST_ROTATE_KEY", "aa".repeat(32));

        run_keys_rotate(config_path.to_str().unwrap())
            .await
            .unwrap();

        let pool = encmind_storage::pool::create_pool(&db_path).unwrap();
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'key_rotation.check'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        std::env::remove_var("ENCMIND_TEST_ROTATE_KEY");
        assert!(count >= 1, "expected at least one key rotation audit event");
    }

    #[test]
    fn cli_parses_channel_login_with_gmail_credentials() {
        let cli = Cli::try_parse_from([
            "encmind-core",
            "channel",
            "login",
            "gmail",
            "--client-id",
            "cid",
            "--client-secret",
            "csec",
            "--refresh-token",
            "rt",
        ])
        .unwrap();
        match cli.command {
            Commands::Channel {
                action:
                    ChannelAction::Login {
                        id_or_type,
                        client_id,
                        client_secret,
                        refresh_token,
                        ..
                    },
            } => {
                assert_eq!(id_or_type, "gmail");
                assert_eq!(client_id.as_deref(), Some("cid"));
                assert_eq!(client_secret.as_deref(), Some("csec"));
                assert_eq!(refresh_token.as_deref(), Some("rt"));
            }
            _ => panic!("expected Channel Login"),
        }
    }
}
