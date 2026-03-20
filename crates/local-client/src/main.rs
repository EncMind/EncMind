mod chat;
mod commands;
mod connect;
mod discover;
mod keystore;
mod known_hosts;
mod memory_cmd;
mod pair;
mod protocol;
mod sessions_cmd;
mod setup;
mod tls;
mod url_utils;

use clap::{Parser, Subcommand};
use std::io::Write;
use tls::is_tls_validation_error;
use url::Url;

use crate::chat::ChatOpts;
use crate::memory_cmd::MemorySubcmd;
use crate::sessions_cmd::SessionsSubcmd;

#[derive(Parser)]
#[command(name = "encmind-edge")]
#[command(about = "Local client for the EncMind gateway")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Gateway URL (e.g. wss://your-server:8443)
    #[arg(long, global = true)]
    pub gateway: Option<String>,

    /// Path to identity file
    #[arg(long, global = true)]
    pub identity: Option<String>,

    /// TLS certificate fingerprint for self-signed cert verification (SHA256:xx:yy:...)
    #[arg(long, global = true)]
    pub fingerprint: Option<String>,

    /// One-shot mode: send a message and print the response
    #[arg(short, global = true)]
    pub m: Option<String>,

    /// Resume an existing chat session
    #[arg(long, global = true)]
    pub session: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start an interactive chat session (default when no subcommand given)
    Chat {
        /// Resume an existing session by ID
        #[arg(long)]
        session: Option<String>,
        /// One-shot: send this message, print response, exit
        #[arg(short)]
        m: Option<String>,
    },
    /// Guided first-time setup (discover + pair). Use --gateway to skip discovery.
    Setup,
    /// Manage chat sessions
    Sessions {
        #[command(subcommand)]
        subcmd: Option<SessionsCommand>,
    },
    /// Memory / RAG operations
    Memory {
        #[command(subcommand)]
        subcmd: Option<MemoryCommand>,
    },
    /// Discover EncMind gateways on the local network
    Discover {
        /// Scan timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },
    /// Pair with a gateway
    Pair {
        /// Device name for this client
        #[arg(short, long, default_value = "bridge-client")]
        name: String,
    },
    /// Connect to a gateway as a node (command executor)
    Connect,
    /// Show edge client status
    Status,
    /// Show configuration
    Config,
}

#[derive(Subcommand)]
pub enum SessionsCommand {
    /// List all sessions (default)
    List,
    /// Delete a session
    Delete {
        /// Session ID
        id: String,
    },
    /// Rename a session
    Rename {
        /// Session ID
        id: String,
        /// New title
        title: String,
    },
}

#[derive(Subcommand)]
pub enum MemoryCommand {
    /// Show memory status (default)
    Status,
    /// Search memories
    Search {
        /// Search query
        query: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let cli = Cli::parse();
    let gateway_was_explicit = cli.gateway.is_some();
    let gateway = cli
        .gateway
        .clone()
        .unwrap_or_else(|| "ws://localhost:8443".to_string());

    // Determine effective command: no subcommand -> Chat (default action).
    let command = cli.command.unwrap_or(Command::Chat {
        session: cli.session.clone(),
        m: cli.m.clone(),
    });

    // Resolve fingerprint: CLI flag takes priority, then known_hosts.
    let mut fingerprint = resolve_initial_fingerprint(
        &command,
        &gateway,
        gateway_was_explicit,
        cli.fingerprint.as_deref(),
    )?;

    match command {
        Command::Chat { session, m } => {
            // Merge global -m / --session flags with subcommand-level ones.
            let effective_session = session.or(cli.session);
            let effective_m = m.or(cli.m);

            let first_attempt = chat::run_chat(ChatOpts {
                session: effective_session.as_deref(),
                one_shot: effective_m.as_deref(),
                gateway_url: &gateway,
                identity_path: cli.identity.as_deref(),
                fingerprint: fingerprint.as_deref(),
            })
            .await;

            match first_attempt {
                Ok(()) => {}
                Err(err) if should_offer_tofu_retry(fingerprint.is_some(), err.as_ref()) => {
                    let Some(fp) = prompt_for_tofu_fingerprint(&gateway).await? else {
                        return Err("TLS fingerprint not trusted; aborting".into());
                    };
                    fingerprint = Some(fp);
                    chat::run_chat(ChatOpts {
                        session: effective_session.as_deref(),
                        one_shot: effective_m.as_deref(),
                        gateway_url: &gateway,
                        identity_path: cli.identity.as_deref(),
                        fingerprint: fingerprint.as_deref(),
                    })
                    .await?;
                }
                Err(err) => return Err(err),
            }

            if let Some(ref fp) = fingerprint {
                persist_known_host(&gateway, fp);
            }
        }
        Command::Setup => {
            // If user explicitly passed --gateway, skip discovery and use it directly.
            let explicit_gateway = cli.gateway.as_deref();

            let first_attempt = setup::run_setup(
                explicit_gateway,
                cli.identity.as_deref(),
                fingerprint.as_deref(),
            )
            .await;

            let paired_gateway = match first_attempt {
                Ok(gateway) => gateway,
                Err(err) if should_offer_tofu_retry(fingerprint.is_some(), err.as_ref()) => {
                    let tofu_gateway =
                        setup_tofu_gateway_for_retry(err.as_ref(), &gateway).to_string();
                    let Some(fp) = prompt_for_tofu_fingerprint(&tofu_gateway).await? else {
                        return Err("TLS fingerprint not trusted; aborting".into());
                    };
                    fingerprint = Some(fp);
                    setup::run_setup(
                        Some(tofu_gateway.as_str()),
                        cli.identity.as_deref(),
                        fingerprint.as_deref(),
                    )
                    .await?
                }
                Err(err) => return Err(err),
            };

            if let Some(ref fp) = fingerprint {
                persist_known_host(&paired_gateway, fp);
            }
        }
        Command::Sessions { subcmd } => {
            let subcmd = match subcmd {
                Some(SessionsCommand::List) | None => SessionsSubcmd::List,
                Some(SessionsCommand::Delete { id }) => SessionsSubcmd::Delete { id },
                Some(SessionsCommand::Rename { id, title }) => SessionsSubcmd::Rename { id, title },
            };

            let first_attempt = sessions_cmd::run_sessions(
                subcmd.clone(),
                &gateway,
                cli.identity.as_deref(),
                fingerprint.as_deref(),
            )
            .await;

            match first_attempt {
                Ok(()) => {}
                Err(err) if should_offer_tofu_retry(fingerprint.is_some(), err.as_ref()) => {
                    let Some(fp) = prompt_for_tofu_fingerprint(&gateway).await? else {
                        return Err("TLS fingerprint not trusted; aborting".into());
                    };
                    fingerprint = Some(fp);
                    sessions_cmd::run_sessions(
                        subcmd,
                        &gateway,
                        cli.identity.as_deref(),
                        fingerprint.as_deref(),
                    )
                    .await?;
                }
                Err(err) => return Err(err),
            }

            if let Some(ref fp) = fingerprint {
                persist_known_host(&gateway, fp);
            }
        }
        Command::Memory { subcmd } => {
            let subcmd = match subcmd {
                Some(MemoryCommand::Status) | None => MemorySubcmd::Status,
                Some(MemoryCommand::Search { query }) => MemorySubcmd::Search { query },
            };

            let first_attempt = memory_cmd::run_memory(
                subcmd.clone(),
                &gateway,
                cli.identity.as_deref(),
                fingerprint.as_deref(),
            )
            .await;

            match first_attempt {
                Ok(()) => {}
                Err(err) if should_offer_tofu_retry(fingerprint.is_some(), err.as_ref()) => {
                    let Some(fp) = prompt_for_tofu_fingerprint(&gateway).await? else {
                        return Err("TLS fingerprint not trusted; aborting".into());
                    };
                    fingerprint = Some(fp);
                    memory_cmd::run_memory(
                        subcmd,
                        &gateway,
                        cli.identity.as_deref(),
                        fingerprint.as_deref(),
                    )
                    .await?;
                }
                Err(err) => return Err(err),
            }

            if let Some(ref fp) = fingerprint {
                persist_known_host(&gateway, fp);
            }
        }
        Command::Discover { timeout } => {
            discover::run_discover(timeout).await?;
        }
        Command::Pair { name } => {
            let first_attempt = pair::run_pair(
                &gateway,
                &name,
                cli.identity.as_deref(),
                fingerprint.as_deref(),
            )
            .await;

            match first_attempt {
                Ok(()) => {}
                Err(err) if should_offer_tofu_retry(fingerprint.is_some(), err.as_ref()) => {
                    let Some(fp) = prompt_for_tofu_fingerprint(&gateway).await? else {
                        return Err("TLS fingerprint not trusted; aborting".into());
                    };
                    pair::run_pair(&gateway, &name, cli.identity.as_deref(), Some(fp.as_str()))
                        .await?;
                    fingerprint = Some(fp);
                }
                Err(err) => return Err(err),
            }

            if let Some(ref fp) = fingerprint {
                persist_known_host(&gateway, fp);
            }
        }
        Command::Connect => {
            let first_attempt =
                connect::run_connect(&gateway, cli.identity.as_deref(), fingerprint.as_deref())
                    .await;

            match first_attempt {
                Ok(()) => {}
                Err(err) if should_offer_tofu_retry(fingerprint.is_some(), err.as_ref()) => {
                    let Some(fp) = prompt_for_tofu_fingerprint(&gateway).await? else {
                        return Err("TLS fingerprint not trusted; aborting".into());
                    };
                    connect::run_connect(&gateway, cli.identity.as_deref(), Some(fp.as_str()))
                        .await?;
                    fingerprint = Some(fp);
                }
                Err(err) => return Err(err),
            }

            if let Some(ref fp) = fingerprint {
                persist_known_host(&gateway, fp);
            }
        }
        Command::Status => {
            if !keystore::identity_exists(cli.identity.as_deref()) {
                return Err("Not set up yet. Run: encmind-edge setup".into());
            }
            let ks = match keystore::LocalKeystore::load_or_create(cli.identity.as_deref()) {
                Ok(ks) => ks,
                Err(e @ keystore::KeystoreError::Parse(_)) => {
                    return Err(format!(
                        "Identity file is corrupted: {e}. Delete it and re-run: encmind-edge setup"
                    )
                    .into());
                }
                Err(e @ keystore::KeystoreError::Io(_)) => {
                    return Err(format!(
                        "Cannot read identity file: {e}. Check path/permissions, or re-run: encmind-edge setup"
                    )
                    .into());
                }
            };
            println!("Device ID: {}", ks.device_id());
            println!("Identity file: {}", ks.path().display());
            println!("Gateway: {}", gateway);
            if let Some(fp) = fingerprint {
                println!("Fingerprint: {fp}");
            }
        }
        Command::Config => {
            println!("Config: gateway={}", gateway);
            if let Some(fp) = fingerprint {
                println!("Pinned fingerprint: {fp}");
            }
        }
    }

    Ok(())
}

/// Resolve the effective fingerprint: CLI flag takes priority, then known_hosts file.
fn resolve_fingerprint(
    gateway_url: &str,
    cli_fingerprint: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let tls_gateway = is_tls_gateway_url(gateway_url);
    if let Some(fp) = cli_fingerprint {
        if !tls_gateway {
            return Err("--fingerprint can only be used with wss:// or https:// gateways".into());
        }
        return Ok(Some(tls::normalize_fingerprint(fp)?));
    }
    if !tls_gateway {
        return Ok(None);
    }
    let hosts = known_hosts::KnownHosts::load();
    resolve_saved_fingerprint(gateway_url, hosts.get(gateway_url))
}

fn resolve_initial_fingerprint(
    command: &Command,
    gateway_url: &str,
    gateway_was_explicit: bool,
    cli_fingerprint: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // setup without explicit --gateway discovers host later, so allow --fingerprint
    // without validating against the default ws://localhost:8443 placeholder.
    if matches!(command, Command::Setup) && !gateway_was_explicit {
        return match cli_fingerprint {
            Some(fp) => Ok(Some(tls::normalize_fingerprint(fp)?)),
            None => Ok(None),
        };
    }
    resolve_fingerprint(gateway_url, cli_fingerprint)
}

fn resolve_saved_fingerprint(
    gateway_url: &str,
    saved: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(saved) = saved else {
        return Ok(None);
    };
    match tls::normalize_fingerprint(saved) {
        Ok(fp) => Ok(Some(fp)),
        Err(e) => {
            eprintln!("Warning: ignoring invalid pinned fingerprint for {gateway_url}: {e}");
            Ok(None)
        }
    }
}

fn persist_known_host(gateway_url: &str, fingerprint: &str) {
    if !is_tls_gateway_url(gateway_url) {
        return;
    }
    let mut hosts = known_hosts::KnownHosts::load();
    if let Err(e) = hosts.set(gateway_url, fingerprint) {
        eprintln!("Warning: failed to save fingerprint to known_hosts: {e}");
    }
}

fn is_tls_gateway_url(gateway_url: &str) -> bool {
    let Ok(url) = Url::parse(gateway_url) else {
        return false;
    };
    matches!(url.scheme(), "wss" | "https")
}

fn should_offer_tofu_retry(
    fingerprint_already_set: bool,
    err: &(dyn std::error::Error + 'static),
) -> bool {
    !fingerprint_already_set && is_tls_validation_error(err)
}

fn setup_tofu_gateway_for_retry<'a>(
    err: &'a (dyn std::error::Error + 'static),
    fallback_gateway: &'a str,
) -> &'a str {
    err.downcast_ref::<setup::SetupError>()
        .and_then(|e| e.tls_retry_gateway())
        .unwrap_or(fallback_gateway)
}

async fn prompt_for_tofu_fingerprint(
    gateway_url: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let fingerprint = tls::probe_server_fingerprint(gateway_url).await?;
    println!("First-time TLS connection to {gateway_url}");
    println!("Fingerprint: {fingerprint}");
    eprint!("Trust and pin this fingerprint? [y/N]: ");
    std::io::stderr().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trust = matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if trust {
        Ok(Some(fingerprint))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // --- No subcommand → Chat ---

    #[test]
    fn cli_no_subcommand_defaults_to_chat() {
        let cli = Cli::parse_from(["encmind-edge"]);
        assert!(cli.command.is_none()); // None → becomes Chat in main()
    }

    #[test]
    fn cli_no_subcommand_with_m_flag() {
        let cli = Cli::parse_from(["encmind-edge", "-m", "hello"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.m.as_deref(), Some("hello"));
    }

    #[test]
    fn cli_no_subcommand_with_session_flag() {
        let cli = Cli::parse_from(["encmind-edge", "--session", "01JN123"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.session.as_deref(), Some("01JN123"));
    }

    // --- Explicit chat subcommand ---

    #[test]
    fn cli_parses_chat() {
        let cli = Cli::parse_from(["encmind-edge", "chat"]);
        assert!(matches!(cli.command, Some(Command::Chat { .. })));
    }

    #[test]
    fn cli_parses_chat_with_m() {
        let cli = Cli::parse_from(["encmind-edge", "chat", "-m", "hello"]);
        match cli.command {
            Some(Command::Chat { m, .. }) => assert_eq!(m.as_deref(), Some("hello")),
            _ => panic!("Expected Chat"),
        }
    }

    #[test]
    fn cli_parses_chat_with_session() {
        let cli = Cli::parse_from(["encmind-edge", "chat", "--session", "01JN"]);
        match cli.command {
            Some(Command::Chat { session, .. }) => assert_eq!(session.as_deref(), Some("01JN")),
            _ => panic!("Expected Chat"),
        }
    }

    // --- Setup ---

    #[test]
    fn cli_parses_setup() {
        let cli = Cli::parse_from(["encmind-edge", "setup"]);
        assert!(matches!(cli.command, Some(Command::Setup)));
    }

    #[test]
    fn cli_parses_setup_with_gateway() {
        let cli = Cli::parse_from(["encmind-edge", "--gateway", "wss://host:8443", "setup"]);
        assert!(matches!(cli.command, Some(Command::Setup)));
        assert_eq!(cli.gateway.as_deref(), Some("wss://host:8443"));
    }

    // --- Sessions ---

    #[test]
    fn cli_parses_sessions_default_list() {
        let cli = Cli::parse_from(["encmind-edge", "sessions"]);
        match cli.command {
            Some(Command::Sessions { subcmd: None }) => {}
            _ => panic!("Expected Sessions with no subcmd"),
        }
    }

    #[test]
    fn cli_parses_sessions_list() {
        let cli = Cli::parse_from(["encmind-edge", "sessions", "list"]);
        assert!(matches!(
            cli.command,
            Some(Command::Sessions {
                subcmd: Some(SessionsCommand::List)
            })
        ));
    }

    #[test]
    fn cli_parses_sessions_delete() {
        let cli = Cli::parse_from(["encmind-edge", "sessions", "delete", "01JN"]);
        match cli.command {
            Some(Command::Sessions {
                subcmd: Some(SessionsCommand::Delete { id }),
            }) => assert_eq!(id, "01JN"),
            _ => panic!("Expected Sessions Delete"),
        }
    }

    #[test]
    fn cli_parses_sessions_rename() {
        let cli = Cli::parse_from(["encmind-edge", "sessions", "rename", "01JN", "My Chat"]);
        match cli.command {
            Some(Command::Sessions {
                subcmd: Some(SessionsCommand::Rename { id, title }),
            }) => {
                assert_eq!(id, "01JN");
                assert_eq!(title, "My Chat");
            }
            _ => panic!("Expected Sessions Rename"),
        }
    }

    // --- Memory ---

    #[test]
    fn cli_parses_memory_default_status() {
        let cli = Cli::parse_from(["encmind-edge", "memory"]);
        match cli.command {
            Some(Command::Memory { subcmd: None }) => {}
            _ => panic!("Expected Memory with no subcmd"),
        }
    }

    #[test]
    fn cli_parses_memory_status() {
        let cli = Cli::parse_from(["encmind-edge", "memory", "status"]);
        assert!(matches!(
            cli.command,
            Some(Command::Memory {
                subcmd: Some(MemoryCommand::Status)
            })
        ));
    }

    #[test]
    fn cli_parses_memory_search() {
        let cli = Cli::parse_from(["encmind-edge", "memory", "search", "yesterday"]);
        match cli.command {
            Some(Command::Memory {
                subcmd: Some(MemoryCommand::Search { query }),
            }) => assert_eq!(query, "yesterday"),
            _ => panic!("Expected Memory Search"),
        }
    }

    // --- Legacy subcommands still work ---

    #[test]
    fn cli_parses_discover() {
        let cli = Cli::parse_from(["encmind-edge", "discover"]);
        match cli.command {
            Some(Command::Discover { timeout }) => assert_eq!(timeout, 5),
            _ => panic!("Expected Discover"),
        }
    }

    #[test]
    fn cli_parses_pair() {
        let cli = Cli::parse_from(["encmind-edge", "pair", "--name", "laptop"]);
        match cli.command {
            Some(Command::Pair { name }) => assert_eq!(name, "laptop"),
            _ => panic!("Expected Pair"),
        }
    }

    #[test]
    fn cli_parses_connect() {
        let cli = Cli::parse_from(["encmind-edge", "connect"]);
        assert!(matches!(cli.command, Some(Command::Connect)));
    }

    #[test]
    fn cli_parses_status() {
        let cli = Cli::parse_from(["encmind-edge", "status"]);
        assert!(matches!(cli.command, Some(Command::Status)));
    }

    #[test]
    fn cli_parses_config() {
        let cli = Cli::parse_from(["encmind-edge", "config"]);
        assert!(matches!(cli.command, Some(Command::Config)));
    }

    #[test]
    fn cli_parses_fingerprint_flag() {
        let cli = Cli::parse_from([
            "encmind-edge",
            "--fingerprint",
            "SHA256:ab:cd:ef",
            "connect",
        ]);
        assert_eq!(cli.fingerprint.as_deref(), Some("SHA256:ab:cd:ef"));
    }

    #[test]
    fn cli_default_has_no_fingerprint() {
        let cli = Cli::parse_from(["encmind-edge", "connect"]);
        assert!(cli.fingerprint.is_none());
    }

    #[test]
    fn cli_parses_gateway_with_fingerprint() {
        let cli = Cli::parse_from([
            "encmind-edge",
            "--gateway",
            "wss://203.0.113.50:8443",
            "--fingerprint",
            "SHA256:ab:cd",
            "pair",
            "--name",
            "laptop",
        ]);
        assert_eq!(cli.gateway.as_deref(), Some("wss://203.0.113.50:8443"));
        assert_eq!(cli.fingerprint.as_deref(), Some("SHA256:ab:cd"));
    }

    // --- is_tls_gateway_url ---

    #[test]
    fn is_tls_gateway_url_wss() {
        assert!(is_tls_gateway_url("wss://example.com:8443"));
    }

    #[test]
    fn is_tls_gateway_url_https() {
        assert!(is_tls_gateway_url("https://example.com:8443"));
    }

    #[test]
    fn is_tls_gateway_url_ws_is_false() {
        assert!(!is_tls_gateway_url("ws://example.com:8443"));
    }

    #[test]
    fn is_tls_gateway_url_http_is_false() {
        assert!(!is_tls_gateway_url("http://example.com:8443"));
    }

    #[test]
    fn is_tls_gateway_url_not_a_url() {
        assert!(!is_tls_gateway_url("not-a-url"));
    }

    // --- resolve_fingerprint ---

    #[test]
    fn resolve_fingerprint_cli_flag_takes_priority() {
        let fp = "SHA256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result = resolve_fingerprint("wss://localhost:8443", Some(fp)).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn resolve_fingerprint_no_flag_no_known_hosts() {
        let result = resolve_saved_fingerprint("wss://example.com:8443", None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn resolve_saved_fingerprint_valid() {
        let fp = "SHA256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result = resolve_saved_fingerprint("wss://example.com:8443", Some(fp)).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn resolve_saved_fingerprint_invalid_returns_none() {
        let result =
            resolve_saved_fingerprint("wss://example.com:8443", Some("not-valid")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn resolve_fingerprint_invalid_cli_flag_errors() {
        let result = resolve_fingerprint("wss://example.com:8443", Some("bad"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_fingerprint_rejects_plain_gateway_with_cli_fingerprint() {
        let fp = "SHA256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result = resolve_fingerprint("ws://example.com:8443", Some(fp));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("can only be used with wss:// or https://"));
    }

    #[test]
    fn resolve_initial_fingerprint_setup_discovery_accepts_cli_fingerprint() {
        let fp = "SHA256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result =
            resolve_initial_fingerprint(&Command::Setup, "ws://localhost:8443", false, Some(fp))
                .unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn resolve_initial_fingerprint_setup_explicit_plain_gateway_rejects_cli_fingerprint() {
        let fp = "SHA256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result =
            resolve_initial_fingerprint(&Command::Setup, "ws://example.com:8443", true, Some(fp));
        assert!(result.is_err());
    }

    // --- is_tls_validation_error ---

    #[test]
    fn is_tls_validation_error_matches_self_signed() {
        let err: Box<dyn std::error::Error> = "self signed certificate".into();
        assert!(is_tls_validation_error(err.as_ref()));
    }

    #[test]
    fn is_tls_validation_error_matches_unknown_issuer() {
        let err: Box<dyn std::error::Error> = "unknown issuer in chain".into();
        assert!(is_tls_validation_error(err.as_ref()));
    }

    #[test]
    fn is_tls_validation_error_no_match() {
        let err: Box<dyn std::error::Error> = "connection refused".into();
        assert!(!is_tls_validation_error(err.as_ref()));
    }

    #[test]
    fn is_tls_validation_error_matches_rustls_error_type() {
        let err: Box<dyn std::error::Error> =
            Box::new(rustls::Error::General("handshake failed".to_string()));
        assert!(is_tls_validation_error(err.as_ref()));
    }

    // --- should_offer_tofu_retry ---

    #[test]
    fn should_offer_tofu_retry_all_conditions_met() {
        let err: Box<dyn std::error::Error> = "invalid peer certificate".into();
        assert!(should_offer_tofu_retry(false, err.as_ref()));
    }

    #[test]
    fn should_offer_tofu_retry_false_when_fingerprint_set() {
        let err: Box<dyn std::error::Error> = "invalid peer certificate".into();
        assert!(!should_offer_tofu_retry(true, err.as_ref()));
    }

    #[test]
    fn should_offer_tofu_retry_true_even_without_url_scheme_context() {
        let err: Box<dyn std::error::Error> = "invalid peer certificate".into();
        assert!(should_offer_tofu_retry(false, err.as_ref()));
    }

    #[test]
    fn should_offer_tofu_retry_false_for_non_tls_error() {
        let err: Box<dyn std::error::Error> = "connection refused".into();
        assert!(!should_offer_tofu_retry(false, err.as_ref()));
    }
}
