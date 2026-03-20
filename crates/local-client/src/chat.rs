use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use encmind_crypto::challenge::sign_nonce;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::keystore::{identity_exists, KeystoreError, LocalKeystore};
use crate::protocol::{AuthPayload, ClientMessage, ServerMessage};
use crate::tls::{build_http_client_with_fingerprint, build_ws_connector};
use crate::url_utils::{normalize_gateway_base_path, normalize_http_url};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

static REQ_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_req_id() -> String {
    let n = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("r-{n}")
}

/// Options for the chat command.
pub struct ChatOpts<'a> {
    pub session: Option<&'a str>,
    pub one_shot: Option<&'a str>,
    pub gateway_url: &'a str,
    pub identity_path: Option<&'a str>,
    pub fingerprint: Option<&'a str>,
}

/// Main entry point for the chat command.
pub async fn run_chat(opts: ChatOpts<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if !identity_exists(opts.identity_path) {
        return Err("Not set up yet. Run: encmind-edge setup".into());
    }

    let ks = match LocalKeystore::load_or_create(opts.identity_path) {
        Ok(ks) => ks,
        Err(e @ KeystoreError::Parse(_)) => {
            return Err(format!(
                "Identity file is corrupted: {e}. Delete it and re-run: encmind-edge setup"
            )
            .into());
        }
        Err(e @ KeystoreError::Io(_)) => {
            return Err(format!(
                "Cannot read identity file: {e}. Check path/permissions, or re-run: encmind-edge setup"
            )
            .into());
        }
    };

    // Check if identity file looks like it was just created (not paired yet).
    // A paired device would have been recognized by the gateway. We can't
    // definitively check pairing status locally, so we proceed and let
    // the gateway reject if not paired.

    let mut ws = connect_and_auth(opts.gateway_url, &ks, opts.fingerprint).await?;

    // Create or resume a chat session.
    let (session_id, session_mode) = if let Some(sid) = opts.session {
        // Validate session exists via sessions.list preflight.
        validate_session_exists(&mut ws, sid).await?;
        (sid.to_string(), "resumed")
    } else {
        // Create a new session.
        let result = send_req(
            &mut ws,
            "sessions.create",
            serde_json::json!({"channel": "cli"}),
        )
        .await?;
        let sid = result["session"]["id"]
            .as_str()
            .or_else(|| result["id"].as_str())
            .ok_or("sessions.create did not return a session id")?
            .to_string();
        (sid, "new")
    };

    if let Some(message) = opts.one_shot {
        // One-shot mode: send message, print response, disconnect.
        let result = send_req(
            &mut ws,
            "chat.send",
            serde_json::json!({
                "session_id": session_id,
                "text": message,
            }),
        )
        .await?;
        print_assistant_response(&result);
        let _ = ws.close(None).await;
        return Ok(());
    }

    // Interactive REPL mode.
    eprintln!("Connected to {}", opts.gateway_url);
    eprintln!("Session: {session_id}  ({session_mode})");
    eprintln!();

    repl_loop(&mut ws, &session_id).await?;

    let _ = ws.close(None).await;
    Ok(())
}

/// Connect to the gateway, authenticate via nonce challenge, and return the WS stream.
pub async fn connect_and_auth(
    gateway_url: &str,
    ks: &LocalKeystore,
    fingerprint: Option<&str>,
) -> Result<WsStream, Box<dyn std::error::Error>> {
    // Step 1: Fetch nonce via HTTP POST /auth/nonce.
    let http_base = normalize_http_url(gateway_url)?;
    let nonce_url = http_base.join("auth/nonce")?;

    let http_client = if let Some(fp) = fingerprint {
        build_http_client_with_fingerprint(fp)?
    } else {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?
    };

    let nonce_resp = http_client
        .post(nonce_url)
        .json(&serde_json::json!({"device_id": ks.device_id().as_str()}))
        .send()
        .await
        .map_err(|e| {
            format!("Cannot reach gateway at {gateway_url}. Is the server running? ({e})")
        })?;

    if !nonce_resp.status().is_success() {
        let status = nonce_resp.status();
        let body = nonce_resp.text().await.unwrap_or_default();
        return Err(format!("auth/nonce failed ({status}): {body}").into());
    }

    let nonce_json: serde_json::Value = nonce_resp.json().await?;
    let nonce_hex = nonce_json["nonce"]
        .as_str()
        .ok_or("missing nonce in auth response")?;

    // Step 2: Sign nonce.
    let nonce_bytes = hex::decode(nonce_hex)?;
    let signature = sign_nonce(ks.signing_key(), &nonce_bytes);
    let signature_hex = hex::encode(&signature);

    // Step 3: Open WebSocket connection.
    let ws_url = ws_url(gateway_url)?;
    let connector = build_ws_connector(fingerprint)?;
    let (mut ws, _) =
        tokio_tungstenite::connect_async_tls_with_config(ws_url.as_str(), None, false, connector)
            .await?;

    // Step 4: Send Connect, await Connected.
    let connect_msg = ClientMessage::Connect {
        auth: AuthPayload {
            device_id: ks.device_id().as_str().to_string(),
            nonce: nonce_hex.to_string(),
            signature: signature_hex,
        },
    };
    let json = serde_json::to_string(&connect_msg)?;
    ws.send(Message::Text(json)).await?;

    // Await Connected response.
    loop {
        let Some(msg) = ws.next().await else {
            return Err("connection closed before auth completed".into());
        };
        match msg? {
            Message::Text(text) => {
                let server_msg: ServerMessage = serde_json::from_str(text.as_ref())?;
                match server_msg {
                    ServerMessage::Connected { .. } => return Ok(ws),
                    ServerMessage::Error { error, .. } => {
                        if error.code == 4001 {
                            return Err(
                                "Device not recognized by gateway. Run: encmind-edge setup".into(),
                            );
                        }
                        return Err(format!("auth error: {}", error.message).into());
                    }
                    _ => continue,
                }
            }
            Message::Close(_) => {
                return Err("connection closed during auth".into());
            }
            _ => continue,
        }
    }
}

/// Send a JSON-RPC request and await the matching response.
pub async fn send_req(
    ws: &mut WsStream,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let id = next_req_id();
    let msg = ClientMessage::Req {
        id: id.clone(),
        method: method.to_string(),
        params,
    };
    let json = serde_json::to_string(&msg)?;
    ws.send(Message::Text(json)).await?;

    // Await matching Res or Error.
    loop {
        let Some(frame) = ws.next().await else {
            return Err("connection closed while awaiting response".into());
        };
        match frame? {
            Message::Text(text) => {
                let server_msg: ServerMessage = serde_json::from_str(text.as_ref())?;
                match server_msg {
                    ServerMessage::Res {
                        id: res_id, result, ..
                    } if res_id == id => {
                        return Ok(result);
                    }
                    ServerMessage::Error {
                        id: Some(ref err_id),
                        ref error,
                    } if *err_id == id => {
                        return Err(
                            format!("server error ({}): {}", error.code, error.message).into()
                        );
                    }
                    _ => continue,
                }
            }
            Message::Close(_) => {
                return Err("connection closed while awaiting response".into());
            }
            _ => continue,
        }
    }
}

/// Validate that a session exists by checking sessions.list.
async fn validate_session_exists(
    ws: &mut WsStream,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = send_req(ws, "sessions.list", serde_json::json!({})).await?;
    let sessions = result["sessions"]
        .as_array()
        .ok_or("sessions.list did not return an array")?;
    let exists = sessions
        .iter()
        .any(|s| s["id"].as_str() == Some(session_id));
    if !exists {
        return Err(format!("Session '{session_id}' not found.").into());
    }
    Ok(())
}

/// The interactive REPL loop.
async fn repl_loop(
    ws: &mut WsStream,
    initial_session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut session_id = initial_session_id.to_string();
    let mut model_override: Option<String> = None;
    let stdin = std::io::stdin();
    let mut line = String::new();

    loop {
        eprint!("You: ");
        std::io::stderr().flush()?;
        line.clear();
        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read == 0 {
            // Ctrl+D / EOF
            eprintln!();
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match parse_repl_command(trimmed) {
            Some(ReplCommand::Exit) => break,
            Some(ReplCommand::Help) => {
                print_repl_help();
            }
            Some(ReplCommand::New) => {
                let result =
                    send_req(ws, "sessions.create", serde_json::json!({"channel": "cli"})).await?;
                let new_id = result["session"]["id"]
                    .as_str()
                    .or_else(|| result["id"].as_str())
                    .ok_or("sessions.create did not return a session id")?;
                session_id = new_id.to_string();
                eprintln!("New session: {session_id}");
            }
            Some(ReplCommand::Sessions) => {
                let result = send_req(ws, "sessions.list", serde_json::json!({})).await?;
                print_sessions_list(&result);
            }
            Some(ReplCommand::Session(target_id)) => {
                validate_session_exists(ws, &target_id).await?;
                session_id = target_id;
                eprintln!("Switched to session: {session_id}");
            }
            Some(ReplCommand::History) => {
                let result = send_req(
                    ws,
                    "chat.history",
                    serde_json::json!({"session_id": session_id}),
                )
                .await?;
                print_chat_history(&result);
            }
            Some(ReplCommand::Model(model)) => {
                model_override = Some(model.clone());
                eprintln!("Model override set to: {model}");
            }
            Some(ReplCommand::ModelClear) => {
                model_override = None;
                eprintln!("Model override cleared (using server default).");
            }
            Some(ReplCommand::Status) => {
                let result = send_req(ws, "memory.status", serde_json::json!({})).await;
                match result {
                    Ok(v) => print_json_pretty(&v),
                    Err(e) => eprintln!("Failed to get status: {e}"),
                }
            }
            Some(cmd @ ReplCommand::CronList)
            | Some(cmd @ ReplCommand::CronCreate { .. })
            | Some(cmd @ ReplCommand::CronTrigger { .. })
            | Some(cmd @ ReplCommand::CronDelete { .. })
            | Some(cmd @ ReplCommand::BackupList)
            | Some(cmd @ ReplCommand::BackupTrigger)
            | Some(cmd @ ReplCommand::KeysList)
            | Some(cmd @ ReplCommand::KeysSet { .. })
            | Some(cmd @ ReplCommand::KeysDelete { .. })
            | Some(cmd @ ReplCommand::LockdownOn { .. })
            | Some(cmd @ ReplCommand::LockdownOff)
            | Some(cmd @ ReplCommand::Audit { .. })
            | Some(cmd @ ReplCommand::Timeline { .. })
            | Some(cmd @ ReplCommand::Models)
            | Some(cmd @ ReplCommand::Nodes)
            | Some(cmd @ ReplCommand::Rpc { .. }) => {
                if let Some((method, params)) = admin_rpc_parts(&cmd) {
                    admin_rpc(ws, &method, params).await;
                }
            }

            Some(ReplCommand::Unknown(cmd)) => {
                eprintln!("Unknown command: /{cmd}. Type /help for available commands.");
            }
            None => {
                // Regular chat message.
                eprint!("\x1b[2m[thinking...]\x1b[0m");
                std::io::stderr().flush()?;

                let result = send_req(
                    ws,
                    "chat.send",
                    build_chat_send_params(&session_id, trimmed, model_override.as_deref()),
                )
                .await;

                // Clear the [thinking...] indicator.
                eprint!("\r\x1b[K");
                std::io::stderr().flush()?;

                match result {
                    Ok(v) => {
                        print!("Assistant: ");
                        print_assistant_response(&v);
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("busy") || msg.contains("active run") {
                            eprintln!(
                                "Session is busy. Try again or start a new session with /new."
                            );
                        } else if msg.contains("lockdown") {
                            eprintln!("Gateway is in lockdown mode.");
                        } else if msg.contains("No LLM") || msg.contains("no llm") {
                            eprintln!("No LLM provider configured on server.");
                        } else {
                            eprintln!("Error: {e}");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn build_chat_send_params(
    session_id: &str,
    text: &str,
    model_override: Option<&str>,
) -> serde_json::Value {
    let mut params = serde_json::json!({
        "session_id": session_id,
        "text": text,
    });
    if let Some(model) = model_override {
        params["model"] = serde_json::Value::String(model.to_owned());
    }
    params
}

fn print_assistant_response(result: &serde_json::Value) {
    if let Some(text) = result["response"].as_str() {
        println!("{text}");
    } else if let Some(text) = result["text"].as_str() {
        println!("{text}");
    } else if let Some(messages) = result["messages"].as_array() {
        for msg in messages {
            if msg["role"].as_str() == Some("assistant") {
                let text = extract_text_from_content(&msg["content"]);
                if !text.is_empty() {
                    println!("{text}");
                }
            }
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    }
}

fn print_sessions_list(result: &serde_json::Value) {
    if let Some(sessions) = result["sessions"].as_array() {
        if sessions.is_empty() {
            eprintln!("No sessions.");
            return;
        }
        for s in sessions {
            let id = s["id"].as_str().unwrap_or("?");
            let title = s["title"].as_str().unwrap_or("(untitled)");
            println!("  {id}  \"{title}\"");
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    }
}

fn print_chat_history(result: &serde_json::Value) {
    if let Some(messages) = result["messages"].as_array() {
        if messages.is_empty() {
            eprintln!("No messages in this session.");
            return;
        }
        for msg in messages {
            let role = msg["role"].as_str().unwrap_or("?");
            let content = extract_text_from_content(&msg["content"]);
            let label = match role {
                "user" => "You",
                "assistant" => "Assistant",
                "system" => "System",
                other => other,
            };
            println!("{label}: {content}");
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    }
}

fn extract_text_from_content(content: &serde_json::Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_owned();
    }

    let Some(blocks) = content.as_array() else {
        return String::new();
    };

    let mut lines = Vec::new();
    for block in blocks {
        let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if block_type == "text" || block_type == "thinking" || block_type.is_empty() {
            if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                if !text.is_empty() {
                    lines.push(text);
                }
            }
        }
    }
    lines.join("\n")
}

fn print_json_pretty(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}

async fn admin_rpc(ws: &mut WsStream, method: &str, params: serde_json::Value) {
    match send_req(ws, method, params).await {
        Ok(v) => print_json_pretty(&v),
        Err(e) => eprintln!("Error: {e}"),
    }
}

fn keys_set_params(provider: String, key: String) -> serde_json::Value {
    serde_json::json!({"provider": provider, "api_key": key})
}

fn admin_rpc_parts(cmd: &ReplCommand) -> Option<(String, serde_json::Value)> {
    match cmd {
        ReplCommand::CronList => Some(("cron.list".to_string(), serde_json::json!({}))),
        ReplCommand::CronCreate {
            name,
            schedule,
            prompt,
            model,
        } => {
            let mut params = serde_json::json!({
                "name": name,
                "schedule": schedule,
                "prompt": prompt,
            });
            if let Some(m) = model {
                params["model"] = serde_json::Value::String(m.clone());
            }
            Some(("cron.create".to_string(), params))
        }
        ReplCommand::CronTrigger { id } => {
            Some(("cron.trigger".to_string(), serde_json::json!({"id": id})))
        }
        ReplCommand::CronDelete { id } => {
            Some(("cron.delete".to_string(), serde_json::json!({"id": id})))
        }
        ReplCommand::BackupList => Some(("backup.list".to_string(), serde_json::json!({}))),
        ReplCommand::BackupTrigger => Some(("backup.trigger".to_string(), serde_json::json!({}))),
        ReplCommand::KeysList => Some(("keys.list".to_string(), serde_json::json!({}))),
        ReplCommand::KeysSet { provider, key } => Some((
            "keys.set".to_string(),
            keys_set_params(provider.clone(), key.clone()),
        )),
        ReplCommand::KeysDelete { provider } => Some((
            "keys.delete".to_string(),
            serde_json::json!({"provider": provider}),
        )),
        ReplCommand::LockdownOn { reason } => {
            let mut params = serde_json::json!({"active": true});
            if let Some(r) = reason {
                params["reason"] = serde_json::Value::String(r.clone());
            }
            Some(("security.lockdown".to_string(), params))
        }
        ReplCommand::LockdownOff => Some((
            "security.lockdown".to_string(),
            serde_json::json!({"active": false}),
        )),
        ReplCommand::Audit { action, limit } => {
            let mut params = serde_json::json!({});
            if let Some(a) = action {
                params["action"] = serde_json::Value::String(a.clone());
            }
            if let Some(n) = limit {
                params["limit"] = serde_json::json!(n);
            }
            Some(("security.audit".to_string(), params))
        }
        ReplCommand::Timeline { event_type, limit } => {
            let mut params = serde_json::json!({});
            if let Some(t) = event_type {
                params["event_type"] = serde_json::Value::String(t.clone());
            }
            if let Some(n) = limit {
                params["limit"] = serde_json::json!(n);
            }
            Some(("timeline.query".to_string(), params))
        }
        ReplCommand::Models => Some(("models.list".to_string(), serde_json::json!({}))),
        ReplCommand::Nodes => Some(("nodes.list".to_string(), serde_json::json!({}))),
        ReplCommand::Rpc { method, params } => Some((method.clone(), params.clone())),
        _ => None,
    }
}

fn print_repl_help() {
    eprintln!("Available commands:");
    eprintln!("  /new                                    Start a new session");
    eprintln!("  /sessions                               List all sessions");
    eprintln!("  /session <ID>                           Switch to a session");
    eprintln!("  /history                                Show messages in current session");
    eprintln!("  /model [<name>]                         Set/clear model override");
    eprintln!("  /status                                 Memory status");
    eprintln!();
    eprintln!("Admin:");
    eprintln!("  /cron list                              List cron jobs");
    eprintln!("  /cron create <name> \"<sched>\" <prompt> [--model <m>]");
    eprintln!("                                          Create a cron job");
    eprintln!("  /cron trigger <id>                      Trigger a cron job now");
    eprintln!("  /cron delete <id>                       Delete a cron job");
    eprintln!("  /backup list                            List backups");
    eprintln!("  /backup trigger                         Create a backup now");
    eprintln!("  /keys list                              List API keys");
    eprintln!("  /keys set <provider> <key>              Set an API key");
    eprintln!("  /keys delete <provider>                 Delete an API key");
    eprintln!("  /lockdown on [reason]                   Activate lockdown");
    eprintln!("  /lockdown off                           Deactivate lockdown");
    eprintln!("  /audit [--action X] [--limit N]         Query audit log");
    eprintln!("  /timeline [--type X] [--limit N]        Query timeline");
    eprintln!("  /models                                 List models");
    eprintln!("  /nodes                                  List connected devices");
    eprintln!("  /rpc <method> [json]                    Send raw RPC");
    eprintln!();
    eprintln!("  /help                                   Show this help");
    eprintln!("  /exit                                   Quit (or Ctrl+D)");
}

/// REPL commands recognized from user input.
#[derive(Debug, PartialEq)]
pub enum ReplCommand {
    New,
    Sessions,
    Session(String),
    History,
    Model(String),
    ModelClear,
    Status,
    Help,
    Exit,
    // Admin: Cron
    CronList,
    CronCreate {
        name: String,
        schedule: String,
        prompt: String,
        model: Option<String>,
    },
    CronTrigger {
        id: String,
    },
    CronDelete {
        id: String,
    },
    // Admin: Backup
    BackupList,
    BackupTrigger,
    // Admin: API Keys
    KeysList,
    KeysSet {
        provider: String,
        key: String,
    },
    KeysDelete {
        provider: String,
    },
    // Admin: Security
    LockdownOn {
        reason: Option<String>,
    },
    LockdownOff,
    Audit {
        action: Option<String>,
        limit: Option<u32>,
    },
    // Admin: Timeline
    Timeline {
        event_type: Option<String>,
        limit: Option<u32>,
    },
    // Admin: Info
    Models,
    Nodes,
    // Admin: Raw RPC
    Rpc {
        method: String,
        params: serde_json::Value,
    },
    Unknown(String),
}

/// Parse a line as a REPL command, or return None for regular chat text.
pub fn parse_repl_command(input: &str) -> Option<ReplCommand> {
    let trimmed = input.trim();
    if !trimmed.starts_with('/') {
        return None;
    }

    let without_slash = &trimmed[1..];
    let mut parts = without_slash.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("").to_ascii_lowercase();
    let arg = parts.next().map(|s| s.trim().to_string());

    match cmd.as_str() {
        "new" => Some(ReplCommand::New),
        "sessions" => Some(ReplCommand::Sessions),
        "session" => {
            let id = arg.unwrap_or_default();
            if id.is_empty() {
                Some(ReplCommand::Unknown("session (missing ID)".into()))
            } else {
                Some(ReplCommand::Session(id))
            }
        }
        "history" => Some(ReplCommand::History),
        "model" => {
            let name = arg.unwrap_or_default();
            if name.is_empty() {
                Some(ReplCommand::ModelClear)
            } else {
                Some(ReplCommand::Model(name))
            }
        }
        "status" => Some(ReplCommand::Status),
        "help" => Some(ReplCommand::Help),
        "exit" | "quit" | "q" => Some(ReplCommand::Exit),

        // --- Admin commands ---
        "cron" => parse_cron_command(arg.as_deref().unwrap_or("")),
        "backup" => parse_backup_command(arg.as_deref().unwrap_or("")),
        "keys" => parse_keys_command(arg.as_deref().unwrap_or("")),
        "lockdown" => parse_lockdown_command(arg.as_deref().unwrap_or("")),
        "audit" => parse_audit_command(arg.as_deref().unwrap_or("")),
        "timeline" => parse_timeline_command(arg.as_deref().unwrap_or("")),
        "models" => Some(ReplCommand::Models),
        "nodes" => Some(ReplCommand::Nodes),
        "rpc" => parse_rpc_command(arg.as_deref().unwrap_or("")),

        other => Some(ReplCommand::Unknown(other.to_string())),
    }
}

fn parse_cron_command(arg: &str) -> Option<ReplCommand> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Some(ReplCommand::CronList);
    }
    let mut parts = arg.splitn(2, char::is_whitespace);
    let sub = parts.next().unwrap_or("").to_ascii_lowercase();
    let rest = parts.next().unwrap_or("").trim();

    match sub.as_str() {
        "list" => Some(ReplCommand::CronList),
        "create" => parse_cron_create(rest),
        "trigger" => {
            if rest.is_empty() {
                Some(ReplCommand::Unknown("cron trigger (missing ID)".into()))
            } else {
                Some(ReplCommand::CronTrigger {
                    id: rest.to_string(),
                })
            }
        }
        "delete" => {
            if rest.is_empty() {
                Some(ReplCommand::Unknown("cron delete (missing ID)".into()))
            } else {
                Some(ReplCommand::CronDelete {
                    id: rest.to_string(),
                })
            }
        }
        _ => Some(ReplCommand::Unknown(format!("cron {sub}"))),
    }
}

/// Parse `/cron create <name> "<schedule>" <prompt> [--model <m>]`
///
/// The schedule must be quoted because cron expressions contain spaces.
fn parse_cron_create(rest: &str) -> Option<ReplCommand> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Some(ReplCommand::Unknown(
            "cron create (missing name, schedule, prompt)".into(),
        ));
    }

    // Extract name (first token).
    let mut parts = rest.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").to_string();
    let after_name = parts.next().unwrap_or("").trim();

    // Extract quoted schedule.
    let (schedule, after_schedule) = if let Some(inner) = after_name.strip_prefix('"') {
        if let Some(end_quote) = inner.find('"') {
            let sched = &inner[..end_quote];
            let rest = inner[end_quote + 1..].trim();
            (sched.to_string(), rest)
        } else {
            return Some(ReplCommand::Unknown(
                "cron create (unterminated quote in schedule)".into(),
            ));
        }
    } else {
        return Some(ReplCommand::Unknown(
            "cron create (schedule must be quoted, e.g. \"0 9 * * *\")".into(),
        ));
    };

    if after_schedule.is_empty() {
        return Some(ReplCommand::Unknown(
            "cron create (missing prompt after schedule)".into(),
        ));
    }

    // Check for --model flag: only recognize when it's the second-to-last token.
    let words: Vec<&str> = after_schedule.split_whitespace().collect();
    let model_pos = words.iter().rposition(|w| *w == "--model");
    if let Some(pos) = model_pos {
        if pos == words.len() - 1 {
            return Some(ReplCommand::Unknown(
                "cron create (--model requires a value)".into(),
            ));
        }
        if pos != words.len() - 2 && pos >= words.len().saturating_sub(3) {
            return Some(ReplCommand::Unknown(
                "cron create (--model must be the final option as '--model <name>')".into(),
            ));
        }
    }
    let (prompt, model) = if let Some(pos) = model_pos {
        if pos == words.len() - 2 {
            let model_val = words[words.len() - 1].to_string();
            let prompt_str = words[..words.len() - 2].join(" ");
            (prompt_str, Some(model_val))
        } else {
            (after_schedule.to_string(), None)
        }
    } else {
        (after_schedule.to_string(), None)
    };

    if prompt.is_empty() {
        return Some(ReplCommand::Unknown(
            "cron create (missing prompt after schedule)".into(),
        ));
    }

    Some(ReplCommand::CronCreate {
        name,
        schedule,
        prompt,
        model,
    })
}

fn parse_backup_command(arg: &str) -> Option<ReplCommand> {
    let sub = arg.trim().to_ascii_lowercase();
    match sub.as_str() {
        "" | "list" => Some(ReplCommand::BackupList),
        "trigger" => Some(ReplCommand::BackupTrigger),
        other => Some(ReplCommand::Unknown(format!("backup {other}"))),
    }
}

fn parse_keys_command(arg: &str) -> Option<ReplCommand> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Some(ReplCommand::KeysList);
    }
    let mut parts = arg.splitn(2, char::is_whitespace);
    let sub = parts.next().unwrap_or("").to_ascii_lowercase();
    let rest = parts.next().unwrap_or("").trim();

    match sub.as_str() {
        "list" => Some(ReplCommand::KeysList),
        "set" => {
            let mut kv = rest.splitn(2, char::is_whitespace);
            let provider = kv.next().unwrap_or("").trim();
            let key = kv.next().unwrap_or("").trim();
            if provider.is_empty() || key.is_empty() {
                Some(ReplCommand::Unknown(
                    "keys set (requires <provider> <key>)".into(),
                ))
            } else {
                Some(ReplCommand::KeysSet {
                    provider: provider.to_string(),
                    key: key.to_string(),
                })
            }
        }
        "delete" => {
            if rest.is_empty() {
                Some(ReplCommand::Unknown(
                    "keys delete (missing provider)".into(),
                ))
            } else {
                Some(ReplCommand::KeysDelete {
                    provider: rest.to_string(),
                })
            }
        }
        _ => Some(ReplCommand::Unknown(format!("keys {sub}"))),
    }
}

fn parse_lockdown_command(arg: &str) -> Option<ReplCommand> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Some(ReplCommand::Unknown(
            "lockdown (specify 'on' or 'off')".into(),
        ));
    }
    let mut parts = arg.splitn(2, char::is_whitespace);
    let sub = parts.next().unwrap_or("").to_ascii_lowercase();
    let rest = parts.next().unwrap_or("").trim();

    match sub.as_str() {
        "on" => {
            let reason = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            Some(ReplCommand::LockdownOn { reason })
        }
        "off" => Some(ReplCommand::LockdownOff),
        _ => Some(ReplCommand::Unknown(format!("lockdown {sub}"))),
    }
}

/// Parse `/audit [--action X] [--limit N]`
fn parse_audit_command(arg: &str) -> Option<ReplCommand> {
    let arg = arg.trim();
    let mut action = None;
    let mut limit = None;
    let tokens: Vec<&str> = arg.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "--action" => {
                if i + 1 < tokens.len() {
                    action = Some(tokens[i + 1].to_string());
                    i += 2;
                } else {
                    return Some(ReplCommand::Unknown(
                        "audit (--action requires a value)".into(),
                    ));
                }
            }
            "--limit" => {
                if i + 1 < tokens.len() {
                    match tokens[i + 1].parse::<u32>() {
                        Ok(n) => limit = Some(n),
                        Err(_) => {
                            return Some(ReplCommand::Unknown(
                                "audit (--limit must be a number)".into(),
                            ));
                        }
                    }
                    i += 2;
                } else {
                    return Some(ReplCommand::Unknown(
                        "audit (--limit requires a value)".into(),
                    ));
                }
            }
            other if other.starts_with("--") => {
                return Some(ReplCommand::Unknown(format!(
                    "audit (unknown flag: {other})"
                )));
            }
            other => {
                let hint = if action.is_none() {
                    "; use --action <value>"
                } else {
                    ""
                };
                return Some(ReplCommand::Unknown(format!(
                    "audit (unexpected argument: {other}{hint})"
                )));
            }
        }
    }
    Some(ReplCommand::Audit { action, limit })
}

/// Parse `/timeline [--type X] [--limit N]`
fn parse_timeline_command(arg: &str) -> Option<ReplCommand> {
    let arg = arg.trim();
    let mut event_type = None;
    let mut limit = None;
    let tokens: Vec<&str> = arg.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "--type" => {
                if i + 1 < tokens.len() {
                    event_type = Some(tokens[i + 1].to_string());
                    i += 2;
                } else {
                    return Some(ReplCommand::Unknown(
                        "timeline (--type requires a value)".into(),
                    ));
                }
            }
            "--limit" => {
                if i + 1 < tokens.len() {
                    match tokens[i + 1].parse::<u32>() {
                        Ok(n) => limit = Some(n),
                        Err(_) => {
                            return Some(ReplCommand::Unknown(
                                "timeline (--limit must be a number)".into(),
                            ));
                        }
                    }
                    i += 2;
                } else {
                    return Some(ReplCommand::Unknown(
                        "timeline (--limit requires a value)".into(),
                    ));
                }
            }
            other if other.starts_with("--") => {
                return Some(ReplCommand::Unknown(format!(
                    "timeline (unknown flag: {other})"
                )));
            }
            other => {
                let hint = if event_type.is_none() {
                    "; use --type <value>"
                } else {
                    ""
                };
                return Some(ReplCommand::Unknown(format!(
                    "timeline (unexpected argument: {other}{hint})"
                )));
            }
        }
    }
    Some(ReplCommand::Timeline { event_type, limit })
}

/// Parse `/rpc <method> [json_params]`
fn parse_rpc_command(arg: &str) -> Option<ReplCommand> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Some(ReplCommand::Unknown("rpc (missing method)".into()));
    }
    let mut parts = arg.splitn(2, char::is_whitespace);
    let method = parts.next().unwrap_or("").to_string();
    let json_str = parts.next().unwrap_or("").trim();
    let params = if json_str.is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => {
                return Some(ReplCommand::Unknown(format!(
                    "rpc (invalid JSON params: {e})"
                )));
            }
        }
    };
    Some(ReplCommand::Rpc { method, params })
}

/// Derive the WebSocket /ws URL from a gateway base URL.
pub fn ws_url(gateway_url: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let mut url = Url::parse(gateway_url)?;
    match url.scheme() {
        "ws" | "wss" => {}
        "http" => {
            let _ = url.set_scheme("ws");
        }
        "https" => {
            let _ = url.set_scheme("wss");
        }
        s => return Err(format!("unsupported scheme '{s}'").into()),
    }

    url.set_query(None);
    url.set_fragment(None);
    let base = normalize_gateway_base_path(url.path());
    url.set_path(&format!("{base}ws"));
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_repl_command ---

    #[test]
    fn parse_new() {
        assert_eq!(parse_repl_command("/new"), Some(ReplCommand::New));
    }

    #[test]
    fn parse_sessions() {
        assert_eq!(parse_repl_command("/sessions"), Some(ReplCommand::Sessions));
    }

    #[test]
    fn parse_session_with_id() {
        assert_eq!(
            parse_repl_command("/session 01JN123"),
            Some(ReplCommand::Session("01JN123".into()))
        );
    }

    #[test]
    fn parse_session_missing_id() {
        match parse_repl_command("/session") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("missing ID")),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_history() {
        assert_eq!(parse_repl_command("/history"), Some(ReplCommand::History));
    }

    #[test]
    fn parse_model_with_name() {
        assert_eq!(
            parse_repl_command("/model gpt-4"),
            Some(ReplCommand::Model("gpt-4".into()))
        );
    }

    #[test]
    fn parse_model_no_arg_clears() {
        assert_eq!(parse_repl_command("/model"), Some(ReplCommand::ModelClear));
    }

    #[test]
    fn parse_status() {
        assert_eq!(parse_repl_command("/status"), Some(ReplCommand::Status));
    }

    #[test]
    fn parse_help() {
        assert_eq!(parse_repl_command("/help"), Some(ReplCommand::Help));
    }

    #[test]
    fn parse_exit() {
        assert_eq!(parse_repl_command("/exit"), Some(ReplCommand::Exit));
    }

    #[test]
    fn parse_quit_alias() {
        assert_eq!(parse_repl_command("/quit"), Some(ReplCommand::Exit));
    }

    #[test]
    fn parse_q_alias() {
        assert_eq!(parse_repl_command("/q"), Some(ReplCommand::Exit));
    }

    #[test]
    fn parse_unknown_command() {
        match parse_repl_command("/foobar") {
            Some(ReplCommand::Unknown(s)) => assert_eq!(s, "foobar"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_regular_text_returns_none() {
        assert_eq!(parse_repl_command("hello world"), None);
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(parse_repl_command("/NEW"), Some(ReplCommand::New));
        assert_eq!(parse_repl_command("/Sessions"), Some(ReplCommand::Sessions));
        assert_eq!(parse_repl_command("/HELP"), Some(ReplCommand::Help));
    }

    #[test]
    fn build_chat_send_params_without_model() {
        let params = build_chat_send_params("sess-1", "hello", None);
        assert_eq!(params["session_id"], "sess-1");
        assert_eq!(params["text"], "hello");
        assert!(params.get("model").is_none());
    }

    #[test]
    fn build_chat_send_params_with_model() {
        let params = build_chat_send_params("sess-1", "hello", Some("gpt-4o"));
        assert_eq!(params["session_id"], "sess-1");
        assert_eq!(params["text"], "hello");
        assert_eq!(params["model"], "gpt-4o");
    }

    #[test]
    fn extract_text_from_content_string() {
        let content = serde_json::json!("plain text");
        assert_eq!(extract_text_from_content(&content), "plain text");
    }

    #[test]
    fn extract_text_from_content_blocks() {
        let content = serde_json::json!([
            {"type":"text","text":"hello"},
            {"type":"tool_use","id":"x","name":"n","input":{}},
            {"type":"text","text":"world"}
        ]);
        assert_eq!(extract_text_from_content(&content), "hello\nworld");
    }

    // --- ws_url ---

    #[test]
    fn ws_url_default() {
        let url = ws_url("ws://localhost:8443").unwrap();
        assert_eq!(url.as_str(), "ws://localhost:8443/ws");
    }

    #[test]
    fn ws_url_from_https() {
        let url = ws_url("https://example.com:8443").unwrap();
        assert_eq!(url.as_str(), "wss://example.com:8443/ws");
    }

    #[test]
    fn ws_url_preserves_base_path() {
        let url = ws_url("wss://example.com/gateway").unwrap();
        assert_eq!(url.as_str(), "wss://example.com/gateway/ws");
    }

    #[test]
    fn ws_url_strips_existing_node_suffix() {
        let url = ws_url("wss://example.com/gateway/node").unwrap();
        assert_eq!(url.as_str(), "wss://example.com/gateway/ws");
    }

    #[test]
    fn ws_url_strips_existing_ws_suffix() {
        let url = ws_url("wss://example.com/api/ws").unwrap();
        assert_eq!(url.as_str(), "wss://example.com/api/ws");
    }

    // --- Admin slash commands: Cron ---

    #[test]
    fn parse_cron_list() {
        assert_eq!(
            parse_repl_command("/cron list"),
            Some(ReplCommand::CronList)
        );
    }

    #[test]
    fn parse_cron_bare() {
        // `/cron` with no subcommand defaults to list
        assert_eq!(parse_repl_command("/cron"), Some(ReplCommand::CronList));
    }

    #[test]
    fn parse_cron_subcommand_case_insensitive() {
        assert_eq!(
            parse_repl_command("/CRON LIST"),
            Some(ReplCommand::CronList)
        );
    }

    #[test]
    fn parse_cron_create() {
        assert_eq!(
            parse_repl_command(r#"/cron create test-job "0 9 * * *" Do something"#),
            Some(ReplCommand::CronCreate {
                name: "test-job".into(),
                schedule: "0 9 * * *".into(),
                prompt: "Do something".into(),
                model: None,
            })
        );
    }

    #[test]
    fn parse_cron_create_with_model() {
        assert_eq!(
            parse_repl_command(r#"/cron create daily "*/2 * * * *" Say hello --model gpt-4"#),
            Some(ReplCommand::CronCreate {
                name: "daily".into(),
                schedule: "*/2 * * * *".into(),
                prompt: "Say hello".into(),
                model: Some("gpt-4".into()),
            })
        );
    }

    #[test]
    fn parse_cron_create_model_missing_value() {
        match parse_repl_command(r#"/cron create daily "*/2 * * * *" Say hello --model"#) {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("--model requires a value"), "got: {s}")
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_create_only_model_flag_missing_value() {
        match parse_repl_command(r#"/cron create daily "*/2 * * * *" --model"#) {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("--model requires a value"), "got: {s}")
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_create_model_not_final_option_rejected() {
        match parse_repl_command(r#"/cron create daily "*/2 * * * *" hello --model gpt-4 extra"#) {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("must be the final option"), "got: {s}")
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_create_missing_args() {
        match parse_repl_command("/cron create") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("missing"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_create_unquoted_schedule() {
        match parse_repl_command("/cron create job 0 9 * * * prompt") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("quoted"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_trigger() {
        assert_eq!(
            parse_repl_command("/cron trigger 01JN123"),
            Some(ReplCommand::CronTrigger {
                id: "01JN123".into()
            })
        );
    }

    #[test]
    fn parse_cron_trigger_missing_id() {
        match parse_repl_command("/cron trigger") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("missing ID"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_delete() {
        assert_eq!(
            parse_repl_command("/cron delete 01JN123"),
            Some(ReplCommand::CronDelete {
                id: "01JN123".into()
            })
        );
    }

    #[test]
    fn parse_cron_delete_missing_id() {
        match parse_repl_command("/cron delete") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("missing ID"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    // --- Admin: Backup ---

    #[test]
    fn parse_backup_list() {
        assert_eq!(
            parse_repl_command("/backup list"),
            Some(ReplCommand::BackupList)
        );
    }

    #[test]
    fn parse_backup_bare() {
        assert_eq!(parse_repl_command("/backup"), Some(ReplCommand::BackupList));
    }

    #[test]
    fn parse_backup_subcommand_case_insensitive() {
        assert_eq!(
            parse_repl_command("/BACKUP TRIGGER"),
            Some(ReplCommand::BackupTrigger)
        );
    }

    #[test]
    fn parse_backup_trigger() {
        assert_eq!(
            parse_repl_command("/backup trigger"),
            Some(ReplCommand::BackupTrigger)
        );
    }

    // --- Admin: Keys ---

    #[test]
    fn parse_keys_list() {
        assert_eq!(
            parse_repl_command("/keys list"),
            Some(ReplCommand::KeysList)
        );
    }

    #[test]
    fn parse_keys_bare() {
        assert_eq!(parse_repl_command("/keys"), Some(ReplCommand::KeysList));
    }

    #[test]
    fn parse_keys_subcommand_case_insensitive() {
        assert_eq!(
            parse_repl_command("/KEYS LIST"),
            Some(ReplCommand::KeysList)
        );
    }

    #[test]
    fn parse_keys_set() {
        assert_eq!(
            parse_repl_command("/keys set openai sk-abc123"),
            Some(ReplCommand::KeysSet {
                provider: "openai".into(),
                key: "sk-abc123".into(),
            })
        );
    }

    #[test]
    fn parse_keys_set_missing_key() {
        match parse_repl_command("/keys set openai") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("requires"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_keys_delete() {
        assert_eq!(
            parse_repl_command("/keys delete openai"),
            Some(ReplCommand::KeysDelete {
                provider: "openai".into(),
            })
        );
    }

    #[test]
    fn parse_keys_delete_missing_provider() {
        match parse_repl_command("/keys delete") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("missing"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    // --- Admin: Security ---

    #[test]
    fn parse_lockdown_on() {
        assert_eq!(
            parse_repl_command("/lockdown on"),
            Some(ReplCommand::LockdownOn { reason: None })
        );
    }

    #[test]
    fn parse_lockdown_on_with_reason() {
        assert_eq!(
            parse_repl_command("/lockdown on security incident"),
            Some(ReplCommand::LockdownOn {
                reason: Some("security incident".into()),
            })
        );
    }

    #[test]
    fn parse_lockdown_off() {
        assert_eq!(
            parse_repl_command("/lockdown off"),
            Some(ReplCommand::LockdownOff)
        );
    }

    #[test]
    fn parse_lockdown_subcommand_case_insensitive() {
        assert_eq!(
            parse_repl_command("/LOCKDOWN ON"),
            Some(ReplCommand::LockdownOn { reason: None })
        );
    }

    #[test]
    fn parse_lockdown_bare() {
        match parse_repl_command("/lockdown") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("on"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    // --- Admin: Audit ---

    #[test]
    fn parse_audit_bare() {
        assert_eq!(
            parse_repl_command("/audit"),
            Some(ReplCommand::Audit {
                action: None,
                limit: None,
            })
        );
    }

    #[test]
    fn parse_audit_with_action() {
        assert_eq!(
            parse_repl_command("/audit --action lockdown"),
            Some(ReplCommand::Audit {
                action: Some("lockdown".into()),
                limit: None,
            })
        );
    }

    #[test]
    fn parse_audit_with_limit() {
        assert_eq!(
            parse_repl_command("/audit --limit 50"),
            Some(ReplCommand::Audit {
                action: None,
                limit: Some(50),
            })
        );
    }

    #[test]
    fn parse_audit_both_flags() {
        assert_eq!(
            parse_repl_command("/audit --action chat.send --limit 10"),
            Some(ReplCommand::Audit {
                action: Some("chat.send".into()),
                limit: Some(10),
            })
        );
    }

    #[test]
    fn parse_audit_rejects_unexpected_positional_arg() {
        match parse_repl_command("/audit lockdown") {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("unexpected argument"), "got: {s}");
                assert!(s.contains("lockdown"), "got: {s}");
                assert!(s.contains("--action"), "got: {s}");
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    // --- Admin: Timeline ---

    #[test]
    fn parse_timeline_bare() {
        assert_eq!(
            parse_repl_command("/timeline"),
            Some(ReplCommand::Timeline {
                event_type: None,
                limit: None,
            })
        );
    }

    #[test]
    fn parse_timeline_with_type() {
        assert_eq!(
            parse_repl_command("/timeline --type cron"),
            Some(ReplCommand::Timeline {
                event_type: Some("cron".into()),
                limit: None,
            })
        );
    }

    #[test]
    fn parse_timeline_with_limit() {
        assert_eq!(
            parse_repl_command("/timeline --limit 20"),
            Some(ReplCommand::Timeline {
                event_type: None,
                limit: Some(20),
            })
        );
    }

    #[test]
    fn parse_timeline_rejects_unexpected_positional_arg() {
        match parse_repl_command("/timeline cron") {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("unexpected argument"), "got: {s}");
                assert!(s.contains("cron"), "got: {s}");
                assert!(s.contains("--type"), "got: {s}");
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    // --- Admin: Info ---

    #[test]
    fn parse_models() {
        assert_eq!(parse_repl_command("/models"), Some(ReplCommand::Models));
    }

    #[test]
    fn parse_nodes() {
        assert_eq!(parse_repl_command("/nodes"), Some(ReplCommand::Nodes));
    }

    // --- Admin: Raw RPC ---

    #[test]
    fn parse_rpc_with_params() {
        assert_eq!(
            parse_repl_command(r#"/rpc cron.list {}"#),
            Some(ReplCommand::Rpc {
                method: "cron.list".into(),
                params: serde_json::json!({}),
            })
        );
    }

    #[test]
    fn parse_rpc_no_params() {
        assert_eq!(
            parse_repl_command("/rpc sessions.list"),
            Some(ReplCommand::Rpc {
                method: "sessions.list".into(),
                params: serde_json::json!({}),
            })
        );
    }

    #[test]
    fn parse_rpc_with_json_object() {
        assert_eq!(
            parse_repl_command(
                r#"/rpc cron.create {"name":"test","schedule":"* * * * *","prompt":"hi"}"#
            ),
            Some(ReplCommand::Rpc {
                method: "cron.create".into(),
                params: serde_json::json!({"name":"test","schedule":"* * * * *","prompt":"hi"}),
            })
        );
    }

    #[test]
    fn parse_rpc_invalid_json() {
        match parse_repl_command("/rpc foo {bad json}") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("invalid JSON"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_rpc_missing_method() {
        match parse_repl_command("/rpc") {
            Some(ReplCommand::Unknown(s)) => assert!(s.contains("missing method"), "got: {s}"),
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    // --- Fix 1: keys.set wire format uses "api_key" ---

    #[test]
    fn parse_keys_set_wire_format() {
        // Verify the actual dispatch helper constructs "api_key", not "key".
        let cmd = parse_repl_command("/keys set openai sk-test123");
        assert_eq!(
            cmd,
            Some(ReplCommand::KeysSet {
                provider: "openai".into(),
                key: "sk-test123".into(),
            })
        );
        if let Some(ReplCommand::KeysSet { provider, key }) = cmd {
            let params = keys_set_params(provider, key);
            assert_eq!(params["api_key"], "sk-test123");
            assert!(params.get("key").is_none(), "must use 'api_key', not 'key'");
        }
    }

    #[test]
    fn admin_rpc_parts_keys_set_uses_api_key() {
        let cmd = ReplCommand::KeysSet {
            provider: "openai".into(),
            key: "sk-test123".into(),
        };
        let (method, params) = admin_rpc_parts(&cmd).expect("admin rpc mapping");
        assert_eq!(method, "keys.set");
        assert_eq!(params["provider"], "openai");
        assert_eq!(params["api_key"], "sk-test123");
        assert!(params.get("key").is_none(), "must use 'api_key', not 'key'");
    }

    #[test]
    fn admin_rpc_parts_rpc_passthrough() {
        let cmd = ReplCommand::Rpc {
            method: "cron.list".into(),
            params: serde_json::json!({"limit": 10}),
        };
        let (method, params) = admin_rpc_parts(&cmd).expect("admin rpc mapping");
        assert_eq!(method, "cron.list");
        assert_eq!(params["limit"], 10);
    }

    #[test]
    fn admin_rpc_parts_non_admin_returns_none() {
        assert!(admin_rpc_parts(&ReplCommand::Status).is_none());
    }

    // --- Fix 2 & 3: cron create empty prompt / --model in prompt text ---

    #[test]
    fn parse_cron_create_prompt_only_model() {
        // `/cron create job "0 9 * * *" --model gpt-4` → empty prompt → Unknown
        match parse_repl_command(r#"/cron create job "0 9 * * *" --model gpt-4"#) {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("missing prompt"), "got: {s}")
            }
            other => panic!("Expected Unknown for empty prompt, got {other:?}"),
        }
    }

    #[test]
    fn parse_cron_create_model_in_prompt_text() {
        // `--model` appearing in the middle of prompt text should NOT be treated as a flag
        assert_eq!(
            parse_repl_command(
                r#"/cron create job "0 9 * * *" Explain the --model flag in detail"#
            ),
            Some(ReplCommand::CronCreate {
                name: "job".into(),
                schedule: "0 9 * * *".into(),
                prompt: "Explain the --model flag in detail".into(),
                model: None,
            })
        );
    }

    // --- Fix 4: unknown flags in audit / timeline ---

    #[test]
    fn parse_audit_unknown_flag() {
        match parse_repl_command("/audit --aciton lockdown") {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("unknown flag"), "got: {s}");
                assert!(s.contains("--aciton"), "got: {s}");
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_timeline_unknown_flag() {
        match parse_repl_command("/timeline --tyep chat") {
            Some(ReplCommand::Unknown(s)) => {
                assert!(s.contains("unknown flag"), "got: {s}");
                assert!(s.contains("--tyep"), "got: {s}");
            }
            other => panic!("Expected Unknown, got {other:?}"),
        }
    }
}
