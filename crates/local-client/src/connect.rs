use crate::commands::{execute_command, is_command_permitted, LocalCommand, LocalPolicy};
use crate::keystore::LocalKeystore;
use crate::tls::build_ws_connector;
use crate::url_utils::{normalize_gateway_base_path, validate_fingerprint_transport};
use encmind_crypto::challenge::sign_nonce;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

pub async fn run_connect(
    gateway_url: &str,
    identity_path: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ks = LocalKeystore::load_or_create(identity_path)?;
    let url = node_ws_url(gateway_url)?;
    validate_fingerprint_transport(&url, fingerprint)?;
    let policy = default_policy();

    println!("Device ID: {}", ks.device_id());
    println!("Connecting to: {url}");
    if let Some(fp) = fingerprint {
        println!("Using pinned fingerprint: {fp}");
    }
    println!(
        "Local policy: file.read={}, file.write={}, file.list={}, bash.exec={}",
        policy.allow_file_read,
        policy.allow_file_write,
        policy.allow_file_list,
        policy.allow_bash_exec
    );

    let connector = build_ws_connector(fingerprint)?;
    let (mut ws, _response) =
        tokio_tungstenite::connect_async_tls_with_config(url.as_str(), None, false, connector)
            .await?;

    let register_msg = serde_json::json!({
        "type": "register",
        "device_id": ks.device_id().as_str(),
        "name": "encmind-edge"
    });
    ws.send(Message::Text(register_msg.to_string())).await?;
    println!("Connected. Waiting for commands (Ctrl+C to quit)...");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Disconnecting...");
                break;
            }
            msg = ws.next() => {
                let Some(msg) = msg else { break; };
                match msg? {
                    Message::Text(text) => {
                        handle_server_message(&mut ws, text.as_ref(), &ks, &policy).await?;
                    }
                    Message::Close(_) => break,
                    Message::Ping(payload) => {
                        ws.send(Message::Pong(payload)).await?;
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = ws.close(None).await;
    Ok(())
}

fn node_ws_url(gateway_url: &str) -> Result<Url, Box<dyn std::error::Error>> {
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
    url.set_path(&format!("{base}node"));
    Ok(url)
}

/// Default policy: all commands allowed. Gateway already enforces DevicePermissions;
/// this is defense-in-depth, configurable later.
fn default_policy() -> LocalPolicy {
    LocalPolicy::default()
}

/// Parse a command name + params JSON into a LocalCommand.
fn parse_command(command_name: &str, params: &serde_json::Value) -> Option<LocalCommand> {
    match command_name {
        "file.read" => {
            let path = params.get("path")?.as_str()?.to_string();
            Some(LocalCommand::FileRead { path })
        }
        "file.write" => {
            let path = params.get("path")?.as_str()?.to_string();
            let content = params.get("content")?.as_str()?.to_string();
            Some(LocalCommand::FileWrite { path, content })
        }
        "file.list" => {
            let path = params.get("path")?.as_str()?.to_string();
            Some(LocalCommand::FileList { path })
        }
        "bash.exec" => {
            let command = params.get("command")?.as_str()?.to_string();
            Some(LocalCommand::BashExec { command })
        }
        _ => None,
    }
}

async fn handle_server_message(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    text: &str,
    ks: &LocalKeystore,
    policy: &LocalPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            println!("Received non-JSON message: {text}");
            return Ok(());
        }
    };

    let msg_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    match msg_type {
        "auth_challenge" => {
            let nonce = value
                .get("nonce")
                .and_then(|v| v.as_str())
                .ok_or("missing nonce in auth_challenge")?;
            let nonce_bytes = hex::decode(nonce)?;
            let signature = sign_nonce(ks.signing_key(), &nonce_bytes);
            let register_auth_msg = serde_json::json!({
                "type": "register_auth",
                "device_id": ks.device_id().as_str(),
                "nonce": nonce,
                "signature": hex::encode(signature),
            });
            ws.send(Message::Text(register_auth_msg.to_string()))
                .await?;
            println!("Received registration challenge; sent signed response.");
        }
        "registered" => {
            let id = value
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("Registered as device: {id}");
        }
        "command" => {
            let request_id = value
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let command_name = value
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let params = value
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

            println!("Received command: {command_name}");

            if request_id.is_empty() {
                return Ok(());
            }

            let result = match parse_command(command_name, &params) {
                Some(cmd) => {
                    if is_command_permitted(&cmd, policy) {
                        let r = execute_command(&cmd, policy).await;
                        serde_json::json!({
                            "ok": r.success,
                            "output": r.output,
                        })
                    } else {
                        serde_json::json!({
                            "ok": false,
                            "error": format!("command '{command_name}' denied by local policy"),
                        })
                    }
                }
                None => {
                    serde_json::json!({
                        "ok": false,
                        "error": format!("unknown command: {command_name}"),
                    })
                }
            };

            let result_msg = serde_json::json!({
                "type": "command_result",
                "request_id": request_id,
                "result": result,
            });
            ws.send(Message::Text(result_msg.to_string())).await?;
        }
        "error" => {
            let err = value
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            println!("Gateway error: {err}");
        }
        _ => {
            println!("Gateway message: {value}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ws_url_appends_default_node_path() {
        let url = node_ws_url("ws://localhost:8443").expect("url");
        assert_eq!(url.as_str(), "ws://localhost:8443/node");
    }

    #[test]
    fn node_ws_url_converts_http_scheme() {
        let url = node_ws_url("http://localhost:8443").expect("url");
        assert_eq!(url.as_str(), "ws://localhost:8443/node");
    }

    #[test]
    fn node_ws_url_preserves_base_path_and_appends_node() {
        let url = node_ws_url("https://example.com/gateway").expect("url");
        assert_eq!(url.as_str(), "wss://example.com/gateway/node");
    }

    #[test]
    fn node_ws_url_strips_existing_node_suffix() {
        let url = node_ws_url("wss://example.com/gateway/node").expect("url");
        assert_eq!(url.as_str(), "wss://example.com/gateway/node");
    }

    #[test]
    fn node_ws_url_strips_existing_ws_suffix() {
        let url = node_ws_url("wss://example.com/api/ws").expect("url");
        assert_eq!(url.as_str(), "wss://example.com/api/node");
    }

    #[test]
    fn parse_command_file_read() {
        let params = serde_json::json!({ "path": "/tmp/test.txt" });
        let cmd = parse_command("file.read", &params).unwrap();
        assert!(matches!(cmd, LocalCommand::FileRead { path } if path == "/tmp/test.txt"));
    }

    #[test]
    fn parse_command_bash_exec() {
        let params = serde_json::json!({ "command": "echo hello" });
        let cmd = parse_command("bash.exec", &params).unwrap();
        assert!(matches!(cmd, LocalCommand::BashExec { command } if command == "echo hello"));
    }

    #[test]
    fn parse_command_unknown_returns_none() {
        let params = serde_json::json!({});
        assert!(parse_command("unknown.cmd", &params).is_none());
    }

    #[test]
    fn default_policy_allows_all() {
        let p = default_policy();
        assert!(p.allow_file_read);
        assert!(p.allow_file_write);
        assert!(p.allow_file_list);
        assert!(p.allow_bash_exec);
    }
}
