use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use encmind_core::types::DevicePermissions;
use futures::stream::SplitSink;
use futures::{FutureExt, SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::dispatch::dispatch_method;
use crate::idempotency::IdempotencyCache;

/// Shared WebSocket sender for streaming events.
pub type WsSender = Arc<Mutex<SplitSink<WebSocket, Message>>>;
use crate::node::check_permission;
use crate::plugin_manager::PluginManager;
use crate::protocol::*;
use crate::state::AppState;

/// axum handler that upgrades HTTP to WebSocket.
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    match state.connection_permits.clone().try_acquire_owned() {
        Ok(permit) => ws
            .on_upgrade(move |socket| handle_connection(socket, state, permit))
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "connection limit reached; try again later",
        )
            .into_response(),
    }
}

/// Handle a single WebSocket connection.
async fn handle_connection(socket: WebSocket, state: AppState, _permit: OwnedSemaphorePermit) {
    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(Mutex::new(sender));
    let auth = Arc::new(RwLock::new(ConnectionAuth::default()));
    let mut in_flight = JoinSet::new();

    // Connection is open — process messages until close
    loop {
        while let Some(join_result) = in_flight.try_join_next() {
            if let Err(err) = join_result {
                warn!(error = %err, "ws message task failed");
            }
        }

        let next = receiver.next().await;
        let msg = match next {
            Some(Ok(msg)) => msg,
            Some(Err(err)) => {
                warn!(error = %err, "ws connection receive failed; closing connection");
                break;
            }
            None => {
                debug!("ws stream ended by peer");
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                let text = text.to_string();
                let is_connect = matches!(
                    serde_json::from_str::<ClientMessage>(&text),
                    Ok(ClientMessage::Connect { .. })
                );

                // Process connect inline to preserve request ordering and avoid
                // races where immediate follow-up requests run before auth is set.
                if is_connect {
                    let response = process_text_message_with_recovery_shared(
                        &state,
                        auth.clone(),
                        &text,
                        Some(sender.clone()),
                    )
                    .await;
                    if let Some(resp) = response {
                        if let Err(err) = send_ws_response_frame(&sender, &resp).await {
                            warn!(error = %err, "ws failed to send response frame; closing connection");
                            break;
                        }
                    }
                    continue;
                }

                let state_clone = state.clone();
                let auth_clone = auth.clone();
                let sender_clone = sender.clone();

                in_flight.spawn(async move {
                    let response = process_text_message_with_recovery_shared(
                        &state_clone,
                        auth_clone,
                        &text,
                        Some(sender_clone.clone()),
                    )
                    .await;
                    if let Some(resp) = response {
                        if let Err(err) = send_ws_response_frame(&sender_clone, &resp).await {
                            warn!(error = %err, "ws failed to send response frame");
                        }
                    }
                });
            }
            Message::Close(frame) => {
                debug!(?frame, "ws close frame received; closing connection");
                break;
            }
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => {}
        }
    }

    in_flight.abort_all();
    while let Some(join_result) = in_flight.join_next().await {
        if let Err(err) = join_result {
            if !err.is_cancelled() {
                warn!(error = %err, "ws message task failed during shutdown");
            }
        }
    }
}

#[derive(Default)]
struct ConnectionAuth {
    session: Option<AuthSession>,
}

#[derive(Clone)]
struct AuthSession {
    device_id: String,
    permissions: DevicePermissions,
}

async fn send_ws_response_frame(sender: &WsSender, response: &ServerMessage) -> Result<(), String> {
    let json = serde_json::to_string(response).map_err(|e| e.to_string())?;
    let mut s = sender.lock().await;
    s.send(Message::Text(json.into()))
        .await
        .map_err(|e| e.to_string())
}

async fn process_text_message_with_recovery_shared(
    state: &AppState,
    auth: Arc<RwLock<ConnectionAuth>>,
    text: &str,
    ws_sender: Option<WsSender>,
) -> Option<ServerMessage> {
    let panic_response_id = extract_req_id_from_raw_text(text);
    match std::panic::AssertUnwindSafe(process_text_message_shared(
        state,
        auth.clone(),
        text,
        ws_sender,
    ))
    .catch_unwind()
    .await
    {
        Ok(response) => response,
        Err(panic_payload) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            let mut guard = auth.write().await;
            *guard = ConnectionAuth::default();
            warn!(
                panic = %panic_msg,
                "ws process_text_message panicked; auth reset and connection kept alive"
            );
            Some(ServerMessage::Error {
                id: panic_response_id,
                error: ErrorPayload::new(
                    ERR_INTERNAL,
                    "internal server error while processing message",
                ),
            })
        }
    }
}

async fn process_text_message_shared(
    state: &AppState,
    auth: Arc<RwLock<ConnectionAuth>>,
    text: &str,
    ws_sender: Option<WsSender>,
) -> Option<ServerMessage> {
    let client_msg: ClientMessage = match serde_json::from_str(text) {
        Ok(msg) => msg,
        Err(e) => {
            return Some(ServerMessage::Error {
                id: None,
                error: ErrorPayload::new(ERR_INTERNAL, format!("invalid message: {e}")),
            });
        }
    };

    match client_msg {
        ClientMessage::Connect { auth: payload } => {
            match authenticate_connection(state, &payload).await {
                Ok((device_id, permissions)) => {
                    let mut guard = auth.write().await;
                    guard.session = Some(AuthSession {
                        device_id: device_id.clone(),
                        permissions,
                    });
                    Some(ServerMessage::Connected {
                        session_id: format!("ws-{device_id}"),
                    })
                }
                Err(message) => Some(ServerMessage::Error {
                    id: None,
                    error: ErrorPayload::new(ERR_AUTH_FAILED, message),
                }),
            }
        }
        ClientMessage::Req { id, method, params } => {
            let session = {
                let guard = auth.read().await;
                match guard.session.as_ref() {
                    Some(session) => session.clone(),
                    None => {
                        return Some(ServerMessage::Error {
                            id: Some(id),
                            error: ErrorPayload::new(
                                ERR_AUTH_FAILED,
                                "authentication required: send connect first",
                            ),
                        });
                    }
                }
            };

            #[cfg(test)]
            if method == "__panic_test__" {
                panic!("ws test panic");
            }

            let plugin_manager = { state.plugin_manager.read().await.clone() };
            if !is_method_allowed_with_plugin(
                &method,
                &params,
                &session.permissions,
                plugin_manager.as_deref(),
            ) {
                return Some(ServerMessage::Error {
                    id: Some(id),
                    error: ErrorPayload::new(
                        ERR_AUTH_FAILED,
                        format!("permission denied for method: {method}"),
                    ),
                });
            }

            let scoped_id = format!("{}:{id}", session.device_id);

            // Check idempotency cache
            {
                let cache = match state.idempotency.lock() {
                    Ok(cache) => cache,
                    Err(poisoned) => recover_poisoned_idempotency_cache(poisoned, "read"),
                };
                if let Some(cached) = cache.get(&scoped_id) {
                    return Some(ServerMessage::Res {
                        id: id.clone(),
                        result: cached.clone(),
                    });
                }
            }

            let response = dispatch_method(state, &method, params, &id, ws_sender.clone()).await;

            // Cache successful results
            if let ServerMessage::Res { ref result, .. } = response {
                let mut cache = match state.idempotency.lock() {
                    Ok(cache) => cache,
                    Err(poisoned) => recover_poisoned_idempotency_cache(poisoned, "write"),
                };
                cache.set(scoped_id, result.clone());
                cache.cleanup();
            }

            Some(response)
        }
        ClientMessage::Ping { seq } => Some(ServerMessage::Pong { seq }),
    }
}

fn extract_req_id_from_raw_text(text: &str) -> Option<String> {
    serde_json::from_str::<ClientMessage>(text)
        .ok()
        .and_then(|msg| match msg {
            ClientMessage::Req { id, .. } => Some(id),
            _ => None,
        })
}

fn recover_poisoned_idempotency_cache<'a>(
    poisoned: std::sync::PoisonError<std::sync::MutexGuard<'a, IdempotencyCache>>,
    context: &'static str,
) -> std::sync::MutexGuard<'a, IdempotencyCache> {
    let mut cache = poisoned.into_inner();
    cache.clear();
    warn!(
        context,
        "ws idempotency cache lock poisoned; cache cleared and recovered"
    );
    cache
}

#[cfg(test)]
async fn process_text_message_with_recovery(
    state: &AppState,
    auth: &mut ConnectionAuth,
    text: &str,
    ws_sender: Option<WsSender>,
) -> Option<ServerMessage> {
    let panic_response_id = extract_req_id_from_raw_text(text);
    match std::panic::AssertUnwindSafe(process_text_message(state, auth, text, ws_sender))
        .catch_unwind()
        .await
    {
        Ok(response) => response,
        Err(panic_payload) => {
            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            // Drop any potentially inconsistent auth state from the panicking frame.
            *auth = ConnectionAuth::default();
            warn!(
                panic = %panic_msg,
                "ws process_text_message panicked; auth reset and connection kept alive"
            );
            Some(ServerMessage::Error {
                id: panic_response_id,
                error: ErrorPayload::new(
                    ERR_INTERNAL,
                    "internal server error while processing message",
                ),
            })
        }
    }
}

#[cfg(test)]
async fn process_text_message(
    state: &AppState,
    auth: &mut ConnectionAuth,
    text: &str,
    ws_sender: Option<WsSender>,
) -> Option<ServerMessage> {
    let client_msg: ClientMessage = match serde_json::from_str(text) {
        Ok(msg) => msg,
        Err(e) => {
            return Some(ServerMessage::Error {
                id: None,
                error: ErrorPayload::new(ERR_INTERNAL, format!("invalid message: {e}")),
            });
        }
    };

    match client_msg {
        ClientMessage::Connect { auth: payload } => {
            match authenticate_connection(state, &payload).await {
                Ok((device_id, permissions)) => {
                    auth.session = Some(AuthSession {
                        device_id: device_id.clone(),
                        permissions,
                    });
                    Some(ServerMessage::Connected {
                        session_id: format!("ws-{device_id}"),
                    })
                }
                Err(message) => Some(ServerMessage::Error {
                    id: None,
                    error: ErrorPayload::new(ERR_AUTH_FAILED, message),
                }),
            }
        }
        ClientMessage::Req { id, method, params } => {
            let session = match auth.session.as_ref() {
                Some(session) => session,
                None => {
                    return Some(ServerMessage::Error {
                        id: Some(id),
                        error: ErrorPayload::new(
                            ERR_AUTH_FAILED,
                            "authentication required: send connect first",
                        ),
                    });
                }
            };

            #[cfg(test)]
            if method == "__panic_test__" {
                panic!("ws test panic");
            }

            let plugin_manager = { state.plugin_manager.read().await.clone() };
            if !is_method_allowed_with_plugin(
                &method,
                &params,
                &session.permissions,
                plugin_manager.as_deref(),
            ) {
                return Some(ServerMessage::Error {
                    id: Some(id),
                    error: ErrorPayload::new(
                        ERR_AUTH_FAILED,
                        format!("permission denied for method: {method}"),
                    ),
                });
            }

            let scoped_id = format!("{}:{id}", session.device_id);

            // Check idempotency cache
            {
                let cache = match state.idempotency.lock() {
                    Ok(cache) => cache,
                    Err(poisoned) => recover_poisoned_idempotency_cache(poisoned, "read"),
                };
                if let Some(cached) = cache.get(&scoped_id) {
                    return Some(ServerMessage::Res {
                        id: id.clone(),
                        result: cached.clone(),
                    });
                }
            }

            let response = dispatch_method(state, &method, params, &id, ws_sender.clone()).await;

            // Cache successful results
            if let ServerMessage::Res { ref result, .. } = response {
                let mut cache = match state.idempotency.lock() {
                    Ok(cache) => cache,
                    Err(poisoned) => recover_poisoned_idempotency_cache(poisoned, "write"),
                };
                cache.set(scoped_id, result.clone());
                cache.cleanup();
            }

            Some(response)
        }
        ClientMessage::Ping { seq } => Some(ServerMessage::Pong { seq }),
    }
}

async fn authenticate_connection(
    state: &AppState,
    payload: &AuthPayload,
) -> Result<(String, DevicePermissions), String> {
    let (verified_device_id, permissions) = state
        .nonce_store
        .verify_challenge(
            &payload.nonce,
            &payload.signature,
            state.device_store.as_ref(),
        )
        .await
        .map_err(|e| e.to_string())?;

    if verified_device_id != payload.device_id {
        return Err("device_id does not match nonce challenge".to_string());
    }

    Ok((verified_device_id, permissions))
}

#[cfg(test)]
pub(crate) fn is_method_allowed(
    method: &str,
    params: &serde_json::Value,
    permissions: &DevicePermissions,
) -> bool {
    is_method_allowed_with_plugin(method, params, permissions, None)
}

pub(crate) fn is_method_allowed_with_plugin(
    method: &str,
    params: &serde_json::Value,
    permissions: &DevicePermissions,
    plugin_manager: Option<&PluginManager>,
) -> bool {
    match method {
        "chat.send" => {
            let model_override = params
                .get("model")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .is_some_and(|s| !s.is_empty());
            if model_override {
                permissions.chat && is_admin(permissions)
            } else {
                permissions.chat
            }
        }
        "channels.status" => {
            let probe = params
                .get("probe")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if probe {
                is_admin(permissions)
            } else {
                permissions.chat
            }
        }
        "chat.history" | "chat.abort" | "sessions.list" | "sessions.create" | "sessions.delete"
        | "sessions.rename" | "models.list" | "nodes.list" | "memory.status" | "memory.search"
        | "channels.list" => permissions.chat,
        "nodes.invoke" => params
            .get("command")
            .and_then(|v| v.as_str())
            .map(|command| check_permission(command, permissions))
            .unwrap_or(false),
        "security.lockdown"
        | "security.audit"
        | "config.get"
        | "config.set"
        | "agents.list"
        | "agents.get"
        | "nodes.update_permissions"
        | "nodes.revoke"
        | "memory.list"
        | "memory.delete"
        | "cron.list"
        | "cron.create"
        | "cron.delete"
        | "cron.trigger"
        | "timeline.query"
        | "api_usage.query"
        | "keys.list"
        | "keys.set"
        | "keys.delete"
        | "config.set_inference_mode"
        | "backup.trigger"
        | "backup.list"
        | "skills.list"
        | "skills.toggle"
        | "approval.respond"
        | "timers.list"
        | "timers.toggle"
        | "plugins.status"
        | "plugins.reload"
        | "skills.metrics"
        | "skills.config.get"
        | "skills.config.set"
        | "skills.resources.get"
        | "skills.resources.set"
        | "channels.add"
        | "channels.remove"
        | "channels.login"
        | "channels.logout" => is_admin(permissions),
        _ => plugin_manager
            .map(|pm| pm.has_method(method) && is_admin(permissions))
            .unwrap_or(false),
    }
}

fn is_admin(permissions: &DevicePermissions) -> bool {
    permissions.admin
}

/// Send a server message through the WebSocket sender.
pub async fn send_message(
    sender: &Mutex<SplitSink<WebSocket, Message>>,
    msg: &ServerMessage,
) -> Result<(), axum::Error> {
    let json = serde_json::to_string(msg).unwrap_or_default();
    let mut s = sender.lock().await;
    s.send(Message::Text(json.into()))
        .await
        .map_err(axum::Error::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use async_trait::async_trait;
    use chrono::Utc;
    use encmind_agent::tool_registry::ToolRegistry;
    use encmind_core::error::PluginError;
    use encmind_core::hooks::HookRegistry;
    use encmind_core::plugin::{
        GatewayMethodHandler, NativePlugin, PluginKind, PluginManifest, PluginRegistrar,
    };
    use encmind_core::types::{DevicePermissions, PairedDevice};
    use encmind_crypto::challenge::sign_nonce;
    use encmind_crypto::device_id::DeviceId;
    use encmind_crypto::keypair::generate_keypair;

    async fn connect_message_with_device(
        state: &AppState,
        name: &str,
        permissions: DevicePermissions,
    ) -> String {
        let (signing, verifying) = generate_keypair();
        let device_id = DeviceId::from_verifying_key(&verifying);

        state
            .device_store
            .add_device(&PairedDevice {
                id: device_id.as_str().to_string(),
                name: name.to_string(),
                public_key: verifying.to_bytes().to_vec(),
                permissions,
                paired_at: Utc::now(),
                last_seen: None,
            })
            .await
            .unwrap();

        let nonce = state.nonce_store.issue_nonce(device_id.as_str());
        let nonce_bytes = hex::decode(&nonce).unwrap();
        let signature = sign_nonce(&signing, &nonce_bytes);

        serde_json::to_string(&ClientMessage::Connect {
            auth: AuthPayload {
                device_id: device_id.as_str().to_string(),
                nonce,
                signature: hex::encode(signature),
            },
        })
        .unwrap()
    }

    #[tokio::test]
    async fn process_connect_message() {
        let state = make_test_state();
        let msg = connect_message_with_device(
            &state,
            "dev-1",
            DevicePermissions {
                chat: true,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Connected { session_id } => {
                assert!(session_id.starts_with("ws-"));
            }
            _ => panic!("Expected Connected"),
        }
    }

    #[tokio::test]
    async fn process_ping_message() {
        let state = make_test_state();
        let mut auth = ConnectionAuth::default();
        let msg = serde_json::to_string(&ClientMessage::Ping { seq: 7 }).unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Pong { seq } => assert_eq!(seq, 7),
            _ => panic!("Expected Pong"),
        }
    }

    #[tokio::test]
    async fn process_req_dispatches() {
        let state = make_test_state();
        let connect = connect_message_with_device(
            &state,
            "dev-2",
            DevicePermissions {
                chat: true,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "r1".into(),
            method: "models.list".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "r1"),
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn process_invalid_json() {
        let state = make_test_state();
        let mut auth = ConnectionAuth::default();
        let result = process_text_message(&state, &mut auth, "not json", None)
            .await
            .unwrap();
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("invalid message"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn idempotency_dedup() {
        let state = make_test_state();
        let connect = connect_message_with_device(
            &state,
            "dev-3",
            DevicePermissions {
                chat: true,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "dedup-1".into(),
            method: "models.list".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        // First call
        let r1 = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        // Second call with same ID should return cached
        let r2 = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();

        match (&r1, &r2) {
            (ServerMessage::Res { result: res1, .. }, ServerMessage::Res { result: res2, .. }) => {
                assert_eq!(res1, res2);
            }
            _ => panic!("Expected matching Res"),
        }
    }

    #[tokio::test]
    async fn lockdown_blocks_ws_req() {
        let state = make_test_state();
        let connect = connect_message_with_device(
            &state,
            "dev-4",
            DevicePermissions {
                chat: true,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        state.lockdown.activate("test");

        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "locked-1".into(),
            method: "chat.send".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_LOCKDOWN);
            }
            _ => panic!("Expected lockdown error"),
        }
    }

    #[tokio::test]
    async fn rejects_request_without_connect() {
        let state = make_test_state();
        let mut auth = ConnectionAuth::default();
        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "unauth-1".into(),
            method: "models.list".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_AUTH_FAILED);
            }
            _ => panic!("Expected auth error"),
        }
    }

    #[tokio::test]
    async fn panic_recovery_resets_auth_and_preserves_request_id() {
        let state = make_test_state();
        let connect = connect_message_with_device(
            &state,
            "dev-panic",
            DevicePermissions {
                chat: true,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();

        let connected = process_text_message_with_recovery(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));
        assert!(auth.session.is_some(), "auth session should be established");

        let panic_req = serde_json::to_string(&ClientMessage::Req {
            id: "panic-1".into(),
            method: "__panic_test__".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let panic_result = process_text_message_with_recovery(&state, &mut auth, &panic_req, None)
            .await
            .unwrap();
        match panic_result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id.as_deref(), Some("panic-1"));
                assert_eq!(error.code, ERR_INTERNAL);
            }
            _ => panic!("Expected internal error from panic recovery"),
        }
        assert!(
            auth.session.is_none(),
            "auth session should be cleared after panic recovery"
        );

        let follow_up_req = serde_json::to_string(&ClientMessage::Req {
            id: "after-panic".into(),
            method: "models.list".into(),
            params: serde_json::json!({}),
        })
        .unwrap();
        let follow_up = process_text_message_with_recovery(&state, &mut auth, &follow_up_req, None)
            .await
            .unwrap();
        match follow_up {
            ServerMessage::Error { id, error } => {
                assert_eq!(id.as_deref(), Some("after-panic"));
                assert_eq!(error.code, ERR_AUTH_FAILED);
            }
            _ => panic!("Expected auth error after auth reset"),
        }
    }

    #[test]
    fn cron_methods_require_admin() {
        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };
        let params = serde_json::json!({});

        for method in &[
            "cron.list",
            "cron.create",
            "cron.delete",
            "cron.trigger",
            "timeline.query",
            "backup.trigger",
            "backup.list",
        ] {
            assert!(
                !is_method_allowed(method, &params, &chat_user),
                "{method} should require admin"
            );
            assert!(
                is_method_allowed(method, &params, &admin_user),
                "{method} should be allowed for admin"
            );
        }
    }

    #[test]
    fn memory_methods_require_expected_permissions() {
        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };
        let params = serde_json::json!({});

        assert!(is_method_allowed("memory.search", &params, &chat_user));
        assert!(is_method_allowed("memory.search", &params, &admin_user));
        assert!(!is_method_allowed("memory.list", &params, &chat_user));
        assert!(is_method_allowed("memory.list", &params, &admin_user));
        assert!(is_method_allowed("memory.status", &params, &chat_user));
        assert!(!is_method_allowed("memory.delete", &params, &chat_user));
        assert!(is_method_allowed("memory.delete", &params, &admin_user));
    }

    // ---- Test 10.5: Admin-only permission check for timeline.query via WS ----

    #[tokio::test]
    async fn timeline_query_rejected_for_chat_only_device() {
        let state = make_test_state();

        // 10.5a: Pair a chat-only (non-admin) device
        let connect = connect_message_with_device(
            &state,
            "chat-dev",
            DevicePermissions {
                chat: true,
                admin: false,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        // Send timeline.query
        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "tl-10-5a".into(),
            method: "timeline.query".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("tl-10-5a".into()));
                assert_eq!(error.code, ERR_AUTH_FAILED);
                assert!(error.message.contains("permission denied"));
            }
            _ => panic!("Expected Error for chat-only device, got {result:?}"),
        }
    }

    #[tokio::test]
    async fn timeline_query_allowed_for_admin_device() {
        let state = make_test_state();

        // 10.5b: Pair an admin device
        let connect = connect_message_with_device(
            &state,
            "admin-dev",
            DevicePermissions {
                chat: true,
                admin: true,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        // Send timeline.query
        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "tl-10-5b".into(),
            method: "timeline.query".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "tl-10-5b");
                assert!(result.is_array(), "expected array result");
            }
            _ => panic!("Expected Res for admin device, got {result:?}"),
        }
    }

    // ── 11: Session method permission tests ─────────────────

    #[tokio::test]
    async fn session_methods_allowed_for_chat_device() {
        let state = make_test_state();
        let connect = connect_message_with_device(
            &state,
            "chat-only-dev",
            DevicePermissions {
                chat: true,
                admin: false,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "s-perm-1".into(),
            method: "sessions.list".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Res { id, .. } => assert_eq!(id, "s-perm-1"),
            other => panic!("expected Res for chat device, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_methods_blocked_without_chat_permission() {
        let state = make_test_state();
        let connect = connect_message_with_device(
            &state,
            "no-chat-dev",
            DevicePermissions {
                chat: false,
                admin: false,
                ..Default::default()
            },
        )
        .await;
        let mut auth = ConnectionAuth::default();
        let connected = process_text_message(&state, &mut auth, &connect, None)
            .await
            .unwrap();
        assert!(matches!(connected, ServerMessage::Connected { .. }));

        let msg = serde_json::to_string(&ClientMessage::Req {
            id: "s-perm-2".into(),
            method: "sessions.list".into(),
            params: serde_json::json!({}),
        })
        .unwrap();

        let result = process_text_message(&state, &mut auth, &msg, None)
            .await
            .unwrap();
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_AUTH_FAILED);
                assert!(error.message.contains("permission denied"));
            }
            other => panic!("expected Error for no-chat device, got {other:?}"),
        }
    }

    #[test]
    fn skills_and_approval_methods_require_admin() {
        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };
        let params = serde_json::json!({});

        for method in &[
            "skills.list",
            "approval.respond",
            "timers.list",
            "timers.toggle",
            "plugins.reload",
            "skills.metrics",
            "skills.config.get",
            "skills.config.set",
            "skills.resources.get",
            "skills.resources.set",
        ] {
            assert!(
                !is_method_allowed(method, &params, &chat_user),
                "{method} should require admin"
            );
            assert!(
                is_method_allowed(method, &params, &admin_user),
                "{method} should be allowed for admin"
            );
        }
    }

    #[test]
    fn chat_send_model_override_requires_admin() {
        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };

        assert!(is_method_allowed(
            "chat.send",
            &serde_json::json!({}),
            &chat_user
        ));
        assert!(!is_method_allowed(
            "chat.send",
            &serde_json::json!({"model": "gpt-4o-mini"}),
            &chat_user
        ));
        assert!(is_method_allowed(
            "chat.send",
            &serde_json::json!({"model": "gpt-4o-mini"}),
            &admin_user
        ));
    }

    struct MethodPlugin;
    #[async_trait]
    impl NativePlugin for MethodPlugin {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "method".into(),
                name: "Method Plugin".into(),
                version: "0.1.0".into(),
                description: "test".into(),
                kind: PluginKind::General,
                required: true,
            }
        }

        async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
            struct Handler;
            #[async_trait]
            impl GatewayMethodHandler for Handler {
                async fn handle(
                    &self,
                    _params: serde_json::Value,
                ) -> Result<serde_json::Value, PluginError> {
                    Ok(serde_json::json!({"ok": true}))
                }
            }
            api.register_gateway_method("plugin.echo", Arc::new(Handler))
        }
    }

    #[tokio::test]
    async fn plugin_methods_require_admin_permissions() {
        let mut tr = ToolRegistry::new();
        let mut hr = HookRegistry::new();
        let pm = crate::plugin_manager::PluginManager::initialize(
            vec![Box::new(MethodPlugin)],
            &mut tr,
            &mut hr,
            std::collections::HashMap::new(),
        )
        .await
        .unwrap();

        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };
        let params = serde_json::json!({});

        assert!(!is_method_allowed_with_plugin(
            "plugin.echo",
            &params,
            &chat_user,
            Some(&pm),
        ));
        assert!(is_method_allowed_with_plugin(
            "plugin.echo",
            &params,
            &admin_user,
            Some(&pm),
        ));
    }

    #[test]
    fn plugins_methods_require_admin() {
        let chat_user = DevicePermissions {
            chat: true,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            admin: true,
            chat: true,
            ..Default::default()
        };
        let params = serde_json::json!({});

        assert!(!is_method_allowed("plugins.status", &params, &chat_user));
        assert!(is_method_allowed("plugins.status", &params, &admin_user));
        assert!(!is_method_allowed("plugins.reload", &params, &chat_user));
        assert!(is_method_allowed("plugins.reload", &params, &admin_user));
    }

    #[test]
    fn channel_methods_permissions() {
        let chat_user = DevicePermissions {
            chat: true,
            admin: false,
            ..Default::default()
        };
        let admin_user = DevicePermissions {
            chat: true,
            admin: true,
            ..Default::default()
        };
        let params = serde_json::json!({});
        let probe_params = serde_json::json!({"probe": true});

        // chat-level: channels.list and channels.status
        assert!(is_method_allowed("channels.list", &params, &chat_user));
        assert!(is_method_allowed("channels.list", &params, &admin_user));
        assert!(is_method_allowed("channels.status", &params, &chat_user));
        assert!(is_method_allowed("channels.status", &params, &admin_user));
        // probing mutates runtime/account status and requires admin
        assert!(!is_method_allowed(
            "channels.status",
            &probe_params,
            &chat_user
        ));
        assert!(is_method_allowed(
            "channels.status",
            &probe_params,
            &admin_user
        ));

        // admin-only: channels.add, channels.remove, channels.login, channels.logout
        assert!(!is_method_allowed("channels.add", &params, &chat_user));
        assert!(is_method_allowed("channels.add", &params, &admin_user));
        assert!(!is_method_allowed("channels.remove", &params, &chat_user));
        assert!(is_method_allowed("channels.remove", &params, &admin_user));
        assert!(!is_method_allowed("channels.login", &params, &chat_user));
        assert!(is_method_allowed("channels.login", &params, &admin_user));
        assert!(!is_method_allowed("channels.logout", &params, &chat_user));
        assert!(is_method_allowed("channels.logout", &params, &admin_user));
    }
}
