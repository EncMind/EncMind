use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit};
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::node::{NodeClientMessage, NodeServerMessage};
use crate::state::AppState;

/// WebSocket endpoint for local node clients.
pub async fn node_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.connection_permits.clone().try_acquire_owned() {
        Ok(permit) => ws
            .on_upgrade(move |socket| handle_node_connection(socket, state, permit))
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "connection limit reached; try again later",
        )
            .into_response(),
    }
}

async fn handle_node_connection(socket: WebSocket, state: AppState, _permit: OwnedSemaphorePermit) {
    struct PendingRegistration {
        device_id: String,
        name: String,
        nonce: String,
    }

    let heartbeat_interval = {
        let cfg = state.config.read().await;
        Duration::from_millis(cfg.gateway.heartbeat_interval_ms.max(1000))
    };
    let idle_timeout = Duration::from_secs(90);

    let (sender, mut receiver) = socket.split();
    let sender = Arc::new(Mutex::new(sender));
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<NodeServerMessage>();
    let cancel = CancellationToken::new();

    let send_sender = sender.clone();
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx_out.recv().await {
            let Ok(json) = serde_json::to_string(&msg) else {
                continue;
            };
            let mut sink = send_sender.lock().await;
            if sink.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    let heartbeat_sender = sender.clone();
    let heartbeat_cancel = cancel.clone();
    let heartbeat_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(heartbeat_interval);
        loop {
            tokio::select! {
                _ = heartbeat_cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let mut sink = heartbeat_sender.lock().await;
                    if sink.send(Message::Ping(Bytes::from_static(b"node-hb"))).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut registered_device_id: Option<String> = None;
    let mut registered_connection_id: Option<String> = None;
    let mut pending_registration: Option<PendingRegistration> = None;
    let mut last_rx = Instant::now();
    let mut idle_check = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = idle_check.tick() => {
                if last_rx.elapsed() > idle_timeout {
                    warn!(
                        device_id = ?registered_device_id,
                        timeout_secs = idle_timeout.as_secs(),
                        "node connection idle timeout exceeded"
                    );
                    break;
                }
            }
            maybe_msg = receiver.next() => {
                let Some(Ok(msg)) = maybe_msg else { break; };
                match msg {
                    Message::Text(text) => {
                        last_rx = Instant::now();
                        let parsed: NodeClientMessage = match serde_json::from_str(&text) {
                            Ok(m) => m,
                            Err(e) => {
                                let _ = tx_out.send(NodeServerMessage::Error {
                                    message: format!("invalid message: {e}"),
                                });
                                continue;
                            }
                        };

                        match parsed {
                            NodeClientMessage::Register { device_id, name } => {
                                if registered_device_id.is_some() {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "already registered".to_string(),
                                    });
                                    continue;
                                }

                                if pending_registration.is_some() {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "registration challenge already pending".to_string(),
                                    });
                                    continue;
                                }

                                let device_id = device_id.trim().to_string();
                                let name = name.trim().to_string();
                                if device_id.is_empty() || name.is_empty() {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "device_id and name are required".to_string(),
                                    });
                                    continue;
                                }

                                match state.device_store.get_device(&device_id).await {
                                    Ok(Some(_)) => {
                                        let nonce = state.nonce_store.issue_nonce(&device_id);
                                        pending_registration = Some(PendingRegistration {
                                            device_id: device_id.clone(),
                                            name,
                                            nonce: nonce.clone(),
                                        });
                                        let _ = tx_out.send(NodeServerMessage::AuthChallenge {
                                            device_id,
                                            nonce,
                                        });
                                    }
                                    Ok(None) => {
                                        let _ = tx_out.send(NodeServerMessage::Error {
                                            message: "device not paired".to_string(),
                                        });
                                        break;
                                    }
                                    Err(e) => {
                                        let _ = tx_out.send(NodeServerMessage::Error {
                                            message: format!("device lookup failed: {e}"),
                                        });
                                        break;
                                    }
                                }
                            }
                            NodeClientMessage::RegisterAuth {
                                device_id,
                                nonce,
                                signature,
                            } => {
                                if registered_device_id.is_some() {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "already registered".to_string(),
                                    });
                                    continue;
                                }

                                let Some(pending) = pending_registration.take() else {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "send register first".to_string(),
                                    });
                                    continue;
                                };

                                if device_id.trim() != pending.device_id || nonce != pending.nonce {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "registration challenge mismatch".to_string(),
                                    });
                                    break;
                                }

                                let verified = state
                                    .nonce_store
                                    .verify_challenge(
                                        &nonce,
                                        &signature,
                                        state.device_store.as_ref(),
                                    )
                                    .await;
                                match verified {
                                    Ok((verified_device_id, _permissions))
                                        if verified_device_id == pending.device_id =>
                                    {
                                        let connection_id = state
                                            .node_registry
                                            .register(
                                                &pending.device_id,
                                                &pending.name,
                                                tx_out.clone(),
                                            )
                                            .await;
                                        let _ = state
                                            .device_store
                                            .update_last_seen(&pending.device_id, Utc::now())
                                            .await;
                                        registered_connection_id = Some(connection_id);
                                        registered_device_id = Some(pending.device_id.clone());
                                        let _ = tx_out.send(NodeServerMessage::Registered {
                                            device_id: pending.device_id,
                                        });
                                    }
                                    Ok(_) => {
                                        let _ = tx_out.send(NodeServerMessage::Error {
                                            message: "device_id mismatch".to_string(),
                                        });
                                        break;
                                    }
                                    Err(e) => {
                                        let _ = tx_out.send(NodeServerMessage::Error {
                                            message: format!("authentication failed: {e}"),
                                        });
                                        break;
                                    }
                                }
                            }
                            NodeClientMessage::CommandResult { request_id, result } => {
                                let Some(device_id) = registered_device_id.as_deref() else {
                                    let _ = tx_out.send(NodeServerMessage::Error {
                                        message: "register first".to_string(),
                                    });
                                    continue;
                                };
                                state
                                    .node_registry
                                    .complete_command(device_id, &request_id, result)
                                    .await;
                            }
                        }
                    }
                    Message::Ping(payload) => {
                        last_rx = Instant::now();
                        let mut sink = sender.lock().await;
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Message::Pong(_) => {
                        last_rx = Instant::now();
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    if let (Some(device_id), Some(connection_id)) = (registered_device_id, registered_connection_id)
    {
        info!(%device_id, %connection_id, "node disconnected");
        state
            .node_registry
            .unregister(&device_id, &connection_id)
            .await;
    }

    cancel.cancel();
    drop(tx_out);
    if let Err(e) = heartbeat_task.await {
        if !e.is_cancelled() {
            warn!("node heartbeat task failed: {e}");
        }
    }
    if let Err(e) = send_task.await {
        if !e.is_cancelled() {
            warn!("node sender task failed: {e}");
        }
    }
}
