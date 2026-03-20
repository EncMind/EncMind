use std::sync::Arc;

use encmind_core::channel_credentials::{
    is_supported_channel_type, merge_and_validate_channel_credentials, ChannelCredentialError,
};
use encmind_core::error::StorageError;
use encmind_core::types::{ChannelAccount, ChannelAccountId, ChannelAccountStatus, ConfigSource};

use crate::protocol::*;
use crate::state::AppState;

/// Helper to resolve an account by ID or channel_type.
async fn resolve_account(
    state: &AppState,
    id_or_type: &str,
) -> Result<ChannelAccount, ServerMessage> {
    let store = state.channel_account_store.as_ref().unwrap();
    match store
        .get_account(&ChannelAccountId::from_string(id_or_type))
        .await
    {
        Ok(Some(a)) => return Ok(a),
        Ok(None) => {}
        Err(e) => {
            return Err(ServerMessage::Error {
                id: None,
                error: ErrorPayload::new(ERR_INTERNAL, format!("failed to look up account: {e}")),
            })
        }
    }
    // Fall back to type lookup
    match store.get_account_by_type(id_or_type).await {
        Ok(Some(a)) => Ok(a),
        Ok(None) => Err(ServerMessage::Error {
            id: None,
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "account not found"),
        }),
        Err(StorageError::InvalidData(msg)) => Err(ServerMessage::Error {
            id: None,
            error: ErrorPayload::new(ERR_INVALID_PARAMS, msg),
        }),
        Err(e) => Err(ServerMessage::Error {
            id: None,
            error: ErrorPayload::new(ERR_INTERNAL, format!("failed to look up account: {e}")),
        }),
    }
}

macro_rules! require_store {
    ($state:expr, $req_id:expr) => {
        match $state.channel_account_store.as_ref() {
            Some(s) => s,
            None => {
                return ServerMessage::Error {
                    id: Some($req_id.to_string()),
                    error: ErrorPayload::new(ERR_INTERNAL, "channel account store not enabled"),
                }
            }
        }
    };
}

fn status_str(status: &ChannelAccountStatus) -> &'static str {
    match status {
        ChannelAccountStatus::Active => "active",
        ChannelAccountStatus::Degraded => "degraded",
        ChannelAccountStatus::Stopped => "stopped",
        ChannelAccountStatus::LoginRequired => "login_required",
        ChannelAccountStatus::Error => "error",
    }
}

/// Spawn the channel inbound loop for a newly started adapter via the manager.
fn spawn_channel_loop(
    state: &AppState,
    channel_type: &str,
) -> impl FnOnce(
    Arc<dyn encmind_core::traits::ChannelAdapter>,
    tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let runtime_state = state.clone();
    let router = state.channel_router.clone();
    let shutdown = state.channel_manager.global_shutdown().clone();
    let channel_name = channel_type.to_string();

    move |adapter, cancel| {
        let inbound = adapter.inbound();
        let cn = channel_name.clone();
        tokio::spawn(async move {
            if let Some(router) = router {
                crate::server::channel_inbound_loop(
                    runtime_state,
                    router,
                    adapter,
                    cn,
                    inbound,
                    shutdown,
                    cancel,
                )
                .await;
            }
        })
    }
}

pub async fn handle_list(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let store = require_store!(state, req_id);
    if let Some(obj) = params.as_object() {
        if let Some(key) = obj.keys().next() {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, format!("unknown parameter: {key}")),
            };
        }
    }

    match store.list_accounts().await {
        Ok(accounts) => ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::to_value(accounts).unwrap_or_default(),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("failed to list channels: {e}")),
        },
    }
}

pub async fn handle_add(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let store = require_store!(state, req_id);
    if let Some(obj) = params.as_object() {
        for key in obj.keys() {
            if !matches!(key.as_str(), "channel_type" | "label") {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown parameter: {key}"),
                    ),
                };
            }
        }
    }

    let channel_type = match params.get("channel_type").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "channel_type is required"),
            }
        }
    };
    if !is_supported_channel_type(&channel_type) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INVALID_PARAMS,
                format!("unsupported channel_type: {channel_type}"),
            ),
        };
    }

    let label = params
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or(&channel_type)
        .to_string();

    let account = ChannelAccount {
        id: ChannelAccountId::new(),
        channel_type: channel_type.clone(),
        label: label.clone(),
        enabled: true,
        status: ChannelAccountStatus::Stopped,
        config_source: ConfigSource::Api,
        policy: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    if let Err(e) = store.create_account(&account).await {
        let error = match e {
            StorageError::InvalidData(msg) => ErrorPayload::new(ERR_INVALID_PARAMS, msg),
            other => ErrorPayload::new(ERR_INTERNAL, format!("failed to create account: {other}")),
        };
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error,
        };
    }

    let _ = state.audit.append(
        "channel",
        "add",
        Some(&format!("type={channel_type} label={label}")),
        None,
    );

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "id": account.id.as_str(),
            "channel_type": account.channel_type,
            "label": account.label,
            "status": "stopped",
        }),
    }
}

pub async fn handle_remove(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let store = require_store!(state, req_id);
    if let Some(obj) = params.as_object() {
        for key in obj.keys() {
            if !matches!(key.as_str(), "id") {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown parameter: {key}"),
                    ),
                };
            }
        }
    }

    let id = match params.get("id").and_then(|v| v.as_str()) {
        Some(id) => ChannelAccountId::from_string(id),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            }
        }
    };

    let account = match store.get_account(&id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "account not found"),
            }
        }
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("failed to get account: {e}")),
            }
        }
    };

    let channel_type = account.channel_type.clone();
    let response = {
        // Serialize remove against concurrent login/logout on the same channel type.
        let _channel_guard = state.channel_manager.lock_channel(&channel_type).await;
        async {
            // Stop adapter if running (best-effort)
            state
                .channel_manager
                .stop_adapter_locked(&channel_type)
                .await;

            // Delete credential (best-effort)
            let _ = store.delete_credential(&id).await;

            if let Err(e) = store.delete_account(&id).await {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INTERNAL,
                        format!("failed to delete account: {e}"),
                    ),
                };
            }

            let _ = state
                .audit
                .append("channel", "remove", Some(&format!("id={id}")), None);

            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({ "deleted": true }),
            }
        }
        .await
    };
    state
        .channel_manager
        .prune_channel_lock_if_idle(&channel_type)
        .await;
    response
}

pub async fn handle_login(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let store = require_store!(state, req_id);
    if let Some(obj) = params.as_object() {
        for key in obj.keys() {
            if !matches!(
                key.as_str(),
                "id" | "bot_token" | "app_token" | "client_id" | "client_secret" | "refresh_token"
            ) {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown parameter: {key}"),
                    ),
                };
            }
        }
    }

    let id_or_type = match params.get("id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            }
        }
    };

    let account = match resolve_account(state, &id_or_type).await {
        Ok(a) => a,
        Err(mut e) => {
            if let ServerMessage::Error { id, .. } = &mut e {
                *id = Some(req_id.to_string());
            }
            return e;
        }
    };
    if !is_supported_channel_type(&account.channel_type) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INVALID_PARAMS,
                format!("unsupported channel_type: {}", account.channel_type),
            ),
        };
    }
    let channel_type = account.channel_type.clone();
    let response = {
        // Serialize credential + adapter lifecycle updates for this channel type.
        let _channel_guard = state.channel_manager.lock_channel(&channel_type).await;
        async {
            // Build incoming credential JSON from params
            let mut incoming_cred = serde_json::Map::new();
            if let Some(bt) = params.get("bot_token").and_then(|v| v.as_str()) {
                incoming_cred.insert("bot_token".into(), serde_json::Value::String(bt.into()));
            }
            if let Some(at) = params.get("app_token").and_then(|v| v.as_str()) {
                incoming_cred.insert("app_token".into(), serde_json::Value::String(at.into()));
            }
            if let Some(ci) = params.get("client_id").and_then(|v| v.as_str()) {
                incoming_cred.insert("client_id".into(), serde_json::Value::String(ci.into()));
            }
            if let Some(cs) = params.get("client_secret").and_then(|v| v.as_str()) {
                incoming_cred.insert("client_secret".into(), serde_json::Value::String(cs.into()));
            }
            if let Some(rt) = params.get("refresh_token").and_then(|v| v.as_str()) {
                incoming_cred.insert("refresh_token".into(), serde_json::Value::String(rt.into()));
            }

            // Merge with existing credentials so partial updates don't clobber required fields.
            let existing_cred = match store.get_credential(&account.id).await {
                Ok(cred) => cred,
                Err(e) => {
                    let _ = store
                        .update_status(&account.id, ChannelAccountStatus::Error)
                        .await;
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INTERNAL,
                            format!("failed to load existing credential: {e}"),
                        ),
                    };
                }
            };
            if incoming_cred.is_empty() && existing_cred.is_none() {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        "at least one credential is required on first login",
                    ),
                };
            }

            let merged_cred = match merge_and_validate_channel_credentials(
                &account.channel_type,
                existing_cred.as_deref(),
                incoming_cred,
            ) {
                Ok(merged) => merged,
                Err(err @ ChannelCredentialError::UnsupportedChannelType(_))
                | Err(err @ ChannelCredentialError::MissingRequiredField(_))
                | Err(err @ ChannelCredentialError::UnexpectedCredentialField(_)) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(ERR_INVALID_PARAMS, err.to_string()),
                    };
                }
                Err(ChannelCredentialError::InvalidStoredCredentialJson(_))
                | Err(ChannelCredentialError::StoredCredentialNotObject) => {
                    let _ = store
                        .update_status(&account.id, ChannelAccountStatus::Error)
                        .await;
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INTERNAL,
                            "stored credential is corrupted; please logout and login again",
                        ),
                    };
                }
            };
            let cred_json = match serde_json::to_string(&merged_cred) {
                Ok(json) => json,
                Err(e) => {
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INTERNAL,
                            format!("failed to serialize credentials: {e}"),
                        ),
                    };
                }
            };

            // Construct adapter from credentials
            let config = { state.config.read().await.clone() };
            let adapter = match encmind_channels::adapter_from_credentials(
                &account.channel_type,
                &config,
                &cred_json,
            ) {
                Ok(a) => a,
                Err(e) => {
                    let _ = store
                        .update_status(&account.id, ChannelAccountStatus::Error)
                        .await;
                    let _ = state.audit.append(
                        "channel",
                        "login",
                        Some(&format!(
                            "id={} type={} error=construct_failed: {}",
                            account.id, account.channel_type, e
                        )),
                        None,
                    );
                    return ServerMessage::Error {
                        id: Some(req_id.to_string()),
                        error: ErrorPayload::new(
                            ERR_INVALID_PARAMS,
                            format!("failed to construct adapter: {e}"),
                        ),
                    };
                }
            };

            // Persist credential after adapter construction succeeds. Probe/start can still fail
            // due transient network/runtime errors; in that case we may roll back below.
            if let Err(e) = store.store_credential(&account.id, &cred_json).await {
                let _ = store
                    .update_status(&account.id, ChannelAccountStatus::Error)
                    .await;
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INTERNAL,
                        format!("failed to store credential: {e}"),
                    ),
                };
            };
            let had_running_adapter = state
                .channel_manager
                .is_running(&account.channel_type)
                .await;

            // Probe the adapter before starting
            let new_status = match adapter.probe().await {
                Ok(()) => {
                    // Start adapter via manager
                    let spawn = spawn_channel_loop(state, &account.channel_type);
                    match state
                        .channel_manager
                        .start_adapter_locked(&account.channel_type, adapter, spawn)
                        .await
                    {
                        Ok(()) => ChannelAccountStatus::Active,
                        Err(e) => {
                            tracing::warn!(
                                channel = %account.channel_type,
                                error = %e,
                                "failed to start adapter after successful probe"
                            );
                            ChannelAccountStatus::Error
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        channel = %account.channel_type,
                        error = %e,
                        "adapter probe failed; not starting"
                    );
                    // If an adapter was already running for this channel, avoid persisting
                    // unverified credentials and roll back to the previously stored value.
                    let mut rollback_succeeded = false;
                    if had_running_adapter {
                        let rollback_result = match existing_cred.as_deref() {
                            Some(prev) => store.store_credential(&account.id, prev).await,
                            None => store.delete_credential(&account.id).await,
                        };
                        match rollback_result {
                            Ok(()) => {
                                rollback_succeeded = true;
                            }
                            Err(rollback_err) => {
                                tracing::warn!(
                                    channel = %account.channel_type,
                                    account_id = %account.id,
                                    error = %rollback_err,
                                    "failed to roll back credentials after probe failure"
                                );
                            }
                        }
                    }
                    if had_running_adapter && rollback_succeeded {
                        ChannelAccountStatus::Active
                    } else {
                        ChannelAccountStatus::Degraded
                    }
                }
            };

            let _ = store.update_status(&account.id, new_status.clone()).await;

            let _ = state.audit.append(
                "channel",
                "login",
                Some(&format!(
                    "id={} type={} status={}",
                    account.id,
                    account.channel_type,
                    status_str(&new_status)
                )),
                None,
            );

            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({
                    "id": account.id.as_str(),
                    "status": status_str(&new_status),
                }),
            }
        }
        .await
    };
    state
        .channel_manager
        .prune_channel_lock_if_idle(&channel_type)
        .await;
    response
}

pub async fn handle_logout(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let store = require_store!(state, req_id);
    if let Some(obj) = params.as_object() {
        for key in obj.keys() {
            if !matches!(key.as_str(), "id") {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown parameter: {key}"),
                    ),
                };
            }
        }
    }

    let id_or_type = match params.get("id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "id is required"),
            }
        }
    };

    let account = match resolve_account(state, &id_or_type).await {
        Ok(a) => a,
        Err(mut e) => {
            if let ServerMessage::Error { id, .. } = &mut e {
                *id = Some(req_id.to_string());
            }
            return e;
        }
    };

    let channel_type = account.channel_type.clone();
    let response = {
        // Serialize logout against concurrent login/remove on the same channel type.
        let _channel_guard = state.channel_manager.lock_channel(&channel_type).await;
        async {
            // Stop adapter (best-effort, don't fail logout)
            state
                .channel_manager
                .stop_adapter_locked(&channel_type)
                .await;

            // Delete credentials
            if let Err(e) = store.delete_credential(&account.id).await {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INTERNAL,
                        format!("failed to delete credential: {e}"),
                    ),
                };
            }

            // Always set status to Stopped
            let _ = store
                .update_status(&account.id, ChannelAccountStatus::Stopped)
                .await;

            let _ = state.audit.append(
                "channel",
                "logout",
                Some(&format!("id={} type={}", account.id, account.channel_type)),
                None,
            );

            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({
                    "id": account.id.as_str(),
                    "status": "stopped",
                }),
            }
        }
        .await
    };
    state
        .channel_manager
        .prune_channel_lock_if_idle(&channel_type)
        .await;
    response
}

pub async fn handle_status(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let store = require_store!(state, req_id);
    if let Some(obj) = params.as_object() {
        for key in obj.keys() {
            if !matches!(key.as_str(), "id" | "probe") {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INVALID_PARAMS,
                        format!("unknown parameter: {key}"),
                    ),
                };
            }
        }
    }

    let id_or_type = match params.get("id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return handle_list(state, serde_json::json!({}), req_id).await,
    };

    let mut account = match resolve_account(state, &id_or_type).await {
        Ok(a) => a,
        Err(mut e) => {
            if let ServerMessage::Error { id, .. } = &mut e {
                *id = Some(req_id.to_string());
            }
            return e;
        }
    };

    let probe = params
        .get("probe")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let runtime_adapter = state
        .channel_manager
        .get_adapter(&account.channel_type)
        .await;
    if let Some(adapter) = runtime_adapter.as_ref() {
        if adapter.health_status() == ChannelAccountStatus::Degraded
            && account.status != ChannelAccountStatus::Degraded
        {
            let _ = store
                .update_status(&account.id, ChannelAccountStatus::Degraded)
                .await;
            account.status = ChannelAccountStatus::Degraded;
        }
    }

    let mut probe_result: Option<serde_json::Value> = None;
    if probe {
        let adapter = runtime_adapter.clone();

        match adapter {
            Some(adapter) => match adapter.probe().await {
                Ok(()) => {
                    let _ = store
                        .update_status(&account.id, ChannelAccountStatus::Active)
                        .await;
                    account.status = ChannelAccountStatus::Active;
                    probe_result = Some(serde_json::json!({ "ok": true }));
                    let _ = state.audit.append(
                        "channel",
                        "probe",
                        Some(&format!(
                            "id={} type={} ok=true",
                            account.id, account.channel_type
                        )),
                        None,
                    );
                }
                Err(e) => {
                    let _ = store
                        .update_status(&account.id, ChannelAccountStatus::Degraded)
                        .await;
                    account.status = ChannelAccountStatus::Degraded;
                    probe_result = Some(serde_json::json!({
                        "ok": false,
                        "error": e.to_string(),
                    }));
                    let _ = state.audit.append(
                        "channel",
                        "probe",
                        Some(&format!(
                            "id={} type={} ok=false error={}",
                            account.id, account.channel_type, e
                        )),
                        None,
                    );
                }
            },
            None => {
                let status_if_missing = match store.get_credential(&account.id).await {
                    Ok(Some(_)) => ChannelAccountStatus::Degraded,
                    Ok(None) => ChannelAccountStatus::LoginRequired,
                    Err(e) => {
                        tracing::warn!(
                            channel = %account.channel_type,
                            account_id = %account.id,
                            error = %e,
                            "failed to inspect credentials for missing adapter probe"
                        );
                        account.status.clone()
                    }
                };
                if status_if_missing != account.status {
                    let _ = store
                        .update_status(&account.id, status_if_missing.clone())
                        .await;
                    account.status = status_if_missing;
                }
                probe_result = Some(serde_json::json!({
                    "ok": false,
                    "error": "adapter not running",
                }));
                let _ = state.audit.append(
                    "channel",
                    "probe",
                    Some(&format!(
                        "id={} type={} ok=false error=adapter_not_running",
                        account.id, account.channel_type
                    )),
                    None,
                );
            }
        }
    }

    // Enrich status with runtime running state
    let is_running = state
        .channel_manager
        .is_running(&account.channel_type)
        .await;

    let mut result = serde_json::to_value(&account).unwrap_or_default();
    result["running"] = serde_json::Value::Bool(is_running);
    if let Some(probe) = probe_result {
        result["probe"] = probe;
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result,
    }
}
