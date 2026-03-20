use crate::protocol::*;
use crate::state::AppState;
use tracing::warn;

pub async fn handle_trigger(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let mgr = match &state.backup_manager {
        Some(mgr) => mgr.clone(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    "backup is not enabled in server configuration",
                ),
            };
        }
    };

    let info = match tokio::task::spawn_blocking({
        let mgr = mgr.clone();
        move || mgr.create_backup()
    })
    .await
    {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("backup failed: {e}")),
            };
        }
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, format!("backup task failed: {e}")),
            };
        }
    };

    // Apply retention after backup and surface failures explicitly.
    let (deleted, retention_error) = match tokio::task::spawn_blocking({
        let mgr = mgr.clone();
        move || mgr.apply_retention()
    })
    .await
    {
        Ok(Ok(count)) => (count, None),
        Ok(Err(e)) => {
            warn!(
                backup_id = %info.id,
                error = %e,
                "backup created but retention cleanup failed"
            );
            (0, Some(e.to_string()))
        }
        Err(e) => {
            warn!(
                backup_id = %info.id,
                error = %e,
                "backup created but retention task failed"
            );
            (0, Some(format!("retention task failed: {e}")))
        }
    };

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "id": info.id,
            "filename": info.filename,
            "created_at": info.created_at.to_rfc3339(),
            "size_bytes": info.size_bytes,
            "encrypted": info.encrypted,
            "retention_deleted": deleted,
            "retention_error": retention_error,
        }),
    }
}

pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let mgr = match &state.backup_manager {
        Some(mgr) => mgr.clone(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    "backup is not enabled in server configuration",
                ),
            };
        }
    };

    match tokio::task::spawn_blocking(move || mgr.list_backups()).await {
        Ok(Ok(backups)) => {
            let list: Vec<serde_json::Value> = backups
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "id": b.id,
                        "filename": b.filename,
                        "created_at": b.created_at.to_rfc3339(),
                        "size_bytes": b.size_bytes,
                        "encrypted": b.encrypted,
                    })
                })
                .collect();
            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!(list),
            }
        }
        Ok(Err(e)) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("list backups failed: {e}")),
        },
        Err(e) => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("list backups task failed: {e}")),
        },
    }
}
