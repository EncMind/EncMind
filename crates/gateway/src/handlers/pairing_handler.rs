use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use ulid::Ulid;

use crate::pairing::{PairingError, PairingSession};
use crate::state::AppState;

/// Maximum age for a pairing session before it expires.
const PAIRING_TTL: std::time::Duration = std::time::Duration::from_secs(300); // 5 minutes
/// Hard cap to limit in-memory growth under pairing spam.
const MAX_PAIRING_SESSIONS: usize = 1024;

#[derive(Debug, Deserialize)]
pub struct PairStartRequest {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct PairConfirmRequest {
    pub pairing_id: String,
    pub code: String,
}

/// Start a pairing flow by validating the submitted public key and issuing a pairing code.
pub async fn pair_start(
    State(state): State<AppState>,
    Json(req): Json<PairStartRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if req.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name is required"})),
        ));
    }

    let session = PairingSession::new(&req.public_key, req.name.trim()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;

    let pairing_id = Ulid::new().to_string();
    let device_id = session.device_id.clone();
    let pairing_code = session.code.clone();
    {
        let mut sessions = state.pairing_sessions.lock().unwrap();
        // Garbage-collect expired sessions
        sessions.retain(|_, s| s.created_at.elapsed() < PAIRING_TTL);
        if sessions.len() >= MAX_PAIRING_SESSIONS {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "too many pending pairing sessions"})),
            ));
        }
        sessions.insert(pairing_id.clone(), session);
    }

    tracing::info!(
        pairing_id = %pairing_id,
        device_id = %device_id,
        pairing_code = %pairing_code,
        "pairing session created"
    );

    let body = serde_json::json!({
        "pairing_id": pairing_id,
        "device_id": device_id,
    });

    Ok(Json(body))
}

/// Confirm a pending pairing flow and persist the paired device.
pub async fn pair_confirm(
    State(state): State<AppState>,
    Json(req): Json<PairConfirmRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Remove the session atomically — prevents brute-force: one attempt per session.
    let session = {
        let mut sessions = state.pairing_sessions.lock().unwrap();
        // Garbage-collect expired sessions while we hold the lock
        sessions.retain(|_, s| s.created_at.elapsed() < PAIRING_TTL);
        sessions.remove(req.pairing_id.trim())
    }
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "pairing session not found or expired"})),
        )
    })?;

    // Check TTL (in case it was just at the boundary)
    if session.created_at.elapsed() >= PAIRING_TTL {
        return Err((
            StatusCode::GONE,
            Json(serde_json::json!({"error": "pairing session expired"})),
        ));
    }

    let default_perms = {
        let config = state.config.read().await;
        config.gateway.default_device_permissions.clone()
    };
    let device_id = session
        .complete(req.code.trim(), state.device_store.as_ref(), &default_perms)
        .await
        .map_err(|e| {
            let status = match &e {
                PairingError::IncorrectCode => StatusCode::UNAUTHORIZED,
                PairingError::StorageFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(serde_json::json!({"error": e.to_string()})))
        })?;

    // Bootstrap admin access safely under concurrency. We serialize this check/update
    // across pair confirmations so exactly one "first admin" decision is made.
    let _bootstrap_guard = state.admin_bootstrap_lock.lock().await;
    let devices = state.device_store.list_devices().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    let has_admin = devices.iter().any(|d| d.permissions.admin);
    if !has_admin {
        if let Some(current) = devices.iter().find(|d| d.id == device_id) {
            let mut perms = current.permissions.clone();
            if !perms.admin {
                perms.admin = true;
                state
                    .device_store
                    .update_permissions(&device_id, &perms)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": e.to_string()})),
                        )
                    })?;
                tracing::info!(device_id = %device_id, "bootstrapped first paired device as admin");
            }
        }
    }

    Ok(Json(serde_json::json!({ "device_id": device_id })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use axum::extract::State;
    use axum::Json;

    fn pair_start_req(name: &str) -> PairStartRequest {
        let (_, verifying) = encmind_crypto::keypair::generate_keypair();
        PairStartRequest {
            public_key: hex::encode(verifying.to_bytes()),
            name: name.to_string(),
        }
    }

    #[tokio::test]
    async fn pair_start_does_not_expose_code_in_response() {
        let state = make_test_state();
        let res = pair_start(State(state), Json(pair_start_req("laptop")))
            .await
            .unwrap();
        let body = res.0;
        assert!(body.get("pairing_id").is_some());
        assert!(body.get("device_id").is_some());
        assert!(body.get("pairing_code").is_none());
    }

    #[tokio::test]
    async fn failed_confirm_consumes_session() {
        let state = make_test_state();
        let res = pair_start(State(state.clone()), Json(pair_start_req("laptop")))
            .await
            .unwrap();
        let pairing_id = res.0["pairing_id"].as_str().unwrap().to_string();
        let session = {
            let sessions = state.pairing_sessions.lock().unwrap();
            sessions.get(&pairing_id).unwrap().clone()
        };

        let wrong = pair_confirm(
            State(state.clone()),
            Json(PairConfirmRequest {
                pairing_id: pairing_id.clone(),
                code: "000000".to_string(),
            }),
        )
        .await;
        assert!(wrong.is_err());

        let second = pair_confirm(
            State(state),
            Json(PairConfirmRequest {
                pairing_id,
                code: session.code,
            }),
        )
        .await;
        assert!(second.is_err());
        let (status, _) = second.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn first_device_gets_admin_permission() {
        let state = make_test_state();
        let started = pair_start(State(state.clone()), Json(pair_start_req("admin-laptop")))
            .await
            .unwrap();
        let pairing_id = started.0["pairing_id"].as_str().unwrap().to_string();
        let device_id = started.0["device_id"].as_str().unwrap().to_string();
        let code = {
            let sessions = state.pairing_sessions.lock().unwrap();
            sessions.get(&pairing_id).unwrap().code.clone()
        };

        let confirmed = pair_confirm(
            State(state.clone()),
            Json(PairConfirmRequest { pairing_id, code }),
        )
        .await;
        assert!(confirmed.is_ok());

        let stored = state
            .device_store
            .get_device(&device_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.permissions.admin);
    }
}
