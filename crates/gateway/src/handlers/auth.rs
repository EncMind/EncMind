use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use encmind_crypto::challenge::generate_nonce;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct NonceRequest {
    pub device_id: String,
}

/// Issue a one-time nonce challenge for an already paired device.
pub async fn issue_nonce(
    State(state): State<AppState>,
    Json(req): Json<NonceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let device_id = req.device_id.trim();
    if device_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "device_id is required"})),
        ));
    }

    match state.device_store.get_device(device_id).await {
        Ok(Some(_)) => Ok(Json(serde_json::json!({
            "nonce": state.nonce_store.issue_nonce(device_id)
        }))),
        Ok(None) => {
            // Avoid paired-device enumeration: return a nonce-shaped response for unknown IDs too.
            let fake_nonce = hex::encode(generate_nonce());
            Ok(Json(serde_json::json!({ "nonce": fake_nonce })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}
