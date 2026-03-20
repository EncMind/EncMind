use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header::AUTHORIZATION, HeaderMap};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::serve::IncomingStream;
use axum::Router;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tracing::warn;

use crate::protocol::{ErrorPayload, ServerMessage, ERR_INVALID_PARAMS};
use crate::state::AppState;
use encmind_core::config::PublicWebhookAuthMode;

const OIDC_ALLOWED_CLOCK_SKEW_SECS: u64 = 30;

/// Connection metadata used for /rpc loopback enforcement across TCP and TLS listeners.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

impl Connected<IncomingStream<'_, TcpListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

#[derive(Debug, Deserialize)]
struct HealthQuery {
    #[serde(default)]
    detail: Option<String>,
}

/// Build the axum router with all gateway endpoints.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/webhooks/gmail", post(gmail_webhook_handler))
        .route("/ws", get(crate::ws::ws_handler))
        .route("/node", get(crate::node_ws::node_ws_handler))
        .route("/auth/nonce", post(crate::handlers::auth::issue_nonce))
        .route(
            "/pair/start",
            post(crate::handlers::pairing_handler::pair_start),
        )
        .route(
            "/pair/confirm",
            post(crate::handlers::pairing_handler::pair_confirm),
        )
        .route("/rpc", post(rpc_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// HTTP RPC endpoint for CLI→gateway calls.
async fn rpc_handler(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<PeerAddr>,
    axum::Json(body): axum::Json<RpcRequest>,
) -> impl IntoResponse {
    // /rpc is for local CLI→gateway lifecycle calls only.
    if !peer_addr.0.ip().is_loopback() {
        let error = ServerMessage::Error {
            id: None,
            error: ErrorPayload::new(ERR_INVALID_PARAMS, "rpc endpoint is loopback-only"),
        };
        let json = serde_json::to_value(error)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));
        return (axum::http::StatusCode::FORBIDDEN, axum::Json(json)).into_response();
    }

    if !matches!(
        body.method.as_str(),
        "channels.login" | "channels.logout" | "channels.status" | "channels.remove"
    ) {
        let error = ServerMessage::Error {
            id: None,
            error: ErrorPayload::new(
                ERR_INVALID_PARAMS,
                format!("rpc method not allowed over HTTP: {}", body.method),
            ),
        };
        let json = serde_json::to_value(error)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));
        return (axum::http::StatusCode::FORBIDDEN, axum::Json(json)).into_response();
    }

    let req_id = ulid::Ulid::new().to_string();
    let resp = crate::dispatch::dispatch_method(&state, &body.method, body.params, &req_id).await;

    // Convert ServerMessage to JSON.
    let json = serde_json::to_value(&resp)
        .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));
    axum::Json(json).into_response()
}

async fn health_handler(
    State(state): State<AppState>,
    Query(query): Query<HealthQuery>,
) -> impl IntoResponse {
    let want_detail = query.detail.as_deref() == Some("true");

    if want_detail {
        let report = crate::handlers::readiness::collect_readiness(&state).await;
        let value = serde_json::to_value(&report)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));
        return axum::Json(value);
    }

    let lockdown_active = state.lockdown.is_active();
    let plugin_degraded = state
        .plugin_manager
        .read()
        .await
        .as_ref()
        .map(|pm| pm.is_degraded())
        .unwrap_or(false);
    axum::Json(serde_json::json!({
        "status": "ok",
        "lockdown": lockdown_active,
        "plugin_degraded": plugin_degraded,
    }))
}

/// Gmail push webhook endpoint.
///
/// Accepts either:
/// - Pub/Sub envelope payload with `message.data` (base64 JSON body), or
/// - direct Gmail notification JSON body.
async fn gmail_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl IntoResponse {
    let config = state.config.read().await.clone();
    if !config.server.public_webhooks.enabled {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "forbidden",
                "error": "public webhooks are disabled",
            })),
        )
            .into_response();
    }
    if config.server.public_webhooks.require_tls && !webhook_tls_is_configured(&config) {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "unavailable",
                "error": "public webhook TLS is required but server TLS is not configured",
            })),
        )
            .into_response();
    }
    if config.channels.gmail.is_none() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "not_found",
                "error": "gmail channel is not configured",
            })),
        )
            .into_response();
    }
    match config.server.public_webhooks.auth_mode {
        PublicWebhookAuthMode::SharedBearer => {
            let expected_bearer = match resolve_webhook_bearer_token(&config.server.public_webhooks)
            {
                Ok(token) => token,
                Err(e) => {
                    warn!(error = %e, "gmail webhook auth configuration is invalid");
                    return (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(serde_json::json!({
                            "status": "error",
                            "error": "webhook auth configuration is invalid",
                        })),
                    )
                        .into_response();
                }
            };
            if !authorization_matches_bearer(&headers, &expected_bearer) {
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "status": "unauthorized",
                        "error": "missing or invalid webhook bearer token",
                    })),
                )
                    .into_response();
            }
        }
        PublicWebhookAuthMode::GoogleOidc => {
            let Some(token) = extract_bearer_token(&headers) else {
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "status": "unauthorized",
                        "error": "missing or invalid webhook bearer token",
                    })),
                )
                    .into_response();
            };
            if let Err(e) = verify_google_oidc_token(token, &config.server.public_webhooks).await {
                warn!(error = %e, "gmail webhook OIDC verification failed");
                return (
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "status": "unauthorized",
                        "error": "invalid webhook OIDC token",
                    })),
                )
                    .into_response();
            }
        }
    }

    let Some(adapter) = state.channel_manager.get_adapter("gmail").await else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "unavailable",
                "error": "gmail adapter is not running",
            })),
        )
            .into_response();
    };

    match adapter.handle_webhook(payload).await {
        Ok(()) => (
            axum::http::StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({"status": "accepted"})),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "gmail webhook handling failed");
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "error": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

fn webhook_tls_is_configured(config: &encmind_core::config::AppConfig) -> bool {
    config.server.auto_tls
        || (config.server.tls_cert_path.is_some() && config.server.tls_key_path.is_some())
}

fn resolve_webhook_bearer_token(
    cfg: &encmind_core::config::PublicWebhooksConfig,
) -> Result<String, String> {
    let env_name = cfg
        .auth_token_env
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "auth_token_env is not configured".to_string())?;

    let token =
        std::env::var(env_name).map_err(|_| format!("auth token env var {env_name} is not set"))?;
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(format!("auth token env var {env_name} is empty"));
    }
    Ok(trimmed.to_string())
}

fn authorization_matches_bearer(headers: &HeaderMap, expected: &str) -> bool {
    let Some(provided) = extract_bearer_token(headers) else {
        return false;
    };
    // Compare fixed-size digests in constant time to avoid token-length leakage.
    let expected_hash = Sha256::digest(expected.as_bytes());
    let provided_hash = Sha256::digest(provided.as_bytes());
    expected_hash[..].ct_eq(&provided_hash[..]).into()
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?;
    let value = raw.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    let trimmed = token.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn validate_google_oidc_claims(
    claims: &serde_json::Value,
    cfg: &encmind_core::config::PublicWebhooksConfig,
) -> Result<(), String> {
    let expected_aud = cfg
        .google_oidc_audience
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "google_oidc_audience is not configured".to_string())?;

    let aud = claims
        .get("aud")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "OIDC token is missing aud".to_string())?;
    if aud != expected_aud {
        return Err("OIDC token aud does not match configured audience".to_string());
    }

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if iss != "accounts.google.com" && iss != "https://accounts.google.com" {
        return Err("OIDC token issuer is not Google".to_string());
    }

    let exp = claims
        .get("exp")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| v.as_u64())
        })
        .ok_or_else(|| "OIDC token is missing exp".to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before epoch".to_string())?
        .as_secs();
    if exp.saturating_add(OIDC_ALLOWED_CLOCK_SKEW_SECS) <= now {
        return Err("OIDC token has expired".to_string());
    }

    if let Some(expected_email) = cfg
        .google_oidc_email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .ok_or_else(|| "OIDC token is missing email".to_string())?;
        if email != expected_email {
            return Err("OIDC token email does not match configured service account".to_string());
        }
        let email_verified = claims
            .get("email_verified")
            .and_then(|v| {
                v.as_str()
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .or(v.as_bool())
            })
            .unwrap_or(false);
        if !email_verified {
            return Err("OIDC token email is not verified".to_string());
        }
    }

    Ok(())
}

async fn verify_google_oidc_token(
    token: &str,
    cfg: &encmind_core::config::PublicWebhooksConfig,
) -> Result<(), String> {
    let tokeninfo_url = reqwest::Url::parse_with_params(
        "https://oauth2.googleapis.com/tokeninfo",
        &[("id_token", token)],
    )
    .map_err(|e| format!("failed to build google tokeninfo URL: {e}"))?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build OIDC verification client: {e}"))?;
    let response = client
        .get(tokeninfo_url)
        .send()
        .await
        .map_err(|e| format!("google tokeninfo request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "google tokeninfo rejected token (HTTP {status}): {body}"
        ));
    }

    let claims = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("failed to parse google tokeninfo response: {e}"))?;

    validate_google_oidc_claims(&claims, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{HeaderValue, Request, StatusCode};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    struct EnvVarGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.original {
                std::env::set_var(&self.key, v);
            } else {
                std::env::remove_var(&self.key);
            }
        }
    }

    fn test_app(state: AppState) -> Router {
        build_router(state).layer(MockConnectInfo(PeerAddr(SocketAddr::from((
            [127, 0, 0, 1],
            34567,
        )))))
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let state = make_test_state();
        let app = test_app(state);

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["lockdown"], false);
        assert_eq!(json["plugin_degraded"], false);
    }

    #[tokio::test]
    async fn health_shows_lockdown_state() {
        let state = make_test_state();
        state.lockdown.activate("test");
        let app = test_app(state);

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["lockdown"], true);
    }

    #[tokio::test]
    async fn health_detail_returns_full_report() {
        let state = make_test_state();
        let app = test_app(state);

        let req = Request::builder()
            .uri("/health?detail=true")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Full report should have subsystem fields
        assert!(json.get("llm").is_some());
        assert!(json.get("tools").is_some());
        assert!(json.get("memory").is_some());
        assert!(json.get("rate_limiting").is_some());
        assert!(json.get("status").is_some());
    }

    #[tokio::test]
    async fn health_default_returns_compact() {
        let state = make_test_state();
        let app = test_app(state);

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Compact mode has "status: ok" but NOT subsystem breakdowns
        assert_eq!(json["status"], "ok");
        assert!(json.get("llm").is_none());
    }

    #[tokio::test]
    async fn rpc_endpoint_dispatches_method() {
        let state = make_test_state();
        let app = test_app(state);

        let body_json = serde_json::json!({
            "method": "channels.logout",
            "params": {}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Should return some valid ServerMessage (Res or Err).
        assert!(
            json.get("type").is_some(),
            "RPC response should have a 'type' field from ServerMessage"
        );
    }

    #[tokio::test]
    async fn rpc_endpoint_allows_channels_status() {
        let state = make_test_state();
        let app = test_app(state);

        let body_json = serde_json::json!({
            "method": "channels.status",
            "params": {}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rpc_endpoint_allows_channels_remove() {
        let state = make_test_state();
        let app = test_app(state);

        let body_json = serde_json::json!({
            "method": "channels.remove",
            "params": { "id": "ca_test" }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rpc_endpoint_unknown_method_returns_error() {
        let state = make_test_state();
        let app = test_app(state);

        let body_json = serde_json::json!({
            "method": "memory.status",
            "params": {}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Should be an error response.
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("error"));
        assert!(json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not allowed"));
    }

    #[tokio::test]
    async fn rpc_endpoint_rejects_non_loopback_client() {
        let state = make_test_state();
        let app = build_router(state).layer(MockConnectInfo(PeerAddr(SocketAddr::from((
            [10, 0, 0, 1],
            45678,
        )))));

        let body_json = serde_json::json!({
            "method": "channels.logout",
            "params": {}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("error"));
        assert!(json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("loopback-only"));
    }

    #[test]
    fn authorization_matches_bearer_accepts_exact_match() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str("Bearer expected-token").unwrap(),
        );
        assert!(authorization_matches_bearer(&headers, "expected-token"));
    }

    #[test]
    fn authorization_matches_bearer_rejects_length_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str("Bearer short").unwrap(),
        );
        assert!(!authorization_matches_bearer(
            &headers,
            "much-longer-expected-token-value"
        ));
    }

    #[test]
    fn validate_google_oidc_claims_accepts_valid_payload() {
        let cfg = encmind_core::config::PublicWebhooksConfig {
            auth_mode: encmind_core::config::PublicWebhookAuthMode::GoogleOidc,
            google_oidc_audience: Some("https://example/webhooks/gmail".to_string()),
            google_oidc_email: Some("svc@example.iam.gserviceaccount.com".to_string()),
            ..Default::default()
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "aud": "https://example/webhooks/gmail",
            "iss": "https://accounts.google.com",
            "exp": now + 300,
            "email": "svc@example.iam.gserviceaccount.com",
            "email_verified": true,
        });
        assert!(validate_google_oidc_claims(&claims, &cfg).is_ok());
    }

    #[test]
    fn validate_google_oidc_claims_rejects_wrong_audience() {
        let cfg = encmind_core::config::PublicWebhooksConfig {
            auth_mode: encmind_core::config::PublicWebhookAuthMode::GoogleOidc,
            google_oidc_audience: Some("https://example/webhooks/gmail".to_string()),
            ..Default::default()
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "aud": "https://wrong-audience",
            "iss": "accounts.google.com",
            "exp": now + 300,
        });
        let err = validate_google_oidc_claims(&claims, &cfg).unwrap_err();
        assert!(err.contains("aud"));
    }

    #[test]
    fn validate_google_oidc_claims_rejects_expired() {
        let cfg = encmind_core::config::PublicWebhooksConfig {
            auth_mode: encmind_core::config::PublicWebhookAuthMode::GoogleOidc,
            google_oidc_audience: Some("https://example/webhooks/gmail".to_string()),
            ..Default::default()
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "aud": "https://example/webhooks/gmail",
            "iss": "accounts.google.com",
            "exp": now.saturating_sub(120),
        });
        let err = validate_google_oidc_claims(&claims, &cfg).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn validate_google_oidc_claims_accepts_small_clock_skew() {
        let cfg = encmind_core::config::PublicWebhooksConfig {
            auth_mode: encmind_core::config::PublicWebhookAuthMode::GoogleOidc,
            google_oidc_audience: Some("https://example/webhooks/gmail".to_string()),
            ..Default::default()
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "aud": "https://example/webhooks/gmail",
            "iss": "accounts.google.com",
            "exp": now.saturating_sub(OIDC_ALLOWED_CLOCK_SKEW_SECS.saturating_sub(1)),
        });
        assert!(validate_google_oidc_claims(&claims, &cfg).is_ok());
    }

    #[tokio::test]
    async fn gmail_webhook_rejects_when_public_webhooks_disabled() {
        let state = make_test_state();
        let app = test_app(state);

        let body_json = serde_json::json!({
            "emailAddress": "user@example.com",
            "historyId": "123",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/gmail")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn gmail_webhook_reports_unavailable_when_adapter_not_running() {
        let state = make_test_state();
        let _guard = EnvVarGuard::set("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN", "test-token");
        {
            let mut cfg = state.config.write().await;
            cfg.server.public_webhooks.enabled = true;
            cfg.server.public_webhooks.auth_token_env =
                Some("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN".to_string());
            cfg.server.auto_tls = true;
            cfg.channels.gmail = Some(encmind_core::config::GmailConfig::default());
        }
        let app = test_app(state);

        let body_json = serde_json::json!({
            "emailAddress": "user@example.com",
            "historyId": "123",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/gmail")
            .header("content-type", "application/json")
            .header("authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn gmail_webhook_rejects_when_tls_required_but_not_configured() {
        let state = make_test_state();
        let _guard = EnvVarGuard::set("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN_TLS", "test-token");
        {
            let mut cfg = state.config.write().await;
            cfg.server.public_webhooks.enabled = true;
            cfg.server.public_webhooks.require_tls = true;
            cfg.server.public_webhooks.auth_token_env =
                Some("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN_TLS".to_string());
            cfg.channels.gmail = Some(encmind_core::config::GmailConfig::default());
            cfg.server.auto_tls = false;
            cfg.server.tls_cert_path = None;
            cfg.server.tls_key_path = None;
        }
        let app = test_app(state);

        let body_json = serde_json::json!({
            "emailAddress": "user@example.com",
            "historyId": "123",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/gmail")
            .header("content-type", "application/json")
            .header("authorization", "Bearer test-token")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn gmail_webhook_rejects_missing_bearer_token() {
        let state = make_test_state();
        let _guard = EnvVarGuard::set("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN", "test-token");
        {
            let mut cfg = state.config.write().await;
            cfg.server.public_webhooks.enabled = true;
            cfg.server.public_webhooks.auth_token_env =
                Some("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN".to_string());
            cfg.server.auto_tls = true;
            cfg.channels.gmail = Some(encmind_core::config::GmailConfig::default());
        }
        let app = test_app(state);

        let body_json = serde_json::json!({
            "emailAddress": "user@example.com",
            "historyId": "123",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/gmail")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn gmail_webhook_google_oidc_mode_rejects_missing_bearer_token() {
        let state = make_test_state();
        {
            let mut cfg = state.config.write().await;
            cfg.server.public_webhooks.enabled = true;
            cfg.server.public_webhooks.auth_mode =
                encmind_core::config::PublicWebhookAuthMode::GoogleOidc;
            cfg.server.public_webhooks.google_oidc_audience =
                Some("https://example/webhooks/gmail".to_string());
            cfg.server.auto_tls = true;
            cfg.channels.gmail = Some(encmind_core::config::GmailConfig::default());
        }
        let app = test_app(state);

        let body_json = serde_json::json!({
            "emailAddress": "user@example.com",
            "historyId": "123",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/gmail")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn gmail_webhook_rejects_invalid_bearer_token() {
        let state = make_test_state();
        let _guard = EnvVarGuard::set("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN", "test-token");
        {
            let mut cfg = state.config.write().await;
            cfg.server.public_webhooks.enabled = true;
            cfg.server.public_webhooks.auth_token_env =
                Some("ENCMIND_TEST_GMAIL_WEBHOOK_TOKEN".to_string());
            cfg.server.auto_tls = true;
            cfg.channels.gmail = Some(encmind_core::config::GmailConfig::default());
        }
        let app = test_app(state);

        let body_json = serde_json::json!({
            "emailAddress": "user@example.com",
            "historyId": "123",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/gmail")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-token")
            .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
