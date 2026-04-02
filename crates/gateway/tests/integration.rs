//! Integration tests for the gateway server.
//!
//! These tests build an `AppState` directly (using the same pattern as
//! `test_utils::make_test_state()`) and exercise the router, dispatch,
//! pairing, and device auth layers.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use encmind_agent::firewall::EgressFirewall;
use encmind_agent::lockdown::LockdownManager;
use encmind_agent::pool::AgentPool;
use encmind_agent::registry::SqliteAgentRegistry;
use encmind_agent::tool_registry::ToolRegistry;
use encmind_core::config::{AgentPoolConfig, AppConfig, LockdownConfig};
use encmind_core::traits::{AgentRegistry, DeviceStore, SessionStore};
use encmind_storage::audit::AuditLogger;
use encmind_storage::device_store::SqliteDeviceStore;
use encmind_storage::encryption::Aes256GcmAdapter;
use encmind_storage::migrations::run_migrations;
use encmind_storage::pool::create_test_pool;
use encmind_storage::session_store::SqliteSessionStore;

use encmind_gateway::idempotency::IdempotencyCache;
use encmind_gateway::node::NodeRegistry;
use encmind_gateway::protocol::*;
use encmind_gateway::rate_limiter::SessionRateLimiter;
use encmind_gateway::routes::build_router;
use encmind_gateway::state::{AppState, NativePluginTimerRuntime, RuntimeResources};
use encmind_gateway::{device_auth::NonceStore, pairing::PairingSession};

// ---------- Helper ----------

fn make_state() -> AppState {
    let pool = create_test_pool();
    {
        let conn = pool.get().unwrap();
        run_migrations(&conn).unwrap();
    }

    let key = [0u8; 32];
    let enc = Arc::new(Aes256GcmAdapter::new(&key));
    let session_store: Arc<dyn SessionStore> = Arc::new(SqliteSessionStore::new(pool.clone(), enc));
    let agent_registry: Arc<dyn AgentRegistry> = Arc::new(SqliteAgentRegistry::new(pool.clone()));
    let device_store: Arc<dyn DeviceStore> = Arc::new(SqliteDeviceStore::new(pool.clone()));
    let audit = Arc::new(AuditLogger::new(pool.clone()));
    let lockdown =
        Arc::new(LockdownManager::new(&LockdownConfig::default()).with_audit(audit.clone()));
    let agent_pool = Arc::new(AgentPool::new(&AgentPoolConfig::default()));
    let config = AppConfig::default();
    let channel_startup_intent = Arc::new(encmind_gateway::state::compute_channel_startup_intent(
        &config,
    ));
    let firewall = Arc::new(EgressFirewall::new(&config.security.egress_firewall));
    let node_registry = Arc::new(NodeRegistry::new());
    let connection_permits = Arc::new(Semaphore::new(config.gateway.max_connections as usize));
    let idempotency = Arc::new(Mutex::new(IdempotencyCache::new(
        config.gateway.idempotency_ttl_secs,
    )));
    let nonce_store = Arc::new(NonceStore::new());
    let pairing_sessions = Arc::new(Mutex::new(HashMap::<String, PairingSession>::new()));
    let admin_bootstrap_lock = Arc::new(AsyncMutex::new(()));
    let active_runs = Arc::new(Mutex::new(HashMap::<String, CancellationToken>::new()));
    let query_guard = Arc::new(encmind_gateway::query_guard::QueryGuardRegistry::new(
        config.gateway.max_queued_per_session,
    ));

    AppState {
        session_store,
        agent_registry,
        device_store,
        lockdown,
        agent_pool,
        runtime: Arc::new(RwLock::new(RuntimeResources {
            llm_backend: None,
            tool_registry: Arc::new(ToolRegistry::new()),
        })),
        api_key_store: None,
        firewall,
        audit,
        config: Arc::new(RwLock::new(config)),
        tls: None,
        node_registry,
        connection_permits,
        idempotency,
        nonce_store,
        pairing_sessions,
        admin_bootstrap_lock,
        active_runs,
        query_guard,
        timeline_store: Some(Arc::new(
            encmind_storage::timeline_store::SqliteTimelineStore::new(pool.clone()),
        )),
        db_pool: pool.clone(),
        memory_store: None,
        cron_store: Some(Arc::new(encmind_storage::cron_store::SqliteCronStore::new(
            pool.clone(),
        ))),
        cron_dispatcher: None,
        channel_router: None,
        channel_manager: Arc::new(
            encmind_gateway::channel_manager::ChannelAdapterManager::new(CancellationToken::new()),
        ),
        backup_manager: None,
        browser_pool: None,
        hook_registry: Arc::new(RwLock::new(encmind_core::hooks::HookRegistry::new())),
        plugin_manager: Arc::new(RwLock::new(None)),
        loaded_skills: Arc::new(RwLock::new(Vec::new())),
        known_skill_ids: Arc::new(RwLock::new(HashSet::new())),
        pending_approvals: Arc::new(Mutex::new(HashMap::new())),
        wasm_http_client: Arc::new(reqwest::Client::new()),
        skill_timer_store: Some(Arc::new(
            encmind_storage::skill_timer_store::SqliteSkillTimerStore::new(pool.clone()),
        )),
        skill_timer_runner: None,
        channel_transforms: Arc::new(RwLock::new(HashMap::new())),
        refresh_lock: Arc::new(RwLock::new(())),
        skill_toggle_store: None,
        skill_toggle_lock: Arc::new(AsyncMutex::new(())),
        skill_resources_lock: Arc::new(AsyncMutex::new(())),
        skill_metrics: Arc::new(RwLock::new(HashMap::new())),
        native_plugin_timers: Arc::new(AsyncMutex::new(NativePluginTimerRuntime {
            cancel: CancellationToken::new(),
            handles: Vec::new(),
        })),
        native_timer_replace_lock: Arc::new(AsyncMutex::new(())),
        session_rate_limiter: Arc::new(SessionRateLimiter::new(30)),
        api_budget_tracker: None,
        channel_account_store: None,
        channel_startup_intent,
    }
}

// ---------- Tests ----------

/// Test 1: Health endpoint returns OK with lockdown status.
#[tokio::test]
async fn health_endpoint() {
    let state = make_state();
    let app = build_router(state);

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
}

/// Test 2: WS connect + chat.send via the dispatch layer.
#[tokio::test]
async fn ws_connect_and_chat_dispatch() {
    let state = make_state();

    // Verify connect message serde
    let connect_msg = serde_json::to_string(&ClientMessage::Connect {
        auth: AuthPayload {
            device_id: "test-device".into(),
            nonce: "test-nonce".into(),
            signature: "test-sig".into(),
        },
    })
    .unwrap();

    let client_msg: ClientMessage = serde_json::from_str(&connect_msg).unwrap();
    match client_msg {
        ClientMessage::Connect { auth } => {
            assert_eq!(auth.device_id, "test-device");
        }
        _ => panic!("Expected Connect"),
    }

    // Dispatch chat.send
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "chat.send",
        serde_json::json!({"message": "hello"}),
        "req-1",
        None,
    )
    .await;

    match result {
        ServerMessage::Res { id, .. } => assert_eq!(id, "req-1"),
        ServerMessage::Error { id, .. } => {
            assert_eq!(id, Some("req-1".to_string()));
        }
        _ => panic!("Expected Res or Error"),
    }
}

/// Test 3: Lockdown blocks non-exempt methods, allows exempt ones.
#[tokio::test]
async fn lockdown_blocks_ws() {
    let state = make_state();
    state.lockdown.activate("integration-test");

    // chat.send should be blocked
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "chat.send",
        serde_json::json!({}),
        "locked-req",
        None,
    )
    .await;

    match result {
        ServerMessage::Error { error, .. } => {
            assert_eq!(error.code, ERR_LOCKDOWN);
            assert!(error.message.contains("lockdown"));
        }
        _ => panic!("Expected lockdown error"),
    }

    // security.lockdown should still work (exempt)
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "security.lockdown",
        serde_json::json!({"active": false}),
        "unlock-req",
        None,
    )
    .await;

    match result {
        ServerMessage::Res { id, .. } => assert_eq!(id, "unlock-req"),
        _ => panic!("Expected Res for exempt method"),
    }
}

/// Test 4: Device auth challenge-response flow.
#[tokio::test]
async fn device_auth_challenge() {
    use chrono::Utc;
    use encmind_core::types::{DevicePermissions, PairedDevice};
    use encmind_crypto::challenge::sign_nonce;
    use encmind_crypto::device_id::DeviceId;
    use encmind_crypto::keypair::generate_keypair;
    use encmind_gateway::device_auth::NonceStore;

    let state = make_state();
    let nonce_store = NonceStore::new();

    // Generate device keypair
    let (signing, verifying) = generate_keypair();
    let device_id = DeviceId::from_verifying_key(&verifying);

    // Register device
    state
        .device_store
        .add_device(&PairedDevice {
            id: device_id.as_str().to_string(),
            name: "Integration Test Device".into(),
            public_key: verifying.to_bytes().to_vec(),
            permissions: DevicePermissions {
                chat: true,
                file_read: true,
                ..Default::default()
            },
            paired_at: Utc::now(),
            last_seen: None,
        })
        .await
        .unwrap();

    // Issue nonce
    let nonce_hex = nonce_store.issue_nonce(device_id.as_str());
    assert_eq!(nonce_hex.len(), 64); // 32 bytes hex

    // Sign nonce
    let nonce_bytes = hex::decode(&nonce_hex).unwrap();
    let signature = sign_nonce(&signing, &nonce_bytes);
    let sig_hex = hex::encode(&signature);

    // Verify challenge
    let result = nonce_store
        .verify_challenge(&nonce_hex, &sig_hex, state.device_store.as_ref())
        .await;
    assert!(result.is_ok());
    let (verified_id, _perms) = result.unwrap();
    assert_eq!(verified_id, device_id.as_str());

    // Nonce consumed — second use fails
    let result = nonce_store
        .verify_challenge(&nonce_hex, &sig_hex, state.device_store.as_ref())
        .await;
    assert!(result.is_err());
}

/// Test 5: Full lockdown flow — QA 8.1–8.5.
///
/// 8.1: Activate lockdown via security.lockdown handler
/// 8.2: Non-exempt method (chat.send) blocked with ERR_LOCKDOWN
/// 8.3: Exempt methods (security.audit, config.get, models.list) still work
/// 8.4: Deactivate lockdown via handler, verify chat.send unblocked
/// 8.5: Audit trail contains both "activated" and "deactivated" entries
#[tokio::test]
async fn lockdown_full_flow() {
    let state = make_state();

    // --- 8.1: Activate lockdown via handler ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "security.lockdown",
        serde_json::json!({"active": true, "reason": "maintenance"}),
        "lock-1",
        None,
    )
    .await;
    match &result {
        ServerMessage::Res { id, result } => {
            assert_eq!(id, "lock-1");
            assert_eq!(result["active"], true);
        }
        other => panic!("8.1: Expected Res, got {other:?}"),
    }
    assert!(state.lockdown.is_active());

    // --- 8.2: Non-exempt method blocked ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "chat.send",
        serde_json::json!({}),
        "chat-1",
        None,
    )
    .await;
    match &result {
        ServerMessage::Error { error, .. } => {
            assert_eq!(error.code, ERR_LOCKDOWN, "8.2: expected ERR_LOCKDOWN");
        }
        other => panic!("8.2: Expected lockdown Error, got {other:?}"),
    }

    // --- 8.3a: Exempt — security.audit ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "security.audit",
        serde_json::json!({}),
        "audit-1",
        None,
    )
    .await;
    match &result {
        ServerMessage::Res { id, .. } => assert_eq!(id, "audit-1"),
        ServerMessage::Error { error, .. } => {
            assert_ne!(
                error.code, ERR_LOCKDOWN,
                "8.3a: security.audit must not be blocked by lockdown"
            );
        }
        other => panic!("8.3a: Expected Res or non-lockdown Error, got {other:?}"),
    }

    // --- 8.3b: Exempt — config.get ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "config.get",
        serde_json::json!({}),
        "cfg-1",
        None,
    )
    .await;
    match &result {
        ServerMessage::Res { id, .. } => assert_eq!(id, "cfg-1"),
        ServerMessage::Error { error, .. } => {
            assert_ne!(
                error.code, ERR_LOCKDOWN,
                "8.3b: config.get must not be blocked by lockdown"
            );
        }
        other => panic!("8.3b: Expected Res or non-lockdown Error, got {other:?}"),
    }

    // --- 8.3c: Exempt — models.list ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "models.list",
        serde_json::json!({}),
        "models-1",
        None,
    )
    .await;
    match &result {
        ServerMessage::Res { id, .. } => assert_eq!(id, "models-1"),
        ServerMessage::Error { error, .. } => {
            assert_ne!(
                error.code, ERR_LOCKDOWN,
                "8.3c: models.list must not be blocked by lockdown"
            );
        }
        other => panic!("8.3c: Expected Res or non-lockdown Error, got {other:?}"),
    }

    // --- 8.4: Deactivate lockdown ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "security.lockdown",
        serde_json::json!({"active": false}),
        "unlock-1",
        None,
    )
    .await;
    match &result {
        ServerMessage::Res { id, result } => {
            assert_eq!(id, "unlock-1");
            assert_eq!(result["active"], false);
        }
        other => panic!("8.4: Expected Res, got {other:?}"),
    }
    assert!(!state.lockdown.is_active());

    // Verify chat.send is no longer blocked by lockdown
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "chat.send",
        serde_json::json!({"message": "hello"}),
        "chat-2",
        None,
    )
    .await;
    match &result {
        ServerMessage::Error { error, .. } => {
            assert_ne!(
                error.code, ERR_LOCKDOWN,
                "8.4: chat.send should not be blocked after deactivation"
            );
        }
        ServerMessage::Res { .. } => {} // OK
        other => panic!("8.4: Expected Res or non-lockdown Error, got {other:?}"),
    }

    // --- 8.5: Audit trail ---
    let result = encmind_gateway::dispatch::dispatch_method(
        &state,
        "security.audit",
        serde_json::json!({"category": "security.lockdown"}),
        "audit-2",
        None,
    )
    .await;
    match &result {
        ServerMessage::Res { id, result } => {
            assert_eq!(id, "audit-2");
            let entries = result["entries"]
                .as_array()
                .expect("8.5: entries should be an array");
            let has_activated = entries.iter().any(|e| e["action"] == "activated");
            let has_deactivated = entries.iter().any(|e| e["action"] == "deactivated");
            assert!(
                has_activated,
                "8.5: audit trail must contain 'activated' entry"
            );
            assert!(
                has_deactivated,
                "8.5: audit trail must contain 'deactivated' entry"
            );
        }
        other => panic!("8.5: Expected Res, got {other:?}"),
    }
}

/// Test 6: Pairing flow stores device and validates code.
#[tokio::test]
async fn pairing_flow() {
    use encmind_crypto::keypair::generate_keypair;
    use encmind_gateway::pairing::PairingSession;

    let state = make_state();

    // Generate client keypair
    let (_, verifying) = generate_keypair();
    let pk_hex = hex::encode(verifying.to_bytes());

    // Create pairing session
    let session = PairingSession::new(&pk_hex, "Test Laptop").unwrap();
    assert_eq!(session.code.len(), 6);
    assert!(session.code.chars().all(|c| c.is_ascii_digit()));

    // Complete with correct code
    let code = session.code.clone();
    let default_perms = encmind_core::types::DevicePermissions {
        chat: true,
        ..Default::default()
    };
    let device_id = session
        .complete(&code, state.device_store.as_ref(), &default_perms)
        .await
        .unwrap();

    // Verify stored
    let device = state
        .device_store
        .get_device(&device_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(device.name, "Test Laptop");
    assert!(device.permissions.chat);

    // Wrong code should fail
    let (_, verifying2) = generate_keypair();
    let pk_hex2 = hex::encode(verifying2.to_bytes());
    let session2 = PairingSession::new(&pk_hex2, "Another").unwrap();
    let default_perms = encmind_core::types::DevicePermissions::default();
    let result = session2
        .complete("000000", state.device_store.as_ref(), &default_perms)
        .await;
    assert!(result.is_err());
}
