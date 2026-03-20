//! Handlers for WASM skill management APIs (`skills.*`) and `approval.respond`.

use crate::handlers::keys::refresh_llm_and_tool_registry;
use crate::protocol::*;
use crate::state::AppState;

use encmind_core::types::SkillApprovalResponse;
use tracing::warn;

const SKILL_SCAN_MAX_MANIFESTS: usize = 256;
const MAX_SKILL_SETTINGS_PAYLOAD_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SkillDiskMatch {
    Canonical,
    BrokenStemOnly,
    AliasMismatch { manifest_skill_id: String },
    NotFound,
}

fn validate_skill_id(skill_id: &str) -> Result<(), String> {
    encmind_core::skill_id::validate_skill_id(skill_id)
}

fn validate_config_key(key: &str) -> Result<(), String> {
    let trimmed = key.trim();
    if key != trimmed {
        return Err("key must not have leading or trailing whitespace".to_string());
    }
    if trimmed.is_empty() {
        return Err("key must not be empty".to_string());
    }
    if trimmed.len() > 128 {
        return Err("key must be at most 128 characters".to_string());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("key must not contain control characters".to_string());
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err("key may only contain [A-Za-z0-9._-]".to_string());
    }
    Ok(())
}

async fn resolve_skill_disk_match(state: &AppState, skill_id: &str) -> SkillDiskMatch {
    let skills_dir = {
        let cfg = state.config.read().await;
        crate::server::resolve_skills_dir(&cfg)
    };
    let target_skill_id = skill_id.to_string();
    tokio::task::spawn_blocking(move || -> SkillDiskMatch {
        let parse_manifest_name = |path: &std::path::Path| -> Option<String> {
            let manifest = std::fs::read_to_string(path).ok()?;
            let parsed = encmind_wasm_host::manifest::parse_manifest_full(&manifest).ok()?;
            Some(parsed.manifest.name)
        };

        // Fast path: direct basename match.
        //
        // Canonical behavior:
        // - If a readable manifest exists, requested skill_id must equal
        //   manifest.skill.name.
        // - If artifacts are broken/missing manifest, allow stem-based matching
        //   so operators can disable malformed skills.
        let direct_wasm = skills_dir.join(format!("{target_skill_id}.wasm"));
        let direct_toml = skills_dir.join(format!("{target_skill_id}.toml"));

        if direct_toml.is_file() {
            return match parse_manifest_name(&direct_toml) {
                Some(name) if name == target_skill_id => SkillDiskMatch::Canonical,
                Some(name) => SkillDiskMatch::AliasMismatch {
                    manifest_skill_id: name,
                },
                None => SkillDiskMatch::BrokenStemOnly,
            };
        }

        if direct_wasm.is_file() {
            if let Some(name) = parse_manifest_name(&direct_wasm.with_extension("toml")) {
                if name == target_skill_id {
                    return SkillDiskMatch::Canonical;
                }
                return SkillDiskMatch::AliasMismatch {
                    manifest_skill_id: name,
                };
            }
            return SkillDiskMatch::BrokenStemOnly;
        }

        // Fallback bounded scan for non-filename-aligned manifests.
        let entries = match std::fs::read_dir(&skills_dir) {
            Ok(e) => e,
            Err(_) => return SkillDiskMatch::NotFound,
        };
        let mut manifests_scanned = 0usize;
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) != Some("toml") {
                continue;
            }
            if manifests_scanned >= SKILL_SCAN_MAX_MANIFESTS {
                break;
            }
            manifests_scanned += 1;
            if path
                .file_stem()
                .and_then(|v| v.to_str())
                .is_some_and(|stem| stem == target_skill_id)
            {
                return match parse_manifest_name(&path) {
                    Some(name) if name == target_skill_id => SkillDiskMatch::Canonical,
                    Some(name) => SkillDiskMatch::AliasMismatch {
                        manifest_skill_id: name,
                    },
                    None => SkillDiskMatch::BrokenStemOnly,
                };
            }
            if parse_manifest_name(&path).as_deref() == Some(target_skill_id.as_str()) {
                return SkillDiskMatch::Canonical;
            }
        }
        SkillDiskMatch::NotFound
    })
    .await
    .unwrap_or(SkillDiskMatch::NotFound)
}

async fn ensure_known_skill_id(
    state: &AppState,
    skill_id: &str,
    req_id: &str,
) -> Result<(), ServerMessage> {
    let loaded_exists = {
        let loaded = state.loaded_skills.read().await;
        loaded.iter().any(|summary| summary.id == skill_id)
    };
    if loaded_exists {
        return Ok(());
    }

    match resolve_skill_disk_match(state, skill_id).await {
        SkillDiskMatch::Canonical | SkillDiskMatch::BrokenStemOnly => {
            let mut known = state.known_skill_ids.write().await;
            known.insert(skill_id.to_string());
            return Ok(());
        }
        SkillDiskMatch::AliasMismatch { manifest_skill_id } => {
            let mut known = state.known_skill_ids.write().await;
            known.remove(skill_id);
            known.insert(manifest_skill_id.clone());
            return Err(ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INVALID_PARAMS,
                    format!(
                        "skill_id '{skill_id}' aliases manifest skill_id '{manifest_skill_id}'; use '{manifest_skill_id}'"
                    ),
                ),
            });
        }
        SkillDiskMatch::NotFound => {}
    }

    // Prune stale cache entries so removed skills cannot be addressed until a
    // successful rediscovery occurs.
    {
        let mut known = state.known_skill_ids.write().await;
        known.remove(skill_id);
    }

    Err(ServerMessage::Error {
        id: Some(req_id.to_string()),
        error: ErrorPayload::new(ERR_INVALID_PARAMS, format!("unknown skill_id: {skill_id}")),
    })
}

/// Handle `skills.list` — returns the list of loaded WASM skills.
pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let mut skills = {
        let loaded = state.loaded_skills.read().await;
        loaded
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "version": s.version,
                    "description": s.description,
                    "enabled": s.enabled,
                    "tool_name": s.tool_name,
                    "hook_points": s.hook_points,
                    "output_schema": s.output_schema,
                })
            })
            .collect::<Vec<_>>()
    };
    skills.sort_by(|a, b| {
        let a_id = a.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        let b_id = b.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        a_id.cmp(b_id)
    });
    let mut pending_approvals = {
        let pending = state.pending_approvals.lock().unwrap();
        pending
            .values()
            .map(|p| {
                serde_json::json!({
                    "request_id": p.request.request_id,
                    "skill_id": p.request.skill_id,
                    "prompt": p.request.prompt,
                    "options": p.request.options,
                })
            })
            .collect::<Vec<_>>()
    };
    pending_approvals.sort_by(|a, b| {
        let a_id = a
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let b_id = b
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        a_id.cmp(b_id)
    });

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "skills": skills,
            "pending_approvals": pending_approvals,
        }),
    }
}

/// Handle `skills.toggle` — enable or disable a WASM skill at runtime.
pub async fn handle_toggle(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let skill_id = match params.get("skill_id").and_then(|v| v.as_str()) {
        Some(id) => id.trim().to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "skill_id is required"),
            };
        }
    };
    if let Err(reason) = validate_skill_id(&skill_id) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
        };
    }

    let enabled = match params.get("enabled").and_then(|v| v.as_bool()) {
        Some(v) => v,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "enabled (bool) is required"),
            };
        }
    };

    let store = match state.skill_toggle_store.as_ref() {
        Some(s) => s,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, "skill toggle store not available"),
            };
        }
    };
    let _toggle_guard = state.skill_toggle_lock.lock().await;

    let previous_enabled = match store.is_enabled(&skill_id).await {
        Ok(v) => v,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(
                    ERR_INTERNAL,
                    format!("failed to read current skill state: {e}"),
                ),
            };
        }
    };
    if let Err(err) = ensure_known_skill_id(state, &skill_id, req_id).await {
        return err;
    }

    if let Err(e) = store.set_enabled(&skill_id, enabled).await {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, format!("failed to persist toggle: {e}")),
        };
    }

    if let Err(e) = refresh_llm_and_tool_registry(state).await {
        let rollback = store.set_enabled(&skill_id, previous_enabled).await;
        let msg = match rollback {
            Ok(()) => format!("failed to apply skill toggle: {e}"),
            Err(rollback_err) => {
                format!("failed to apply skill toggle: {e}; rollback failed: {rollback_err}")
            }
        };
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, msg),
        };
    }

    // Audit
    if let Err(e) = state.audit.append(
        "skill",
        &format!("skill.{skill_id}.toggle"),
        Some(
            &serde_json::json!({
                "enabled": enabled,
                "previous_enabled": previous_enabled
            })
            .to_string(),
        ),
        Some("admin"),
    ) {
        warn!(
            error = %e,
            skill_id = %skill_id,
            "failed to append skills.toggle audit event"
        );
    }

    let active = {
        let loaded = state.loaded_skills.read().await;
        loaded
            .iter()
            .find(|summary| summary.id == skill_id)
            .is_some_and(|summary| summary.enabled)
    };
    let activation_blocked = enabled && !active;
    let activation_note = if activation_blocked {
        Some(
            "persisted as enabled, but skill is not active in runtime (check policy/allowlist/load errors)"
                .to_string(),
        )
    } else {
        None
    };

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "toggled": previous_enabled != enabled,
            "enabled": enabled,
            "persisted_enabled": enabled,
            "active": active,
            "activation_blocked": activation_blocked,
            "activation_note": activation_note,
        }),
    }
}

/// Handle `approval.respond` — delivers a user's approval decision to a waiting WASM skill.
pub async fn handle_respond(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let request_id = match params.get("request_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "request_id is required"),
            };
        }
    };

    let approved = params
        .get("approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let choice = params
        .get("choice")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let has_choice = choice.is_some();

    let response = SkillApprovalResponse {
        request_id: request_id.clone(),
        approved,
        choice,
    };

    // Find and remove the pending approval request
    let pending = {
        let mut pending = state.pending_approvals.lock().unwrap();
        pending.remove(&request_id)
    };

    match pending {
        Some(entry) => {
            if entry.responder.send(response).is_err() {
                return ServerMessage::Error {
                    id: Some(req_id.to_string()),
                    error: ErrorPayload::new(
                        ERR_INTERNAL,
                        "approval request is no longer awaiting a response",
                    ),
                };
            }

            let skill_id = entry.request.skill_id.clone();
            let action = format!("skill.{skill_id}.approval_respond");
            if let Err(e) = state.audit.append(
                "skill",
                &action,
                Some(
                    &serde_json::json!({
                        "request_id": request_id,
                        "approved": approved,
                        "has_choice": has_choice,
                    })
                    .to_string(),
                ),
                Some("admin"),
            ) {
                warn!(
                    error = %e,
                    skill_id = %skill_id,
                    "failed to append approval.respond audit event"
                );
            }

            ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({ "delivered": true }),
            }
        }
        None => ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INVALID_PARAMS,
                format!("no pending approval with request_id: {request_id}"),
            ),
        },
    }
}

/// Handler for `skills.metrics` — returns per-skill invocation/error counts.
pub async fn handle_metrics(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let skill_id = params["skill_id"].as_str().map(|s| s.trim().to_string());
    if let Some(ref skill_id) = skill_id {
        if let Err(reason) = validate_skill_id(skill_id) {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
            };
        }
        if let Err(err) = ensure_known_skill_id(state, skill_id, req_id).await {
            return err;
        }
    }

    if let Some(sid) = skill_id.as_deref() {
        let active = {
            let loaded = state.loaded_skills.read().await;
            loaded
                .iter()
                .find(|summary| summary.id == sid)
                .is_some_and(|summary| summary.enabled)
        };
        let metrics_map = state.skill_metrics.read().await;
        match metrics_map.get(sid) {
            Some(m) => {
                let last = m.last_invoked_at.lock().unwrap().clone();
                ServerMessage::Res {
                    id: req_id.to_string(),
                    result: serde_json::json!({
                        "skill_id": sid,
                        "known": true,
                        "active": active,
                        "invocations": m.invocations.load(std::sync::atomic::Ordering::Relaxed),
                        "errors": m.errors.load(std::sync::atomic::Ordering::Relaxed),
                        "last_invoked_at": last,
                    }),
                }
            }
            None => ServerMessage::Res {
                id: req_id.to_string(),
                result: serde_json::json!({
                    "skill_id": sid,
                    "known": true,
                    "active": active,
                    "invocations": 0,
                    "errors": 0,
                    "last_invoked_at": null,
                }),
            },
        }
    } else {
        let loaded_skills = state.loaded_skills.read().await;
        let metrics_map = state.skill_metrics.read().await;
        let mut all: Vec<serde_json::Value> = loaded_skills
            .iter()
            .map(|summary| match metrics_map.get(&summary.id) {
                Some(m) => {
                    let last = m.last_invoked_at.lock().unwrap().clone();
                    serde_json::json!({
                        "skill_id": summary.id,
                        "known": true,
                        "active": summary.enabled,
                        "invocations": m.invocations.load(std::sync::atomic::Ordering::Relaxed),
                        "errors": m.errors.load(std::sync::atomic::Ordering::Relaxed),
                        "last_invoked_at": last,
                    })
                }
                None => serde_json::json!({
                    "skill_id": summary.id,
                    "known": true,
                    "active": summary.enabled,
                    "invocations": 0,
                    "errors": 0,
                    "last_invoked_at": null,
                }),
            })
            .collect();
        all.sort_by(|a, b| a["skill_id"].as_str().cmp(&b["skill_id"].as_str()));
        ServerMessage::Res {
            id: req_id.to_string(),
            result: serde_json::json!({ "skills": all }),
        }
    }
}

/// Handler for `skills.config.get` — reads per-skill runtime config from `skill_kv`.
pub async fn handle_config_get(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let skill_id = match params["skill_id"].as_str() {
        Some(s) => s,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "skill_id is required"),
            }
        }
    };
    if let Err(reason) = validate_skill_id(skill_id) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
        };
    }
    if let Err(err) = ensure_known_skill_id(state, skill_id, req_id).await {
        return err;
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }
        }
    };

    let mut stmt = match conn.prepare(
        "SELECT key, value FROM skill_kv WHERE skill_id = ?1 AND key LIKE 'config:%' ORDER BY key",
    ) {
        Ok(s) => s,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }
        }
    };

    let rows: Vec<(String, Vec<u8>)> = match stmt
        .query_map(rusqlite::params![skill_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .and_then(|iter| iter.collect::<Result<Vec<_>, _>>())
    {
        Ok(r) => r,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }
        }
    };

    let mut config = serde_json::Map::new();
    for (key, value) in rows {
        let short_key = key.strip_prefix("config:").unwrap_or(&key);
        let parsed = match serde_json::from_slice::<serde_json::Value>(&value) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!(
                    skill_id = %skill_id,
                    key = %short_key,
                    error = %e,
                    "invalid skill config JSON payload; falling back to string"
                );
                serde_json::Value::String(String::from_utf8_lossy(&value).into())
            }
        };
        config.insert(short_key.to_string(), parsed);
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({ "skill_id": skill_id, "config": config }),
    }
}

/// Handler for `skills.config.set` — writes per-skill runtime config JSON to `skill_kv`.
pub async fn handle_config_set(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    // Serialize config/resource mutate+refresh sequences to avoid interleaved
    // rollback races when concurrent requests target the same skill/runtime.
    let _settings_guard = state.skill_resources_lock.lock().await;

    let skill_id = match params["skill_id"].as_str() {
        Some(s) => s,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "skill_id is required"),
            }
        }
    };
    if let Err(reason) = validate_skill_id(skill_id) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
        };
    }

    let key = match params["key"].as_str() {
        Some(s) => s,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "key is required"),
            }
        }
    };
    if let Err(reason) = validate_config_key(key) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
        };
    }

    let value = match params.get("value") {
        Some(v) => v,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "value is required"),
            };
        }
    };

    if let Err(err) = ensure_known_skill_id(state, skill_id, req_id).await {
        return err;
    }

    let prefixed_key = format!("config:{key}");
    let value_bytes = match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, format!("invalid value: {e}")),
            };
        }
    };
    if value_bytes.len() > MAX_SKILL_SETTINGS_PAYLOAD_BYTES {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INVALID_PARAMS,
                format!("value exceeds {} bytes", MAX_SKILL_SETTINGS_PAYLOAD_BYTES),
            ),
        };
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }
        }
    };

    let previous_value = match conn.query_row(
        "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
        rusqlite::params![skill_id, &prefixed_key],
        |row| row.get::<_, Vec<u8>>(0),
    ) {
        Ok(bytes) => Some(bytes),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    if let Err(e) = conn.execute(
        "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
        rusqlite::params![skill_id, &prefixed_key, value_bytes],
    ) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        };
    }

    drop(conn);

    if let Err(e) = refresh_llm_and_tool_registry(state).await {
        let rollback_result: Result<(), String> = match state.db_pool.get() {
            Ok(conn) => match previous_value {
                Some(bytes) => conn
                    .execute(
                        "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
                         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                        rusqlite::params![skill_id, &prefixed_key, bytes],
                    )
                    .map(|_| ())
                    .map_err(|err| err.to_string()),
                None => conn
                    .execute(
                        "DELETE FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                        rusqlite::params![skill_id, &prefixed_key],
                    )
                    .map(|_| ())
                    .map_err(|err| err.to_string()),
            },
            Err(pool_err) => Err(pool_err.to_string()),
        };
        let msg = match rollback_result {
            Ok(()) => format!("failed to apply config update: {e}"),
            Err(rollback_err) => {
                format!("failed to apply config update: {e}; rollback failed: {rollback_err}")
            }
        };
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, msg),
        };
    }

    if let Err(e) = state.audit.append(
        "skill",
        &format!("skill.{skill_id}.config_set"),
        Some(
            &serde_json::json!({
                "key": key,
                "value_kind": match value {
                    serde_json::Value::Null => "null",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                },
                "value_redacted": true,
            })
            .to_string(),
        ),
        Some("admin"),
    ) {
        warn!(
            error = %e,
            skill_id = %skill_id,
            key = %key,
            "failed to append skills.config.set audit event"
        );
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "ok": true,
            "skill_id": skill_id,
            "key": key,
            "refreshed": true
        }),
    }
}

/// Handler for `skills.resources.get` — returns persisted resource overrides for a skill.
pub async fn handle_resources_get(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let skill_id = match params["skill_id"].as_str() {
        Some(s) => s,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "skill_id is required"),
            }
        }
    };
    if let Err(reason) = validate_skill_id(skill_id) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
        };
    }
    if let Err(err) = ensure_known_skill_id(state, skill_id, req_id).await {
        return err;
    }

    // Read overrides from skill_kv
    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }
        }
    };

    let overrides = match conn.query_row(
        "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = '__resources'",
        rusqlite::params![skill_id],
        |row| row.get::<_, Vec<u8>>(0),
    ) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!(
                    skill_id = %skill_id,
                    error = %e,
                    "invalid __resources JSON payload; returning empty overrides"
                );
                serde_json::json!({})
            }
        },
        Err(rusqlite::Error::QueryReturnedNoRows) => serde_json::json!({}),
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "skill_id": skill_id,
            "overrides": overrides,
        }),
    }
}

/// Handler for `skills.resources.set` — stores runtime resource overrides.
pub async fn handle_resources_set(
    state: &AppState,
    params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    // Serialize resources.set end-to-end (persist + refresh + rollback) to avoid
    // interleaved rollback races between concurrent updates.
    let _resources_guard = state.skill_resources_lock.lock().await;

    let skill_id = match params["skill_id"].as_str() {
        Some(s) => s,
        None => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "skill_id is required"),
            }
        }
    };
    if let Err(reason) = validate_skill_id(skill_id) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INVALID_PARAMS, reason),
        };
    }

    let overrides = match params.get("overrides") {
        Some(v) if v.is_object() => v,
        _ => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, "overrides object is required"),
            }
        }
    };

    if let Err(err) = ensure_known_skill_id(state, skill_id, req_id).await {
        return err;
    }

    // Cap against resource ceiling from policy config
    let config = state.config.read().await;
    let ceiling = &config.plugin_policy.resource_ceiling;
    let mut capped = overrides.clone();
    if let Some(obj) = capped.as_object_mut() {
        if let Some(fuel) = obj.get("max_fuel_per_invocation").and_then(|v| v.as_u64()) {
            if fuel > ceiling.max_fuel {
                obj.insert(
                    "max_fuel_per_invocation".into(),
                    serde_json::json!(ceiling.max_fuel),
                );
            }
        }
        if let Some(wall) = obj.get("max_wall_clock_ms").and_then(|v| v.as_u64()) {
            if wall > ceiling.max_wall_clock_ms {
                obj.insert(
                    "max_wall_clock_ms".into(),
                    serde_json::json!(ceiling.max_wall_clock_ms),
                );
            }
        }
        if let Some(invocations) = obj
            .get("max_invocations_per_minute")
            .and_then(|v| v.as_u64())
        {
            let capped_invocations = invocations.min(ceiling.max_invocations_per_minute as u64);
            obj.insert(
                "max_invocations_per_minute".into(),
                serde_json::json!(capped_invocations as u32),
            );
        }
        if let Some(concurrent) = obj.get("max_concurrent").and_then(|v| v.as_u64()) {
            let capped_concurrent = concurrent.min(ceiling.max_concurrent as u64);
            obj.insert(
                "max_concurrent".into(),
                serde_json::json!(capped_concurrent as u32),
            );
        }
    }
    drop(config);

    let value_bytes = match serde_json::to_vec(&capped) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INVALID_PARAMS, format!("invalid overrides: {e}")),
            };
        }
    };
    if value_bytes.len() > MAX_SKILL_SETTINGS_PAYLOAD_BYTES {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(
                ERR_INVALID_PARAMS,
                format!(
                    "overrides exceeds {} bytes",
                    MAX_SKILL_SETTINGS_PAYLOAD_BYTES
                ),
            ),
        };
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            }
        }
    };

    let previous_value = match conn.query_row(
        "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = '__resources'",
        rusqlite::params![skill_id],
        |row| row.get::<_, Vec<u8>>(0),
    ) {
        Ok(bytes) => Some(bytes),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => {
            return ServerMessage::Error {
                id: Some(req_id.to_string()),
                error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
            };
        }
    };

    if let Err(e) = conn.execute(
        "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
         VALUES (?1, '__resources', ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
        rusqlite::params![skill_id, value_bytes],
    ) {
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, e.to_string()),
        };
    }
    drop(conn);

    if let Err(e) = refresh_llm_and_tool_registry(state).await {
        let rollback_result: Result<(), String> = match state.db_pool.get() {
            Ok(conn) => match previous_value {
                Some(bytes) => conn
                    .execute(
                        "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
                         VALUES (?1, '__resources', ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
                        rusqlite::params![skill_id, bytes],
                    )
                    .map(|_| ())
                    .map_err(|err| err.to_string()),
                None => conn
                    .execute(
                        "DELETE FROM skill_kv WHERE skill_id = ?1 AND key = '__resources'",
                        rusqlite::params![skill_id],
                    )
                    .map(|_| ())
                    .map_err(|err| err.to_string()),
            },
            Err(pool_err) => Err(pool_err.to_string()),
        };
        let msg = match rollback_result {
            Ok(()) => format!("failed to apply resources update: {e}"),
            Err(rollback_err) => {
                format!("failed to apply resources update: {e}; rollback failed: {rollback_err}")
            }
        };
        return ServerMessage::Error {
            id: Some(req_id.to_string()),
            error: ErrorPayload::new(ERR_INTERNAL, msg),
        };
    }

    if let Err(e) = state.audit.append(
        "skill",
        &format!("skill.{skill_id}.resources_set"),
        Some(
            &serde_json::json!({
                "effective_overrides": capped,
            })
            .to_string(),
        ),
        Some("admin"),
    ) {
        warn!(
            error = %e,
            skill_id = %skill_id,
            "failed to append skills.resources.set audit event"
        );
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({
            "ok": true,
            "skill_id": skill_id,
            "effective_overrides": capped,
            "refreshed": true
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use encmind_core::error::PluginError;
    use encmind_core::hooks::{HookContext, HookHandler, HookPoint, HookResult};
    use std::sync::Arc;

    struct PassHook;

    #[async_trait::async_trait]
    impl HookHandler for PassHook {
        async fn execute(&self, _ctx: &mut HookContext) -> Result<HookResult, PluginError> {
            Ok(HookResult::Continue)
        }
    }

    #[tokio::test]
    async fn skills_list_returns_empty() {
        let state = make_test_state();
        let result = handle_list(&state, serde_json::json!({}), "req-sk1").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-sk1");
                assert!(result["skills"].as_array().unwrap().is_empty());
                assert!(result["pending_approvals"].as_array().unwrap().is_empty());
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn skills_list_includes_disabled_skill() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "skill.disabled".to_string(),
                version: "1.0.0".to_string(),
                description: "disabled test skill".to_string(),
                tool_name: Some("disabled_tool".to_string()),
                hook_points: vec![],
                enabled: false,
                output_schema: None,
            });
        }

        let result = handle_list(&state, serde_json::json!({}), "req-sk-disabled").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-sk-disabled");
                let skills = result["skills"].as_array().unwrap();
                assert_eq!(skills.len(), 1);
                assert_eq!(skills[0]["id"], "skill.disabled");
                assert_eq!(skills[0]["enabled"], false);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn skills_list_sorts_by_skill_id() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "zeta.skill".to_string(),
                version: "1.0.0".to_string(),
                description: "".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
            loaded.push(crate::state::LoadedSkillSummary {
                id: "alpha.skill".to_string(),
                version: "1.0.0".to_string(),
                description: "".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }

        let result = handle_list(&state, serde_json::json!({}), "req-sk-sorted").await;
        match result {
            ServerMessage::Res { result, .. } => {
                let ids = result["skills"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s["id"].as_str().unwrap().to_string())
                    .collect::<Vec<_>>();
                assert_eq!(ids, vec!["alpha.skill", "zeta.skill"]);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn skills_list_sorts_pending_approvals_by_request_id() {
        let state = make_test_state();
        let (tx_b, _rx_b) = tokio::sync::oneshot::channel();
        let (tx_a, _rx_a) = tokio::sync::oneshot::channel();
        {
            let mut pending = state.pending_approvals.lock().unwrap();
            pending.insert(
                "req-b".to_string(),
                crate::state::PendingSkillApproval {
                    request: encmind_core::types::SkillApprovalRequest {
                        request_id: "req-b".to_string(),
                        skill_id: "skill.b".to_string(),
                        prompt: "b".to_string(),
                        options: vec![],
                    },
                    responder: tx_b,
                },
            );
            pending.insert(
                "req-a".to_string(),
                crate::state::PendingSkillApproval {
                    request: encmind_core::types::SkillApprovalRequest {
                        request_id: "req-a".to_string(),
                        skill_id: "skill.a".to_string(),
                        prompt: "a".to_string(),
                        options: vec![],
                    },
                    responder: tx_a,
                },
            );
        }

        let result = handle_list(&state, serde_json::json!({}), "req-sk-pending-sorted").await;
        match result {
            ServerMessage::Res { result, .. } => {
                let ids = result["pending_approvals"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s["request_id"].as_str().unwrap().to_string())
                    .collect::<Vec<_>>();
                assert_eq!(ids, vec!["req-a", "req-b"]);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_missing_skill_id() {
        let state = make_test_state();
        let result = handle_toggle(&state, serde_json::json!({}), "req-t1").await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t1".to_string()));
                assert!(error.message.contains("skill_id is required"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_missing_enabled() {
        let state = make_test_state();
        let result =
            handle_toggle(&state, serde_json::json!({"skill_id": "skill-a"}), "req-t2").await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t2".to_string()));
                assert!(error.message.contains("enabled"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_persists_and_returns() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "skill-a".to_string(),
                version: "1.0.0".to_string(),
                description: "test skill".to_string(),
                tool_name: Some("skill_a_tool".to_string()),
                hook_points: vec![],
                enabled: false,
                output_schema: None,
            });
        }
        let store = state.skill_toggle_store.as_ref().unwrap();
        store.set_enabled("skill-a", false).await.unwrap();
        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "skill-a", "enabled": true}),
            "req-t3",
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t3");
                assert_eq!(result["toggled"], true);
                assert_eq!(result["enabled"], true);
                assert_eq!(result["persisted_enabled"], true);
                assert_eq!(result["active"], false);
                assert_eq!(result["activation_blocked"], true);
                assert!(result["activation_note"].as_str().is_some());
            }
            _ => panic!("Expected Res"),
        }

        // Verify persistence
        assert!(store.is_enabled("skill-a").await.unwrap());
    }

    #[tokio::test]
    async fn skills_toggle_unknown_skill_rejected() {
        let state = make_test_state();
        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "does-not-exist", "enabled": false}),
            "req-t4",
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t4".to_string()));
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_rejects_invalid_skill_id_format() {
        let state = make_test_state();
        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "../etc/passwd", "enabled": false}),
            "req-t4b",
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t4b".to_string()));
                assert!(error.message.contains("allowed characters"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_rejects_leading_dot_skill_id() {
        let state = make_test_state();
        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": ".hidden", "enabled": false}),
            "req-t4c",
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t4c".to_string()));
                assert!(error.message.contains("must not start or end with '.'"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_rejects_stale_disabled_skill_id() {
        let state = make_test_state();
        let store = state.skill_toggle_store.as_ref().unwrap();
        store.set_enabled("stale-skill", false).await.unwrap();

        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "stale-skill", "enabled": true}),
            "req-t5",
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t5".to_string()));
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn skills_toggle_rejects_stale_known_skill_id_cache_entry() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        {
            let mut known = state.known_skill_ids.write().await;
            known.insert("ghost-skill".to_string());
        }

        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "ghost-skill", "enabled": true}),
            "req-t5b",
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t5b".to_string()));
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }

        let known = state.known_skill_ids.read().await;
        assert!(
            !known.contains("ghost-skill"),
            "stale known_skill_ids cache entry should be pruned"
        );
    }

    #[tokio::test]
    async fn skills_toggle_disable_removes_skill_hooks_only() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "skill-a".to_string(),
                version: "1.0.0".to_string(),
                description: "test skill".to_string(),
                tool_name: Some("skill_a_tool".to_string()),
                hook_points: vec!["before_tool_call".to_string()],
                enabled: true,
                output_schema: None,
            });
        }
        {
            let mut hooks = state.hook_registry.write().await;
            hooks
                .register(
                    HookPoint::BeforeToolCall,
                    0,
                    "skill:skill-a",
                    Arc::new(PassHook),
                    5000,
                )
                .unwrap();
            hooks
                .register(
                    HookPoint::BeforeToolCall,
                    0,
                    "native-plugin",
                    Arc::new(PassHook),
                    5000,
                )
                .unwrap();
            assert_eq!(hooks.total_hooks(), 2);
        }

        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "skill-a", "enabled": false}),
            "req-t6",
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t6");
                assert_eq!(result["enabled"], false);
            }
            _ => panic!("Expected Res"),
        }

        let hooks = state.hook_registry.read().await;
        assert_eq!(hooks.total_hooks(), 1);
    }

    #[tokio::test]
    async fn skills_toggle_reenable_restores_skill_hook() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
            cfg.plugin_policy.allow_risk_levels = vec![
                encmind_core::policy::CapabilityRiskLevel::Low,
                encmind_core::policy::CapabilityRiskLevel::Sensitive,
                encmind_core::policy::CapabilityRiskLevel::Critical,
            ];
        }

        // Minimal hook-enabled skill on disk.
        std::fs::write(
            skills_dir.join("skill-a.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
                (func (export "__on_hook") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("skill-a.toml"),
            r#"[skill]
name = "skill-a"
version = "1.0.0"

[hooks]
before_tool_call = "__on_hook"
"#,
        )
        .unwrap();

        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "skill-a".to_string(),
                version: "1.0.0".to_string(),
                description: "test skill".to_string(),
                tool_name: None,
                hook_points: vec!["before_tool_call".to_string()],
                enabled: true,
                output_schema: None,
            });
        }
        {
            let mut hooks = state.hook_registry.write().await;
            hooks
                .register(
                    HookPoint::BeforeToolCall,
                    0,
                    "skill:skill-a",
                    Arc::new(PassHook),
                    5000,
                )
                .unwrap();
            hooks
                .register(
                    HookPoint::BeforeToolCall,
                    0,
                    "native-plugin",
                    Arc::new(PassHook),
                    5000,
                )
                .unwrap();
            assert_eq!(hooks.total_hooks(), 2);
        }

        let disabled = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "skill-a", "enabled": false}),
            "req-t7-disable",
        )
        .await;
        match disabled {
            ServerMessage::Res { .. } => {}
            _ => panic!("Expected Res"),
        }
        let hooks_after_disable = state.hook_registry.read().await;
        assert_eq!(hooks_after_disable.total_hooks(), 1);
        drop(hooks_after_disable);

        let reenabled = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "skill-a", "enabled": true}),
            "req-t7-enable",
        )
        .await;
        match reenabled {
            ServerMessage::Res { .. } => {}
            _ => panic!("Expected Res"),
        }
        let hooks_after_enable = state.hook_registry.read().await;
        assert_eq!(hooks_after_enable.total_hooks(), 2);
    }

    #[tokio::test]
    async fn skills_toggle_disk_only_skill_is_allowed() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
        }

        std::fs::write(skills_dir.join("disk-only.wasm"), "(module)").unwrap();
        std::fs::write(
            skills_dir.join("disk-only.toml"),
            r#"[skill]
name = "disk-only"
version = "1.0.0"
"#,
        )
        .unwrap();
        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "disk-only", "enabled": false}),
            "req-t8",
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t8");
                assert_eq!(result["enabled"], false);
                assert_eq!(result["persisted_enabled"], false);
                assert_eq!(result["active"], false);
                assert_eq!(result["activation_blocked"], false);
                assert_eq!(result["activation_note"], serde_json::Value::Null);
            }
            _ => panic!("Expected Res"),
        }
        let store = state.skill_toggle_store.as_ref().unwrap();
        assert!(!store.is_enabled("disk-only").await.unwrap());
        let known = state.known_skill_ids.read().await;
        assert!(known.contains("disk-only"));
    }

    #[tokio::test]
    async fn skills_toggle_broken_wasm_by_stem_is_allowed() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
        }

        // Broken skill payload: wasm exists, manifest missing.
        std::fs::write(skills_dir.join("broken.wasm"), b"(module)").unwrap();

        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "broken", "enabled": false}),
            "req-t9",
        )
        .await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-t9");
                assert_eq!(result["enabled"], false);
            }
            _ => panic!("Expected Res"),
        }

        let store = state.skill_toggle_store.as_ref().unwrap();
        assert!(!store.is_enabled("broken").await.unwrap());
        let known = state.known_skill_ids.read().await;
        assert!(known.contains("broken"));
    }

    #[tokio::test]
    async fn skills_toggle_rejects_stem_alias_when_manifest_name_differs() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        let skills_dir = temp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.storage.db_path = temp.path().join("data.db");
            cfg.skills.wasm_dir = skills_dir.clone();
        }

        std::fs::write(
            skills_dir.join("stem-alias.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            )"#,
        )
        .unwrap();
        std::fs::write(
            skills_dir.join("stem-alias.toml"),
            r#"[skill]
name = "canonical-skill"
version = "1.0.0"
"#,
        )
        .unwrap();

        let result = handle_toggle(
            &state,
            serde_json::json!({"skill_id": "stem-alias", "enabled": false}),
            "req-t9-alias",
        )
        .await;

        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-t9-alias".to_string()));
                assert!(
                    error
                        .message
                        .contains("aliases manifest skill_id 'canonical-skill'"),
                    "unexpected error: {}",
                    error.message
                );
            }
            _ => panic!("Expected Error"),
        }

        let known = state.known_skill_ids.read().await;
        assert!(known.contains("canonical-skill"));
        assert!(!known.contains("stem-alias"));
    }

    #[tokio::test]
    async fn approval_respond_missing_request_id() {
        let state = make_test_state();
        let result = handle_respond(&state, serde_json::json!({}), "req-ap1").await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ap1".to_string()));
                assert!(error.message.contains("request_id is required"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn approval_respond_unknown_request_id() {
        let state = make_test_state();
        let result = handle_respond(
            &state,
            serde_json::json!({"request_id": "unknown-123", "approved": true}),
            "req-ap2",
        )
        .await;
        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ap2".to_string()));
                assert!(error.message.contains("no pending approval"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn approval_respond_delivers_to_sender() {
        let state = make_test_state();
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Register a pending approval
        {
            let mut pending = state.pending_approvals.lock().unwrap();
            pending.insert(
                "test-req-1".to_string(),
                crate::state::PendingSkillApproval {
                    request: encmind_core::types::SkillApprovalRequest {
                        request_id: "test-req-1".to_string(),
                        skill_id: "skill.echo".to_string(),
                        prompt: "allow?".to_string(),
                        options: vec!["allow".to_string(), "deny".to_string()],
                    },
                    responder: tx,
                },
            );
        }

        let result = handle_respond(
            &state,
            serde_json::json!({
                "request_id": "test-req-1",
                "approved": true,
                "choice": "allow"
            }),
            "req-ap3",
        )
        .await;

        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-ap3");
                assert_eq!(result["delivered"], true);
            }
            _ => panic!("Expected Res"),
        }

        // Verify the response was delivered
        let response = rx.await.unwrap();
        assert!(response.approved);
        assert_eq!(response.choice.as_deref(), Some("allow"));
        assert_eq!(response.request_id, "test-req-1");

        let audit_entries = state
            .audit
            .query(
                encmind_storage::audit::AuditFilter {
                    action: Some("skill.skill.echo.approval_respond".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(audit_entries.len(), 1);
        let detail = audit_entries[0]
            .detail
            .as_ref()
            .expect("approval respond audit should include detail");
        let detail_json: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(detail_json["request_id"], "test-req-1");
        assert_eq!(detail_json["approved"], true);
        assert_eq!(detail_json["has_choice"], true);
    }

    #[tokio::test]
    async fn approval_respond_defaults_approved_to_false() {
        let state = make_test_state();
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut pending = state.pending_approvals.lock().unwrap();
            pending.insert(
                "test-req-2".to_string(),
                crate::state::PendingSkillApproval {
                    request: encmind_core::types::SkillApprovalRequest {
                        request_id: "test-req-2".to_string(),
                        skill_id: "skill.echo".to_string(),
                        prompt: "allow?".to_string(),
                        options: Vec::new(),
                    },
                    responder: tx,
                },
            );
        }

        let _ = handle_respond(
            &state,
            serde_json::json!({"request_id": "test-req-2"}),
            "req-ap4",
        )
        .await;

        let response = rx.await.unwrap();
        assert!(!response.approved);
        assert!(response.choice.is_none());
    }

    #[tokio::test]
    async fn approval_respond_errors_when_request_no_longer_waiting() {
        let state = make_test_state();
        let (tx, rx) = tokio::sync::oneshot::channel::<SkillApprovalResponse>();
        drop(rx);

        {
            let mut pending = state.pending_approvals.lock().unwrap();
            pending.insert(
                "test-req-3".to_string(),
                crate::state::PendingSkillApproval {
                    request: encmind_core::types::SkillApprovalRequest {
                        request_id: "test-req-3".to_string(),
                        skill_id: "skill.echo".to_string(),
                        prompt: "allow?".to_string(),
                        options: Vec::new(),
                    },
                    responder: tx,
                },
            );
        }

        let result = handle_respond(
            &state,
            serde_json::json!({"request_id": "test-req-3", "approved": true}),
            "req-ap5",
        )
        .await;

        match result {
            ServerMessage::Error { id, error } => {
                assert_eq!(id, Some("req-ap5".to_string()));
                assert!(error.message.contains("no longer awaiting"));
            }
            _ => panic!("Expected Error"),
        }
    }

    // ---------- skills.metrics tests ----------

    #[tokio::test]
    async fn metrics_rejects_unknown_skill() {
        let state = make_test_state();
        let result = handle_metrics(
            &state,
            serde_json::json!({"skill_id": "nonexistent"}),
            "req-m1",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn metrics_returns_counts_after_increment() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "test-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "metrics test skill".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        {
            let mut map = state.skill_metrics.write().await;
            let m = Arc::new(crate::state::SkillMetrics::new());
            m.invocations.store(5, std::sync::atomic::Ordering::Relaxed);
            m.errors.store(2, std::sync::atomic::Ordering::Relaxed);
            *m.last_invoked_at.lock().unwrap() = Some("2026-03-01T00:00:00Z".to_string());
            map.insert("test-skill".into(), m);
        }
        let result = handle_metrics(
            &state,
            serde_json::json!({"skill_id": "test-skill"}),
            "req-m2",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["known"], true);
                assert_eq!(result["active"], true);
                assert_eq!(result["invocations"], 5);
                assert_eq!(result["errors"], 2);
                assert_eq!(result["last_invoked_at"], "2026-03-01T00:00:00Z");
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn metrics_returns_all_skills_when_no_id() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "a-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "a".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
            loaded.push(crate::state::LoadedSkillSummary {
                id: "b-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "b".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: false,
                output_schema: None,
            });
        }
        {
            let mut map = state.skill_metrics.write().await;
            let a_metrics = Arc::new(crate::state::SkillMetrics::new());
            a_metrics
                .invocations
                .store(2, std::sync::atomic::Ordering::Relaxed);
            map.insert("a-skill".into(), a_metrics);
            // Stale metrics entry for an unloaded skill should not be listed.
            map.insert(
                "stale-skill".into(),
                Arc::new(crate::state::SkillMetrics::new()),
            );
        }
        let result = handle_metrics(&state, serde_json::json!({}), "req-m3").await;
        match result {
            ServerMessage::Res { result, .. } => {
                let skills = result["skills"].as_array().unwrap();
                assert_eq!(skills.len(), 2);
                assert_eq!(skills[0]["skill_id"], "a-skill");
                assert_eq!(skills[0]["invocations"], 2);
                assert_eq!(skills[0]["active"], true);
                assert_eq!(skills[1]["skill_id"], "b-skill");
                assert_eq!(skills[1]["invocations"], 0);
                assert_eq!(skills[1]["active"], false);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn metrics_known_disabled_skill_reports_inactive() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "disabled-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "disabled test skill".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: false,
                output_schema: None,
            });
        }

        let result = handle_metrics(
            &state,
            serde_json::json!({"skill_id": "disabled-skill"}),
            "req-m3b",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["known"], true);
                assert_eq!(result["active"], false);
                assert_eq!(result["invocations"], 0);
                assert_eq!(result["errors"], 0);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn metrics_rejects_invalid_skill_id() {
        let state = make_test_state();
        let result =
            handle_metrics(&state, serde_json::json!({"skill_id": "bad id"}), "req-m4").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    // ---------- skills.config tests ----------

    #[tokio::test]
    async fn config_set_and_get_roundtrip() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        std::fs::write(temp.path().join("skills").join("my-skill.toml"), "# test").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }

        // Set
        let result = handle_config_set(
            &state,
            serde_json::json!({"skill_id": "my-skill", "key": "theme", "value": "dark"}),
            "req-c1",
        )
        .await;
        match &result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["ok"], true);
                assert_eq!(result["refreshed"], true);
            }
            _ => panic!("Expected Res, got {result:?}"),
        }

        let audit_entries = state
            .audit
            .query(
                encmind_storage::audit::AuditFilter {
                    action: Some("skill.my-skill.config_set".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(audit_entries.len(), 1);

        // Get
        let result = handle_config_get(
            &state,
            serde_json::json!({"skill_id": "my-skill"}),
            "req-c2",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["config"]["theme"], "dark");
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn config_get_requires_skill_id() {
        let state = make_test_state();
        let result = handle_config_get(&state, serde_json::json!({}), "req-c3").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_set_requires_all_fields() {
        let state = make_test_state();
        let result =
            handle_config_set(&state, serde_json::json!({"skill_id": "x"}), "req-c4").await;
        match result {
            ServerMessage::Error { error, .. } => assert!(error.message.contains("key")),
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_get_rejects_invalid_skill_id() {
        let state = make_test_state();
        let result =
            handle_config_get(&state, serde_json::json!({"skill_id": "bad id"}), "req-c5").await;
        match result {
            ServerMessage::Error { error, .. } => assert!(error.message.contains("skill_id")),
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_get_rejects_unknown_skill_id() {
        let state = make_test_state();
        let result = handle_config_get(
            &state,
            serde_json::json!({"skill_id": "missing-skill"}),
            "req-c5b",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_set_rejects_invalid_key() {
        let state = make_test_state();
        let result = handle_config_set(
            &state,
            serde_json::json!({"skill_id": "my-skill", "key": "bad key", "value": "x"}),
            "req-c6",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => assert!(error.message.contains("key")),
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_set_rejects_key_with_surrounding_whitespace() {
        let state = make_test_state();
        let result = handle_config_set(
            &state,
            serde_json::json!({"skill_id": "my-skill", "key": "  theme  ", "value": "x"}),
            "req-c6b",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("leading or trailing whitespace"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_set_and_get_structured_json_value() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        std::fs::write(temp.path().join("skills").join("my-skill.toml"), "# test").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        let result = handle_config_set(
            &state,
            serde_json::json!({
                "skill_id": "my-skill",
                "key": "options",
                "value": { "enabled": true, "retries": 2, "tags": ["a", "b"] }
            }),
            "req-c7",
        )
        .await;
        match result {
            ServerMessage::Res { .. } => {}
            _ => panic!("Expected Res"),
        }

        let result = handle_config_get(
            &state,
            serde_json::json!({"skill_id": "my-skill"}),
            "req-c8",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["config"]["options"]["enabled"], true);
                assert_eq!(result["config"]["options"]["retries"], 2);
                assert_eq!(result["config"]["options"]["tags"][0], "a");
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn config_set_rejects_oversized_value() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "my-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }

        let oversized = "x".repeat(MAX_SKILL_SETTINGS_PAYLOAD_BYTES + 1);
        let result = handle_config_set(
            &state,
            serde_json::json!({
                "skill_id": "my-skill",
                "key": "blob",
                "value": oversized,
            }),
            "req-c8b",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("exceeds"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn config_set_rejects_unknown_skill_id() {
        let state = make_test_state();
        let result = handle_config_set(
            &state,
            serde_json::json!({"skill_id": "missing-skill", "key": "theme", "value": "dark"}),
            "req-c9",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn config_set_rolls_back_when_refresh_fails() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "my-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = std::path::PathBuf::from("/nonexistent/skills-dir");
        }

        let conn = state.db_pool.get().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            rusqlite::params!["my-skill", "config:theme", serde_json::to_vec(&serde_json::json!("old")).unwrap()],
        )
        .unwrap();
        drop(conn);

        let result = handle_config_set(
            &state,
            serde_json::json!({"skill_id": "my-skill", "key": "theme", "value": "new"}),
            "req-c10",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("failed to apply config update"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }

        let conn = state.db_pool.get().unwrap();
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
                rusqlite::params!["my-skill", "config:theme"],
                |row| row.get(0),
            )
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, serde_json::json!("old"));
    }

    // ---------- skills.resources tests ----------

    #[tokio::test]
    async fn resources_set_and_get_roundtrip() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        std::fs::write(temp.path().join("skills").join("my-skill.toml"), "# test").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }

        let result = handle_resources_set(
            &state,
            serde_json::json!({
                "skill_id": "my-skill",
                "overrides": {"max_wall_clock_ms": 5000, "max_concurrent": 2}
            }),
            "req-r1",
        )
        .await;
        match &result {
            ServerMessage::Res { result, .. } => assert_eq!(result["ok"], true),
            _ => panic!("Expected Res, got {result:?}"),
        }

        let audit_entries = state
            .audit
            .query(
                encmind_storage::audit::AuditFilter {
                    action: Some("skill.my-skill.resources_set".to_string()),
                    ..Default::default()
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(audit_entries.len(), 1);

        let result = handle_resources_get(
            &state,
            serde_json::json!({"skill_id": "my-skill"}),
            "req-r2",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["overrides"]["max_wall_clock_ms"], 5000);
                assert_eq!(result["overrides"]["max_concurrent"], 2);
            }
            _ => panic!("Expected Res"),
        }
    }

    #[tokio::test]
    async fn resources_set_requires_overrides_object() {
        let state = make_test_state();
        let result =
            handle_resources_set(&state, serde_json::json!({"skill_id": "x"}), "req-r3").await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("overrides"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn resources_set_rejects_unknown_skill_id() {
        let state = make_test_state();
        let result = handle_resources_set(
            &state,
            serde_json::json!({
                "skill_id": "missing-skill",
                "overrides": {"max_wall_clock_ms": 5000}
            }),
            "req-r6",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn resources_get_rejects_invalid_skill_id() {
        let state = make_test_state();
        let result =
            handle_resources_get(&state, serde_json::json!({"skill_id": "bad id"}), "req-r4").await;
        match result {
            ServerMessage::Error { error, .. } => assert!(error.message.contains("skill_id")),
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn resources_get_rejects_unknown_skill_id() {
        let state = make_test_state();
        let result = handle_resources_get(
            &state,
            serde_json::json!({"skill_id": "missing-skill"}),
            "req-r4b",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert!(error.message.contains("unknown skill_id"));
            }
            _ => panic!("Expected Error"),
        }
    }

    #[tokio::test]
    async fn resources_set_rejects_oversized_overrides() {
        let state = make_test_state();
        {
            let mut loaded = state.loaded_skills.write().await;
            loaded.push(crate::state::LoadedSkillSummary {
                id: "my-skill".to_string(),
                version: "1.0.0".to_string(),
                description: "test".to_string(),
                tool_name: None,
                hook_points: vec![],
                enabled: true,
                output_schema: None,
            });
        }
        let oversized = "x".repeat(MAX_SKILL_SETTINGS_PAYLOAD_BYTES + 1);
        let result = handle_resources_set(
            &state,
            serde_json::json!({
                "skill_id": "my-skill",
                "overrides": { "notes": oversized }
            }),
            "req-r4c",
        )
        .await;
        match result {
            ServerMessage::Error { error, .. } => {
                assert_eq!(error.code, ERR_INVALID_PARAMS);
                assert!(error.message.contains("exceeds"));
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resources_get_returns_empty_for_malformed_json_payload() {
        let state = make_test_state();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("skills")).unwrap();
        std::fs::write(temp.path().join("skills").join("my-skill.toml"), "# test").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.skills.wasm_dir = temp.path().join("skills");
        }
        let conn = state.db_pool.get().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
             VALUES (?1, '__resources', ?2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            rusqlite::params!["my-skill", b"not-json".to_vec()],
        )
        .unwrap();
        drop(conn);

        let result = handle_resources_get(
            &state,
            serde_json::json!({"skill_id": "my-skill"}),
            "req-r5",
        )
        .await;
        match result {
            ServerMessage::Res { result, .. } => {
                assert_eq!(result["overrides"], serde_json::json!({}));
            }
            _ => panic!("Expected Res"),
        }
    }
}
