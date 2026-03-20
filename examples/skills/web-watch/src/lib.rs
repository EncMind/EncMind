// EncMind Skill: web-watch — Web Page Change Monitor (Native ABI)
//
// Capabilities used: net_outbound, kv, emit_events
// Tool actions: add, remove, list, check
// Timer: __timer_poll — polls all watched URLs on schedule

use chrono::DateTime;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Host function imports (encmind Native ABI)
// ---------------------------------------------------------------------------

#[link(wasm_import_module = "encmind")]
extern "C" {
    fn __encmind_net_fetch(url_ptr: i32, url_len: i32) -> i64;
    fn __encmind_kv_get(key_ptr: i32, key_len: i32) -> i64;
    fn __encmind_kv_set(
        key_ptr: i32,
        key_len: i32,
        val_ptr: i32,
        val_len: i32,
    ) -> i32;
    fn __encmind_kv_delete(key_ptr: i32, key_len: i32) -> i32;
    fn __encmind_kv_list(prefix_ptr: i32, prefix_len: i32) -> i64;
    fn __encmind_hooks_emit(event_ptr: i32, event_len: i32) -> i64;
    fn __encmind_log(level: i32, msg_ptr: i32, msg_len: i32) -> i32;
}

// ---------------------------------------------------------------------------
// ABI helpers (fat-pointer protocol)
// ---------------------------------------------------------------------------

/// Decode a fat pointer (ptr << 32 | len) and read the bytes from guest memory.
fn read_fat_ptr(fat: i64) -> Option<Vec<u8>> {
    if fat == 0 {
        return None;
    }
    let ptr = (fat >> 32) as i32;
    let len = (fat & 0xFFFF_FFFF) as i32;
    if ptr == 0 || len <= 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    Some(slice.to_vec())
}

/// Write bytes to guest memory and return (ptr, len).
fn write_to_guest(data: &[u8]) -> (i32, i32) {
    let ptr = encmind_skill_sdk::alloc_guest(data.len() as i32);
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
    }
    (ptr, data.len() as i32)
}

// ---------------------------------------------------------------------------
// Wrappers around host functions
// ---------------------------------------------------------------------------

fn log_info(msg: &str) {
    let (ptr, len) = write_to_guest(msg.as_bytes());
    unsafe { __encmind_log(2, ptr, len) };
}

fn log_warn(msg: &str) {
    let (ptr, len) = write_to_guest(msg.as_bytes());
    unsafe { __encmind_log(3, ptr, len) };
}

fn kv_get(key: &str) -> Option<Vec<u8>> {
    let (ptr, len) = write_to_guest(key.as_bytes());
    let fat = unsafe { __encmind_kv_get(ptr, len) };
    read_fat_ptr(fat)
}

fn kv_set(key: &str, value: &[u8]) -> bool {
    let (kp, kl) = write_to_guest(key.as_bytes());
    let (vp, vl) = write_to_guest(value);
    unsafe { __encmind_kv_set(kp, kl, vp, vl) == 0 }
}

fn kv_delete(key: &str) -> bool {
    let (ptr, len) = write_to_guest(key.as_bytes());
    unsafe { __encmind_kv_delete(ptr, len) == 0 }
}

fn kv_list(prefix: &str) -> Vec<String> {
    let (ptr, len) = write_to_guest(prefix.as_bytes());
    let fat = unsafe { __encmind_kv_list(ptr, len) };
    match read_fat_ptr(fat) {
        Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        None => Vec::new(),
    }
}

fn net_fetch(url: &str) -> Result<Value, String> {
    let (ptr, len) = write_to_guest(url.as_bytes());
    let fat = unsafe { __encmind_net_fetch(ptr, len) };
    match read_fat_ptr(fat) {
        Some(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("parse fetch response: {e}"))
        }
        None => Err("net_fetch returned null (denied or network error)".into()),
    }
}

fn emit_event(event_type: &str, payload: &Value) -> bool {
    let event = json!({ "type": event_type, "payload": payload });
    let bytes = serde_json::to_vec(&event).unwrap_or_default();
    let (ptr, len) = write_to_guest(&bytes);
    let fat = unsafe { __encmind_hooks_emit(ptr, len) };
    fat != 0
}

// ---------------------------------------------------------------------------
// Watch entry stored in KV
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct WatchEntry {
    url: String,
    interval_minutes: u64,
    content_hash: String,
    last_check_epoch: u64,
    change_count: u64,
}

const KV_PREFIX: &str = "watch:";

fn watch_key(url: &str) -> String {
    format!("{KV_PREFIX}{url}")
}

// ---------------------------------------------------------------------------
// Content hashing
// ---------------------------------------------------------------------------

const HASH_SAMPLE_BYTES: usize = 128 * 1024;

fn hash_content(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"len:");
    hasher.update((bytes.len() as u64).to_le_bytes());
    if bytes.len() <= HASH_SAMPLE_BYTES * 2 {
        hasher.update(bytes);
    } else {
        hasher.update(&bytes[..HASH_SAMPLE_BYTES]);
        hasher.update(&bytes[bytes.len() - HASH_SAMPLE_BYTES..]);
    }

    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Fetch a page and return (status, hash)
// ---------------------------------------------------------------------------

fn fetch_page(url: &str) -> Result<(u64, String), String> {
    let resp = net_fetch(url)?;
    let status = resp
        .get("status")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let body = resp
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let h = hash_content(body);
    Ok((status, h))
}

// ---------------------------------------------------------------------------
// Current epoch (seconds). WASM has no clock, so we keep the latest timer
// timestamp in KV and reuse it for tool actions.
// ---------------------------------------------------------------------------

fn current_epoch() -> u64 {
    // `__timer_poll` stores the host-provided timer timestamp here.
    // When unavailable (legacy payloads), we synthesize ticks via bump_epoch.
    match kv_get("__epoch") {
        Some(bytes) => {
            let s = String::from_utf8_lossy(&bytes);
            s.trim().parse().unwrap_or(0)
        }
        None => 0,
    }
}

fn set_epoch(now: u64) {
    let _ = kv_set("__epoch", now.to_string().as_bytes());
}

fn bump_epoch(increment: u64) -> u64 {
    let now = current_epoch() + increment;
    set_epoch(now);
    now
}

fn epoch_from_rfc3339(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|dt| u64::try_from(dt.timestamp()).ok())
}

fn epoch_from_timer_payload(payload: &Value) -> Option<u64> {
    payload
        .get("next_tick_at")
        .and_then(|v| v.as_str())
        .and_then(epoch_from_rfc3339)
        .or_else(|| {
            payload
                .get("last_tick_at")
                .and_then(|v| v.as_str())
                .and_then(epoch_from_rfc3339)
        })
}

fn resolve_timer_epoch(payload: &Value) -> u64 {
    if let Some(now) = epoch_from_timer_payload(payload) {
        set_epoch(now);
        return now;
    }
    // Backward-compatible fallback when timer metadata is missing.
    bump_epoch(fallback_epoch_increment_secs())
}

fn fallback_epoch_increment_secs() -> u64 {
    let mut min_secs: Option<u64> = None;
    for key in kv_list(KV_PREFIX) {
        let Some(bytes) = kv_get(&key) else {
            continue;
        };
        let Ok(entry) = serde_json::from_slice::<WatchEntry>(&bytes) else {
            continue;
        };
        let secs = entry.interval_minutes.saturating_mul(60).max(60);
        min_secs = Some(min_secs.map_or(secs, |cur| cur.min(secs)));
    }
    min_secs.unwrap_or(60)
}

// ---------------------------------------------------------------------------
// Tool handler
// ---------------------------------------------------------------------------

fn handle(input: Value) -> Value {
    let action = input
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match action {
        "add" => handle_add(&input),
        "remove" => handle_remove(&input),
        "list" => handle_list(),
        "check" => handle_check(&input),
        _ => json!({ "error": format!("unknown action '{action}'; use add, remove, list, or check") }),
    }
}

fn handle_add(input: &Value) -> Value {
    let url = match input.get("url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u,
        _ => return json!({ "error": "'url' is required for add action" }),
    };

    let interval = input
        .get("interval_minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
        .max(1);

    // Fetch initial content
    let (status, content_hash) = match fetch_page(url) {
        Ok(r) => r,
        Err(e) => return json!({ "error": format!("failed to fetch '{url}': {e}") }),
    };

    if status >= 400 {
        return json!({ "error": format!("fetch returned HTTP {status} for '{url}'") });
    }

    let entry = WatchEntry {
        url: url.to_string(),
        interval_minutes: interval,
        content_hash,
        last_check_epoch: current_epoch(),
        change_count: 0,
    };

    let value = serde_json::to_vec(&entry).unwrap_or_default();
    if !kv_set(&watch_key(url), &value) {
        return json!({ "error": "failed to store watch entry" });
    }

    log_info(&format!("added watch: {url} (every {interval} min)"));

    json!({
        "result": format!("watching '{url}' every {interval} minutes"),
        "url": url,
        "interval_minutes": interval,
        "initial_hash": entry.content_hash,
    })
}

fn handle_remove(input: &Value) -> Value {
    let url = match input.get("url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u,
        _ => return json!({ "error": "'url' is required for remove action" }),
    };

    if kv_delete(&watch_key(url)) {
        log_info(&format!("removed watch: {url}"));
        json!({ "result": format!("stopped watching '{url}'"), "url": url })
    } else {
        json!({ "error": format!("no watch found for '{url}'") })
    }
}

fn handle_list() -> Value {
    let keys = kv_list(KV_PREFIX);
    let mut watches = Vec::new();

    for key in &keys {
        if let Some(bytes) = kv_get(key) {
            if let Ok(entry) = serde_json::from_slice::<WatchEntry>(&bytes) {
                watches.push(json!({
                    "url": entry.url,
                    "interval_minutes": entry.interval_minutes,
                    "content_hash": entry.content_hash,
                    "change_count": entry.change_count,
                }));
            }
        }
    }

    json!({
        "result": format!("{} active watches", watches.len()),
        "watches": watches,
    })
}

fn handle_check(input: &Value) -> Value {
    let url = match input.get("url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u,
        _ => return json!({ "error": "'url' is required for check action" }),
    };

    // Load existing entry (if any)
    let existing = kv_get(&watch_key(url))
        .and_then(|b| serde_json::from_slice::<WatchEntry>(&b).ok());

    // Fetch current content
    let (status, new_hash) = match fetch_page(url) {
        Ok(r) => r,
        Err(e) => return json!({ "error": format!("failed to fetch '{url}': {e}") }),
    };

    if status >= 400 {
        return json!({ "error": format!("fetch returned HTTP {status}") });
    }

    let changed = existing
        .as_ref()
        .map(|e| e.content_hash != new_hash)
        .unwrap_or(false);

    // Update entry if it exists
    if let Some(mut entry) = existing {
        let old_hash = entry.content_hash.clone();
        entry.content_hash = new_hash.clone();
        entry.last_check_epoch = current_epoch();
        if changed {
            entry.change_count += 1;
        }
        let value = serde_json::to_vec(&entry).unwrap_or_default();
        let key = watch_key(url);
        if !kv_set(&key, &value) {
            log_warn(&format!("check: failed to persist watch state for {url}"));
            return json!({ "error": format!("failed to persist watch state for '{url}'") });
        }

        if changed {
            emit_event(
                "web_watch.changed",
                &json!({
                    "url": url,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                    "change_count": entry.change_count,
                }),
            );
        }
    }

    json!({
        "result": if changed { "changed" } else { "unchanged" },
        "url": url,
        "hash": new_hash,
        "changed": changed,
    })
}

// ---------------------------------------------------------------------------
// Timer: poll all watches
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn __timer_poll(ptr: i32, len: i32) -> i64 {
    let payload = encmind_skill_sdk::decode_input(ptr, len).unwrap_or_else(|_| json!({}));
    let now = resolve_timer_epoch(&payload);

    let keys = kv_list(KV_PREFIX);
    let mut checked = 0u32;
    let mut changed = 0u32;
    let mut errors = 0u32;

    for key in &keys {
        let bytes = match kv_get(key) {
            Some(b) => b,
            None => continue,
        };
        let mut entry: WatchEntry = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Check if enough time has passed (interval_minutes * 60 seconds)
        let interval_secs = entry.interval_minutes * 60;
        if now.saturating_sub(entry.last_check_epoch) < interval_secs {
            continue;
        }

        checked += 1;

        match fetch_page(&entry.url) {
            Ok((status, new_hash)) => {
                if status >= 400 {
                    entry.last_check_epoch = now;
                    let value = serde_json::to_vec(&entry).unwrap_or_default();
                    if !kv_set(key, &value) {
                        log_warn(&format!(
                            "watch poll: failed to persist HTTP error checkpoint for {}",
                            entry.url
                        ));
                    }
                    log_warn(&format!(
                        "watch poll: {} returned HTTP {}",
                        entry.url, status
                    ));
                    errors += 1;
                    continue;
                }

                let old_hash = entry.content_hash.clone();
                let is_changed = old_hash != new_hash;

                entry.content_hash = new_hash.clone();
                entry.last_check_epoch = now;
                if is_changed {
                    entry.change_count += 1;
                }

                let value = serde_json::to_vec(&entry).unwrap_or_default();
                if !kv_set(key, &value) {
                    log_warn(&format!(
                        "watch poll: failed to persist watch state for {}",
                        entry.url
                    ));
                    errors += 1;
                    continue;
                }

                if is_changed {
                    changed += 1;
                    emit_event(
                        "web_watch.changed",
                        &json!({
                            "url": entry.url,
                            "old_hash": old_hash,
                            "new_hash": new_hash,
                            "change_count": entry.change_count,
                        }),
                    );

                    log_info(&format!(
                        "change detected: {} (count={})",
                        entry.url, entry.change_count
                    ));
                }
            }
            Err(e) => {
                entry.last_check_epoch = now;
                let value = serde_json::to_vec(&entry).unwrap_or_default();
                if !kv_set(key, &value) {
                    log_warn(&format!(
                        "watch poll: failed to persist error checkpoint for {}",
                        entry.url
                    ));
                }
                log_warn(&format!("watch poll failed for {}: {e}", entry.url));
                errors += 1;
            }
        }
    }

    // Return a summary as the timer result
    let result = json!({
        "checked": checked,
        "changed": changed,
        "errors": errors,
        "total_watches": keys.len(),
    });

    let bytes = serde_json::to_vec(&result).unwrap_or_default();
    let (out_ptr, out_len) = write_to_guest(&bytes);
    ((out_ptr as i64) << 32) | (out_len as i64)
}

// ---------------------------------------------------------------------------
// Export tool handler via SDK macro
// ---------------------------------------------------------------------------

encmind_skill_sdk::export_tool!(handle);
