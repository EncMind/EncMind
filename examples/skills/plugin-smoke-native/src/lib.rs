// EncMind Skill: Plugin Smoke Test (Rust / Native ABI)
//
// Exercises all Native ABI plugin capabilities:
// - Tool with output schema validation
// - KV host functions (get/set/delete)
// - Config host functions
// - Context host functions
// - Event emission
// - Approval prompts
// - Logging
// - Hooks (before/after tool call)
// - Timers (healthy + intentional failure)
// - Channel transforms (inbound/outbound)
//
// Build:
//   cargo build --release --target wasm32-unknown-unknown
//   # or: encmind-skill build .

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Host function imports (provided by the WASM runtime)
// ---------------------------------------------------------------------------
#[link(wasm_import_module = "encmind")]
extern "C" {
    fn __encmind_net_fetch(url_ptr: i32, url_len: i32) -> i64;
    fn __encmind_kv_get(key_ptr: i32, key_len: i32) -> i64;
    fn __encmind_kv_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;
    fn __encmind_kv_delete(key_ptr: i32, key_len: i32) -> i32;
    fn __encmind_kv_list(prefix_ptr: i32, prefix_len: i32) -> i64;
    fn __encmind_config_get(key_ptr: i32, key_len: i32) -> i64;
    fn __encmind_context_get() -> i64;
    fn __encmind_hooks_emit(event_ptr: i32, event_len: i32) -> i64;
    fn __encmind_approval_prompt(prompt_ptr: i32, prompt_len: i32) -> i64;
    fn __encmind_log(level: i32, msg_ptr: i32, msg_len: i32) -> i32;
}

// ---------------------------------------------------------------------------
// ABI helpers
// ---------------------------------------------------------------------------

/// Decode a fat pointer `(ptr << 32) | len` and read bytes from guest memory.
///
/// # Safety
/// The host wrote data into memory allocated by our `__encmind_alloc`, so the
/// pointer is within the module's linear memory.
unsafe fn read_fat_ptr(fat: i64) -> Option<Vec<u8>> {
    if fat == 0 {
        return None;
    }
    let ptr = (fat >> 32) as i32;
    let len = (fat & 0xFFFF_FFFF) as i32;
    if ptr <= 0 || len <= 0 {
        return None;
    }
    let slice = core::slice::from_raw_parts(ptr as *const u8, len as usize);
    Some(slice.to_vec())
}

/// Write bytes into guest memory using the SDK allocator. Returns (ptr, len).
fn write_to_guest(data: &[u8]) -> (i32, i32) {
    let ptr = encmind_skill_sdk::alloc_guest(data.len() as i32);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
    }
    (ptr, data.len() as i32)
}

// ---------------------------------------------------------------------------
// Typed wrappers around host functions
// ---------------------------------------------------------------------------

fn call_kv_get(key: &str) -> Option<String> {
    let (ptr, len) = write_to_guest(key.as_bytes());
    let fat = unsafe { __encmind_kv_get(ptr, len) };
    unsafe { read_fat_ptr(fat) }.and_then(|bytes| String::from_utf8(bytes).ok())
}

fn call_kv_set(key: &str, value: &str) {
    let (kp, kl) = write_to_guest(key.as_bytes());
    let (vp, vl) = write_to_guest(value.as_bytes());
    unsafe { __encmind_kv_set(kp, kl, vp, vl) };
}

fn call_kv_list(prefix: &str) -> Option<Vec<String>> {
    let (ptr, len) = write_to_guest(prefix.as_bytes());
    let fat = unsafe { __encmind_kv_list(ptr, len) };
    unsafe { read_fat_ptr(fat) }.and_then(|bytes| serde_json::from_slice::<Vec<String>>(&bytes).ok())
}

fn call_net_fetch(url: &str) -> Option<Value> {
    let (ptr, len) = write_to_guest(url.as_bytes());
    let fat = unsafe { __encmind_net_fetch(ptr, len) };
    unsafe { read_fat_ptr(fat) }.and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
}

fn call_log(level: i32, msg: &str) {
    let (ptr, len) = write_to_guest(msg.as_bytes());
    unsafe { __encmind_log(level, ptr, len) };
}

// ---------------------------------------------------------------------------
// Tool handler — dispatched via `mode` field
// ---------------------------------------------------------------------------

fn handle(input: Value) -> Value {
    let mode = input.get("mode").and_then(|v| v.as_str()).unwrap_or("echo");

    match mode {
        // Basic tool + output schema conformance
        "echo" => {
            let msg = serde_json::to_string(&input).unwrap_or_default();
            json!({ "result": format!("echo: {msg}") })
        }

        // Intentional schema violation: missing required "result" field
        "bad_output" => {
            json!({ "wrong_field": 123 })
        }

        // KV get + set: increment a counter
        "kv_counter" => {
            let key = input
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("counter");
            let current: u64 = call_kv_get(key)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let next = current + 1;
            call_kv_set(key, &next.to_string());
            json!({ "result": format!("counter={next}") })
        }

        // KV list by prefix
        "kv_list" => {
            let prefix = input
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let keys = call_kv_list(prefix).unwrap_or_default();
            let keys_json = serde_json::to_string(&keys).unwrap_or_else(|_| "[]".to_string());
            json!({ "result": format!("keys={keys_json}") })
        }

        // Net probe (deterministic in tests: use a disallowed domain by default).
        // Returns net_ok:<status> on success, net_error when host returns null fat ptr.
        "net_probe" => {
            let url = input
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("https://forbidden.invalid");
            match call_net_fetch(url) {
                Some(resp) => {
                    let status = resp
                        .get("status")
                        .and_then(|v| v.as_u64())
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    json!({ "result": format!("net_ok:{status}") })
                }
                None => json!({ "result": "net_error" }),
            }
        }

        // Context API
        "context_echo" => {
            let fat = unsafe { __encmind_context_get() };
            let ctx_str = unsafe { read_fat_ptr(fat) }
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "null".to_string());
            json!({ "result": ctx_str })
        }

        // Config API
        "config_probe" => {
            let key = input
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("mode");
            let (ptr, len) = write_to_guest(key.as_bytes());
            let fat = unsafe { __encmind_config_get(ptr, len) };
            let val_str = unsafe { read_fat_ptr(fat) }
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "null".to_string());
            json!({ "result": val_str })
        }

        // Event emission
        "emit_event" => {
            let event = json!({
                "type": "smoke.test",
                "payload": { "source": "plugin-smoke-native" }
            });
            let event_bytes = serde_json::to_vec(&event).unwrap_or_default();
            let (ptr, len) = write_to_guest(&event_bytes);
            let fat = unsafe { __encmind_hooks_emit(ptr, len) };
            let result_str = unsafe { read_fat_ptr(fat) }
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "null".to_string());
            json!({ "result": result_str })
        }

        // Approval prompt
        "needs_approval" => {
            let prompt = json!({
                "prompt": "Smoke test approval request",
                "options": ["approve", "deny"]
            });
            let prompt_bytes = serde_json::to_vec(&prompt).unwrap_or_default();
            let (ptr, len) = write_to_guest(&prompt_bytes);
            let fat = unsafe { __encmind_approval_prompt(ptr, len) };
            let result_str = unsafe { read_fat_ptr(fat) }
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_else(|| "null".to_string());
            json!({ "result": result_str })
        }

        // KV delete
        "kv_delete" => {
            let key = input
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("counter");
            let (ptr, len) = write_to_guest(key.as_bytes());
            let rc = unsafe { __encmind_kv_delete(ptr, len) };
            json!({ "result": format!("deleted rc={rc}") })
        }

        other => {
            json!({ "result": format!("unknown mode: {other}") })
        }
    }
}

// Export __encmind_alloc and __encmind_invoke via the SDK macro.
encmind_skill_sdk::export_tool!(handle);

// ---------------------------------------------------------------------------
// Named exports: hooks
// ---------------------------------------------------------------------------

/// Hook: before_tool_call — logs and passes through.
#[no_mangle]
pub extern "C" fn __on_before_tool(ptr: i32, len: i32) -> i64 {
    call_log(2, "hook:before_tool_call fired");
    let input = encmind_skill_sdk::decode_input(ptr, len).unwrap_or_default();
    let output = json!({ "action": "continue", "payload": input });
    encmind_skill_sdk::encode_output(&output)
}

/// Hook: after_tool_call — logs and passes through.
#[no_mangle]
pub extern "C" fn __on_after_tool(ptr: i32, len: i32) -> i64 {
    call_log(2, "hook:after_tool_call fired");
    let input = encmind_skill_sdk::decode_input(ptr, len).unwrap_or_default();
    let output = json!({ "action": "continue", "payload": input });
    encmind_skill_sdk::encode_output(&output)
}

// ---------------------------------------------------------------------------
// Named exports: timers
// ---------------------------------------------------------------------------

/// Timer: heartbeat_ok — increments KV counter and logs.
#[no_mangle]
pub extern "C" fn __on_heartbeat_ok(_ptr: i32, _len: i32) -> i64 {
    let current: u64 = call_kv_get("heartbeat_count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let next = current + 1;
    call_kv_set("heartbeat_count", &next.to_string());
    call_log(2, &format!("heartbeat_ok: count={next}"));
    let output = json!({ "result": format!("heartbeat count={next}") });
    encmind_skill_sdk::encode_output(&output)
}

/// Timer: heartbeat_fail — intentional failure for auto-disable testing.
#[no_mangle]
pub extern "C" fn __on_heartbeat_fail(_ptr: i32, _len: i32) -> i64 {
    call_log(4, "heartbeat_fail: intentional failure");
    let output = json!({ "error": "intentional failure for auto-disable testing" });
    encmind_skill_sdk::encode_output(&output)
}

// ---------------------------------------------------------------------------
// Named exports: channel transforms
// ---------------------------------------------------------------------------

/// Transform: inbound — prefix message content with [smoke-in].
#[no_mangle]
pub extern "C" fn __transform_inbound(ptr: i32, len: i32) -> i64 {
    let mut input = encmind_skill_sdk::decode_input(ptr, len).unwrap_or_default();
    if let Some(content) = input.get("content").and_then(|v| v.as_str()) {
        input["content"] = Value::String(format!("[smoke-in] {content}"));
    }
    encmind_skill_sdk::encode_output(&input)
}

/// Transform: outbound — append [smoke-out] tag to message content.
#[no_mangle]
pub extern "C" fn __transform_outbound(ptr: i32, len: i32) -> i64 {
    let mut input = encmind_skill_sdk::decode_input(ptr, len).unwrap_or_default();
    if let Some(content) = input.get("content").and_then(|v| v.as_str()) {
        input["content"] = Value::String(format!("{content} [smoke-out]"));
    }
    encmind_skill_sdk::encode_output(&input)
}
