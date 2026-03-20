//! ABI helpers for data passing between host and WASM guest.
//!
//! Convention:
//! - **WASM→Host**: Guest passes `(ptr: i32, len: i32)` pointing into linear memory.
//! - **Host→WASM**: Host calls guest-exported `__encmind_alloc(len) -> ptr`, writes bytes,
//!   returns a fat pointer `(ptr << 32) | len` encoded as i64.
//! - **Errors**: Return 0i64 (null fat pointer); error message stored in `StoreState.last_error`.

use encmind_core::error::WasmHostError;
use encmind_core::traits::{SKILL_HOST_ABI_JAVY, SKILL_HOST_ABI_V1};
use wasmtime::{Memory, Module, StoreContext, StoreContextMut, TypedFunc};

use crate::runtime::StoreState;

/// The ABI variant used by a compiled WASM skill module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillAbi {
    /// Native ABI: exports `__encmind_alloc` + `__encmind_invoke`, full host function access.
    Native,
    /// Javy ABI: exports `_start`, uses WASI stdin/stdout for JSON I/O, tool invocation only.
    Javy,
}

/// Detect the ABI of a compiled WASM module by inspecting its exports.
///
/// - If the module exports `__encmind_invoke`, it uses the **Native** ABI.
/// - If the module exports `_start` (WASI entry point), it uses the **Javy** ABI.
/// - If neither is found, defaults to **Native** (will error at invocation time).
pub fn detect_abi(module: &Module) -> SkillAbi {
    let exports: Vec<String> = module.exports().map(|e| e.name().to_string()).collect();
    if exports.iter().any(|e| e == "__encmind_invoke") {
        SkillAbi::Native
    } else if exports.iter().any(|e| e == "_start") {
        SkillAbi::Javy
    } else {
        SkillAbi::Native
    }
}

/// Resolve expected ABI from a manifest `host_abi` value.
pub fn expected_abi_from_manifest(host_abi: &str) -> Result<SkillAbi, String> {
    match host_abi {
        SKILL_HOST_ABI_V1 => Ok(SkillAbi::Native),
        SKILL_HOST_ABI_JAVY => Ok(SkillAbi::Javy),
        other => Err(format!(
            "unsupported host_abi '{other}'; supported values: {SKILL_HOST_ABI_V1}, {SKILL_HOST_ABI_JAVY}"
        )),
    }
}

/// Maximum size for a single guest read/write (16 MiB).
pub const MAX_GUEST_BYTES: usize = 16 * 1024 * 1024;
/// Reserved top-level JSON object key used by Javy runtime envelopes.
/// Note: single underscore prefix — `"__encmind"` (double) triggers a
/// QuickJS atom-table bug in Javy 3.0 that corrupts `Uint8Array` type checks.
pub const JAVY_RUNTIME_ENVELOPE_KEY: &str = "_encmind";
/// Legacy reserved envelope key used by older Javy skill templates.
pub const JAVY_RUNTIME_ENVELOPE_KEY_LEGACY: &str = "__encmind";
/// Reserved error field inside the Javy runtime envelope.
pub const JAVY_RUNTIME_ERROR_KEY: &str = "runtime_error";

/// Encode a (ptr, len) pair into a single i64 fat pointer.
pub fn encode_fat_ptr(ptr: i32, len: i32) -> i64 {
    ((ptr as u32 as i64) << 32) | (len as u32 as i64)
}

/// Decode a fat pointer i64 into (ptr, len).
pub fn decode_fat_ptr(fat: i64) -> (i32, i32) {
    let ptr = ((fat as u64) >> 32) as i32;
    let len = (fat as u64 & 0xFFFF_FFFF) as i32;
    (ptr, len)
}

/// Read raw bytes from guest linear memory.
///
/// Returns an error for out-of-bounds reads or reads exceeding `MAX_GUEST_BYTES`.
pub fn read_guest_bytes(
    memory: &Memory,
    store: StoreContext<'_, StoreState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, WasmHostError> {
    if len < 0 || ptr < 0 {
        return Err(WasmHostError::HostFunctionError(
            "negative ptr or len".into(),
        ));
    }
    let len = len as usize;
    let ptr = ptr as usize;

    if len > MAX_GUEST_BYTES {
        return Err(WasmHostError::HostFunctionError(format!(
            "guest data too large: {len} bytes (max {MAX_GUEST_BYTES})"
        )));
    }

    let data = memory.data(store);
    let end = ptr
        .checked_add(len)
        .ok_or_else(|| WasmHostError::HostFunctionError("address overflow".into()))?;

    if end > data.len() {
        return Err(WasmHostError::HostFunctionError(format!(
            "out of bounds: ptr={ptr}, len={len}, memory_size={}",
            data.len()
        )));
    }

    Ok(data[ptr..end].to_vec())
}

/// Read a UTF-8 string from guest linear memory.
pub fn read_guest_string(
    memory: &Memory,
    store: StoreContext<'_, StoreState>,
    ptr: i32,
    len: i32,
) -> Result<String, WasmHostError> {
    let bytes = read_guest_bytes(memory, store, ptr, len)?;
    String::from_utf8(bytes).map_err(|e| WasmHostError::HostFunctionError(e.to_string()))
}

/// Allocate space in the guest, write data, and return a fat pointer.
///
/// Calls the guest-exported `__encmind_alloc(len) -> ptr` function.
pub async fn write_to_guest(
    alloc_fn: &TypedFunc<i32, i32>,
    mut store: StoreContextMut<'_, StoreState>,
    memory: &Memory,
    data: &[u8],
) -> Result<i64, WasmHostError> {
    if data.is_empty() {
        return Ok(encode_fat_ptr(0, 0));
    }

    if data.len() > MAX_GUEST_BYTES {
        return Err(WasmHostError::HostFunctionError(format!(
            "data too large to write: {} bytes (max {MAX_GUEST_BYTES})",
            data.len()
        )));
    }

    let len = data.len() as i32;
    let ptr = alloc_fn
        .call_async(&mut store, len)
        .await
        .map_err(|e| WasmHostError::HostFunctionError(format!("alloc failed: {e}")))?;

    if ptr <= 0 {
        return Err(WasmHostError::HostFunctionError(
            "guest alloc returned null".into(),
        ));
    }

    let mem_data = memory.data_mut(&mut store);
    let start = ptr as usize;
    let end = start + data.len();
    if end > mem_data.len() {
        return Err(WasmHostError::HostFunctionError(
            "alloc returned ptr beyond memory bounds".into(),
        ));
    }
    mem_data[start..end].copy_from_slice(data);

    Ok(encode_fat_ptr(ptr, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::{AsContext, Store};

    fn test_store() -> (wasmtime::Engine, Store<StoreState>) {
        let engine = wasmtime::Engine::default();
        let store = Store::new(
            &engine,
            StoreState {
                limiter: crate::limiter::SkillResourceLimiter::default(),
                skill_id: "test".into(),
                capabilities: encmind_core::traits::CapabilitySet {
                    net_outbound: vec![],
                    fs_read: vec![],
                    fs_write: vec![],
                    exec_shell: false,
                    env_secrets: false,
                    kv: false,
                    prompt_user: false,
                    emit_events: vec![],
                    hooks: vec![],
                    schedule_timers: false,
                    schedule_transforms: vec![],
                },
                last_error: None,
                db_pool: None,
                http_client: None,
                outbound_policy: None,
                hook_registry: None,
                skill_config: None,
                approval_prompter: None,
                execution_context: crate::runtime::ExecutionContext::Interactive,
                session_id: None,
                agent_id: None,
                channel: None,
                invocation_id: None,
                wasi_ctx: None,
            },
        );
        (engine, store)
    }

    #[test]
    fn fat_ptr_roundtrip() {
        let ptr = 12345_i32;
        let len = 678_i32;
        let fat = encode_fat_ptr(ptr, len);
        let (p, l) = decode_fat_ptr(fat);
        assert_eq!(p, ptr);
        assert_eq!(l, len);
    }

    #[test]
    fn fat_ptr_zero() {
        let fat = encode_fat_ptr(0, 0);
        assert_eq!(fat, 0);
        let (p, l) = decode_fat_ptr(0);
        assert_eq!(p, 0);
        assert_eq!(l, 0);
    }

    #[test]
    fn fat_ptr_large_values() {
        let ptr = i32::MAX;
        let len = i32::MAX;
        let fat = encode_fat_ptr(ptr, len);
        let (p, l) = decode_fat_ptr(fat);
        assert_eq!(p, ptr);
        assert_eq!(l, len);
    }

    #[test]
    fn read_guest_bytes_negative_ptr() {
        let (_engine, mut store) = test_store();
        let mem_ty = wasmtime::MemoryType::new(1, None);
        let memory = Memory::new(&mut store, mem_ty).unwrap();

        let result = read_guest_bytes(&memory, store.as_context(), -1, 10);
        assert!(result.is_err());
    }

    #[test]
    fn read_guest_bytes_too_large() {
        let (_engine, mut store) = test_store();
        let mem_ty = wasmtime::MemoryType::new(1, None);
        let memory = Memory::new(&mut store, mem_ty).unwrap();

        let result = read_guest_bytes(&memory, store.as_context(), 0, (MAX_GUEST_BYTES + 1) as i32);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too large"), "got: {msg}");
    }

    #[test]
    fn read_guest_bytes_out_of_bounds() {
        let (_engine, mut store) = test_store();
        let mem_ty = wasmtime::MemoryType::new(1, None);
        let memory = Memory::new(&mut store, mem_ty).unwrap();

        // 1 page = 64KiB, try reading beyond it
        let result = read_guest_bytes(&memory, store.as_context(), 0, 100_000);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("out of bounds"), "got: {msg}");
    }

    #[test]
    fn read_guest_bytes_valid() {
        let (_engine, mut store) = test_store();
        let mem_ty = wasmtime::MemoryType::new(1, None);
        let memory = Memory::new(&mut store, mem_ty).unwrap();

        // Write some data to memory
        let data = b"hello world";
        memory.data_mut(&mut store)[0..data.len()].copy_from_slice(data);

        let result = read_guest_bytes(&memory, store.as_context(), 0, data.len() as i32).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn read_guest_string_valid_utf8() {
        let (_engine, mut store) = test_store();
        let mem_ty = wasmtime::MemoryType::new(1, None);
        let memory = Memory::new(&mut store, mem_ty).unwrap();

        let text = "Hello, WASM!";
        memory.data_mut(&mut store)[0..text.len()].copy_from_slice(text.as_bytes());

        let result = read_guest_string(&memory, store.as_context(), 0, text.len() as i32).unwrap();
        assert_eq!(result, text);
    }

    #[test]
    fn detect_abi_native() {
        let engine = wasmtime::Engine::default();
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        let module = wasmtime::Module::new(&engine, wat).unwrap();
        assert_eq!(detect_abi(&module), SkillAbi::Native);
    }

    #[test]
    fn detect_abi_javy() {
        let engine = wasmtime::Engine::default();
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "_start"))
        )"#;
        let module = wasmtime::Module::new(&engine, wat).unwrap();
        assert_eq!(detect_abi(&module), SkillAbi::Javy);
    }

    #[test]
    fn detect_abi_defaults_to_native() {
        let engine = wasmtime::Engine::default();
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "run") (result i32) i32.const 42)
        )"#;
        let module = wasmtime::Module::new(&engine, wat).unwrap();
        assert_eq!(detect_abi(&module), SkillAbi::Native);
    }

    #[test]
    fn read_guest_string_invalid_utf8() {
        let (_engine, mut store) = test_store();
        let mem_ty = wasmtime::MemoryType::new(1, None);
        let memory = Memory::new(&mut store, mem_ty).unwrap();

        // Write invalid UTF-8
        memory.data_mut(&mut store)[0..3].copy_from_slice(&[0xFF, 0xFE, 0xFD]);

        let result = read_guest_string(&memory, store.as_context(), 0, 3);
        assert!(result.is_err());
    }
}
