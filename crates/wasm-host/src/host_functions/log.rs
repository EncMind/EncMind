//! `log.*` host functions — structured logging from WASM skills.

use encmind_core::error::WasmHostError;
use wasmtime::{AsContext, Linker};

use crate::abi;
use crate::runtime::StoreState;

/// Maximum log message size (8 KiB).
const MAX_LOG_MSG_BYTES: usize = 8 * 1024;

/// Register log host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_log",
            |mut caller: wasmtime::Caller<'_, StoreState>,
             (level, msg_ptr, msg_len): (i32, i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => return -1i32,
                    };

                    let msg = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        msg_ptr,
                        msg_len,
                    ) {
                        Ok(s) => s,
                        Err(_) => return -1i32,
                    };

                    let skill_id = caller.data().skill_id.clone();

                    // Truncate to max size
                    let msg = if msg.len() > MAX_LOG_MSG_BYTES {
                        format!("{}...(truncated)", &msg[..MAX_LOG_MSG_BYTES])
                    } else {
                        msg
                    };

                    match level {
                        0 => tracing::trace!("[skill:{skill_id}] {msg}"),
                        1 => tracing::debug!("[skill:{skill_id}] {msg}"),
                        2 => tracing::info!("[skill:{skill_id}] {msg}"),
                        3 => tracing::warn!("[skill:{skill_id}] {msg}"),
                        4 => tracing::error!("[skill:{skill_id}] {msg}"),
                        _ => tracing::info!("[skill:{skill_id}] {msg}"), // unknown → info
                    }

                    0i32 // success
                })
            },
        )
        .map_err(|e| WasmHostError::HostFunctionError(format!("log registration: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::WasmRuntime;

    #[tokio::test]
    async fn log_call_succeeds() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_log" (func $log (param i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "hello from skill")
            (func (export "run") (result i32)
                (call $log (i32.const 2) (i32.const 0) (i32.const 16))
            )
        )"#;
        rt.load_module("log_test", wat.as_bytes()).unwrap();
        let result = rt.invoke("log_test", "run").await.unwrap();
        assert_eq!(result, 0); // success
    }

    #[tokio::test]
    async fn log_invalid_level_defaults_to_info() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_log" (func $log (param i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "test message")
            (func (export "run") (result i32)
                (call $log (i32.const 99) (i32.const 0) (i32.const 12))
            )
        )"#;
        rt.load_module("log_inv", wat.as_bytes()).unwrap();
        let result = rt.invoke("log_inv", "run").await.unwrap();
        assert_eq!(result, 0); // should still succeed
    }

    #[tokio::test]
    async fn log_no_memory_returns_error() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_log" (func $log (param i32 i32 i32) (result i32)))
            (func (export "run") (result i32)
                (call $log (i32.const 2) (i32.const 0) (i32.const 5))
            )
        )"#;
        rt.load_module("log_nomem", wat.as_bytes()).unwrap();
        let result = rt.invoke("log_nomem", "run").await.unwrap();
        assert_eq!(result, -1); // error: no memory
    }
}
