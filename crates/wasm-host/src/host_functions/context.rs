//! `context.*` host functions — invocation metadata access.

use encmind_core::error::WasmHostError;
use wasmtime::{AsContextMut, Linker};

use crate::abi;
use crate::runtime::StoreState;

/// Register context host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    // __encmind_context_get() -> i64 (fat ptr to JSON object)
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_context_get",
            |mut caller: wasmtime::Caller<'_, StoreState>, (): ()| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let context = serde_json::json!({
                        "session_id": caller.data().session_id,
                        "agent_id": caller.data().agent_id,
                        "channel": caller.data().channel,
                        "invocation_id": caller.data().invocation_id,
                        "execution_context": caller.data().execution_context.as_str(),
                    });
                    let bytes = serde_json::to_vec(&context).unwrap_or_default();

                    let alloc_fn = match caller.get_export("__encmind_alloc") {
                        Some(wasmtime::Extern::Func(f)) => match f.typed::<i32, i32>(&caller) {
                            Ok(tf) => tf,
                            Err(e) => {
                                caller.data_mut().last_error =
                                    Some(format!("alloc type error: {e}"));
                                return 0i64;
                            }
                        },
                        _ => {
                            caller.data_mut().last_error = Some("no __encmind_alloc export".into());
                            return 0i64;
                        }
                    };

                    match abi::write_to_guest(&alloc_fn, caller.as_context_mut(), &memory, &bytes)
                        .await
                    {
                        Ok(fat) => fat,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            0i64
                        }
                    }
                })
            },
        )
        .map_err(|e| WasmHostError::HostFunctionError(format!("context.get registration: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::WasmRuntime;

    #[tokio::test]
    async fn context_get_registers_and_callable() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_context_get" (func $context_get (result i64)))
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 1024
            )
            (func (export "run") (result i32)
                (i64.ne (call $context_get) (i64.const 0))
            )
        )"#;
        rt.load_module("context", wat.as_bytes()).unwrap();
        let result = rt.invoke("context", "run").await.unwrap();
        assert_eq!(result, 1);
    }
}
