//! `config.*` host functions — skill configuration access.

use encmind_core::error::WasmHostError;
use wasmtime::{AsContext, AsContextMut, Linker};

use crate::abi;
use crate::runtime::StoreState;

/// Register config host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_config_get",
            |mut caller: wasmtime::Caller<'_, StoreState>, (key_ptr, key_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let key = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        key_ptr,
                        key_len,
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    let value: Option<serde_json::Value> = caller
                        .data()
                        .skill_config
                        .as_ref()
                        .and_then(|cfg: &serde_json::Value| cfg.get(&key).cloned());

                    let json_bytes = match value {
                        Some(v) => serde_json::to_vec(&v).unwrap_or_default(),
                        None => b"null".to_vec(),
                    };

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

                    match abi::write_to_guest(
                        &alloc_fn,
                        caller.as_context_mut(),
                        &memory,
                        &json_bytes,
                    )
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
        .map_err(|e| WasmHostError::HostFunctionError(format!("config.get registration: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::WasmRuntime;

    #[tokio::test]
    async fn config_get_registers_and_callable() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_config_get" (func $config_get (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 1024
            )
            (func (export "run") (result i32)
                i32.const 0
                i32.const 3
                call $config_get
                drop
                i32.const 1
            )
        )"#;
        rt.load_module("cfg", wat.as_bytes()).unwrap();
        let result = rt.invoke("cfg", "run").await.unwrap();
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn config_get_returns_response() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_config_get" (func $config_get (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 2048
            )
            (data (i32.const 0) "key")
            (func (export "run") (result i32)
                (call $config_get (i32.const 0) (i32.const 3))
                i64.const 0
                i64.ne
            )
        )"#;
        rt.load_module("cfg2", wat.as_bytes()).unwrap();
        let result = rt.invoke("cfg2", "run").await.unwrap();
        assert_eq!(result, 1); // Got a response (even if "null")
    }

    #[tokio::test]
    async fn config_state_with_data() {
        let state = crate::runtime::StoreState {
            limiter: crate::limiter::SkillResourceLimiter::new(64),
            skill_id: "test-skill".into(),
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
            skill_config: Some(serde_json::json!({"api_url": "https://example.com"})),
            approval_prompter: None,
            execution_context: crate::runtime::ExecutionContext::Interactive,
            session_id: None,
            agent_id: None,
            channel: None,
            invocation_id: None,
            wasi_ctx: None,
        };
        assert!(state.skill_config.is_some());
        let cfg = state.skill_config.as_ref().unwrap();
        assert_eq!(
            cfg.get("api_url").unwrap().as_str().unwrap(),
            "https://example.com"
        );
    }
}
