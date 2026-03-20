//! `hooks.*` host functions — event emission from WASM skills.

use encmind_core::error::WasmHostError;
use encmind_core::hooks::{HookContext, HookPoint, HookResult};
use encmind_core::types::{AgentId, SessionId};
use wasmtime::{AsContext, AsContextMut, Linker};

use crate::abi;
use crate::runtime::ExecutionContext;
use crate::runtime::StoreState;

fn custom_event_method(execution_context: ExecutionContext, skill_id: &str) -> String {
    match execution_context {
        ExecutionContext::Interactive => format!("skill_event:{skill_id}"),
        ExecutionContext::CronJob => format!("cron.skill_event:{skill_id}"),
        ExecutionContext::SkillTimer => format!("skill_timer.skill_event:{skill_id}"),
        ExecutionContext::ChannelTransform => format!("channel.skill_event:{skill_id}"),
    }
}

/// Register hooks host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    // __encmind_hooks_register(config_ptr, config_len) -> i32
    // Dynamic runtime hook registration is not supported yet. Hooks must be
    // declared in the skill manifest [hooks] section at load time.
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_hooks_register",
            |mut caller: wasmtime::Caller<'_, StoreState>, (_cfg_ptr, _cfg_len): (i32, i32)| {
                Box::new(async move {
                    caller.data_mut().last_error = Some(
                        "hooks.register is not supported at runtime; declare hooks in skill manifest"
                            .into(),
                    );
                    -1i32
                })
            },
        )
        .map_err(|e| {
            WasmHostError::HostFunctionError(format!("hooks.register registration: {e}"))
        })?;

    // __encmind_hooks_emit(event_ptr, event_len) -> i64 (fat ptr to JSON result)
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_hooks_emit",
            |mut caller: wasmtime::Caller<'_, StoreState>, (event_ptr, event_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let event_json = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        event_ptr,
                        event_len,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    // Check emit_events capability
                    let event: serde_json::Value = match serde_json::from_str(&event_json) {
                        Ok(v) => v,
                        Err(e) => {
                            caller.data_mut().last_error = Some(format!("invalid event JSON: {e}"));
                            return 0i64;
                        }
                    };

                    let event_type = event
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");

                    // Verify the skill has permission to emit this event type
                    let allowed = caller
                        .data()
                        .capabilities
                        .emit_events
                        .iter()
                        .any(|e| e == "*" || e == event_type);

                    if !allowed {
                        caller.data_mut().last_error = Some(format!(
                            "emit_events capability not granted for event type: {event_type}"
                        ));
                        return 0i64;
                    }

                    // Emit to hook registry if available
                    let hook_registry = match caller.data().hook_registry.as_ref() {
                        Some(hr) => hr.clone(),
                        None => {
                            // No hook registry — silently succeed (event just isn't dispatched)
                            let result = serde_json::json!({"emitted": true});
                            let result_bytes = serde_json::to_vec(&result).unwrap_or_default();
                            let alloc_fn = match caller.get_export("__encmind_alloc") {
                                Some(wasmtime::Extern::Func(f)) => {
                                    match f.typed::<i32, i32>(&caller) {
                                        Ok(tf) => tf,
                                        Err(_) => return 0i64,
                                    }
                                }
                                _ => return 0i64,
                            };
                            return match abi::write_to_guest(
                                &alloc_fn,
                                caller.as_context_mut(),
                                &memory,
                                &result_bytes,
                            )
                            .await
                            {
                                Ok(fat) => fat,
                                Err(e) => {
                                    caller.data_mut().last_error = Some(e.to_string());
                                    0i64
                                }
                            };
                        }
                    };

                    let skill_id = caller.data().skill_id.clone();
                    let execution_context = caller.data().execution_context;
                    let session_id = caller
                        .data()
                        .session_id
                        .as_ref()
                        .map(|id| SessionId::from_string(id.clone()));
                    let agent_id = caller
                        .data()
                        .agent_id
                        .as_ref()
                        .map(|id| AgentId::new(id.clone()));

                    // Create a hook context from the event
                    let mut ctx = HookContext {
                        session_id,
                        agent_id,
                        method: Some(custom_event_method(execution_context, &skill_id)),
                        payload: event.clone(),
                    };

                    // Use CustomEvent hook point and surface fail-closed aborts.
                    let registry = hook_registry.read().await;
                    match registry.execute(HookPoint::CustomEvent, &mut ctx).await {
                        Ok(HookResult::Continue) | Ok(HookResult::Override(_)) => {}
                        Ok(HookResult::Abort { reason }) => {
                            caller.data_mut().last_error =
                                Some(format!("hooks.emit aborted by registry: {reason}"));
                            return 0i64;
                        }
                        Err(e) => {
                            caller.data_mut().last_error =
                                Some(format!("hooks.emit dispatch failed: {e}"));
                            return 0i64;
                        }
                    }

                    let result = serde_json::json!({"emitted": true});
                    let result_bytes = serde_json::to_vec(&result).unwrap_or_default();

                    let alloc_fn = match caller.get_export("__encmind_alloc") {
                        Some(wasmtime::Extern::Func(f)) => match f.typed::<i32, i32>(&caller) {
                            Ok(tf) => tf,
                            Err(_) => return 0i64,
                        },
                        _ => return 0i64,
                    };

                    match abi::write_to_guest(
                        &alloc_fn,
                        caller.as_context_mut(),
                        &memory,
                        &result_bytes,
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
        .map_err(|e| WasmHostError::HostFunctionError(format!("hooks.emit registration: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::custom_event_method;
    use crate::runtime::ExecutionContext;
    use crate::runtime::WasmRuntime;

    #[tokio::test]
    async fn hooks_emit_registers() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_hooks_register" (func $reg (param i32 i32) (result i32)))
            (import "encmind" "__encmind_hooks_emit" (func $emit (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                i32.const 1
            )
        )"#;
        rt.load_module("hooks", wat.as_bytes()).unwrap();
        let result = rt.invoke("hooks", "run").await.unwrap();
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn hooks_emit_denied_without_capability() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_hooks_emit" (func $emit (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{\"type\":\"test\"}")
            (func (export "run") (result i32)
                (i64.eqz (call $emit (i32.const 0) (i32.const 15)))
            )
        )"#;
        rt.load_module("hooks_deny", wat.as_bytes()).unwrap();
        let result = rt.invoke("hooks_deny", "run").await.unwrap();
        assert_eq!(result, 1); // denied → 0 → eqz → 1
    }

    #[tokio::test]
    async fn hooks_register_reports_not_supported() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_hooks_register" (func $reg (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                (call $reg (i32.const 0) (i32.const 0))
            )
        )"#;
        rt.load_module("hooks_reg_unsupported", wat.as_bytes())
            .unwrap();
        let result = rt.invoke("hooks_reg_unsupported", "run").await.unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn custom_event_method_maps_execution_context_prefixes() {
        assert_eq!(
            custom_event_method(ExecutionContext::Interactive, "skill-a"),
            "skill_event:skill-a"
        );
        assert_eq!(
            custom_event_method(ExecutionContext::CronJob, "skill-a"),
            "cron.skill_event:skill-a"
        );
        assert_eq!(
            custom_event_method(ExecutionContext::SkillTimer, "skill-a"),
            "skill_timer.skill_event:skill-a"
        );
        assert_eq!(
            custom_event_method(ExecutionContext::ChannelTransform, "skill-a"),
            "channel.skill_event:skill-a"
        );
    }
}
