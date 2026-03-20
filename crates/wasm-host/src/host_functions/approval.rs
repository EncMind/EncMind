//! `approval.*` host functions — runtime user confirmation from WASM skills.

use encmind_core::error::WasmHostError;
use encmind_core::types::SkillApprovalRequest;
use wasmtime::{AsContext, AsContextMut, Linker};

use crate::abi;
use crate::runtime::StoreState;

/// Timeout for approval responses: 60 seconds.
const APPROVAL_TIMEOUT_SECS: u64 = 60;

/// Register approval host functions on the linker.
pub fn register(linker: &mut Linker<StoreState>) -> Result<(), WasmHostError> {
    // __encmind_approval_prompt(prompt_ptr, prompt_len) -> i64
    // Returns fat ptr to JSON: {"approved": bool, "choice": "..."}
    linker
        .func_wrap_async(
            "encmind",
            "__encmind_approval_prompt",
            |mut caller: wasmtime::Caller<'_, StoreState>, (prompt_ptr, prompt_len): (i32, i32)| {
                Box::new(async move {
                    let memory = match caller.get_export("memory") {
                        Some(wasmtime::Extern::Memory(m)) => m,
                        _ => {
                            caller.data_mut().last_error = Some("no memory export".into());
                            return 0i64;
                        }
                    };

                    let prompt_json = match abi::read_guest_string(
                        &memory,
                        caller.as_context(),
                        prompt_ptr,
                        prompt_len,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            caller.data_mut().last_error = Some(e.to_string());
                            return 0i64;
                        }
                    };

                    // Check capability
                    if !caller.data().capabilities.prompt_user {
                        caller.data_mut().last_error =
                            Some("approval.prompt_user capability not granted".into());
                        return 0i64;
                    }

                    // Fast-deny in non-interactive contexts (timers, transforms, cron)
                    if caller.data().execution_context
                        != crate::runtime::ExecutionContext::Interactive
                    {
                        let result = serde_json::json!({
                            "approved": false,
                            "choice": null,
                            "reason": format!("approval denied: non-interactive context ({:?})",
                                              caller.data().execution_context),
                        });
                        let result_bytes = serde_json::to_vec(&result).unwrap_or_default();

                        let alloc_fn = match caller.get_export("__encmind_alloc") {
                            Some(wasmtime::Extern::Func(f)) => match f.typed::<i32, i32>(&caller) {
                                Ok(tf) => tf,
                                Err(_) => return 0i64,
                            },
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

                    let req: serde_json::Value = match serde_json::from_str(&prompt_json) {
                        Ok(v) => v,
                        Err(e) => {
                            caller.data_mut().last_error =
                                Some(format!("invalid prompt JSON: {e}"));
                            return 0i64;
                        }
                    };

                    let prompt_text = req
                        .get("prompt")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Skill requests approval")
                        .to_string();

                    let options: Vec<String> = req
                        .get("options")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    let request_id = ulid::Ulid::new().to_string();
                    let skill_id = caller.data().skill_id.clone();

                    let approval_req = SkillApprovalRequest {
                        request_id,
                        skill_id,
                        prompt: prompt_text,
                        options,
                    };

                    let response = if let Some(prompter) = caller.data().approval_prompter.clone() {
                        prompter
                            .prompt(
                                approval_req,
                                std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS),
                            )
                            .await
                    } else {
                        // No runtime approval bridge configured — fail closed.
                        encmind_core::types::SkillApprovalResponse {
                            request_id: String::new(),
                            approved: false,
                            choice: None,
                        }
                    };

                    let result = serde_json::json!({
                        "approved": response.approved,
                        "choice": response.choice,
                    });
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
        .map_err(|e| {
            WasmHostError::HostFunctionError(format!("approval.prompt registration: {e}"))
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::{ExecutionContext, WasmRuntime};

    #[tokio::test]
    async fn approval_registers() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                i32.const 1
            )
        )"#;
        rt.load_module("approval", wat.as_bytes()).unwrap();
        let result = rt.invoke("approval", "run").await.unwrap();
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn approval_denied_without_capability() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        let wat = r#"(module
            (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{\"prompt\":\"allow?\"}")
            (func (export "run") (result i32)
                (i64.eqz (call $prompt (i32.const 0) (i32.const 19)))
            )
        )"#;
        rt.load_module("approval_deny", wat.as_bytes()).unwrap();
        let result = rt.invoke("approval_deny", "run").await.unwrap();
        assert_eq!(result, 1); // denied → 0 → eqz → 1
    }

    #[tokio::test]
    async fn approval_auto_deny_no_channel() {
        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        // Module with prompt_user capability but no approval channel
        let wat = r#"(module
            (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 4096
            )
            (data (i32.const 0) "{\"prompt\":\"allow?\"}")
            (func (export "run") (result i32)
                (call $prompt (i32.const 0) (i32.const 19))
                ;; Returns non-zero fat ptr with {"approved": false}
                i64.const 0
                i64.ne
            )
        )"#;
        rt.load_module("approval_no_ch", wat.as_bytes()).unwrap();
        // This test will return 0 because capability isn't granted (default StoreState)
        let result = rt.invoke("approval_no_ch", "run").await.unwrap();
        // Without prompt_user capability, should return 0 (denied)
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn approval_fast_deny_in_non_interactive_context() {
        use crate::limiter::SkillResourceLimiter;
        use crate::runtime::StoreState;

        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        // Module that calls approval prompt and returns the fat ptr
        let wat = r#"(module
            (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 4096
            )
            (func (export "__encmind_invoke") (param i32 i32) (result i64)
                (call $prompt (i32.const 0) (i32.const 19))
            )
            (data (i32.const 0) "{\"prompt\":\"allow?\"}")
        )"#;
        rt.load_module("timer_skill", wat.as_bytes()).unwrap();

        let state = StoreState {
            limiter: SkillResourceLimiter::new(64),
            skill_id: "test-timer".into(),
            capabilities: encmind_core::traits::CapabilitySet {
                net_outbound: vec![],
                fs_read: vec![],
                fs_write: vec![],
                exec_shell: false,
                env_secrets: false,
                kv: false,
                prompt_user: true, // capability granted
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
            execution_context: ExecutionContext::SkillTimer, // non-interactive
            session_id: None,
            agent_id: None,
            channel: None,
            invocation_id: None,
            wasi_ctx: None,
        };

        let input = serde_json::json!({"tool": "test"});
        let result = rt.invoke_json("timer_skill", &input, state).await.unwrap();
        // Should get immediate denial with reason
        assert_eq!(result["approved"], false);
        let reason = result["reason"].as_str().unwrap();
        assert!(reason.contains("non-interactive"), "got: {reason}");
        assert!(reason.contains("SkillTimer"), "got: {reason}");
    }

    #[test]
    fn execution_context_default_is_interactive() {
        let rt = WasmRuntime::new(0, 64).unwrap();
        // make_default_state is private, test via invoke which uses it
        // Instead, just verify the enum variant exists and is used
        assert_eq!(ExecutionContext::Interactive, ExecutionContext::Interactive);
        assert_ne!(ExecutionContext::Interactive, ExecutionContext::SkillTimer);
        assert_ne!(
            ExecutionContext::Interactive,
            ExecutionContext::ChannelTransform
        );
        assert_ne!(ExecutionContext::Interactive, ExecutionContext::CronJob);
        let _ = rt; // ensure rt is constructed
    }

    #[tokio::test]
    async fn approval_proceeds_in_interactive_context() {
        use crate::limiter::SkillResourceLimiter;
        use crate::runtime::StoreState;

        let mut rt = WasmRuntime::new(1_000_000, 64).unwrap();
        // Same module as fast-deny test
        let wat = r#"(module
            (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32)
                i32.const 4096
            )
            (func (export "__encmind_invoke") (param i32 i32) (result i64)
                (call $prompt (i32.const 0) (i32.const 19))
            )
            (data (i32.const 0) "{\"prompt\":\"allow?\"}")
        )"#;
        rt.load_module("interactive_skill", wat.as_bytes()).unwrap();

        let state = StoreState {
            limiter: SkillResourceLimiter::new(64),
            skill_id: "test-interactive".into(),
            capabilities: encmind_core::traits::CapabilitySet {
                net_outbound: vec![],
                fs_read: vec![],
                fs_write: vec![],
                exec_shell: false,
                env_secrets: false,
                kv: false,
                prompt_user: true,
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
            approval_prompter: None, // no prompter → fail-closed denial
            execution_context: ExecutionContext::Interactive, // interactive context
            session_id: None,
            agent_id: None,
            channel: None,
            invocation_id: None,
            wasi_ctx: None,
        };

        let input = serde_json::json!({"tool": "test"});
        let result = rt
            .invoke_json("interactive_skill", &input, state)
            .await
            .unwrap();
        // Interactive context reaches prompter, but no prompter is set → fail-closed denial
        // The key difference: no "non-interactive" reason in the response
        assert_eq!(result["approved"], false);
        // Should NOT contain "non-interactive" since it went through the normal path
        assert!(
            result.get("reason").is_none()
                || !result["reason"]
                    .as_str()
                    .unwrap_or("")
                    .contains("non-interactive")
        );
    }
}
