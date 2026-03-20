use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use encmind_core::traits::CapabilitySet;
use encmind_core::types::{SkillApprovalRequest, SkillApprovalResponse};
use encmind_wasm_host::abi::{expected_abi_from_manifest, SkillAbi};
use encmind_wasm_host::invoker::InvokeDeps;
use encmind_wasm_host::manifest::parse_manifest_full;
use encmind_wasm_host::{ApprovalPrompter, OutboundPolicy};

use crate::manifest_utils::{ensure_manifest_artifact_matches_source_content, validate_skill_name};

/// Run skill tests in a local sandbox with mock host functions.
///
/// The sandbox is intentionally non-networked:
/// - outbound policy denies every URL
/// - no HTTP client is injected
pub fn run_test(path: &str) -> Result<(), String> {
    let dir = Path::new(path);
    if !dir.exists() {
        return Err(format!("project directory not found: {}", dir.display()));
    }

    let manifest_path = dir.join("manifest.toml");
    if !manifest_path.exists() {
        return Err(format!("manifest.toml not found in {}", dir.display()));
    }
    // Authoring-time source of truth.
    let source_manifest_str =
        fs::read_to_string(&manifest_path).map_err(|e| format!("failed to read manifest: {e}"))?;
    let parsed_manifest = parse_manifest_full(&source_manifest_str)
        .map_err(|e| format!("invalid manifest in {}: {e}", manifest_path.display()))?;
    validate_skill_name(&parsed_manifest.manifest.name)
        .map_err(|e| format!("invalid manifest in {}: {e}", manifest_path.display()))?;

    // Find .wasm file
    let wasm_files: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory: {e}"))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    if wasm_files.is_empty() {
        return Err("no .wasm file found; run 'encmind-skill build' first".into());
    }
    if wasm_files.len() > 1 {
        let mut names: Vec<String> = wasm_files.iter().map(|p| p.display().to_string()).collect();
        names.sort();
        return Err(format!(
            "multiple .wasm files found: {}; expected exactly one",
            names.join(", ")
        ));
    }

    let wasm_path = &wasm_files[0];
    println!("Testing: {}", wasm_path.display());

    // Loader parity: require `{wasm_stem}.toml` alongside the selected module.
    let stem_manifest_path = wasm_path.with_extension("toml");
    if !stem_manifest_path.exists() {
        return Err(format!(
            "expected {} not found; run 'encmind-skill build' first",
            stem_manifest_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<wasm_stem>.toml")
        ));
    }

    ensure_manifest_artifact_matches_source_content(
        &manifest_path,
        &source_manifest_str,
        &stem_manifest_path,
    )?;

    // Load and validate the WASM module
    let wasm_bytes = fs::read(wasm_path).map_err(|e| format!("failed to read WASM file: {e}"))?;

    let mut engine_cfg = wasmtime::Config::new();
    engine_cfg.async_support(true);
    engine_cfg.consume_fuel(true);
    let engine =
        wasmtime::Engine::new(&engine_cfg).map_err(|e| format!("failed to init engine: {e}"))?;
    let module = wasmtime::Module::new(&engine, &wasm_bytes)
        .map_err(|e| format!("failed to compile WASM module: {e}"))?;

    let expected_abi = expected_abi_from_manifest(&parsed_manifest.manifest.host_abi)?;
    validate_required_exports(
        &module,
        &parsed_manifest.manifest.host_abi,
        expected_abi,
        parsed_manifest.tool.is_some(),
    )?;

    match expected_abi {
        SkillAbi::Native => test_native_abi(
            &engine,
            &module,
            &parsed_manifest.manifest.capabilities,
            parsed_manifest.tool.is_some(),
        )?,
        SkillAbi::Javy => test_javy_abi(&engine, &module, &parsed_manifest.manifest.capabilities)?,
    }

    println!("\nAll basic tests passed.");
    Ok(())
}

fn test_native_abi(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    capabilities: &CapabilitySet,
    has_tool: bool,
) -> Result<(), String> {
    println!("  ABI: Native");

    // Check required exports
    let exports: Vec<String> = module.exports().map(|e| e.name().to_string()).collect();
    let mut required = vec!["__encmind_alloc", "memory"];
    if has_tool {
        required.push("__encmind_invoke");
    }
    for required in required {
        if !exports.iter().any(|e| e == required) {
            return Err(format!("missing required export: {required}"));
        }
    }

    if has_tool {
        let value = invoke_once(
            engine,
            module,
            SkillAbi::Native,
            "skill-cli-test-native",
            capabilities,
        )?;
        if !value.is_object() {
            return Err(format!(
                "native invocation returned non-object JSON: {value}"
            ));
        }
        println!("  __encmind_invoke: OK (JSON response)");
    } else {
        println!("  no [tool] section; skipping __encmind_invoke smoke call");
    }

    Ok(())
}

fn test_javy_abi(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    capabilities: &CapabilitySet,
) -> Result<(), String> {
    println!("  ABI: Javy (WASI stdin/stdout)");

    let exports: Vec<String> = module.exports().map(|e| e.name().to_string()).collect();
    if !exports.iter().any(|e| e == "_start") {
        return Err("missing required export: _start".into());
    }
    if !exports.iter().any(|e| e == "memory") {
        return Err("missing required export: memory".into());
    }
    println!("  _start export: OK");
    println!("  memory export: OK");
    let value = invoke_once(
        engine,
        module,
        SkillAbi::Javy,
        "skill-cli-test-javy",
        capabilities,
    )?;
    if !value.is_object() {
        return Err(format!("javy invocation returned non-object JSON: {value}"));
    }
    println!("  _start invocation: OK (stdout JSON parsed)");

    Ok(())
}

fn invoke_once(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    abi: SkillAbi,
    skill_id: &str,
    capabilities: &CapabilitySet,
) -> Result<serde_json::Value, String> {
    let invoker = encmind_wasm_host::invoker::SkillInvoker::new(
        engine.clone(),
        module.clone(),
        abi,
        skill_id.to_string(),
        capabilities.clone(),
        10_000_000,
        64,
    );
    let (deps, db_path) = build_invoke_deps()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime init failed: {e}"))?;
    let result = rt.block_on(async {
        invoker
            .invoke_json(
                &serde_json::json!({"message":"hello"}),
                &deps,
                Duration::from_secs(5),
            )
            .await
    });
    // Ensure pooled connections are released before removing temp files.
    drop(deps);
    cleanup_temp_sqlite_artifacts(&db_path);
    result.map_err(|e| format!("{abi:?} invocation failed: {e}"))
}

fn validate_required_exports(
    module: &wasmtime::Module,
    host_abi: &str,
    expected_abi: SkillAbi,
    native_requires_invoke: bool,
) -> Result<(), String> {
    let exports: std::collections::HashSet<String> =
        module.exports().map(|e| e.name().to_string()).collect();
    let required: Vec<&str> = match expected_abi {
        SkillAbi::Native => {
            let mut required = vec!["memory", "__encmind_alloc"];
            if native_requires_invoke {
                required.push("__encmind_invoke");
            }
            required
        }
        SkillAbi::Javy => vec!["memory", "_start"],
    };
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|name| !exports.contains(*name))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "WASM module declares host_abi '{host_abi}' but is missing required exports: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

struct DenyAllOutboundPolicy;

#[async_trait]
impl OutboundPolicy for DenyAllOutboundPolicy {
    async fn check_url(&self, url: &str) -> Result<(), String> {
        Err(format!(
            "outbound network disabled in encmind-skill test sandbox: {url}"
        ))
    }
}

struct AutoApprovePrompter;

#[async_trait]
impl ApprovalPrompter for AutoApprovePrompter {
    async fn prompt(
        &self,
        request: SkillApprovalRequest,
        _timeout: Duration,
    ) -> SkillApprovalResponse {
        SkillApprovalResponse {
            request_id: request.request_id,
            approved: true,
            choice: Some("approve".to_string()),
        }
    }
}

fn build_invoke_deps() -> Result<(InvokeDeps, PathBuf), String> {
    let db_path = std::env::temp_dir().join(format!(
        "encmind-skill-cli-test-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_nanos()
    ));
    let pool = encmind_storage::pool::create_pool(&db_path)
        .map_err(|e| format!("failed to create test DB pool: {e}"))?;
    {
        let conn = pool
            .get()
            .map_err(|e| format!("failed to acquire test DB connection: {e}"))?;
        encmind_storage::migrations::run_migrations(&conn)
            .map_err(|e| format!("failed to run test DB migrations: {e}"))?;
    }

    let deps = InvokeDeps {
        db_pool: Some(Arc::new(pool)),
        http_client: None,
        outbound_policy: Some(Arc::new(DenyAllOutboundPolicy)),
        hook_registry: Some(Arc::new(tokio::sync::RwLock::new(
            encmind_core::hooks::HookRegistry::new(),
        ))),
        approval_prompter: Some(Arc::new(AutoApprovePrompter)),
        skill_config: None,
        execution_context: encmind_wasm_host::ExecutionContext::Interactive,
        session_id: None,
        agent_id: None,
        channel: None,
        invocation_id: None,
    };
    Ok((deps, db_path))
}

fn cleanup_temp_sqlite_artifacts(db_path: &Path) {
    let mut wal_name = db_path.as_os_str().to_owned();
    wal_name.push("-wal");
    let mut shm_name = db_path.as_os_str().to_owned();
    shm_name.push("-shm");

    for candidate in [
        db_path.to_path_buf(),
        PathBuf::from(wal_name),
        PathBuf::from(shm_name),
    ] {
        match std::fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "warning: failed to remove temp sqlite artifact {}: {e}",
                candidate.display()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn example_skill_dir(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/skills")
            .join(name)
    }

    #[test]
    fn test_rejects_missing_project() {
        let result = run_test("/nonexistent/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_sandbox_dependencies_disable_network() {
        let (deps, db_path) = build_invoke_deps().expect("deps should build");
        assert!(deps.http_client.is_none());
        assert!(deps.outbound_policy.is_some());
        drop(deps);
        cleanup_temp_sqlite_artifacts(&db_path);
    }

    #[test]
    fn test_rejects_multiple_wasm_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='x'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("a.wasm"), "").unwrap();
        std::fs::write(tmp.path().join("b.wasm"), "").unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("multiple .wasm files found"));
    }

    #[test]
    fn test_rejects_manifest_wasm_abi_mismatch() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='mismatch'\nversion='0.1.0'\nhost_abi='javy'\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("mismatch.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("mismatch.toml"),
            "[skill]\nname='mismatch'\nversion='0.1.0'\nhost_abi='javy'\n",
        )
        .unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("declares host_abi 'javy' but is missing required exports"));
    }

    #[test]
    fn test_accepts_dual_exports_when_host_abi_is_javy() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='dual'\nversion='0.1.0'\nhost_abi='javy'\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("dual.wasm"),
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
                (data (i32.const 256) "{\"result\":\"ok\"}")
                (func (export "_start")
                    (i32.store (i32.const 0) (i32.const 256))
                    (i32.store (i32.const 4) (i32.const 15))
                    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
                )
            )"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("dual.toml"),
            "[skill]\nname='dual'\nversion='0.1.0'\nhost_abi='javy'\n",
        )
        .unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(result.is_ok(), "unexpected error: {result:?}");
    }

    #[test]
    fn test_runs_native_wasm_smoke() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='native'\nversion='0.1.0'\n",
        )
        .unwrap();
        // Minimal Native ABI WAT. wasmtime::Module::new accepts WAT bytes.
        std::fs::write(
            tmp.path().join("native.wasm"),
            r#"(module
                (memory (export "memory") 2)
                (global $offset (mut i32) (i32.const 1024))
                (func (export "__encmind_alloc") (param $size i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $offset))
                    (global.set $offset (i32.add (global.get $offset) (local.get $size)))
                    (local.get $ptr))
                (func (export "__encmind_invoke") (param $ptr i32) (param $len i32) (result i64)
                    (i32.store8 (i32.const 0) (i32.const 123))
                    (i32.store8 (i32.const 1) (i32.const 125))
                    (i64.or
                        (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                        (i64.const 2)))
            )"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("native.toml"),
            "[skill]\nname='native'\nversion='0.1.0'\n",
        )
        .unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(result.is_ok(), "unexpected error: {result:?}");
    }

    #[test]
    fn test_runs_native_without_tool_and_without_invoke_export() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='native-hooks'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("native_hooks.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
            )"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("native_hooks.toml"),
            "[skill]\nname='native-hooks'\nversion='0.1.0'\n",
        )
        .unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(
            result.is_ok(),
            "native no-tool skills should not require __encmind_invoke: {result:?}"
        );
    }

    #[test]
    fn test_rejects_missing_stem_manifest() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='x'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("x.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("run 'encmind-skill build' first"));
    }

    #[test]
    fn test_rejects_stem_manifest_drift() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("manifest.toml"),
            "[skill]\nname='x'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("x.toml"),
            "[skill]\nname='x'\nversion='0.2.0'\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("x.wasm"),
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
                (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();

        let result = run_test(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("differs from manifest.toml"));
    }

    #[test]
    fn test_runs_example_plugin_smoke_native() {
        let dir = example_skill_dir("plugin-smoke-native");
        assert!(
            dir.exists(),
            "example skill directory missing: {}",
            dir.display()
        );
        let result = run_test(dir.to_str().unwrap());
        assert!(result.is_ok(), "unexpected error: {result:?}");
    }

    #[test]
    fn test_runs_example_plugin_smoke_javy() {
        let dir = example_skill_dir("plugin-smoke-javy");
        assert!(
            dir.exists(),
            "example skill directory missing: {}",
            dir.display()
        );
        let result = run_test(dir.to_str().unwrap());
        assert!(result.is_ok(), "unexpected error: {result:?}");
    }
}
