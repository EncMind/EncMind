use std::fs;
use std::path::Path;

use encmind_wasm_host::abi::{expected_abi_from_manifest, SkillAbi};
use encmind_wasm_host::manifest::ManifestFile;

use crate::manifest_utils::validate_skill_name;

/// Validate a skill manifest and optionally check WASM binary exports.
pub fn run_validate(manifest_path: &str, wasm_path: Option<&str>) -> Result<(), String> {
    let manifest_path = Path::new(manifest_path);
    if !manifest_path.exists() {
        return Err(format!(
            "manifest file not found: {}",
            manifest_path.display()
        ));
    }

    // Parse manifest
    let manifest_str =
        fs::read_to_string(manifest_path).map_err(|e| format!("failed to read manifest: {e}"))?;

    let manifest: ManifestFile =
        toml::from_str(&manifest_str).map_err(|e| format!("invalid manifest: {e}"))?;
    let _ = expected_abi_from_manifest(&manifest.skill.host_abi)?;

    // Basic validation
    validate_skill_name(&manifest.skill.name).map_err(|e| format!("manifest error: {e}"))?;
    if manifest.skill.version.is_empty() {
        return Err("manifest error: skill.version must not be empty".into());
    }

    // Validate timer declarations
    for timer in &manifest.schedule.timers {
        if timer.interval_secs < 60 {
            return Err(format!(
                "manifest error: timer '{}' interval_secs must be >= 60, got {}",
                timer.name, timer.interval_secs
            ));
        }
        if timer.export_fn.trim().is_empty() {
            return Err(format!(
                "manifest error: timer '{}' export_fn must not be empty",
                timer.name
            ));
        }
    }

    // Validate transform declarations
    for transform in &manifest.schedule.transforms {
        if transform.inbound_fn.is_none() && transform.outbound_fn.is_none() {
            return Err(format!(
                "manifest error: transform for channel '{}' must specify at least one of inbound_fn or outbound_fn",
                transform.channel
            ));
        }
        if transform
            .inbound_fn
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(format!(
                "manifest error: transform for channel '{}' inbound_fn must not be empty",
                transform.channel
            ));
        }
        if transform
            .outbound_fn
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(format!(
                "manifest error: transform for channel '{}' outbound_fn must not be empty",
                transform.channel
            ));
        }
    }

    for key in &manifest.config.required_keys {
        validate_required_config_key(key)?;
    }

    println!(
        "Manifest OK: {} v{}",
        manifest.skill.name, manifest.skill.version
    );

    if let Some(tool) = &manifest.tool {
        println!("  Tool: {} — {}", tool.name, tool.description);
    }

    if !manifest.schedule.timers.is_empty() {
        println!(
            "  Timers: {}",
            manifest
                .schedule
                .timers
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !manifest.schedule.transforms.is_empty() {
        println!(
            "  Transforms: {}",
            manifest
                .schedule
                .transforms
                .iter()
                .map(|t| t.channel.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Check WASM exports if a binary is provided
    if let Some(wasm) = wasm_path {
        validate_wasm_exports(
            wasm,
            Some(&manifest.skill.host_abi),
            Some(manifest.tool.is_some()),
        )?;
    }

    Ok(())
}

fn validate_wasm_exports(
    wasm_path: &str,
    manifest_host_abi: Option<&str>,
    native_requires_invoke: Option<bool>,
) -> Result<SkillAbi, String> {
    let path = Path::new(wasm_path);
    if !path.exists() {
        return Err(format!("WASM file not found: {}", path.display()));
    }

    let wasm_bytes = fs::read(path).map_err(|e| format!("failed to read WASM file: {e}"))?;

    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::new(&engine, &wasm_bytes)
        .map_err(|e| format!("failed to compile WASM module: {e}"))?;
    let exports: std::collections::HashSet<String> =
        module.exports().map(|e| e.name().to_string()).collect();

    let expected = if let Some(host_abi) = manifest_host_abi {
        expected_abi_from_manifest(host_abi)?
    } else if exports.contains("__encmind_invoke") {
        SkillAbi::Native
    } else if exports.contains("_start") {
        SkillAbi::Javy
    } else {
        return Err(
            "WASM module has neither __encmind_invoke (Native) nor _start (Javy) exports".into(),
        );
    };

    let required: Vec<&str> = match expected {
        SkillAbi::Native => {
            let mut required = vec!["memory", "__encmind_alloc"];
            if native_requires_invoke.unwrap_or(true) {
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
        if let Some(host_abi) = manifest_host_abi {
            return Err(format!(
                "WASM module declares host_abi '{host_abi}' but is missing required exports: {}",
                missing.join(", ")
            ));
        }
        return Err(format!(
            "WASM module ({expected:?} ABI) missing required exports: {}",
            missing.join(", ")
        ));
    }

    println!(
        "WASM exports OK ({expected:?} ABI): {} exports found",
        exports.len()
    );
    Ok(expected)
}

fn validate_required_config_key(key: &str) -> Result<(), String> {
    if key.trim() != key {
        return Err(format!(
            "manifest error: config.required_keys entry '{key}' must not have leading/trailing whitespace"
        ));
    }
    if key.is_empty() {
        return Err("manifest error: config.required_keys entries must not be empty".into());
    }
    if key.len() > 128 {
        return Err(format!(
            "manifest error: config.required_keys entry '{key}' exceeds 128 characters"
        ));
    }
    if key.chars().any(char::is_control) {
        return Err(format!(
            "manifest error: config.required_keys entry '{key}' contains control characters"
        ));
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!(
            "manifest error: config.required_keys entry '{key}' may only contain [A-Za-z0-9._-]"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn validate_valid_manifest() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = "echo"
version = "1.0.0"
description = "Echo skill"

[tool]
name = "echo"
description = "Echoes input"
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_invalid_manifest_missing_name() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = ""
version = "1.0.0"
description = "Bad skill"
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("name must not be empty"));
    }

    #[test]
    fn validate_manifest_rejects_path_traversal_skill_name() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = "../evil"
version = "1.0.0"
description = "Bad skill"
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("allowed characters are [A-Za-z0-9._-]"));
    }

    #[test]
    fn validate_manifest_rejects_unsupported_host_abi() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = "bad-abi"
version = "1.0.0"
host_abi = "v9"
description = "Bad abi"
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported host_abi 'v9'"));
    }

    #[test]
    fn validate_manifest_not_found() {
        let result = run_validate("/nonexistent/manifest.toml", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("manifest file not found"));
    }

    #[test]
    fn validate_manifest_timer_interval_too_low() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = "fast-timer"
version = "1.0.0"
description = "Timer skill"

[[schedule.timers]]
name = "too-fast"
interval_secs = 10
export_fn = "on_tick"
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("interval_secs must be >= 60"));
    }

    #[test]
    fn validate_manifest_timer_export_fn_whitespace_rejected() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = "timer-whitespace-export"
version = "1.0.0"
description = "Timer skill"

[[schedule.timers]]
name = "tick"
interval_secs = 60
export_fn = "   "
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("export_fn must not be empty"));
    }

    #[test]
    fn validate_manifest_transform_whitespace_fn_rejected() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        fs::write(
            &manifest_path,
            r#"
[skill]
name = "transform-whitespace-fn"
version = "1.0.0"
description = "Transform skill"

[[schedule.transforms]]
channel = "telegram"
inbound_fn = "   "
"#,
        )
        .unwrap();

        let result = run_validate(manifest_path.to_str().unwrap(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("inbound_fn must not be empty"));
    }

    #[test]
    fn validate_wasm_with_valid_exports() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("skill.wasm");

        // Minimal valid WAT with required exports
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        // Write WAT text directly — wasmtime::Module::new accepts WAT
        let wasm = wat.as_bytes();
        fs::write(&wasm_path, wasm).unwrap();

        let result = validate_wasm_exports(wasm_path.to_str().unwrap(), None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_wasm_javy_abi_exports() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("skill.wasm");

        // Javy-style module with _start + memory
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "_start"))
        )"#;
        fs::write(&wasm_path, wat.as_bytes()).unwrap();

        let result = validate_wasm_exports(wasm_path.to_str().unwrap(), None, None);
        assert!(
            result.is_ok(),
            "Javy ABI should pass validation: {:?}",
            result
        );
    }

    #[test]
    fn validate_wasm_no_recognized_abi() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("bad.wasm");

        // Module with neither __encmind_invoke nor _start
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "run") (result i32) i32.const 0)
        )"#;
        fs::write(&wasm_path, wat.as_bytes()).unwrap();

        let result = validate_wasm_exports(wasm_path.to_str().unwrap(), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("neither"));
    }

    #[test]
    fn validate_wasm_missing_exports() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("bad.wasm");

        // Module missing __encmind_invoke
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
        )"#;
        // Write WAT text directly — wasmtime::Module::new accepts WAT
        let wasm = wat.as_bytes();
        fs::write(&wasm_path, wasm).unwrap();

        let result = validate_wasm_exports(wasm_path.to_str().unwrap(), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("__encmind_invoke"));
    }

    #[test]
    fn validate_manifest_native_without_tool_allows_missing_invoke() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join("manifest.toml");
        let wasm_path = tmp.path().join("native_hooks_only.wasm");

        fs::write(
            &manifest_path,
            r#"
[skill]
name = "native-hooks-only"
version = "1.0.0"
description = "Native skill without tool section"
"#,
        )
        .unwrap();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
        )"#;
        fs::write(&wasm_path, wat.as_bytes()).unwrap();

        let result = run_validate(
            manifest_path.to_str().unwrap(),
            Some(wasm_path.to_str().unwrap()),
        );
        assert!(
            result.is_ok(),
            "native no-tool manifest should not require __encmind_invoke: {result:?}"
        );
    }

    #[test]
    fn validate_wasm_manifest_abi_mismatch_errors() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("mismatch.wasm");
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        fs::write(&wasm_path, wat.as_bytes()).unwrap();

        let result = validate_wasm_exports(wasm_path.to_str().unwrap(), Some("javy"), Some(true));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("declares host_abi 'javy' but is missing required exports"));
    }

    #[test]
    fn validate_wasm_dual_exports_allowed_when_manifest_matches() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("dual.wasm");
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
            (func (export "_start"))
        )"#;
        fs::write(&wasm_path, wat.as_bytes()).unwrap();

        let native_result =
            validate_wasm_exports(wasm_path.to_str().unwrap(), Some("v1"), Some(true));
        assert!(
            native_result.is_ok(),
            "native host_abi should pass on dual exports"
        );

        let javy_result =
            validate_wasm_exports(wasm_path.to_str().unwrap(), Some("javy"), Some(true));
        assert!(
            javy_result.is_ok(),
            "javy host_abi should pass on dual exports"
        );
    }

    // ── Javy spike tests (run by default; skip if javy is unavailable) ──────────

    fn ensure_javy_available() -> bool {
        use std::process::Command;

        let available = Command::new("javy")
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if available {
            return true;
        }

        let strict = std::env::var("ENCMIND_REQUIRE_JAVY")
            .map(|v| v == "1")
            .unwrap_or(false);
        if strict {
            panic!("javy CLI is required but not available in PATH");
        }

        eprintln!("skipping javy integration check: javy CLI not available");
        false
    }

    #[test]
    fn javy_compiles_js_to_wasm() {
        use std::process::Command;

        if !ensure_javy_available() {
            return;
        }

        let tmp = TempDir::new().unwrap();
        let js_file = tmp.path().join("test.js");
        fs::write(
            &js_file,
            r#"
            // Minimal JS that javy should compile
            function handle(input) {
                return { result: "ok" };
            }
            "#,
        )
        .unwrap();

        let wasm_output = tmp.path().join("test.wasm");
        let status = Command::new("javy")
            .args([
                "compile",
                js_file.to_str().unwrap(),
                "-o",
                wasm_output.to_str().unwrap(),
            ])
            .status()
            .expect("javy should be available");

        assert!(status.success(), "javy compile should succeed");
        assert!(wasm_output.exists(), "output .wasm should exist");
        assert!(
            fs::metadata(&wasm_output).unwrap().len() > 0,
            "output .wasm should not be empty"
        );
    }

    #[test]
    fn javy_compiled_module_has_expected_structure() {
        use std::process::Command;

        if !ensure_javy_available() {
            return;
        }

        let tmp = TempDir::new().unwrap();
        let js_file = tmp.path().join("test.js");
        fs::write(
            &js_file,
            r#"
            const buf = new Uint8Array(1024);
            const read = Javy.IO.readSync(0, buf);
            const input = JSON.parse(new TextDecoder().decode(buf.slice(0, read)));
            const output = JSON.stringify({ result: "echo" });
            Javy.IO.writeSync(1, new TextEncoder().encode(output));
            "#,
        )
        .unwrap();

        let wasm_output = tmp.path().join("test.wasm");
        let status = Command::new("javy")
            .args([
                "compile",
                js_file.to_str().unwrap(),
                "-o",
                wasm_output.to_str().unwrap(),
            ])
            .status()
            .expect("javy should be available");

        assert!(status.success());

        let wasm_bytes = fs::read(&wasm_output).unwrap();
        let engine = wasmtime::Engine::default();
        let module =
            wasmtime::Module::new(&engine, &wasm_bytes).expect("javy output should be valid WASM");

        let exports: Vec<String> = module.exports().map(|e| e.name().to_string()).collect();

        // Javy modules export "memory" and "_start"
        assert!(
            exports.iter().any(|e| e == "memory"),
            "javy module should export memory"
        );
    }
}
