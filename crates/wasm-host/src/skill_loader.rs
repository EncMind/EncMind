//! Skill loader — discovers and loads WASM skills from the skills directory.
//!
//! Looks for `.wasm` + `.toml` file pairs in `~/.encmind/skills/` and
//! compiles them into ready-to-use tool handlers and hook bridges.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use wasmtime::{Engine, Module};

use encmind_core::error::WasmHostError;
use encmind_core::hooks::HookRegistry;
use encmind_core::traits::{SKILL_HOST_ABI_JAVY, SKILL_HOST_ABI_V1};

use crate::abi::SkillAbi;
use crate::hook_bridge::{hook_point_from_name, HookRuntimeDeps, WasmHookBridge};
use crate::manifest::{parse_manifest_full, ParsedManifest};

/// A loaded WASM skill ready for registration.
pub struct LoadedSkill {
    /// The parsed manifest.
    pub manifest: ParsedManifest,
    /// The compiled WASM module.
    pub module: Module,
    /// Path to the WASM file (for diagnostics).
    pub wasm_path: PathBuf,
    /// Detected ABI (Native or Javy).
    pub abi: SkillAbi,
}

/// Result of loading skills from a directory.
pub struct LoadResult {
    /// Successfully loaded skills.
    pub skills: Vec<LoadedSkill>,
    /// Structured errors encountered during loading.
    pub errors: Vec<LoadError>,
}

/// Structured errors emitted by [`load_skills_from_dir`].
#[derive(Debug, Clone)]
pub enum LoadError {
    /// The skills directory could not be read.
    DirectoryUnreadable { dir: PathBuf, error: String },
    /// A `.wasm` skill file has no matching `.toml` manifest.
    MissingManifest {
        skill_id: String,
        wasm_path: PathBuf,
    },
    /// Loading/compiling a skill failed.
    SkillLoadFailed {
        skill_id: String,
        wasm_path: PathBuf,
        error: String,
    },
}

/// Load all WASM skills from the given directory.
///
/// For each `.wasm` file, looks for a matching `.toml` manifest file.
/// Files without a matching manifest are skipped with a warning.
///
/// The engine must have `async_support(true)`.
pub fn load_skills_from_dir(dir: &Path, engine: &Engine) -> LoadResult {
    let mut result = LoadResult {
        skills: Vec::new(),
        errors: Vec::new(),
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::debug!(dir = %dir.display(), error = %e, "skills directory not readable");
                return result;
            }
            tracing::warn!(dir = %dir.display(), error = %e, "skills directory not readable");
            result.errors.push(LoadError::DirectoryUnreadable {
                dir: dir.to_path_buf(),
                error: format!("read_dir failed: {e}"),
            });
            return result;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
            continue;
        }

        let manifest_path = path.with_extension("toml");
        if !manifest_path.exists() {
            tracing::warn!(
                wasm = %path.display(),
                "WASM skill missing manifest (.toml); skipping"
            );
            let skill_id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            result.errors.push(LoadError::MissingManifest {
                skill_id,
                wasm_path: path.clone(),
            });
            continue;
        }

        let skill_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        match load_single_skill(&path, &manifest_path, engine) {
            Ok(skill) => {
                tracing::info!(
                    skill = %skill.manifest.manifest.name,
                    hooks = skill.manifest.hooks.bindings.len(),
                    has_tool = skill.manifest.tool.is_some(),
                    "loaded WASM skill"
                );
                result.skills.push(skill);
            }
            Err(e) => {
                tracing::error!(
                    skill = %skill_name,
                    error = %e,
                    "failed to load WASM skill"
                );
                result.errors.push(LoadError::SkillLoadFailed {
                    skill_id: skill_name,
                    wasm_path: path.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    result
}

/// Load a single WASM skill from its .wasm and .toml files.
fn load_single_skill(
    wasm_path: &Path,
    manifest_path: &Path,
    engine: &Engine,
) -> Result<LoadedSkill, WasmHostError> {
    let manifest_str = std::fs::read_to_string(manifest_path)
        .map_err(|e| WasmHostError::ManifestParseError(format!("read manifest: {e}")))?;

    let mut parsed = parse_manifest_full(&manifest_str)?;

    let wasm_bytes = std::fs::read(wasm_path)
        .map_err(|e| WasmHostError::ModuleLoadFailed(format!("read wasm: {e}")))?;

    let module = Module::new(engine, &wasm_bytes)
        .map_err(|e| WasmHostError::ModuleLoadFailed(e.to_string()))?;

    let exports: std::collections::HashSet<String> =
        module.exports().map(|e| e.name().to_string()).collect();
    let native_requires_invoke = parsed.tool.is_some();
    let (abi, required_exports): (SkillAbi, Vec<&str>) = match parsed.manifest.host_abi.as_str() {
        SKILL_HOST_ABI_V1 => {
            let mut required = vec!["memory", "__encmind_alloc"];
            if native_requires_invoke {
                required.push("__encmind_invoke");
            }
            (SkillAbi::Native, required)
        }
        SKILL_HOST_ABI_JAVY => (SkillAbi::Javy, vec!["memory", "_start"]),
        other => {
            return Err(WasmHostError::ModuleLoadFailed(format!(
                "unsupported host_abi '{other}' for skill '{}'",
                parsed.manifest.name
            )));
        }
    };

    let missing: Vec<&str> = required_exports
        .iter()
        .copied()
        .filter(|name| !exports.contains(*name))
        .collect();
    if !missing.is_empty() {
        return Err(WasmHostError::ModuleLoadFailed(format!(
            "skill '{}' declares host_abi '{}' but module is missing required exports: {}",
            parsed.manifest.name,
            parsed.manifest.host_abi,
            missing.join(", ")
        )));
    }

    // Javy ABI: tool invocation only — strip hooks, timers, transforms, and
    // advanced capabilities that require host functions.
    if abi == SkillAbi::Javy {
        if !parsed.hooks.bindings.is_empty() {
            tracing::warn!(
                skill = %parsed.manifest.name,
                hooks = ?parsed.hooks.bindings.keys().collect::<Vec<_>>(),
                "Javy skill declares hooks — stripping (Javy ABI is tool-only)"
            );
            parsed.hooks.bindings.clear();
        }
        if !parsed.timers.is_empty() {
            tracing::warn!(
                skill = %parsed.manifest.name,
                timers = parsed.timers.len(),
                "Javy skill declares timers — stripping (Javy ABI is tool-only)"
            );
            parsed.timers.clear();
        }
        if !parsed.transforms.is_empty() {
            tracing::warn!(
                skill = %parsed.manifest.name,
                transforms = parsed.transforms.len(),
                "Javy skill declares transforms — stripping (Javy ABI is tool-only)"
            );
            parsed.transforms.clear();
        }
        let stripped_advanced = !parsed.manifest.capabilities.net_outbound.is_empty()
            || !parsed.manifest.capabilities.fs_read.is_empty()
            || !parsed.manifest.capabilities.fs_write.is_empty()
            || parsed.manifest.capabilities.exec_shell
            || parsed.manifest.capabilities.env_secrets
            || parsed.manifest.capabilities.kv
            || parsed.manifest.capabilities.prompt_user
            || !parsed.manifest.capabilities.emit_events.is_empty()
            || !parsed.manifest.capabilities.hooks.is_empty()
            || parsed.manifest.capabilities.schedule_timers
            || !parsed.manifest.capabilities.schedule_transforms.is_empty();
        if stripped_advanced {
            tracing::warn!(
                skill = %parsed.manifest.name,
                "Javy skill declares advanced capabilities — stripping (Javy ABI has no encmind host functions)"
            );
        }
        // Strip advanced capabilities (Javy ABI has no encmind host functions).
        parsed.manifest.capabilities.net_outbound.clear();
        parsed.manifest.capabilities.fs_read.clear();
        parsed.manifest.capabilities.fs_write.clear();
        parsed.manifest.capabilities.exec_shell = false;
        parsed.manifest.capabilities.env_secrets = false;
        parsed.manifest.capabilities.kv = false;
        parsed.manifest.capabilities.prompt_user = false;
        parsed.manifest.capabilities.emit_events.clear();
        parsed.manifest.capabilities.hooks.clear();
        parsed.manifest.capabilities.schedule_timers = false;
        parsed.manifest.capabilities.schedule_transforms.clear();
    }

    if abi == SkillAbi::Native {
        validate_declared_native_exports(&parsed, &exports)?;
    }

    Ok(LoadedSkill {
        manifest: parsed,
        module,
        wasm_path: wasm_path.to_path_buf(),
        abi,
    })
}

fn validate_declared_native_exports(
    parsed: &ParsedManifest,
    exports: &std::collections::HashSet<String>,
) -> Result<(), WasmHostError> {
    let mut missing = Vec::new();

    for (hook_point, export_name) in &parsed.hooks.bindings {
        if !exports.contains(export_name) {
            missing.push(format!("hook '{hook_point}' -> '{export_name}'"));
        }
    }

    for timer in &parsed.timers {
        if !exports.contains(&timer.export_fn) {
            missing.push(format!("timer '{}' -> '{}'", timer.name, timer.export_fn));
        }
    }

    for transform in &parsed.transforms {
        if let Some(inbound) = transform.inbound_fn.as_deref() {
            if !exports.contains(inbound) {
                missing.push(format!(
                    "transform '{}' inbound -> '{}'",
                    transform.channel, inbound
                ));
            }
        }
        if let Some(outbound) = transform.outbound_fn.as_deref() {
            if !exports.contains(outbound) {
                missing.push(format!(
                    "transform '{}' outbound -> '{}'",
                    transform.channel, outbound
                ));
            }
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    Err(WasmHostError::ModuleLoadFailed(format!(
        "skill '{}' manifest references missing exports: {}",
        parsed.manifest.name,
        missing.join("; ")
    )))
}

/// Register a loaded skill's hook bindings into the hook registry.
///
/// Returns the number of hooks registered.
pub fn register_skill_hooks(
    skill: &LoadedSkill,
    hook_registry: &mut HookRegistry,
    engine: &Engine,
    fuel_limit: u64,
    max_memory_mb: usize,
    runtime_deps: HookRuntimeDeps,
) -> Result<usize, WasmHostError> {
    if skill.abi != SkillAbi::Native {
        return Err(WasmHostError::HostFunctionError(format!(
            "skill '{}' uses Javy ABI which does not support hooks",
            skill.manifest.manifest.name
        )));
    }

    let mut count = 0;
    let plugin_id = format!("skill:{}", skill.manifest.manifest.name);

    for (point_name, export_name) in &skill.manifest.hooks.bindings {
        let Some(hook_point) = hook_point_from_name(point_name) else {
            tracing::warn!(
                skill = %skill.manifest.manifest.name,
                hook = %point_name,
                "unknown hook point; skipping"
            );
            continue;
        };

        let bridge = WasmHookBridge::new(
            engine.clone(),
            skill.module.clone(),
            export_name.clone(),
            skill.manifest.manifest.name.clone(),
            skill.manifest.manifest.capabilities.clone(),
            fuel_limit,
            max_memory_mb,
        )
        .with_runtime_deps(runtime_deps.clone());

        hook_registry
            .register(
                hook_point,
                0, // default priority
                &plugin_id,
                Arc::new(bridge),
                5000, // 5s timeout
            )
            .map_err(|e| {
                WasmHostError::HostFunctionError(format!(
                    "hook registration failed for {point_name}: {e}"
                ))
            })?;

        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_test_engine() -> Engine {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        Engine::new(&config).unwrap()
    }

    #[test]
    fn load_from_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();
        let result = load_skills_from_dir(dir.path(), &engine);
        assert!(result.skills.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn load_from_nonexistent_dir() {
        let engine = create_test_engine();
        let result = load_skills_from_dir(Path::new("/nonexistent/path"), &engine);
        assert!(result.skills.is_empty());
    }

    #[test]
    fn load_wasm_without_manifest_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        // Module::new accepts WAT text format directly
        let wat = r#"(module (func (export "run") (result i32) i32.const 1))"#;
        // Write WAT text — Module::new auto-detects format
        std::fs::write(dir.path().join("test.wasm"), wat.as_bytes()).unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert!(result.skills.is_empty());
        assert_eq!(result.errors.len(), 1);
        match &result.errors[0] {
            LoadError::MissingManifest { skill_id, .. } => assert_eq!(skill_id, "test"),
            other => panic!("expected MissingManifest, got {other:?}"),
        }
    }

    #[test]
    fn load_valid_skill() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        // Write WAT text to .wasm file (Module::new auto-detects format)
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        std::fs::write(dir.path().join("echo.wasm"), wat.as_bytes()).unwrap();

        // Create manifest
        let manifest = r#"
[skill]
name = "echo"
version = "1.0.0"
description = "Echo skill"

[tool]
name = "echo"
description = "Echoes input"
"#;
        let mut f = std::fs::File::create(dir.path().join("echo.toml")).unwrap();
        f.write_all(manifest.as_bytes()).unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert_eq!(result.skills.len(), 1);
        assert!(result.errors.is_empty());
        assert_eq!(result.skills[0].manifest.manifest.name, "echo");
        assert!(result.skills[0].manifest.tool.is_some());
    }

    #[test]
    fn load_valid_native_skill_without_tool_does_not_require_invoke_export() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
        )"#;
        std::fs::write(dir.path().join("hook-only.wasm"), wat.as_bytes()).unwrap();

        let manifest = r#"
[skill]
name = "hook-only"
version = "1.0.0"
description = "Native skill without tool"
"#;
        let mut f = std::fs::File::create(dir.path().join("hook-only.toml")).unwrap();
        f.write_all(manifest.as_bytes()).unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert_eq!(result.skills.len(), 1);
        assert!(result.errors.is_empty());
        assert_eq!(result.skills[0].manifest.manifest.name, "hook-only");
        assert!(result.skills[0].manifest.tool.is_none());
        assert_eq!(result.skills[0].abi, SkillAbi::Native);
    }

    #[test]
    fn load_invalid_manifest_reports_structured_error_with_dotted_skill_id() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        std::fs::write(dir.path().join("acme.search.v1.wasm"), wat.as_bytes()).unwrap();
        std::fs::write(dir.path().join("acme.search.v1.toml"), "not valid toml {{{").unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert!(result.skills.is_empty());
        assert_eq!(result.errors.len(), 1);
        match &result.errors[0] {
            LoadError::SkillLoadFailed { skill_id, .. } => assert_eq!(skill_id, "acme.search.v1"),
            other => panic!("expected SkillLoadFailed, got {other:?}"),
        }
    }

    #[test]
    fn load_declared_javy_without_start_reports_error() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        std::fs::write(dir.path().join("bad-javy.wasm"), wat.as_bytes()).unwrap();

        let manifest = r#"
[skill]
name = "bad-javy"
version = "1.0.0"
description = "declares javy but exports native entrypoints"
host_abi = "javy"

[tool]
name = "bad_javy"
description = "bad"
"#;
        std::fs::write(dir.path().join("bad-javy.toml"), manifest).unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert!(result.skills.is_empty());
        assert_eq!(result.errors.len(), 1);
        match &result.errors[0] {
            LoadError::SkillLoadFailed { error, .. } => {
                assert!(error.contains("host_abi 'javy'"), "got: {error}");
                assert!(error.contains("_start"), "got: {error}");
            }
            other => panic!("expected SkillLoadFailed, got {other:?}"),
        }
    }

    #[test]
    fn load_valid_javy_skill() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "_start"))
        )"#;
        std::fs::write(dir.path().join("echo-javy.wasm"), wat.as_bytes()).unwrap();

        let manifest = r#"
[skill]
name = "echo-javy"
version = "1.0.0"
description = "Echo skill (javy)"
host_abi = "javy"

[capabilities]
net_outbound = ["api.example.com"]
fs_read = ["/tmp"]
fs_write = ["/tmp"]
exec_shell = true
env_secrets = true
kv = true
prompt_user = true
emit_events = ["evt.sample"]
hooks = ["before_tool_call"]

[tool]
name = "echo_javy"
description = "Echoes input"

[hooks]
before_tool_call = "__before_tool"

[[schedule.timers]]
name = "javy_timer"
interval_secs = 60
export_fn = "__on_timer"

[[schedule.transforms]]
channel = "telegram"
inbound_fn = "__transform_inbound"
"#;
        std::fs::write(dir.path().join("echo-javy.toml"), manifest).unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert_eq!(result.skills.len(), 1);
        assert!(result.errors.is_empty());
        assert_eq!(result.skills[0].manifest.manifest.name, "echo-javy");
        assert_eq!(result.skills[0].abi, SkillAbi::Javy);
        let caps = &result.skills[0].manifest.manifest.capabilities;
        assert!(caps.net_outbound.is_empty());
        assert!(caps.fs_read.is_empty());
        assert!(caps.fs_write.is_empty());
        assert!(!caps.exec_shell);
        assert!(!caps.env_secrets);
        assert!(!caps.kv);
        assert!(!caps.prompt_user);
        assert!(caps.emit_events.is_empty());
        assert!(caps.hooks.is_empty());
        assert!(!caps.schedule_timers);
        assert!(caps.schedule_transforms.is_empty());
        assert!(result.skills[0].manifest.hooks.bindings.is_empty());
        assert!(result.skills[0].manifest.timers.is_empty());
        assert!(result.skills[0].manifest.transforms.is_empty());
    }

    #[test]
    fn load_native_skill_missing_declared_exports_reports_error() {
        let dir = tempfile::tempdir().unwrap();
        let engine = create_test_engine();

        // Module includes only required native tool exports.
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        std::fs::write(
            dir.path().join("native-missing-exports.wasm"),
            wat.as_bytes(),
        )
        .unwrap();

        let manifest = r#"
[skill]
name = "native-missing-exports"
version = "1.0.0"
description = "declares missing exports"
host_abi = "v1"

[tool]
name = "native_missing_exports"
description = "tool"

[hooks]
before_tool_call = "__missing_hook"

[[schedule.timers]]
name = "heartbeat"
interval_secs = 60
export_fn = "__missing_timer"

[[schedule.transforms]]
channel = "telegram"
inbound_fn = "__missing_transform"
"#;
        std::fs::write(
            dir.path().join("native-missing-exports.toml"),
            manifest.as_bytes(),
        )
        .unwrap();

        let result = load_skills_from_dir(dir.path(), &engine);
        assert!(result.skills.is_empty());
        assert_eq!(result.errors.len(), 1);
        match &result.errors[0] {
            LoadError::SkillLoadFailed { error, .. } => {
                assert!(
                    error.contains("manifest references missing exports"),
                    "got: {error}"
                );
                assert!(error.contains("__missing_hook"), "got: {error}");
                assert!(error.contains("__missing_timer"), "got: {error}");
                assert!(error.contains("__missing_transform"), "got: {error}");
            }
            other => panic!("expected SkillLoadFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_hooks_from_manifest() {
        let engine = create_test_engine();
        let mut registry = HookRegistry::new();

        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
            (func (export "__on_before_tool") (param i32 i32) (result i64) i64.const 0)
        )"#;
        let module = Module::new(&engine, wat).unwrap();

        let mut hooks = crate::manifest::ParsedHooks::default();
        hooks
            .bindings
            .insert("before_tool_call".into(), "__on_before_tool".into());

        let skill = LoadedSkill {
            manifest: ParsedManifest {
                manifest: encmind_core::traits::SkillManifest {
                    name: "test".into(),
                    version: "1.0.0".into(),
                    description: "test".into(),
                    host_abi: "v1".into(),
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
                },
                hooks,
                tool: None,
                timers: vec![],
                transforms: vec![],
                required_config_keys: vec![],
                resources: crate::manifest::ResourcesSection::default(),
            },
            module,
            wasm_path: PathBuf::from("test.wasm"),
            abi: SkillAbi::Native,
        };

        let count = register_skill_hooks(
            &skill,
            &mut registry,
            &engine,
            0,
            64,
            HookRuntimeDeps::default(),
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(registry.total_hooks(), 1);
    }

    #[tokio::test]
    async fn register_hooks_rejects_javy_skill() {
        let engine = create_test_engine();
        let mut registry = HookRegistry::new();

        let module = Module::new(
            &engine,
            r#"(module
                (memory (export "memory") 1)
                (func (export "_start"))
            )"#,
        )
        .unwrap();

        let mut hooks = crate::manifest::ParsedHooks::default();
        hooks
            .bindings
            .insert("before_tool_call".into(), "__on_before_tool".into());

        let skill = LoadedSkill {
            manifest: ParsedManifest {
                manifest: encmind_core::traits::SkillManifest {
                    name: "javy-skill".into(),
                    version: "1.0.0".into(),
                    description: "test".into(),
                    host_abi: "javy".into(),
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
                },
                hooks,
                tool: None,
                timers: vec![],
                transforms: vec![],
                required_config_keys: vec![],
                resources: crate::manifest::ResourcesSection::default(),
            },
            module,
            wasm_path: PathBuf::from("javy.wasm"),
            abi: SkillAbi::Javy,
        };

        let err = register_skill_hooks(
            &skill,
            &mut registry,
            &engine,
            0,
            64,
            HookRuntimeDeps::default(),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("Javy ABI which does not support hooks"));
    }
}
