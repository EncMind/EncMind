use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use encmind_wasm_host::abi::{expected_abi_from_manifest, SkillAbi};

use crate::manifest_utils::{ensure_manifest_artifact_matches_source_content, validate_skill_name};

/// Build the skill project to a .wasm file.
pub fn run_build(path: &str) -> Result<(), String> {
    let dir = Path::new(path);
    if !dir.exists() {
        return Err(format!("project directory not found: {}", dir.display()));
    }

    let manifest_path = dir.join("manifest.toml");
    if !manifest_path.exists() {
        return Err(format!("manifest.toml not found in {}", dir.display()));
    }

    // Detect project type
    if dir.join("Cargo.toml").exists() {
        build_rust(dir)
    } else if dir.join("tsconfig.json").exists() || dir.join("src/index.ts").exists() {
        build_typescript(dir)
    } else {
        Err("could not detect project type: expected Cargo.toml (Rust) or tsconfig.json (TypeScript)".into())
    }
}

fn build_rust(dir: &Path) -> Result<(), String> {
    println!("Building Rust skill...");

    let manifest_str = fs::read_to_string(dir.join("manifest.toml"))
        .map_err(|e| format!("failed to read manifest: {e}"))?;
    let manifest: encmind_wasm_host::manifest::ManifestFile =
        toml::from_str(&manifest_str).map_err(|e| format!("invalid manifest: {e}"))?;
    validate_skill_name(&manifest.skill.name)?;

    let status = Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir(dir)
        .status()
        .map_err(|e| format!("failed to run cargo: {e}"))?;

    if !status.success() {
        return Err("cargo build failed".into());
    }

    // Find the built .wasm file
    let target_dir = dir.join("target/wasm32-unknown-unknown/release");
    let cargo_toml = fs::read_to_string(dir.join("Cargo.toml"))
        .map_err(|e| format!("failed to read Cargo.toml: {e}"))?;

    // Extract crate name from Cargo.toml package metadata.
    let crate_name =
        extract_crate_name(&cargo_toml).ok_or("could not determine crate name from Cargo.toml")?;
    let wasm_name = crate_name.replace('-', "_");
    let wasm_file = target_dir.join(format!("{wasm_name}.wasm"));

    if !wasm_file.exists() {
        return Err(format!(
            "expected WASM output not found: {}",
            wasm_file.display()
        ));
    }

    // Copy to project root
    let output = dir.join(format!("{wasm_name}.wasm"));
    fs::copy(&wasm_file, &output).map_err(|e| format!("failed to copy WASM file: {e}"))?;

    validate_built_wasm_abi(&output, &manifest)?;

    // Copy manifest as {wasm_name}.toml for loader convention ({stem}.toml)
    let manifest_src = dir.join("manifest.toml");
    let manifest_dst = dir.join(format!("{wasm_name}.toml"));
    if manifest_src.exists() && manifest_src != manifest_dst {
        fs::copy(&manifest_src, &manifest_dst)
            .map_err(|e| format!("failed to copy manifest to {}: {e}", manifest_dst.display()))?;
    }

    println!("Built: {}", output.display());
    Ok(())
}

fn build_typescript(dir: &Path) -> Result<(), String> {
    println!("Building TypeScript skill...");

    // Check for javy
    let javy_check = Command::new("javy").arg("--version").output();

    match javy_check {
        Ok(output) if output.status.success() => {}
        _ => {
            return Err(
                "javy not found. Install javy to compile TypeScript skills to WASM.\n\
                 See: https://github.com/nicolo-ribaudo/javy"
                    .into(),
            );
        }
    }

    // Compile TS to JS first (requires tsc or similar)
    let ts_file = dir.join("src/index.ts");
    let js_file = dir.join("dist/index.js");

    if !ts_file.exists() {
        return Err("src/index.ts not found".into());
    }

    // Use local TypeScript compiler for reproducible builds.
    let local_tsc = dir.join("node_modules/typescript/bin/tsc");
    let local_tsc_in_project = Path::new("node_modules/typescript/bin/tsc");
    if !local_tsc.is_file() {
        return Err(format!(
            "TypeScript compiler not found at {}. Run 'npm install' in the skill project first.",
            local_tsc.display()
        ));
    }
    let tsc_status = Command::new("node")
        .arg(local_tsc_in_project)
        .args(["--outDir", "dist"])
        .current_dir(dir)
        .status()
        .map_err(|e| format!("failed to run local tsc via node: {e}"))?;

    if !tsc_status.success() {
        return Err("TypeScript compilation failed".into());
    }

    if !js_file.exists() {
        return Err("dist/index.js not found after TypeScript compilation".into());
    }

    // Compile JS to WASM via javy
    let manifest_str = fs::read_to_string(dir.join("manifest.toml"))
        .map_err(|e| format!("failed to read manifest: {e}"))?;
    let manifest: encmind_wasm_host::manifest::ManifestFile =
        toml::from_str(&manifest_str).map_err(|e| format!("invalid manifest: {e}"))?;
    validate_skill_name(&manifest.skill.name)?;

    let output_name = format!("{}.wasm", manifest.skill.name);
    let output_path = dir.join(&output_name);

    let javy_status = Command::new("javy")
        .args(["compile", "dist/index.js", "-o", output_name.as_str()])
        .current_dir(dir)
        .status()
        .map_err(|e| format!("failed to run javy: {e}"))?;

    if !javy_status.success() {
        return Err("javy compilation failed".into());
    }

    validate_built_wasm_abi(&output_path, &manifest)?;

    // Copy manifest as {skill_name}.toml for loader convention ({stem}.toml)
    let manifest_dst = dir.join(format!("{}.toml", manifest.skill.name));
    let manifest_src = dir.join("manifest.toml");
    if manifest_src != manifest_dst {
        fs::copy(&manifest_src, &manifest_dst)
            .map_err(|e| format!("failed to copy manifest to {}: {e}", manifest_dst.display()))?;
    }

    println!("Built: {}", output_path.display());
    Ok(())
}

/// Package a skill into a distributable tarball (.tar.gz).
pub fn run_pack(path: &str, output_dir: &str) -> Result<(), String> {
    let dir = Path::new(path);
    if !dir.exists() {
        return Err(format!("project directory not found: {}", dir.display()));
    }

    let manifest_path = dir.join("manifest.toml");
    if !manifest_path.exists() {
        return Err(format!("manifest.toml not found in {}", dir.display()));
    }

    let manifest_str =
        fs::read_to_string(&manifest_path).map_err(|e| format!("failed to read manifest: {e}"))?;
    let manifest: encmind_wasm_host::manifest::ManifestFile =
        toml::from_str(&manifest_str).map_err(|e| format!("invalid manifest: {e}"))?;
    validate_skill_name(&manifest.skill.name)?;

    // Find .wasm file in project directory
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
        return Err(
            "no .wasm file found in project directory; run 'encmind-skill build' first".into(),
        );
    }
    if wasm_files.len() > 1 {
        return Err(format!(
            "multiple .wasm files found: {}; expected exactly one",
            wasm_files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let wasm_file = &wasm_files[0];
    let tarball_name = format!("{}-{}.tar.gz", manifest.skill.name, manifest.skill.version);
    let output_path = Path::new(output_dir).join(&tarball_name);

    // Create tarball using tar command
    let wasm_filename = wasm_file.file_name().ok_or_else(|| {
        format!(
            "invalid WASM file path (missing file name): {}",
            wasm_file.display()
        )
    })?;
    let wasm_stem = wasm_file.file_stem().ok_or_else(|| {
        format!(
            "invalid WASM file path (missing file stem): {}",
            wasm_file.display()
        )
    })?;
    let mut toml_filename: OsString = wasm_stem.to_os_string();
    toml_filename.push(".toml");
    let stem_manifest_path = dir.join(&toml_filename);
    let manifest_to_pack = if stem_manifest_path.exists() {
        ensure_manifest_artifact_matches_source_content(
            &manifest_path,
            &manifest_str,
            &stem_manifest_path,
        )?;
        toml_filename
    } else {
        let expected = Path::new(&toml_filename)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "<wasm_stem>.toml".to_string());
        return Err(format!(
            "expected {} not found; run 'encmind-skill build' first",
            expected
        ));
    };

    let status = Command::new("tar")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .arg("czf")
        .arg(&output_path)
        .arg("-C")
        .arg(dir)
        .arg(&manifest_to_pack)
        .arg(wasm_filename)
        .status()
        .map_err(|e| format!("failed to run tar: {e}"))?;

    if !status.success() {
        return Err("tar packaging failed".into());
    }

    println!("Packed: {}", output_path.display());
    Ok(())
}

fn validate_built_wasm_abi(
    wasm_path: &Path,
    manifest: &encmind_wasm_host::manifest::ManifestFile,
) -> Result<(), String> {
    let wasm_bytes = fs::read(wasm_path)
        .map_err(|e| format!("failed to read built WASM {}: {e}", wasm_path.display()))?;
    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::new(&engine, &wasm_bytes)
        .map_err(|e| format!("failed to compile built WASM {}: {e}", wasm_path.display()))?;
    let expected = expected_abi_from_manifest(&manifest.skill.host_abi)?;

    let exports: std::collections::HashSet<String> =
        module.exports().map(|e| e.name().to_string()).collect();
    let required: Vec<&str> = match expected {
        SkillAbi::Native => {
            let mut required = vec!["memory", "__encmind_alloc"];
            if manifest.tool.is_some() {
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
            "built WASM declares host_abi '{}' but is missing required exports: {}",
            manifest.skill.host_abi,
            missing.join(", ")
        ));
    }

    Ok(())
}

fn extract_crate_name(cargo_toml: &str) -> Option<String> {
    let parsed: toml::Value = toml::from_str(cargo_toml).ok()?;
    parsed
        .get("package")?
        .get("name")?
        .as_str()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn extract_crate_name_from_cargo_toml() {
        let toml = r#"
[package]
name = "my-skill"
version = "0.1.0"
"#;
        assert_eq!(extract_crate_name(toml), Some("my-skill".into()));
    }

    #[test]
    fn extract_crate_name_ignores_non_package_name_fields() {
        let toml = r#"
[package]
name = "my-skill"
version = "0.1.0"

[dependencies]
name = "not-the-crate-name"
"#;
        assert_eq!(extract_crate_name(toml), Some("my-skill".into()));
    }

    #[test]
    fn skill_name_validation_rejects_invalid_names() {
        let err = validate_skill_name("../evil").unwrap_err();
        assert!(err.contains("allowed characters"));
        let err = validate_skill_name("a/b").unwrap_err();
        assert!(err.contains("allowed characters"));
        let err = validate_skill_name(".hidden").unwrap_err();
        assert!(err.contains("must not start or end with '.'"));
    }

    #[test]
    fn validate_built_native_without_tool_allows_missing_invoke() {
        let tmp = TempDir::new().unwrap();
        let wasm_path = tmp.path().join("native_no_tool.wasm");
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
        )"#;
        fs::write(&wasm_path, wat.as_bytes()).unwrap();

        let manifest: encmind_wasm_host::manifest::ManifestFile = toml::from_str(
            r#"
[skill]
name = "native-no-tool"
version = "0.1.0"
"#,
        )
        .unwrap();

        let result = validate_built_wasm_abi(&wasm_path, &manifest);
        assert!(
            result.is_ok(),
            "native no-tool build should not require __encmind_invoke: {result:?}"
        );
    }

    #[test]
    fn build_detects_missing_project() {
        let result = run_build("/nonexistent/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn build_detects_missing_manifest() {
        let tmp = TempDir::new().unwrap();
        let result = run_build(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("manifest.toml not found"));
    }

    #[test]
    fn build_ts_detects_missing_javy() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path().join("ts-skill");
        fs::create_dir_all(project_dir.join("src")).unwrap();
        fs::write(
            project_dir.join("manifest.toml"),
            "[skill]\nname = \"ts-test\"\nversion = \"1.0.0\"\ndescription = \"test\"\n",
        )
        .unwrap();
        fs::write(project_dir.join("tsconfig.json"), "{}").unwrap();
        fs::write(project_dir.join("src/index.ts"), "export const x = 1;\n").unwrap();

        // This will fail because javy is not installed (or tsc fails first)
        let result = run_build(project_dir.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn pack_creates_tarball() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path().join("test-skill");
        fs::create_dir_all(&project_dir).unwrap();

        // Write manifest
        fs::write(
            project_dir.join("manifest.toml"),
            r#"
[skill]
name = "test-skill"
version = "0.1.0"
description = "Test"
"#,
        )
        .unwrap();

        // Write a dummy .wasm file
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#;
        // Write WAT text directly — wasmtime::Module::new accepts WAT
        let wasm = wat.as_bytes();
        fs::write(project_dir.join("test_skill.wasm"), wasm).unwrap();
        fs::write(
            project_dir.join("test_skill.toml"),
            r#"
[skill]
name = "test-skill"
version = "0.1.0"
description = "Test"
"#,
        )
        .unwrap();

        let output_dir = tmp.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        let result = run_pack(project_dir.to_str().unwrap(), output_dir.to_str().unwrap());
        assert!(result.is_ok(), "pack failed: {:?}", result);

        let tarball = output_dir.join("test-skill-0.1.0.tar.gz");
        assert!(tarball.exists(), "tarball should exist");
        assert!(
            fs::metadata(&tarball).unwrap().len() > 0,
            "tarball should not be empty"
        );
    }

    #[test]
    fn pack_fails_when_stem_manifest_missing() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path().join("bad-skill");
        fs::create_dir_all(&project_dir).unwrap();
        fs::write(
            project_dir.join("manifest.toml"),
            r#"
[skill]
name = "bad-skill"
version = "0.1.0"
description = "Bad"
"#,
        )
        .unwrap();
        fs::write(
            project_dir.join("bad_skill.wasm"),
            r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#,
        )
        .unwrap();

        let out = tmp.path().join("out");
        fs::create_dir_all(&out).unwrap();
        let result = run_pack(project_dir.to_str().unwrap(), out.to_str().unwrap());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("run 'encmind-skill build' first"));
    }

    #[test]
    fn pack_fails_when_stem_manifest_differs_from_manifest_toml() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path().join("drift-skill");
        fs::create_dir_all(&project_dir).unwrap();
        fs::write(
            project_dir.join("manifest.toml"),
            r#"
[skill]
name = "drift-skill"
version = "0.1.0"
description = "Source manifest"
"#,
        )
        .unwrap();
        fs::write(
            project_dir.join("drift_skill.toml"),
            r#"
[skill]
name = "drift-skill"
version = "0.2.0"
description = "Built manifest drifted"
"#,
        )
        .unwrap();
        fs::write(
            project_dir.join("drift_skill.wasm"),
            r#"(module
            (memory (export "memory") 1)
            (func (export "__encmind_alloc") (param i32) (result i32) i32.const 0)
            (func (export "__encmind_invoke") (param i32 i32) (result i64) i64.const 0)
        )"#,
        )
        .unwrap();

        let out = tmp.path().join("out");
        fs::create_dir_all(&out).unwrap();
        let result = run_pack(project_dir.to_str().unwrap(), out.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("differs from manifest.toml"));
    }
}
