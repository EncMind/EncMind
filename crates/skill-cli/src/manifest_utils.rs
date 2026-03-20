use std::fs;
use std::path::Path;

/// Validate a skill name for safe file/path and manifest usage.
///
/// Allowed characters: `[A-Za-z0-9._-]`.
/// Additional constraints:
/// - non-empty
/// - must not start or end with `.`
pub fn validate_skill_name(skill_name: &str) -> Result<(), String> {
    encmind_core::skill_id::validate_skill_id(skill_name)
        .map_err(|err| err.replace("skill_id", "skill name"))
}

/// Ensure a built `{wasm_stem}.toml` artifact matches already-read source
/// manifest content.
pub fn ensure_manifest_artifact_matches_source_content(
    source_manifest_path: &Path,
    source_manifest_str: &str,
    built_manifest_path: &Path,
) -> Result<(), String> {
    let built_manifest_str = fs::read_to_string(built_manifest_path).map_err(|e| {
        format!(
            "failed to read built manifest {}: {e}",
            built_manifest_path.display()
        )
    })?;
    let source_manifest_val: toml::Value = toml::from_str(source_manifest_str).map_err(|e| {
        format!(
            "invalid source manifest {}: {e}",
            source_manifest_path.display()
        )
    })?;
    let built_manifest_val: toml::Value = toml::from_str(&built_manifest_str).map_err(|e| {
        format!(
            "invalid built manifest {}: {e}",
            built_manifest_path.display()
        )
    })?;

    if source_manifest_val != built_manifest_val {
        return Err(format!(
            "{} differs from manifest.toml; run 'encmind-skill build' first",
            built_manifest_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<wasm_stem>.toml")
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn validates_skill_name_allows_expected_characters() {
        assert!(validate_skill_name("echo-skill_v1").is_ok());
        assert!(validate_skill_name("acme.search.v1").is_ok());
    }

    #[test]
    fn validates_skill_name_rejects_invalid_patterns() {
        let err = validate_skill_name("").unwrap_err();
        assert!(err.contains("must not be empty"));

        let err = validate_skill_name("bad/skill").unwrap_err();
        assert!(err.contains("allowed characters"));

        let err = validate_skill_name("bad skill").unwrap_err();
        assert!(err.contains("allowed characters"));

        let err = validate_skill_name(".hidden").unwrap_err();
        assert!(err.contains("must not start or end with '.'"));

        let err = validate_skill_name("trailing.").unwrap_err();
        assert!(err.contains("must not start or end with '.'"));
    }

    #[test]
    fn accepts_equivalent_manifests() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("manifest.toml");
        let built = tmp.path().join("skill.toml");

        fs::write(
            &source,
            r#"
[skill]
name = "echo"
version = "0.1.0"
description = "desc"
"#,
        )
        .unwrap();
        // Same semantic content, different formatting/order.
        fs::write(
            &built,
            r#" [skill]
description="desc"
version="0.1.0"
name="echo"
"#,
        )
        .unwrap();

        let source_manifest = fs::read_to_string(&source).unwrap();
        assert!(
            ensure_manifest_artifact_matches_source_content(&source, &source_manifest, &built)
                .is_ok()
        );
    }

    #[test]
    fn rejects_different_manifests() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("manifest.toml");
        let built = tmp.path().join("skill.toml");

        fs::write(&source, "[skill]\nname='echo'\nversion='0.1.0'\n").unwrap();
        fs::write(&built, "[skill]\nname='echo'\nversion='0.2.0'\n").unwrap();

        let source_manifest = fs::read_to_string(&source).unwrap();
        let err =
            ensure_manifest_artifact_matches_source_content(&source, &source_manifest, &built)
                .unwrap_err();
        assert!(err.contains("differs from manifest.toml"));
    }

    #[test]
    fn reports_missing_built_manifest() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("manifest.toml");
        let built = tmp.path().join("skill.toml");

        fs::write(&source, "[skill]\nname='echo'\nversion='0.1.0'\n").unwrap();
        let source_manifest = fs::read_to_string(&source).unwrap();
        let err =
            ensure_manifest_artifact_matches_source_content(&source, &source_manifest, &built)
                .unwrap_err();
        assert!(err.contains("failed to read built manifest"));
    }
}
