/// Validate a skill identifier used across manifests, APIs, and runtime state.
///
/// Allowed characters: `[A-Za-z0-9._-]`.
/// Additional constraints:
/// - non-empty
/// - must not start or end with `.`
pub fn validate_skill_id(skill_id: &str) -> Result<(), String> {
    if skill_id.is_empty() {
        return Err("skill_id must not be empty".into());
    }
    if !skill_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Err(format!(
            "invalid skill_id '{skill_id}': allowed characters are [A-Za-z0-9._-]"
        ));
    }
    if skill_id.starts_with('.') || skill_id.ends_with('.') {
        return Err(format!(
            "invalid skill_id '{skill_id}': must not start or end with '.'"
        ));
    }
    Ok(())
}

/// Predicate helper for skill identifier validation.
pub fn is_valid_skill_id(skill_id: &str) -> bool {
    validate_skill_id(skill_id).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_skill_id_accepts_expected_patterns() {
        assert!(validate_skill_id("echo-skill_v1").is_ok());
        assert!(validate_skill_id("acme.search.v1").is_ok());
    }

    #[test]
    fn validate_skill_id_rejects_invalid_patterns() {
        let err = validate_skill_id("").unwrap_err();
        assert!(err.contains("must not be empty"));

        let err = validate_skill_id("bad/skill").unwrap_err();
        assert!(err.contains("allowed characters"));

        let err = validate_skill_id("bad skill").unwrap_err();
        assert!(err.contains("allowed characters"));

        let err = validate_skill_id(".hidden").unwrap_err();
        assert!(err.contains("must not start or end with '.'"));

        let err = validate_skill_id("trailing.").unwrap_err();
        assert!(err.contains("must not start or end with '.'"));
    }
}
