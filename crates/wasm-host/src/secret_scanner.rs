use std::sync::LazyLock;

use regex::Regex;

use encmind_core::error::WasmHostError;

static SECRET_PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern {
            name: "Anthropic API key",
            regex: Regex::new(r"sk-ant-[a-zA-Z0-9_-]{20,}").unwrap(),
        },
        SecretPattern {
            name: "OpenAI API key",
            regex: Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap(),
        },
        SecretPattern {
            name: "AWS access key",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        SecretPattern {
            name: "GitHub token",
            regex: Regex::new(r"gh[ps]_[A-Za-z0-9_]{36,}").unwrap(),
        },
        SecretPattern {
            name: "PEM private key",
            regex: Regex::new(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
        },
        SecretPattern {
            name: "Bearer token",
            regex: Regex::new(r"Bearer\s+[a-zA-Z0-9._\-]{20,}").unwrap(),
        },
        SecretPattern {
            name: "Generic secret",
            regex: Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['"][a-zA-Z0-9._-]{16,}['"]"#).unwrap(),
        },
]
});

struct SecretPattern {
    name: &'static str,
    regex: Regex,
}

/// Scan text for potential secrets.
///
/// Returns `Ok(())` if no secrets are found, or `Err(SecretDetected)` with
/// the pattern name that matched.
pub fn scan(text: &str) -> Result<(), WasmHostError> {
    for pattern in SECRET_PATTERNS.iter() {
        if pattern.regex.is_match(text) {
            return Err(WasmHostError::SecretDetected(format!(
                "blocked: {} pattern detected in outbound data",
                pattern.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_passes() {
        assert!(scan("Hello, world! This is normal text.").is_ok());
    }

    #[test]
    fn detects_openai_key() {
        let text = "Using key sk-abcdefghijklmnopqrstuvwxyz1234567890";
        assert!(scan(text).is_err());
    }

    #[test]
    fn detects_anthropic_key() {
        let text = "key: sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        assert!(scan(text).is_err());
    }

    #[test]
    fn detects_aws_key() {
        let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        assert!(scan(text).is_err());
    }

    #[test]
    fn detects_github_token() {
        let text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12";
        assert!(scan(text).is_err());
    }

    #[test]
    fn detects_pem_private_key() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        assert!(scan(text).is_err());
    }

    #[test]
    fn detects_bearer_token() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
        assert!(scan(text).is_err());
    }

    #[test]
    fn detects_generic_secret() {
        let text = r#"config: api_key = "sk_live_1234567890abcdef""#;
        assert!(scan(text).is_err());
    }

    #[test]
    fn short_strings_pass() {
        // Too short to match patterns
        assert!(scan("sk-abc").is_ok());
        assert!(scan("Bearer short").is_ok());
    }

    #[test]
    fn error_includes_pattern_name() {
        let err = scan("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pattern detected"), "got: {msg}");
    }
}
