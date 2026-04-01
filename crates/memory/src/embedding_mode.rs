use std::sync::Arc;

use encmind_core::config::{EmbeddingMode, MemoryConfig};
use encmind_core::error::MemoryError;
use encmind_core::traits::Embedder;

use crate::embedder::api::ApiEmbedder;

/// Known embedding API domains that external mode may use.
const KNOWN_EMBEDDING_DOMAINS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "api.cohere.ai",
    "api.voyageai.com",
];

/// Enforces embedding mode policies: Private vs External.
pub struct EmbeddingModeEnforcer {
    mode: EmbeddingMode,
}

impl EmbeddingModeEnforcer {
    pub fn new(mode: EmbeddingMode) -> Self {
        Self { mode }
    }

    /// Create an embedder based on the current mode and config.
    pub fn create_embedder(&self, config: &MemoryConfig) -> Result<Arc<dyn Embedder>, MemoryError> {
        match &self.mode {
            EmbeddingMode::Private => {
                #[cfg(feature = "local-embedding")]
                {
                    let embedder = if let Some(local_model_path) =
                        config.local_model_path.as_deref()
                    {
                        crate::embedder::local::LocalEmbedder::from_local_dir(
                            &config.model_name,
                            local_model_path,
                        )?
                    } else {
                        crate::embedder::local::LocalEmbedder::from_hub(&config.model_name, None)?
                    };
                    Ok(Arc::new(embedder))
                }
                #[cfg(not(feature = "local-embedding"))]
                {
                    let _ = config;
                    Err(MemoryError::ModelNotLoaded(
                        "private embedding mode requires the 'local-embedding' feature; \
                         rebuild with: cargo build --features local-embedding"
                            .into(),
                    ))
                }
            }
            EmbeddingMode::External {
                provider,
                api_base_url,
            } => {
                let key_env = embedding_api_key_env(provider);
                let api_key = std::env::var(&key_env).map_err(|_| {
                    MemoryError::InvalidConfig(format!(
                        "missing embedding API key for provider '{provider}'; set env var {key_env}"
                    ))
                })?;
                Ok(Arc::new(ApiEmbedder::new(
                    api_base_url,
                    &config.model_name,
                    config.embedding_dimensions,
                    Some(api_key),
                )))
            }
        }
    }

    /// Verify that the egress firewall config is consistent with the embedding mode.
    ///
    /// - Private mode: emits warnings if known embedding API domains are present in allowlist.
    /// - External mode: soft check only; firewall enforcement happens at request time.
    pub fn verify_firewall_consistency(
        &self,
        firewall_allowlist: &[String],
    ) -> Result<(), MemoryError> {
        match &self.mode {
            EmbeddingMode::Private => {
                let mut embedding_domains = Vec::new();
                for domain in firewall_allowlist {
                    if KNOWN_EMBEDDING_DOMAINS.iter().any(|d| domain.contains(d)) {
                        embedding_domains.push(domain.clone());
                    }
                }
                if !embedding_domains.is_empty() {
                    tracing::warn!(
                        allowlist_domains = ?embedding_domains,
                        "private embedding mode is enabled but firewall allowlist includes known embedding API domains"
                    );
                }
                Ok(())
            }
            EmbeddingMode::External { api_base_url, .. } => {
                // Check that the API base URL's domain is reachable (in the allowlist or firewall disabled)
                // This is a soft check — actual enforcement happens at the firewall layer
                let _ = api_base_url; // We trust the firewall to handle this
                Ok(())
            }
        }
    }

    /// Switch to a new embedding mode. Returns the old mode.
    pub fn switch_mode(&mut self, new_mode: EmbeddingMode) -> EmbeddingMode {
        let old = self.mode.clone();
        tracing::info!(
            old = ?old,
            new = ?new_mode,
            "security.embedding_mode_changed"
        );
        self.mode = new_mode;
        old
    }

    /// Get the current mode.
    pub fn current_mode(&self) -> &EmbeddingMode {
        &self.mode
    }

    /// List known embedding API domains.
    pub fn known_domains() -> &'static [&'static str] {
        KNOWN_EMBEDDING_DOMAINS
    }
}

fn embedding_api_key_env(provider: &str) -> String {
    if provider.eq_ignore_ascii_case("openai") {
        return "OPENAI_API_KEY".to_owned();
    }
    if provider.eq_ignore_ascii_case("anthropic") {
        return "ANTHROPIC_API_KEY".to_owned();
    }

    let normalized = provider
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{normalized}_API_KEY")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn default_config() -> MemoryConfig {
        MemoryConfig::default()
    }

    #[test]
    fn private_mode_uses_configured_local_model_path() {
        let mut config = default_config();
        let temp = tempdir().expect("create tempdir");
        config.local_model_path = Some(temp.path().join("missing-model-dir"));
        let enforcer = EmbeddingModeEnforcer::new(EmbeddingMode::Private);
        let err = match enforcer.create_embedder(&config) {
            Ok(_) => panic!("expected create_embedder to fail for invalid local_model_path"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("local_model_path is not a directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn external_mode_creates_api_embedder() {
        std::env::set_var("ACME_API_KEY", "test-key");
        let mut config = default_config();
        config.model_name = "text-embedding-3-small".to_string();
        config.embedding_dimensions = 1536;
        let enforcer = EmbeddingModeEnforcer::new(EmbeddingMode::External {
            provider: "acme".into(),
            api_base_url: "https://example.com".into(),
        });
        let result = enforcer.create_embedder(&config);
        assert!(result.is_ok());
        let embedder = result.unwrap();
        assert_eq!(embedder.dimensions(), 1536);
        std::env::remove_var("ACME_API_KEY");
    }

    #[test]
    fn firewall_consistency_private_allows_embedding_domains() {
        let enforcer = EmbeddingModeEnforcer::new(EmbeddingMode::Private);
        let allowlist = vec!["api.openai.com".to_string(), "example.com".to_string()];
        let result = enforcer.verify_firewall_consistency(&allowlist);
        assert!(result.is_ok());
    }

    #[test]
    fn firewall_consistency_private_allows_non_embedding_domains() {
        let enforcer = EmbeddingModeEnforcer::new(EmbeddingMode::Private);
        let allowlist = vec!["example.com".to_string()];
        let result = enforcer.verify_firewall_consistency(&allowlist);
        assert!(result.is_ok());
    }

    #[test]
    fn firewall_consistency_external_ok() {
        let enforcer = EmbeddingModeEnforcer::new(EmbeddingMode::External {
            provider: "openai".into(),
            api_base_url: "https://api.openai.com".into(),
        });
        let allowlist = vec!["api.openai.com".to_string()];
        let result = enforcer.verify_firewall_consistency(&allowlist);
        assert!(result.is_ok());
    }

    #[test]
    fn mode_switch() {
        let mut enforcer = EmbeddingModeEnforcer::new(EmbeddingMode::Private);
        let old = enforcer.switch_mode(EmbeddingMode::External {
            provider: "openai".into(),
            api_base_url: "https://api.openai.com".into(),
        });
        assert!(matches!(old, EmbeddingMode::Private));
        assert!(matches!(
            enforcer.current_mode(),
            EmbeddingMode::External { .. }
        ));
    }

    #[test]
    fn known_domains_list() {
        let domains = EmbeddingModeEnforcer::known_domains();
        assert!(domains.contains(&"api.openai.com"));
        assert!(domains.len() >= 3);
    }
}
