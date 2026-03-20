use std::path::Path;

use tokio_util::sync::CancellationToken;
use tracing::info;

/// Run the EncMind server.
pub async fn run_serve(config_path: &str) -> Result<(), anyhow::Error> {
    // Initialize tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // Load config
    let config = encmind_core::config::load_config(Path::new(config_path))?;
    info!(
        host = %config.server.host,
        port = config.server.port,
        "loaded configuration"
    );

    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    // Spawn Ctrl+C handler
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("received shutdown signal");
        shutdown_clone.cancel();
    });

    // Run the gateway
    encmind_gateway::server::run_gateway(config, shutdown).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_config_only(
        config_path: &str,
    ) -> Result<encmind_core::config::AppConfig, anyhow::Error> {
        let config = encmind_core::config::load_config(Path::new(config_path))?;
        Ok(config)
    }

    #[test]
    fn serve_fails_gracefully_on_bad_config() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(run_serve("/nonexistent/config.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn serve_fails_on_invalid_config_content() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad.yaml");
        std::fs::write(&config_path, "not: [valid: yaml: {{{").unwrap();

        let result = encmind_core::config::load_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn serve_loads_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        let db_path = dir.path().join("data.db");

        let yaml = format!(
            r#"
server:
  host: "127.0.0.1"
  port: 9999
storage:
  db_path: "{}"
  key_source:
    type: Passphrase
    passphrase_env: "ENCMIND_PASSPHRASE"
"#,
            db_path.display()
        );
        std::fs::write(&config_path, &yaml).unwrap();

        let config = load_config_only(config_path.to_str().unwrap()).unwrap();
        assert_eq!(config.server.port, 9999);
    }
}
