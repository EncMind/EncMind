pub mod cron_dispatcher;
pub mod gmail;
pub mod heartbeat;
pub mod router;
pub mod slack;
pub mod telegram;
pub mod transform;
mod util;

use std::sync::Arc;

use encmind_core::channel_credentials::{
    CHANNEL_TYPE_GMAIL, CHANNEL_TYPE_SLACK, CHANNEL_TYPE_TELEGRAM,
};
use encmind_core::config::AppConfig;
use encmind_core::error::ChannelError;
use encmind_core::traits::ChannelAdapter;

/// Factory: construct a channel adapter from stored credentials and the app config.
/// Returns `Arc<dyn ChannelAdapter>` for the given `channel_type`.
pub fn adapter_from_credentials(
    channel_type: &str,
    config: &AppConfig,
    cred_json: &str,
) -> Result<Arc<dyn ChannelAdapter>, ChannelError> {
    match channel_type {
        CHANNEL_TYPE_TELEGRAM => {
            let telegram_config = config.channels.telegram.clone().unwrap_or_default();
            let adapter =
                telegram::TelegramAdapter::from_config_and_credentials(telegram_config, cred_json)?;
            Ok(Arc::new(adapter))
        }
        CHANNEL_TYPE_SLACK => {
            let slack_config = config.channels.slack.clone().unwrap_or_default();
            let adapter =
                slack::SlackAdapter::from_config_and_credentials(slack_config, cred_json)?;
            Ok(Arc::new(adapter))
        }
        CHANNEL_TYPE_GMAIL => {
            let gmail_config = config.channels.gmail.clone().unwrap_or_default();
            let adapter =
                gmail::GmailAdapter::from_config_and_credentials(gmail_config, cred_json)?;
            Ok(Arc::new(adapter))
        }
        other => Err(ChannelError::NotConfigured(format!(
            "unsupported channel_type: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_telegram() {
        let config = AppConfig::default();
        let cred = r#"{"bot_token": "123:ABC"}"#;
        let adapter = adapter_from_credentials(CHANNEL_TYPE_TELEGRAM, &config, cred);
        assert!(adapter.is_ok());
    }

    #[test]
    fn factory_slack() {
        let config = AppConfig::default();
        let cred = r#"{"bot_token": "xoxb-test", "app_token": "xapp-test"}"#;
        let adapter = adapter_from_credentials(CHANNEL_TYPE_SLACK, &config, cred);
        assert!(adapter.is_ok());
    }

    #[test]
    fn factory_gmail() {
        let config = AppConfig::default();
        let cred = r#"{"client_id": "cid", "client_secret": "csec", "refresh_token": "rt"}"#;
        let adapter = adapter_from_credentials(CHANNEL_TYPE_GMAIL, &config, cred);
        assert!(adapter.is_ok());
    }

    #[test]
    fn factory_unknown_type() {
        let config = AppConfig::default();
        match adapter_from_credentials("discord", &config, "{}") {
            Err(ChannelError::NotConfigured(msg)) => {
                assert!(msg.contains("unsupported channel_type"));
            }
            Err(other) => panic!("expected NotConfigured, got different error: {other}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
