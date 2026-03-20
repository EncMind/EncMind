use serde_json::{Map, Value};
use thiserror::Error;

pub const CHANNEL_TYPE_TELEGRAM: &str = "telegram";
pub const CHANNEL_TYPE_SLACK: &str = "slack";
pub const CHANNEL_TYPE_GMAIL: &str = "gmail";
const TELEGRAM_FIELDS: &[&str] = &["bot_token"];
const SLACK_FIELDS: &[&str] = &["bot_token", "app_token"];
const GMAIL_FIELDS: &[&str] = &["client_id", "client_secret", "refresh_token"];

#[derive(Clone, Copy)]
struct ChannelCredentialSchema {
    required_fields: &'static [&'static str],
    allowed_fields: &'static [&'static str],
}

fn channel_credential_schema(channel_type: &str) -> Option<ChannelCredentialSchema> {
    match channel_type {
        CHANNEL_TYPE_TELEGRAM => Some(ChannelCredentialSchema {
            required_fields: TELEGRAM_FIELDS,
            allowed_fields: TELEGRAM_FIELDS,
        }),
        CHANNEL_TYPE_SLACK => Some(ChannelCredentialSchema {
            required_fields: SLACK_FIELDS,
            allowed_fields: SLACK_FIELDS,
        }),
        CHANNEL_TYPE_GMAIL => Some(ChannelCredentialSchema {
            required_fields: GMAIL_FIELDS,
            allowed_fields: GMAIL_FIELDS,
        }),
        _ => None,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelCredentialError {
    #[error("unsupported channel_type: {0}")]
    UnsupportedChannelType(String),
    #[error("missing required credential field: {0}")]
    MissingRequiredField(String),
    #[error("invalid stored credential JSON: {0}")]
    InvalidStoredCredentialJson(String),
    #[error("stored credential JSON must be an object")]
    StoredCredentialNotObject,
    #[error("unexpected credential field: {0}")]
    UnexpectedCredentialField(String),
}

pub fn is_supported_channel_type(channel_type: &str) -> bool {
    channel_credential_schema(channel_type).is_some()
}

pub fn required_channel_credential_fields(channel_type: &str) -> Option<&'static [&'static str]> {
    channel_credential_schema(channel_type).map(|schema| schema.required_fields)
}

pub fn allowed_channel_credential_fields(channel_type: &str) -> Option<&'static [&'static str]> {
    channel_credential_schema(channel_type).map(|schema| schema.allowed_fields)
}

pub fn parse_channel_credential_object(
    raw: &str,
) -> Result<Map<String, Value>, ChannelCredentialError> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| ChannelCredentialError::InvalidStoredCredentialJson(e.to_string()))?;
    let obj = parsed
        .as_object()
        .ok_or(ChannelCredentialError::StoredCredentialNotObject)?;
    Ok(obj.clone())
}

pub fn merge_and_validate_channel_credentials(
    channel_type: &str,
    existing: Option<&str>,
    incoming: Map<String, Value>,
) -> Result<Map<String, Value>, ChannelCredentialError> {
    let Some(schema) = channel_credential_schema(channel_type) else {
        return Err(ChannelCredentialError::UnsupportedChannelType(
            channel_type.to_string(),
        ));
    };
    let required_fields = schema.required_fields;
    let allowed_fields = schema.allowed_fields;

    let mut merged = if let Some(raw) = existing {
        parse_channel_credential_object(raw)?
    } else {
        Map::new()
    };
    // Forward compatibility: tolerate and drop unknown stored keys so
    // previously persisted data does not break login after schema changes.
    merged.retain(|key, _| allowed_fields.contains(&key.as_str()));
    for key in incoming.keys() {
        if !allowed_fields.contains(&key.as_str()) {
            return Err(ChannelCredentialError::UnexpectedCredentialField(
                key.to_string(),
            ));
        }
    }
    for (k, v) in incoming {
        merged.insert(k, v);
    }

    for required in required_fields {
        let value = merged
            .get(*required)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if value.is_none() {
            return Err(ChannelCredentialError::MissingRequiredField(
                required.to_string(),
            ));
        }
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_types_are_known() {
        assert!(is_supported_channel_type(CHANNEL_TYPE_TELEGRAM));
        assert!(is_supported_channel_type(CHANNEL_TYPE_SLACK));
        assert!(is_supported_channel_type(CHANNEL_TYPE_GMAIL));
        assert!(!is_supported_channel_type("discord"));
    }

    #[test]
    fn gmail_merge_requires_all_fields() {
        let mut incoming = Map::new();
        incoming.insert("client_id".to_string(), Value::String("cid".to_string()));
        incoming.insert(
            "client_secret".to_string(),
            Value::String("csec".to_string()),
        );
        let err = merge_and_validate_channel_credentials(CHANNEL_TYPE_GMAIL, None, incoming)
            .expect_err("should reject missing refresh_token");
        assert_eq!(
            err,
            ChannelCredentialError::MissingRequiredField("refresh_token".to_string())
        );
    }

    #[test]
    fn gmail_merge_succeeds_with_all_fields() {
        let mut incoming = Map::new();
        incoming.insert("client_id".into(), Value::String("cid".into()));
        incoming.insert("client_secret".into(), Value::String("csec".into()));
        incoming.insert("refresh_token".into(), Value::String("rt".into()));
        let merged = merge_and_validate_channel_credentials(CHANNEL_TYPE_GMAIL, None, incoming)
            .expect("should succeed with all fields");
        assert_eq!(
            merged.get("client_id").and_then(|v| v.as_str()),
            Some("cid")
        );
        assert_eq!(
            merged.get("refresh_token").and_then(|v| v.as_str()),
            Some("rt")
        );
    }

    #[test]
    fn merge_preserves_existing_required_fields() {
        let existing = r#"{"bot_token":"xoxb-old","app_token":"xapp-old"}"#;
        let mut incoming = Map::new();
        incoming.insert(
            "bot_token".to_string(),
            Value::String("xoxb-new".to_string()),
        );

        let merged =
            merge_and_validate_channel_credentials(CHANNEL_TYPE_SLACK, Some(existing), incoming)
                .expect("merge should succeed");

        assert_eq!(
            merged.get("bot_token").and_then(|v| v.as_str()),
            Some("xoxb-new")
        );
        assert_eq!(
            merged.get("app_token").and_then(|v| v.as_str()),
            Some("xapp-old")
        );
    }

    #[test]
    fn merge_rejects_missing_required_field() {
        let mut incoming = Map::new();
        incoming.insert(
            "bot_token".to_string(),
            Value::String("xoxb-only".to_string()),
        );
        let err = merge_and_validate_channel_credentials(CHANNEL_TYPE_SLACK, None, incoming)
            .expect_err("should reject missing app_token");
        assert_eq!(
            err,
            ChannelCredentialError::MissingRequiredField("app_token".to_string())
        );
    }

    #[test]
    fn merge_rejects_unknown_channel_type() {
        let err = merge_and_validate_channel_credentials("discord", None, Map::new())
            .expect_err("should reject unknown channel");
        assert_eq!(
            err,
            ChannelCredentialError::UnsupportedChannelType("discord".to_string())
        );
    }

    #[test]
    fn merge_rejects_invalid_existing_json() {
        let err = merge_and_validate_channel_credentials(
            CHANNEL_TYPE_TELEGRAM,
            Some("not-json"),
            Map::new(),
        )
        .expect_err("should reject invalid existing credential payload");
        assert!(matches!(
            err,
            ChannelCredentialError::InvalidStoredCredentialJson(_)
        ));
    }

    #[test]
    fn merge_rejects_unexpected_field() {
        let mut incoming = Map::new();
        incoming.insert(
            "bot_token".to_string(),
            Value::String("xoxb-token".to_string()),
        );
        incoming.insert(
            "refresh_token".to_string(),
            Value::String("secret".to_string()),
        );
        let err = merge_and_validate_channel_credentials(CHANNEL_TYPE_TELEGRAM, None, incoming)
            .expect_err("should reject unknown field");
        assert_eq!(
            err,
            ChannelCredentialError::UnexpectedCredentialField("refresh_token".to_string())
        );
    }

    #[test]
    fn merge_drops_unexpected_stored_field() {
        let existing = r#"{"bot_token":"xoxb-old","refresh_token":"bad"}"#;
        let mut incoming = Map::new();
        incoming.insert(
            "bot_token".to_string(),
            Value::String("xoxb-new".to_string()),
        );
        let merged =
            merge_and_validate_channel_credentials(CHANNEL_TYPE_TELEGRAM, Some(existing), incoming)
                .expect("unknown stored field should be dropped");
        assert_eq!(
            merged.get("bot_token").and_then(|v| v.as_str()),
            Some("xoxb-new")
        );
        assert!(merged.get("refresh_token").is_none());
    }
}
