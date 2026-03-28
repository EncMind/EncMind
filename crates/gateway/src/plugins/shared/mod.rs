pub mod url_extract;

use encmind_core::error::AppError;
use futures::StreamExt;

pub(crate) fn parse_optional_trimmed_string_field(
    input: &serde_json::Value,
    field: &str,
    context: &str,
) -> Result<Option<String>, AppError> {
    match input.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => {
            let value = value.trim();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value.to_string()))
            }
        }
        Some(_) => Err(AppError::Internal(format!(
            "{context}: {field} must be a string when provided"
        ))),
    }
}

pub(crate) async fn read_response_body_capped(
    response: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> Result<Vec<u8>, AppError> {
    if let Some(content_len) = response.content_length() {
        if content_len > max_bytes as u64 {
            return Err(AppError::Internal(format!(
                "{context}: response body exceeds limit ({content_len} > {max_bytes} bytes)"
            )));
        }
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| AppError::Internal(format!("{context}: failed to read body: {e}")))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(AppError::Internal(format!(
                "{context}: response body exceeded limit ({max_bytes} bytes)"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::parse_optional_trimmed_string_field;

    #[test]
    fn parse_optional_trimmed_string_field_trims_and_normalizes() {
        let input = serde_json::json!({ "selector": "  article.main  " });
        let parsed =
            parse_optional_trimmed_string_field(&input, "selector", "test_context").unwrap();
        assert_eq!(parsed.as_deref(), Some("article.main"));
    }

    #[test]
    fn parse_optional_trimmed_string_field_empty_is_none() {
        let input = serde_json::json!({ "selector": "   " });
        let parsed =
            parse_optional_trimmed_string_field(&input, "selector", "test_context").unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_optional_trimmed_string_field_rejects_non_string() {
        let input = serde_json::json!({ "selector": 123 });
        let err =
            parse_optional_trimmed_string_field(&input, "selector", "test_context").unwrap_err();
        assert!(
            err.to_string()
                .contains("test_context: selector must be a string"),
            "err = {err}"
        );
    }
}
