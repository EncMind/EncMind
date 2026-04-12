pub mod anthropic;
pub mod health;
pub mod openai;
pub mod retry;
pub mod sse;

mod dispatcher;
pub use dispatcher::LlmDispatcher;

/// Parse a `Retry-After` header value as numeric delta-seconds.
/// HTTP-date format is ignored (Anthropic/OpenAI use numeric in practice).
pub(crate) fn parse_retry_after(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retry_after_numeric() {
        assert_eq!(parse_retry_after("42"), Some(42));
        assert_eq!(parse_retry_after("  7 "), Some(7));
        assert_eq!(parse_retry_after("0"), Some(0));
    }

    #[test]
    fn parse_retry_after_rejects_non_numeric() {
        assert_eq!(parse_retry_after("Thu, 01 Jan 2026 00:00:00 GMT"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("abc"), None);
        assert_eq!(parse_retry_after("-1"), None);
    }
}
