//! User-facing error classification for chat.send failures.
//!
//! Maps raw `AppError` variants into short, actionable messages
//! suitable for channel-based UX (Telegram, Slack, Gmail) where
//! users can't inspect logs or retry with flags. The classifier
//! returns a `ClassifiedError` with both the original raw detail
//! (for audit logs) and a user-friendly hint (for the response).

use encmind_core::error::{AppError, LlmError};

/// A classified error with both operator-facing and user-facing text.
#[derive(Debug)]
pub struct ClassifiedError {
    /// Short category tag for programmatic routing (e.g. metrics).
    pub category: &'static str,
    /// Actionable message safe to show to end users via channels.
    pub user_message: String,
    /// Full raw error detail for audit logs.
    pub raw_detail: String,
}

/// Classify an `AppError` into a user-facing message + category.
pub fn classify(error: &AppError) -> ClassifiedError {
    let raw = error.to_string();

    match error {
        // ---- LLM-layer errors ----
        AppError::Llm(llm_err) => classify_llm_error(llm_err, &raw),

        // ---- Tool denials ----
        AppError::ToolDenied { reason, message } => ClassifiedError {
            category: "tool_denied",
            user_message: format!("Action blocked by security policy: {message}"),
            raw_detail: format!("ToolDenied({reason}): {message}"),
        },

        // ---- Storage ----
        AppError::Storage(_) => ClassifiedError {
            category: "storage_error",
            user_message:
                "A database error occurred. The request could not be completed — please try again."
                    .to_string(),
            raw_detail: raw,
        },

        // ---- Everything else ----
        _ => ClassifiedError {
            category: "internal_error",
            user_message:
                "An internal error occurred. If this persists, check the server logs.".to_string(),
            raw_detail: raw,
        },
    }
}

fn classify_llm_error(err: &LlmError, raw: &str) -> ClassifiedError {
    match err {
        LlmError::NotConfigured => ClassifiedError {
            category: "not_configured",
            user_message: "The AI model is not configured. Please set up an API provider."
                .to_string(),
            raw_detail: raw.to_string(),
        },

        LlmError::RateLimited { retry_after_secs } => {
            let hint = match retry_after_secs {
                Some(secs) => format!(
                    "The AI service is rate-limited. Please wait about {secs} seconds and try again."
                ),
                None => "The AI service is rate-limited. Please wait a moment and try again."
                    .to_string(),
            };
            ClassifiedError {
                category: "rate_limited",
                user_message: hint,
                raw_detail: raw.to_string(),
            }
        }

        LlmError::AllProvidersUnhealthy => ClassifiedError {
            category: "providers_unavailable",
            user_message: "All AI providers are currently unavailable. Please try again shortly."
                .to_string(),
            raw_detail: raw.to_string(),
        },

        LlmError::Cancelled => ClassifiedError {
            category: "cancelled",
            user_message: "The request was cancelled.".to_string(),
            raw_detail: raw.to_string(),
        },

        // Pattern-match on the error string for status-code hints
        // that the typed error doesn't capture (e.g. provider errors
        // that wrap HTTP status codes).
        LlmError::InferenceError(msg)
        | LlmError::ProviderError(msg)
        | LlmError::ApiError(msg)
        | LlmError::StreamError(msg) => classify_llm_message(msg, raw),

        LlmError::TokenizationError(_) => ClassifiedError {
            category: "tokenization_error",
            user_message:
                "Failed to count tokens for your message. Try sending a shorter message."
                    .to_string(),
            raw_detail: raw.to_string(),
        },
    }
}

fn classify_llm_message(msg: &str, raw: &str) -> ClassifiedError {
    let lower = msg.to_lowercase();

    // Overloaded / 529
    if lower.contains("529") || lower.contains("overloaded") {
        return ClassifiedError {
            category: "overloaded",
            user_message:
                "The AI service is temporarily overloaded. Please retry shortly.".to_string(),
            raw_detail: raw.to_string(),
        };
    }

    // Rate limit (string-level, for cases not caught by the typed variant)
    if lower.contains("429") || lower.contains("rate limit") || lower.contains("too many") {
        return ClassifiedError {
            category: "rate_limited",
            user_message: "The AI service is rate-limited. Please wait a moment and try again."
                .to_string(),
            raw_detail: raw.to_string(),
        };
    }

    // Context length / prompt too long
    if lower.contains("context length")
        || lower.contains("too many tokens")
        || lower.contains("prompt is too long")
        || lower.contains("maximum context")
    {
        return ClassifiedError {
            category: "context_too_long",
            user_message:
                "Your conversation is too long for the model's context window. Try starting a new session or sending a shorter message."
                    .to_string(),
            raw_detail: raw.to_string(),
        };
    }

    // Server errors (500-504)
    if lower.contains("500")
        || lower.contains("502")
        || lower.contains("503")
        || lower.contains("504")
        || lower.contains("internal server error")
        || lower.contains("bad gateway")
        || lower.contains("service unavailable")
    {
        return ClassifiedError {
            category: "server_error",
            user_message: "The AI service encountered a temporary error. Please try again."
                .to_string(),
            raw_detail: raw.to_string(),
        };
    }

    // Auth errors
    if lower.contains("401")
        || lower.contains("403")
        || lower.contains("authentication")
        || lower.contains("unauthorized")
    {
        return ClassifiedError {
            category: "auth_error",
            user_message: "Authentication with the AI provider failed. Please check your API keys."
                .to_string(),
            raw_detail: raw.to_string(),
        };
    }

    // Fallback
    ClassifiedError {
        category: "inference_error",
        user_message: "The AI model returned an error. Please try again.".to_string(),
        raw_detail: raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_with_retry_after() {
        let err = AppError::Llm(LlmError::RateLimited {
            retry_after_secs: Some(30),
        });
        let c = classify(&err);
        assert_eq!(c.category, "rate_limited");
        assert!(c.user_message.contains("30 seconds"));
    }

    #[test]
    fn rate_limited_without_retry_after() {
        let err = AppError::Llm(LlmError::RateLimited {
            retry_after_secs: None,
        });
        let c = classify(&err);
        assert_eq!(c.category, "rate_limited");
        assert!(c.user_message.contains("wait a moment"));
    }

    #[test]
    fn overloaded_529() {
        let err = AppError::Llm(LlmError::InferenceError(
            "HTTP 529 Overloaded".to_string(),
        ));
        let c = classify(&err);
        assert_eq!(c.category, "overloaded");
        assert!(c.user_message.contains("retry shortly"));
    }

    #[test]
    fn context_too_long() {
        let err = AppError::Llm(LlmError::ApiError(
            "prompt is too long: 150000 tokens exceeds maximum context length of 128000"
                .to_string(),
        ));
        let c = classify(&err);
        assert_eq!(c.category, "context_too_long");
        assert!(c.user_message.contains("too long"));
    }

    #[test]
    fn auth_failure() {
        let err = AppError::Llm(LlmError::ProviderError(
            "401 Unauthorized: invalid API key".to_string(),
        ));
        let c = classify(&err);
        assert_eq!(c.category, "auth_error");
        assert!(c.user_message.contains("API keys"));
    }

    #[test]
    fn server_error_502() {
        let err = AppError::Llm(LlmError::StreamError("502 Bad Gateway".to_string()));
        let c = classify(&err);
        assert_eq!(c.category, "server_error");
        assert!(c.user_message.contains("temporary error"));
    }

    #[test]
    fn tool_denied_surfaces_message() {
        let err = AppError::ToolDenied {
            reason: "policy_denied".to_string(),
            message: "bash is disabled".to_string(),
        };
        let c = classify(&err);
        assert_eq!(c.category, "tool_denied");
        assert!(c.user_message.contains("bash is disabled"));
    }

    #[test]
    fn not_configured() {
        let err = AppError::Llm(LlmError::NotConfigured);
        let c = classify(&err);
        assert_eq!(c.category, "not_configured");
        assert!(c.user_message.contains("not configured"));
    }

    #[test]
    fn all_providers_unhealthy() {
        let err = AppError::Llm(LlmError::AllProvidersUnhealthy);
        let c = classify(&err);
        assert_eq!(c.category, "providers_unavailable");
    }

    #[test]
    fn generic_inference_error_falls_back() {
        let err = AppError::Llm(LlmError::InferenceError("unknown glitch".to_string()));
        let c = classify(&err);
        assert_eq!(c.category, "inference_error");
        assert!(c.user_message.contains("try again"));
    }

    #[test]
    fn storage_error_gives_generic_hint() {
        let err = AppError::Storage(encmind_core::error::StorageError::Sqlite(
            "database is locked".to_string(),
        ));
        let c = classify(&err);
        assert_eq!(c.category, "storage_error");
        assert!(c.user_message.contains("database error"));
    }

    #[test]
    fn internal_error_gives_generic_hint() {
        let err = AppError::Internal("unexpected state".to_string());
        let c = classify(&err);
        assert_eq!(c.category, "internal_error");
        assert!(c.user_message.contains("internal error"));
    }
}
