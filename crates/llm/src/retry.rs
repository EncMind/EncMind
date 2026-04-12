use std::time::Duration;

use encmind_core::scheduler::QueryClass;

/// Retry policy for LLM API calls.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter_fraction: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            jitter_fraction: 0.25,
        }
    }
}

impl RetryPolicy {
    /// Build a retry policy scoped to a query class.
    ///
    /// - `Interactive` — user-facing traffic gets the full default
    ///   retry budget (3 attempts, exponential backoff). When the
    ///   upstream rate-limits or overloads, we want to give the user
    ///   a chance before surfacing the error.
    /// - `Background` — cron, webhook, and timer runs bail after a
    ///   single retry. Aggressive retries on background traffic during
    ///   an upstream cascade would amplify the outage, so fail fast
    ///   and let the caller propagate the error.
    ///
    /// The overall run is still bounded by
    /// `AgentPool::per_session_timeout_secs`, so neither class can
    /// retry indefinitely.
    pub fn for_class(class: QueryClass) -> Self {
        match class {
            QueryClass::Interactive => Self::default(),
            QueryClass::Background => Self {
                max_retries: 1,
                ..Self::default()
            },
        }
    }

    /// Build a retry policy from the current task-local query class,
    /// defaulting to `Interactive` when not set (tests, direct calls
    /// from outside an agent run).
    pub fn for_current_class() -> Self {
        Self::for_class(encmind_core::scheduler::current_query_class())
    }
}

/// Classification of exhausted retry errors for operator-facing messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustedErrorClass {
    RateLimited,
    ServerError,
    NetworkError,
    Unknown,
}

impl ExhaustedErrorClass {
    /// Human-readable explanation for logs/audit.
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::RateLimited => "all retries exhausted: upstream rate limit (429)",
            Self::ServerError => "all retries exhausted: upstream server error (5xx)",
            Self::NetworkError => "all retries exhausted: network/connection error",
            Self::Unknown => "all retries exhausted: unknown transient error",
        }
    }
}

impl RetryPolicy {
    /// Determine if an error string is retryable.
    /// Returns true for 429, 500-504, network/stream errors.
    /// Returns false for 400, 404, 422, cancelled, not-configured.
    pub fn is_retryable(error: &str) -> bool {
        let lower = error.to_lowercase();

        // Not retryable: client errors and explicit non-transient
        if lower.contains("400") && lower.contains("bad request") {
            return false;
        }
        if lower.contains("404") || lower.contains("not found") {
            return false;
        }
        if lower.contains("422") || lower.contains("unprocessable") {
            return false;
        }
        if lower.contains("cancelled") || lower.contains("canceled") {
            return false;
        }
        if lower.contains("not configured") || lower.contains("no provider") {
            return false;
        }
        if lower.contains("authentication") || lower.contains("401") || lower.contains("403") {
            return false;
        }

        // Retryable: rate limit
        if lower.contains("429")
            || lower.contains("rate limit")
            || lower.contains("too many requests")
        {
            return true;
        }
        // Retryable: server errors (including Anthropic's 529 "overloaded").
        if lower.contains("500")
            || lower.contains("502")
            || lower.contains("503")
            || lower.contains("504")
            || lower.contains("529")
        {
            return true;
        }
        if lower.contains("internal server error")
            || lower.contains("bad gateway")
            || lower.contains("service unavailable")
            || lower.contains("gateway timeout")
            || lower.contains("overloaded")
        {
            return true;
        }
        // Retryable: network/connection errors
        if lower.contains("connection")
            || lower.contains("timeout")
            || lower.contains("stream")
            || lower.contains("network")
            || lower.contains("reset")
        {
            return true;
        }

        false
    }

    /// Classify an error for user-facing messages after retries are exhausted.
    pub fn classify_error(error: &str) -> ExhaustedErrorClass {
        let lower = error.to_lowercase();
        if lower.contains("429")
            || lower.contains("rate limit")
            || lower.contains("too many requests")
        {
            ExhaustedErrorClass::RateLimited
        } else if lower.contains("500")
            || lower.contains("502")
            || lower.contains("503")
            || lower.contains("504")
            || lower.contains("529")
            || lower.contains("internal server error")
            || lower.contains("bad gateway")
            || lower.contains("service unavailable")
            || lower.contains("gateway timeout")
            || lower.contains("overloaded")
        {
            ExhaustedErrorClass::ServerError
        } else if lower.contains("connection")
            || lower.contains("timeout")
            || lower.contains("network")
            || lower.contains("reset")
        {
            ExhaustedErrorClass::NetworkError
        } else {
            ExhaustedErrorClass::Unknown
        }
    }

    /// Calculate delay for retry attempt `n` (0-based).
    pub fn delay_for_retry(&self, n: u32) -> Duration {
        let exp_delay = self.base_delay.as_millis() as f64 * 2.0_f64.powi(n as i32);
        let capped = exp_delay.min(self.max_delay.as_millis() as f64);

        // Apply jitter: uniform random in [delay * (1 - jitter), delay * (1 + jitter)]
        let jitter_range = capped * self.jitter_fraction;
        use rand::RngExt as _;
        let jittered = capped + (rand::rng().random::<f64>() * 2.0 - 1.0) * jitter_range;
        let final_ms = jittered.max(0.0) as u64;

        Duration::from_millis(final_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_retryable_429() {
        assert!(RetryPolicy::is_retryable("HTTP 429 Too Many Requests"));
        assert!(RetryPolicy::is_retryable("rate limit exceeded"));
    }

    #[test]
    fn is_retryable_503() {
        assert!(RetryPolicy::is_retryable("HTTP 503 Service Unavailable"));
        assert!(RetryPolicy::is_retryable("502 Bad Gateway"));
    }

    #[test]
    fn not_retryable_400() {
        assert!(!RetryPolicy::is_retryable("400 Bad Request: invalid model"));
    }

    #[test]
    fn not_retryable_cancelled() {
        assert!(!RetryPolicy::is_retryable("request cancelled by user"));
    }

    #[test]
    fn is_retryable_529_overloaded() {
        // Anthropic's overloaded status — must be retryable.
        assert!(RetryPolicy::is_retryable("HTTP 529 Overloaded"));
        assert!(RetryPolicy::is_retryable(
            "upstream returned status 529 overloaded"
        ));
        assert!(RetryPolicy::is_retryable("API is overloaded, try later"));
    }

    #[test]
    fn classify_529_as_server_error() {
        assert_eq!(
            RetryPolicy::classify_error("HTTP 529 Overloaded"),
            ExhaustedErrorClass::ServerError
        );
    }

    #[test]
    fn for_class_interactive_uses_default_budget() {
        let policy = RetryPolicy::for_class(QueryClass::Interactive);
        assert_eq!(policy.max_retries, 3);
    }

    #[test]
    fn for_class_background_bails_fast() {
        let policy = RetryPolicy::for_class(QueryClass::Background);
        assert_eq!(
            policy.max_retries, 1,
            "background runs must bail after a single retry to avoid \
             amplifying upstream cascades"
        );
    }

    #[tokio::test]
    async fn for_current_class_reads_task_local() {
        use encmind_core::scheduler::{QueryClass, CURRENT_QUERY_CLASS};
        // Outside any scope, defaults to Interactive → full budget.
        assert_eq!(RetryPolicy::for_current_class().max_retries, 3);

        // Inside Background scope → fast bail.
        let max = CURRENT_QUERY_CLASS
            .scope(QueryClass::Background, async {
                RetryPolicy::for_current_class().max_retries
            })
            .await;
        assert_eq!(max, 1);
    }

    #[test]
    fn delay_increases_exponentially() {
        let policy = RetryPolicy {
            jitter_fraction: 0.0, // no jitter for deterministic test
            ..Default::default()
        };
        let d0 = policy.delay_for_retry(0);
        let d1 = policy.delay_for_retry(1);
        let d2 = policy.delay_for_retry(2);
        assert_eq!(d0, Duration::from_millis(500));
        assert_eq!(d1, Duration::from_millis(1000));
        assert_eq!(d2, Duration::from_millis(2000));
    }

    #[test]
    fn delay_capped_at_max() {
        let policy = RetryPolicy {
            jitter_fraction: 0.0,
            max_delay: Duration::from_secs(2),
            ..Default::default()
        };
        let d10 = policy.delay_for_retry(10);
        assert_eq!(d10, Duration::from_secs(2));
    }

    #[tokio::test]
    async fn cancel_during_backoff_returns_promptly() {
        // The dispatcher's retry sleep uses tokio::select! with
        // cancel.cancelled(). This test verifies the pattern works
        // by timing a cancel that fires during a long backoff.
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let start = std::time::Instant::now();

        // Spawn a task that cancels after 50ms — well before the
        // 10-second sleep would normally complete.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_clone.cancel();
        });

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                panic!("sleep should have been interrupted by cancel");
            }
            _ = cancel.cancelled() => {
                // Expected path.
            }
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "cancel should interrupt within ~50ms, took {elapsed:?}"
        );
    }

    #[test]
    fn server_hint_precedence_uses_max_of_hint_and_backoff() {
        // When Retry-After is larger than computed backoff, use it.
        // When smaller, use the backoff. Both capped at max_delay.
        let policy = RetryPolicy {
            jitter_fraction: 0.0,
            max_delay: Duration::from_secs(60),
            ..Default::default()
        };
        let backoff_0 = policy.delay_for_retry(0); // 500ms
        let server_hint_5s = Duration::from_secs(5);
        let effective = server_hint_5s.max(backoff_0).min(policy.max_delay);
        assert_eq!(effective, Duration::from_secs(5), "server hint should win over 500ms backoff");

        let server_hint_0 = Duration::ZERO;
        let effective_no_hint = server_hint_0.max(backoff_0).min(policy.max_delay);
        assert_eq!(effective_no_hint, Duration::from_millis(500), "no hint should use backoff");

        // Server hint exceeding max_delay is capped.
        let server_hint_huge = Duration::from_secs(120);
        let effective_capped = server_hint_huge.max(backoff_0).min(policy.max_delay);
        assert_eq!(effective_capped, Duration::from_secs(60), "huge hint capped at max_delay");
    }
}
