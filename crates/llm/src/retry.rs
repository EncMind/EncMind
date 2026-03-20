use std::time::Duration;

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
        // Retryable: server errors
        if lower.contains("500")
            || lower.contains("502")
            || lower.contains("503")
            || lower.contains("504")
        {
            return true;
        }
        if lower.contains("internal server error")
            || lower.contains("bad gateway")
            || lower.contains("service unavailable")
            || lower.contains("gateway timeout")
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
            || lower.contains("internal server error")
            || lower.contains("bad gateway")
            || lower.contains("service unavailable")
            || lower.contains("gateway timeout")
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
}
