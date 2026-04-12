//! Generic circuit breaker for protecting against cascading failures.
//!
//! Three states:
//! - **Closed** — normal operation; failures increment a counter.
//! - **Open** — circuit tripped; all calls rejected until reset timeout.
//! - **HalfOpen** — after reset timeout expires, one probe call is
//!   allowed. Success → Closed; Failure → Open (with fresh timeout).
//!
//! Thread-safe: all state is behind a `Mutex` so the breaker can be
//! shared across async tasks via `Arc<CircuitBreaker>`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for a circuit breaker instance.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures before the circuit opens.
    pub failure_threshold: u32,
    /// How long the circuit stays open before allowing a probe.
    pub reset_timeout: Duration,
    /// Optional name for logging. Not used internally — callers use
    /// it when logging state transitions.
    pub name: String,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(60),
            name: "unnamed".to_string(),
        }
    }
}

/// The current state of the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

struct Inner {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure_at: Option<Instant>,
    failure_threshold: u32,
    reset_timeout: Duration,
}

/// A thread-safe circuit breaker.
pub struct CircuitBreaker {
    inner: Mutex<Inner>,
    name: String,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                last_failure_at: None,
                failure_threshold: config.failure_threshold,
                reset_timeout: config.reset_timeout,
            }),
            name: config.name,
        }
    }

    /// Check whether a call is permitted right now.
    ///
    /// - `Closed` → always permitted
    /// - `Open` → permitted only if the reset timeout has expired
    ///   (transitions to `HalfOpen`)
    /// - `HalfOpen` → NOT permitted (one probe is already in flight)
    pub fn is_call_permitted(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last) = inner.last_failure_at {
                    if last.elapsed() >= inner.reset_timeout {
                        inner.state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    // No recorded failure time — shouldn't happen, but
                    // fail-open to avoid permanent lockout.
                    inner.state = CircuitState::Closed;
                    inner.consecutive_failures = 0;
                    true
                }
            }
            // Only one probe allowed in HalfOpen. Additional callers
            // must wait until the probe completes.
            CircuitState::HalfOpen => false,
        }
    }

    /// Record a successful call. Resets the failure counter and
    /// transitions HalfOpen → Closed.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.consecutive_failures = 0;
        inner.state = CircuitState::Closed;
    }

    /// Record a failed call. Increments the failure counter and
    /// opens the circuit when the threshold is reached.
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.consecutive_failures += 1;
        inner.last_failure_at = Some(Instant::now());
        if inner.consecutive_failures >= inner.failure_threshold {
            inner.state = CircuitState::Open;
        }
    }

    /// Current state (for logging/metrics).
    pub fn state(&self) -> CircuitState {
        self.inner.lock().unwrap().state
    }

    /// Current consecutive failure count (for logging/metrics).
    pub fn consecutive_failures(&self) -> u32 {
        self.inner.lock().unwrap().consecutive_failures
    }

    /// The name assigned at construction (for logging).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The configured reset timeout (for deriving sleep durations).
    pub fn reset_timeout(&self) -> Duration {
        self.inner.lock().unwrap().reset_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breaker(threshold: u32, reset_ms: u64) -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: threshold,
            reset_timeout: Duration::from_millis(reset_ms),
            name: "test".into(),
        })
    }

    #[test]
    fn starts_closed_and_permits_calls() {
        let cb = breaker(3, 1000);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_call_permitted());
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = breaker(3, 1000);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_call_permitted());

        cb.record_failure(); // 3rd = threshold
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_call_permitted());
    }

    #[test]
    fn success_resets_failure_counter() {
        let cb = breaker(3, 1000);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.consecutive_failures(), 0);
        assert_eq!(cb.state(), CircuitState::Closed);

        // Need 3 fresh failures to open again.
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn transitions_to_half_open_after_reset_timeout() {
        let cb = breaker(2, 10); // 10ms reset
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_call_permitted());

        std::thread::sleep(Duration::from_millis(20));
        // After timeout, is_call_permitted transitions to HalfOpen.
        assert!(cb.is_call_permitted());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Second caller during HalfOpen is blocked.
        assert!(!cb.is_call_permitted());
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let cb = breaker(2, 10);
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(20));
        assert!(cb.is_call_permitted()); // → HalfOpen

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_call_permitted());
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let cb = breaker(2, 10);
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(20));
        assert!(cb.is_call_permitted()); // → HalfOpen

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_call_permitted());
    }

    #[test]
    fn reset_timeout_returns_configured_value() {
        let cb = breaker(3, 5000);
        assert_eq!(cb.reset_timeout(), Duration::from_millis(5000));
    }
}
