//! Browser runtime guardrails — loop detection, retry policy, action timeout,
//! and metrics. All types in this module are testable without Chrome.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use encmind_core::error::AppError;

// ---------------------------------------------------------------------------
// BrowserMetrics
// ---------------------------------------------------------------------------

/// Shared atomic counters for browser runtime events.
pub struct BrowserMetrics {
    pub total_actions: AtomicU64,
    pub timeout_count: AtomicU64,
    pub retry_count: AtomicU64,
    pub loop_abort_count: AtomicU64,
    pub dialog_dismissed_count: AtomicU64,
}

impl BrowserMetrics {
    pub fn new() -> Self {
        Self {
            total_actions: AtomicU64::new(0),
            timeout_count: AtomicU64::new(0),
            retry_count: AtomicU64::new(0),
            loop_abort_count: AtomicU64::new(0),
            dialog_dismissed_count: AtomicU64::new(0),
        }
    }

    /// Take a serializable snapshot of the current counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_actions: self.total_actions.load(Ordering::Relaxed),
            timeout_count: self.timeout_count.load(Ordering::Relaxed),
            retry_count: self.retry_count.load(Ordering::Relaxed),
            loop_abort_count: self.loop_abort_count.load(Ordering::Relaxed),
            dialog_dismissed_count: self.dialog_dismissed_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for BrowserMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable snapshot of browser metrics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub total_actions: u64,
    pub timeout_count: u64,
    pub retry_count: u64,
    pub loop_abort_count: u64,
    pub dialog_dismissed_count: u64,
}

// ---------------------------------------------------------------------------
// LoopDetector
// ---------------------------------------------------------------------------

/// Fingerprint of a browser action for loop detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionFingerprint {
    pub action: String,
    pub page_url: String,
    pub selector: Option<String>,
}

/// Detects repeated identical actions within a sliding window.
pub struct LoopDetector {
    history: VecDeque<ActionFingerprint>,
    window: usize,
    threshold: usize,
}

impl LoopDetector {
    pub fn new(window: usize, threshold: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(window),
            window: window.max(1),
            threshold: threshold.max(1),
        }
    }

    /// Record an action and check for loops.
    ///
    /// Returns `Err` if the last `threshold` actions (including this one)
    /// are identical, indicating a loop.
    pub fn record_and_check(&mut self, fp: ActionFingerprint) -> Result<(), LoopAbort> {
        // Evict oldest if at capacity.
        while self.history.len() >= self.window {
            self.history.pop_front();
        }
        self.history.push_back(fp);

        // Check if the tail of the history is all identical.
        if self.history.len() >= self.threshold {
            let latest = self.history.back().unwrap();
            let tail_count = self
                .history
                .iter()
                .rev()
                .take(self.threshold)
                .filter(|f| *f == latest)
                .count();
            if tail_count >= self.threshold {
                return Err(LoopAbort {
                    action: latest.action.clone(),
                    count: tail_count,
                });
            }
        }

        Ok(())
    }

    /// Clear all recorded history.
    pub fn reset(&mut self) {
        self.history.clear();
    }
}

impl Default for LoopDetector {
    fn default() -> Self {
        Self::new(4, 3)
    }
}

/// Returned when a loop is detected.
#[derive(Debug)]
pub struct LoopAbort {
    pub action: String,
    pub count: usize,
}

// ---------------------------------------------------------------------------
// RetryPolicy
// ---------------------------------------------------------------------------

/// Actions that are safe to retry because they don't mutate page state.
/// "wait" is excluded: retrying a timed-out wait just wastes more time.
const READ_ONLY_ACTIONS: &[&str] = &["navigate", "screenshot", "get_text"];

/// Returns true if the action is safe to retry (read-only / idempotent).
pub fn is_action_retryable(action: &str) -> bool {
    READ_ONLY_ACTIONS.contains(&action)
}

/// Determines whether a browser action error is transient and retryable.
pub struct RetryPolicy;

fn is_guardrail_timeout_message(msg_lower: &str) -> bool {
    msg_lower.starts_with("navigation timed out after ")
        || msg_lower.starts_with("screenshot navigation timed out after ")
        || msg_lower.starts_with("get_text navigation timed out after ")
        || msg_lower.starts_with("page navigation timed out after ")
        || (msg_lower.starts_with("action '") && msg_lower.contains("' timed out after "))
}

impl RetryPolicy {
    /// Returns true for transient errors that may succeed on retry.
    ///
    /// Timeout errors are NOT retryable — they trigger session release (the
    /// page may be in an undefined state), so retrying on the same page is
    /// impossible. Network/CDP timeouts remain retryable.
    pub fn is_retryable(err: &AppError) -> bool {
        let msg = err.to_string().to_ascii_lowercase();
        // Policy/validation failures are never retryable.
        if msg.contains("not allowed")
            || msg.contains("not found")
            || msg.contains("firewall")
            || msg.contains("policy")
        {
            return false;
        }

        // Guardrail timeouts release the session and are not retried.
        if is_guardrail_timeout_message(&msg) {
            return false;
        }

        // Retry only transport-flavored transient failures.
        // "timed out"/"timeout" cover Chrome-level ERR_TIMED_OUT and timeout
        // exceeded variants that are NOT our guardrail timeouts (already excluded above).
        let has_transport_marker = msg.contains("connection")
            || msg.contains("cdp")
            || msg.contains("socket")
            || msg.contains("websocket")
            || msg.contains("network")
            || msg.contains("connect")
            || msg.contains("timed out")
            || msg.contains("timeout")
            || msg.contains("err_timed_out");
        if has_transport_marker {
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// GuardrailConfig
// ---------------------------------------------------------------------------

/// Runtime guardrail configuration derived from BrowserConfig.
#[derive(Debug, Clone)]
pub struct GuardrailConfig {
    pub action_timeout: Duration,
    pub page_load_timeout: Duration,
    pub max_retries: usize,
    pub loop_window: usize,
    pub loop_threshold: usize,
}

impl Default for GuardrailConfig {
    fn default() -> Self {
        Self {
            action_timeout: Duration::from_secs(10),
            page_load_timeout: Duration::from_secs(30),
            max_retries: 2,
            loop_window: 4,
            loop_threshold: 3,
        }
    }
}

impl GuardrailConfig {
    /// Build from a `BrowserConfig`.
    pub fn from_browser_config(config: &encmind_core::config::BrowserConfig) -> Self {
        Self {
            action_timeout: Duration::from_secs(config.action_timeout_secs),
            page_load_timeout: Duration::from_secs(config.page_load_timeout_secs),
            max_retries: config.max_action_retries,
            loop_window: config.loop_detection_window,
            loop_threshold: config.loop_detection_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- LoopDetector tests --

    #[test]
    fn loop_detector_no_abort_below_threshold() {
        let mut ld = LoopDetector::new(4, 3);
        let fp = ActionFingerprint {
            action: "click".into(),
            page_url: "https://example.com".into(),
            selector: Some("#btn".into()),
        };
        assert!(ld.record_and_check(fp.clone()).is_ok());
        assert!(ld.record_and_check(fp).is_ok());
    }

    #[test]
    fn loop_detector_aborts_at_threshold() {
        let mut ld = LoopDetector::new(4, 3);
        let fp = ActionFingerprint {
            action: "click".into(),
            page_url: "https://example.com".into(),
            selector: Some("#btn".into()),
        };
        assert!(ld.record_and_check(fp.clone()).is_ok());
        assert!(ld.record_and_check(fp.clone()).is_ok());
        let err = ld.record_and_check(fp).unwrap_err();
        assert_eq!(err.action, "click");
        assert_eq!(err.count, 3);
    }

    #[test]
    fn loop_detector_different_actions_no_abort() {
        let mut ld = LoopDetector::new(4, 3);
        for i in 0..10 {
            let fp = ActionFingerprint {
                action: format!("action_{}", i % 2),
                page_url: "https://example.com".into(),
                selector: None,
            };
            assert!(ld.record_and_check(fp).is_ok());
        }
    }

    #[test]
    fn loop_detector_selector_none_vs_some_distinct() {
        let mut ld = LoopDetector::new(4, 3);
        let base = ActionFingerprint {
            action: "click".into(),
            page_url: "https://example.com".into(),
            selector: None,
        };
        let with_sel = ActionFingerprint {
            selector: Some("#btn".into()),
            ..base.clone()
        };
        assert!(ld.record_and_check(base.clone()).is_ok());
        assert!(ld.record_and_check(with_sel).is_ok());
        assert!(ld.record_and_check(base).is_ok()); // not 3 identical
    }

    #[test]
    fn loop_detector_respects_capacity_window() {
        // Window=3, threshold=3: fill with 2 "click", then a different action,
        // then 2 more "click" — should not trigger because the window evicts old entries.
        let mut ld = LoopDetector::new(3, 3);
        let click = ActionFingerprint {
            action: "click".into(),
            page_url: "https://a.com".into(),
            selector: None,
        };
        let other = ActionFingerprint {
            action: "type".into(),
            page_url: "https://a.com".into(),
            selector: None,
        };
        assert!(ld.record_and_check(click.clone()).is_ok());
        assert!(ld.record_and_check(click.clone()).is_ok());
        assert!(ld.record_and_check(other).is_ok()); // breaks the run
        assert!(ld.record_and_check(click.clone()).is_ok());
        assert!(ld.record_and_check(click).is_ok()); // only 2 identical in window
    }

    #[test]
    fn loop_detector_reset_clears_history() {
        let mut ld = LoopDetector::new(4, 3);
        let fp = ActionFingerprint {
            action: "click".into(),
            page_url: "https://a.com".into(),
            selector: None,
        };
        assert!(ld.record_and_check(fp.clone()).is_ok());
        assert!(ld.record_and_check(fp.clone()).is_ok());
        ld.reset();
        // After reset, previous history is gone.
        assert!(ld.record_and_check(fp.clone()).is_ok());
        assert!(ld.record_and_check(fp.clone()).is_ok());
        // Now third triggers abort.
        assert!(ld.record_and_check(fp).is_err());
    }

    // -- Action retryability tests --

    #[test]
    fn read_only_actions_are_retryable() {
        assert!(is_action_retryable("navigate"));
        assert!(is_action_retryable("screenshot"));
        assert!(is_action_retryable("get_text"));
    }

    #[test]
    fn non_retryable_actions() {
        // Mutating actions — retry could duplicate side effects
        assert!(!is_action_retryable("click"));
        assert!(!is_action_retryable("type"));
        assert!(!is_action_retryable("press"));
        assert!(!is_action_retryable("select"));
        assert!(!is_action_retryable("upload"));
        assert!(!is_action_retryable("eval"));
        assert!(!is_action_retryable("close"));
        // Wait — retrying a timed-out wait just wastes more time
        assert!(!is_action_retryable("wait"));
    }

    #[test]
    fn retry_gated_by_action_and_error_class() {
        // A transient error on a read-only action: retryable.
        let timeout_err = AppError::Internal("CDP connection reset".into());
        assert!(
            is_action_retryable("screenshot") && RetryPolicy::is_retryable(&timeout_err),
            "read-only + transient should be retryable"
        );

        // A transient error on a mutating action: NOT retryable.
        assert!(
            !is_action_retryable("click") || !RetryPolicy::is_retryable(&timeout_err),
            "mutating action must not be retried even on transient error"
        );

        // A non-transient error on a read-only action: NOT retryable.
        let validation_err = AppError::Internal("element not found: #btn".into());
        assert!(
            !RetryPolicy::is_retryable(&validation_err),
            "non-transient error should not be retried"
        );
    }

    // -- RetryPolicy tests --

    #[test]
    fn retry_policy_timeout_not_retryable() {
        // Timeouts release the session — retrying on a tainted page is unsafe.
        let err = AppError::Internal("action 'click' timed out after 10s".into());
        assert!(!RetryPolicy::is_retryable(&err));

        let err2 = AppError::Internal("page navigation timed out after 30s".into());
        assert!(!RetryPolicy::is_retryable(&err2));
    }

    #[test]
    fn retry_policy_connection_is_retryable() {
        let err = AppError::Internal("CDP connection reset".into());
        assert!(RetryPolicy::is_retryable(&err));
    }

    #[test]
    fn retry_policy_element_not_found_not_retryable() {
        let err = AppError::Internal("element not found: #btn".into());
        assert!(!RetryPolicy::is_retryable(&err));
    }

    #[test]
    fn retry_policy_firewall_not_retryable() {
        let err = AppError::Internal("egress firewall blocked connection to api.com".into());
        assert!(!RetryPolicy::is_retryable(&err));
    }

    #[test]
    fn retry_policy_action_not_allowed_not_retryable() {
        let err = AppError::Internal("action 'eval' is not allowed by policy".into());
        assert!(!RetryPolicy::is_retryable(&err));
    }

    #[test]
    fn timeout_errors_are_terminal_not_retried() {
        // Timeout errors trigger session release in the handler. They must NOT
        // be classified as retryable, otherwise the retry loop would attempt to
        // reuse a released/tainted session.
        let nav_timeout = AppError::Internal("page navigation timed out after 30s".into());
        let action_timeout = AppError::Internal("action 'get_text' timed out after 10s".into());
        assert!(
            !RetryPolicy::is_retryable(&nav_timeout),
            "navigation timeout must not be retried"
        );
        assert!(
            !RetryPolicy::is_retryable(&action_timeout),
            "action timeout must not be retried"
        );

        // But CDP connection errors (no session release) ARE retryable.
        let cdp_err = AppError::Internal("CDP connection reset".into());
        assert!(
            RetryPolicy::is_retryable(&cdp_err),
            "CDP connection error should be retried"
        );
    }

    #[test]
    fn transport_timeout_is_retryable_but_guardrail_timeout_is_not() {
        let transport_timeout =
            AppError::Internal("websocket connection timed out while reading frame".into());
        assert!(
            RetryPolicy::is_retryable(&transport_timeout),
            "transport timeout should be retried"
        );

        // Chrome-style ERR_TIMED_OUT is a transport timeout, not our guardrail.
        let chrome_timeout = AppError::Internal(
            "navigation failed: ERR_TIMED_OUT at https://slow.example.com".into(),
        );
        assert!(
            RetryPolicy::is_retryable(&chrome_timeout),
            "Chrome ERR_TIMED_OUT should be retried"
        );

        // Some stacks use "timeout exceeded" wording without "timed out".
        let timeout_exceeded =
            AppError::Internal("navigation failed: timeout exceeded while loading page".into());
        assert!(
            RetryPolicy::is_retryable(&timeout_exceeded),
            "transport timeout exceeded should be retried"
        );

        let guardrail_timeout = AppError::Internal("action 'click' timed out after 10s".into());
        assert!(
            !RetryPolicy::is_retryable(&guardrail_timeout),
            "guardrail timeout should not be retried"
        );
    }

    // -- BrowserMetrics tests --

    #[test]
    fn metrics_snapshot_defaults_to_zero() {
        let m = BrowserMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.total_actions, 0);
        assert_eq!(s.timeout_count, 0);
        assert_eq!(s.retry_count, 0);
        assert_eq!(s.loop_abort_count, 0);
        assert_eq!(s.dialog_dismissed_count, 0);
    }

    #[test]
    fn metrics_increment_and_snapshot() {
        let m = BrowserMetrics::new();
        m.total_actions.fetch_add(5, Ordering::Relaxed);
        m.timeout_count.fetch_add(2, Ordering::Relaxed);
        m.retry_count.fetch_add(3, Ordering::Relaxed);
        m.loop_abort_count.fetch_add(1, Ordering::Relaxed);
        m.dialog_dismissed_count.fetch_add(4, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.total_actions, 5);
        assert_eq!(s.timeout_count, 2);
        assert_eq!(s.retry_count, 3);
        assert_eq!(s.loop_abort_count, 1);
        assert_eq!(s.dialog_dismissed_count, 4);
    }

    // -- GuardrailConfig tests --

    #[test]
    fn guardrail_config_defaults() {
        let gc = GuardrailConfig::default();
        assert_eq!(gc.action_timeout, Duration::from_secs(10));
        assert_eq!(gc.page_load_timeout, Duration::from_secs(30));
        assert_eq!(gc.max_retries, 2);
        assert_eq!(gc.loop_window, 4);
        assert_eq!(gc.loop_threshold, 3);
    }
}
