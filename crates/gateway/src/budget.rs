use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Tracks approximate API spend per 24-hour rolling window.
/// Stores values in cents (hundredths of a dollar) to avoid floating-point.
pub struct ApiBudgetTracker {
    /// Budget limit in cents.
    limit_cents: u64,
    /// Accumulated spend in cents for the current period.
    spend_cents: AtomicU64,
    /// Start of the current 24h window.
    window_start: Mutex<Instant>,
}

/// Hardcoded per-token costs in micro-dollars (1e-6 USD).
/// These are rough approximations; operators can adjust budget_usd accordingly.
const INPUT_TOKEN_COST_MICRO_USD: u64 = 3; // ~$3/M input tokens
const OUTPUT_TOKEN_COST_MICRO_USD: u64 = 15; // ~$15/M output tokens

impl ApiBudgetTracker {
    /// Create a new tracker with the given budget in USD.
    pub fn new(budget_usd: f64) -> Self {
        let limit_cents = (budget_usd * 100.0).round() as u64;
        Self {
            limit_cents,
            spend_cents: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
        }
    }

    /// Record token usage and return true if still under budget.
    /// Returns false if the budget is exceeded (call should be rejected).
    pub fn record_tokens(&self, input_tokens: u64, output_tokens: u64) -> bool {
        self.maybe_reset();

        // Calculate cost in micro-dollars, then convert to cents
        let cost_micro =
            input_tokens * INPUT_TOKEN_COST_MICRO_USD + output_tokens * OUTPUT_TOKEN_COST_MICRO_USD;
        let cost_cents = cost_micro / 10_000; // 1 cent = 10_000 micro-dollars

        // Add at least 1 cent if there was any usage
        let cost_cents = if cost_cents == 0 && (input_tokens > 0 || output_tokens > 0) {
            1
        } else {
            cost_cents
        };

        self.spend_cents.fetch_add(cost_cents, Ordering::Relaxed);

        self.spend_cents.load(Ordering::Relaxed) <= self.limit_cents
    }

    /// Check if the budget has been exceeded.
    pub fn is_exceeded(&self) -> bool {
        self.maybe_reset();
        self.spend_cents.load(Ordering::Relaxed) > self.limit_cents
    }

    /// Current spend in cents.
    pub fn current_spend_cents(&self) -> u64 {
        self.spend_cents.load(Ordering::Relaxed)
    }

    /// Auto-reset after 24h.
    fn maybe_reset(&self) {
        let now = Instant::now();
        let mut start = self.window_start.lock().unwrap();
        if now.duration_since(*start) >= std::time::Duration::from_secs(86400) {
            self.spend_cents.store(0, Ordering::Relaxed);
            *start = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_budget() {
        let tracker = ApiBudgetTracker::new(1.0); // $1 = 100 cents
                                                  // Small usage should be under budget
        assert!(tracker.record_tokens(100, 50));
        assert!(!tracker.is_exceeded());
    }

    #[test]
    fn rejects_over_budget() {
        let tracker = ApiBudgetTracker::new(0.01); // $0.01 = 1 cent
                                                   // Record enough tokens to exceed 1 cent
                                                   // 10000 output tokens * 15 micro-USD = 150,000 micro-USD = 15 cents
        assert!(!tracker.record_tokens(0, 10_000));
        assert!(tracker.is_exceeded());
    }

    #[test]
    fn resets_daily() {
        let tracker = ApiBudgetTracker::new(0.01); // 1 cent
        tracker.record_tokens(0, 10_000); // exceed
        assert!(tracker.is_exceeded());

        // Simulate 24h passing
        {
            let mut start = tracker.window_start.lock().unwrap();
            *start = Instant::now() - std::time::Duration::from_secs(86401);
        }

        assert!(!tracker.is_exceeded());
    }

    #[test]
    fn disabled_when_not_configured() {
        // When budget is very large, it's effectively disabled
        let tracker = ApiBudgetTracker::new(1_000_000.0);
        for _ in 0..1000 {
            assert!(tracker.record_tokens(10_000, 5_000));
        }
        assert!(!tracker.is_exceeded());
    }
}
