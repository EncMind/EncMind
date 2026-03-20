use std::time::{Duration, Instant};

/// Health state for a single LLM provider.
#[derive(Debug)]
pub struct ProviderHealth {
    pub name: String,
    pub healthy: bool,
    pub consecutive_failures: u32,
    pub cooldown_until: Option<Instant>,
}

/// Tracks health across multiple LLM providers for failover.
///
/// Providers are tried in config order. After 3 consecutive failures a
/// provider enters cooldown with exponential backoff (5 min base, 1 hour
/// max). Success resets the counter immediately.
pub struct ProviderHealthTracker {
    providers: Vec<ProviderHealth>,
    base_cooldown: Duration,
    max_cooldown: Duration,
    failure_threshold: u32,
}

impl ProviderHealthTracker {
    pub fn new(provider_names: Vec<String>) -> Self {
        let providers = provider_names
            .into_iter()
            .map(|name| ProviderHealth {
                name,
                healthy: true,
                consecutive_failures: 0,
                cooldown_until: None,
            })
            .collect();

        Self {
            providers,
            base_cooldown: Duration::from_secs(5 * 60),
            max_cooldown: Duration::from_secs(60 * 60),
            failure_threshold: 3,
        }
    }

    /// Index of the next healthy provider (in config order).
    ///
    /// A provider is considered available if it is healthy *or* its cooldown
    /// period has elapsed.
    pub fn next_healthy(&self) -> Option<usize> {
        let now = Instant::now();
        for (i, p) in self.providers.iter().enumerate() {
            if p.healthy {
                return Some(i);
            }
            if let Some(until) = p.cooldown_until {
                if now >= until {
                    return Some(i);
                }
            }
        }
        None
    }

    /// All currently-available providers in priority order.
    pub fn healthy_indices(&self) -> Vec<usize> {
        let now = Instant::now();
        self.providers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                if p.healthy || p.cooldown_until.is_some_and(|until| now >= until) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Record a successful call — resets failure count and marks healthy.
    pub fn report_success(&mut self, index: usize) {
        if let Some(p) = self.providers.get_mut(index) {
            p.healthy = true;
            p.consecutive_failures = 0;
            p.cooldown_until = None;
        }
    }

    /// Record a failed call — increments failure count, enters cooldown
    /// after threshold.
    pub fn report_failure(&mut self, index: usize) {
        if let Some(p) = self.providers.get_mut(index) {
            p.consecutive_failures += 1;
            if p.consecutive_failures >= self.failure_threshold {
                p.healthy = false;
                let exponent = p.consecutive_failures - self.failure_threshold;
                let backoff = self.base_cooldown * 2u32.saturating_pow(exponent);
                let cooldown = backoff.min(self.max_cooldown);
                p.cooldown_until = Some(Instant::now() + cooldown);
            }
        }
    }

    /// True when every provider is unhealthy and in cooldown.
    pub fn all_unhealthy(&self) -> bool {
        self.next_healthy().is_none()
    }

    pub fn provider_name(&self, index: usize) -> Option<&str> {
        self.providers.get(index).map(|p| p.name.as_str())
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initially_all_healthy() {
        let tracker = ProviderHealthTracker::new(vec!["a".into(), "b".into()]);
        assert_eq!(tracker.next_healthy(), Some(0));
        assert!(!tracker.all_unhealthy());
    }

    #[test]
    fn success_resets_failure_count() {
        let mut tracker = ProviderHealthTracker::new(vec!["a".into()]);
        tracker.report_failure(0);
        tracker.report_failure(0);
        tracker.report_success(0);
        assert_eq!(tracker.providers[0].consecutive_failures, 0);
        assert!(tracker.providers[0].healthy);
    }

    #[test]
    fn enters_cooldown_after_threshold() {
        let mut tracker = ProviderHealthTracker::new(vec!["a".into(), "b".into()]);
        tracker.report_failure(0);
        tracker.report_failure(0);
        assert!(tracker.providers[0].healthy); // not yet
        tracker.report_failure(0);
        assert!(!tracker.providers[0].healthy);
        assert!(tracker.providers[0].cooldown_until.is_some());
        // Second provider should be next
        assert_eq!(tracker.next_healthy(), Some(1));
    }

    #[test]
    fn all_unhealthy_when_all_in_cooldown() {
        let mut tracker = ProviderHealthTracker::new(vec!["a".into()]);
        for _ in 0..3 {
            tracker.report_failure(0);
        }
        assert!(tracker.all_unhealthy());
    }

    #[test]
    fn cooldown_expires() {
        let mut tracker = ProviderHealthTracker::new(vec!["a".into()]);
        for _ in 0..3 {
            tracker.report_failure(0);
        }
        // Manually set cooldown to the past
        tracker.providers[0].cooldown_until = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(tracker.next_healthy(), Some(0));
    }

    #[test]
    fn failover_order() {
        let mut tracker = ProviderHealthTracker::new(vec![
            "primary".into(),
            "secondary".into(),
            "tertiary".into(),
        ]);
        // Kill primary
        for _ in 0..3 {
            tracker.report_failure(0);
        }
        assert_eq!(tracker.next_healthy(), Some(1));
        // Kill secondary
        for _ in 0..3 {
            tracker.report_failure(1);
        }
        assert_eq!(tracker.next_healthy(), Some(2));
    }

    #[test]
    fn provider_name_lookup() {
        let tracker = ProviderHealthTracker::new(vec!["anthropic".into()]);
        assert_eq!(tracker.provider_name(0), Some("anthropic"));
        assert_eq!(tracker.provider_name(99), None);
    }

    #[test]
    fn empty_tracker() {
        let tracker = ProviderHealthTracker::new(vec![]);
        assert!(tracker.is_empty());
        assert!(tracker.all_unhealthy());
        assert_eq!(tracker.next_healthy(), None);
    }
}
