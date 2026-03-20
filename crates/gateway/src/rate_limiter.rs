use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Sliding-window per-session rate limiter.
pub struct SessionRateLimiter {
    window_secs: u64,
    max_messages: u32,
    sessions: Mutex<HashMap<String, Vec<Instant>>>,
}

impl SessionRateLimiter {
    pub fn new(messages_per_minute: u32) -> Self {
        Self {
            window_secs: 60,
            max_messages: messages_per_minute,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Check rate limit and record the request if allowed.
    /// Returns `Ok(())` if allowed, or `Err(retry_after_secs)` if rate-limited.
    pub fn check_and_record(&self, session_id: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let timestamps = sessions.entry(session_id.to_string()).or_default();

        // Prune expired entries
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_messages as usize {
            // Calculate retry-after from the oldest entry in the window
            let oldest = timestamps.first().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest).as_secs();
            let retry_after = self.window_secs.saturating_sub(elapsed).max(1);
            return Err(retry_after);
        }

        timestamps.push(now);
        Ok(())
    }

    /// Remove stale sessions (no activity for 2x the window).
    pub fn cleanup(&self) {
        let now = Instant::now();
        let stale_threshold = std::time::Duration::from_secs(self.window_secs * 2);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, timestamps| {
            if let Some(last) = timestamps.last() {
                now.duration_since(*last) < stale_threshold
            } else {
                false
            }
        });
    }

    /// Number of sessions currently tracked.
    pub fn active_session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let limiter = SessionRateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.check_and_record("sess1").is_ok());
        }
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = SessionRateLimiter::new(3);
        for _ in 0..3 {
            assert!(limiter.check_and_record("sess1").is_ok());
        }
        let err = limiter.check_and_record("sess1");
        assert!(err.is_err());
        let retry_after = err.unwrap_err();
        assert!(retry_after > 0);
    }

    #[test]
    fn per_session_isolation() {
        let limiter = SessionRateLimiter::new(2);
        assert!(limiter.check_and_record("a").is_ok());
        assert!(limiter.check_and_record("a").is_ok());
        assert!(limiter.check_and_record("a").is_err());
        // Different session should be independent
        assert!(limiter.check_and_record("b").is_ok());
        assert!(limiter.check_and_record("b").is_ok());
        assert!(limiter.check_and_record("b").is_err());
    }

    #[test]
    fn window_expires() {
        // Use a limiter with 1 message per minute window
        let limiter = SessionRateLimiter::new(1);
        assert!(limiter.check_and_record("sess").is_ok());
        assert!(limiter.check_and_record("sess").is_err());

        // Manually expire the entry by modifying the internal state
        {
            let mut sessions = limiter.sessions.lock().unwrap();
            let timestamps = sessions.get_mut("sess").unwrap();
            // Set the timestamp to 61 seconds ago
            timestamps[0] = Instant::now() - std::time::Duration::from_secs(61);
        }

        // Now it should be allowed again
        assert!(limiter.check_and_record("sess").is_ok());
    }

    #[test]
    fn cleanup_removes_stale() {
        let limiter = SessionRateLimiter::new(10);
        assert!(limiter.check_and_record("active").is_ok());
        assert!(limiter.check_and_record("stale").is_ok());

        // Make "stale" session old
        {
            let mut sessions = limiter.sessions.lock().unwrap();
            let timestamps = sessions.get_mut("stale").unwrap();
            timestamps[0] = Instant::now() - std::time::Duration::from_secs(300);
        }

        assert_eq!(limiter.active_session_count(), 2);
        limiter.cleanup();
        assert_eq!(limiter.active_session_count(), 1);
    }
}
