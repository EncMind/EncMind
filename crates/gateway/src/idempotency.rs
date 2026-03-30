use std::collections::HashMap;
use std::time::{Duration, Instant};

/// In-memory cache for idempotency key deduplication.
/// Stores request results keyed by request ID with a TTL.
pub struct IdempotencyCache {
    entries: HashMap<String, CacheEntry>,
    ttl: Duration,
}

struct CacheEntry {
    result: serde_json::Value,
    inserted_at: Instant,
}

impl IdempotencyCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get a cached result for the given request ID.
    pub fn get(&self, id: &str) -> Option<&serde_json::Value> {
        self.entries.get(id).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.ttl {
                Some(&entry.result)
            } else {
                None
            }
        })
    }

    /// Store a result for the given request ID.
    pub fn set(&mut self, id: String, result: serde_json::Value) {
        self.entries.insert(
            id,
            CacheEntry {
                result,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Remove expired entries.
    pub fn cleanup(&mut self) {
        self.entries
            .retain(|_, entry| entry.inserted_at.elapsed() < self.ttl);
    }

    /// Drop all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_missing() {
        let cache = IdempotencyCache::new(300);
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn set_and_get() {
        let mut cache = IdempotencyCache::new(300);
        cache.set("req-1".into(), serde_json::json!({"ok": true}));
        let result = cache.get("req-1").unwrap();
        assert_eq!(result["ok"], true);
    }

    #[test]
    fn expired_entries_return_none() {
        let mut cache = IdempotencyCache::new(0);
        cache.set("req-1".into(), serde_json::json!({"ok": true}));
        // TTL is 0 seconds, so it's immediately expired
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("req-1").is_none());
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut cache = IdempotencyCache::new(0);
        cache.set("req-1".into(), serde_json::json!({"ok": true}));
        std::thread::sleep(Duration::from_millis(10));
        cache.cleanup();
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn cleanup_keeps_fresh() {
        let mut cache = IdempotencyCache::new(300);
        cache.set("req-1".into(), serde_json::json!({"ok": true}));
        cache.cleanup();
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut cache = IdempotencyCache::new(300);
        cache.set("req-1".into(), serde_json::json!({"ok": true}));
        cache.set("req-2".into(), serde_json::json!({"ok": false}));
        cache.clear();
        assert!(cache.entries.is_empty());
    }
}
