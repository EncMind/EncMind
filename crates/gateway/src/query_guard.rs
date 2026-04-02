//! Per-session query guard that serializes concurrent `chat.send` calls.
//!
//! Instead of rejecting concurrent sends with ERR_RATE_LIMITED, the guard
//! queues them in FIFO order. Different sessions process independently.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Registry of per-session query guards.
///
/// Each session gets its own semaphore (permits=1) that serializes concurrent
/// `chat.send` calls. Different sessions are fully independent.
pub struct QueryGuardRegistry {
    guards: Mutex<HashMap<String, Arc<SessionGuard>>>,
    /// Maximum total requests per session (1 active + N-1 queued).
    /// For example, `max_total=5` means 1 executing + up to 4 waiting.
    max_total: usize,
}

struct SessionGuard {
    /// Semaphore with 1 permit — only one chat.send executes at a time.
    semaphore: Arc<Semaphore>,
    /// Total number of requests associated with this session (1 active + N queued).
    total_count: AtomicUsize,
}

/// RAII guard that decrements `total_count` on drop.
///
/// Held from increment through permit acquisition and execution. If the future
/// is cancelled while waiting for the semaphore, Drop ensures the counter is
/// decremented. Map cleanup is deferred to the next acquire() call (lazy
/// eviction) to avoid races between drop and concurrent acquire.
struct WaiterGuard {
    guard: Arc<SessionGuard>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        // Unconditional decrement. No map cleanup here — that's done lazily
        // in acquire() to avoid the race where drop removes an entry while
        // a concurrent acquire is about to use it.
        self.guard.total_count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// RAII permit returned by [`QueryGuardRegistry::acquire`].
///
/// Holds the semaphore permit (serializing execution) and the cancellation
/// token for this run. On drop, releases the permit (next queued request
/// proceeds), removes the cancel token from `active_runs`, and decrements
/// the session's total count via WaiterGuard.
pub struct QueryPermit {
    // Drop order: _waiter decrements total_count BEFORE _permit releases
    // the semaphore. This prevents a window where a new acquire sees stale
    // total_count and falsely rejects.
    _waiter: WaiterGuard,
    _permit: OwnedSemaphorePermit,
    cancel_token: CancellationToken,
    active_runs: Arc<std::sync::Mutex<HashMap<String, CancellationToken>>>,
    session_key: String,
}

impl Drop for QueryPermit {
    fn drop(&mut self) {
        // Remove cancel token from active_runs.
        let mut runs = self.active_runs.lock().unwrap();
        runs.remove(&self.session_key);
        // _waiter and _permit drop after this, decrementing count and releasing semaphore.
    }
}

impl QueryPermit {
    /// Get a reference to this run's cancellation token.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }
}

impl QueryGuardRegistry {
    /// Create a new registry.
    ///
    /// `max_total` limits the total number of requests per session (1 active +
    /// N-1 queued). Set to 0 for unlimited (not recommended).
    pub fn new(max_total: usize) -> Self {
        Self {
            guards: Mutex::new(HashMap::new()),
            max_total,
        }
    }

    /// Acquire a permit for the given session.
    ///
    /// If another `chat.send` is running on this session, this call waits
    /// until it completes (FIFO order). Different sessions proceed independently.
    ///
    /// Returns `None` if the total depth for this session is exceeded.
    pub async fn acquire(
        self: &Arc<Self>,
        session_key: &str,
        active_runs: Arc<std::sync::Mutex<HashMap<String, CancellationToken>>>,
    ) -> Option<QueryPermit> {
        // Hold the map lock while getting/creating the guard AND incrementing
        // total_count. This prevents the race where WaiterGuard::drop decrements
        // to 0 and a subsequent acquire creates a new guard for the same session
        // while the old guard's semaphore is still held.
        let guard = {
            let mut guards = self.guards.lock().await;

            // Lazy cleanup: remove stale entries with zero count, but NOT the
            // session we're about to acquire (it may transiently be 0 between
            // a prior drop and our increment).
            let key = session_key.to_owned();
            guards.retain(|k, g| k == &key || g.total_count.load(Ordering::SeqCst) > 0);

            let guard = guards
                .entry(session_key.to_owned())
                .or_insert_with(|| {
                    Arc::new(SessionGuard {
                        semaphore: Arc::new(Semaphore::new(1)),
                        total_count: AtomicUsize::new(0),
                    })
                })
                .clone();

            // Increment while holding map lock — no window for race.
            let current = guard.total_count.fetch_add(1, Ordering::SeqCst);
            if self.max_total > 0 && current >= self.max_total {
                guard.total_count.fetch_sub(1, Ordering::SeqCst);
                return None;
            }

            guard
            // Map lock released here.
        };

        // WaiterGuard created immediately after increment. If the future is
        // cancelled while awaiting the semaphore, WaiterGuard::drop decrements.
        let waiter = WaiterGuard {
            guard: Arc::clone(&guard),
        };

        // Wait for our turn (FIFO — tokio Semaphore is fair).
        let permit = guard
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed unexpectedly");

        // Register cancellation token in active_runs.
        let cancel_token = CancellationToken::new();
        {
            let mut runs = active_runs.lock().unwrap();
            runs.insert(session_key.to_owned(), cancel_token.clone());
        }

        Some(QueryPermit {
            _permit: permit,
            _waiter: waiter,
            cancel_token,
            active_runs,
            session_key: session_key.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_active_runs() -> Arc<std::sync::Mutex<HashMap<String, CancellationToken>>> {
        Arc::new(std::sync::Mutex::new(HashMap::new()))
    }

    #[tokio::test]
    async fn single_session_serializes() {
        let registry = Arc::new(QueryGuardRegistry::new(10));
        let active_runs = make_active_runs();
        let counter = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for _ in 0..5 {
            let reg = Arc::clone(&registry);
            let ar = Arc::clone(&active_runs);
            let ctr = Arc::clone(&counter);
            let max = Arc::clone(&max_concurrent);
            handles.push(tokio::spawn(async move {
                let permit = reg.acquire("session-1", ar).await.unwrap();
                let current = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                ctr.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(max_concurrent.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_sessions_parallel() {
        let registry = Arc::new(QueryGuardRegistry::new(10));
        let active_runs = make_active_runs();
        let counter = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for i in 0..5 {
            let reg = Arc::clone(&registry);
            let ar = Arc::clone(&active_runs);
            let ctr = Arc::clone(&counter);
            let max = Arc::clone(&max_concurrent);
            let session = format!("session-{i}");
            handles.push(tokio::spawn(async move {
                let permit = reg.acquire(&session, ar).await.unwrap();
                let current = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                ctr.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert!(
            max_concurrent.load(Ordering::SeqCst) > 1,
            "different sessions should run in parallel"
        );
    }

    #[tokio::test]
    async fn depth_exceeded_returns_none() {
        // max_total=2 means 1 active + 1 queued.
        let registry = Arc::new(QueryGuardRegistry::new(2));
        let active_runs = make_active_runs();

        let _p1 = registry
            .acquire("session-1", Arc::clone(&active_runs))
            .await
            .unwrap();

        let reg2 = Arc::clone(&registry);
        let ar2 = Arc::clone(&active_runs);
        let handle = tokio::spawn(async move { reg2.acquire("session-1", ar2).await });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = registry
            .acquire("session-1", Arc::clone(&active_runs))
            .await;
        assert!(result.is_none(), "should reject when depth exceeded");

        drop(_p1);
        let p2 = handle.await.unwrap();
        assert!(p2.is_some());
    }

    #[tokio::test]
    async fn cancel_token_registered_and_cleaned() {
        let registry = Arc::new(QueryGuardRegistry::new(10));
        let active_runs = make_active_runs();

        let permit = registry
            .acquire("session-1", Arc::clone(&active_runs))
            .await
            .unwrap();

        assert!(active_runs.lock().unwrap().contains_key("session-1"));

        drop(permit);

        assert!(!active_runs.lock().unwrap().contains_key("session-1"));
    }

    #[tokio::test]
    async fn stale_guard_cleaned_on_next_acquire() {
        let registry = Arc::new(QueryGuardRegistry::new(10));
        let active_runs = make_active_runs();

        // Acquire and release — leaves entry with count 0.
        {
            let _permit = registry
                .acquire("session-1", Arc::clone(&active_runs))
                .await
                .unwrap();
        }

        // Next acquire on any session triggers lazy cleanup.
        let _permit = registry
            .acquire("session-2", Arc::clone(&active_runs))
            .await
            .unwrap();

        let guards = registry.guards.lock().await;
        assert!(
            !guards.contains_key("session-1"),
            "stale session-1 guard should be cleaned up by lazy eviction"
        );
        assert!(guards.contains_key("session-2"));
    }

    #[tokio::test]
    async fn cancelled_future_does_not_leak_count() {
        let registry = Arc::new(QueryGuardRegistry::new(10));
        let active_runs = make_active_runs();

        let _p1 = registry
            .acquire("session-1", Arc::clone(&active_runs))
            .await
            .unwrap();

        let reg2 = Arc::clone(&registry);
        let ar2 = Arc::clone(&active_runs);
        let handle = tokio::spawn(async move { reg2.acquire("session-1", ar2).await });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Abort the waiting task (simulates client disconnect).
        handle.abort();
        let _ = handle.await;

        drop(_p1);

        // Counter should be back to 0 — no leak.
        let p3 = registry
            .acquire("session-1", Arc::clone(&active_runs))
            .await;
        assert!(p3.is_some(), "should succeed — no leaked count");
    }

    #[tokio::test]
    async fn no_parallel_execution_after_guard_recreate() {
        // Regression test for the race: drop removes guard, concurrent acquire
        // creates new guard with fresh semaphore → parallel execution.
        // Use unlimited depth so all 20 tasks can queue.
        let registry = Arc::new(QueryGuardRegistry::new(0));
        let active_runs = make_active_runs();
        let counter = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for _ in 0..20 {
            let reg = Arc::clone(&registry);
            let ar = Arc::clone(&active_runs);
            let ctr = Arc::clone(&counter);
            let max = Arc::clone(&max_concurrent);
            handles.push(tokio::spawn(async move {
                let permit = reg.acquire("session-1", ar).await.unwrap();
                let current = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
                ctr.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            1,
            "must never have parallel execution on same session"
        );
    }
}
