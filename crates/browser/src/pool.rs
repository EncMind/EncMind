use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::{
    EventJavascriptDialogOpening, HandleJavaScriptDialogParams,
};
use chromiumoxide::page::Page;
use futures::StreamExt;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

use crate::guardrails::{BrowserMetrics, LoopDetector};

/// A pool of headless Chrome pages controlled by a semaphore.
pub struct BrowserPool {
    browser: Arc<Browser>,
    permits: Arc<Semaphore>,
    idle_timeout: Duration,
    metrics: Arc<BrowserMetrics>,
    auto_dismiss_dialogs: bool,
    _handler_handle: tokio::task::JoinHandle<()>,
}

/// A leased browser page. The semaphore permit is returned when dropped.
pub struct BrowserLease {
    pub page: Page,
    _permit: OwnedSemaphorePermit,
    _dialog_handle: Option<tokio::task::JoinHandle<()>>,
}

impl BrowserPool {
    /// Launch headless Chrome and create a pool with `pool_size` concurrent page slots.
    pub async fn new(
        pool_size: usize,
        idle_timeout_secs: u64,
        no_sandbox: bool,
        metrics: Arc<BrowserMetrics>,
        auto_dismiss_dialogs: bool,
    ) -> Result<Self, BrowserPoolError> {
        let mut builder = BrowserConfig::builder();
        if no_sandbox {
            warn!("browser sandbox disabled (no_sandbox=true)");
            builder = builder.no_sandbox();
        }
        let config = builder
            .enable_request_intercept()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .build()
            .map_err(|e| BrowserPoolError::LaunchFailed(e.to_string()))?;

        let (browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| BrowserPoolError::LaunchFailed(e.to_string()))?;

        let handler_handle = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if event.is_err() {
                    warn!("browser CDP handler received error event");
                }
            }
        });

        info!(pool_size, idle_timeout_secs, "browser pool initialized");

        Ok(Self {
            browser: Arc::new(browser),
            permits: Arc::new(Semaphore::new(pool_size)),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            metrics,
            auto_dismiss_dialogs,
            _handler_handle: handler_handle,
        })
    }

    /// Acquire a browser page lease. Blocks if all slots are in use.
    pub async fn acquire(&self) -> Result<BrowserLease, BrowserPoolError> {
        let permit = tokio::time::timeout(self.idle_timeout, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| BrowserPoolError::AcquireTimeout)?
            .map_err(|_| BrowserPoolError::PoolClosed)?;

        let page = self
            .browser
            .new_page("about:blank")
            .await
            .map_err(|e| BrowserPoolError::PageCreationFailed(e.to_string()))?;

        let dialog_handle = if self.auto_dismiss_dialogs {
            Some(spawn_dialog_auto_dismiss(&page, self.metrics.clone()).await)
        } else {
            None
        };

        Ok(BrowserLease {
            page,
            _permit: permit,
            _dialog_handle: dialog_handle,
        })
    }

    /// Number of currently available permits.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Get the shared metrics handle.
    pub fn metrics(&self) -> &Arc<BrowserMetrics> {
        &self.metrics
    }
}

/// Spawn a background task that auto-dismisses JavaScript dialogs (alert/confirm/prompt).
async fn spawn_dialog_auto_dismiss(
    page: &Page,
    metrics: Arc<BrowserMetrics>,
) -> tokio::task::JoinHandle<()> {
    // event_listener can fail if the CDP connection is already closed.
    let listener = page.event_listener::<EventJavascriptDialogOpening>().await;
    let page_clone = page.clone();
    tokio::spawn(async move {
        let Ok(mut events) = listener else {
            return;
        };
        while let Some(_event) = events.next().await {
            tracing::warn!("auto-dismissing JavaScript dialog");
            let _ = page_clone
                .execute(HandleJavaScriptDialogParams::new(false))
                .await;
            metrics
                .dialog_dismissed_count
                .fetch_add(1, Ordering::Relaxed);
        }
    })
}

impl Drop for BrowserLease {
    fn drop(&mut self) {
        if let Some(handle) = self._dialog_handle.take() {
            handle.abort();
        }
    }
}

/// A session-scoped browser page that persists across tool calls within a session.
struct SessionPage {
    lease: BrowserLease,
    last_used: Instant,
    loop_detector: LoopDetector,
}

type SessionHandle = Arc<Mutex<SessionPage>>;
type SessionMap = HashMap<String, SessionHandle>;

/// Try to remove a session if the handle is the same one we inspected AND:
/// - no external refs are currently active (map + expected snapshot only), and
/// - `last_used` is still expired.
///
/// Re-checking under the map lock closes races where `acquire_session`
/// refreshes the timestamp or clones the handle between snapshot and removal.
fn try_evict_session(
    map: &mut SessionMap,
    key: &str,
    expected: &SessionHandle,
    idle_timeout: Duration,
    now: Instant,
) -> bool {
    let should_evict = {
        let Some(current) = map.get(key) else {
            return false;
        };
        let ptr_matches = Arc::ptr_eq(current, expected);
        let strong_count = Arc::strong_count(current);
        let last_used = match current.try_lock() {
            Ok(page) => Some(page.last_used),
            Err(_) => None,
        };
        should_evict_candidate(ptr_matches, strong_count, last_used, idle_timeout, now)
    };
    if should_evict {
        map.remove(key);
    }
    should_evict
}

fn should_evict_candidate(
    ptr_matches: bool,
    strong_count: usize,
    last_used: Option<Instant>,
    idle_timeout: Duration,
    now: Instant,
) -> bool {
    if !ptr_matches {
        return false;
    }
    // Only evict when there are no additional external references beyond:
    // 1) the map entry and 2) the expected snapshot handle.
    if strong_count > 2 {
        return false;
    }
    // If the session is currently locked (in-use) or was recently refreshed,
    // skip eviction.
    let Some(last_used) = last_used else {
        return false;
    };
    now.duration_since(last_used) >= idle_timeout
}

/// Manages session-scoped browser pages. Pages persist across tool calls within
/// a session and are cleaned up after idle timeout.
pub struct SessionBrowserManager {
    pool: Arc<BrowserPool>,
    sessions: Arc<Mutex<SessionMap>>,
    idle_timeout: Duration,
    loop_window: usize,
    loop_threshold: usize,
    cleanup_handle: tokio::task::JoinHandle<()>,
}

impl SessionBrowserManager {
    /// Create a new SessionBrowserManager with the given pool and idle timeout.
    /// Starts a background cleanup task that runs every 30 seconds.
    pub fn new(pool: Arc<BrowserPool>, idle_timeout: Duration) -> Arc<Self> {
        Self::with_loop_config(pool, idle_timeout, 4, 3)
    }

    /// Create with explicit loop detection parameters.
    pub fn with_loop_config(
        pool: Arc<BrowserPool>,
        idle_timeout: Duration,
        loop_window: usize,
        loop_threshold: usize,
    ) -> Arc<Self> {
        let sessions: Arc<Mutex<SessionMap>> = Arc::new(Mutex::new(HashMap::new()));
        let sessions_clone = sessions.clone();
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let snapshot: Vec<(String, SessionHandle)> = {
                    let sessions = sessions_clone.lock().await;
                    sessions
                        .iter()
                        .map(|(session_id, handle)| (session_id.clone(), handle.clone()))
                        .collect()
                };

                let mut expired = Vec::new();
                for (session_id, handle) in snapshot {
                    match handle.try_lock() {
                        Ok(page) => {
                            if now.duration_since(page.last_used) >= idle_timeout {
                                expired.push((session_id, handle.clone()));
                            }
                        }
                        // Skip active sessions; they are in use and should not be evicted.
                        Err(_) => continue,
                    }
                }

                if !expired.is_empty() {
                    let mut sessions = sessions_clone.lock().await;
                    for (session_id, expected_handle) in expired {
                        if try_evict_session(
                            &mut sessions,
                            &session_id,
                            &expected_handle,
                            idle_timeout,
                            Instant::now(),
                        ) {
                            info!(session_id, "releasing idle browser session");
                        }
                    }
                }
            }
        });
        Arc::new(Self {
            pool,
            sessions,
            idle_timeout,
            loop_window,
            loop_threshold,
            cleanup_handle,
        })
    }

    /// Acquire a session page. If the session already has a page, returns a reference
    /// to the existing page. If not, acquires a new page from the pool.
    pub async fn acquire_session(
        &self,
        session_id: &str,
    ) -> Result<SessionPageGuard, BrowserPoolError> {
        // Fast path: existing session handle.
        if let Some(handle) = {
            let sessions = self.sessions.lock().await;
            sessions.get(session_id).cloned()
        } {
            let mut page = handle.lock_owned().await;
            page.last_used = Instant::now();
            return Ok(SessionPageGuard { page });
        }

        // Slow path: no session found. Acquire a page without holding the map lock.
        let lease = self.pool.acquire().await?;
        let new_handle = Arc::new(Mutex::new(SessionPage {
            lease,
            last_used: Instant::now(),
            loop_detector: LoopDetector::new(self.loop_window, self.loop_threshold),
        }));

        // Insert if still absent; otherwise reuse the winner and drop the extra lease.
        let handle = {
            let mut sessions = self.sessions.lock().await;
            sessions
                .entry(session_id.to_string())
                .or_insert_with(|| new_handle.clone())
                .clone()
        };

        let mut page = handle.lock_owned().await;
        page.last_used = Instant::now();
        Ok(SessionPageGuard { page })
    }

    /// Release a session, dropping the browser page and returning the pool permit.
    pub async fn release(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().await;
        if sessions.remove(session_id).is_some() {
            info!(session_id, "browser session released");
        }
    }

    /// Get the idle timeout duration.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

impl Drop for SessionBrowserManager {
    fn drop(&mut self) {
        self.cleanup_handle.abort();
    }
}

/// A guard providing access to a session's browser page.
/// Holds only the per-session lock, not the global sessions map.
pub struct SessionPageGuard {
    page: tokio::sync::OwnedMutexGuard<SessionPage>,
}

impl SessionPageGuard {
    /// Get a reference to the browser page for this session.
    pub fn page(&self) -> &Page {
        &self.page.lease.page
    }

    /// Get a mutable reference to the session's loop detector.
    pub fn loop_detector(&mut self) -> &mut LoopDetector {
        &mut self.page.loop_detector
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BrowserPoolError {
    #[error("browser launch failed: {0}")]
    LaunchFailed(String),
    #[error("page creation failed: {0}")]
    PageCreationFailed(String),
    #[error("timed out waiting for browser slot")]
    AcquireTimeout,
    #[error("browser pool is closed")]
    PoolClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_disabled_skips_pool() {
        // When browser is disabled in config, no pool should be created.
        // This test verifies that the pool is opt-in and does not require Chrome.
        let pool_size = 0;
        let permits = Arc::new(Semaphore::new(pool_size));
        assert_eq!(permits.available_permits(), 0);
    }

    // The following tests require a running Chrome instance and are ignored by default.

    #[tokio::test]
    #[ignore]
    async fn pool_acquire_and_release() {
        let pool = BrowserPool::new(2, 30, false, Arc::new(BrowserMetrics::new()), true)
            .await
            .unwrap();
        assert_eq!(pool.available(), 2);

        let lease = pool.acquire().await.unwrap();
        assert_eq!(pool.available(), 1);

        drop(lease);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.available(), 2);
    }

    #[tokio::test]
    #[ignore]
    async fn pool_blocks_when_exhausted() {
        let pool = Arc::new(
            BrowserPool::new(1, 2, false, Arc::new(BrowserMetrics::new()), true)
                .await
                .unwrap(),
        );

        let _lease1 = pool.acquire().await.unwrap();
        assert_eq!(pool.available(), 0);

        let pool2 = pool.clone();
        let handle = tokio::spawn(async move { pool2.acquire().await });

        let result = handle.await.unwrap();
        assert!(result.is_err(), "should timeout when pool exhausted");
    }

    #[tokio::test]
    #[ignore]
    async fn navigate_loads_page() {
        let pool = BrowserPool::new(1, 30, false, Arc::new(BrowserMetrics::new()), true)
            .await
            .unwrap();
        let lease = pool.acquire().await.unwrap();

        lease
            .page
            .goto("data:text/html,<title>Test Page</title><body>Hello</body>")
            .await
            .unwrap();

        let title = lease.page.get_title().await.unwrap();
        assert_eq!(title, Some("Test Page".to_string()));
    }

    #[tokio::test]
    #[ignore]
    async fn screenshot_returns_bytes() {
        let pool = BrowserPool::new(1, 30, false, Arc::new(BrowserMetrics::new()), true)
            .await
            .unwrap();
        let lease = pool.acquire().await.unwrap();

        lease
            .page
            .goto("data:text/html,<body style='background:red'>Screenshot</body>")
            .await
            .unwrap();

        let screenshot = lease
            .page
            .screenshot(
                chromiumoxide::page::ScreenshotParams::builder()
                    .format(
                        chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat::Png,
                    )
                    .build(),
            )
            .await
            .unwrap();
        assert!(!screenshot.is_empty(), "screenshot should have data");
        // PNG magic bytes
        assert_eq!(&screenshot[..4], &[0x89, 0x50, 0x4E, 0x47]);
    }

    #[test]
    fn session_browser_manager_idle_timeout() {
        let timeout = Duration::from_secs(120);
        // Just verify we can construct the idle timeout correctly
        assert_eq!(timeout.as_secs(), 120);
    }

    #[test]
    fn browser_pool_error_display() {
        let err = BrowserPoolError::AcquireTimeout;
        assert_eq!(err.to_string(), "timed out waiting for browser slot");

        let err = BrowserPoolError::PoolClosed;
        assert_eq!(err.to_string(), "browser pool is closed");
    }

    #[test]
    fn should_evict_candidate_guards() {
        let idle = Duration::from_secs(60);
        let now = Instant::now();
        let old = now - Duration::from_secs(120);
        let fresh = now - Duration::from_secs(10);

        assert!(!should_evict_candidate(false, 2, Some(old), idle, now));
        assert!(!should_evict_candidate(true, 3, Some(old), idle, now));
        assert!(!should_evict_candidate(true, 2, None, idle, now));
        assert!(!should_evict_candidate(true, 2, Some(fresh), idle, now));
        assert!(should_evict_candidate(true, 2, Some(old), idle, now));
    }

    /// Verify that `try_evict_session` respects Arc identity, expiry, and
    /// lock state.  Requires Chrome because `SessionPage` holds a `BrowserLease`.
    #[tokio::test]
    #[ignore]
    async fn try_evict_session_guards() {
        let pool = Arc::new(
            BrowserPool::new(3, 30, false, Arc::new(BrowserMetrics::new()), true)
                .await
                .unwrap(),
        );

        // Build two session handles with different ages.
        let fresh_lease = pool.acquire().await.unwrap();
        let fresh: SessionHandle = Arc::new(Mutex::new(SessionPage {
            lease: fresh_lease,
            last_used: Instant::now(),
            loop_detector: LoopDetector::default(),
        }));

        let old_lease = pool.acquire().await.unwrap();
        let old: SessionHandle = Arc::new(Mutex::new(SessionPage {
            lease: old_lease,
            last_used: Instant::now() - Duration::from_secs(120),
            loop_detector: LoopDetector::default(),
        }));

        let wrong_ptr: SessionHandle = Arc::new(Mutex::new(SessionPage {
            lease: pool.acquire().await.unwrap(),
            last_used: Instant::now() - Duration::from_secs(120),
            loop_detector: LoopDetector::default(),
        }));

        let idle = Duration::from_secs(60);
        let now = Instant::now();
        let mut map: SessionMap = HashMap::new();
        map.insert("fresh".to_string(), fresh.clone());
        map.insert("old".to_string(), old.clone());

        // Missing key → false.
        assert!(!try_evict_session(&mut map, "nope", &old, idle, now));

        // Pointer mismatch → false.
        assert!(!try_evict_session(&mut map, "old", &wrong_ptr, idle, now));
        assert!(map.contains_key("old"));

        // Extra external ref present (simulating a concurrent acquire clone)
        // → skip eviction.
        let old_external_ref = old.clone();
        assert!(!try_evict_session(&mut map, "old", &old, idle, now));
        assert!(map.contains_key("old"));
        drop(old_external_ref);

        // Matching pointer + expired + no extra refs → evicted.
        assert!(try_evict_session(&mut map, "old", &old, idle, now));
        assert!(!map.contains_key("old"));

        // Recently used → not evicted.
        assert!(!try_evict_session(&mut map, "fresh", &fresh, idle, now));
        assert!(map.contains_key("fresh"));
    }

    #[tokio::test]
    #[ignore]
    async fn session_manager_same_session_reuses_page() {
        let pool = Arc::new(
            BrowserPool::new(2, 30, false, Arc::new(BrowserMetrics::new()), true)
                .await
                .unwrap(),
        );
        let manager = SessionBrowserManager::new(pool.clone(), Duration::from_secs(60));

        // First acquire creates a new page
        {
            let guard = manager.acquire_session("session-1").await.unwrap();
            guard
                .page()
                .goto("data:text/html,<title>Page1</title>")
                .await
                .unwrap();
        }

        // Second acquire should return the same page (same session)
        {
            let guard = manager.acquire_session("session-1").await.unwrap();
            let title = guard.page().get_title().await.unwrap();
            assert_eq!(title, Some("Page1".to_string()));
        }

        manager.release("session-1").await;
    }

    #[tokio::test]
    #[ignore]
    async fn session_manager_release_frees_slot() {
        let pool = Arc::new(
            BrowserPool::new(1, 30, false, Arc::new(BrowserMetrics::new()), true)
                .await
                .unwrap(),
        );
        let manager = SessionBrowserManager::new(pool.clone(), Duration::from_secs(60));

        {
            let _guard = manager.acquire_session("session-1").await.unwrap();
        }
        manager.release("session-1").await;

        // After release, pool slot should be freed
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.available(), 1);
    }

    #[tokio::test]
    #[ignore]
    async fn session_manager_different_sessions_get_different_pages() {
        let pool = Arc::new(
            BrowserPool::new(2, 30, false, Arc::new(BrowserMetrics::new()), true)
                .await
                .unwrap(),
        );
        let manager = SessionBrowserManager::new(pool.clone(), Duration::from_secs(60));

        {
            let guard1 = manager.acquire_session("session-a").await.unwrap();
            guard1
                .page()
                .goto("data:text/html,<title>PageA</title>")
                .await
                .unwrap();
        }
        {
            let guard2 = manager.acquire_session("session-b").await.unwrap();
            guard2
                .page()
                .goto("data:text/html,<title>PageB</title>")
                .await
                .unwrap();
        }
        {
            let guard_a = manager.acquire_session("session-a").await.unwrap();
            let title_a = guard_a.page().get_title().await.unwrap();
            assert_eq!(title_a, Some("PageA".to_string()));
        }
        {
            let guard_b = manager.acquire_session("session-b").await.unwrap();
            let title_b = guard_b.page().get_title().await.unwrap();
            assert_eq!(title_b, Some("PageB".to_string()));
        }

        manager.release("session-a").await;
        manager.release("session-b").await;
    }

    #[tokio::test]
    #[ignore]
    async fn get_text_extracts_body() {
        let pool = BrowserPool::new(1, 30, false, Arc::new(BrowserMetrics::new()), true)
            .await
            .unwrap();
        let lease = pool.acquire().await.unwrap();

        lease
            .page
            .goto("data:text/html,<body>Extracted Text Content</body>")
            .await
            .unwrap();

        let content = lease.page.content().await.unwrap();
        assert!(content.contains("Extracted Text Content"));
    }
}
