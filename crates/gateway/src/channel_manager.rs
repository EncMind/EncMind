use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use encmind_core::traits::ChannelAdapter;

/// A running adapter with its inbound processing loop.
struct RunningAdapter {
    adapter: Arc<dyn ChannelAdapter>,
    inbound_handle: JoinHandle<()>,
    cancel: CancellationToken,
}

/// Manages runtime channel adapter lifecycle (start/stop/replace).
///
/// Provides per-channel serialization so that concurrent login/logout/remove
/// operations for the same channel serialize cleanly.
pub struct ChannelAdapterManager {
    running: RwLock<HashMap<String, RunningAdapter>>,
    /// Per-channel mutex to serialize login/logout/remove for the same channel.
    channel_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    global_shutdown: CancellationToken,
}

impl ChannelAdapterManager {
    pub fn new(global_shutdown: CancellationToken) -> Self {
        Self {
            running: RwLock::new(HashMap::new()),
            channel_locks: Mutex::new(HashMap::new()),
            global_shutdown,
        }
    }

    /// Acquire a per-channel serialization lock.
    async fn channel_lock(&self, channel_type: &str) -> Arc<Mutex<()>> {
        let mut locks = self.channel_locks.lock().await;
        locks
            .entry(channel_type.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Acquire an owned per-channel lock guard for the channel lifecycle.
    ///
    /// This can be used by higher-level handlers that need to serialize
    /// persistence + probe + runtime replacement in a single critical section.
    pub async fn lock_channel(&self, channel_type: &str) -> OwnedMutexGuard<()> {
        let lock = self.channel_lock(channel_type).await;
        lock.lock_owned().await
    }

    async fn start_adapter_inner<F>(
        &self,
        channel_type: &str,
        adapter: Arc<dyn ChannelAdapter>,
        spawn_loop: F,
    ) -> Result<(), encmind_core::error::ChannelError>
    where
        F: FnOnce(Arc<dyn ChannelAdapter>, CancellationToken) -> JoinHandle<()>,
    {
        // Remove old entry if present (drop write lock before stopping)
        let old = {
            let mut running = self.running.write().await;
            running.remove(channel_type)
        };

        // Stop old adapter outside any lock
        if let Some(old) = old {
            old.cancel.cancel();
            let _ = old.inbound_handle.await;
            if let Err(e) = old.adapter.stop().await {
                warn!(
                    channel = %channel_type,
                    error = %e,
                    "failed to stop old adapter during replacement"
                );
            }
        }

        // Start the new adapter
        adapter.start().await?;

        let cancel = CancellationToken::new();
        let handle = spawn_loop(adapter.clone(), cancel.clone());

        // Insert new entry
        {
            let mut running = self.running.write().await;
            running.insert(
                channel_type.to_string(),
                RunningAdapter {
                    adapter,
                    inbound_handle: handle,
                    cancel,
                },
            );
        }

        info!(channel = %channel_type, "channel adapter started via manager");
        Ok(())
    }

    async fn stop_adapter_inner(&self, channel_type: &str) {
        let old = {
            let mut running = self.running.write().await;
            running.remove(channel_type)
        };

        if let Some(old) = old {
            old.cancel.cancel();
            let _ = old.inbound_handle.await;
            if let Err(e) = old.adapter.stop().await {
                warn!(
                    channel = %channel_type,
                    error = %e,
                    "failed to stop adapter"
                );
            }
            info!(channel = %channel_type, "channel adapter stopped via manager");
        }
    }

    async fn prune_channel_lock_if_idle_with_lock(
        &self,
        channel_type: &str,
        lock: &Arc<Mutex<()>>,
    ) {
        // Keep lock entries while adapters are running.
        if self.is_running(channel_type).await {
            return;
        }

        // Remove lock entries only when no other operation holds/clones this lock.
        // `2` means map entry + local `lock` reference.
        if Arc::strong_count(lock) == 2 {
            let mut locks = self.channel_locks.lock().await;
            if let Some(existing) = locks.get(channel_type) {
                if Arc::ptr_eq(existing, lock) && Arc::strong_count(existing) == 2 {
                    locks.remove(channel_type);
                }
            }
        }
    }

    /// Best-effort cleanup for idle per-channel locks.
    ///
    /// Callers should invoke this after releasing any channel guard.
    pub async fn prune_channel_lock_if_idle(&self, channel_type: &str) {
        // Keep lock entries while adapters are running.
        if self.is_running(channel_type).await {
            return;
        }

        let mut locks = self.channel_locks.lock().await;
        if let Some(existing) = locks.get(channel_type) {
            // `1` means the map itself is the last owner.
            if Arc::strong_count(existing) == 1 {
                locks.remove(channel_type);
            }
        }
    }

    /// Start an adapter. If one is already running for this channel type,
    /// stop the old one first.
    ///
    /// `spawn_loop` is a callback that takes the adapter + a cancellation token
    /// and returns a JoinHandle for the inbound processing loop.
    pub async fn start_adapter<F>(
        &self,
        channel_type: &str,
        adapter: Arc<dyn ChannelAdapter>,
        spawn_loop: F,
    ) -> Result<(), encmind_core::error::ChannelError>
    where
        F: FnOnce(Arc<dyn ChannelAdapter>, CancellationToken) -> JoinHandle<()>,
    {
        let lock = self.channel_lock(channel_type).await;
        let _guard = lock.lock().await;
        self.start_adapter_inner(channel_type, adapter, spawn_loop)
            .await
    }

    /// Start an adapter while the caller already holds the channel lock.
    pub async fn start_adapter_locked<F>(
        &self,
        channel_type: &str,
        adapter: Arc<dyn ChannelAdapter>,
        spawn_loop: F,
    ) -> Result<(), encmind_core::error::ChannelError>
    where
        F: FnOnce(Arc<dyn ChannelAdapter>, CancellationToken) -> JoinHandle<()>,
    {
        self.start_adapter_inner(channel_type, adapter, spawn_loop)
            .await
    }

    /// Stop a running adapter. No-op if not running.
    pub async fn stop_adapter(&self, channel_type: &str) {
        let lock = self.channel_lock(channel_type).await;
        {
            let _guard = lock.lock().await;
            self.stop_adapter_inner(channel_type).await;
        }
        self.prune_channel_lock_if_idle_with_lock(channel_type, &lock)
            .await;
    }

    /// Stop a running adapter while the caller already holds the channel lock.
    pub async fn stop_adapter_locked(&self, channel_type: &str) {
        self.stop_adapter_inner(channel_type).await;
    }

    /// Get a reference to a running adapter.
    pub async fn get_adapter(&self, channel_type: &str) -> Option<Arc<dyn ChannelAdapter>> {
        let running = self.running.read().await;
        running.get(channel_type).map(|r| r.adapter.clone())
    }

    /// Check if an adapter is running for the given channel type.
    pub async fn is_running(&self, channel_type: &str) -> bool {
        let running = self.running.read().await;
        running.contains_key(channel_type)
    }

    /// Number of currently running channel adapters.
    pub async fn running_count(&self) -> usize {
        let running = self.running.read().await;
        running.len()
    }

    /// List currently running channel types.
    pub async fn running_channel_types(&self) -> Vec<String> {
        let running = self.running.read().await;
        let mut channels: Vec<String> = running.keys().cloned().collect();
        channels.sort();
        channels
    }

    /// Stop all running adapters (for graceful shutdown).
    pub async fn stop_all(&self) {
        let entries: Vec<(String, RunningAdapter)> = {
            let mut running = self.running.write().await;
            running.drain().collect()
        };

        for (channel_type, entry) in entries {
            entry.cancel.cancel();
            let _ = entry.inbound_handle.await;
            if let Err(e) = entry.adapter.stop().await {
                warn!(
                    channel = %channel_type,
                    error = %e,
                    "failed to stop adapter during shutdown"
                );
            }
        }
    }

    /// The global shutdown token used by this manager.
    pub fn global_shutdown(&self) -> &CancellationToken {
        &self.global_shutdown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use encmind_core::error::ChannelError;
    use encmind_core::types::{
        ChannelAccountStatus, ChannelTarget, InboundMessage, OutboundMessage,
    };
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock adapter that tracks start/stop calls.
    struct MockAdapter {
        starts: AtomicUsize,
        stops: AtomicUsize,
    }

    impl MockAdapter {
        fn new() -> Self {
            Self {
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
            }
        }

        fn start_count(&self) -> usize {
            self.starts.load(Ordering::SeqCst)
        }

        fn stop_count(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChannelAdapter for MockAdapter {
        async fn start(&self) -> Result<(), ChannelError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) -> Result<(), ChannelError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn send_message(
            &self,
            _target: &ChannelTarget,
            _msg: &OutboundMessage,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn inbound(&self) -> Pin<Box<dyn futures::Stream<Item = InboundMessage> + Send>> {
            Box::pin(futures::stream::empty())
        }

        fn health_status(&self) -> ChannelAccountStatus {
            ChannelAccountStatus::Active
        }
    }

    fn dummy_spawn_loop(
        _adapter: Arc<dyn ChannelAdapter>,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            cancel.cancelled().await;
        })
    }

    #[tokio::test]
    async fn start_and_stop() {
        let manager = ChannelAdapterManager::new(CancellationToken::new());
        let adapter = Arc::new(MockAdapter::new());

        manager
            .start_adapter("telegram", adapter.clone(), dummy_spawn_loop)
            .await
            .unwrap();

        assert!(manager.is_running("telegram").await);
        assert_eq!(adapter.start_count(), 1);

        manager.stop_adapter("telegram").await;
        assert!(!manager.is_running("telegram").await);
        assert_eq!(adapter.stop_count(), 1);
    }

    #[tokio::test]
    async fn double_start_replaces_old() {
        let manager = ChannelAdapterManager::new(CancellationToken::new());
        let adapter1 = Arc::new(MockAdapter::new());
        let adapter2 = Arc::new(MockAdapter::new());

        manager
            .start_adapter("telegram", adapter1.clone(), dummy_spawn_loop)
            .await
            .unwrap();
        manager
            .start_adapter("telegram", adapter2.clone(), dummy_spawn_loop)
            .await
            .unwrap();

        assert!(manager.is_running("telegram").await);
        // Old adapter was stopped
        assert_eq!(adapter1.stop_count(), 1);
        // New adapter was started
        assert_eq!(adapter2.start_count(), 1);
    }

    #[tokio::test]
    async fn stop_nonexistent_is_noop() {
        let manager = ChannelAdapterManager::new(CancellationToken::new());
        // Should not panic
        manager.stop_adapter("telegram").await;
    }

    #[tokio::test]
    async fn get_adapter_returns_running() {
        let manager = ChannelAdapterManager::new(CancellationToken::new());
        assert!(manager.get_adapter("telegram").await.is_none());

        let adapter = Arc::new(MockAdapter::new());
        manager
            .start_adapter("telegram", adapter.clone(), dummy_spawn_loop)
            .await
            .unwrap();

        assert!(manager.get_adapter("telegram").await.is_some());
    }

    #[tokio::test]
    async fn stop_all_drains_map() {
        let manager = ChannelAdapterManager::new(CancellationToken::new());
        let a1 = Arc::new(MockAdapter::new());
        let a2 = Arc::new(MockAdapter::new());

        manager
            .start_adapter("telegram", a1.clone(), dummy_spawn_loop)
            .await
            .unwrap();
        manager
            .start_adapter("slack", a2.clone(), dummy_spawn_loop)
            .await
            .unwrap();

        manager.stop_all().await;

        assert!(!manager.is_running("telegram").await);
        assert!(!manager.is_running("slack").await);
        assert_eq!(a1.stop_count(), 1);
        assert_eq!(a2.stop_count(), 1);
    }

    #[tokio::test]
    async fn running_channel_types_returns_sorted_names() {
        let manager = ChannelAdapterManager::new(CancellationToken::new());
        let a1 = Arc::new(MockAdapter::new());
        let a2 = Arc::new(MockAdapter::new());

        manager
            .start_adapter("telegram", a1, dummy_spawn_loop)
            .await
            .unwrap();
        manager
            .start_adapter("slack", a2, dummy_spawn_loop)
            .await
            .unwrap();

        assert_eq!(
            manager.running_channel_types().await,
            vec!["slack".to_string(), "telegram".to_string()]
        );
    }

    #[tokio::test]
    async fn concurrent_login_logout_same_channel() {
        let manager = Arc::new(ChannelAdapterManager::new(CancellationToken::new()));
        let adapter = Arc::new(MockAdapter::new());

        // Start first
        manager
            .start_adapter("telegram", adapter.clone(), dummy_spawn_loop)
            .await
            .unwrap();

        let m1 = manager.clone();
        let m2 = manager.clone();
        let a = adapter.clone();

        // Concurrent login and logout
        let (_, r2) = tokio::join!(
            async move { m1.stop_adapter("telegram").await },
            async move { m2.start_adapter("telegram", a, dummy_spawn_loop).await }
        );

        // Both should complete without panic
        let _ = r2; // May succeed or fail, but no panic/deadlock
    }

    #[tokio::test]
    async fn concurrent_different_channels_both_succeed() {
        let manager = Arc::new(ChannelAdapterManager::new(CancellationToken::new()));
        let a1 = Arc::new(MockAdapter::new());
        let a2 = Arc::new(MockAdapter::new());

        let m1 = manager.clone();
        let m2 = manager.clone();

        let (r1, r2) = tokio::join!(
            async move { m1.start_adapter("telegram", a1, dummy_spawn_loop).await },
            async move { m2.start_adapter("slack", a2, dummy_spawn_loop).await }
        );

        r1.unwrap();
        r2.unwrap();
        assert!(manager.is_running("telegram").await);
        assert!(manager.is_running("slack").await);
    }
}
