//! Two-class priority scheduler for global agent-run concurrency.
//!
//! Traffic is split into two classes:
//!
//! - `Interactive` — user-initiated runs (chat.send from the UI, channel
//!   messages from Telegram/Slack/Gmail). These are drained first.
//! - `Background` — automated runs (cron, webhook triggers, workflow
//!   timers). These are served only when no interactive waiter is
//!   pending, or when the fairness cap has been reached.
//!
//! A fairness cap prevents background starvation: after `fairness_cap`
//! consecutive interactive runs, the scheduler serves exactly one
//! background waiter before resuming interactive priority. A cap of 0
//! means strict priority (background may starve; use only when that is
//! the desired behavior).
//!
//! Per-session FIFO ordering is enforced separately by
//! `gateway::query_guard`. This scheduler only controls the global
//! order in which *different* sessions compete for agent-pool permits.
//!
//! # Design
//!
//! The scheduler runs a single dispatcher task that owns a tokio
//! `Semaphore` with `max_concurrent` permits. Callers submit a request
//! via an unbounded channel and receive their permit over a oneshot.
//! The dispatcher accepts new requests while waiting for the semaphore,
//! so class assignment is always current.
//!
//! Cancelled waiters (whose oneshot receiver has been dropped) are
//! pruned lazily when the dispatcher pops them, so permits are never
//! wasted more than briefly.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

// Re-export the task-local scheduler primitives from core so existing
// call sites (`encmind_agent::scheduler::QueryClass`,
// `current_query_class()`, `CURRENT_QUERY_CLASS`) keep working while
// the canonical definitions live in encmind-core — lower layers
// (encmind-llm) can read the task-local without depending on this
// crate.
pub use encmind_core::scheduler::{current_query_class, QueryClass, CURRENT_QUERY_CLASS};

#[derive(Debug)]
pub struct SchedulerClosed;

impl fmt::Display for SchedulerClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("two-class scheduler is closed")
    }
}

impl std::error::Error for SchedulerClosed {}

/// A two-class priority scheduler backed by a single global semaphore.
///
/// `new()` is synchronous and does not require a running tokio runtime;
/// the dispatcher task is spawned lazily on the first `acquire()` call.
pub struct TwoClassScheduler {
    tx: mpsc::UnboundedSender<WaiterRequest>,
    max_concurrent: usize,
    fairness_cap: usize,
    semaphore: Arc<Semaphore>,
    /// Pending dispatcher state: the receiver is taken and the
    /// dispatcher task spawned on first `acquire()`. Wrapped in a
    /// std mutex so `new()` stays sync and multiple concurrent
    /// acquires race safely (only one actually spawns).
    pending: std::sync::Mutex<Option<mpsc::UnboundedReceiver<WaiterRequest>>>,
}

struct WaiterRequest {
    class: QueryClass,
    resp: oneshot::Sender<OwnedSemaphorePermit>,
}

impl TwoClassScheduler {
    /// Create a new scheduler.
    ///
    /// - `max_concurrent`: global agent-run cap. Clamped to at least 1.
    /// - `fairness_cap`: max consecutive interactive dispatches before
    ///   forcing one background dispatch. Use 0 for strict priority.
    pub fn new(max_concurrent: usize, fairness_cap: usize) -> Self {
        let max_concurrent = max_concurrent.max(1);
        let (tx, rx) = mpsc::unbounded_channel::<WaiterRequest>();
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        Self {
            tx,
            max_concurrent,
            fairness_cap,
            semaphore,
            pending: std::sync::Mutex::new(Some(rx)),
        }
    }

    fn ensure_dispatcher(&self) {
        let mut guard = self.pending.lock().unwrap();
        if let Some(rx) = guard.take() {
            let sem = self.semaphore.clone();
            let fairness_cap = self.fairness_cap;
            tokio::spawn(dispatcher_loop(rx, sem, fairness_cap));
        }
    }

    /// Acquire a permit for the given class.
    ///
    /// The returned permit releases its slot when dropped. Cancelling
    /// this future while it is waiting is safe: the oneshot receiver
    /// drops, and the dispatcher will discard or release the permit.
    pub async fn acquire(
        &self,
        class: QueryClass,
    ) -> Result<OwnedSemaphorePermit, SchedulerClosed> {
        self.ensure_dispatcher();
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(WaiterRequest {
                class,
                resp: resp_tx,
            })
            .map_err(|_| SchedulerClosed)?;
        resp_rx.await.map_err(|_| SchedulerClosed)
    }

    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    pub fn fairness_cap(&self) -> usize {
        self.fairness_cap
    }
}

async fn dispatcher_loop(
    mut rx: mpsc::UnboundedReceiver<WaiterRequest>,
    sem: Arc<Semaphore>,
    fairness_cap: usize,
) {
    let mut interactive: VecDeque<oneshot::Sender<OwnedSemaphorePermit>> = VecDeque::new();
    let mut background: VecDeque<oneshot::Sender<OwnedSemaphorePermit>> = VecDeque::new();
    let mut consecutive_interactive_served = 0usize;

    loop {
        // Drain any pending requests without blocking.
        while let Ok(req) = rx.try_recv() {
            push_waiter(&mut interactive, &mut background, req);
        }

        // Prune cancelled waiters (receivers dropped before dispatch).
        interactive.retain(|s| !s.is_closed());
        background.retain(|s| !s.is_closed());

        // No waiters — wait for the next request.
        if interactive.is_empty() && background.is_empty() {
            match rx.recv().await {
                Some(req) => push_waiter(&mut interactive, &mut background, req),
                None => return, // scheduler dropped
            }
            continue;
        }

        // Try to acquire a permit, but stay responsive to new requests.
        let permit = tokio::select! {
            maybe_req = rx.recv() => match maybe_req {
                Some(req) => {
                    push_waiter(&mut interactive, &mut background, req);
                    continue;
                }
                None => return,
            },
            permit_res = sem.clone().acquire_owned() => match permit_res {
                Ok(p) => p,
                Err(_) => return,
            },
        };

        // Decide which class to serve:
        // - If interactive is empty, serve background.
        // - If background is empty, serve interactive.
        // - Otherwise prefer interactive, but force background if the
        //   fairness cap has been reached.
        let serve_background = if background.is_empty() {
            false
        } else if interactive.is_empty() {
            true
        } else {
            fairness_cap > 0 && consecutive_interactive_served >= fairness_cap
        };

        let sender_opt = if serve_background {
            background.pop_front()
        } else {
            interactive.pop_front()
        };

        let Some(sender) = sender_opt else {
            // Queue emptied due to cancellation between retain() and
            // pop_front() (not possible in single-threaded dispatcher,
            // but defensive). Drop the permit and loop.
            drop(permit);
            continue;
        };

        match sender.send(permit) {
            Ok(()) => {
                if serve_background {
                    consecutive_interactive_served = 0;
                } else {
                    consecutive_interactive_served += 1;
                }
            }
            Err(_permit) => {
                // Receiver was dropped between pop and send; the
                // permit drops with the Err variant, releasing the
                // slot. Counter is unchanged because we didn't
                // successfully serve anyone.
            }
        }
    }
}

fn push_waiter(
    interactive: &mut VecDeque<oneshot::Sender<OwnedSemaphorePermit>>,
    background: &mut VecDeque<oneshot::Sender<OwnedSemaphorePermit>>,
    req: WaiterRequest,
) {
    match req.class {
        QueryClass::Interactive => interactive.push_back(req.resp),
        QueryClass::Background => background.push_back(req.resp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn interactive_drains_before_background() {
        let scheduler = Arc::new(TwoClassScheduler::new(1, 0));

        // Hold the single permit so all subsequent waiters queue.
        let initial = scheduler
            .acquire(QueryClass::Interactive)
            .await
            .expect("initial acquire");

        let order: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for label in ["bg-1", "bg-2", "bg-3"] {
            let sched = scheduler.clone();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                let _p = sched
                    .acquire(QueryClass::Background)
                    .await
                    .expect("bg acquire");
                order.lock().unwrap().push(label);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }));
        }
        // Give background waiters time to register.
        tokio::time::sleep(Duration::from_millis(10)).await;

        for label in ["inter-1", "inter-2"] {
            let sched = scheduler.clone();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                let _p = sched
                    .acquire(QueryClass::Interactive)
                    .await
                    .expect("interactive acquire");
                order.lock().unwrap().push(label);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }));
        }
        // Give interactive waiters time to register.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Release the initial permit. The dispatcher should now serve
        // waiters; with fairness_cap=0 (strict priority) interactives
        // must drain before any background runs.
        drop(initial);

        for h in handles {
            h.await.unwrap();
        }

        let observed = order.lock().unwrap().clone();
        // All interactives must appear before any background entry.
        let first_background = observed
            .iter()
            .position(|s| s.starts_with("bg-"))
            .expect("background entries present");
        for (i, label) in observed.iter().enumerate().take(first_background) {
            assert!(
                label.starts_with("inter-"),
                "entry {i} should be interactive, got {label}"
            );
        }
        // All interactives should appear.
        assert_eq!(
            observed.iter().filter(|s| s.starts_with("inter-")).count(),
            2
        );
        assert_eq!(observed.iter().filter(|s| s.starts_with("bg-")).count(), 3);
    }

    #[tokio::test]
    async fn fairness_cap_interleaves_background() {
        // Cap=2 means serve 2 interactives then 1 background.
        let scheduler = Arc::new(TwoClassScheduler::new(1, 2));

        // Hold the single permit until all waiters queue.
        let initial = scheduler
            .acquire(QueryClass::Interactive)
            .await
            .expect("initial acquire");

        let order: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        // Enqueue 5 interactives and 5 backgrounds.
        let mut handles = Vec::new();
        for label in ["i1", "i2", "i3", "i4", "i5"] {
            let sched = scheduler.clone();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                let _p = sched.acquire(QueryClass::Interactive).await.unwrap();
                order.lock().unwrap().push(label);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        for label in ["b1", "b2", "b3", "b4", "b5"] {
            let sched = scheduler.clone();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                let _p = sched.acquire(QueryClass::Background).await.unwrap();
                order.lock().unwrap().push(label);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;

        drop(initial);

        for h in handles {
            h.await.unwrap();
        }

        let observed = order.lock().unwrap().clone();
        // Expected: i1, i2, b1, i3, i4, b2, i5, b3, b4, b5
        //                  ^        ^      ^
        //                  cap hit  cap hit (only 1 more interactive remains)
        // After the last interactive drains, remaining backgrounds run.
        //
        // The exact interleave depends on task scheduling; we assert
        // the invariant that between any two interactives separated
        // by a background, there are at most `fairness_cap` = 2
        // consecutive interactives.
        let mut consec_interactive = 0usize;
        let mut max_consec_interactive = 0usize;
        for label in &observed {
            if label.starts_with('i') {
                consec_interactive += 1;
                max_consec_interactive = max_consec_interactive.max(consec_interactive);
            } else {
                consec_interactive = 0;
            }
        }
        // After all interactives are drained, the remaining backgrounds
        // run in sequence, which can exceed the cap on the tail. We
        // care about the cap only while interactives are available.
        // Since there are 5 interactives and cap=2, the first 2 i's
        // must be followed by a b before a 3rd i.
        let first_b_idx = observed.iter().position(|s| s.starts_with('b'));
        if let Some(idx) = first_b_idx {
            let i_count_before_first_b = observed
                .iter()
                .take(idx)
                .filter(|s| s.starts_with('i'))
                .count();
            assert!(
                i_count_before_first_b <= 2,
                "cap should force background after 2 interactives; got {i_count_before_first_b} before first background. Sequence: {observed:?}"
            );
        }
        // Both classes must be fully drained.
        assert_eq!(observed.iter().filter(|s| s.starts_with('i')).count(), 5);
        assert_eq!(observed.iter().filter(|s| s.starts_with('b')).count(), 5);
    }

    #[tokio::test]
    async fn background_served_when_no_interactive_pending() {
        let scheduler = Arc::new(TwoClassScheduler::new(1, 3));
        let p1 = scheduler.acquire(QueryClass::Background).await.unwrap();
        // Verify that a single background can acquire even with fairness cap.
        drop(p1);

        for _ in 0..5 {
            let _p = scheduler.acquire(QueryClass::Background).await.unwrap();
        }
    }

    #[tokio::test]
    async fn respects_max_concurrent_limit() {
        let scheduler = Arc::new(TwoClassScheduler::new(3, 0));
        let active = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let sched = scheduler.clone();
            let active = active.clone();
            let max_observed = max_observed.clone();
            handles.push(tokio::spawn(async move {
                let _p = sched.acquire(QueryClass::Interactive).await.unwrap();
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_observed.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        assert!(
            max_observed.load(Ordering::SeqCst) <= 3,
            "scheduler must never exceed max_concurrent=3"
        );
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_waste_permit() {
        let scheduler = Arc::new(TwoClassScheduler::new(1, 0));
        let initial = scheduler.acquire(QueryClass::Interactive).await.unwrap();

        // Spawn a waiter and abort it before the permit frees.
        let sched = scheduler.clone();
        let handle =
            tokio::spawn(async move { sched.acquire(QueryClass::Interactive).await.unwrap() });
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort();
        let _ = handle.await;

        drop(initial);

        // A fresh acquisition should succeed promptly — no permit lost.
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            scheduler.acquire(QueryClass::Interactive),
        )
        .await
        .expect("acquire should not hang");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn max_concurrent_clamped_to_one() {
        let scheduler = TwoClassScheduler::new(0, 0);
        assert_eq!(scheduler.max_concurrent(), 1);
    }
}
