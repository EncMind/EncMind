use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use futures::FutureExt;
use rand::RngExt;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use encmind_core::config::SkillErrorPolicy;
use encmind_core::hooks::HookRegistry;
use encmind_core::traits::SkillTimerStore;
use encmind_core::types::SkillTimer;
use encmind_storage::audit::AuditLogger;
use encmind_wasm_host::invoker::{InvokeDeps, SkillInvoker};
use encmind_wasm_host::manifest::TimerDeclaration;
use encmind_wasm_host::{ApprovalPrompter, OutboundPolicy};

use crate::server::load_skill_runtime_config;

/// Runtime spec used to execute timers for a skill.
#[derive(Clone)]
pub struct SkillTimerRuntimeSpec {
    pub invoker: Arc<SkillInvoker>,
    pub wall_clock_timeout: StdDuration,
}

/// Shared dependencies injected into timer WASM invocations.
#[derive(Clone)]
pub struct TimerWasmDependencies {
    pub db_pool: Arc<encmind_wasm_host::SqlitePool>,
    pub http_client: Arc<reqwest::Client>,
    pub outbound_policy: Arc<dyn OutboundPolicy>,
    pub hook_registry: Arc<RwLock<HookRegistry>>,
    pub approval_prompter: Arc<dyn ApprovalPrompter>,
}

/// Per-skill resource limits for the timer runner.
#[derive(Debug, Clone)]
pub struct SkillTimerLimits {
    pub max_concurrent: u32,
    pub invocations_per_minute: u32,
}

impl Default for SkillTimerLimits {
    fn default() -> Self {
        Self {
            max_concurrent: 2,
            invocations_per_minute: 60,
        }
    }
}

/// Reconcile manifest-declared timers for a single skill with the DB.
/// Upserts current timers and deletes timers no longer declared.
pub async fn reconcile_skill_timers(
    store: &dyn SkillTimerStore,
    skill_id: &str,
    timers: &[TimerDeclaration],
    manifest_hash: &str,
) -> Result<(), String> {
    for decl in timers {
        let timer_id = format!("{skill_id}:{}", decl.name);
        let now = Utc::now();
        // Apply startup jitter (0-5s) to prevent thundering herd
        let jitter_ms = rand::rng().random_range(0..5000);
        let next_tick = now + Duration::milliseconds(jitter_ms);

        let timer = SkillTimer {
            id: timer_id,
            skill_id: skill_id.to_string(),
            timer_name: decl.name.clone(),
            interval_secs: decl.interval_secs,
            export_fn: decl.export_fn.clone(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(next_tick),
            source_manifest_hash: Some(manifest_hash.to_string()),
            consecutive_failures: 0,
            created_at: now,
            updated_at: now,
        };
        store
            .upsert_timer(&timer)
            .await
            .map_err(|e| format!("failed to upsert timer {}: {e}", decl.name))?;
    }

    let keep_names: Vec<&str> = timers.iter().map(|t| t.name.as_str()).collect();
    store
        .delete_stale_timers(skill_id, &keep_names)
        .await
        .map_err(|e| format!("failed to delete stale timers for {skill_id}: {e}"))?;

    Ok(())
}

/// Reconcile all manifest-declared timers with the DB.
/// For each loaded skill: upsert current timers, delete stale timers.
/// Then globally: delete timers for skills no longer loaded.
pub async fn reconcile_all_timers(
    store: &dyn SkillTimerStore,
    skill_timers: &[(String, Vec<TimerDeclaration>, String)], // (skill_id, timers, manifest_hash)
) -> Result<(), String> {
    let loaded_ids: Vec<&str> = skill_timers.iter().map(|(id, _, _)| id.as_str()).collect();

    // Per-skill reconciliation
    for (skill_id, timers, hash) in skill_timers {
        reconcile_skill_timers(store, skill_id, timers, hash).await?;
    }

    // Global orphan cleanup — remove timers for skills no longer loaded
    store
        .delete_timers_not_in_skills(&loaded_ids)
        .await
        .map_err(|e| format!("failed to cleanup orphan timers: {e}"))?;

    Ok(())
}

/// Runs skill timers on a periodic check interval.
/// Follows the CronDispatcher pattern: global semaphore + dedup map.
/// Also enforces per-skill concurrency limits and per-skill rate limits.
pub struct SkillTimerRunner {
    timer_store: Arc<dyn SkillTimerStore>,
    global_semaphore: Arc<Semaphore>,
    active_ticks: Mutex<HashMap<String, ActiveTickPermits>>,
    /// Per-skill concurrency semaphores. Keys are skill_id.
    per_skill_semaphores: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Per-skill rate counters: (window_start, count_in_window).
    rate_counters: Mutex<HashMap<String, (std::time::Instant, u32)>>,
    /// Per-skill resource limits. Keys are skill_id.
    skill_limits: RwLock<HashMap<String, SkillTimerLimits>>,
    /// Runtime spec for each loaded skill, used to execute timer exports.
    skill_runtime_specs: RwLock<HashMap<String, SkillTimerRuntimeSpec>>,
    /// Optional WASM host dependencies required by timer execution.
    wasm_deps: Option<TimerWasmDependencies>,
    /// Optional audit logger for operator-visible timer lifecycle events.
    audit_logger: Option<Arc<AuditLogger>>,
    check_interval_secs: u64,
}

impl SkillTimerRunner {
    pub fn new(
        timer_store: Arc<dyn SkillTimerStore>,
        max_concurrent: usize,
        check_interval_secs: u64,
    ) -> Self {
        Self {
            timer_store,
            global_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            active_ticks: Mutex::new(HashMap::new()),
            per_skill_semaphores: Mutex::new(HashMap::new()),
            rate_counters: Mutex::new(HashMap::new()),
            skill_limits: RwLock::new(HashMap::new()),
            skill_runtime_specs: RwLock::new(HashMap::new()),
            wasm_deps: None,
            audit_logger: None,
            check_interval_secs,
        }
    }

    pub fn with_wasm_dependencies(mut self, deps: TimerWasmDependencies) -> Self {
        self.wasm_deps = Some(deps);
        self
    }

    pub fn with_audit_logger(mut self, audit_logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = Some(audit_logger);
        self
    }

    /// Update per-skill resource limits (called during reconciliation/refresh).
    pub async fn set_skill_limits(&self, limits: HashMap<String, SkillTimerLimits>) {
        let previous_limits = self.skill_limits.read().await.clone();
        let active_by_skill: HashMap<String, usize> = {
            let active = self.active_ticks.lock().await;
            let mut counts: HashMap<String, usize> = HashMap::new();
            for permits in active.values() {
                *counts.entry(permits.skill_id.clone()).or_insert(0) += 1;
            }
            counts
        };

        // Keep existing semaphores so in-flight permits remain attached to the
        // same semaphore instance across refreshes. Replacing semaphores while
        // permits are active can transiently bypass per-skill concurrency limits.
        let mut semaphores = self.per_skill_semaphores.lock().await;
        semaphores.retain(|skill_id, _| limits.contains_key(skill_id));
        for (skill_id, limit) in &limits {
            let active_for_skill = active_by_skill.get(skill_id).copied().unwrap_or(0);
            if active_for_skill == 0 {
                // No in-flight permits: reset to exact configured capacity.
                semaphores.insert(
                    skill_id.clone(),
                    Arc::new(Semaphore::new(limit.max_concurrent as usize)),
                );
                continue;
            }

            match semaphores.get(skill_id) {
                Some(existing) => {
                    // We can safely increase semaphore capacity in place.
                    let previous = previous_limits
                        .get(skill_id)
                        .map(|l| l.max_concurrent)
                        .unwrap_or(limit.max_concurrent);
                    if limit.max_concurrent > previous {
                        existing.add_permits((limit.max_concurrent - previous) as usize);
                    }
                }
                None => {
                    semaphores.insert(
                        skill_id.clone(),
                        Arc::new(Semaphore::new(limit.max_concurrent as usize)),
                    );
                }
            }
        }
        drop(semaphores);

        let mut skill_limits = self.skill_limits.write().await;
        *skill_limits = limits;
    }

    /// Update runtime specs for timer execution.
    pub async fn set_skill_runtime_specs(&self, specs: HashMap<String, SkillTimerRuntimeSpec>) {
        let mut runtime_specs = self.skill_runtime_specs.write().await;
        *runtime_specs = specs;
    }

    /// Main loop: check for due timers every `check_interval_secs`.
    pub async fn run_loop(&self, shutdown: CancellationToken, error_policy: SkillErrorPolicy) {
        let interval = tokio::time::Duration::from_secs(self.check_interval_secs);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("skill_timer_runner shutting down");
                    break;
                }
                _ = tokio::time::sleep(interval) => {
                    if let Err(e) = self.tick(&error_policy).await {
                        warn!(error = %e, "skill_timer_runner.tick_error");
                    }
                }
            }
        }
    }

    /// One pass: find due timers, fire each that isn't already active.
    pub async fn tick(&self, error_policy: &SkillErrorPolicy) -> Result<u32, String> {
        let now = Utc::now();
        let due_timers = self
            .timer_store
            .list_enabled_due(now)
            .await
            .map_err(|e| format!("failed to list due timers: {e}"))?;

        let mut fired = 0u32;
        for timer in due_timers {
            // Check per-skill rate limit first
            if self.check_rate_limit(&timer.skill_id).await {
                warn!(
                    skill_id = %timer.skill_id,
                    timer = %timer.timer_name,
                    "skill_resource.rate_limit_hit"
                );
                continue;
            }

            match self.try_reserve_timer(&timer.id, &timer.skill_id).await {
                Ok(()) => {}
                Err(ReserveError::AlreadyActive) => {
                    debug!(
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        timer_id = %timer.id,
                        "skill_timer_runner.skip_already_active"
                    );
                    continue;
                }
                Err(ReserveError::PerSkillAtCapacity) => {
                    warn!(
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        "skill_resource.per_skill_capacity"
                    );
                    continue;
                }
                Err(ReserveError::AtCapacity) => {
                    warn!(
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        timer_id = %timer.id,
                        "skill_resource.global_capacity"
                    );
                    break;
                }
            }

            // Increment rate counter after successful reservation
            self.increment_rate_counter(&timer.skill_id).await;

            // Compute expected vs actual for lag measurement
            let expected_tick = timer.next_tick_at.unwrap_or(now);
            let lag_ms = (now - expected_tick).num_milliseconds().max(0);

            let invocation_id = ulid::Ulid::new().to_string();

            // Execute the timer tick via WASM runtime.
            // Panics are converted into timer errors so permit cleanup still runs.
            let execution = AssertUnwindSafe(async {
                let tick_start = std::time::Instant::now();
                let result = self.execute_timer_tick(&timer, &invocation_id).await;
                let tick_duration_ms = tick_start.elapsed().as_millis();
                (result, tick_duration_ms)
            })
            .catch_unwind()
            .await;
            let (result, tick_duration_ms) = match execution {
                Ok(outcome) => outcome,
                Err(payload) => {
                    let panic_msg = if let Some(msg) = payload.downcast_ref::<&str>() {
                        (*msg).to_string()
                    } else if let Some(msg) = payload.downcast_ref::<String>() {
                        msg.clone()
                    } else {
                        "unknown panic payload".to_string()
                    };
                    (Err(format!("timer execution panicked: {panic_msg}")), 0)
                }
            };

            // Audit log the timer tick
            if let Some(ref audit) = self.audit_logger {
                let status = if result.is_ok() { "ok" } else { "error" };
                let detail = serde_json::json!({
                    "invocation_id": invocation_id.as_str(),
                    "skill_id": timer.skill_id,
                    "timer_name": timer.timer_name,
                    "status": status,
                    "duration_ms": tick_duration_ms,
                });
                if let Err(err) = audit.append(
                    "skill",
                    &format!("skill.{}.timer.{}", timer.skill_id, timer.timer_name),
                    Some(&detail.to_string()),
                    Some("timer"),
                ) {
                    warn!(
                        error = %err,
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        "failed to append timer tick audit event"
                    );
                }
            }

            match result {
                Ok(()) => {
                    info!(
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        lag_ms = lag_ms,
                        "skill_timer.tick"
                    );
                    let ticked_at = Utc::now();
                    let next_tick = ticked_at + Duration::seconds(timer.interval_secs as i64);
                    if let Err(err) = self
                        .timer_store
                        .mark_tick(&timer.id, ticked_at, next_tick)
                        .await
                    {
                        warn!(
                            skill_id = %timer.skill_id,
                            timer = %timer.timer_name,
                            error = %err,
                            "skill_timer.mark_tick_failed_after_success"
                        );
                    }
                    if let Err(err) = self.timer_store.reset_failures(&timer.id).await {
                        warn!(
                            skill_id = %timer.skill_id,
                            timer = %timer.timer_name,
                            error = %err,
                            "skill_timer.reset_failures_failed"
                        );
                    }
                }
                Err(e) => {
                    let new_count = self
                        .timer_store
                        .increment_failures(&timer.id)
                        .await
                        .unwrap_or(timer.consecutive_failures + 1);

                    warn!(
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        error = %e,
                        consecutive_failures = new_count,
                        "skill_timer.tick_failed"
                    );

                    // Still advance next_tick so we don't re-fire immediately
                    let ticked_at = Utc::now();
                    let next_tick = ticked_at + Duration::seconds(timer.interval_secs as i64);
                    if let Err(err) = self
                        .timer_store
                        .mark_tick(&timer.id, ticked_at, next_tick)
                        .await
                    {
                        warn!(
                            skill_id = %timer.skill_id,
                            timer = %timer.timer_name,
                            error = %err,
                            "skill_timer.mark_tick_failed_after_error"
                        );
                    }

                    // Auto-disable if threshold reached
                    if error_policy.timer_auto_disable
                        && new_count >= error_policy.timer_max_consecutive_failures
                    {
                        error!(
                            skill_id = %timer.skill_id,
                            timer = %timer.timer_name,
                            reason = %e,
                            consecutive_failures = new_count,
                            "skill_timer.auto_disabled"
                        );
                        let _ = self.timer_store.disable_timer(&timer.id).await;
                        self.audit_timer_auto_disabled(&timer, new_count, &e, &invocation_id);
                    }
                }
            }

            self.mark_timer_complete(&timer.id).await;
            fired += 1;
        }

        Ok(fired)
    }

    async fn execute_timer_tick(
        &self,
        timer: &SkillTimer,
        invocation_id: &str,
    ) -> Result<(), String> {
        let runtime_spec = {
            let specs = self.skill_runtime_specs.read().await;
            specs.get(&timer.skill_id).cloned()
        };
        let Some(runtime_spec) = runtime_spec else {
            return Err({
                warn!(
                    skill_id = %timer.skill_id,
                    timer = %timer.timer_name,
                    "timer runtime spec missing"
                );
                format!(
                    "timer runtime spec missing for skill '{}' (timer '{}')",
                    timer.skill_id, timer.timer_name
                )
            });
        };

        let Some(wasm_deps) = self.wasm_deps.as_ref().cloned() else {
            return Err({
                warn!(
                    skill_id = %timer.skill_id,
                    timer = %timer.timer_name,
                    "timer WASM dependencies missing"
                );
                format!(
                    "timer WASM dependencies missing for skill '{}' (timer '{}')",
                    timer.skill_id, timer.timer_name
                )
            });
        };

        let input_payload = serde_json::json!({
            "timer_id": timer.id,
            "skill_id": timer.skill_id,
            "timer_name": timer.timer_name,
            "last_tick_at": timer.last_tick_at.map(|ts| ts.to_rfc3339()),
            "next_tick_at": timer.next_tick_at.map(|ts| ts.to_rfc3339()),
        });
        let deps = InvokeDeps {
            db_pool: Some(wasm_deps.db_pool.clone()),
            http_client: Some(wasm_deps.http_client.clone()),
            outbound_policy: Some(wasm_deps.outbound_policy.clone()),
            hook_registry: Some(wasm_deps.hook_registry.clone()),
            approval_prompter: Some(wasm_deps.approval_prompter.clone()),
            skill_config: load_skill_runtime_config(&wasm_deps.db_pool, &timer.skill_id),
            execution_context: encmind_wasm_host::ExecutionContext::SkillTimer,
            session_id: None,
            agent_id: None,
            channel: Some("cron".to_string()),
            invocation_id: Some(invocation_id.to_string()),
        };

        let json = runtime_spec
            .invoker
            .invoke_export(
                &timer.export_fn,
                &input_payload,
                &deps,
                runtime_spec.wall_clock_timeout,
            )
            .await
            .map_err(|e| format!("{e}"))?;

        if json.get("action").and_then(|v| v.as_str()) == Some("abort") {
            let reason = json
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("timer aborted by WASM hook");
            return Err(reason.to_string());
        }

        Ok(())
    }

    fn audit_timer_auto_disabled(
        &self,
        timer: &SkillTimer,
        consecutive_failures: u32,
        reason: &str,
        invocation_id: &str,
    ) {
        let Some(audit) = &self.audit_logger else {
            return;
        };

        let detail = serde_json::json!({
            "invocation_id": invocation_id,
            "timer_id": timer.id,
            "timer_name": timer.timer_name,
            "skill_id": timer.skill_id,
            "reason": reason,
            "consecutive_failures": consecutive_failures,
        });
        let detail_str = detail.to_string();
        if let Err(err) = audit.append(
            "skill",
            "timer_auto_disabled",
            Some(detail_str.as_str()),
            Some(timer.skill_id.as_str()),
        ) {
            warn!(
                skill_id = %timer.skill_id,
                timer = %timer.timer_name,
                error = %err,
                "failed to append timer auto-disable audit event"
            );
        }
    }

    /// Check if a skill has exceeded its per-minute invocation rate limit.
    /// Returns `true` if the limit is hit (caller should skip this timer).
    async fn check_rate_limit(&self, skill_id: &str) -> bool {
        let limits = self.skill_limits.read().await;
        let max_rpm = match limits.get(skill_id) {
            Some(l) => l.invocations_per_minute,
            None => return false, // no limit configured
        };
        drop(limits);

        let mut counters = self.rate_counters.lock().await;
        let now = std::time::Instant::now();
        let entry = counters.entry(skill_id.to_string()).or_insert((now, 0));

        // If window has expired (>60s), reset
        if now.duration_since(entry.0).as_secs() >= 60 {
            *entry = (now, 0);
        }

        entry.1 >= max_rpm
    }

    /// Increment the rate counter for a skill after firing a timer.
    async fn increment_rate_counter(&self, skill_id: &str) {
        let mut counters = self.rate_counters.lock().await;
        let now = std::time::Instant::now();
        let entry = counters.entry(skill_id.to_string()).or_insert((now, 0));

        // Reset window if expired
        if now.duration_since(entry.0).as_secs() >= 60 {
            *entry = (now, 1);
        } else {
            entry.1 += 1;
        }
    }

    async fn try_reserve_timer(&self, timer_id: &str, skill_id: &str) -> Result<(), ReserveError> {
        let configured_skill_limit = {
            let limits = self.skill_limits.read().await;
            limits.get(skill_id).map(|l| l.max_concurrent as usize)
        };

        let mut active = self.active_ticks.lock().await;
        if active.contains_key(timer_id) {
            return Err(ReserveError::AlreadyActive);
        }

        if let Some(max_concurrent) = configured_skill_limit {
            let active_for_skill = active
                .values()
                .filter(|permits| permits.skill_id == skill_id)
                .count();
            if active_for_skill >= max_concurrent {
                return Err(ReserveError::PerSkillAtCapacity);
            }
        }

        let per_skill_permit = {
            let semaphores = self.per_skill_semaphores.lock().await;
            match semaphores.get(skill_id) {
                Some(sem) => match sem.clone().try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => return Err(ReserveError::PerSkillAtCapacity),
                },
                None => None,
            }
        };

        match self.global_semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                active.insert(
                    timer_id.to_string(),
                    ActiveTickPermits {
                        skill_id: skill_id.to_string(),
                        _global: permit,
                        _per_skill: per_skill_permit,
                    },
                );
                Ok(())
            }
            Err(_) => Err(ReserveError::AtCapacity),
        }
    }

    pub async fn mark_timer_complete(&self, timer_id: &str) {
        let mut active = self.active_ticks.lock().await;
        active.remove(timer_id); // permit dropped, freeing semaphore slot
    }

    pub async fn is_timer_active(&self, timer_id: &str) -> bool {
        self.active_ticks.lock().await.contains_key(timer_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveError {
    AlreadyActive,
    PerSkillAtCapacity,
    AtCapacity,
}

struct ActiveTickPermits {
    skill_id: String,
    _global: OwnedSemaphorePermit,
    _per_skill: Option<OwnedSemaphorePermit>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::DateTime;
    use encmind_core::error::StorageError;
    use encmind_core::hooks::HookRegistry;
    use encmind_core::traits::CapabilitySet;
    use encmind_core::types::{SkillApprovalRequest, SkillApprovalResponse};
    use encmind_storage::audit::{AuditFilter, AuditLogger};
    use encmind_wasm_host::{ApprovalPrompter, OutboundPolicy};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration as StdDuration;

    /// In-memory mock SkillTimerStore for unit tests.
    struct MockTimerStore {
        timers: Mutex<Vec<SkillTimer>>,
        tick_count: AtomicU32,
        fail_count: AtomicU32,
    }

    impl MockTimerStore {
        fn new(timers: Vec<SkillTimer>) -> Self {
            Self {
                timers: Mutex::new(timers),
                tick_count: AtomicU32::new(0),
                fail_count: AtomicU32::new(0),
            }
        }
    }

    struct AllowAllOutboundPolicy;

    #[async_trait]
    impl OutboundPolicy for AllowAllOutboundPolicy {
        async fn check_url(&self, _url: &str) -> Result<(), String> {
            Ok(())
        }
    }

    struct AutoApprovePrompter;

    #[async_trait]
    impl ApprovalPrompter for AutoApprovePrompter {
        async fn prompt(
            &self,
            request: SkillApprovalRequest,
            _timeout: StdDuration,
        ) -> SkillApprovalResponse {
            SkillApprovalResponse {
                request_id: request.request_id,
                approved: true,
                choice: Some("approve".into()),
            }
        }
    }

    struct SlowApprovePrompter;

    #[async_trait]
    impl ApprovalPrompter for SlowApprovePrompter {
        async fn prompt(
            &self,
            request: SkillApprovalRequest,
            _timeout: StdDuration,
        ) -> SkillApprovalResponse {
            tokio::time::sleep(StdDuration::from_millis(200)).await;
            SkillApprovalResponse {
                request_id: request.request_id,
                approved: true,
                choice: Some("approve".into()),
            }
        }
    }

    #[async_trait]
    impl SkillTimerStore for MockTimerStore {
        async fn list_timers(&self) -> Result<Vec<SkillTimer>, StorageError> {
            Ok(self.timers.lock().await.clone())
        }

        async fn list_enabled_due(
            &self,
            now: DateTime<Utc>,
        ) -> Result<Vec<SkillTimer>, StorageError> {
            let timers = self.timers.lock().await;
            Ok(timers
                .iter()
                .filter(|t| t.enabled && t.next_tick_at.is_some_and(|nt| nt <= now))
                .cloned()
                .collect())
        }

        async fn upsert_timer(&self, timer: &SkillTimer) -> Result<(), StorageError> {
            let mut timers = self.timers.lock().await;
            if let Some(existing) = timers.iter_mut().find(|t| t.id == timer.id) {
                *existing = timer.clone();
            } else {
                timers.push(timer.clone());
            }
            Ok(())
        }

        async fn delete_timers_for_skill(&self, skill_id: &str) -> Result<u64, StorageError> {
            let mut timers = self.timers.lock().await;
            let before = timers.len();
            timers.retain(|t| t.skill_id != skill_id);
            Ok((before - timers.len()) as u64)
        }

        async fn delete_stale_timers(
            &self,
            skill_id: &str,
            keep_names: &[&str],
        ) -> Result<u64, StorageError> {
            let mut timers = self.timers.lock().await;
            let before = timers.len();
            timers
                .retain(|t| t.skill_id != skill_id || keep_names.contains(&t.timer_name.as_str()));
            Ok((before - timers.len()) as u64)
        }

        async fn delete_timers_not_in_skills(
            &self,
            active_skill_ids: &[&str],
        ) -> Result<u64, StorageError> {
            let mut timers = self.timers.lock().await;
            let before = timers.len();
            timers.retain(|t| active_skill_ids.contains(&t.skill_id.as_str()));
            Ok((before - timers.len()) as u64)
        }

        async fn mark_tick(
            &self,
            id: &str,
            _ticked_at: DateTime<Utc>,
            next_tick_at: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            self.tick_count.fetch_add(1, Ordering::SeqCst);
            let mut timers = self.timers.lock().await;
            if let Some(t) = timers.iter_mut().find(|t| t.id == id) {
                t.last_tick_at = Some(Utc::now());
                t.next_tick_at = Some(next_tick_at);
            }
            Ok(())
        }

        async fn increment_failures(&self, id: &str) -> Result<u32, StorageError> {
            self.fail_count.fetch_add(1, Ordering::SeqCst);
            let mut timers = self.timers.lock().await;
            if let Some(t) = timers.iter_mut().find(|t| t.id == id) {
                t.consecutive_failures += 1;
                Ok(t.consecutive_failures)
            } else {
                Err(StorageError::NotFound(format!("timer {id}")))
            }
        }

        async fn reset_failures(&self, id: &str) -> Result<(), StorageError> {
            let mut timers = self.timers.lock().await;
            if let Some(t) = timers.iter_mut().find(|t| t.id == id) {
                t.consecutive_failures = 0;
            }
            Ok(())
        }

        async fn disable_timer(&self, id: &str) -> Result<(), StorageError> {
            let mut timers = self.timers.lock().await;
            if let Some(t) = timers.iter_mut().find(|t| t.id == id) {
                t.enabled = false;
            }
            Ok(())
        }

        async fn enable_timer(
            &self,
            id: &str,
            next_tick_at: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            let mut timers = self.timers.lock().await;
            if let Some(t) = timers.iter_mut().find(|t| t.id == id) {
                t.enabled = true;
                t.consecutive_failures = 0;
                t.next_tick_at = Some(next_tick_at);
            }
            Ok(())
        }
    }

    fn make_due_timer(skill_id: &str, name: &str) -> SkillTimer {
        let now = Utc::now();
        SkillTimer {
            id: format!("{skill_id}:{name}"),
            skill_id: skill_id.to_string(),
            timer_name: name.to_string(),
            interval_secs: 120,
            export_fn: "on_tick".to_string(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now - Duration::seconds(10)),
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_future_timer(skill_id: &str, name: &str) -> SkillTimer {
        let now = Utc::now();
        SkillTimer {
            id: format!("{skill_id}:{name}"),
            skill_id: skill_id.to_string(),
            timer_name: name.to_string(),
            interval_secs: 120,
            export_fn: "on_tick".to_string(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now + Duration::hours(1)),
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: now,
            updated_at: now,
        }
    }

    fn default_error_policy() -> SkillErrorPolicy {
        SkillErrorPolicy::default()
    }

    fn empty_capabilities() -> CapabilitySet {
        CapabilitySet {
            net_outbound: vec![],
            fs_read: vec![],
            fs_write: vec![],
            exec_shell: false,
            env_secrets: false,
            kv: false,
            prompt_user: false,
            emit_events: vec![],
            hooks: vec![],
            schedule_timers: false,
            schedule_transforms: vec![],
        }
    }

    fn make_test_timer_wasm_deps() -> TimerWasmDependencies {
        TimerWasmDependencies {
            db_pool: Arc::new(encmind_storage::pool::create_test_pool()),
            http_client: Arc::new(reqwest::Client::new()),
            outbound_policy: Arc::new(AllowAllOutboundPolicy),
            hook_registry: Arc::new(RwLock::new(HookRegistry::new())),
            approval_prompter: Arc::new(AutoApprovePrompter),
        }
    }

    fn make_slow_prompt_timer_wasm_deps() -> TimerWasmDependencies {
        TimerWasmDependencies {
            db_pool: Arc::new(encmind_storage::pool::create_test_pool()),
            http_client: Arc::new(reqwest::Client::new()),
            outbound_policy: Arc::new(AllowAllOutboundPolicy),
            hook_registry: Arc::new(RwLock::new(HookRegistry::new())),
            approval_prompter: Arc::new(SlowApprovePrompter),
        }
    }

    fn compile_test_module(wat: &str, consume_fuel: bool) -> (wasmtime::Engine, wasmtime::Module) {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        config.consume_fuel(consume_fuel);
        let engine = wasmtime::Engine::new(&config).expect("create test engine");
        let module = wasmtime::Module::new(&engine, wat).expect("compile test module");
        (engine, module)
    }

    fn build_runtime_specs_for_skills(
        skill_ids: &[&str],
        wat: &str,
        fuel_limit: u64,
        timeout_ms: u64,
    ) -> HashMap<String, SkillTimerRuntimeSpec> {
        build_runtime_specs_for_skills_with_fuel_tracking(
            skill_ids, wat, fuel_limit, timeout_ms, true,
        )
    }

    fn build_runtime_specs_for_skills_with_fuel_tracking(
        skill_ids: &[&str],
        wat: &str,
        fuel_limit: u64,
        timeout_ms: u64,
        consume_fuel: bool,
    ) -> HashMap<String, SkillTimerRuntimeSpec> {
        build_runtime_specs_with_capabilities(
            skill_ids,
            wat,
            fuel_limit,
            timeout_ms,
            consume_fuel,
            empty_capabilities(),
        )
    }

    fn build_runtime_specs_with_capabilities(
        skill_ids: &[&str],
        wat: &str,
        fuel_limit: u64,
        timeout_ms: u64,
        consume_fuel: bool,
        capabilities: CapabilitySet,
    ) -> HashMap<String, SkillTimerRuntimeSpec> {
        let (engine, module) = compile_test_module(wat, consume_fuel);
        skill_ids
            .iter()
            .map(|skill_id| {
                let invoker = Arc::new(SkillInvoker::new(
                    engine.clone(),
                    module.clone(),
                    encmind_wasm_host::SkillAbi::Native,
                    (*skill_id).to_string(),
                    capabilities.clone(),
                    fuel_limit,
                    64,
                ));
                (
                    (*skill_id).to_string(),
                    SkillTimerRuntimeSpec {
                        invoker,
                        wall_clock_timeout: StdDuration::from_millis(timeout_ms.max(1)),
                    },
                )
            })
            .collect()
    }

    fn echo_timer_wat(export_fn: &str) -> String {
        format!(
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (i64.or
                        (i64.shl (i64.extend_i32_u (local.get 0)) (i64.const 32))
                        (i64.extend_i32_u (local.get 1))
                    )
                )
            )"#
        )
    }

    fn static_json_timer_wat(export_fn: &str, json: &str) -> String {
        let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
        let len = json.len();
        format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 2048) "{escaped}")
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (i64.or
                        (i64.shl (i64.const 2048) (i64.const 32))
                        (i64.const {len})
                    )
                )
            )"#
        )
    }

    fn spin_timer_wat(export_fn: &str) -> String {
        format!(
            r#"(module
                (memory (export "memory") 1)
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (loop $spin
                        br $spin
                    )
                    i64.const 0
                )
            )"#
        )
    }

    fn approval_wait_timer_wat(export_fn: &str) -> String {
        let prompt = r#"{"prompt":"wait"}"#;
        let escaped = prompt.replace('\\', "\\\\").replace('"', "\\\"");
        let len = prompt.len();
        format!(
            r#"(module
                (import "encmind" "__encmind_approval_prompt" (func $prompt (param i32 i32) (result i64)))
                (memory (export "memory") 1)
                (data (i32.const 0) "{escaped}")
                (func (export "__encmind_alloc") (param i32) (result i32) i32.const 1024)
                (func (export "{export_fn}") (param i32 i32) (result i64)
                    (call $prompt (i32.const 0) (i32.const {len}))
                )
            )"#
        )
    }

    #[tokio::test]
    async fn runner_creation() {
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner = SkillTimerRunner::new(store, 4, 10);
        assert_eq!(runner.global_semaphore.available_permits(), 4);
    }

    #[tokio::test]
    async fn fires_due_timer() {
        let timer = make_due_timer("skill-a", "heartbeat");
        let store = Arc::new(MockTimerStore::new(vec![timer]));
        let runner = SkillTimerRunner::new(store.clone(), 4, 10)
            .with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-a"],
                &echo_timer_wat("on_tick"),
                1_000_000,
                500,
            ))
            .await;

        let fired = runner.tick(&default_error_policy()).await.unwrap();
        assert_eq!(fired, 1);
        assert_eq!(store.tick_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_future_timer() {
        let timer = make_future_timer("skill-a", "heartbeat");
        let store = Arc::new(MockTimerStore::new(vec![timer]));
        let runner = SkillTimerRunner::new(store.clone(), 4, 10);

        let fired = runner.tick(&default_error_policy()).await.unwrap();
        assert_eq!(fired, 0);
    }

    #[tokio::test]
    async fn skips_already_active_timer() {
        let timer = make_due_timer("skill-a", "heartbeat");
        let timer_id = timer.id.clone();
        let store = Arc::new(MockTimerStore::new(vec![timer]));
        let runner = SkillTimerRunner::new(store.clone(), 4, 10);

        // Pre-insert as active
        let permit = runner.global_semaphore.clone().try_acquire_owned().unwrap();
        runner.active_ticks.lock().await.insert(
            timer_id.clone(),
            ActiveTickPermits {
                skill_id: "skill-a".into(),
                _global: permit,
                _per_skill: None,
            },
        );

        let fired = runner.tick(&default_error_policy()).await.unwrap();
        assert_eq!(fired, 0);
    }

    #[tokio::test]
    async fn respects_global_semaphore_limit() {
        let timers = vec![
            make_due_timer("s1", "t1"),
            make_due_timer("s2", "t2"),
            make_due_timer("s3", "t3"),
        ];
        let store = Arc::new(MockTimerStore::new(timers));
        let runner = SkillTimerRunner::new(store.clone(), 2, 10);

        // Pre-exhaust both permits so 0 slots remain
        let _held1 = runner.global_semaphore.clone().try_acquire_owned().unwrap();
        let _held2 = runner.global_semaphore.clone().try_acquire_owned().unwrap();
        assert_eq!(runner.global_semaphore.available_permits(), 0);

        let fired = runner.tick(&default_error_policy()).await.unwrap();
        assert_eq!(fired, 0, "should fire nothing when semaphore exhausted");
    }

    #[tokio::test]
    async fn marks_tick_after_completion() {
        let timer = make_due_timer("skill-a", "check");
        let store = Arc::new(MockTimerStore::new(vec![timer.clone()]));
        let runner = SkillTimerRunner::new(store.clone(), 4, 10)
            .with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-a"],
                &echo_timer_wat("on_tick"),
                1_000_000,
                500,
            ))
            .await;

        runner.tick(&default_error_policy()).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        let updated = timers.iter().find(|t| t.id == timer.id).unwrap();
        assert!(updated.last_tick_at.is_some());
        assert!(updated.next_tick_at.unwrap() > Utc::now());
    }

    #[tokio::test]
    async fn respects_shutdown_token() {
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner = Arc::new(SkillTimerRunner::new(store, 4, 10));
        let shutdown = CancellationToken::new();
        let policy = default_error_policy();

        let runner_clone = runner.clone();
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(async move {
            runner_clone.run_loop(shutdown_clone, policy).await;
        });

        // Cancel immediately
        shutdown.cancel();
        // Should exit promptly
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("runner should stop within 2s")
            .expect("runner task should not panic");
    }

    #[tokio::test]
    async fn reconcile_upserts_and_deletes_stale() {
        let existing = SkillTimer {
            id: "skill-a:old-timer".into(),
            skill_id: "skill-a".into(),
            timer_name: "old-timer".into(),
            interval_secs: 60,
            export_fn: "on_old".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: None,
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let store = Arc::new(MockTimerStore::new(vec![existing]));

        let new_decls = vec![TimerDeclaration {
            name: "new-timer".into(),
            interval_secs: 120,
            export_fn: "on_new".into(),
            description: String::new(),
        }];

        reconcile_skill_timers(store.as_ref(), "skill-a", &new_decls, "hash1")
            .await
            .unwrap();

        let timers = store.list_timers().await.unwrap();
        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].timer_name, "new-timer");
    }

    #[tokio::test]
    async fn reconcile_all_cleans_orphan_skills() {
        let orphan = SkillTimer {
            id: "removed-skill:timer".into(),
            skill_id: "removed-skill".into(),
            timer_name: "timer".into(),
            interval_secs: 60,
            export_fn: "on_tick".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: None,
            source_manifest_hash: None,
            consecutive_failures: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let store = Arc::new(MockTimerStore::new(vec![orphan]));

        // No loaded skills — all timers should be cleaned up
        reconcile_all_timers(store.as_ref(), &[]).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert!(timers.is_empty());
    }

    #[tokio::test]
    async fn auto_disable_after_consecutive_failures() {
        // Create a runner with a store containing a timer that has consecutive_failures
        // just below the threshold.
        let now = Utc::now();
        let timer = SkillTimer {
            id: "fail-skill:check".into(),
            skill_id: "fail-skill".into(),
            timer_name: "check".into(),
            interval_secs: 60,
            export_fn: "on_check".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now - Duration::seconds(5)),
            source_manifest_hash: None,
            consecutive_failures: 4, // threshold is 5, one more failure → disable
            created_at: now,
            updated_at: now,
        };

        let store = Arc::new(MockTimerStore::new(vec![timer]));

        // Use a custom runner that forces failure
        let runner = FailingTimerRunner {
            inner: SkillTimerRunner::new(store.clone(), 4, 10),
        };

        let policy = SkillErrorPolicy {
            timer_max_consecutive_failures: 5,
            timer_auto_disable: true,
            ..Default::default()
        };

        runner.tick_with_failure(&policy).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        let t = &timers[0];
        assert!(!t.enabled, "timer should be auto-disabled after 5 failures");
        assert_eq!(t.consecutive_failures, 5);
    }

    #[tokio::test]
    async fn successful_tick_resets_failure_count() {
        let now = Utc::now();
        let timer = SkillTimer {
            id: "skill-x:check".into(),
            skill_id: "skill-x".into(),
            timer_name: "check".into(),
            interval_secs: 60,
            export_fn: "on_check".into(),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(now - Duration::seconds(5)),
            source_manifest_hash: None,
            consecutive_failures: 3,
            created_at: now,
            updated_at: now,
        };

        let store = Arc::new(MockTimerStore::new(vec![timer]));
        let runner = SkillTimerRunner::new(store.clone(), 4, 10)
            .with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-x"],
                &echo_timer_wat("on_check"),
                1_000_000,
                500,
            ))
            .await;

        runner.tick(&default_error_policy()).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert_eq!(timers[0].consecutive_failures, 0);
    }

    #[tokio::test]
    async fn enforces_per_skill_concurrency_limit() {
        // Two timers for the same skill, per-skill limit of 1
        let timers = vec![
            make_due_timer("skill-a", "t1"),
            make_due_timer("skill-a", "t2"),
        ];
        let store = Arc::new(MockTimerStore::new(timers));
        let runner = SkillTimerRunner::new(store.clone(), 10, 10)
            .with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-a"],
                &echo_timer_wat("on_tick"),
                1_000_000,
                500,
            ))
            .await;

        // Set per-skill limit to 1 concurrent
        let mut limits = HashMap::new();
        limits.insert(
            "skill-a".into(),
            SkillTimerLimits {
                max_concurrent: 1,
                invocations_per_minute: 60,
            },
        );
        runner.set_skill_limits(limits).await;

        // Pre-exhaust the per-skill semaphore (simulate an active timer for skill-a)
        {
            let semaphores = runner.per_skill_semaphores.lock().await;
            let sem = semaphores.get("skill-a").unwrap();
            let _permit = sem.clone().try_acquire_owned().unwrap();
            assert_eq!(sem.available_permits(), 0);
            drop(semaphores);

            // With semaphore exhausted, tick should skip both timers
            let fired = runner.tick(&default_error_policy()).await.unwrap();
            assert_eq!(
                fired, 0,
                "should skip timers when per-skill semaphore exhausted"
            );
        }
        // After _permit drops, the semaphore is restored — verify timers fire now
        let fired = runner.tick(&default_error_policy()).await.unwrap();
        assert_eq!(
            fired, 2,
            "should fire timers after per-skill semaphore freed"
        );
    }

    #[tokio::test]
    async fn enforces_rate_limit() {
        let timers = vec![
            make_due_timer("skill-a", "t1"),
            make_due_timer("skill-a", "t2"),
            make_due_timer("skill-a", "t3"),
        ];
        let store = Arc::new(MockTimerStore::new(timers));
        let runner = SkillTimerRunner::new(store.clone(), 10, 10)
            .with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-a"],
                &echo_timer_wat("on_tick"),
                1_000_000,
                500,
            ))
            .await;

        // Set per-skill rate limit to 2 invocations per minute
        let mut limits = HashMap::new();
        limits.insert(
            "skill-a".into(),
            SkillTimerLimits {
                max_concurrent: 10,
                invocations_per_minute: 2,
            },
        );
        runner.set_skill_limits(limits).await;

        let fired = runner.tick(&default_error_policy()).await.unwrap();
        assert_eq!(fired, 2, "should fire only 2 timers before rate limit");
    }

    #[tokio::test]
    async fn set_skill_limits_rebuilds_semaphores() {
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner = SkillTimerRunner::new(store, 10, 10);

        let mut limits = HashMap::new();
        limits.insert(
            "skill-x".into(),
            SkillTimerLimits {
                max_concurrent: 3,
                invocations_per_minute: 100,
            },
        );
        runner.set_skill_limits(limits).await;

        let semaphores = runner.per_skill_semaphores.lock().await;
        let sem = semaphores.get("skill-x").unwrap();
        assert_eq!(sem.available_permits(), 3);
    }

    #[tokio::test]
    async fn set_skill_limits_resets_capacity_exactly_when_inactive() {
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner = SkillTimerRunner::new(store, 10, 10);

        let mut limits = HashMap::new();
        limits.insert(
            "skill-x".into(),
            SkillTimerLimits {
                max_concurrent: 3,
                invocations_per_minute: 100,
            },
        );
        runner.set_skill_limits(limits).await;

        let mut limits = HashMap::new();
        limits.insert(
            "skill-x".into(),
            SkillTimerLimits {
                max_concurrent: 1,
                invocations_per_minute: 100,
            },
        );
        runner.set_skill_limits(limits).await;

        let semaphores = runner.per_skill_semaphores.lock().await;
        let sem = semaphores.get("skill-x").unwrap();
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn set_skill_limits_refresh_does_not_bypass_active_per_skill_limit() {
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner = SkillTimerRunner::new(store, 10, 10);

        let mut limits = HashMap::new();
        limits.insert(
            "skill-a".into(),
            SkillTimerLimits {
                max_concurrent: 1,
                invocations_per_minute: 60,
            },
        );
        runner.set_skill_limits(limits.clone()).await;

        assert!(matches!(
            runner.try_reserve_timer("skill-a:t1", "skill-a").await,
            Ok(())
        ));

        // Simulate refresh while a timer is still active for this skill.
        runner.set_skill_limits(limits).await;

        assert!(matches!(
            runner.try_reserve_timer("skill-a:t2", "skill-a").await,
            Err(ReserveError::PerSkillAtCapacity)
        ));

        runner.mark_timer_complete("skill-a:t1").await;
        assert!(matches!(
            runner.try_reserve_timer("skill-a:t2", "skill-a").await,
            Ok(())
        ));
        runner.mark_timer_complete("skill-a:t2").await;
    }

    #[tokio::test]
    async fn missing_runtime_spec_counts_as_failure_and_auto_disables() {
        let timer = make_due_timer("missing-skill", "heartbeat");
        let store = Arc::new(MockTimerStore::new(vec![timer]));
        let pool = encmind_storage::pool::create_test_pool();
        {
            let conn = pool.get().expect("get db conn");
            encmind_storage::migrations::run_migrations(&conn).expect("run migrations");
        }
        let audit = Arc::new(AuditLogger::new(pool));
        let runner = SkillTimerRunner::new(store.clone(), 4, 10)
            .with_wasm_dependencies(make_test_timer_wasm_deps())
            .with_audit_logger(audit.clone());

        let policy = SkillErrorPolicy {
            timer_auto_disable: true,
            timer_max_consecutive_failures: 1,
            ..Default::default()
        };

        let fired = runner.tick(&policy).await.unwrap();
        assert_eq!(fired, 1);

        let timers = store.list_timers().await.unwrap();
        assert_eq!(timers[0].consecutive_failures, 1);
        assert!(
            !timers[0].enabled,
            "timer should auto-disable after missing runtime spec"
        );

        let entries = audit
            .query(
                AuditFilter {
                    action: Some("timer_auto_disabled".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .expect("query audit entries");
        assert_eq!(
            entries.len(),
            1,
            "expected one timer auto-disable audit entry"
        );
        let detail = entries[0].detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("runtime spec missing"),
            "unexpected audit detail: {detail}"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(detail).expect("timer auto-disable detail must be JSON");
        assert!(
            parsed
                .get("invocation_id")
                .and_then(|v| v.as_str())
                .is_some_and(|v| !v.trim().is_empty()),
            "expected invocation_id in audit detail: {detail}"
        );
    }

    #[tokio::test]
    async fn execute_timer_tick_returns_abort_reason() {
        let mut timer = make_due_timer("skill-abort", "heartbeat");
        timer.export_fn = "on_abort".into();
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner =
            SkillTimerRunner::new(store, 4, 10).with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-abort"],
                &static_json_timer_wat("on_abort", r#"{"action":"abort","reason":"stop-now"}"#),
                1_000_000,
                500,
            ))
            .await;

        let err = runner
            .execute_timer_tick(&timer, "invocation-test")
            .await
            .unwrap_err();
        assert!(err.contains("stop-now"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn execute_timer_tick_fast_denies_approval() {
        // In SkillTimer context, approval prompts get fast-denied instead of blocking.
        let mut timer = make_due_timer("skill-timeout", "heartbeat");
        timer.export_fn = "on_wait_prompt".into();
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner = SkillTimerRunner::new(store, 4, 10)
            .with_wasm_dependencies(make_slow_prompt_timer_wasm_deps());
        let mut caps = empty_capabilities();
        caps.prompt_user = true;
        let specs = build_runtime_specs_with_capabilities(
            &["skill-timeout"],
            &approval_wait_timer_wat("on_wait_prompt"),
            1_000_000,
            20,
            true,
            caps,
        );
        runner.set_skill_runtime_specs(specs).await;

        // Fast-deny means the invocation completes immediately (no timeout)
        let result = runner.execute_timer_tick(&timer, "invocation-test").await;
        assert!(
            result.is_ok(),
            "expected fast-deny to succeed, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn execute_timer_tick_fails_on_fuel_exhaustion() {
        let mut timer = make_due_timer("skill-fuel", "heartbeat");
        timer.export_fn = "on_spin".into();
        let store = Arc::new(MockTimerStore::new(vec![]));
        let runner =
            SkillTimerRunner::new(store, 4, 10).with_wasm_dependencies(make_test_timer_wasm_deps());
        runner
            .set_skill_runtime_specs(build_runtime_specs_for_skills(
                &["skill-fuel"],
                &spin_timer_wat("on_spin"),
                50,
                1_000,
            ))
            .await;

        let err = runner
            .execute_timer_tick(&timer, "invocation-test")
            .await
            .unwrap_err();
        let lower = err.to_lowercase();
        assert!(
            lower.contains("fuel")
                || lower.contains("out of fuel")
                || lower.contains("invocation failed"),
            "unexpected error: {err}"
        );
        assert!(
            !lower.contains("timed out"),
            "expected trap-style failure, got timeout: {err}"
        );
    }

    /// Helper that overrides execute_timer_tick to always fail.
    struct FailingTimerRunner {
        inner: SkillTimerRunner,
    }

    impl FailingTimerRunner {
        async fn tick_with_failure(&self, error_policy: &SkillErrorPolicy) -> Result<u32, String> {
            let now = Utc::now();
            let due_timers = self
                .inner
                .timer_store
                .list_enabled_due(now)
                .await
                .map_err(|e| format!("list failed: {e}"))?;

            let mut fired = 0u32;
            for timer in due_timers {
                match self
                    .inner
                    .try_reserve_timer(&timer.id, &timer.skill_id)
                    .await
                {
                    Ok(()) => {}
                    Err(ReserveError::AlreadyActive) => continue,
                    Err(ReserveError::PerSkillAtCapacity) => continue,
                    Err(ReserveError::AtCapacity) => break,
                }

                // Force failure
                let e = "forced test failure";

                let new_count = self
                    .inner
                    .timer_store
                    .increment_failures(&timer.id)
                    .await
                    .unwrap_or(timer.consecutive_failures + 1);

                // Advance next_tick
                let ticked_at = Utc::now();
                let next_tick = ticked_at + Duration::seconds(timer.interval_secs as i64);
                let _ = self
                    .inner
                    .timer_store
                    .mark_tick(&timer.id, ticked_at, next_tick)
                    .await;

                if error_policy.timer_auto_disable
                    && new_count >= error_policy.timer_max_consecutive_failures
                {
                    error!(
                        skill_id = %timer.skill_id,
                        timer = %timer.timer_name,
                        consecutive_failures = new_count,
                        "skill_timer.auto_disabled"
                    );
                    let _ = self.inner.timer_store.disable_timer(&timer.id).await;
                }

                self.inner.mark_timer_complete(&timer.id).await;
                fired += 1;

                let _ = e; // suppress unused warning
            }
            Ok(fired)
        }
    }
}
