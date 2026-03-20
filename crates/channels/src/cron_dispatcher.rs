use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use encmind_core::error::StorageError;
use encmind_core::traits::CronStore;

/// Dispatches due cron jobs with its own semaphore to prevent starving interactive sessions.
/// Permits are held in `active_jobs` for the duration of each job's execution.
pub struct CronDispatcher {
    cron_store: Arc<dyn CronStore>,
    semaphore: Arc<Semaphore>,
    active_jobs: Mutex<HashMap<String, OwnedSemaphorePermit>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReserveJobError {
    AlreadyActive,
    AtCapacity,
}

impl CronDispatcher {
    pub fn new(cron_store: Arc<dyn CronStore>, max_concurrent: usize) -> Self {
        Self {
            cron_store,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            active_jobs: Mutex::new(HashMap::new()),
        }
    }

    /// Check for due jobs and dispatch them. Returns the count of jobs dispatched.
    pub async fn tick(&self) -> Result<u32, StorageError> {
        let jobs = self.dispatch_due_jobs().await?;
        Ok(jobs.len() as u32)
    }

    /// Check for due jobs and reserve permits for execution.
    /// Returns the jobs that should be executed by the caller.
    pub async fn dispatch_due_jobs(
        &self,
    ) -> Result<Vec<encmind_core::types::CronJob>, StorageError> {
        let due_jobs = self.cron_store.list_due_jobs(Utc::now()).await?;
        let mut dispatched_jobs = Vec::new();

        for job in due_jobs {
            match self.try_reserve_job_internal(job.id.as_str()).await {
                Ok(()) => dispatched_jobs.push(job),
                Err(ReserveJobError::AlreadyActive) => {
                    // Stale detection: job already has an in-flight run
                    continue;
                }
                Err(ReserveJobError::AtCapacity) => {
                    // No permits available — stop dispatching this tick
                    break;
                }
            }
        }

        Ok(dispatched_jobs)
    }

    /// Try to reserve a concurrency slot for the given job.
    /// Returns Ok(()) if the job was successfully reserved (permit acquired, tracked in active_jobs).
    /// Returns Err with a message if the job is already active or the concurrency limit is reached.
    pub async fn try_reserve_job(&self, job_id: &str) -> Result<(), String> {
        match self.try_reserve_job_internal(job_id).await {
            Ok(()) => Ok(()),
            Err(ReserveJobError::AlreadyActive) => {
                Err(format!("cron job {job_id} is already running"))
            }
            Err(ReserveJobError::AtCapacity) => Err("cron concurrency limit reached".to_string()),
        }
    }

    /// Atomically reserve a concurrency slot for a job.
    /// Locking active_jobs for check+insert avoids races with concurrent reserve paths.
    async fn try_reserve_job_internal(&self, job_id: &str) -> Result<(), ReserveJobError> {
        let mut active = self.active_jobs.lock().await;
        if active.contains_key(job_id) {
            return Err(ReserveJobError::AlreadyActive);
        }
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                active.insert(job_id.to_string(), permit);
                Ok(())
            }
            Err(_) => Err(ReserveJobError::AtCapacity),
        }
    }

    pub async fn is_job_active(&self, job_id: &str) -> bool {
        let active = self.active_jobs.lock().await;
        active.contains_key(job_id)
    }

    /// Mark a job as complete. Drops the semaphore permit, freeing a slot.
    pub async fn mark_job_complete(&self, job_id: &str) {
        let mut active = self.active_jobs.lock().await;
        active.remove(job_id); // permit is dropped here, releasing the semaphore slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use encmind_core::types::{AgentId, CronJob, CronJobId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Simple in-memory CronStore mock
    struct MockCronStore {
        jobs: Mutex<Vec<CronJob>>,
        mark_started_calls: AtomicUsize,
    }

    impl MockCronStore {
        fn new(jobs: Vec<CronJob>) -> Self {
            Self {
                jobs: Mutex::new(jobs),
                mark_started_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl CronStore for MockCronStore {
        async fn list_jobs(&self) -> Result<Vec<CronJob>, StorageError> {
            Ok(self.jobs.lock().await.clone())
        }
        async fn get_job(&self, id: &CronJobId) -> Result<Option<CronJob>, StorageError> {
            let jobs = self.jobs.lock().await;
            Ok(jobs.iter().find(|j| j.id == *id).cloned())
        }
        async fn create_job(&self, job: &CronJob) -> Result<(), StorageError> {
            self.jobs.lock().await.push(job.clone());
            Ok(())
        }
        async fn update_job(&self, _job: &CronJob) -> Result<(), StorageError> {
            Ok(())
        }
        async fn delete_job(&self, _id: &CronJobId) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list_due_jobs(&self, now: DateTime<Utc>) -> Result<Vec<CronJob>, StorageError> {
            let jobs = self.jobs.lock().await;
            Ok(jobs
                .iter()
                .filter(|j| j.enabled && j.next_run_at.is_some_and(|t| t <= now))
                .cloned()
                .collect())
        }
        async fn mark_run_started(
            &self,
            _id: &CronJobId,
            _started_at: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            self.mark_started_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn mark_run_completed(
            &self,
            _id: &CronJobId,
            _next_run_at: DateTime<Utc>,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn make_due_job(name: &str) -> CronJob {
        CronJob {
            id: CronJobId::new(),
            name: name.into(),
            schedule: "* * * * *".into(),
            prompt: "run".into(),
            agent_id: AgentId::default(),
            model: None,
            max_concurrent_runs: 4,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now() - chrono::Duration::minutes(1)),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn tick_dispatches_due_jobs() {
        let jobs = vec![make_due_job("job-a"), make_due_job("job-b")];
        let store = Arc::new(MockCronStore::new(jobs));
        let dispatcher = CronDispatcher::new(store, 4);
        let dispatched = dispatcher.tick().await.unwrap();
        assert_eq!(dispatched, 2);
    }

    #[tokio::test]
    async fn stale_job_skipped() {
        let job = make_due_job("stale");
        let job_id = job.id.as_str().to_string();
        let store = Arc::new(MockCronStore::new(vec![job]));
        let dispatcher = CronDispatcher::new(store, 4);

        // Pre-insert the job as active with a real permit
        let permit = dispatcher.semaphore.clone().try_acquire_owned().unwrap();
        dispatcher
            .active_jobs
            .lock()
            .await
            .insert(job_id.clone(), permit);

        let dispatched = dispatcher.tick().await.unwrap();
        assert_eq!(dispatched, 0);
    }

    #[tokio::test]
    async fn semaphore_bounds_concurrency() {
        let jobs = vec![make_due_job("j1"), make_due_job("j2"), make_due_job("j3")];
        let store = Arc::new(MockCronStore::new(jobs));
        // Only allow 2 concurrent
        let dispatcher = CronDispatcher::new(store, 2);
        let dispatched = dispatcher.tick().await.unwrap();
        assert_eq!(dispatched, 2, "should stop at semaphore limit");

        // Available permits should be 0
        assert_eq!(dispatcher.semaphore.available_permits(), 0);

        // Complete one job — frees a permit
        let first_key = {
            let active = dispatcher.active_jobs.lock().await;
            active.keys().next().unwrap().clone()
        };
        dispatcher.mark_job_complete(&first_key).await;
        assert_eq!(dispatcher.semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn try_reserve_rejects_already_active_job() {
        let job = make_due_job("reserve-test");
        let job_id = job.id.as_str().to_string();
        let store = Arc::new(MockCronStore::new(vec![job]));
        let dispatcher = CronDispatcher::new(store, 4);

        // First reserve should succeed
        dispatcher.try_reserve_job(&job_id).await.unwrap();
        assert!(dispatcher.is_job_active(&job_id).await);

        // Second reserve for the same job should fail
        let err = dispatcher.try_reserve_job(&job_id).await.unwrap_err();
        assert!(err.contains("already running"));

        // After completing, reserve should succeed again
        dispatcher.mark_job_complete(&job_id).await;
        dispatcher.try_reserve_job(&job_id).await.unwrap();
    }

    #[tokio::test]
    async fn try_reserve_rejects_when_at_capacity() {
        let store = Arc::new(MockCronStore::new(vec![]));
        let dispatcher = CronDispatcher::new(store, 1);

        dispatcher.try_reserve_job("job-a").await.unwrap();
        let err = dispatcher.try_reserve_job("job-b").await.unwrap_err();
        assert!(err.contains("concurrency limit"));
    }

    #[tokio::test]
    async fn dispatch_due_jobs_does_not_mark_started() {
        let store = Arc::new(MockCronStore::new(vec![make_due_job("job-a")]));
        let dispatcher = CronDispatcher::new(store.clone(), 1);

        let jobs = dispatcher.dispatch_due_jobs().await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(
            store.mark_started_calls.load(Ordering::SeqCst),
            0,
            "dispatcher should only reserve permits; run state is handled by execution path"
        );
    }
}
