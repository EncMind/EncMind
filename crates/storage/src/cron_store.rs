use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::CronStore;
use encmind_core::types::{AgentId, CronJob, CronJobId};

pub struct SqliteCronStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteCronStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

fn row_to_cron_job(row: &rusqlite::Row<'_>) -> Result<CronJob, rusqlite::Error> {
    let id: String = row.get("id")?;
    let name: String = row.get("name")?;
    let schedule: String = row.get("schedule")?;
    let prompt: String = row.get("prompt")?;
    let agent_id: String = row.get("agent_id")?;
    let model: Option<String> = row.get("model")?;
    let max_concurrent_runs: i64 = row.get("max_concurrent_runs")?;
    let enabled: bool = row.get("enabled")?;
    let last_run_at: Option<String> = row.get("last_run_at")?;
    let next_run_at: Option<String> = row.get("next_run_at")?;
    let created_at: String = row.get("created_at")?;

    let parsed_last_run_at = match last_run_at {
        Some(ref s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        8,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
        ),
        None => None,
    };

    let parsed_next_run_at = match next_run_at {
        Some(ref s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        9,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
        ),
        None => None,
    };

    let parsed_created_at = DateTime::parse_from_rfc3339(&created_at)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(CronJob {
        id: CronJobId::from_string(id),
        name,
        schedule,
        prompt,
        agent_id: AgentId::new(agent_id),
        model,
        max_concurrent_runs: max_concurrent_runs as u32,
        enabled,
        last_run_at: parsed_last_run_at,
        next_run_at: parsed_next_run_at,
        created_at: parsed_created_at,
    })
}

fn dt_to_string(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[async_trait]
impl CronStore for SqliteCronStore {
    async fn list_jobs(&self) -> Result<Vec<CronJob>, StorageError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare("SELECT * FROM cron_jobs ORDER BY created_at")
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let jobs = stmt
                .query_map([], row_to_cron_job)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(jobs)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn get_job(&self, id: &CronJobId) -> Result<Option<CronJob>, StorageError> {
        let pool = self.pool.clone();
        let id = id.0.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare("SELECT * FROM cron_jobs WHERE id = ?1")
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut rows = stmt
                .query_map(rusqlite::params![id], row_to_cron_job)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            match rows.next() {
                Some(row) => Ok(Some(row.map_err(|e| StorageError::Sqlite(e.to_string()))?)),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn create_job(&self, job: &CronJob) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let job = job.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| StorageError::Sqlite(e.to_string()))?;
            conn.execute(
                "INSERT INTO cron_jobs (id, name, schedule, prompt, agent_id, model, max_concurrent_runs, enabled, last_run_at, next_run_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    job.id.as_str(),
                    job.name,
                    job.schedule,
                    job.prompt,
                    job.agent_id.as_str(),
                    job.model,
                    job.max_concurrent_runs as i64,
                    job.enabled,
                    job.last_run_at.map(|d| dt_to_string(&d)),
                    job.next_run_at.map(|d| dt_to_string(&d)),
                    dt_to_string(&job.created_at),
                ],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn update_job(&self, job: &CronJob) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let job = job.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute(
                    "UPDATE cron_jobs SET name=?2, schedule=?3, prompt=?4, agent_id=?5, model=?6, max_concurrent_runs=?7, enabled=?8, next_run_at=?9 WHERE id=?1",
                    rusqlite::params![
                        job.id.as_str(),
                        job.name,
                        job.schedule,
                        job.prompt,
                        job.agent_id.as_str(),
                        job.model,
                        job.max_concurrent_runs as i64,
                        job.enabled,
                        job.next_run_at.map(|d| dt_to_string(&d)),
                    ],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("cron job {}", job.id)));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn delete_job(&self, id: &CronJobId) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.0.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute("DELETE FROM cron_jobs WHERE id = ?1", rusqlite::params![id])
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("cron job {id}")));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn list_due_jobs(&self, now: DateTime<Utc>) -> Result<Vec<CronJob>, StorageError> {
        let pool = self.pool.clone();
        let now_str = dt_to_string(&now);
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare("SELECT * FROM cron_jobs WHERE enabled = 1 AND next_run_at <= ?1")
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let jobs = stmt
                .query_map(rusqlite::params![now_str], row_to_cron_job)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(jobs)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn mark_run_started(
        &self,
        id: &CronJobId,
        started_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.0.clone();
        let started_str = dt_to_string(&started_at);
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute(
                    "UPDATE cron_jobs SET last_run_at = ?2 WHERE id = ?1",
                    rusqlite::params![id, started_str],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("cron job {id}")));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn mark_run_completed(
        &self,
        id: &CronJobId,
        next_run_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.0.clone();
        let next_str = dt_to_string(&next_run_at);
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute(
                    "UPDATE cron_jobs SET next_run_at = ?2 WHERE id = ?1",
                    rusqlite::params![id, next_str],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("cron job {id}")));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;

    fn make_store() -> SqliteCronStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        SqliteCronStore::new(pool)
    }

    fn make_job(name: &str) -> CronJob {
        CronJob {
            id: CronJobId::new(),
            name: name.into(),
            schedule: "0 * * * *".into(),
            prompt: "run something".into(),
            agent_id: AgentId::new("main"),
            model: None,
            max_concurrent_runs: 4,
            enabled: true,
            last_run_at: None,
            next_run_at: Some(Utc::now()),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let store = make_store();
        let job = make_job("roundtrip-test");
        store.create_job(&job).await.unwrap();
        let fetched = store.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "roundtrip-test");
        assert_eq!(fetched.schedule, "0 * * * *");
        assert_eq!(fetched.max_concurrent_runs, 4);
    }

    #[tokio::test]
    async fn list_jobs_returns_all() {
        let store = make_store();
        store.create_job(&make_job("a")).await.unwrap();
        store.create_job(&make_job("b")).await.unwrap();
        let jobs = store.list_jobs().await.unwrap();
        assert_eq!(jobs.len(), 2);
    }

    #[tokio::test]
    async fn update_changes_fields() {
        let store = make_store();
        let mut job = make_job("original");
        store.create_job(&job).await.unwrap();
        job.name = "updated".into();
        job.enabled = false;
        store.update_job(&job).await.unwrap();
        let fetched = store.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "updated");
        assert!(!fetched.enabled);
    }

    #[tokio::test]
    async fn delete_removes_job() {
        let store = make_store();
        let job = make_job("to-delete");
        store.create_job(&job).await.unwrap();
        store.delete_job(&job.id).await.unwrap();
        let fetched = store.get_job(&job.id).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn list_due_jobs_filters_by_time() {
        let store = make_store();
        let now = Utc::now();

        let mut due = make_job("due");
        due.next_run_at = Some(now - chrono::Duration::minutes(5));
        store.create_job(&due).await.unwrap();

        let mut future = make_job("future");
        future.next_run_at = Some(now + chrono::Duration::hours(1));
        store.create_job(&future).await.unwrap();

        let mut disabled = make_job("disabled");
        disabled.next_run_at = Some(now - chrono::Duration::minutes(5));
        disabled.enabled = false;
        store.create_job(&disabled).await.unwrap();

        let due_jobs = store.list_due_jobs(now).await.unwrap();
        assert_eq!(due_jobs.len(), 1);
        assert_eq!(due_jobs[0].name, "due");
    }

    #[tokio::test]
    async fn mark_run_started_missing_job_returns_not_found() {
        let store = make_store();
        let missing = CronJobId::new();
        let err = store
            .mark_run_started(&missing, Utc::now())
            .await
            .expect_err("missing job should return not found");
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn mark_run_completed_missing_job_returns_not_found() {
        let store = make_store();
        let missing = CronJobId::new();
        let err = store
            .mark_run_completed(&missing, Utc::now() + chrono::Duration::minutes(1))
            .await
            .expect_err("missing job should return not found");
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_job_fails_on_invalid_created_at() {
        let store = make_store();
        let job_id = CronJobId::new();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO cron_jobs (id, name, schedule, prompt, agent_id, model, max_concurrent_runs, enabled, last_run_at, next_run_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, 1, 1, NULL, NULL, ?6)",
                rusqlite::params![
                    job_id.as_str(),
                    "bad-time",
                    "* * * * *",
                    "run",
                    "main",
                    "not-a-timestamp",
                ],
            )
            .unwrap();
        }

        let err = store
            .get_job(&job_id)
            .await
            .expect_err("invalid created_at should fail");
        assert!(
            err.to_string().contains("Conversion error"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn get_job_fails_on_invalid_last_run_at() {
        let store = make_store();
        let job_id = CronJobId::new();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO cron_jobs (id, name, schedule, prompt, agent_id, model, max_concurrent_runs, enabled, last_run_at, next_run_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, 1, 1, ?6, NULL, ?7)",
                rusqlite::params![
                    job_id.as_str(),
                    "bad-last-run",
                    "* * * * *",
                    "run",
                    "main",
                    "garbage",
                    "2026-01-01T00:00:00Z",
                ],
            )
            .unwrap();
        }

        let err = store
            .get_job(&job_id)
            .await
            .expect_err("invalid last_run_at should fail");
        assert!(
            err.to_string().contains("Conversion error"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn get_job_fails_on_invalid_next_run_at() {
        let store = make_store();
        let job_id = CronJobId::new();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO cron_jobs (id, name, schedule, prompt, agent_id, model, max_concurrent_runs, enabled, last_run_at, next_run_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, 1, 1, NULL, ?6, ?7)",
                rusqlite::params![
                    job_id.as_str(),
                    "bad-next-run",
                    "* * * * *",
                    "run",
                    "main",
                    "garbage-next",
                    "2026-01-01T00:00:00Z",
                ],
            )
            .unwrap();
        }

        let err = store
            .get_job(&job_id)
            .await
            .expect_err("invalid next_run_at should fail");
        assert!(
            err.to_string().contains("Conversion error"),
            "unexpected error: {err}"
        );
    }
}
