use async_trait::async_trait;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::WorkflowStore;
use encmind_core::types::{WorkflowRun, WorkflowRunStatus};

pub struct SqliteWorkflowStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteWorkflowStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn row_to_workflow_run(row: &rusqlite::Row<'_>) -> Result<WorkflowRun, rusqlite::Error> {
    let status_raw: String = row.get("status")?;
    let status = status_raw.parse::<WorkflowRunStatus>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;

    Ok(WorkflowRun {
        id: row.get("id")?,
        workflow_name: row.get("workflow_name")?,
        agent_id: row.get("agent_id")?,
        status,
        current_step: row.get("current_step")?,
        total_steps: row.get("total_steps")?,
        error_detail: row.get("error_detail")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        completed_at: row.get("completed_at")?,
    })
}

#[async_trait]
impl WorkflowStore for SqliteWorkflowStore {
    async fn list_runs(
        &self,
        status_filter: Option<WorkflowRunStatus>,
        limit: usize,
    ) -> Result<Vec<WorkflowRun>, StorageError> {
        let pool = self.pool.clone();
        let status_filter = status_filter.map(|s| s.as_str().to_owned());
        let limit = limit.min(1000) as i64;
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, workflow_name, agent_id, status, current_step, total_steps, \
                     error_detail, created_at, updated_at, completed_at \
                     FROM workflow_runs \
                     WHERE (?1 IS NULL OR status = ?1) \
                     ORDER BY updated_at DESC \
                     LIMIT ?2",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![status_filter, limit], row_to_workflow_run)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut runs = Vec::new();
            for row in rows {
                runs.push(row.map_err(|e| StorageError::Sqlite(e.to_string()))?);
            }
            Ok(runs)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn get_run(&self, id: &str) -> Result<Option<WorkflowRun>, StorageError> {
        let pool = self.pool.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, workflow_name, agent_id, status, current_step, total_steps, \
                     error_detail, created_at, updated_at, completed_at \
                     FROM workflow_runs WHERE id = ?1",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let result = stmt
                .query_row(rusqlite::params![id], row_to_workflow_run)
                .optional()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(result)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn cancel_run(&self, id: &str) -> Result<bool, StorageError> {
        let pool = self.pool.clone();
        let id = id.to_owned();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let affected = conn
                .execute(
                    "UPDATE workflow_runs SET status = 'cancelled', updated_at = ?1, completed_at = COALESCE(completed_at, ?1) \
                     WHERE id = ?2 AND status = 'running'",
                    rusqlite::params![now, id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(affected > 0)
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

    fn setup() -> Pool<SqliteConnectionManager> {
        let pool = create_test_pool();
        let conn = pool.get().unwrap();
        run_migrations(&conn).unwrap();
        pool
    }

    fn insert_run(pool: &Pool<SqliteConnectionManager>, id: &str, name: &str, status: &str) {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO workflow_runs (id, workflow_name, agent_id, status, current_step) \
             VALUES (?1, ?2, 'main', ?3, 0)",
            rusqlite::params![id, name, status],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn list_empty() {
        let pool = setup();
        let store = SqliteWorkflowStore::new(pool);
        let runs = store.list_runs(None, 50).await.unwrap();
        assert!(runs.is_empty());
    }

    #[tokio::test]
    async fn list_with_status_filter() {
        let pool = setup();
        insert_run(&pool, "r1", "wf1", "running");
        insert_run(&pool, "r2", "wf2", "completed");
        let store = SqliteWorkflowStore::new(pool);

        let running = store
            .list_runs(Some(WorkflowRunStatus::Running), 50)
            .await
            .unwrap();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].id, "r1");
        assert_eq!(running[0].status, WorkflowRunStatus::Running);

        let all = store.list_runs(None, 50).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn get_existing_run() {
        let pool = setup();
        insert_run(&pool, "r1", "wf1", "running");
        let store = SqliteWorkflowStore::new(pool);

        let run = store.get_run("r1").await.unwrap();
        assert!(run.is_some());
        let run = run.unwrap();
        assert_eq!(run.workflow_name, "wf1");
        assert_eq!(run.status, WorkflowRunStatus::Running);
    }

    #[tokio::test]
    async fn get_missing_run() {
        let pool = setup();
        let store = SqliteWorkflowStore::new(pool);
        let run = store.get_run("nonexistent").await.unwrap();
        assert!(run.is_none());
    }

    #[tokio::test]
    async fn cancel_running_run() {
        let pool = setup();
        insert_run(&pool, "r1", "wf1", "running");
        let store = SqliteWorkflowStore::new(pool);

        let cancelled = store.cancel_run("r1").await.unwrap();
        assert!(cancelled);

        let run = store.get_run("r1").await.unwrap().unwrap();
        assert_eq!(run.status, WorkflowRunStatus::Cancelled);
        assert!(run.completed_at.is_some());
    }

    #[tokio::test]
    async fn cancel_non_running_run() {
        let pool = setup();
        insert_run(&pool, "r1", "wf1", "completed");
        let store = SqliteWorkflowStore::new(pool);

        let cancelled = store.cancel_run("r1").await.unwrap();
        assert!(!cancelled);
    }

    #[tokio::test]
    async fn cancel_missing_run() {
        let pool = setup();
        let store = SqliteWorkflowStore::new(pool);
        let cancelled = store.cancel_run("nonexistent").await.unwrap();
        assert!(!cancelled);
    }
}
