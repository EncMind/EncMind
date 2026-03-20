use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::SkillTimerStore;
use encmind_core::types::SkillTimer;

pub struct SqliteSkillTimerStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteSkillTimerStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

fn parse_optional_datetime(s: &Option<String>) -> Result<Option<DateTime<Utc>>, rusqlite::Error> {
    match s {
        Some(ref ts) => {
            let dt = DateTime::parse_from_rfc3339(ts)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
            Ok(Some(dt))
        }
        None => Ok(None),
    }
}

fn row_to_timer(row: &rusqlite::Row<'_>) -> Result<SkillTimer, rusqlite::Error> {
    let id: String = row.get("id")?;
    let skill_id: String = row.get("skill_id")?;
    let timer_name: String = row.get("timer_name")?;
    let interval_secs: i64 = row.get("interval_secs")?;
    let export_fn: String = row.get("export_fn")?;
    let enabled: bool = row.get("enabled")?;
    let last_tick_at: Option<String> = row.get("last_tick_at")?;
    let next_tick_at: Option<String> = row.get("next_tick_at")?;
    let source_manifest_hash: Option<String> = row.get("source_manifest_hash")?;
    let consecutive_failures: i64 = row.get("consecutive_failures")?;
    let created_at: String = row.get("created_at")?;
    let updated_at: String = row.get("updated_at")?;

    let parsed_created_at = DateTime::parse_from_rfc3339(&created_at)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let parsed_updated_at = DateTime::parse_from_rfc3339(&updated_at)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(SkillTimer {
        id,
        skill_id,
        timer_name,
        interval_secs: interval_secs as u64,
        export_fn,
        enabled,
        last_tick_at: parse_optional_datetime(&last_tick_at)?,
        next_tick_at: parse_optional_datetime(&next_tick_at)?,
        source_manifest_hash,
        consecutive_failures: consecutive_failures as u32,
        created_at: parsed_created_at,
        updated_at: parsed_updated_at,
    })
}

fn join_err(e: tokio::task::JoinError) -> StorageError {
    StorageError::Sqlite(e.to_string())
}

#[async_trait]
impl SkillTimerStore for SqliteSkillTimerStore {
    async fn list_timers(&self) -> Result<Vec<SkillTimer>, StorageError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let mut stmt = conn
                .prepare("SELECT * FROM skill_timers ORDER BY skill_id, timer_name")
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let timers = stmt
                .query_map([], row_to_timer)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(timers)
        })
        .await
        .map_err(join_err)?
    }

    async fn list_enabled_due(&self, now: DateTime<Utc>) -> Result<Vec<SkillTimer>, StorageError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let now_str = now.to_rfc3339();
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM skill_timers WHERE enabled = 1 AND next_tick_at <= ?1 \
                     ORDER BY next_tick_at",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let timers = stmt
                .query_map(rusqlite::params![now_str], row_to_timer)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(timers)
        })
        .await
        .map_err(join_err)?
    }

    async fn upsert_timer(&self, timer: &SkillTimer) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let timer = timer.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let now = Utc::now().to_rfc3339();
            let next_tick = timer.next_tick_at.map(|t| t.to_rfc3339());
            let last_tick = timer.last_tick_at.map(|t| t.to_rfc3339());
            conn.execute(
                "INSERT INTO skill_timers (id, skill_id, timer_name, interval_secs, export_fn, \
                 enabled, last_tick_at, next_tick_at, source_manifest_hash, consecutive_failures, \
                 created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(skill_id, timer_name) DO UPDATE SET \
                 interval_secs = excluded.interval_secs, \
                 export_fn = excluded.export_fn, \
                 source_manifest_hash = excluded.source_manifest_hash, \
                 updated_at = excluded.updated_at",
                rusqlite::params![
                    timer.id,
                    timer.skill_id,
                    timer.timer_name,
                    timer.interval_secs as i64,
                    timer.export_fn,
                    timer.enabled,
                    last_tick,
                    next_tick,
                    timer.source_manifest_hash,
                    timer.consecutive_failures as i64,
                    now,
                    now,
                ],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(join_err)?
    }

    async fn delete_timers_for_skill(&self, skill_id: &str) -> Result<u64, StorageError> {
        let pool = self.pool.clone();
        let skill_id = skill_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let count = conn
                .execute(
                    "DELETE FROM skill_timers WHERE skill_id = ?1",
                    rusqlite::params![skill_id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(count as u64)
        })
        .await
        .map_err(join_err)?
    }

    async fn delete_stale_timers(
        &self,
        skill_id: &str,
        keep_names: &[&str],
    ) -> Result<u64, StorageError> {
        let pool = self.pool.clone();
        let skill_id = skill_id.to_string();
        let keep_names = keep_names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            if keep_names.is_empty() {
                let count = conn
                    .execute(
                        "DELETE FROM skill_timers WHERE skill_id = ?1",
                        rusqlite::params![skill_id],
                    )
                    .map_err(|e| StorageError::Sqlite(e.to_string()))?;
                return Ok(count as u64);
            }
            let placeholders: Vec<String> = (0..keep_names.len())
                .map(|i| format!("?{}", i + 2))
                .collect();
            let sql = format!(
                "DELETE FROM skill_timers WHERE skill_id = ?1 AND timer_name NOT IN ({})",
                placeholders.join(", ")
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(skill_id)];
            for name in keep_names {
                params.push(Box::new(name));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let count = conn
                .execute(&sql, param_refs.as_slice())
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(count as u64)
        })
        .await
        .map_err(join_err)?
    }

    async fn delete_timers_not_in_skills(
        &self,
        active_skill_ids: &[&str],
    ) -> Result<u64, StorageError> {
        let pool = self.pool.clone();
        let active_skill_ids = active_skill_ids
            .iter()
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            if active_skill_ids.is_empty() {
                let count = conn
                    .execute("DELETE FROM skill_timers", [])
                    .map_err(|e| StorageError::Sqlite(e.to_string()))?;
                return Ok(count as u64);
            }
            let placeholders: Vec<String> = (0..active_skill_ids.len())
                .map(|i| format!("?{}", i + 1))
                .collect();
            let sql = format!(
                "DELETE FROM skill_timers WHERE skill_id NOT IN ({})",
                placeholders.join(", ")
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            for id in active_skill_ids {
                params.push(Box::new(id));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let count = conn
                .execute(&sql, param_refs.as_slice())
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(count as u64)
        })
        .await
        .map_err(join_err)?
    }

    async fn mark_tick(
        &self,
        id: &str,
        ticked_at: DateTime<Utc>,
        next_tick_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let count = conn
                .execute(
                    "UPDATE skill_timers SET last_tick_at = ?1, next_tick_at = ?2, \
                     updated_at = ?3 WHERE id = ?4",
                    rusqlite::params![
                        ticked_at.to_rfc3339(),
                        next_tick_at.to_rfc3339(),
                        Utc::now().to_rfc3339(),
                        id,
                    ],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if count == 0 {
                return Err(StorageError::NotFound("timer not found".into()));
            }
            Ok(())
        })
        .await
        .map_err(join_err)?
    }

    async fn increment_failures(&self, id: &str) -> Result<u32, StorageError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            conn.execute(
                "UPDATE skill_timers SET consecutive_failures = consecutive_failures + 1, \
                 updated_at = ?1 WHERE id = ?2",
                rusqlite::params![Utc::now().to_rfc3339(), id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

            let count: i64 = conn
                .query_row(
                    "SELECT consecutive_failures FROM skill_timers WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(count as u32)
        })
        .await
        .map_err(join_err)?
    }

    async fn reset_failures(&self, id: &str) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            conn.execute(
                "UPDATE skill_timers SET consecutive_failures = 0, \
                 updated_at = ?1 WHERE id = ?2",
                rusqlite::params![Utc::now().to_rfc3339(), id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(join_err)?
    }

    async fn disable_timer(&self, id: &str) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let updated = conn
                .execute(
                    "UPDATE skill_timers SET enabled = 0, \
                 updated_at = ?1 WHERE id = ?2",
                    rusqlite::params![Utc::now().to_rfc3339(), id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if updated == 0 {
                return Err(StorageError::NotFound("timer not found".into()));
            }
            Ok(())
        })
        .await
        .map_err(join_err)?
    }

    async fn enable_timer(
        &self,
        id: &str,
        next_tick_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;
            let updated = conn
                .execute(
                    "UPDATE skill_timers SET enabled = 1, consecutive_failures = 0, \
                 next_tick_at = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![next_tick_at.to_rfc3339(), Utc::now().to_rfc3339(), id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if updated == 0 {
                return Err(StorageError::NotFound("timer not found".into()));
            }
            Ok(())
        })
        .await
        .map_err(join_err)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> SqliteSkillTimerStore {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager).unwrap();
        let conn = pool.get().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        crate::migrations::run_migrations(&conn).unwrap();
        SqliteSkillTimerStore::new(pool)
    }

    fn make_timer(skill_id: &str, name: &str, interval: u64) -> SkillTimer {
        SkillTimer {
            id: format!("{skill_id}:{name}"),
            skill_id: skill_id.into(),
            timer_name: name.into(),
            interval_secs: interval,
            export_fn: format!("__on_{name}"),
            enabled: true,
            last_tick_at: None,
            next_tick_at: Some(Utc::now()),
            source_manifest_hash: Some("abc123".into()),
            consecutive_failures: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn upsert_and_list() {
        let store = create_test_store();
        let timer = make_timer("skill-a", "daily", 3600);
        store.upsert_timer(&timer).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].skill_id, "skill-a");
        assert_eq!(timers[0].timer_name, "daily");
        assert_eq!(timers[0].interval_secs, 3600);
    }

    #[tokio::test]
    async fn upsert_updates_on_conflict() {
        let store = create_test_store();
        let timer = make_timer("skill-a", "daily", 3600);
        store.upsert_timer(&timer).await.unwrap();

        // Upsert with different interval
        let mut updated = timer.clone();
        updated.id = "new-id".into(); // different id, but same skill_id+timer_name
        updated.interval_secs = 7200;
        store.upsert_timer(&updated).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].interval_secs, 7200);
        // Original ID preserved (ON CONFLICT DO UPDATE doesn't change id)
        assert_eq!(timers[0].id, "skill-a:daily");
    }

    #[tokio::test]
    async fn list_enabled_due() {
        let store = create_test_store();
        let past = Utc::now() - chrono::Duration::hours(1);
        let future = Utc::now() + chrono::Duration::hours(1);

        let mut due_timer = make_timer("skill-a", "due", 60);
        due_timer.next_tick_at = Some(past);
        store.upsert_timer(&due_timer).await.unwrap();

        let mut future_timer = make_timer("skill-a", "future", 60);
        future_timer.next_tick_at = Some(future);
        store.upsert_timer(&future_timer).await.unwrap();

        let mut disabled_timer = make_timer("skill-b", "disabled", 60);
        disabled_timer.next_tick_at = Some(past);
        disabled_timer.enabled = false;
        store.upsert_timer(&disabled_timer).await.unwrap();

        let due = store.list_enabled_due(Utc::now()).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].timer_name, "due");
    }

    #[tokio::test]
    async fn mark_tick_updates() {
        let store = create_test_store();
        let timer = make_timer("skill-a", "daily", 3600);
        store.upsert_timer(&timer).await.unwrap();

        let now = Utc::now();
        let next = now + chrono::Duration::hours(1);
        store.mark_tick(&timer.id, now, next).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert!(timers[0].last_tick_at.is_some());
        assert!(timers[0].next_tick_at.is_some());
    }

    #[tokio::test]
    async fn mark_tick_not_found() {
        let store = create_test_store();
        let result = store.mark_tick("nonexistent", Utc::now(), Utc::now()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete_for_skill() {
        let store = create_test_store();
        store
            .upsert_timer(&make_timer("skill-a", "t1", 60))
            .await
            .unwrap();
        store
            .upsert_timer(&make_timer("skill-a", "t2", 120))
            .await
            .unwrap();
        store
            .upsert_timer(&make_timer("skill-b", "t1", 60))
            .await
            .unwrap();

        let count = store.delete_timers_for_skill("skill-a").await.unwrap();
        assert_eq!(count, 2);

        let remaining = store.list_timers().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].skill_id, "skill-b");
    }

    #[tokio::test]
    async fn delete_stale_timers() {
        let store = create_test_store();
        store
            .upsert_timer(&make_timer("skill-a", "keep", 60))
            .await
            .unwrap();
        store
            .upsert_timer(&make_timer("skill-a", "stale", 120))
            .await
            .unwrap();

        let count = store
            .delete_stale_timers("skill-a", &["keep"])
            .await
            .unwrap();
        assert_eq!(count, 1);

        let remaining = store.list_timers().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].timer_name, "keep");
    }

    #[tokio::test]
    async fn delete_timers_not_in_skills() {
        let store = create_test_store();
        store
            .upsert_timer(&make_timer("skill-a", "t1", 60))
            .await
            .unwrap();
        store
            .upsert_timer(&make_timer("skill-b", "t1", 60))
            .await
            .unwrap();
        store
            .upsert_timer(&make_timer("skill-c", "t1", 60))
            .await
            .unwrap();

        let count = store
            .delete_timers_not_in_skills(&["skill-a", "skill-c"])
            .await
            .unwrap();
        assert_eq!(count, 1);

        let remaining = store.list_timers().await.unwrap();
        assert_eq!(remaining.len(), 2);
        let ids: Vec<&str> = remaining.iter().map(|t| t.skill_id.as_str()).collect();
        assert!(ids.contains(&"skill-a"));
        assert!(ids.contains(&"skill-c"));
    }

    #[tokio::test]
    async fn increment_and_reset_failures() {
        let store = create_test_store();
        let timer = make_timer("skill-a", "flaky", 60);
        store.upsert_timer(&timer).await.unwrap();

        let count = store.increment_failures(&timer.id).await.unwrap();
        assert_eq!(count, 1);
        let count = store.increment_failures(&timer.id).await.unwrap();
        assert_eq!(count, 2);

        store.reset_failures(&timer.id).await.unwrap();
        let timers = store.list_timers().await.unwrap();
        assert_eq!(timers[0].consecutive_failures, 0);
    }

    #[tokio::test]
    async fn disable_timer() {
        let store = create_test_store();
        let timer = make_timer("skill-a", "daily", 3600);
        store.upsert_timer(&timer).await.unwrap();

        store.disable_timer(&timer.id).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert!(!timers[0].enabled);
    }

    #[tokio::test]
    async fn enable_timer_resets_and_schedules() {
        let store = create_test_store();
        let mut timer = make_timer("skill-a", "daily", 3600);
        timer.enabled = false;
        timer.consecutive_failures = 5;
        timer.next_tick_at = None;
        store.upsert_timer(&timer).await.unwrap();

        let next = Utc::now() + chrono::Duration::seconds(60);
        store.enable_timer(&timer.id, next).await.unwrap();

        let timers = store.list_timers().await.unwrap();
        assert!(timers[0].enabled);
        assert_eq!(timers[0].consecutive_failures, 0);
        assert!(timers[0].next_tick_at.is_some());
    }

    #[tokio::test]
    async fn disable_timer_returns_not_found_for_missing_id() {
        let store = create_test_store();
        let err = store
            .disable_timer("missing-skill:missing-timer")
            .await
            .expect_err("missing timer should return not found");
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn enable_timer_returns_not_found_for_missing_id() {
        let store = create_test_store();
        let err = store
            .enable_timer("missing-skill:missing-timer", Utc::now())
            .await
            .expect_err("missing timer should return not found");
        assert!(matches!(err, StorageError::NotFound(_)));
    }
}
