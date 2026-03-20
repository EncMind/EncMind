use async_trait::async_trait;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use rusqlite::OptionalExtension;

use encmind_core::error::StorageError;
use encmind_core::traits::SkillToggleStore;

pub struct SqliteSkillToggleStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteSkillToggleStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SkillToggleStore for SqliteSkillToggleStore {
    async fn is_enabled(&self, skill_id: &str) -> Result<bool, StorageError> {
        let pool = self.pool.clone();
        let skill_id = skill_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let result: Option<bool> = conn
                .query_row(
                    "SELECT enabled FROM skill_toggle_state WHERE skill_id = ?1",
                    params![skill_id],
                    |row| {
                        let v: i64 = row.get(0)?;
                        Ok(v != 0)
                    },
                )
                .optional()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            // Default to enabled if no row exists
            Ok(result.unwrap_or(true))
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn set_enabled(&self, skill_id: &str, enabled: bool) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let skill_id = skill_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if enabled {
                // Default state is enabled; remove explicit rows to avoid stale state buildup.
                conn.execute(
                    "DELETE FROM skill_toggle_state WHERE skill_id = ?1",
                    params![skill_id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            } else {
                conn.execute(
                    "INSERT INTO skill_toggle_state (skill_id, enabled, updated_at) \
                     VALUES (?1, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) \
                     ON CONFLICT(skill_id) DO UPDATE SET \
                       enabled = 0, \
                       updated_at = excluded.updated_at",
                    params![skill_id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn list_disabled(&self) -> Result<Vec<String>, StorageError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare("SELECT skill_id FROM skill_toggle_state WHERE enabled = 0")
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row.map_err(|e| StorageError::Sqlite(e.to_string()))?);
            }
            Ok(ids)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_storage_test_helpers::create_test_pool;

    fn setup() -> SqliteSkillToggleStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            crate::migrations::run_migrations(&conn).unwrap();
        }
        SqliteSkillToggleStore::new(pool)
    }

    #[tokio::test]
    async fn is_enabled_defaults_to_true() {
        let store = setup();
        assert!(store.is_enabled("unknown-skill").await.unwrap());
    }

    #[tokio::test]
    async fn set_enabled_and_read_back() {
        let store = setup();
        store.set_enabled("skill-a", false).await.unwrap();
        assert!(!store.is_enabled("skill-a").await.unwrap());

        store.set_enabled("skill-a", true).await.unwrap();
        assert!(store.is_enabled("skill-a").await.unwrap());
    }

    #[tokio::test]
    async fn list_disabled_returns_only_disabled() {
        let store = setup();
        store.set_enabled("skill-a", false).await.unwrap();
        store.set_enabled("skill-b", true).await.unwrap();
        store.set_enabled("skill-c", false).await.unwrap();

        let mut disabled = store.list_disabled().await.unwrap();
        disabled.sort();
        assert_eq!(disabled, vec!["skill-a", "skill-c"]);
    }

    #[tokio::test]
    async fn set_enabled_upserts() {
        let store = setup();
        store.set_enabled("skill-a", false).await.unwrap();
        store.set_enabled("skill-a", false).await.unwrap();
        assert!(!store.is_enabled("skill-a").await.unwrap());
    }

    #[tokio::test]
    async fn set_enabled_true_removes_row() {
        let store = setup();
        store.set_enabled("skill-a", false).await.unwrap();
        store.set_enabled("skill-a", true).await.unwrap();
        assert!(store.is_enabled("skill-a").await.unwrap());
        assert!(store.list_disabled().await.unwrap().is_empty());

        // Verify row removal directly.
        let conn = store.pool.get().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM skill_toggle_state WHERE skill_id = ?1",
                params!["skill-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}

/// Helper module alias for tests that need `create_test_pool`.
#[cfg(test)]
mod encmind_storage_test_helpers {
    pub use crate::pool::create_test_pool;
}
