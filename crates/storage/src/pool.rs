use std::path::Path;
use std::time::Duration;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;

use encmind_core::error::StorageError;

/// Create an r2d2 connection pool for SQLite with WAL mode.
pub fn create_pool(db_path: &Path) -> Result<Pool<SqliteConnectionManager>, StorageError> {
    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
    }

    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
        .with_init(|conn| {
            // Enable WAL mode for concurrent readers
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;
                 PRAGMA synchronous = NORMAL;",
            )?;
            Ok(())
        });

    let pool = Pool::builder()
        .max_size(4)
        .connection_timeout(Duration::from_secs(10))
        .build(manager)
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

    Ok(pool)
}

/// Create an in-memory pool for testing.
#[cfg(any(test, feature = "test-helpers"))]
pub fn create_test_pool() -> Pool<SqliteConnectionManager> {
    let manager = SqliteConnectionManager::memory().with_init(|conn| {
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        Ok(())
    });

    Pool::builder()
        .max_size(1) // Single connection for in-memory DBs (shared state)
        .build(manager)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_pool_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let pool = create_pool(&db_path).unwrap();

        let conn = pool.get().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn create_pool_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("subdir/nested/test.db");
        let pool = create_pool(&db_path).unwrap();
        let _conn = pool.get().unwrap();
        assert!(db_path.exists());
    }
}
