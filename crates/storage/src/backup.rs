use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use tracing::warn;

use encmind_core::config::BackupRetention;
use encmind_core::error::StorageError;
use encmind_core::traits::EncryptionAdapter;

/// Metadata about a single backup snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: String,
    pub filename: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub encrypted: bool,
}

/// Manages local SQLite backup snapshots with optional encryption and retention.
pub struct BackupManager {
    pool: Pool<SqliteConnectionManager>,
    backup_dir: PathBuf,
    encryption: Option<Box<dyn EncryptionAdapter>>,
    retention: BackupRetention,
}

const TIMESTAMP_FORMAT: &str = "%Y%m%d_%H%M%S_%3f";
const LEGACY_TIMESTAMP_FORMAT: &str = "%Y%m%d_%H%M%S";

impl BackupManager {
    /// Create a new BackupManager. Creates `backup_dir` if it doesn't exist.
    pub fn new(
        pool: Pool<SqliteConnectionManager>,
        backup_dir: PathBuf,
        encryption: Option<Box<dyn EncryptionAdapter>>,
        retention: BackupRetention,
    ) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&backup_dir)?;
        Ok(Self {
            pool,
            backup_dir,
            encryption,
            retention,
        })
    }

    /// Create a new backup snapshot. Returns metadata about the created backup.
    pub fn create_backup(&self) -> Result<BackupInfo, StorageError> {
        let now = Utc::now();
        let timestamp = now.format(TIMESTAMP_FORMAT).to_string();
        let id = format!("backup-{timestamp}-{}", ulid::Ulid::new());
        let extension = if self.encryption.is_some() {
            "enc"
        } else {
            "db"
        };
        let filename = format!("{id}.{extension}");
        let tmp_path = self.backup_dir.join(format!("{id}.tmp"));
        let final_path = self.backup_dir.join(&filename);

        // Use rusqlite's Backup API to create a consistent snapshot
        let src_conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(format!("pool error: {e}")))?;

        {
            let mut dst_conn = rusqlite::Connection::open(&tmp_path)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let backup = rusqlite::backup::Backup::new(&src_conn, &mut dst_conn)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            backup
                .run_to_completion(100, std::time::Duration::from_millis(10), None)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
        }

        // Read the raw backup, optionally encrypt, then write to final path
        let raw = std::fs::read(&tmp_path)?;
        if let Err(e) = std::fs::remove_file(&tmp_path) {
            warn!(
                path = %tmp_path.display(),
                error = %e,
                "failed to remove temporary backup file"
            );
        }

        if let Some(enc) = &self.encryption {
            let (ciphertext, nonce) = enc.encrypt(&raw)?;
            // Format: [12-byte nonce][ciphertext]
            let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            std::fs::write(&final_path, &out)?;
        } else {
            std::fs::write(&final_path, &raw)?;
        }

        let size_bytes = std::fs::metadata(&final_path)?.len();

        Ok(BackupInfo {
            id,
            filename,
            created_at: now,
            size_bytes,
            encrypted: self.encryption.is_some(),
        })
    }

    /// List existing backups in the backup directory, sorted newest-first.
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>, StorageError> {
        let mut backups = Vec::new();
        let entries = std::fs::read_dir(&self.backup_dir).map_err(StorageError::Io)?;

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            // Only process backup files (skip .tmp and other files)
            if !name.starts_with("backup-") {
                continue;
            }
            let (id, encrypted) = if let Some(id) = name.strip_suffix(".enc") {
                (id.to_string(), true)
            } else if let Some(id) = name.strip_suffix(".db") {
                (id.to_string(), false)
            } else {
                continue;
            };

            let timestamp_str = match id.strip_prefix("backup-") {
                Some(ts) => ts,
                None => continue,
            };

            let created_at = match parse_backup_timestamp(timestamp_str) {
                Some(dt) => dt,
                None => continue,
            };

            let size_bytes = entry.metadata().map_err(StorageError::Io)?.len();

            backups.push(BackupInfo {
                id,
                filename: name,
                created_at,
                size_bytes,
                encrypted,
            });
        }

        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(backups)
    }

    /// Restore a backup to the given database path.
    /// The server must be stopped before calling this.
    pub fn restore_backup(&self, backup_id: &str, db_path: &Path) -> Result<(), StorageError> {
        let backup = self
            .list_backups()?
            .into_iter()
            .find(|b| b.id == backup_id)
            .ok_or_else(|| StorageError::NotFound(format!("backup not found: {backup_id}")))?;

        let backup_path = self.backup_dir.join(&backup.filename);
        let raw = std::fs::read(&backup_path)?;

        let db_bytes = if backup.encrypted {
            let enc = self
                .encryption
                .as_ref()
                .ok_or(StorageError::DecryptionFailed)?;
            if raw.len() < 12 {
                return Err(StorageError::DecryptionFailed);
            }
            let (nonce, ciphertext) = raw.split_at(12);
            enc.decrypt(ciphertext, nonce)?
        } else {
            raw
        };

        std::fs::write(db_path, &db_bytes)?;
        Ok(())
    }

    /// Apply the retention policy: keep the `daily + weekly` most recent backups
    /// (sorted by creation time) and delete everything older.
    /// Returns the number of deleted backups.
    pub fn apply_retention(&self) -> Result<usize, StorageError> {
        let backups = self.list_backups()?;
        let keep = (self.retention.daily + self.retention.weekly) as usize;
        let mut deleted = 0;

        if backups.len() > keep {
            for backup in &backups[keep..] {
                let path = self.backup_dir.join(&backup.filename);
                std::fs::remove_file(&path).map_err(StorageError::Io)?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }
}

/// Restore a backup without requiring a database connection pool.
///
/// This is intended for CLI restore operations where the pool must be closed
/// before overwriting the database file.
pub fn restore_backup_file(
    backup_dir: &Path,
    backup_id: &str,
    db_path: &Path,
    encryption: Option<&dyn EncryptionAdapter>,
) -> Result<(), StorageError> {
    // Find the backup file by scanning the directory
    let entries = std::fs::read_dir(backup_dir).map_err(StorageError::Io)?;
    let mut found: Option<(String, bool)> = None;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("backup-") {
            continue;
        }
        let (id, encrypted) = if let Some(id) = name.strip_suffix(".enc") {
            (id.to_string(), true)
        } else if let Some(id) = name.strip_suffix(".db") {
            (id.to_string(), false)
        } else {
            continue;
        };
        if id == backup_id {
            found = Some((name, encrypted));
            break;
        }
    }

    let (filename, encrypted) =
        found.ok_or_else(|| StorageError::NotFound(format!("backup not found: {backup_id}")))?;

    let backup_path = backup_dir.join(&filename);
    let raw = std::fs::read(&backup_path)?;

    let db_bytes = if encrypted {
        let enc = encryption.ok_or(StorageError::DecryptionFailed)?;
        if raw.len() < 12 {
            return Err(StorageError::DecryptionFailed);
        }
        let (nonce, ciphertext) = raw.split_at(12);
        enc.decrypt(ciphertext, nonce)?
    } else {
        raw
    };

    std::fs::write(db_path, &db_bytes)?;
    Ok(())
}

/// Parse a timestamp string in the backup format (YYYYMMDD_HHMMSS) into a DateTime<Utc>.
fn parse_backup_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let ts = s.split('-').next().unwrap_or(s);
    NaiveDateTime::parse_from_str(ts, TIMESTAMP_FORMAT)
        .or_else(|_| NaiveDateTime::parse_from_str(ts, LEGACY_TIMESTAMP_FORMAT))
        .ok()
        .map(|ndt| ndt.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;
    use encmind_storage::encryption::Aes256GcmAdapter;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;
    use tempfile::TempDir;

    // Forwarding import for within-crate test context
    use crate as encmind_storage;

    fn test_pool() -> Pool<SqliteConnectionManager> {
        let pool = create_test_pool();
        let conn = pool.get().unwrap();
        run_migrations(&conn).unwrap();
        pool
    }

    fn test_encryption() -> Box<dyn EncryptionAdapter> {
        Box::new(Aes256GcmAdapter::new(&[0x42u8; 32]))
    }

    #[test]
    fn create_backup_produces_file() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();
        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            None,
            BackupRetention::default(),
        )
        .unwrap();

        let info = mgr.create_backup().unwrap();
        assert!(info.id.starts_with("backup-"));
        assert!(info.filename.ends_with(".db"));
        assert!(!info.encrypted);
        assert!(info.size_bytes > 0);
        assert!(dir.path().join(&info.filename).exists());
    }

    #[test]
    fn create_backup_encrypted_roundtrip() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();
        let enc = test_encryption();
        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            Some(enc),
            BackupRetention::default(),
        )
        .unwrap();

        let info = mgr.create_backup().unwrap();
        assert!(info.encrypted);
        assert!(info.filename.ends_with(".enc"));

        // Manually verify we can decrypt the file
        let raw = std::fs::read(dir.path().join(&info.filename)).unwrap();
        assert!(raw.len() > 12);
        let dec = Aes256GcmAdapter::new(&[0x42u8; 32]);
        let (nonce, ct) = raw.split_at(12);
        let plaintext = dec.decrypt(ct, nonce).unwrap();
        // SQLite files start with "SQLite format 3\0"
        assert!(plaintext.starts_with(b"SQLite format 3"));
    }

    #[test]
    fn list_backups_sorted_newest_first() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();
        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            None,
            BackupRetention::default(),
        )
        .unwrap();

        // Create backup files manually with distinct timestamps
        std::fs::write(dir.path().join("backup-20260101_010000.db"), "a").unwrap();
        std::fs::write(dir.path().join("backup-20260101_030000.db"), "c").unwrap();
        std::fs::write(dir.path().join("backup-20260101_020000.db"), "b").unwrap();

        let list = mgr.list_backups().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id, "backup-20260101_030000");
        assert_eq!(list[1].id, "backup-20260101_020000");
        assert_eq!(list[2].id, "backup-20260101_010000");
    }

    #[test]
    fn list_backups_ignores_tmp_files() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();
        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            None,
            BackupRetention::default(),
        )
        .unwrap();

        // Create a .tmp file and a non-backup file
        std::fs::write(dir.path().join("backup-20260101_000000.tmp"), "tmp").unwrap();
        std::fs::write(dir.path().join("something_else.db"), "other").unwrap();

        let list = mgr.list_backups().unwrap();
        assert!(
            list.is_empty(),
            "should not pick up .tmp or non-backup files"
        );
    }

    #[test]
    fn restore_backup_overwrites_db() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();

        // Insert a row so the backup has data
        {
            let conn = pool.get().unwrap();
            conn.execute_batch("CREATE TABLE test_restore (x TEXT)")
                .unwrap();
            conn.execute("INSERT INTO test_restore VALUES ('hello')", [])
                .unwrap();
        }

        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            None,
            BackupRetention::default(),
        )
        .unwrap();
        let info = mgr.create_backup().unwrap();

        // Restore to a new path
        let restore_path = dir.path().join("restored.db");
        mgr.restore_backup(&info.id, &restore_path).unwrap();

        // Verify the restored db has the data
        let conn = rusqlite::Connection::open(&restore_path).unwrap();
        let val: String = conn
            .query_row("SELECT x FROM test_restore", [], |row| row.get(0))
            .unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn restore_encrypted_backup() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();

        {
            let conn = pool.get().unwrap();
            conn.execute_batch("CREATE TABLE enc_test (v TEXT)")
                .unwrap();
            conn.execute("INSERT INTO enc_test VALUES ('encrypted_data')", [])
                .unwrap();
        }

        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            Some(test_encryption()),
            BackupRetention::default(),
        )
        .unwrap();
        let info = mgr.create_backup().unwrap();
        assert!(info.encrypted);

        let restore_path = dir.path().join("restored_enc.db");
        mgr.restore_backup(&info.id, &restore_path).unwrap();

        let conn = rusqlite::Connection::open(&restore_path).unwrap();
        let val: String = conn
            .query_row("SELECT v FROM enc_test", [], |row| row.get(0))
            .unwrap();
        assert_eq!(val, "encrypted_data");
    }

    #[test]
    fn restore_nonexistent_errors() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();
        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            None,
            BackupRetention::default(),
        )
        .unwrap();

        let result = mgr.restore_backup("backup-does-not-exist", &dir.path().join("out.db"));
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::NotFound(msg) => assert!(msg.contains("not found")),
            other => panic!("Expected NotFound, got: {other}"),
        }
    }

    #[test]
    fn apply_retention_removes_old() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();

        // Retention: keep 2 (daily=1, weekly=1)
        let retention = BackupRetention {
            daily: 1,
            weekly: 1,
        };
        let mgr = BackupManager::new(pool, dir.path().to_path_buf(), None, retention).unwrap();

        // Create 5 backups with different timestamps
        for i in 0..5 {
            // Create backup files manually with distinct timestamps
            let ts = format!("20260101_{:02}0000", i);
            let filename = format!("backup-{ts}.db");
            std::fs::write(dir.path().join(&filename), format!("data{i}")).unwrap();
        }

        let deleted = mgr.apply_retention().unwrap();
        assert_eq!(deleted, 3); // 5 - 2 = 3

        let remaining = mgr.list_backups().unwrap();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn parse_backup_timestamp_valid() {
        let dt = parse_backup_timestamp("20260217_143000").unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 2);
        assert_eq!(dt.day(), 17);
    }

    #[test]
    fn parse_backup_timestamp_with_millis_and_suffix_valid() {
        let dt = parse_backup_timestamp("20260217_143000_123-01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 2);
        assert_eq!(dt.day(), 17);
    }

    #[test]
    fn parse_backup_timestamp_invalid() {
        assert!(parse_backup_timestamp("not-a-timestamp").is_none());
        assert!(parse_backup_timestamp("2026-02-17T14:30:00").is_none());
    }

    #[test]
    fn restore_backup_file_without_pool() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();

        {
            let conn = pool.get().unwrap();
            conn.execute_batch("CREATE TABLE poolless_test (v TEXT)")
                .unwrap();
            conn.execute("INSERT INTO poolless_test VALUES ('standalone')", [])
                .unwrap();
        }

        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            None,
            BackupRetention::default(),
        )
        .unwrap();
        let info = mgr.create_backup().unwrap();

        // Restore using the standalone function (no pool required)
        let restore_path = dir.path().join("restored_poolless.db");
        restore_backup_file(dir.path(), &info.id, &restore_path, None).unwrap();

        let conn = rusqlite::Connection::open(&restore_path).unwrap();
        let val: String = conn
            .query_row("SELECT v FROM poolless_test", [], |row| row.get(0))
            .unwrap();
        assert_eq!(val, "standalone");
    }

    #[test]
    fn restore_backup_file_encrypted() {
        let dir = TempDir::new().unwrap();
        let pool = test_pool();

        {
            let conn = pool.get().unwrap();
            conn.execute_batch("CREATE TABLE enc_poolless (v TEXT)")
                .unwrap();
            conn.execute("INSERT INTO enc_poolless VALUES ('secret')", [])
                .unwrap();
        }

        let enc = test_encryption();
        let mgr = BackupManager::new(
            pool,
            dir.path().to_path_buf(),
            Some(enc),
            BackupRetention::default(),
        )
        .unwrap();
        let info = mgr.create_backup().unwrap();
        assert!(info.encrypted);

        let dec = Aes256GcmAdapter::new(&[0x42u8; 32]);
        let restore_path = dir.path().join("restored_enc_poolless.db");
        restore_backup_file(dir.path(), &info.id, &restore_path, Some(&dec)).unwrap();

        let conn = rusqlite::Connection::open(&restore_path).unwrap();
        let val: String = conn
            .query_row("SELECT v FROM enc_poolless", [], |row| row.get(0))
            .unwrap();
        assert_eq!(val, "secret");
    }

    #[test]
    fn restore_backup_file_not_found() {
        let dir = TempDir::new().unwrap();
        let result = restore_backup_file(
            dir.path(),
            "backup-nonexistent",
            &dir.path().join("x.db"),
            None,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::NotFound(msg) => assert!(msg.contains("not found")),
            other => panic!("Expected NotFound, got: {other}"),
        }
    }
}
