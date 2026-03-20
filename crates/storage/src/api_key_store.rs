use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::{ApiKeyStore, EncryptionAdapter};
use encmind_core::types::ApiKeyRecord;

pub struct SqliteApiKeyStore {
    pool: Pool<SqliteConnectionManager>,
    encryption: Arc<dyn EncryptionAdapter>,
}

impl SqliteApiKeyStore {
    pub fn new(
        pool: Pool<SqliteConnectionManager>,
        encryption: Arc<dyn EncryptionAdapter>,
    ) -> Self {
        Self { pool, encryption }
    }
}

fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| StorageError::InvalidData(format!("invalid timestamp: {e}")))
}

#[async_trait]
impl ApiKeyStore for SqliteApiKeyStore {
    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, StorageError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, provider, created_at, updated_at FROM api_keys ORDER BY provider",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let records = stmt
                .query_map([], |row| {
                    let provider: String = row.get("provider")?;
                    let created_at: String = row.get("created_at")?;
                    let updated_at: String = row.get("updated_at")?;
                    Ok((provider, created_at, updated_at))
                })
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;

            let mut result = Vec::new();
            for (provider, created_at, updated_at) in records {
                result.push(ApiKeyRecord {
                    provider,
                    created_at: parse_timestamp(&created_at)?,
                    updated_at: parse_timestamp(&updated_at)?,
                });
            }
            Ok(result)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn get_key(&self, provider: &str) -> Result<Option<String>, StorageError> {
        let pool = self.pool.clone();
        let provider = provider.to_owned();
        let encryption = self.encryption.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, key_blob, nonce
                     FROM api_keys
                     WHERE id = ?1 COLLATE NOCASE OR provider = ?1 COLLATE NOCASE
                     ORDER BY CASE
                         WHEN id = ?1 THEN 0
                         WHEN provider = ?1 THEN 1
                         ELSE 2
                     END
                     LIMIT 1",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let row = stmt.query_row(rusqlite::params![provider], |row| {
                let stored_id: String = row.get(0)?;
                let key_blob: Vec<u8> = row.get(1)?;
                let nonce: Vec<u8> = row.get(2)?;
                Ok((stored_id, key_blob, nonce))
            });

            match row {
                Ok((stored_id, key_blob, nonce)) => {
                    // Backward compatibility: older rows were encrypted without AAD.
                    // Prefer AAD-bound decrypt, then fall back to legacy decrypt.
                    let (plaintext, legacy_mode) =
                        match encryption.decrypt_with_aad(&key_blob, &nonce, stored_id.as_bytes()) {
                            Ok(data) => (data, false),
                            Err(_) => (encryption.decrypt(&key_blob, &nonce)?, true),
                        };
                    // Opportunistic migration: once a legacy row is read successfully,
                    // rewrite it with provider-bound AAD to restore integrity guarantees.
                    if legacy_mode {
                        let (new_key_blob, new_nonce) =
                            encryption.encrypt_with_aad(&plaintext, stored_id.as_bytes())?;
                        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
                        conn.execute(
                            "UPDATE api_keys SET key_blob = ?1, nonce = ?2, updated_at = ?3 WHERE id = ?4",
                            rusqlite::params![new_key_blob, new_nonce, now, stored_id],
                        )
                        .map_err(|e| StorageError::Sqlite(e.to_string()))?;
                    };
                    let key =
                        String::from_utf8(plaintext).map_err(|_| StorageError::DecryptionFailed)?;
                    Ok(Some(key))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(StorageError::Sqlite(e.to_string())),
            }
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn set_key(&self, provider: &str, api_key: &str) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let provider = provider.to_owned();
        let encryption = self.encryption.clone();
        let (key_blob, nonce) =
            encryption.encrypt_with_aad(api_key.as_bytes(), provider.as_bytes())?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            // Remove legacy case-variant rows (but not the exact-match id)
            // so we converge on a single canonical entry.
            tx.execute(
                "DELETE FROM api_keys \
                 WHERE (id = ?1 COLLATE NOCASE OR provider = ?1 COLLATE NOCASE) \
                 AND id != ?1",
                rusqlite::params![&provider],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            // Upsert: insert new or update existing, preserving created_at.
            tx.execute(
                "INSERT INTO api_keys (id, key_blob, nonce, provider, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(id) DO UPDATE SET provider=?4, key_blob=?2, nonce=?3, updated_at=?6",
                rusqlite::params![&provider, key_blob, nonce, &provider, now, now],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            tx.commit()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn delete_key(&self, provider: &str) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let provider = provider.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            conn.execute(
                "DELETE FROM api_keys WHERE id = ?1 COLLATE NOCASE OR provider = ?1 COLLATE NOCASE",
                rusqlite::params![provider],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aes256GcmAdapter;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;

    fn make_store() -> SqliteApiKeyStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let enc = Arc::new(Aes256GcmAdapter::new(&key));
        SqliteApiKeyStore::new(pool, enc)
    }

    #[tokio::test]
    async fn set_and_get_roundtrip() {
        let store = make_store();
        store.set_key("openai", "sk-test-key-123").await.unwrap();
        let got = store.get_key("openai").await.unwrap();
        assert_eq!(got, Some("sk-test-key-123".to_string()));
    }

    #[tokio::test]
    async fn get_legacy_row_without_aad_still_works() {
        let store = make_store();
        let (key_blob, nonce) = store.encryption.encrypt(b"sk-legacy").unwrap();
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO api_keys (id, key_blob, nonce, provider, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["OpenAI", key_blob, nonce, "OpenAI", now, now],
            )
            .unwrap();
        }

        assert_eq!(
            store.get_key("openai").await.unwrap(),
            Some("sk-legacy".to_string())
        );
        assert_eq!(
            store.get_key("OPENAI").await.unwrap(),
            Some("sk-legacy".to_string())
        );
    }

    #[tokio::test]
    async fn legacy_row_is_upgraded_to_aad_on_read() {
        let store = make_store();
        let (key_blob, nonce) = store.encryption.encrypt(b"sk-legacy-upgrade").unwrap();
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "INSERT INTO api_keys (id, key_blob, nonce, provider, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["OpenAI", key_blob, nonce, "OpenAI", now, now],
            )
            .unwrap();
        }

        assert_eq!(
            store.get_key("openai").await.unwrap(),
            Some("sk-legacy-upgrade".to_string())
        );

        let (upgraded_blob, upgraded_nonce): (Vec<u8>, Vec<u8>) = {
            let conn = store.pool.get().unwrap();
            conn.query_row(
                "SELECT key_blob, nonce FROM api_keys WHERE id = 'OpenAI'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };

        let with_aad = store
            .encryption
            .decrypt_with_aad(&upgraded_blob, &upgraded_nonce, b"OpenAI")
            .unwrap();
        assert_eq!(String::from_utf8(with_aad).unwrap(), "sk-legacy-upgrade");
        assert!(
            store
                .encryption
                .decrypt(&upgraded_blob, &upgraded_nonce)
                .is_err(),
            "upgraded row should require AAD"
        );
    }

    #[tokio::test]
    async fn list_returns_providers_only() {
        let store = make_store();
        store.set_key("openai", "sk-open").await.unwrap();
        store.set_key("anthropic", "sk-anth").await.unwrap();
        let records = store.list_keys().await.unwrap();
        assert_eq!(records.len(), 2);
        // list_keys returns provider metadata, never the key value
        let providers: Vec<&str> = records.iter().map(|r| r.provider.as_str()).collect();
        assert!(providers.contains(&"openai"));
        assert!(providers.contains(&"anthropic"));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = make_store();
        let got = store.get_key("nonexistent").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let store = make_store();
        store.set_key("openai", "sk-test").await.unwrap();
        store.delete_key("openai").await.unwrap();
        let got = store.get_key("openai").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn set_same_provider_upserts() {
        let store = make_store();
        store.set_key("openai", "old-key").await.unwrap();
        let records_before = store.list_keys().await.unwrap();
        let created_at = records_before[0].created_at;

        // Small delay so updated_at would differ if timestamps change
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        store.set_key("openai", "new-key").await.unwrap();
        let got = store.get_key("openai").await.unwrap();
        assert_eq!(got, Some("new-key".to_string()));
        let records = store.list_keys().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].created_at, created_at,
            "created_at should be preserved on upsert"
        );
    }

    #[tokio::test]
    async fn get_is_case_insensitive_for_legacy_rows() {
        let store = make_store();
        store.set_key("OpenAI", "sk-mixed-case").await.unwrap();

        assert_eq!(
            store.get_key("openai").await.unwrap(),
            Some("sk-mixed-case".to_string())
        );
        assert_eq!(
            store.get_key("OPENAI").await.unwrap(),
            Some("sk-mixed-case".to_string())
        );
    }

    #[tokio::test]
    async fn delete_is_case_insensitive_for_legacy_rows() {
        let store = make_store();
        store.set_key("OpenAI", "sk-mixed-case").await.unwrap();

        store.delete_key("openai").await.unwrap();
        assert!(store.get_key("OpenAI").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_removes_case_variant_duplicates() {
        let store = make_store();
        store.set_key("OpenAI", "old").await.unwrap();
        store.set_key("openai", "new").await.unwrap();

        let count: i64 = {
            let conn = store.pool.get().unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM api_keys WHERE id = 'openai' COLLATE NOCASE",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(count, 1);
        assert_eq!(
            store.get_key("OPENAI").await.unwrap(),
            Some("new".to_string())
        );
    }

    #[tokio::test]
    async fn get_after_delete_returns_none() {
        let store = make_store();
        store.set_key("openai", "sk-key").await.unwrap();
        assert!(store.get_key("openai").await.unwrap().is_some());
        store.delete_key("openai").await.unwrap();
        assert!(store.get_key("openai").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn nonce_differs_per_write() {
        let store = make_store();
        store.set_key("openai", "key-1").await.unwrap();
        let nonce1: Vec<u8> = {
            let conn = store.pool.get().unwrap();
            conn.query_row(
                "SELECT nonce FROM api_keys WHERE id = 'openai'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        store.set_key("openai", "key-2").await.unwrap();
        let nonce2: Vec<u8> = {
            let conn = store.pool.get().unwrap();
            conn.query_row(
                "SELECT nonce FROM api_keys WHERE id = 'openai'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_ne!(nonce1, nonce2, "nonce should differ on each write");
    }

    #[tokio::test]
    async fn corrupted_blob_returns_error() {
        let store = make_store();
        store.set_key("openai", "real-key").await.unwrap();
        // Corrupt the key_blob directly
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "UPDATE api_keys SET key_blob = X'DEADBEEF' WHERE id = 'openai'",
                [],
            )
            .unwrap();
        }
        let result = store.get_key("openai").await;
        assert!(result.is_err(), "corrupted blob should fail decryption");
    }

    #[tokio::test]
    async fn swapped_blob_between_providers_fails_decryption() {
        let store = make_store();
        store.set_key("openai", "sk-open").await.unwrap();
        store.set_key("anthropic", "sk-anth").await.unwrap();

        // Swap key_blob and nonce from anthropic into openai's row
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "UPDATE api_keys SET key_blob = (SELECT key_blob FROM api_keys WHERE id = 'anthropic'), \
                 nonce = (SELECT nonce FROM api_keys WHERE id = 'anthropic') WHERE id = 'openai'",
                [],
            )
            .unwrap();
        }

        let result = store.get_key("openai").await;
        assert!(
            result.is_err(),
            "swapped blob should fail due to AAD mismatch"
        );
    }
}
