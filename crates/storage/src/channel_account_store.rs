use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;

use encmind_core::error::StorageError;
use encmind_core::traits::{ChannelAccountStore, EncryptionAdapter};
use encmind_core::types::{
    ChannelAccount, ChannelAccountId, ChannelAccountStatus, ChannelPolicy, ConfigSource,
};

pub struct SqliteChannelAccountStore {
    pool: Pool<SqliteConnectionManager>,
    encryption: Arc<dyn EncryptionAdapter>,
}

impl SqliteChannelAccountStore {
    pub fn new(
        pool: Pool<SqliteConnectionManager>,
        encryption: Arc<dyn EncryptionAdapter>,
    ) -> Self {
        Self { pool, encryption }
    }

    /// Store encrypted credentials for a channel account.
    /// Uses AES-256-GCM with account_id as AAD to bind ciphertext to the account.
    pub async fn store_credential(
        &self,
        account_id: &ChannelAccountId,
        credential_json: &str,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let account_id = account_id.as_str().to_owned();
        let encryption = self.encryption.clone();
        let (cred_blob, nonce) =
            encryption.encrypt_with_aad(credential_json.as_bytes(), account_id.as_bytes())?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            conn.execute(
                "INSERT INTO channel_credentials (account_id, cred_blob, nonce, updated_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(account_id) DO UPDATE SET cred_blob=?2, nonce=?3, updated_at=?4",
                rusqlite::params![account_id, cred_blob, nonce, now],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    /// Retrieve and decrypt credentials for a channel account.
    pub async fn get_credential(
        &self,
        account_id: &ChannelAccountId,
    ) -> Result<Option<String>, StorageError> {
        let pool = self.pool.clone();
        let account_id = account_id.as_str().to_owned();
        let encryption = self.encryption.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let row = conn.query_row(
                "SELECT cred_blob, nonce FROM channel_credentials WHERE account_id = ?1",
                rusqlite::params![account_id],
                |row| {
                    let cred_blob: Vec<u8> = row.get(0)?;
                    let nonce: Vec<u8> = row.get(1)?;
                    Ok((cred_blob, nonce))
                },
            );
            match row {
                Ok((cred_blob, nonce)) => {
                    let plaintext =
                        encryption.decrypt_with_aad(&cred_blob, &nonce, account_id.as_bytes())?;
                    let json =
                        String::from_utf8(plaintext).map_err(|_| StorageError::DecryptionFailed)?;
                    Ok(Some(json))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(StorageError::Sqlite(e.to_string())),
            }
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    /// Delete credentials for a channel account.
    pub async fn delete_credential(
        &self,
        account_id: &ChannelAccountId,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let account_id = account_id.as_str().to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            conn.execute(
                "DELETE FROM channel_credentials WHERE account_id = ?1",
                rusqlite::params![account_id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    /// Get per-channel policy for an account.
    pub async fn get_policy(
        &self,
        account_id: &ChannelAccountId,
    ) -> Result<Option<ChannelPolicy>, StorageError> {
        let pool = self.pool.clone();
        let account_id = account_id.as_str().to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let row = conn.query_row(
                "SELECT policy_json FROM channel_accounts WHERE id = ?1",
                rusqlite::params![account_id],
                |row| {
                    let policy_json: Option<String> = row.get(0)?;
                    Ok(policy_json)
                },
            );
            match row {
                Ok(Some(json)) => {
                    let policy: ChannelPolicy = serde_json::from_str(&json).map_err(|e| {
                        StorageError::InvalidData(format!("invalid policy JSON: {e}"))
                    })?;
                    Ok(Some(policy))
                }
                Ok(None) => Ok(None),
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    Err(StorageError::NotFound(format!("account {account_id}")))
                }
                Err(e) => Err(StorageError::Sqlite(e.to_string())),
            }
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    /// Set per-channel policy for an account.
    pub async fn set_policy(
        &self,
        account_id: &ChannelAccountId,
        policy: &ChannelPolicy,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let account_id = account_id.as_str().to_owned();
        let policy_json = serde_json::to_string(policy)
            .map_err(|e| StorageError::InvalidData(format!("failed to serialize policy: {e}")))?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute(
                    "UPDATE channel_accounts SET policy_json = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![policy_json, now, account_id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("account {account_id}")));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }
}

fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| StorageError::InvalidData(format!("invalid timestamp: {e}")))
}

fn parse_status(s: &str) -> ChannelAccountStatus {
    match s {
        "active" => ChannelAccountStatus::Active,
        "degraded" => ChannelAccountStatus::Degraded,
        "stopped" => ChannelAccountStatus::Stopped,
        "login_required" => ChannelAccountStatus::LoginRequired,
        "error" => ChannelAccountStatus::Error,
        _ => ChannelAccountStatus::Error,
    }
}

fn status_to_str(status: &ChannelAccountStatus) -> &'static str {
    match status {
        ChannelAccountStatus::Active => "active",
        ChannelAccountStatus::Degraded => "degraded",
        ChannelAccountStatus::Stopped => "stopped",
        ChannelAccountStatus::LoginRequired => "login_required",
        ChannelAccountStatus::Error => "error",
    }
}

fn parse_config_source(s: &str) -> ConfigSource {
    match s {
        "config_file" => ConfigSource::ConfigFile,
        _ => ConfigSource::Api,
    }
}

fn config_source_to_str(source: &ConfigSource) -> &'static str {
    match source {
        ConfigSource::ConfigFile => "config_file",
        ConfigSource::Api => "api",
    }
}

fn is_channel_type_unique_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(sql_err, msg)
            if sql_err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            let msg = msg.as_deref().unwrap_or_default();
            msg.contains("channel_accounts.channel_type")
                || msg.contains("idx_channel_accounts_type_unique")
        }
        _ => false,
    }
}

struct ChannelAccountRow {
    id: String,
    channel_type: String,
    label: String,
    enabled: i64,
    status: String,
    config_source: String,
    policy_json: Option<String>,
    created_at: String,
    updated_at: String,
}

fn row_to_account(row: &rusqlite::Row) -> Result<ChannelAccountRow, rusqlite::Error> {
    Ok(ChannelAccountRow {
        id: row.get::<_, String>(0)?,
        channel_type: row.get::<_, String>(1)?,
        label: row.get::<_, String>(2)?,
        enabled: row.get::<_, i64>(3)?,
        status: row.get::<_, String>(4)?,
        config_source: row.get::<_, String>(5)?,
        policy_json: row.get::<_, Option<String>>(6)?,
        created_at: row.get::<_, String>(7)?,
        updated_at: row.get::<_, String>(8)?,
    })
}

fn build_account(row: ChannelAccountRow) -> Result<ChannelAccount, StorageError> {
    let policy = match row.policy_json {
        Some(json) => Some(
            serde_json::from_str(&json)
                .map_err(|e| StorageError::InvalidData(format!("invalid policy JSON: {e}")))?,
        ),
        None => None,
    };
    Ok(ChannelAccount {
        id: ChannelAccountId::from_string(row.id),
        channel_type: row.channel_type,
        label: row.label,
        enabled: row.enabled != 0,
        status: parse_status(&row.status),
        config_source: parse_config_source(&row.config_source),
        policy,
        created_at: parse_timestamp(&row.created_at)?,
        updated_at: parse_timestamp(&row.updated_at)?,
    })
}

#[async_trait]
impl ChannelAccountStore for SqliteChannelAccountStore {
    async fn list_accounts(&self) -> Result<Vec<ChannelAccount>, StorageError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, channel_type, label, enabled, status, config_source, policy_json, created_at, updated_at \
                     FROM channel_accounts ORDER BY created_at",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map([], row_to_account)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;

            let mut result = Vec::new();
            for row in rows {
                result.push(build_account(row)?);
            }
            Ok(result)
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn get_account(
        &self,
        id: &ChannelAccountId,
    ) -> Result<Option<ChannelAccount>, StorageError> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let row = conn.query_row(
                "SELECT id, channel_type, label, enabled, status, config_source, policy_json, created_at, updated_at \
                 FROM channel_accounts WHERE id = ?1",
                rusqlite::params![id],
                row_to_account,
            );
            match row {
                Ok(row) => Ok(Some(build_account(row)?)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(StorageError::Sqlite(e.to_string())),
            }
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn get_account_by_type(
        &self,
        channel_type: &str,
    ) -> Result<Option<ChannelAccount>, StorageError> {
        let pool = self.pool.clone();
        let channel_type = channel_type.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, channel_type, label, enabled, status, config_source, policy_json, created_at, updated_at \
                     FROM channel_accounts WHERE channel_type = ?1 ORDER BY created_at DESC LIMIT 2",
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![channel_type], row_to_account)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            match rows.as_slice() {
                [] => Ok(None),
                [row] => Ok(Some(build_account(ChannelAccountRow {
                    id: row.id.clone(),
                    channel_type: row.channel_type.clone(),
                    label: row.label.clone(),
                    enabled: row.enabled,
                    status: row.status.clone(),
                    config_source: row.config_source.clone(),
                    policy_json: row.policy_json.clone(),
                    created_at: row.created_at.clone(),
                    updated_at: row.updated_at.clone(),
                })?)),
                _ => {
                    Err(StorageError::InvalidData(
                        "multiple accounts configured for channel_type; use account id".to_string(),
                    ))
                }
            }
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn create_account(&self, account: &ChannelAccount) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = account.id.as_str().to_owned();
        let channel_type = account.channel_type.clone();
        let label = account.label.clone();
        let enabled = account.enabled as i64;
        let status = status_to_str(&account.status).to_owned();
        let config_source = config_source_to_str(&account.config_source).to_owned();
        let policy_json = account
            .policy
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_default());
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let existing: Option<String> = conn
                .query_row(
                    "SELECT id FROM channel_accounts WHERE channel_type = ?1 LIMIT 1",
                    rusqlite::params![channel_type],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if existing.is_some() {
                return Err(StorageError::InvalidData(
                    "channel_type already exists; remove existing account or use account id"
                        .to_string(),
                ));
            }
            conn.execute(
                "INSERT INTO channel_accounts (id, channel_type, label, enabled, status, config_source, policy_json, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![id, channel_type, label, enabled, status, config_source, policy_json, now, now],
            )
            .map_err(|e| {
                if is_channel_type_unique_violation(&e) {
                    StorageError::InvalidData(
                        "channel_type already exists; remove existing account or use account id"
                            .to_string(),
                    )
                } else {
                    StorageError::Sqlite(e.to_string())
                }
            })?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn update_account(&self, account: &ChannelAccount) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = account.id.as_str().to_owned();
        let label = account.label.clone();
        let enabled = account.enabled as i64;
        let status = status_to_str(&account.status).to_owned();
        let policy_json = account
            .policy
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_default());
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute(
                    "UPDATE channel_accounts SET label=?1, enabled=?2, status=?3, policy_json=?4, updated_at=?5 WHERE id=?6",
                    rusqlite::params![label, enabled, status, policy_json, now, id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("account {id}")));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn delete_account(&self, id: &ChannelAccountId) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            conn.execute(
                "DELETE FROM channel_accounts WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn update_status(
        &self,
        id: &ChannelAccountId,
        status: ChannelAccountStatus,
    ) -> Result<(), StorageError> {
        let pool = self.pool.clone();
        let id = id.as_str().to_owned();
        let status_str = status_to_str(&status).to_owned();
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            let rows = conn
                .execute(
                    "UPDATE channel_accounts SET status=?1, updated_at=?2 WHERE id=?3",
                    rusqlite::params![status_str, now, id],
                )
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            if rows == 0 {
                return Err(StorageError::NotFound(format!("account {id}")));
            }
            Ok(())
        })
        .await
        .map_err(|e| StorageError::Sqlite(e.to_string()))?
    }

    async fn store_credential(
        &self,
        id: &ChannelAccountId,
        credential_json: &str,
    ) -> Result<(), StorageError> {
        SqliteChannelAccountStore::store_credential(self, id, credential_json).await
    }

    async fn get_credential(&self, id: &ChannelAccountId) -> Result<Option<String>, StorageError> {
        SqliteChannelAccountStore::get_credential(self, id).await
    }

    async fn delete_credential(&self, id: &ChannelAccountId) -> Result<(), StorageError> {
        SqliteChannelAccountStore::delete_credential(self, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aes256GcmAdapter;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;
    use encmind_core::types::DenylistEntry;

    fn make_store() -> SqliteChannelAccountStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let key = [0u8; 32];
        let enc = Arc::new(Aes256GcmAdapter::new(&key));
        SqliteChannelAccountStore::new(pool, enc)
    }

    fn make_account(channel_type: &str, label: &str) -> ChannelAccount {
        ChannelAccount {
            id: ChannelAccountId::new(),
            channel_type: channel_type.into(),
            label: label.into(),
            enabled: true,
            status: ChannelAccountStatus::Stopped,
            config_source: ConfigSource::Api,
            policy: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let store = make_store();
        let account = make_account("telegram", "My Bot");
        store.create_account(&account).await.unwrap();

        let got = store.get_account(&account.id).await.unwrap().unwrap();
        assert_eq!(got.id, account.id);
        assert_eq!(got.channel_type, "telegram");
        assert_eq!(got.label, "My Bot");
        assert!(got.enabled);
        assert_eq!(got.status, ChannelAccountStatus::Stopped);
    }

    #[tokio::test]
    async fn list_accounts_returns_all() {
        let store = make_store();
        store
            .create_account(&make_account("telegram", "Bot 1"))
            .await
            .unwrap();
        store
            .create_account(&make_account("slack", "Slack 1"))
            .await
            .unwrap();

        let accounts = store.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 2);
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = make_store();
        let got = store
            .get_account(&ChannelAccountId::from_string("nonexistent"))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn get_account_by_type_works() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        let got = store
            .get_account_by_type("telegram")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.id, account.id);

        let missing = store.get_account_by_type("slack").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn update_account_changes_fields() {
        let store = make_store();
        let mut account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        account.label = "Updated Bot".into();
        account.enabled = false;
        account.status = ChannelAccountStatus::Active;
        store.update_account(&account).await.unwrap();

        let got = store.get_account(&account.id).await.unwrap().unwrap();
        assert_eq!(got.label, "Updated Bot");
        assert!(!got.enabled);
        assert_eq!(got.status, ChannelAccountStatus::Active);
    }

    #[tokio::test]
    async fn delete_account_removes_row() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();
        store.delete_account(&account.id).await.unwrap();

        let got = store.get_account(&account.id).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn update_status_works() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        store
            .update_status(&account.id, ChannelAccountStatus::Active)
            .await
            .unwrap();
        let got = store.get_account(&account.id).await.unwrap().unwrap();
        assert_eq!(got.status, ChannelAccountStatus::Active);

        store
            .update_status(&account.id, ChannelAccountStatus::Degraded)
            .await
            .unwrap();
        let got = store.get_account(&account.id).await.unwrap().unwrap();
        assert_eq!(got.status, ChannelAccountStatus::Degraded);
    }

    #[tokio::test]
    async fn credential_encrypt_decrypt_roundtrip() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        let cred = r#"{"bot_token":"123:ABC"}"#;
        store.store_credential(&account.id, cred).await.unwrap();

        let got = store.get_credential(&account.id).await.unwrap().unwrap();
        assert_eq!(got, cred);
    }

    #[tokio::test]
    async fn credential_aad_swap_detection() {
        let store = make_store();
        let acct1 = make_account("telegram", "Bot1");
        let acct2 = make_account("slack", "Bot2");
        store.create_account(&acct1).await.unwrap();
        store.create_account(&acct2).await.unwrap();

        store
            .store_credential(&acct1.id, r#"{"token":"t1"}"#)
            .await
            .unwrap();
        store
            .store_credential(&acct2.id, r#"{"token":"t2"}"#)
            .await
            .unwrap();

        // Swap credential blobs between accounts
        {
            let conn = store.pool.get().unwrap();
            conn.execute(
                "UPDATE channel_credentials SET cred_blob = (SELECT cred_blob FROM channel_credentials WHERE account_id = ?1), \
                 nonce = (SELECT nonce FROM channel_credentials WHERE account_id = ?1) WHERE account_id = ?2",
                rusqlite::params![acct2.id.as_str(), acct1.id.as_str()],
            )
            .unwrap();
        }

        let result = store.get_credential(&acct1.id).await;
        assert!(
            result.is_err(),
            "swapped blob should fail due to AAD mismatch"
        );
    }

    #[tokio::test]
    async fn delete_credential_removes_row() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();
        store.store_credential(&account.id, "secret").await.unwrap();

        store.delete_credential(&account.id).await.unwrap();
        let got = store.get_credential(&account.id).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn policy_store_and_retrieve() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        let policy = ChannelPolicy {
            dm_only: true,
            mention_gating: true,
            denylist: vec![DenylistEntry {
                sender_id: "spammer".into(),
                label: Some("Known spammer".into()),
            }],
            ..Default::default()
        };
        store.set_policy(&account.id, &policy).await.unwrap();

        let got = store.get_policy(&account.id).await.unwrap().unwrap();
        assert!(got.dm_only);
        assert!(got.mention_gating);
        assert_eq!(got.denylist.len(), 1);
        assert_eq!(got.denylist[0].sender_id, "spammer");
    }

    #[tokio::test]
    async fn policy_none_when_not_set() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        let got = store.get_policy(&account.id).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn delete_account_cascades_credentials() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();
        store.store_credential(&account.id, "secret").await.unwrap();

        store.delete_account(&account.id).await.unwrap();

        // Credential should also be gone (FK cascade)
        let got = store.get_credential(&account.id).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn credential_upsert_overwrites() {
        let store = make_store();
        let account = make_account("telegram", "Bot");
        store.create_account(&account).await.unwrap();

        store
            .store_credential(&account.id, "old-secret")
            .await
            .unwrap();
        store
            .store_credential(&account.id, "new-secret")
            .await
            .unwrap();

        let got = store.get_credential(&account.id).await.unwrap().unwrap();
        assert_eq!(got, "new-secret");
    }

    #[tokio::test]
    async fn update_nonexistent_account_returns_not_found() {
        let store = make_store();
        let result = store
            .update_status(
                &ChannelAccountId::from_string("nonexistent"),
                ChannelAccountStatus::Active,
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }
}
