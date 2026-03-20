use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::StorageError;
use encmind_core::traits::DeviceStore;
use encmind_core::types::{DevicePermissions, PairedDevice};

pub struct SqliteDeviceStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteDeviceStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceStore for SqliteDeviceStore {
    async fn list_devices(&self) -> Result<Vec<PairedDevice>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, public_key, permissions, paired_at, last_seen \
                 FROM paired_devices ORDER BY paired_at DESC",
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let devices = stmt
            .query_map([], |row| {
                let perms_json: String = row.get(3)?;
                let permissions: DevicePermissions =
                    serde_json::from_str(&perms_json).unwrap_or_default();
                let paired_at_str: String = row.get(4)?;
                let last_seen_str: Option<String> = row.get(5)?;
                Ok(PairedDevice {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: row.get(2)?,
                    permissions,
                    paired_at: parse_datetime(&paired_at_str),
                    last_seen: last_seen_str.as_deref().map(parse_datetime),
                })
            })
            .map_err(|e| StorageError::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(devices)
    }

    async fn get_device(&self, id: &str) -> Result<Option<PairedDevice>, StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let result = conn.query_row(
            "SELECT id, name, public_key, permissions, paired_at, last_seen \
             FROM paired_devices WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let perms_json: String = row.get(3)?;
                let permissions: DevicePermissions =
                    serde_json::from_str(&perms_json).unwrap_or_default();
                let paired_at_str: String = row.get(4)?;
                let last_seen_str: Option<String> = row.get(5)?;
                Ok(PairedDevice {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: row.get(2)?,
                    permissions,
                    paired_at: parse_datetime(&paired_at_str),
                    last_seen: last_seen_str.as_deref().map(parse_datetime),
                })
            },
        );

        match result {
            Ok(device) => Ok(Some(device)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Sqlite(e.to_string())),
        }
    }

    async fn add_device(&self, device: &PairedDevice) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let perms_json = serde_json::to_string(&device.permissions)
            .map_err(|e| StorageError::InvalidData(e.to_string()))?;
        let paired_at_str = device.paired_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let last_seen_str = device
            .last_seen
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

        conn.execute(
            "INSERT INTO paired_devices (id, name, public_key, permissions, paired_at, last_seen) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(id) DO UPDATE SET \
               name = excluded.name, \
               public_key = excluded.public_key, \
               permissions = excluded.permissions, \
               paired_at = excluded.paired_at, \
               last_seen = NULL",
            rusqlite::params![
                device.id,
                device.name,
                device.public_key,
                perms_json,
                paired_at_str,
                last_seen_str,
            ],
        )
        .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        Ok(())
    }

    async fn update_permissions(
        &self,
        id: &str,
        permissions: &DevicePermissions,
    ) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let perms_json = serde_json::to_string(permissions)
            .map_err(|e| StorageError::InvalidData(e.to_string()))?;

        let rows = conn
            .execute(
                "UPDATE paired_devices SET permissions = ?1 WHERE id = ?2",
                rusqlite::params![perms_json, id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("device {id}")));
        }
        Ok(())
    }

    async fn update_last_seen(
        &self,
        id: &str,
        last_seen: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let last_seen_str = last_seen.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let rows = conn
            .execute(
                "UPDATE paired_devices SET last_seen = ?1 WHERE id = ?2",
                rusqlite::params![last_seen_str, id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("device {id}")));
        }
        Ok(())
    }

    async fn remove_device(&self, id: &str) -> Result<(), StorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        let rows = conn
            .execute(
                "DELETE FROM paired_devices WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("device {id}")));
        }
        Ok(())
    }
}

fn parse_datetime(s: &str) -> DateTime<Utc> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .map(|ndt| ndt.and_utc())
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;

    fn setup() -> SqliteDeviceStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        SqliteDeviceStore::new(pool)
    }

    fn make_device(id: &str, name: &str) -> PairedDevice {
        PairedDevice {
            id: id.into(),
            name: name.into(),
            public_key: vec![1, 2, 3, 4],
            permissions: DevicePermissions {
                chat: true,
                ..Default::default()
            },
            paired_at: Utc::now(),
            last_seen: None,
        }
    }

    #[tokio::test]
    async fn add_and_get_device() {
        let store = setup();
        let dev = make_device("dev-1", "Laptop");
        store.add_device(&dev).await.unwrap();

        let fetched = store.get_device("dev-1").await.unwrap().unwrap();
        assert_eq!(fetched.id, "dev-1");
        assert_eq!(fetched.name, "Laptop");
        assert!(fetched.permissions.chat);
    }

    #[tokio::test]
    async fn get_nonexistent_device_returns_none() {
        let store = setup();
        let result = store.get_device("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_devices() {
        let store = setup();
        store
            .add_device(&make_device("dev-1", "Laptop"))
            .await
            .unwrap();
        store
            .add_device(&make_device("dev-2", "Phone"))
            .await
            .unwrap();

        let devices = store.list_devices().await.unwrap();
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn update_permissions() {
        let store = setup();
        store
            .add_device(&make_device("dev-1", "Laptop"))
            .await
            .unwrap();

        let new_perms = DevicePermissions {
            file_read: true,
            bash_exec: true,
            chat: true,
            ..Default::default()
        };
        store.update_permissions("dev-1", &new_perms).await.unwrap();

        let fetched = store.get_device("dev-1").await.unwrap().unwrap();
        assert!(fetched.permissions.file_read);
        assert!(fetched.permissions.bash_exec);
        assert!(fetched.permissions.chat);
        assert!(!fetched.permissions.file_write);
    }

    #[tokio::test]
    async fn update_permissions_nonexistent() {
        let store = setup();
        let result = store
            .update_permissions("nope", &DevicePermissions::default())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn update_last_seen() {
        let store = setup();
        store
            .add_device(&make_device("dev-1", "Laptop"))
            .await
            .unwrap();

        let now = Utc::now();
        store.update_last_seen("dev-1", now).await.unwrap();

        let fetched = store.get_device("dev-1").await.unwrap().unwrap();
        assert!(fetched.last_seen.is_some());
    }

    #[tokio::test]
    async fn remove_device() {
        let store = setup();
        store
            .add_device(&make_device("dev-1", "Laptop"))
            .await
            .unwrap();

        store.remove_device("dev-1").await.unwrap();

        let result = store.get_device("dev-1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn remove_nonexistent_device() {
        let store = setup();
        let result = store.remove_device("nope").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn public_key_stored_as_blob() {
        let store = setup();
        let dev = PairedDevice {
            id: "dev-blob".into(),
            name: "Blob Test".into(),
            public_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            permissions: DevicePermissions::default(),
            paired_at: Utc::now(),
            last_seen: None,
        };
        store.add_device(&dev).await.unwrap();

        let fetched = store.get_device("dev-blob").await.unwrap().unwrap();
        assert_eq!(fetched.public_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn add_device_upserts_on_conflict() {
        let store = setup();
        let dev1 = make_device("dev-upsert", "Original");
        store.add_device(&dev1).await.unwrap();

        // Re-add with different name and key
        let dev2 = PairedDevice {
            id: "dev-upsert".into(),
            name: "Updated".into(),
            public_key: vec![5, 6, 7, 8],
            permissions: DevicePermissions {
                chat: true,
                file_read: true,
                ..Default::default()
            },
            paired_at: Utc::now(),
            last_seen: Some(Utc::now()),
        };
        store.add_device(&dev2).await.unwrap();

        let fetched = store.get_device("dev-upsert").await.unwrap().unwrap();
        assert_eq!(fetched.name, "Updated");
        assert_eq!(fetched.public_key, vec![5, 6, 7, 8]);
        assert!(fetched.permissions.file_read);
        // last_seen should be reset to NULL on re-pair
        assert!(fetched.last_seen.is_none());
    }

    #[tokio::test]
    async fn permissions_stored_as_json() {
        let store = setup();
        let dev = PairedDevice {
            id: "dev-json".into(),
            name: "JSON Test".into(),
            public_key: vec![1],
            permissions: DevicePermissions {
                file_read: true,
                file_write: true,
                file_list: true,
                bash_exec: true,
                chat: true,
                admin: false,
            },
            paired_at: Utc::now(),
            last_seen: None,
        };
        store.add_device(&dev).await.unwrap();

        let fetched = store.get_device("dev-json").await.unwrap().unwrap();
        assert!(fetched.permissions.file_read);
        assert!(fetched.permissions.file_write);
        assert!(fetched.permissions.file_list);
        assert!(fetched.permissions.bash_exec);
        assert!(fetched.permissions.chat);
    }
}
