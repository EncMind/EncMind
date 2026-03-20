use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::PluginError;
use encmind_core::plugin::PluginStateStore;

/// SQLite-backed plugin state store.
///
/// Reuses the existing `skill_kv` table (composite PK `skill_id, key`).
/// Plugin state is stored using `plugin:{plugin_id}` as the `skill_id` prefix
/// to avoid collisions with WASM skill KV data.
pub struct SqlitePluginStateStore {
    pool: Pool<SqliteConnectionManager>,
    /// Prefixed plugin ID used as `skill_id` in the `skill_kv` table.
    prefixed_id: String,
}

impl SqlitePluginStateStore {
    pub fn new(pool: Pool<SqliteConnectionManager>, plugin_id: &str) -> Self {
        Self {
            pool,
            prefixed_id: format!("plugin:{plugin_id}"),
        }
    }
}

impl PluginStateStore for SqlitePluginStateStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PluginError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| PluginError::MethodError(e.to_string()))?;
        let result = conn.query_row(
            "SELECT value FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
            rusqlite::params![self.prefixed_id, key],
            |row| row.get(0),
        );
        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(PluginError::MethodError(e.to_string())),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), PluginError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| PluginError::MethodError(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO skill_kv (skill_id, key, value, updated_at) \
             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
            rusqlite::params![self.prefixed_id, key, value],
        )
        .map_err(|e| PluginError::MethodError(e.to_string()))?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), PluginError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| PluginError::MethodError(e.to_string()))?;
        conn.execute(
            "DELETE FROM skill_kv WHERE skill_id = ?1 AND key = ?2",
            rusqlite::params![self.prefixed_id, key],
        )
        .map_err(|e| PluginError::MethodError(e.to_string()))?;
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, PluginError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| PluginError::MethodError(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT key FROM skill_kv WHERE skill_id = ?1 ORDER BY key")
            .map_err(|e| PluginError::MethodError(e.to_string()))?;
        let keys = stmt
            .query_map(rusqlite::params![self.prefixed_id], |row| row.get(0))
            .map_err(|e| PluginError::MethodError(e.to_string()))?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| PluginError::MethodError(e.to_string()))?;
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::run_migrations;
    use crate::pool::create_test_pool;

    fn setup(plugin_id: &str) -> SqlitePluginStateStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        SqlitePluginStateStore::new(pool, plugin_id)
    }

    #[test]
    fn get_set_roundtrip() {
        let store = setup("browser");
        assert!(store.get("theme").unwrap().is_none());

        store.set("theme", b"dark").unwrap();
        assert_eq!(store.get("theme").unwrap().unwrap(), b"dark");

        // Overwrite
        store.set("theme", b"light").unwrap();
        assert_eq!(store.get("theme").unwrap().unwrap(), b"light");
    }

    #[test]
    fn delete_key() {
        let store = setup("browser");
        store.set("temp", b"val").unwrap();
        assert!(store.get("temp").unwrap().is_some());

        store.delete("temp").unwrap();
        assert!(store.get("temp").unwrap().is_none());
    }

    #[test]
    fn list_keys_returns_sorted() {
        let store = setup("browser");
        store.set("beta", b"2").unwrap();
        store.set("alpha", b"1").unwrap();
        store.set("gamma", b"3").unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn cross_plugin_isolation() {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        let store_a = SqlitePluginStateStore::new(pool.clone(), "plugin-a");
        let store_b = SqlitePluginStateStore::new(pool, "plugin-b");

        store_a.set("key", b"val-a").unwrap();
        store_b.set("key", b"val-b").unwrap();

        assert_eq!(store_a.get("key").unwrap().unwrap(), b"val-a");
        assert_eq!(store_b.get("key").unwrap().unwrap(), b"val-b");
    }
}
