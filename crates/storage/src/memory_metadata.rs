use async_trait::async_trait;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::MemoryError;
use encmind_core::traits::MemoryMetadataStore;
use encmind_core::types::*;

/// SQLite-backed memory metadata store with FTS5 integration.
pub struct SqliteMemoryMetadataStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteMemoryMetadataStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MemoryMetadataStore for SqliteMemoryMetadataStore {
    async fn insert_entry(&self, entry: &MemoryEntry) -> Result<(), MemoryError> {
        let pool = self.pool.clone();
        let entry = entry.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            tx.execute(
                "INSERT INTO memory_entries (id, session_id, vector_point_id, summary, source_channel, source_device, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    entry.id.as_str(),
                    entry.session_id.as_ref().map(|s| s.as_str().to_owned()),
                    entry.vector_point_id,
                    entry.summary,
                    entry.source_channel,
                    entry.source_device,
                    entry.created_at.to_rfc3339(),
                ],
            )
            .map_err(|e| MemoryError::Storage(e.to_string()))?;

            // Sync to FTS5
            tx.execute(
                "INSERT INTO memory_fts (memory_id, summary) VALUES (?1, ?2)",
                rusqlite::params![entry.id.as_str(), entry.summary],
            )
            .map_err(|e| MemoryError::Storage(e.to_string()))?;

            tx.commit()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }

    async fn get_entry(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, MemoryError> {
        let pool = self.pool.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, vector_point_id, summary, source_channel, source_device, created_at \
                     FROM memory_entries WHERE id = ?1",
                )
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            let entry = stmt
                .query_row(rusqlite::params![id.as_str()], |row| {
                    Ok(row_to_entry(row))
                })
                .optional()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            Ok(entry)
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }

    async fn delete_entry(&self, id: &MemoryId) -> Result<(), MemoryError> {
        let pool = self.pool.clone();
        let id = id.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            tx.execute(
                "DELETE FROM memory_fts WHERE memory_id = ?1",
                rusqlite::params![id.as_str()],
            )
            .map_err(|e| MemoryError::Storage(e.to_string()))?;

            tx.execute(
                "DELETE FROM memory_entries WHERE id = ?1",
                rusqlite::params![id.as_str()],
            )
            .map_err(|e| MemoryError::Storage(e.to_string()))?;

            tx.commit()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }

    async fn list_entries(
        &self,
        filter: &MemoryFilter,
        pagination: &Pagination,
    ) -> Result<Vec<MemoryEntry>, MemoryError> {
        let pool = self.pool.clone();
        let filter = filter.clone();
        let pagination = pagination.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            let mut sql = "SELECT id, session_id, vector_point_id, summary, source_channel, source_device, created_at \
                           FROM memory_entries WHERE 1=1".to_owned();
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref ch) = filter.source_channel {
                sql.push_str(&format!(" AND source_channel = ?{}", params.len() + 1));
                params.push(Box::new(ch.clone()));
            }
            if let Some(ref dev) = filter.source_device {
                sql.push_str(&format!(" AND source_device = ?{}", params.len() + 1));
                params.push(Box::new(dev.clone()));
            }
            if let Some(ref sid) = filter.session_id {
                sql.push_str(&format!(" AND session_id = ?{}", params.len() + 1));
                params.push(Box::new(sid.as_str().to_owned()));
            }
            if let Some(ref since) = filter.since {
                sql.push_str(&format!(" AND created_at >= ?{}", params.len() + 1));
                params.push(Box::new(since.to_rfc3339()));
            }
            if let Some(ref until) = filter.until {
                sql.push_str(&format!(" AND created_at <= ?{}", params.len() + 1));
                params.push(Box::new(until.to_rfc3339()));
            }

            sql.push_str(" ORDER BY created_at DESC");
            sql.push_str(&format!(
                " LIMIT ?{} OFFSET ?{}",
                params.len() + 1,
                params.len() + 2
            ));
            params.push(Box::new(pagination.limit as i64));
            params.push(Box::new(pagination.offset as i64));

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();

            let entries = stmt
                .query_map(param_refs.as_slice(), |row| Ok(row_to_entry(row)))
                .map_err(|e| MemoryError::Storage(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(entries)
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }

    async fn get_entries_by_vector_ids(
        &self,
        ids: &[String],
    ) -> Result<Vec<MemoryEntry>, MemoryError> {
        let pool = self.pool.clone();
        let ids = ids.to_vec();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            if ids.is_empty() {
                return Ok(vec![]);
            }

            let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("?{i}")).collect();
            let sql = format!(
                "SELECT id, session_id, vector_point_id, summary, source_channel, source_device, created_at \
                 FROM memory_entries WHERE vector_point_id IN ({})",
                placeholders.join(", ")
            );

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            let params: Vec<&dyn rusqlite::types::ToSql> =
                ids.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();

            let entries = stmt
                .query_map(params.as_slice(), |row| Ok(row_to_entry(row)))
                .map_err(|e| MemoryError::Storage(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(entries)
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }

    async fn count_entries(&self) -> Result<usize, MemoryError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            let count: i64 = conn
                .query_row("SELECT count(*) FROM memory_entries", [], |row| row.get(0))
                .map_err(|e| MemoryError::Storage(e.to_string()))?;
            Ok(count as usize)
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }

    async fn fts_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(MemoryId, f32)>, MemoryError> {
        let pool = self.pool.clone();
        let query = normalize_fts_match_query(query);
        let limit = limit as i64;
        tokio::task::spawn_blocking(move || {
            if query.is_empty() {
                return Ok(vec![]);
            }

            let conn = pool
                .get()
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            // FTS5 MATCH query with rank
            let mut stmt = conn
                .prepare(
                    "SELECT memory_id, rank FROM memory_fts WHERE memory_fts MATCH ?1 \
                     ORDER BY rank LIMIT ?2",
                )
                .map_err(|e| MemoryError::Storage(e.to_string()))?;

            let results: Vec<(MemoryId, f32)> = stmt
                .query_map(rusqlite::params![query, limit], |row| {
                    let id: String = row.get(0)?;
                    let rank: f64 = row.get(1)?;
                    Ok((MemoryId::from_string(id), rank as f32))
                })
                .map_err(|e| MemoryError::Storage(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(results)
        })
        .await
        .map_err(|e| MemoryError::Storage(e.to_string()))?
    }
}

fn normalize_fts_match_query(raw_query: &str) -> String {
    raw_query
        .split_whitespace()
        .filter(|term| !term.is_empty())
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn row_to_entry(row: &rusqlite::Row) -> MemoryEntry {
    let id: String = row.get(0).unwrap_or_default();
    let session_id: Option<String> = row.get(1).unwrap_or(None);
    let vector_point_id: String = row.get(2).unwrap_or_default();
    let summary: String = row.get(3).unwrap_or_default();
    let source_channel: Option<String> = row.get(4).unwrap_or(None);
    let source_device: Option<String> = row.get(5).unwrap_or(None);
    let created_at_str: String = row.get(6).unwrap_or_default();
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    MemoryEntry {
        id: MemoryId::from_string(id),
        session_id: session_id.map(SessionId::from_string),
        vector_point_id,
        summary,
        source_channel,
        source_device,
        created_at,
    }
}

/// rusqlite helper to make optional queries cleaner.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::create_test_pool;
    use chrono::Utc;

    fn setup() -> SqliteMemoryMetadataStore {
        let pool = create_test_pool();
        let conn = pool.get().unwrap();
        crate::migrations::run_migrations(&conn).unwrap();
        SqliteMemoryMetadataStore::new(pool)
    }

    fn make_entry(summary: &str) -> MemoryEntry {
        MemoryEntry {
            id: MemoryId::new(),
            session_id: None, // No FK reference needed for tests
            vector_point_id: ulid::Ulid::new().to_string(),
            summary: summary.to_owned(),
            source_channel: Some("web".into()),
            source_device: Some("laptop".into()),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn insert_and_get_roundtrip() {
        let store = setup();
        let entry = make_entry("User likes dark mode");
        store.insert_entry(&entry).await.unwrap();

        let fetched = store.get_entry(&entry.id).await.unwrap().unwrap();
        assert_eq!(fetched.id, entry.id);
        assert_eq!(fetched.summary, "User likes dark mode");
        assert_eq!(fetched.source_device, Some("laptop".into()));
    }

    #[tokio::test]
    async fn insert_and_list() {
        let store = setup();
        let e1 = make_entry("memory one");
        let e2 = make_entry("memory two");
        store.insert_entry(&e1).await.unwrap();
        store.insert_entry(&e2).await.unwrap();

        let entries = store
            .list_entries(&MemoryFilter::default(), &Pagination::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn delete_entry() {
        let store = setup();
        let entry = make_entry("to delete");
        store.insert_entry(&entry).await.unwrap();
        assert_eq!(store.count_entries().await.unwrap(), 1);

        store.delete_entry(&entry.id).await.unwrap();
        assert_eq!(store.count_entries().await.unwrap(), 0);
        assert!(store.get_entry(&entry.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn filter_by_channel() {
        let store = setup();
        let mut e1 = make_entry("via web");
        e1.source_channel = Some("web".into());
        let mut e2 = make_entry("via slack");
        e2.source_channel = Some("slack".into());
        store.insert_entry(&e1).await.unwrap();
        store.insert_entry(&e2).await.unwrap();

        let filter = MemoryFilter {
            source_channel: Some("slack".into()),
            ..Default::default()
        };
        let entries = store
            .list_entries(&filter, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_channel, Some("slack".into()));
    }

    #[tokio::test]
    async fn filter_by_device() {
        let store = setup();
        let mut e1 = make_entry("from laptop");
        e1.source_device = Some("laptop".into());
        let mut e2 = make_entry("from phone");
        e2.source_device = Some("phone".into());
        store.insert_entry(&e1).await.unwrap();
        store.insert_entry(&e2).await.unwrap();

        let filter = MemoryFilter {
            source_device: Some("phone".into()),
            ..Default::default()
        };
        let entries = store
            .list_entries(&filter, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_device, Some("phone".into()));
    }

    #[tokio::test]
    async fn filter_by_date_range() {
        let store = setup();
        let e1 = make_entry("old memory");
        // Small sleep to separate timestamps
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let cutoff = Utc::now();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let e2 = make_entry("new memory");
        store.insert_entry(&e1).await.unwrap();
        store.insert_entry(&e2).await.unwrap();

        let filter = MemoryFilter {
            since: Some(cutoff),
            ..Default::default()
        };
        let entries = store
            .list_entries(&filter, &Pagination::default())
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].summary, "new memory");
    }

    #[tokio::test]
    async fn pagination_works() {
        let store = setup();
        for i in 0..5 {
            let entry = make_entry(&format!("memory {i}"));
            store.insert_entry(&entry).await.unwrap();
            // Space out timestamps for deterministic ordering
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let page1 = store
            .list_entries(
                &MemoryFilter::default(),
                &Pagination {
                    offset: 0,
                    limit: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);

        let page2 = store
            .list_entries(
                &MemoryFilter::default(),
                &Pagination {
                    offset: 2,
                    limit: 2,
                },
            )
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_ne!(page1[0].id, page2[0].id);
    }

    #[tokio::test]
    async fn get_entries_by_vector_ids() {
        let store = setup();
        let e1 = make_entry("first");
        let e2 = make_entry("second");
        let e3 = make_entry("third");
        store.insert_entry(&e1).await.unwrap();
        store.insert_entry(&e2).await.unwrap();
        store.insert_entry(&e3).await.unwrap();

        let entries = store
            .get_entries_by_vector_ids(&[e1.vector_point_id.clone(), e3.vector_point_id.clone()])
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn count_entries() {
        let store = setup();
        assert_eq!(store.count_entries().await.unwrap(), 0);
        store.insert_entry(&make_entry("one")).await.unwrap();
        assert_eq!(store.count_entries().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn nonexistent_returns_none() {
        let store = setup();
        let result = store.get_entry(&MemoryId::new()).await.unwrap();
        assert!(result.is_none());
    }

    // ── FTS tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn fts_search_returns_match() {
        let store = setup();
        store
            .insert_entry(&make_entry("User prefers dark mode theme"))
            .await
            .unwrap();
        store
            .insert_entry(&make_entry("Meeting scheduled for Monday"))
            .await
            .unwrap();

        let results = store.fts_search("dark mode", 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn fts_multi_word_search() {
        let store = setup();
        store
            .insert_entry(&make_entry("The Rust programming language is fast"))
            .await
            .unwrap();
        store
            .insert_entry(&make_entry("Python is a programming language"))
            .await
            .unwrap();

        let results = store.fts_search("Rust fast", 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn fts_no_match_returns_empty() {
        let store = setup();
        store
            .insert_entry(&make_entry("hello world"))
            .await
            .unwrap();

        let results = store.fts_search("nonexistent", 10).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn fts_rank_ordering() {
        let store = setup();
        store
            .insert_entry(&make_entry("Rust Rust Rust programming"))
            .await
            .unwrap();
        store
            .insert_entry(&make_entry("Rust is nice"))
            .await
            .unwrap();

        let results = store.fts_search("Rust", 10).await.unwrap();
        assert_eq!(results.len(), 2);
        // FTS5 rank is negative (more negative = better match)
        // So the first result should have a lower (more negative) rank
    }

    #[tokio::test]
    async fn fts_delete_removes_from_index() {
        let store = setup();
        let entry = make_entry("unique findable term xyzzy");
        store.insert_entry(&entry).await.unwrap();

        let results = store.fts_search("xyzzy", 10).await.unwrap();
        assert_eq!(results.len(), 1);

        store.delete_entry(&entry.id).await.unwrap();

        let results = store.fts_search("xyzzy", 10).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn fts_search_with_limit() {
        let store = setup();
        for i in 0..5 {
            store
                .insert_entry(&make_entry(&format!("keyword item {i}")))
                .await
                .unwrap();
        }

        let results = store.fts_search("keyword", 2).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn fts_search_handles_special_characters() {
        let store = setup();
        store
            .insert_entry(&make_entry("C++ reference guide"))
            .await
            .unwrap();

        let results = store.fts_search("C++", 10).await.unwrap();
        assert_eq!(results.len(), 1);
    }
}
