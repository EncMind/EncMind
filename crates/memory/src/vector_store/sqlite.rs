use async_trait::async_trait;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use encmind_core::error::MemoryError;
use encmind_core::traits::VectorStore;
use encmind_core::types::VectorSearchResult;

/// SQLite-backed vector store. Persists vectors as f32 BLOBs in `memory_vectors`.
/// Uses brute-force cosine similarity — adequate for single-user workloads.
pub struct SqliteVectorStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteVectorStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }
}

fn f32_vec_to_blob(vec: &[f32]) -> Vec<u8> {
    vec.iter().flat_map(|f| f.to_le_bytes()).collect()
}

fn blob_to_f32_vec(blob: &[u8]) -> Vec<f32> {
    blob.chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

#[async_trait]
impl VectorStore for SqliteVectorStore {
    async fn upsert(&self, point_id: &str, vector: Vec<f32>) -> Result<(), MemoryError> {
        let pool = self.pool.clone();
        let point_id = point_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            let blob = f32_vec_to_blob(&vector);
            conn.execute(
                "INSERT INTO memory_vectors (point_id, vector) VALUES (?1, ?2) \
                 ON CONFLICT(point_id) DO UPDATE SET vector = ?2",
                rusqlite::params![point_id, blob],
            )
            .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?
    }

    async fn search(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorSearchResult>, MemoryError> {
        let pool = self.pool.clone();
        let query = query.to_vec();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            let mut stmt = conn
                .prepare("SELECT point_id, vector FROM memory_vectors")
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            let mut scores: Vec<(String, f32)> = stmt
                .query_map([], |row| {
                    let point_id: String = row.get(0)?;
                    let blob: Vec<u8> = row.get(1)?;
                    Ok((point_id, blob))
                })
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?
                .filter_map(|r| r.ok())
                .map(|(point_id, blob)| {
                    let vec = blob_to_f32_vec(&blob);
                    let score = cosine_similarity(&query, &vec);
                    (point_id, score)
                })
                .collect();

            scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scores.truncate(limit);
            Ok(scores
                .into_iter()
                .map(|(point_id, score)| VectorSearchResult { point_id, score })
                .collect())
        })
        .await
        .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?
    }

    async fn delete(&self, point_id: &str) -> Result<(), MemoryError> {
        let pool = self.pool.clone();
        let point_id = point_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            conn.execute(
                "DELETE FROM memory_vectors WHERE point_id = ?1",
                rusqlite::params![point_id],
            )
            .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?
    }

    async fn count(&self) -> Result<usize, MemoryError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            let count: i64 = conn
                .query_row("SELECT count(*) FROM memory_vectors", [], |row| row.get(0))
                .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?;
            Ok(count as usize)
        })
        .await
        .map_err(|e| MemoryError::VectorStoreError(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_storage::pool::create_test_pool;

    fn setup() -> Pool<SqliteConnectionManager> {
        let pool = create_test_pool();
        let conn = pool.get().unwrap();
        encmind_storage::migrations::run_migrations(&conn).unwrap();
        pool
    }

    #[tokio::test]
    async fn sqlite_upsert_and_search() {
        let pool = setup();
        let store = SqliteVectorStore::new(pool);
        store.upsert("p1", vec![1.0, 0.0, 0.0]).await.unwrap();
        store.upsert("p2", vec![0.0, 1.0, 0.0]).await.unwrap();

        let results = store.search(&[1.0, 0.0, 0.0], 2).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].point_id, "p1");
    }

    #[tokio::test]
    async fn sqlite_delete() {
        let pool = setup();
        let store = SqliteVectorStore::new(pool);
        store.upsert("p1", vec![1.0]).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);

        store.delete("p1").await.unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn sqlite_count() {
        let pool = setup();
        let store = SqliteVectorStore::new(pool);
        assert_eq!(store.count().await.unwrap(), 0);
        store.upsert("p1", vec![1.0]).await.unwrap();
        store.upsert("p2", vec![2.0]).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn sqlite_ranking() {
        let pool = setup();
        let store = SqliteVectorStore::new(pool);
        store.upsert("close", vec![0.9, 0.1, 0.0]).await.unwrap();
        store.upsert("far", vec![0.0, 0.0, 1.0]).await.unwrap();

        let results = store.search(&[1.0, 0.0, 0.0], 2).await.unwrap();
        assert_eq!(results[0].point_id, "close");
    }
}
