use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use encmind_core::error::MemoryError;
use encmind_core::traits::VectorStore;
use encmind_core::types::VectorSearchResult;

/// In-memory vector store using brute-force cosine similarity. Good for tests.
pub struct InMemoryVectorStore {
    vectors: Mutex<HashMap<String, Vec<f32>>>,
}

impl InMemoryVectorStore {
    pub fn new() -> Self {
        Self {
            vectors: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryVectorStore {
    fn default() -> Self {
        Self::new()
    }
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
impl VectorStore for InMemoryVectorStore {
    async fn upsert(&self, point_id: &str, vector: Vec<f32>) -> Result<(), MemoryError> {
        self.vectors
            .lock()
            .unwrap()
            .insert(point_id.to_owned(), vector);
        Ok(())
    }

    async fn search(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorSearchResult>, MemoryError> {
        let vecs = self.vectors.lock().unwrap();
        let mut scores: Vec<(String, f32)> = vecs
            .iter()
            .map(|(id, vec)| (id.clone(), cosine_similarity(query, vec)))
            .collect();
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(limit);
        Ok(scores
            .into_iter()
            .map(|(point_id, score)| VectorSearchResult { point_id, score })
            .collect())
    }

    async fn delete(&self, point_id: &str) -> Result<(), MemoryError> {
        self.vectors.lock().unwrap().remove(point_id);
        Ok(())
    }

    async fn count(&self) -> Result<usize, MemoryError> {
        Ok(self.vectors.lock().unwrap().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_and_search() {
        let store = InMemoryVectorStore::new();
        store.upsert("p1", vec![1.0, 0.0, 0.0]).await.unwrap();
        store.upsert("p2", vec![0.0, 1.0, 0.0]).await.unwrap();

        let results = store.search(&[1.0, 0.0, 0.0], 2).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].point_id, "p1");
        assert!((results[0].score - 1.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn ranking_order() {
        let store = InMemoryVectorStore::new();
        store.upsert("close", vec![0.9, 0.1, 0.0]).await.unwrap();
        store.upsert("far", vec![0.0, 0.0, 1.0]).await.unwrap();

        let results = store.search(&[1.0, 0.0, 0.0], 2).await.unwrap();
        assert_eq!(results[0].point_id, "close");
        assert_eq!(results[1].point_id, "far");
    }

    #[tokio::test]
    async fn delete_removes_vector() {
        let store = InMemoryVectorStore::new();
        store.upsert("p1", vec![1.0, 0.0]).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);

        store.delete("p1").await.unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn count_tracks_size() {
        let store = InMemoryVectorStore::new();
        assert_eq!(store.count().await.unwrap(), 0);
        store.upsert("p1", vec![1.0]).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);
        store.upsert("p2", vec![2.0]).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn empty_search() {
        let store = InMemoryVectorStore::new();
        let results = store.search(&[1.0, 0.0], 10).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn search_respects_limit() {
        let store = InMemoryVectorStore::new();
        for i in 0..10 {
            store
                .upsert(&format!("p{i}"), vec![i as f32, 0.0])
                .await
                .unwrap();
        }

        let results = store.search(&[1.0, 0.0], 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }
}
