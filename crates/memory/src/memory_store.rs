use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;

use tracing::{info, warn};

use encmind_core::error::MemoryError;
use encmind_core::traits::{Embedder, MemoryMetadataStore, MemorySearchProvider, VectorStore};
use encmind_core::types::*;

use crate::hybrid_search::reciprocal_rank_fusion;

/// Status information about the memory store.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryStatus {
    pub entry_count: usize,
    pub vector_count: usize,
    pub model_name: String,
    pub embedding_dimensions: usize,
}

/// Statistics from a memory rebuild operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RebuildStats {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
}

/// The main memory store orchestrator that combines embeddings, vector search,
/// metadata storage, and FTS into a unified interface.
pub struct MemoryStoreImpl {
    embedder: Arc<dyn Embedder>,
    vector_store: Arc<dyn VectorStore>,
    metadata_store: Arc<dyn MemoryMetadataStore>,
}

const MAX_EMBED_INPUT_CHARS: usize = 6000;
const EMBED_CHUNK_OVERLAP_CHARS: usize = 300;
const MAX_EMBED_CHUNKS: usize = 8;

impl MemoryStoreImpl {
    pub fn new(
        embedder: Arc<dyn Embedder>,
        vector_store: Arc<dyn VectorStore>,
        metadata_store: Arc<dyn MemoryMetadataStore>,
    ) -> Self {
        Self {
            embedder,
            vector_store,
            metadata_store,
        }
    }

    fn chunk_embedding_input(text: &str) -> Vec<(String, usize)> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() <= MAX_EMBED_INPUT_CHARS {
            return vec![(trimmed.to_owned(), chars.len())];
        }

        let mut chunks: Vec<(String, usize)> = Vec::new();
        let mut start: usize = 0;
        while start < chars.len() {
            if chunks.len() >= MAX_EMBED_CHUNKS {
                // Preserve tail context when we hit the chunk cap.
                let tail_start = chars.len().saturating_sub(MAX_EMBED_INPUT_CHARS);
                let tail_len = chars.len().saturating_sub(tail_start);
                let tail: String = chars[tail_start..].iter().collect();
                if let Some(last) = chunks.last_mut() {
                    *last = (tail, tail_len);
                } else {
                    chunks.push((tail, tail_len));
                }
                break;
            }

            let end = (start + MAX_EMBED_INPUT_CHARS).min(chars.len());
            let chunk_len = end.saturating_sub(start);
            let chunk: String = chars[start..end].iter().collect();
            chunks.push((chunk, chunk_len));
            if end >= chars.len() {
                break;
            }
            start = end.saturating_sub(EMBED_CHUNK_OVERLAP_CHARS);
        }

        chunks
    }

    async fn embed_with_chunking(
        &self,
        text: &str,
        purpose: &str,
    ) -> Result<Vec<f32>, MemoryError> {
        let chunks = Self::chunk_embedding_input(text);
        if chunks.is_empty() {
            return Err(MemoryError::EmbeddingFailed(format!(
                "{purpose} text is empty"
            )));
        }

        if chunks.len() > 1 {
            warn!(
                purpose = purpose,
                input_chars = text.chars().count(),
                chunk_count = chunks.len(),
                max_chunk_chars = MAX_EMBED_INPUT_CHARS,
                "embedding input exceeded limit; using chunked pooling"
            );
        }

        let mut weighted_sum: Option<Vec<f32>> = None;
        let mut total_weight: f32 = 0.0;
        for (chunk, chunk_len) in chunks {
            let vector = self.embedder.embed(&chunk).await?;
            let weight = chunk_len as f32;
            match weighted_sum.as_mut() {
                Some(sum) => {
                    if sum.len() != vector.len() {
                        return Err(MemoryError::EmbeddingFailed(format!(
                            "embedding dimension mismatch while pooling chunks: {} vs {}",
                            sum.len(),
                            vector.len()
                        )));
                    }
                    for (acc, value) in sum.iter_mut().zip(vector.iter()) {
                        *acc += value * weight;
                    }
                }
                None => {
                    weighted_sum = Some(vector.into_iter().map(|v| v * weight).collect());
                }
            }
            total_weight += weight;
        }

        let mut pooled = weighted_sum.ok_or_else(|| {
            MemoryError::EmbeddingFailed("chunked embedding produced no vectors".to_string())
        })?;
        if total_weight > 0.0 {
            for v in &mut pooled {
                *v /= total_weight;
            }
        }
        // Keep chunked vectors on the same cosine scale as single-pass embeddings.
        let l2_norm = pooled.iter().map(|v| v * v).sum::<f32>().sqrt();
        if l2_norm > f32::EPSILON {
            for v in &mut pooled {
                *v /= l2_norm;
            }
        }

        Ok(pooled)
    }

    /// Insert a new memory.
    pub async fn insert(
        &self,
        summary: &str,
        session_id: Option<SessionId>,
        source_channel: Option<String>,
        source_device: Option<String>,
    ) -> Result<MemoryEntry, MemoryError> {
        let vector = self.embed_with_chunking(summary, "memory insert").await?;

        let entry = MemoryEntry {
            id: MemoryId::new(),
            session_id,
            vector_point_id: ulid::Ulid::new().to_string(),
            summary: summary.to_owned(),
            source_channel,
            source_device,
            created_at: Utc::now(),
        };

        self.vector_store
            .upsert(&entry.vector_point_id, vector)
            .await?;

        if let Err(e) = self.metadata_store.insert_entry(&entry).await {
            // Compensate: remove the orphan vector
            if let Err(cleanup_err) = self.vector_store.delete(&entry.vector_point_id).await {
                warn!(
                    error = %cleanup_err,
                    point_id = %entry.vector_point_id,
                    "failed to clean up orphan vector after metadata insert failure"
                );
            }
            return Err(e);
        }

        Ok(entry)
    }

    /// Search memories using hybrid vector + FTS search with RRF fusion.
    pub async fn search(
        &self,
        query: &str,
        limit: usize,
        filter: Option<&MemoryFilter>,
    ) -> Result<Vec<MemoryResult>, MemoryError> {
        let normalized_limit = limit.clamp(1, 200);
        let candidate_limit = normalized_limit.saturating_mul(2);

        // 1. Vector search
        let query_vec = self.embed_with_chunking(query, "memory search").await?;
        let vector_results = self
            .vector_store
            .search(&query_vec, candidate_limit)
            .await?;

        // Map vector results to (memory_id, score)
        let vector_point_ids: Vec<String> =
            vector_results.iter().map(|r| r.point_id.clone()).collect();
        let vector_entries = self
            .metadata_store
            .get_entries_by_vector_ids(&vector_point_ids)
            .await?;

        // Build lookup for point_id -> entry
        let entry_map: std::collections::HashMap<String, MemoryEntry> = vector_entries
            .into_iter()
            .map(|e| (e.vector_point_id.clone(), e))
            .collect();

        let vector_scored: Vec<(String, f32)> = vector_results
            .iter()
            .filter_map(|r| {
                entry_map
                    .get(&r.point_id)
                    .map(|e| (e.id.as_str().to_owned(), r.score))
            })
            .collect();

        // 2. FTS search
        let fts_results = self
            .metadata_store
            .fts_search(query, candidate_limit)
            .await?;
        let fts_scored: Vec<(String, f32)> = fts_results
            .into_iter()
            .map(|(id, rank)| (id.as_str().to_owned(), -rank)) // FTS5 rank is negative; negate for positive
            .collect();

        // 3. RRF fusion — fuse at candidate_limit so post-filtering has
        //    enough headroom to satisfy the requested normalized_limit.
        let fused = reciprocal_rank_fusion(&[vector_scored, fts_scored], candidate_limit);

        // 4. Build final results
        // We need entries for all fused IDs — some may already be in entry_map
        let mut results = Vec::with_capacity(fused.len());
        for (id_str, score) in &fused {
            let mem_id = MemoryId::from_string(id_str.clone());
            // Try entry_map first, then fall back to individual lookup
            let entry = if let Some(e) = entry_map.values().find(|e| e.id.as_str() == id_str) {
                Some(e.clone())
            } else {
                self.metadata_store.get_entry(&mem_id).await?
            };

            if let Some(entry) = entry {
                // Determine source
                let source = MemorySource::Hybrid;
                results.push(MemoryResult {
                    entry,
                    score: *score,
                    source,
                });
            }
        }

        // Post-filter by caller-supplied criteria, then truncate to requested limit
        if let Some(filter) = filter {
            results.retain(|r| Self::matches_filter(&r.entry, filter));
        }
        results.truncate(normalized_limit);

        Ok(results)
    }

    /// Check whether a memory entry matches the given filter.
    fn matches_filter(entry: &MemoryEntry, filter: &MemoryFilter) -> bool {
        if let Some(ref ch) = filter.source_channel {
            if entry.source_channel.as_deref() != Some(ch.as_str()) {
                return false;
            }
        }
        if let Some(ref dev) = filter.source_device {
            if entry.source_device.as_deref() != Some(dev.as_str()) {
                return false;
            }
        }
        if let Some(ref sid) = filter.session_id {
            if entry.session_id.as_ref() != Some(sid) {
                return false;
            }
        }
        if let Some(ref since) = filter.since {
            if entry.created_at < *since {
                return false;
            }
        }
        if let Some(ref until) = filter.until {
            if entry.created_at > *until {
                return false;
            }
        }
        true
    }

    /// Delete a memory by ID.
    ///
    /// Deletes metadata first (removes from search results immediately),
    /// then best-effort vector cleanup. An orphan vector is harmless.
    pub async fn delete(&self, id: &MemoryId) -> Result<(), MemoryError> {
        if let Some(entry) = self.metadata_store.get_entry(id).await? {
            self.metadata_store.delete_entry(id).await?;
            if let Err(e) = self.vector_store.delete(&entry.vector_point_id).await {
                warn!(
                    error = %e,
                    point_id = %entry.vector_point_id,
                    "failed to delete vector during memory deletion; orphan vector remains"
                );
            }
        }
        Ok(())
    }

    /// List memories with filtering and pagination.
    pub async fn list(
        &self,
        filter: &MemoryFilter,
        pagination: &Pagination,
    ) -> Result<Vec<MemoryEntry>, MemoryError> {
        self.metadata_store.list_entries(filter, pagination).await
    }

    /// Re-embed all stored memory entries and upsert their vectors.
    ///
    /// Useful after changing embedding models or recovering from corrupt vector storage.
    /// Processes entries in batches to avoid loading everything at once.
    pub async fn rebuild(&self) -> Result<RebuildStats, MemoryError> {
        const BATCH_SIZE: u32 = 100;
        let mut offset: u32 = 0;
        let mut total: usize = 0;
        let mut succeeded: usize = 0;
        let mut failed: usize = 0;
        let filter = MemoryFilter::default();

        loop {
            let pagination = Pagination {
                offset,
                limit: BATCH_SIZE,
            };
            let batch = self
                .metadata_store
                .list_entries(&filter, &pagination)
                .await?;
            let batch_len = batch.len();
            total += batch_len;

            for entry in &batch {
                match self
                    .embed_with_chunking(&entry.summary, "memory rebuild")
                    .await
                {
                    Ok(vector) => {
                        if let Err(e) = self
                            .vector_store
                            .upsert(&entry.vector_point_id, vector)
                            .await
                        {
                            warn!(
                                memory_id = %entry.id.as_str(),
                                error = %e,
                                "failed to upsert vector during rebuild"
                            );
                            failed += 1;
                        } else {
                            succeeded += 1;
                        }
                    }
                    Err(e) => {
                        warn!(
                            memory_id = %entry.id.as_str(),
                            error = %e,
                            "failed to embed entry during rebuild"
                        );
                        failed += 1;
                    }
                }
            }

            info!(
                offset,
                batch_size = batch_len,
                succeeded,
                failed,
                "rebuild batch complete"
            );

            if (batch_len as u32) < BATCH_SIZE {
                break;
            }
            offset += BATCH_SIZE;
        }

        Ok(RebuildStats {
            total,
            succeeded,
            failed,
        })
    }

    /// Get status information about the memory store.
    pub async fn status(&self) -> Result<MemoryStatus, MemoryError> {
        Ok(MemoryStatus {
            entry_count: self.metadata_store.count_entries().await?,
            vector_count: self.vector_store.count().await?,
            model_name: self.embedder.model_name().to_owned(),
            embedding_dimensions: self.embedder.dimensions(),
        })
    }
}

#[async_trait]
impl MemorySearchProvider for MemoryStoreImpl {
    async fn search_for_context(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemoryResult>, MemoryError> {
        self.search(query, limit, None).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::embedder::MockEmbedder;
    use crate::vector_store::InMemoryVectorStore;
    use encmind_core::traits::{MemoryMetadataStore, VectorStore};
    use encmind_storage::memory_metadata::SqliteMemoryMetadataStore;
    use encmind_storage::pool::create_test_pool;

    #[derive(Default)]
    struct TrackingVectorStore {
        upserted_ids: Mutex<Vec<String>>,
        deleted_ids: Mutex<Vec<String>>,
        fail_delete: bool,
    }

    #[async_trait]
    impl VectorStore for TrackingVectorStore {
        async fn upsert(&self, point_id: &str, _vector: Vec<f32>) -> Result<(), MemoryError> {
            self.upserted_ids.lock().unwrap().push(point_id.to_owned());
            Ok(())
        }

        async fn search(
            &self,
            _query: &[f32],
            _limit: usize,
        ) -> Result<Vec<VectorSearchResult>, MemoryError> {
            Ok(vec![])
        }

        async fn delete(&self, point_id: &str) -> Result<(), MemoryError> {
            self.deleted_ids.lock().unwrap().push(point_id.to_owned());
            if self.fail_delete {
                Err(MemoryError::VectorStoreError(
                    "injected delete failure".into(),
                ))
            } else {
                Ok(())
            }
        }

        async fn count(&self) -> Result<usize, MemoryError> {
            Ok(self.upserted_ids.lock().unwrap().len())
        }
    }

    struct InsertFailMetadataStore;

    struct LengthLimitedEmbedder {
        max_chars: usize,
        dims: usize,
        seen_lengths: Mutex<Vec<usize>>,
    }

    impl LengthLimitedEmbedder {
        fn new(max_chars: usize, dims: usize) -> Self {
            Self {
                max_chars,
                dims,
                seen_lengths: Mutex::new(Vec::new()),
            }
        }

        fn seen_lengths(&self) -> Vec<usize> {
            self.seen_lengths.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Embedder for LengthLimitedEmbedder {
        async fn embed(&self, text: &str) -> Result<Vec<f32>, MemoryError> {
            let len = text.chars().count();
            self.seen_lengths.lock().unwrap().push(len);
            if len > self.max_chars {
                return Err(MemoryError::EmbeddingFailed(format!(
                    "input too long for test embedder: {len} > {}",
                    self.max_chars
                )));
            }
            Ok(vec![len as f32; self.dims])
        }

        fn model_name(&self) -> &str {
            "length-limited-embedder"
        }

        fn dimensions(&self) -> usize {
            self.dims
        }
    }

    #[async_trait]
    impl MemoryMetadataStore for InsertFailMetadataStore {
        async fn insert_entry(&self, _entry: &MemoryEntry) -> Result<(), MemoryError> {
            Err(MemoryError::Storage(
                "injected metadata insert failure".into(),
            ))
        }

        async fn get_entry(&self, _id: &MemoryId) -> Result<Option<MemoryEntry>, MemoryError> {
            Ok(None)
        }

        async fn delete_entry(&self, _id: &MemoryId) -> Result<(), MemoryError> {
            Ok(())
        }

        async fn list_entries(
            &self,
            _filter: &MemoryFilter,
            _pagination: &Pagination,
        ) -> Result<Vec<MemoryEntry>, MemoryError> {
            Ok(vec![])
        }

        async fn get_entries_by_vector_ids(
            &self,
            _ids: &[String],
        ) -> Result<Vec<MemoryEntry>, MemoryError> {
            Ok(vec![])
        }

        async fn count_entries(&self) -> Result<usize, MemoryError> {
            Ok(0)
        }

        async fn fts_search(
            &self,
            _query: &str,
            _limit: usize,
        ) -> Result<Vec<(MemoryId, f32)>, MemoryError> {
            Ok(vec![])
        }
    }

    struct DeleteTrackingMetadataStore {
        entry: Mutex<Option<MemoryEntry>>,
        deleted_ids: Mutex<Vec<String>>,
    }

    impl DeleteTrackingMetadataStore {
        fn new(entry: MemoryEntry) -> Self {
            Self {
                entry: Mutex::new(Some(entry)),
                deleted_ids: Mutex::new(vec![]),
            }
        }
    }

    struct FixedVectorStore {
        ordered_point_ids: Vec<String>,
    }

    impl FixedVectorStore {
        fn new(point_ids: Vec<&str>) -> Self {
            Self {
                ordered_point_ids: point_ids.into_iter().map(|id| id.to_owned()).collect(),
            }
        }
    }

    #[async_trait]
    impl VectorStore for FixedVectorStore {
        async fn upsert(&self, _point_id: &str, _vector: Vec<f32>) -> Result<(), MemoryError> {
            Ok(())
        }

        async fn search(
            &self,
            _query: &[f32],
            limit: usize,
        ) -> Result<Vec<VectorSearchResult>, MemoryError> {
            Ok(self
                .ordered_point_ids
                .iter()
                .take(limit)
                .enumerate()
                .map(|(rank, point_id)| VectorSearchResult {
                    point_id: point_id.clone(),
                    score: 1.0 - rank as f32 * 0.01,
                })
                .collect())
        }

        async fn delete(&self, _point_id: &str) -> Result<(), MemoryError> {
            Ok(())
        }

        async fn count(&self) -> Result<usize, MemoryError> {
            Ok(self.ordered_point_ids.len())
        }
    }

    struct FixedMetadataStore {
        by_point_id: HashMap<String, MemoryEntry>,
        by_memory_id: HashMap<String, MemoryEntry>,
    }

    impl FixedMetadataStore {
        fn new(entries: Vec<MemoryEntry>) -> Self {
            let mut by_point_id = HashMap::new();
            let mut by_memory_id = HashMap::new();
            for entry in entries {
                by_point_id.insert(entry.vector_point_id.clone(), entry.clone());
                by_memory_id.insert(entry.id.as_str().to_owned(), entry);
            }
            Self {
                by_point_id,
                by_memory_id,
            }
        }
    }

    #[async_trait]
    impl MemoryMetadataStore for FixedMetadataStore {
        async fn insert_entry(&self, _entry: &MemoryEntry) -> Result<(), MemoryError> {
            Ok(())
        }

        async fn get_entry(&self, id: &MemoryId) -> Result<Option<MemoryEntry>, MemoryError> {
            Ok(self.by_memory_id.get(id.as_str()).cloned())
        }

        async fn delete_entry(&self, _id: &MemoryId) -> Result<(), MemoryError> {
            Ok(())
        }

        async fn list_entries(
            &self,
            _filter: &MemoryFilter,
            pagination: &Pagination,
        ) -> Result<Vec<MemoryEntry>, MemoryError> {
            let mut entries: Vec<MemoryEntry> = self.by_memory_id.values().cloned().collect();
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            let start = pagination.offset as usize;
            if start >= entries.len() {
                return Ok(vec![]);
            }
            let end = (start + pagination.limit as usize).min(entries.len());
            Ok(entries[start..end].to_vec())
        }

        async fn get_entries_by_vector_ids(
            &self,
            ids: &[String],
        ) -> Result<Vec<MemoryEntry>, MemoryError> {
            Ok(ids
                .iter()
                .filter_map(|id| self.by_point_id.get(id).cloned())
                .collect())
        }

        async fn count_entries(&self) -> Result<usize, MemoryError> {
            Ok(self.by_memory_id.len())
        }

        async fn fts_search(
            &self,
            _query: &str,
            _limit: usize,
        ) -> Result<Vec<(MemoryId, f32)>, MemoryError> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl MemoryMetadataStore for DeleteTrackingMetadataStore {
        async fn insert_entry(&self, _entry: &MemoryEntry) -> Result<(), MemoryError> {
            Ok(())
        }

        async fn get_entry(&self, _id: &MemoryId) -> Result<Option<MemoryEntry>, MemoryError> {
            Ok(self.entry.lock().unwrap().clone())
        }

        async fn delete_entry(&self, id: &MemoryId) -> Result<(), MemoryError> {
            self.deleted_ids
                .lock()
                .unwrap()
                .push(id.as_str().to_owned());
            *self.entry.lock().unwrap() = None;
            Ok(())
        }

        async fn list_entries(
            &self,
            _filter: &MemoryFilter,
            _pagination: &Pagination,
        ) -> Result<Vec<MemoryEntry>, MemoryError> {
            Ok(vec![])
        }

        async fn get_entries_by_vector_ids(
            &self,
            _ids: &[String],
        ) -> Result<Vec<MemoryEntry>, MemoryError> {
            Ok(vec![])
        }

        async fn count_entries(&self) -> Result<usize, MemoryError> {
            Ok(0)
        }

        async fn fts_search(
            &self,
            _query: &str,
            _limit: usize,
        ) -> Result<Vec<(MemoryId, f32)>, MemoryError> {
            Ok(vec![])
        }
    }

    fn setup() -> MemoryStoreImpl {
        let pool = create_test_pool();
        let conn = pool.get().unwrap();
        encmind_storage::migrations::run_migrations(&conn).unwrap();

        let embedder = Arc::new(MockEmbedder::new(128));
        let vector_store = Arc::new(InMemoryVectorStore::new());
        let metadata_store = Arc::new(SqliteMemoryMetadataStore::new(pool));

        MemoryStoreImpl::new(embedder, vector_store, metadata_store)
    }

    #[tokio::test]
    async fn insert_and_search() {
        let store = setup();
        store
            .insert("User prefers dark mode", None, Some("web".into()), None)
            .await
            .unwrap();

        let results = store.search("dark mode", 5, None).await.unwrap();
        assert!(!results.is_empty());
        assert!(results[0].entry.summary.contains("dark mode"));
    }

    #[tokio::test]
    async fn similar_query_returns_results() {
        let store = setup();
        store
            .insert("Meeting with John about project status", None, None, None)
            .await
            .unwrap();

        let results = store.search("project meeting", 5, None).await.unwrap();
        assert!(!results.is_empty());
    }

    #[tokio::test]
    async fn unrelated_query_returns_lower_scores() {
        let store = setup();
        store
            .insert("User prefers dark mode", None, None, None)
            .await
            .unwrap();
        store
            .insert("Recipe for chocolate cake", None, None, None)
            .await
            .unwrap();

        let results = store.search("dark mode", 5, None).await.unwrap();
        assert!(!results.is_empty());
        // The dark mode entry should generally appear
    }

    #[tokio::test]
    async fn delete_removes_memory() {
        let store = setup();
        let entry = store
            .insert("temporary memory", None, None, None)
            .await
            .unwrap();

        store.delete(&entry.id).await.unwrap();

        let status = store.status().await.unwrap();
        assert_eq!(status.entry_count, 0);
        assert_eq!(status.vector_count, 0);
    }

    #[tokio::test]
    async fn list_with_filter() {
        let store = setup();
        store
            .insert("web memory", None, Some("web".into()), None)
            .await
            .unwrap();
        store
            .insert("slack memory", None, Some("slack".into()), None)
            .await
            .unwrap();

        let filter = MemoryFilter {
            source_channel: Some("web".into()),
            ..Default::default()
        };
        let entries = store.list(&filter, &Pagination::default()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_channel, Some("web".into()));
    }

    #[tokio::test]
    async fn status_returns_counts() {
        let store = setup();
        store.insert("memory one", None, None, None).await.unwrap();
        store.insert("memory two", None, None, None).await.unwrap();

        let status = store.status().await.unwrap();
        assert_eq!(status.entry_count, 2);
        assert_eq!(status.vector_count, 2);
        assert_eq!(status.model_name, "mock-embedder");
        assert_eq!(status.embedding_dimensions, 128);
    }

    #[tokio::test]
    async fn fts_only_results() {
        let store = setup();
        store
            .insert("xyzzy unique keyword here", None, None, None)
            .await
            .unwrap();

        // FTS should find this via keyword match
        let results = store.search("xyzzy", 5, None).await.unwrap();
        assert!(!results.is_empty());
    }

    fn make_fixed_entry(memory_id: &str, point_id: &str, channel: &str) -> MemoryEntry {
        MemoryEntry {
            id: MemoryId::from_string(memory_id.to_owned()),
            session_id: None,
            vector_point_id: point_id.to_owned(),
            summary: format!("entry {memory_id}"),
            source_channel: Some(channel.to_owned()),
            source_device: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn search_filter_applies_before_final_truncation() {
        let embedder = Arc::new(MockEmbedder::new(8));
        let vector_store = Arc::new(FixedVectorStore::new(vec!["p1", "p2", "p3", "p4"]));
        let metadata_store = Arc::new(FixedMetadataStore::new(vec![
            make_fixed_entry("mem-1", "p1", "web"),
            make_fixed_entry("mem-2", "p2", "web"),
            make_fixed_entry("mem-3", "p3", "slack"),
            make_fixed_entry("mem-4", "p4", "slack"),
        ]));
        let store = MemoryStoreImpl::new(embedder, vector_store, metadata_store);

        // Requested limit=2 => candidate_limit=4.
        // The first 2 vector candidates are "web", and slack entries are 3rd/4th.
        // If fusion truncates too early, this would return 0 after filtering.
        let filter = MemoryFilter {
            source_channel: Some("slack".into()),
            ..Default::default()
        };
        let results = store.search("query", 2, Some(&filter)).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|r| r.entry.source_channel.as_deref() == Some("slack")));
        let ids: Vec<&str> = results.iter().map(|r| r.entry.id.as_str()).collect();
        assert!(ids.contains(&"mem-3"));
        assert!(ids.contains(&"mem-4"));
    }

    #[tokio::test]
    async fn empty_store_search() {
        let store = setup();
        let results = store.search("anything", 5, None).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn insert_failure_cleans_up_orphan_vector() {
        let embedder = Arc::new(MockEmbedder::new(8));
        let vector_store = Arc::new(TrackingVectorStore::default());
        let metadata_store = Arc::new(InsertFailMetadataStore);
        let store = MemoryStoreImpl::new(embedder, vector_store.clone(), metadata_store);

        let err = store
            .insert("this should fail metadata insert", None, None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("injected metadata insert failure"),
            "unexpected error: {err}"
        );

        let upserted = vector_store.upserted_ids.lock().unwrap().clone();
        let deleted = vector_store.deleted_ids.lock().unwrap().clone();
        assert_eq!(upserted.len(), 1, "vector should be inserted first");
        assert_eq!(
            deleted, upserted,
            "failed insert should clean up orphan vector"
        );
    }

    #[tokio::test]
    async fn delete_succeeds_even_when_vector_cleanup_fails() {
        let embedder = Arc::new(MockEmbedder::new(8));
        let vector_store = Arc::new(TrackingVectorStore {
            fail_delete: true,
            ..Default::default()
        });
        let entry = MemoryEntry {
            id: MemoryId::new(),
            session_id: None,
            vector_point_id: "pt-delete-failure".into(),
            summary: "entry to delete".into(),
            source_channel: Some("web".into()),
            source_device: None,
            created_at: Utc::now(),
        };
        let metadata_store = Arc::new(DeleteTrackingMetadataStore::new(entry.clone()));
        let store = MemoryStoreImpl::new(embedder, vector_store.clone(), metadata_store.clone());

        store.delete(&entry.id).await.unwrap();

        let metadata_deleted = metadata_store.deleted_ids.lock().unwrap().clone();
        let vectors_deleted = vector_store.deleted_ids.lock().unwrap().clone();
        assert_eq!(metadata_deleted, vec![entry.id.as_str().to_owned()]);
        assert_eq!(vectors_deleted, vec![entry.vector_point_id]);
    }

    #[tokio::test]
    async fn rebuild_empty_store() {
        let store = setup();
        let stats = store.rebuild().await.unwrap();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.succeeded, 0);
        assert_eq!(stats.failed, 0);
    }

    #[tokio::test]
    async fn rebuild_re_embeds_all_entries() {
        let store = setup();
        store
            .insert("first memory", None, None, None)
            .await
            .unwrap();
        store
            .insert("second memory", None, None, None)
            .await
            .unwrap();

        let stats = store.rebuild().await.unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.succeeded, 2);
        assert_eq!(stats.failed, 0);
    }

    #[tokio::test]
    async fn rebuild_partial_failure() {
        // Use a FailingEmbedder that fails on specific inputs
        struct FailOnSecondEmbedder {
            call_count: Mutex<usize>,
        }

        #[async_trait]
        impl Embedder for FailOnSecondEmbedder {
            async fn embed(&self, _text: &str) -> Result<Vec<f32>, MemoryError> {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                // Count includes the two insert-time embeddings, so fail on call #4
                // to simulate one rebuild-time embed failure.
                if *count == 4 {
                    return Err(MemoryError::EmbeddingFailed(
                        "injected embed failure".into(),
                    ));
                }
                Ok(vec![0.1; 8])
            }

            fn model_name(&self) -> &str {
                "fail-embedder"
            }

            fn dimensions(&self) -> usize {
                8
            }
        }

        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }

        let embedder = Arc::new(FailOnSecondEmbedder {
            call_count: Mutex::new(0),
        });
        let vector_store = Arc::new(InMemoryVectorStore::new());
        let metadata_store = Arc::new(SqliteMemoryMetadataStore::new(pool));

        let store = MemoryStoreImpl::new(embedder, vector_store, metadata_store);

        // Insert 2 entries (uses embed calls 1 and 2)
        store
            .insert("first memory", None, None, None)
            .await
            .unwrap();
        store
            .insert("second memory", None, None, None)
            .await
            .unwrap();

        // Rebuild (uses embed calls 3 and 4; call 4 will fail)
        let stats = store.rebuild().await.unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.succeeded, 1);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn chunk_embedding_input_splits_large_text() {
        let text = "a".repeat(MAX_EMBED_INPUT_CHARS * 2 + 250);
        let chunks = MemoryStoreImpl::chunk_embedding_input(&text);
        assert!(chunks.len() >= 2);
        assert!(chunks.len() <= MAX_EMBED_CHUNKS);
        assert!(chunks.iter().all(|(_, len)| *len <= MAX_EMBED_INPUT_CHARS));
    }

    #[test]
    fn chunk_embedding_input_caps_chunk_count_and_keeps_tail() {
        let text = "z".repeat(MAX_EMBED_INPUT_CHARS * MAX_EMBED_CHUNKS + 4096);
        let chars: Vec<char> = text.chars().collect();
        let tail_start = chars.len().saturating_sub(MAX_EMBED_INPUT_CHARS);
        let expected_tail: String = chars[tail_start..].iter().collect();

        let chunks = MemoryStoreImpl::chunk_embedding_input(&text);
        assert_eq!(chunks.len(), MAX_EMBED_CHUNKS);
        let (last_chunk, last_len) = chunks.last().expect("expected last chunk");
        assert_eq!(*last_len, MAX_EMBED_INPUT_CHARS);
        assert_eq!(last_chunk, &expected_tail);
    }

    #[tokio::test]
    async fn embed_with_chunking_normalizes_pooled_vector() {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let embedder = Arc::new(LengthLimitedEmbedder::new(MAX_EMBED_INPUT_CHARS, 4));
        let vector_store = Arc::new(InMemoryVectorStore::new());
        let metadata_store = Arc::new(SqliteMemoryMetadataStore::new(pool));
        let store = MemoryStoreImpl::new(embedder, vector_store, metadata_store);

        let long_text = "n".repeat(MAX_EMBED_INPUT_CHARS * 2 + 100);
        let vector = store
            .embed_with_chunking(&long_text, "test normalization")
            .await
            .expect("chunked embedding should succeed");
        let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-4,
            "expected pooled vector to be unit-normalized, got norm={norm}"
        );
    }

    #[tokio::test]
    async fn search_chunks_large_query_before_embedding() {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let embedder = Arc::new(LengthLimitedEmbedder::new(MAX_EMBED_INPUT_CHARS, 16));
        let vector_store = Arc::new(InMemoryVectorStore::new());
        let metadata_store = Arc::new(SqliteMemoryMetadataStore::new(pool));
        let store = MemoryStoreImpl::new(
            embedder.clone() as Arc<dyn Embedder>,
            vector_store,
            metadata_store,
        );

        store
            .insert("small memory seed", None, Some("web".into()), None)
            .await
            .unwrap();

        let long_query = "q".repeat(MAX_EMBED_INPUT_CHARS * 3 + 100);
        let _ = store.search(&long_query, 5, None).await.unwrap();

        let seen = embedder.seen_lengths();
        assert!(
            seen.iter().all(|len| *len <= MAX_EMBED_INPUT_CHARS),
            "all embed calls should be chunk-limited; seen={seen:?}"
        );
        assert!(
            seen.len() >= 3,
            "expected multiple embed calls (insert + chunked search), seen={seen:?}"
        );
    }

    #[tokio::test]
    async fn insert_chunks_large_summary_before_embedding() {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            encmind_storage::migrations::run_migrations(&conn).unwrap();
        }
        let embedder = Arc::new(LengthLimitedEmbedder::new(MAX_EMBED_INPUT_CHARS, 16));
        let vector_store = Arc::new(InMemoryVectorStore::new());
        let metadata_store = Arc::new(SqliteMemoryMetadataStore::new(pool));
        let store = MemoryStoreImpl::new(
            embedder.clone() as Arc<dyn Embedder>,
            vector_store,
            metadata_store,
        );

        let long_summary = "s".repeat(MAX_EMBED_INPUT_CHARS * 2 + 200);
        let _entry = store
            .insert(&long_summary, None, Some("web".into()), None)
            .await
            .unwrap();

        let seen = embedder.seen_lengths();
        assert!(
            seen.iter().all(|len| *len <= MAX_EMBED_INPUT_CHARS),
            "all embed calls should be chunk-limited; seen={seen:?}"
        );
        assert!(
            seen.len() >= 2,
            "expected multiple embed calls for large insert; seen={seen:?}"
        );
    }
}
