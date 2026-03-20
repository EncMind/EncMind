use async_trait::async_trait;
use qdrant_client::qdrant::{
    vectors_config, CollectionInfo, CountPointsBuilder, CreateCollectionBuilder,
    DeletePointsBuilder, Distance, PointStruct, PointsIdsList, SearchPointsBuilder, VectorParams,
    VectorParamsBuilder, VectorsConfig,
};
use qdrant_client::Qdrant;
use tracing::warn;

use encmind_core::error::MemoryError;
use encmind_core::traits::VectorStore;
use encmind_core::types::VectorSearchResult;

/// Vector store backed by Qdrant (gRPC).
pub struct QdrantVectorStore {
    client: Qdrant,
    collection: String,
}

impl QdrantVectorStore {
    /// Connect to Qdrant and ensure the collection exists.
    ///
    /// `url` — gRPC endpoint, e.g. `http://localhost:6334`.
    /// `collection` — collection name, e.g. `encmind_memories`.
    /// `dimensions` — vector dimensionality (must match the embedder).
    pub async fn connect(
        url: &str,
        collection: &str,
        dimensions: usize,
    ) -> Result<Self, MemoryError> {
        let client = Qdrant::from_url(url)
            .build()
            .map_err(|e| MemoryError::VectorStoreError(format!("qdrant connect failed: {e}")))?;

        let exists = client
            .collection_exists(collection)
            .await
            .map_err(|e| MemoryError::VectorStoreError(format!("qdrant check failed: {e}")))?;

        if !exists {
            client
                .create_collection(CreateCollectionBuilder::new(collection).vectors_config(
                    VectorParamsBuilder::new(dimensions as u64, Distance::Cosine),
                ))
                .await
                .map_err(|e| {
                    MemoryError::VectorStoreError(format!("qdrant create collection failed: {e}"))
                })?;
        } else {
            let info = client.collection_info(collection).await.map_err(|e| {
                MemoryError::VectorStoreError(format!(
                    "qdrant collection info failed for '{collection}': {e}"
                ))
            })?;
            let info = info.result.ok_or_else(|| {
                MemoryError::VectorStoreError(format!(
                    "qdrant collection info missing result for '{collection}'"
                ))
            })?;
            validate_collection_schema(&info, collection, dimensions)?;
        }

        Ok(Self {
            client,
            collection: collection.to_owned(),
        })
    }
}

fn validate_collection_schema(
    info: &CollectionInfo,
    collection: &str,
    expected_dimensions: usize,
) -> Result<(), MemoryError> {
    let vectors_config = info
        .config
        .as_ref()
        .and_then(|cfg| cfg.params.as_ref())
        .and_then(|params| params.vectors_config.as_ref())
        .ok_or_else(|| {
            MemoryError::VectorStoreError(format!(
                "qdrant collection '{collection}' has no vectors_config"
            ))
        })?;

    let params = vector_params_from_config(vectors_config, collection)?;

    if params.size != expected_dimensions as u64 {
        return Err(MemoryError::VectorStoreError(format!(
            "qdrant collection '{collection}' dimension mismatch: expected {}, got {}",
            expected_dimensions, params.size
        )));
    }

    let distance = Distance::try_from(params.distance).unwrap_or(Distance::UnknownDistance);
    if distance != Distance::Cosine {
        return Err(MemoryError::VectorStoreError(format!(
            "qdrant collection '{collection}' distance mismatch: expected Cosine, got {}",
            distance.as_str_name()
        )));
    }

    Ok(())
}

fn vector_params_from_config<'a>(
    config: &'a VectorsConfig,
    collection: &str,
) -> Result<&'a VectorParams, MemoryError> {
    match config.config.as_ref() {
        Some(vectors_config::Config::Params(params)) => Ok(params),
        Some(vectors_config::Config::ParamsMap(map)) => match map.map.get("") {
            Some(default_params) => Ok(default_params),
            None => {
                let mut names: Vec<&str> = map.map.keys().map(String::as_str).collect();
                names.sort_unstable();
                Err(MemoryError::VectorStoreError(format!(
                    "qdrant collection '{collection}' uses named vectors ({:?}); EncMind requires default unnamed vector key \"\"",
                    names
                )))
            }
        },
        None => Err(MemoryError::VectorStoreError(format!(
            "qdrant collection '{collection}' has empty vectors_config"
        ))),
    }
}

/// Convert a ULID string to a UUID string for Qdrant point IDs.
fn ulid_to_uuid(ulid_str: &str) -> Result<String, MemoryError> {
    let ulid: ulid::Ulid = ulid_str
        .parse()
        .map_err(|e| MemoryError::VectorStoreError(format!("invalid ULID '{ulid_str}': {e}")))?;
    let uuid: uuid::Uuid = ulid.into();
    Ok(uuid.to_string())
}

/// Convert a UUID string back to a ULID string.
fn uuid_to_ulid(uuid_str: &str) -> Result<String, MemoryError> {
    let uuid: uuid::Uuid = uuid_str
        .parse()
        .map_err(|e| MemoryError::VectorStoreError(format!("invalid UUID '{uuid_str}': {e}")))?;
    let ulid = ulid::Ulid::from(uuid);
    Ok(ulid.to_string())
}

#[async_trait]
impl VectorStore for QdrantVectorStore {
    async fn upsert(&self, point_id: &str, vector: Vec<f32>) -> Result<(), MemoryError> {
        let uuid_str = ulid_to_uuid(point_id)?;
        let point = PointStruct::new(uuid_str, vector, serde_json::Map::new());
        self.client
            .upsert_points(
                qdrant_client::qdrant::UpsertPointsBuilder::new(&self.collection, vec![point])
                    .wait(true),
            )
            .await
            .map_err(|e| MemoryError::VectorStoreError(format!("qdrant upsert failed: {e}")))?;
        Ok(())
    }

    async fn search(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorSearchResult>, MemoryError> {
        let response = self
            .client
            .search_points(
                SearchPointsBuilder::new(&self.collection, query.to_vec(), limit as u64)
                    .with_payload(false),
            )
            .await
            .map_err(|e| MemoryError::VectorStoreError(format!("qdrant search failed: {e}")))?;

        let mut results = Vec::with_capacity(response.result.len());
        for scored in response.result {
            let uuid_str = match scored.id.and_then(|id| id.point_id_options) {
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(u)) => u,
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Num(n)) => {
                    warn!(
                        numeric_id = n,
                        "skipping search result with non-UUID point ID"
                    );
                    continue;
                }
                None => {
                    warn!("skipping search result with missing point ID");
                    continue;
                }
            };
            let point_id = match uuid_to_ulid(&uuid_str) {
                Ok(id) => id,
                Err(e) => {
                    warn!(
                        uuid = %uuid_str,
                        error = %e,
                        "skipping search result with unparseable UUID"
                    );
                    continue;
                }
            };
            results.push(VectorSearchResult {
                point_id,
                score: scored.score,
            });
        }
        Ok(results)
    }

    async fn delete(&self, point_id: &str) -> Result<(), MemoryError> {
        let uuid_str = ulid_to_uuid(point_id)?;
        self.client
            .delete_points(
                DeletePointsBuilder::new(&self.collection)
                    .points(PointsIdsList {
                        ids: vec![uuid_str.into()],
                    })
                    .wait(true),
            )
            .await
            .map_err(|e| MemoryError::VectorStoreError(format!("qdrant delete failed: {e}")))?;
        Ok(())
    }

    async fn count(&self) -> Result<usize, MemoryError> {
        let response = self
            .client
            .count(CountPointsBuilder::new(&self.collection).exact(true))
            .await
            .map_err(|e| MemoryError::VectorStoreError(format!("qdrant count failed: {e}")))?;
        Ok(response.result.map(|r| r.count).unwrap_or(0) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_uuid_roundtrip() {
        let ulid = ulid::Ulid::new();
        let ulid_str = ulid.to_string();
        let uuid_str = ulid_to_uuid(&ulid_str).unwrap();
        let back = uuid_to_ulid(&uuid_str).unwrap();
        assert_eq!(ulid_str, back);
    }

    #[test]
    fn ulid_to_uuid_invalid_input() {
        let result = ulid_to_uuid("not-a-ulid");
        assert!(result.is_err());
    }

    #[test]
    fn uuid_to_ulid_invalid_input() {
        let result = uuid_to_ulid("not-a-uuid");
        assert!(result.is_err());
    }

    /// Integration tests — require a running Qdrant instance at localhost:6334.
    /// Run with: `cargo test -p encmind-memory --features qdrant -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn qdrant_connect_creates_collection() {
        let store =
            QdrantVectorStore::connect("http://localhost:6334", "test_connect_creates", 384)
                .await
                .unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
        // Clean up
        let _ = store.client.delete_collection("test_connect_creates").await;
    }

    #[tokio::test]
    #[ignore]
    async fn qdrant_upsert_search_delete() {
        let store = QdrantVectorStore::connect("http://localhost:6334", "test_upsert_search", 3)
            .await
            .unwrap();

        let ulid1 = ulid::Ulid::new().to_string();
        let ulid2 = ulid::Ulid::new().to_string();

        store.upsert(&ulid1, vec![1.0, 0.0, 0.0]).await.unwrap();
        store.upsert(&ulid2, vec![0.0, 1.0, 0.0]).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        let results = store.search(&[1.0, 0.0, 0.0], 2).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].point_id, ulid1);

        store.delete(&ulid1).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);

        // Clean up
        let _ = store.client.delete_collection("test_upsert_search").await;
    }

    fn collection_info_with(vc: vectors_config::Config) -> CollectionInfo {
        CollectionInfo {
            status: 0,
            optimizer_status: None,
            segments_count: 0,
            config: Some(qdrant_client::qdrant::CollectionConfig {
                params: Some(qdrant_client::qdrant::CollectionParams {
                    shard_number: 1,
                    on_disk_payload: false,
                    vectors_config: Some(VectorsConfig { config: Some(vc) }),
                    replication_factor: None,
                    write_consistency_factor: None,
                    read_fan_out_factor: None,
                    read_fan_out_delay_ms: None,
                    sharding_method: None,
                    sparse_vectors_config: None,
                }),
                hnsw_config: None,
                optimizer_config: None,
                wal_config: None,
                quantization_config: None,
                strict_mode_config: None,
                metadata: std::collections::HashMap::new(),
            }),
            payload_schema: std::collections::HashMap::new(),
            points_count: None,
            indexed_vectors_count: None,
            warnings: vec![],
            update_queue: None,
        }
    }

    fn make_vector_params(size: u64, distance: Distance) -> VectorParams {
        VectorParams {
            size,
            distance: distance as i32,
            hnsw_config: None,
            quantization_config: None,
            on_disk: None,
            datatype: None,
            multivector_config: None,
        }
    }

    #[test]
    fn validate_collection_schema_rejects_named_vectors() {
        let mut map = std::collections::HashMap::new();
        map.insert(
            "text".to_string(),
            make_vector_params(384, Distance::Cosine),
        );
        let info = collection_info_with(vectors_config::Config::ParamsMap(
            qdrant_client::qdrant::VectorParamsMap { map },
        ));
        let err = validate_collection_schema(&info, "test", 384).unwrap_err();
        assert!(err.to_string().contains("default unnamed vector key"));
    }

    #[test]
    fn validate_collection_schema_accepts_params_map_with_default_key() {
        let mut map = std::collections::HashMap::new();
        map.insert("".to_string(), make_vector_params(384, Distance::Cosine));
        let info = collection_info_with(vectors_config::Config::ParamsMap(
            qdrant_client::qdrant::VectorParamsMap { map },
        ));
        validate_collection_schema(&info, "test", 384).unwrap();
    }

    #[test]
    fn validate_collection_schema_rejects_dimension_mismatch() {
        let info = collection_info_with(vectors_config::Config::Params(make_vector_params(
            768,
            Distance::Cosine,
        )));
        let err = validate_collection_schema(&info, "test", 384).unwrap_err();
        assert!(err.to_string().contains("dimension mismatch"));
    }

    #[test]
    fn validate_collection_schema_rejects_non_cosine_distance() {
        let info = collection_info_with(vectors_config::Config::Params(make_vector_params(
            384,
            Distance::Dot,
        )));
        let err = validate_collection_schema(&info, "test", 384).unwrap_err();
        assert!(err.to_string().contains("distance mismatch"));
    }
}
