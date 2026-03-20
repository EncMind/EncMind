use async_trait::async_trait;

use encmind_core::error::MemoryError;
use encmind_core::traits::Embedder;

/// An embedder that calls an OpenAI-compatible embeddings API.
pub struct ApiEmbedder {
    client: reqwest::Client,
    api_base_url: String,
    model: String,
    dimensions: usize,
    api_key: Option<String>,
}

impl ApiEmbedder {
    pub fn new(
        api_base_url: &str,
        model: &str,
        dimensions: usize,
        api_key: Option<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base_url: api_base_url.trim_end_matches('/').to_owned(),
            model: model.to_owned(),
            dimensions,
            api_key,
        }
    }
}

#[async_trait]
impl Embedder for ApiEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, MemoryError> {
        let url = format!("{}/v1/embeddings", self.api_base_url);
        let body = serde_json::json!({
            "model": self.model,
            "input": text,
        });

        let mut request = self.client.post(&url).json(&body);
        if let Some(api_key) = &self.api_key {
            request = request.bearer_auth(api_key);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| MemoryError::EmbeddingFailed(format!("HTTP error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_owned());
            return Err(MemoryError::EmbeddingFailed(format!(
                "API returned {status}: {body}"
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| MemoryError::EmbeddingFailed(format!("JSON parse error: {e}")))?;

        let raw = json["data"][0]["embedding"].as_array().ok_or_else(|| {
            MemoryError::EmbeddingFailed("missing data[0].embedding in response".into())
        })?;

        let embedding: Vec<f32> = raw
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.as_f64().map(|n| n as f32).ok_or_else(|| {
                    MemoryError::EmbeddingFailed(format!("non-numeric element at index {i}: {v}"))
                })
            })
            .collect::<Result<_, _>>()?;

        if embedding.len() != self.dimensions {
            return Err(MemoryError::EmbeddingFailed(format!(
                "expected {} dimensions, got {}",
                self.dimensions,
                embedding.len()
            )));
        }

        Ok(embedding)
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_embedder_construction() {
        let embedder = ApiEmbedder::new(
            "https://api.openai.com",
            "text-embedding-3-small",
            1536,
            Some("test-key".into()),
        );
        assert_eq!(embedder.dimensions(), 1536);
        assert_eq!(embedder.model_name(), "text-embedding-3-small");
    }

    #[tokio::test]
    async fn api_embedder_error_on_failure() {
        // Use a non-existent local server to trigger an error
        let embedder = ApiEmbedder::new("http://127.0.0.1:1", "test", 128, None);
        let result = embedder.embed("test").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("HTTP error") || err.contains("embedding failed"),
            "unexpected error: {err}"
        );
    }
}
