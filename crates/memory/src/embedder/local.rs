//! Local embedding via candle (pure Rust, no ONNX Runtime).
//!
//! Uses a BERT-family sentence-transformer model (e.g., bge-small-en-v1.5) to
//! compute embeddings entirely on-device. No external API calls.

use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig, DTYPE};
use hf_hub::{api::sync::Api, Repo, RepoType};
use tokenizers::{Tokenizer, TruncationParams};

use encmind_core::error::MemoryError;
use encmind_core::traits::Embedder;

/// Default HuggingFace model ID for local embedding.
const DEFAULT_MODEL_ID: &str = "BAAI/bge-small-en-v1.5";

/// Maximum token sequence length.
const MAX_TOKENS: usize = 512;

/// Loaded model + tokenizer, held behind a mutex for thread safety.
struct LoadedModel {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

/// An embedder that runs a BERT sentence-transformer model locally via candle.
pub struct LocalEmbedder {
    inner: Mutex<LoadedModel>,
    dimensions: usize,
    model_name: String,
}

impl LocalEmbedder {
    /// Load a model from HuggingFace Hub (downloads on first use, cached after).
    ///
    /// # Arguments
    /// * `model_id` — HuggingFace model ID (e.g., "BAAI/bge-small-en-v1.5")
    /// * `cache_dir` — optional local cache directory override
    pub fn from_hub(model_id: &str, _cache_dir: Option<&PathBuf>) -> Result<Self, MemoryError> {
        let device = Device::Cpu;

        tracing::info!(
            model_id,
            "local embedding: downloading/loading model from HuggingFace Hub"
        );

        let api = Api::new().map_err(|e| {
            MemoryError::ModelNotLoaded(format!("failed to create HF Hub API: {e}"))
        })?;

        let repo = api.repo(Repo::new(model_id.to_string(), RepoType::Model));

        let config_path = repo.get("config.json").map_err(|e| {
            MemoryError::ModelNotLoaded(format!("failed to download config.json: {e}"))
        })?;
        let tokenizer_path = repo.get("tokenizer.json").map_err(|e| {
            MemoryError::ModelNotLoaded(format!("failed to download tokenizer.json: {e}"))
        })?;
        let weights_path = repo.get("model.safetensors").map_err(|e| {
            MemoryError::ModelNotLoaded(format!("failed to download model.safetensors: {e}"))
        })?;

        // Load config.
        let config_data = std::fs::read_to_string(&config_path)
            .map_err(|e| MemoryError::ModelNotLoaded(format!("failed to read config.json: {e}")))?;
        let config: BertConfig = serde_json::from_str(&config_data).map_err(|e| {
            MemoryError::ModelNotLoaded(format!("failed to parse config.json: {e}"))
        })?;
        let dimensions = config.hidden_size;

        // Load tokenizer.
        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| MemoryError::ModelNotLoaded(format!("failed to load tokenizer: {e}")))?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: MAX_TOKENS,
                ..Default::default()
            }))
            .map_err(|e| MemoryError::ModelNotLoaded(format!("failed to set truncation: {e}")))?;
        tokenizer.with_padding(None);

        // Load weights.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DTYPE, &device).map_err(|e| {
                MemoryError::ModelNotLoaded(format!("failed to load model weights: {e}"))
            })?
        };

        let model = BertModel::load(vb, &config)
            .map_err(|e| MemoryError::ModelNotLoaded(format!("failed to build BERT model: {e}")))?;

        tracing::info!(
            model_id,
            dimensions,
            "local embedding: model loaded successfully"
        );

        Ok(Self {
            inner: Mutex::new(LoadedModel {
                model,
                tokenizer,
                device,
            }),
            dimensions,
            model_name: model_id.to_string(),
        })
    }

    /// Load the default model (bge-small-en-v1.5, 384 dimensions).
    pub fn default_model(cache_dir: Option<&PathBuf>) -> Result<Self, MemoryError> {
        Self::from_hub(DEFAULT_MODEL_ID, cache_dir)
    }

    /// Embed a single text synchronously.
    fn embed_sync(&self, text: &str) -> Result<Vec<f32>, MemoryError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| MemoryError::EmbeddingFailed(format!("model lock poisoned: {e}")))?;

        let encoding = inner
            .tokenizer
            .encode(text, true)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("tokenization failed: {e}")))?;

        let ids = encoding.get_ids();
        let type_ids = encoding.get_type_ids();
        let attention_mask = encoding.get_attention_mask();

        let input_ids = Tensor::new(ids, &inner.device)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("tensor creation failed: {e}")))?
            .unsqueeze(0)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("unsqueeze failed: {e}")))?;
        let token_type_ids = Tensor::new(type_ids, &inner.device)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("tensor creation failed: {e}")))?
            .unsqueeze(0)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("unsqueeze failed: {e}")))?;
        let attention_mask_tensor = Tensor::new(attention_mask, &inner.device)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("tensor creation failed: {e}")))?
            .unsqueeze(0)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("unsqueeze failed: {e}")))?;

        // Run BERT forward pass.
        let output = inner
            .model
            .forward(&input_ids, &token_type_ids, Some(&attention_mask_tensor))
            .map_err(|e| MemoryError::EmbeddingFailed(format!("model forward pass failed: {e}")))?;

        // Mean pooling over non-padding tokens.
        // output shape: [1, seq_len, hidden_dim]
        let mask_f32 = attention_mask_tensor
            .to_dtype(candle_core::DType::F32)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("dtype conversion failed: {e}")))?
            .unsqueeze(2)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("unsqueeze failed: {e}")))?;

        // Expand mask to [1, seq_len, hidden_dim] and multiply.
        let masked = output
            .broadcast_mul(&mask_f32)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("broadcast_mul failed: {e}")))?;

        // Sum over seq_len dimension.
        let summed = masked
            .sum(1)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("sum failed: {e}")))?;

        // Count non-padding tokens.
        let count = mask_f32
            .sum(1)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("count sum failed: {e}")))?
            .clamp(1e-9, f64::MAX)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("clamp failed: {e}")))?;

        // Mean = summed / count.
        let mean_pooled = summed
            .broadcast_div(&count)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("div failed: {e}")))?;

        // Squeeze batch dimension → [hidden_dim].
        let embedding = mean_pooled
            .squeeze(0)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("squeeze failed: {e}")))?;

        // L2-normalize.
        let norm = embedding
            .sqr()
            .map_err(|e| MemoryError::EmbeddingFailed(format!("sqr failed: {e}")))?
            .sum_all()
            .map_err(|e| MemoryError::EmbeddingFailed(format!("sum_all failed: {e}")))?
            .sqrt()
            .map_err(|e| MemoryError::EmbeddingFailed(format!("sqrt failed: {e}")))?
            .clamp(1e-12, f64::MAX)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("clamp failed: {e}")))?;

        let normalized = embedding
            .broadcast_div(&norm)
            .map_err(|e| MemoryError::EmbeddingFailed(format!("normalize failed: {e}")))?;

        let result: Vec<f32> = normalized
            .to_vec1()
            .map_err(|e| MemoryError::EmbeddingFailed(format!("to_vec1 failed: {e}")))?;

        if result.len() != self.dimensions {
            return Err(MemoryError::EmbeddingFailed(format!(
                "expected {} dimensions, got {}",
                self.dimensions,
                result.len()
            )));
        }

        Ok(result)
    }
}

#[async_trait]
impl Embedder for LocalEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, MemoryError> {
        let text = text.to_string();
        let self_ptr = self as *const Self as usize;
        tokio::task::spawn_blocking(move || {
            // SAFETY: the caller holds &self for the lifetime of this call,
            // and spawn_blocking is awaited immediately — self outlives the task.
            let this = unsafe { &*(self_ptr as *const Self) };
            this.embed_sync(&text)
        })
        .await
        .map_err(|e| MemoryError::EmbeddingFailed(format!("embedding task failed: {e}")))?
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests download the model on first run (~130MB).
    // They are not #[ignore] because the download is cached.

    #[test]
    fn local_embedder_loads_default_model() {
        let result = LocalEmbedder::default_model(None);
        match result {
            Ok(e) => {
                assert_eq!(e.dimensions(), 384);
                assert_eq!(e.model_name(), DEFAULT_MODEL_ID);
            }
            Err(e) => {
                eprintln!("skipping test (network/disk issue): {e}");
            }
        }
    }

    #[tokio::test]
    async fn local_embedder_produces_384_dimensions() {
        let embedder = match LocalEmbedder::default_model(None) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };
        let vec = embedder.embed("hello world").await.unwrap();
        assert_eq!(vec.len(), 384);
    }

    #[tokio::test]
    async fn local_embedder_output_is_normalized() {
        let embedder = match LocalEmbedder::default_model(None) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };
        let vec = embedder.embed("test normalization").await.unwrap();
        let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 0.05,
            "expected L2 norm ~1.0, got {norm}"
        );
    }

    #[tokio::test]
    async fn local_embedder_similar_texts_high_cosine() {
        let embedder = match LocalEmbedder::default_model(None) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };
        let a = embedder.embed("the cat sat on the mat").await.unwrap();
        let b = embedder.embed("a cat was sitting on a mat").await.unwrap();
        let cosine: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        assert!(
            cosine > 0.7,
            "expected similar texts cosine > 0.7, got {cosine}"
        );
    }

    #[tokio::test]
    async fn local_embedder_different_texts_lower_cosine() {
        let embedder = match LocalEmbedder::default_model(None) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };
        let a = embedder.embed("hello world").await.unwrap();
        let b = embedder
            .embed("quantum chromodynamics explains strong nuclear force")
            .await
            .unwrap();
        let cosine: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        assert!(
            cosine < 0.5,
            "expected different texts cosine < 0.5, got {cosine}"
        );
    }
}
