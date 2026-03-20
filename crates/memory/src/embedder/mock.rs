use async_trait::async_trait;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use encmind_core::error::MemoryError;
use encmind_core::traits::Embedder;

/// A deterministic embedder for tests: produces normalized vectors derived from a hash of the input.
pub struct MockEmbedder {
    dimensions: usize,
}

impl MockEmbedder {
    pub fn new(dimensions: usize) -> Self {
        Self { dimensions }
    }
}

#[async_trait]
impl Embedder for MockEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, MemoryError> {
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        let seed = hasher.finish();

        let mut vector = Vec::with_capacity(self.dimensions);
        let mut state = seed;
        for _ in 0..self.dimensions {
            // Simple LCG-style deterministic sequence
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let val = ((state >> 33) as f32) / (u32::MAX as f32) * 2.0 - 1.0;
            vector.push(val);
        }

        // Normalize
        let magnitude: f32 = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
        if magnitude > 0.0 {
            for v in &mut vector {
                *v /= magnitude;
            }
        }

        Ok(vector)
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn model_name(&self) -> &str {
        "mock-embedder"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn correct_dimensions() {
        let embedder = MockEmbedder::new(384);
        let vec = embedder.embed("hello world").await.unwrap();
        assert_eq!(vec.len(), 384);
    }

    #[tokio::test]
    async fn deterministic() {
        let embedder = MockEmbedder::new(128);
        let a = embedder.embed("test input").await.unwrap();
        let b = embedder.embed("test input").await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn different_inputs_differ() {
        let embedder = MockEmbedder::new(128);
        let a = embedder.embed("hello").await.unwrap();
        let b = embedder.embed("world").await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn output_normalized() {
        let embedder = MockEmbedder::new(256);
        let vec = embedder.embed("normalize me").await.unwrap();
        let magnitude: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!(
            (magnitude - 1.0).abs() < 0.001,
            "expected magnitude ~1.0, got {magnitude}"
        );
    }
}
