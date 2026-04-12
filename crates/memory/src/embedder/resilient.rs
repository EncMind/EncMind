//! Resilient embedder wrapper — adds retry + circuit breaker around
//! any `Embedder` implementation.
//!
//! When the upstream embedding API is transiently unavailable, the
//! wrapper retries up to `max_retries` times with exponential backoff.
//! After `failure_threshold` consecutive failures the circuit opens
//! and subsequent calls fail immediately with a clear "circuit open"
//! error until the reset timeout expires, at which point one probe
//! call is allowed. This prevents memory search from hammering a
//! dead API and producing cascading timeouts in the agent runtime.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use encmind_core::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use encmind_core::error::MemoryError;
use encmind_core::traits::Embedder;

/// Configuration for the resilient embedder wrapper.
pub struct ResilientEmbedderConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub circuit_failure_threshold: u32,
    pub circuit_reset_timeout: Duration,
}

impl Default for ResilientEmbedderConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(200),
            circuit_failure_threshold: 5,
            circuit_reset_timeout: Duration::from_secs(60),
        }
    }
}

/// Wraps an `Embedder` with retry + circuit breaker.
pub struct ResilientEmbedder {
    inner: Arc<dyn Embedder>,
    circuit: CircuitBreaker,
    max_retries: u32,
    base_delay: Duration,
}

impl ResilientEmbedder {
    pub fn new(inner: Arc<dyn Embedder>, config: ResilientEmbedderConfig) -> Self {
        Self {
            inner,
            circuit: CircuitBreaker::new(CircuitBreakerConfig {
                failure_threshold: config.circuit_failure_threshold,
                reset_timeout: config.circuit_reset_timeout,
                name: "embedding_api".into(),
            }),
            max_retries: config.max_retries,
            base_delay: config.base_delay,
        }
    }
}

#[async_trait]
impl Embedder for ResilientEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, MemoryError> {
        if !self.circuit.is_call_permitted() {
            return Err(MemoryError::EmbeddingFailed(format!(
                "embedding circuit breaker is open ({} consecutive failures); \
                 memory search will fall back to text-only results until the API recovers",
                self.circuit.consecutive_failures()
            )));
        }

        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match self.inner.embed(text).await {
                Ok(result) => {
                    self.circuit.record_success();
                    return Ok(result);
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < self.max_retries {
                        let delay = self.base_delay * 2u32.saturating_pow(attempt);
                        tracing::debug!(
                            attempt = attempt + 1,
                            max = self.max_retries,
                            delay_ms = delay.as_millis() as u64,
                            "embedding API call failed; retrying"
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // All retries exhausted.
        self.circuit.record_failure();
        tracing::warn!(
            circuit = self.circuit.name(),
            failures = self.circuit.consecutive_failures(),
            state = %self.circuit.state().as_str(),
            "embedding API call failed after retries"
        );
        Err(last_err.unwrap_or_else(|| {
            MemoryError::EmbeddingFailed("embedding failed (no error captured)".into())
        }))
    }

    fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    fn model_name(&self) -> &str {
        self.inner.model_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct FailNTimesEmbedder {
        fail_count: AtomicU32,
        fail_until: u32,
        dimensions: usize,
    }

    #[async_trait]
    impl Embedder for FailNTimesEmbedder {
        async fn embed(&self, _text: &str) -> Result<Vec<f32>, MemoryError> {
            let n = self.fail_count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_until {
                return Err(MemoryError::EmbeddingFailed("transient".into()));
            }
            Ok(vec![0.0; self.dimensions])
        }

        fn dimensions(&self) -> usize {
            self.dimensions
        }

        fn model_name(&self) -> &str {
            "test"
        }
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        let inner = Arc::new(FailNTimesEmbedder {
            fail_count: AtomicU32::new(0),
            fail_until: 2,
            dimensions: 3,
        });
        let embedder = ResilientEmbedder::new(
            inner.clone(),
            ResilientEmbedderConfig {
                max_retries: 3,
                base_delay: Duration::from_millis(1),
                circuit_failure_threshold: 10,
                circuit_reset_timeout: Duration::from_secs(60),
            },
        );
        let result = embedder.embed("hello").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
        // Should have taken 3 attempts (2 failures + 1 success).
        assert_eq!(inner.fail_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn circuit_opens_after_threshold() {
        let inner = Arc::new(FailNTimesEmbedder {
            fail_count: AtomicU32::new(0),
            fail_until: 100, // always fails
            dimensions: 3,
        });
        let embedder = ResilientEmbedder::new(
            inner,
            ResilientEmbedderConfig {
                max_retries: 0, // no retries — each call = 1 attempt
                base_delay: Duration::from_millis(1),
                circuit_failure_threshold: 3,
                circuit_reset_timeout: Duration::from_secs(300),
            },
        );

        // 3 failures open the circuit.
        for _ in 0..3 {
            assert!(embedder.embed("x").await.is_err());
        }

        // 4th call should be rejected by the circuit without hitting inner.
        let err = embedder.embed("x").await.unwrap_err();
        assert!(
            err.to_string().contains("circuit breaker is open"),
            "expected circuit-open error, got: {err}"
        );
    }

    #[tokio::test]
    async fn success_resets_circuit() {
        let inner = Arc::new(FailNTimesEmbedder {
            fail_count: AtomicU32::new(0),
            fail_until: 2, // fail twice then succeed
            dimensions: 3,
        });
        let embedder = ResilientEmbedder::new(
            inner,
            ResilientEmbedderConfig {
                max_retries: 3,
                base_delay: Duration::from_millis(1),
                circuit_failure_threshold: 10,
                circuit_reset_timeout: Duration::from_secs(60),
            },
        );
        // First call retries internally and succeeds.
        assert!(embedder.embed("x").await.is_ok());
        // Circuit should be closed.
        assert!(embedder.circuit.is_call_permitted());
    }
}
