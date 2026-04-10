use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use encmind_core::error::LlmError;
use encmind_core::traits::*;
use encmind_core::types::*;
use futures::Stream;
use tokio_util::sync::CancellationToken;

use crate::health::ProviderHealthTracker;
use crate::retry::RetryPolicy;

/// Routes LLM requests to the first healthy provider with automatic failover.
///
/// On initial call failure the dispatcher tries the next healthy provider.
/// Success/failure is reported to the `ProviderHealthTracker` which applies
/// exponential-backoff cooldowns.
pub struct LlmDispatcher {
    backends: Vec<Box<dyn LlmBackend>>,
    tracker: Mutex<ProviderHealthTracker>,
}

impl LlmDispatcher {
    /// Create a dispatcher from named backends (order determines priority).
    pub fn new(backends: Vec<(String, Box<dyn LlmBackend>)>) -> Self {
        let names: Vec<String> = backends.iter().map(|(n, _)| n.clone()).collect();
        let backends: Vec<Box<dyn LlmBackend>> = backends.into_iter().map(|(_, b)| b).collect();
        Self {
            backends,
            tracker: Mutex::new(ProviderHealthTracker::new(names)),
        }
    }

    /// Return the model info of the first healthy provider.
    pub fn primary_model_info(&self) -> Option<ModelInfo> {
        let tracker = self.tracker.lock().unwrap();
        tracker
            .next_healthy()
            .map(|idx| self.backends[idx].model_info())
    }

    fn parse_http_status_from_api_error(message: &str) -> Option<u16> {
        // Expected format from providers: "HTTP <code>: <body>"
        let rest = message.strip_prefix("HTTP ")?;
        let code_text = rest.split(':').next()?.trim();
        code_text.parse::<u16>().ok()
    }

    fn should_penalize_provider(error: &LlmError) -> bool {
        match error {
            // Bad request/model mismatches are caller-side input issues and
            // should not degrade provider health or trigger cooldown.
            LlmError::ApiError(message) => {
                if let Some(status) = Self::parse_http_status_from_api_error(message) {
                    return !matches!(status, 400 | 404 | 422);
                }
                true
            }
            _ => true,
        }
    }

    /// Single attempt at completion across all backends (failover logic).
    async fn try_complete(
        &self,
        messages: &[Message],
        params: CompletionParams,
        cancel: CancellationToken,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
    {
        // Collect healthy candidates (snapshot under lock)
        let candidates: Vec<usize> = {
            let tracker = self.tracker.lock().unwrap();
            tracker.healthy_indices()
        };

        if candidates.is_empty() {
            return Err(LlmError::AllProvidersUnhealthy);
        }

        let mut last_error: Option<LlmError> = None;

        for idx in &candidates {
            let backend = &self.backends[*idx];

            match backend
                .complete(messages, params.clone(), cancel.clone())
                .await
            {
                Ok(stream) => {
                    let mut tracker = self.tracker.lock().unwrap();
                    tracker.report_success(*idx);
                    return Ok(stream);
                }
                Err(e) => {
                    let penalize = Self::should_penalize_provider(&e);
                    let provider_name = if penalize {
                        let mut tracker = self.tracker.lock().unwrap();
                        tracker.report_failure(*idx);
                        tracker.provider_name(*idx).unwrap_or("unknown").to_string()
                    } else {
                        let tracker = self.tracker.lock().unwrap();
                        tracker.provider_name(*idx).unwrap_or("unknown").to_string()
                    };
                    tracing::warn!(
                        provider = %provider_name,
                        error = %e,
                        penalized = penalize,
                        "provider failed, trying next"
                    );
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or(LlmError::AllProvidersUnhealthy))
    }
}

#[async_trait]
impl LlmBackend for LlmDispatcher {
    /// Complete with retry on transient errors, wrapping the failover logic.
    async fn complete(
        &self,
        messages: &[Message],
        params: CompletionParams,
        cancel: CancellationToken,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
    {
        // Build the retry policy from the current task-local query class.
        // Interactive runs get the full retry budget; background runs
        // (cron, webhook, timer) bail fast so they can't amplify an
        // upstream cascade. Overall run is still bounded by
        // AgentPool::per_session_timeout_secs.
        let policy = RetryPolicy::for_current_class();
        let query_class = encmind_core::scheduler::current_query_class();
        let mut retries = 0u32;

        // Generate a stable idempotency key for this logical request.
        // The same key is reused across retries so the provider can
        // dedup: a retried request after a network timeout won't be
        // processed twice (and double-billed).
        let mut params = params;
        if params.request_id.is_none() {
            use rand::RngExt as _;
            let mut bytes = [0u8; 16];
            rand::rng().fill(&mut bytes);
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            params.request_id = Some(hex);
        }

        loop {
            match self
                .try_complete(messages, params.clone(), cancel.clone())
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    let err_str = e.to_string();
                    if RetryPolicy::is_retryable(&err_str) && retries < policy.max_retries {
                        let delay = policy.delay_for_retry(retries);
                        tracing::warn!(
                            retry = retries + 1,
                            max = policy.max_retries,
                            delay_ms = delay.as_millis() as u64,
                            class = %query_class.as_str(),
                            error = %err_str,
                            "retrying LLM completion after transient error"
                        );
                        tokio::time::sleep(delay).await;
                        retries += 1;
                    } else {
                        if retries > 0 {
                            let class = RetryPolicy::classify_error(&err_str);
                            tracing::error!(
                                retries = retries,
                                class = ?class,
                                query_class = %query_class.as_str(),
                                "{}", class.user_message()
                            );
                        }
                        return Err(e);
                    }
                }
            }
        }
    }

    async fn count_tokens(&self, messages: &[Message]) -> Result<u32, LlmError> {
        let idx = {
            let tracker = self.tracker.lock().unwrap();
            tracker
                .next_healthy()
                .ok_or(LlmError::AllProvidersUnhealthy)?
        };
        self.backends[idx].count_tokens(messages).await
    }

    fn model_info(&self) -> ModelInfo {
        self.primary_model_info().unwrap_or(ModelInfo {
            id: "none".into(),
            name: "No provider available".into(),
            context_window: 0,
            provider: "none".into(),
            supports_tools: false,
            supports_streaming: false,
            supports_thinking: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A test backend that always succeeds with an empty stream.
    struct OkBackend {
        name: String,
        call_count: Arc<AtomicU32>,
    }

    #[async_trait]
    impl LlmBackend for OkBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(Box::pin(futures::stream::empty()))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Ok(0)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: self.name.clone(),
                name: self.name.clone(),
                context_window: 4096,
                provider: "test".into(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    /// A test backend that always fails.
    struct FailBackend {
        name: String,
    }

    #[async_trait]
    impl LlmBackend for FailBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            Err(LlmError::ProviderError(format!("{} is down", self.name)))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Err(LlmError::ProviderError("down".into()))
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: self.name.clone(),
                name: self.name.clone(),
                context_window: 4096,
                provider: "test".into(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    struct BadRequestBackend {
        name: String,
        call_count: Arc<AtomicU32>,
    }

    #[async_trait]
    impl LlmBackend for BadRequestBackend {
        async fn complete(
            &self,
            _messages: &[Message],
            _params: CompletionParams,
            _cancel: CancellationToken,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
        {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err(LlmError::ApiError(format!(
                "HTTP 400: unsupported model for {}",
                self.name
            )))
        }

        async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
            Ok(0)
        }

        fn model_info(&self) -> ModelInfo {
            ModelInfo {
                id: self.name.clone(),
                name: self.name.clone(),
                context_window: 4096,
                provider: "test".into(),
                supports_tools: false,
                supports_streaming: true,
                supports_thinking: false,
            }
        }
    }

    #[tokio::test]
    async fn routes_to_primary() {
        let count = Arc::new(AtomicU32::new(0));
        let dispatcher = LlmDispatcher::new(vec![(
            "primary".into(),
            Box::new(OkBackend {
                name: "primary".into(),
                call_count: count.clone(),
            }) as Box<dyn LlmBackend>,
        )]);

        let cancel = CancellationToken::new();
        let _stream = dispatcher
            .complete(&[], CompletionParams::default(), cancel)
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failover_to_secondary() {
        let secondary_count = Arc::new(AtomicU32::new(0));
        let dispatcher = LlmDispatcher::new(vec![
            (
                "primary".into(),
                Box::new(FailBackend {
                    name: "primary".into(),
                }) as Box<dyn LlmBackend>,
            ),
            (
                "secondary".into(),
                Box::new(OkBackend {
                    name: "secondary".into(),
                    call_count: secondary_count.clone(),
                }) as Box<dyn LlmBackend>,
            ),
        ]);

        let cancel = CancellationToken::new();
        let _stream = dispatcher
            .complete(&[], CompletionParams::default(), cancel)
            .await
            .unwrap();
        assert_eq!(secondary_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cooldown_provider_is_not_retried() {
        let primary_count = Arc::new(AtomicU32::new(0));
        let secondary_count = Arc::new(AtomicU32::new(0));
        let dispatcher = LlmDispatcher::new(vec![
            (
                "primary".into(),
                Box::new(OkBackend {
                    name: "primary".into(),
                    call_count: primary_count.clone(),
                }) as Box<dyn LlmBackend>,
            ),
            (
                "secondary".into(),
                Box::new(OkBackend {
                    name: "secondary".into(),
                    call_count: secondary_count.clone(),
                }) as Box<dyn LlmBackend>,
            ),
        ]);

        {
            let mut tracker = dispatcher.tracker.lock().unwrap();
            tracker.report_failure(0);
            tracker.report_failure(0);
            tracker.report_failure(0);
        }

        let cancel = CancellationToken::new();
        let _stream = dispatcher
            .complete(&[], CompletionParams::default(), cancel)
            .await
            .unwrap();

        assert_eq!(primary_count.load(Ordering::SeqCst), 0);
        assert_eq!(secondary_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn all_fail_returns_error() {
        let dispatcher = LlmDispatcher::new(vec![
            (
                "a".into(),
                Box::new(FailBackend { name: "a".into() }) as Box<dyn LlmBackend>,
            ),
            (
                "b".into(),
                Box::new(FailBackend { name: "b".into() }) as Box<dyn LlmBackend>,
            ),
        ]);

        let cancel = CancellationToken::new();
        let result = dispatcher
            .complete(&[], CompletionParams::default(), cancel)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn empty_dispatcher_returns_error() {
        let dispatcher = LlmDispatcher::new(vec![]);
        let cancel = CancellationToken::new();
        let result = dispatcher
            .complete(&[], CompletionParams::default(), cancel)
            .await;
        assert!(matches!(result, Err(LlmError::AllProvidersUnhealthy)));
    }

    #[test]
    fn model_info_returns_primary() {
        let count = Arc::new(AtomicU32::new(0));
        let dispatcher = LlmDispatcher::new(vec![(
            "test".into(),
            Box::new(OkBackend {
                name: "test-model".into(),
                call_count: count,
            }) as Box<dyn LlmBackend>,
        )]);
        assert_eq!(dispatcher.model_info().id, "test-model");
    }

    #[tokio::test]
    async fn bad_request_error_does_not_cooldown_provider() {
        let primary_count = Arc::new(AtomicU32::new(0));
        let secondary_count = Arc::new(AtomicU32::new(0));
        let dispatcher = LlmDispatcher::new(vec![
            (
                "primary".into(),
                Box::new(BadRequestBackend {
                    name: "primary".into(),
                    call_count: primary_count.clone(),
                }) as Box<dyn LlmBackend>,
            ),
            (
                "secondary".into(),
                Box::new(OkBackend {
                    name: "secondary".into(),
                    call_count: secondary_count.clone(),
                }) as Box<dyn LlmBackend>,
            ),
        ]);

        for _ in 0..4 {
            let cancel = CancellationToken::new();
            let _stream = dispatcher
                .complete(&[], CompletionParams::default(), cancel)
                .await
                .unwrap();
        }

        // Primary should still be attempted each time (no cooldown from HTTP 400).
        assert_eq!(primary_count.load(Ordering::SeqCst), 4);
        assert_eq!(secondary_count.load(Ordering::SeqCst), 4);
    }
}
