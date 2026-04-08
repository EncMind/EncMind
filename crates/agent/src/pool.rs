use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use encmind_core::config::AgentPoolConfig;
use encmind_core::error::AppError;
use encmind_core::types::*;

use crate::runtime::{AgentRuntime, ChatEvent, RunResult};
use crate::scheduler::{QueryClass, TwoClassScheduler};

/// Concurrency-limited pool for agent executions.
///
/// Uses a two-class priority scheduler to limit the number of
/// concurrent agent runs and to prioritize interactive traffic
/// over background (cron/webhook/timer) traffic. A per-session
/// timeout prevents runaway executions.
pub struct AgentPool {
    pub(crate) scheduler: Arc<TwoClassScheduler>,
    timeout: Duration,
}

impl AgentPool {
    pub fn new(config: &AgentPoolConfig) -> Self {
        Self {
            scheduler: Arc::new(TwoClassScheduler::new(
                config.max_concurrent_agents as usize,
                config.scheduler_fairness_cap,
            )),
            timeout: Duration::from_secs(config.per_session_timeout_secs),
        }
    }

    /// Execute an agent run with concurrency limiting and timeout.
    ///
    /// `class` controls scheduling priority: interactive runs are
    /// served before background runs (subject to the fairness cap).
    pub async fn execute(
        &self,
        runtime: &AgentRuntime,
        session_id: &SessionId,
        user_message: Message,
        agent_config: &AgentConfig,
        cancel: CancellationToken,
        class: QueryClass,
    ) -> Result<RunResult, AppError> {
        let permit = self
            .scheduler
            .acquire(class)
            .await
            .map_err(|_| AppError::Internal("agent pool scheduler closed".into()))?;

        let result = tokio::time::timeout(
            self.timeout,
            runtime.run(session_id, user_message, agent_config, cancel),
        )
        .await;

        drop(permit);

        match result {
            Ok(inner) => inner,
            Err(_) => {
                warn!(
                    session = %session_id,
                    timeout_secs = self.timeout.as_secs(),
                    "agent execution timed out"
                );
                Err(AppError::Internal(format!(
                    "agent execution timed out after {} seconds",
                    self.timeout.as_secs()
                )))
            }
        }
    }

    /// Execute an agent run with streaming events, concurrency limiting, and timeout.
    ///
    /// Returns a receiver for streaming events and a join handle for the final result.
    /// The scheduler permit is held until the run completes.
    ///
    /// `class` controls scheduling priority: interactive runs are
    /// served before background runs (subject to the fairness cap).
    pub async fn execute_streaming(
        &self,
        runtime: &AgentRuntime,
        session_id: SessionId,
        user_message: Message,
        agent_config: AgentConfig,
        cancel: CancellationToken,
        class: QueryClass,
    ) -> Result<
        (
            tokio::sync::mpsc::Receiver<ChatEvent>,
            tokio::task::JoinHandle<Result<RunResult, AppError>>,
        ),
        AppError,
    > {
        let permit = self
            .scheduler
            .acquire(class)
            .await
            .map_err(|_| AppError::Internal("agent pool scheduler closed".into()))?;

        let timeout = self.timeout;
        let timeout_cancel = cancel.clone();
        let (rx, inner_handle) =
            runtime.run_streaming(session_id, user_message, agent_config, cancel);

        // Wrap the inner handle with timeout and permit release.
        let handle = tokio::spawn(async move {
            let mut inner_handle = inner_handle;
            let result = tokio::select! {
                join = &mut inner_handle => {
                    match join {
                        Ok(inner) => inner,
                        Err(join_err) => Err(AppError::Internal(format!(
                            "agent task panicked: {join_err}"
                        ))),
                    }
                }
                _ = tokio::time::sleep(timeout) => {
                    timeout_cancel.cancel();
                    inner_handle.abort();
                    let _ = inner_handle.await;
                    Err(AppError::Internal(format!(
                        "agent execution timed out after {} seconds",
                        timeout.as_secs()
                    )))
                }
            };
            drop(permit);
            result
        });

        Ok((rx, handle))
    }

    /// Maximum concurrent agent runs allowed by this pool.
    pub fn max_concurrent(&self) -> usize {
        self.scheduler.max_concurrent()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::test_helpers::*;
    use crate::runtime::RuntimeConfig;
    use crate::tool_registry::ToolRegistry;
    use encmind_core::traits::{LlmBackend, SessionStore};

    fn make_user_msg(text: &str) -> Message {
        Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_owned(),
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        }
    }

    fn default_agent() -> AgentConfig {
        AgentConfig {
            id: AgentId::default(),
            name: "Test".into(),
            model: None,
            workspace: None,
            system_prompt: None,
            skills: vec![],
            is_default: true,
        }
    }

    async fn make_pool_and_runtime(
        max_concurrent: u32,
        timeout_secs: u64,
        responses: Vec<Vec<encmind_core::traits::CompletionDelta>>,
    ) -> (AgentPool, AgentRuntime, Arc<InMemorySessionStore>) {
        let pool = AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: max_concurrent,
            per_session_timeout_secs: timeout_secs,
            ..Default::default()
        });

        let llm: Arc<dyn LlmBackend> = Arc::new(ScriptedLlmBackend::new(responses, 128_000));
        let store = Arc::new(InMemorySessionStore::new());

        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn encmind_core::traits::SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        );

        (pool, runtime, store)
    }

    #[tokio::test]
    async fn basic_execution() {
        let (pool, runtime, store) =
            make_pool_and_runtime(4, 60, vec![text_response("hello")]).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = pool
            .execute(
                &runtime,
                &session.id,
                make_user_msg("hi"),
                &default_agent(),
                cancel,
                QueryClass::Interactive,
            )
            .await
            .unwrap();

        assert_eq!(result.iterations, 1);
    }

    #[tokio::test]
    async fn max_concurrent_reported() {
        let pool = AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
            ..Default::default()
        });
        assert_eq!(pool.max_concurrent(), 4);
    }

    #[tokio::test]
    async fn timeout_returns_error() {
        use async_trait::async_trait;
        use encmind_core::error::LlmError;
        use encmind_core::traits::{CompletionDelta, CompletionParams, ModelInfo};
        use std::pin::Pin;
        use tokio_stream::Stream;

        // An LLM backend that hangs forever
        struct HangingLlmBackend;

        #[async_trait]
        impl LlmBackend for HangingLlmBackend {
            async fn complete(
                &self,
                _messages: &[Message],
                _params: CompletionParams,
                _cancel: CancellationToken,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
                LlmError,
            > {
                // Hang forever
                tokio::time::sleep(Duration::from_secs(3600)).await;
                unreachable!()
            }

            async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
                Ok(10)
            }

            fn model_info(&self) -> ModelInfo {
                ModelInfo {
                    id: "hang".into(),
                    name: "Hanging".into(),
                    context_window: 128_000,
                    provider: "test".into(),
                    supports_tools: true,
                    supports_streaming: true,
                    supports_thinking: false,
                }
            }
        }

        let pool = AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 2,
            per_session_timeout_secs: 1, // 1 second timeout
            ..Default::default()
        });

        let llm: Arc<dyn LlmBackend> = Arc::new(HangingLlmBackend);
        let store = Arc::new(InMemorySessionStore::new());
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn encmind_core::traits::SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();

        let result = pool
            .execute(
                &runtime,
                &session.id,
                make_user_msg("timeout"),
                &default_agent(),
                cancel,
                QueryClass::Interactive,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out"), "expected timeout error: {err}");
    }

    #[tokio::test]
    async fn streaming_timeout_returns_error_and_releases_permit() {
        use async_trait::async_trait;
        use encmind_core::error::LlmError;
        use encmind_core::traits::{CompletionDelta, CompletionParams, ModelInfo};
        use std::pin::Pin;
        use tokio_stream::Stream;

        struct HangingLlmBackend;

        #[async_trait]
        impl LlmBackend for HangingLlmBackend {
            async fn complete(
                &self,
                _messages: &[Message],
                _params: CompletionParams,
                _cancel: CancellationToken,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>,
                LlmError,
            > {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                unreachable!()
            }

            async fn count_tokens(&self, _messages: &[Message]) -> Result<u32, LlmError> {
                Ok(10)
            }

            fn model_info(&self) -> ModelInfo {
                ModelInfo {
                    id: "hang".into(),
                    name: "Hanging".into(),
                    context_window: 128_000,
                    provider: "test".into(),
                    supports_tools: true,
                    supports_streaming: true,
                    supports_thinking: false,
                }
            }
        }

        let pool = AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 1,
            per_session_timeout_secs: 1,
            ..Default::default()
        });

        let llm: Arc<dyn LlmBackend> = Arc::new(HangingLlmBackend);
        let store = Arc::new(InMemorySessionStore::new());
        let runtime = AgentRuntime::new(
            llm,
            store.clone() as Arc<dyn encmind_core::traits::SessionStore>,
            Arc::new(ToolRegistry::new()),
            RuntimeConfig::default(),
        );

        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        let (_rx, handle) = pool
            .execute_streaming(
                &runtime,
                session.id.clone(),
                make_user_msg("timeout"),
                default_agent(),
                cancel,
                QueryClass::Interactive,
            )
            .await
            .unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out"), "expected timeout error: {err}");

        // After timeout, the scheduler slot must be released — a
        // subsequent acquire should not hang.
        let (_rx2, handle2) = tokio::time::timeout(
            Duration::from_secs(2),
            pool.execute_streaming(
                &runtime,
                store.create_session("web").await.unwrap().id,
                make_user_msg("again"),
                default_agent(),
                CancellationToken::new(),
                QueryClass::Interactive,
            ),
        )
        .await
        .expect("acquire should not hang after timeout release")
        .unwrap();
        // Clean up the second run (it will also hit the hanging backend).
        handle2.abort();
    }

    #[tokio::test]
    async fn permit_released_after_cancel() {
        let (pool, runtime, store) = make_pool_and_runtime(1, 60, vec![text_response("x")]).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();

        // Cancelled run errors out but must release its scheduler slot.
        let _ = pool
            .execute(
                &runtime,
                &session.id,
                make_user_msg("cancel"),
                &default_agent(),
                cancel,
                QueryClass::Interactive,
            )
            .await;

        // Behavioral check: with max_concurrent=1, a second acquire
        // must succeed without hanging.
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            pool.execute(
                &runtime,
                &session.id,
                make_user_msg("next"),
                &default_agent(),
                CancellationToken::new(),
                QueryClass::Interactive,
            ),
        )
        .await;
        assert!(
            result.is_ok(),
            "second acquire should not hang — slot was not released after cancel"
        );
    }

    #[tokio::test]
    async fn interactive_preempts_background_under_pressure() {
        let (pool, _runtime, _store) = make_pool_and_runtime(1, 60, vec![]).await;
        let pool = Arc::new(pool);

        // Hold the single slot with a background waiter.
        let held = pool
            .scheduler
            .acquire(QueryClass::Background)
            .await
            .unwrap();

        // Queue 3 backgrounds, then 2 interactives.
        let order: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for label in ["bg-1", "bg-2", "bg-3"] {
            let p = pool.clone();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                let _permit = p.scheduler.acquire(QueryClass::Background).await.unwrap();
                order.lock().unwrap().push(label);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        for label in ["int-1", "int-2"] {
            let p = pool.clone();
            let order = order.clone();
            handles.push(tokio::spawn(async move {
                let _permit = p.scheduler.acquire(QueryClass::Interactive).await.unwrap();
                order.lock().unwrap().push(label);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;

        drop(held);

        for h in handles {
            h.await.unwrap();
        }

        let observed = order.lock().unwrap().clone();
        // Both interactives must be served before any background
        // that was queued after them finishes. With fairness_cap=4
        // (the default) and only 2 interactives, interactives are
        // drained first, then backgrounds follow.
        let first_bg_after_int = observed
            .iter()
            .position(|s| s.starts_with("int-"))
            .and_then(|int_pos| {
                observed
                    .iter()
                    .enumerate()
                    .skip(int_pos)
                    .find(|(_, s)| s.starts_with("bg-"))
                    .map(|(idx, _)| idx)
            });
        let last_int_pos = observed
            .iter()
            .enumerate()
            .rev()
            .find(|(_, s)| s.starts_with("int-"))
            .map(|(idx, _)| idx)
            .expect("interactive must be served");
        if let Some(bg_idx) = first_bg_after_int {
            assert!(
                bg_idx > last_int_pos,
                "interactives should finish before remaining backgrounds start. sequence: {observed:?}"
            );
        }
    }
}
