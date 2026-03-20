use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use encmind_core::config::AgentPoolConfig;
use encmind_core::error::AppError;
use encmind_core::types::*;

use crate::runtime::{AgentRuntime, RunResult};

/// Concurrency-limited pool for agent executions.
///
/// Uses a semaphore to limit the number of concurrent agent runs
/// and a per-session timeout to prevent runaway executions.
pub struct AgentPool {
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

impl AgentPool {
    pub fn new(config: &AgentPoolConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_agents as usize)),
            timeout: Duration::from_secs(config.per_session_timeout_secs),
        }
    }

    /// Execute an agent run with concurrency limiting and timeout.
    pub async fn execute(
        &self,
        runtime: &AgentRuntime,
        session_id: &SessionId,
        user_message: Message,
        agent_config: &AgentConfig,
        cancel: CancellationToken,
    ) -> Result<RunResult, AppError> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AppError::Internal("agent pool semaphore closed".into()))?;

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

    /// Number of currently available permits.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
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
            )
            .await
            .unwrap();

        assert_eq!(result.iterations, 1);
    }

    #[tokio::test]
    async fn available_permits_reported() {
        let pool = AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 4,
            per_session_timeout_secs: 60,
        });
        assert_eq!(pool.available_permits(), 4);
    }

    #[tokio::test]
    async fn concurrency_limiting() {
        // Create a pool with max 2 concurrent
        let pool = Arc::new(AgentPool::new(&AgentPoolConfig {
            max_concurrent_agents: 2,
            per_session_timeout_secs: 60,
        }));

        // Verify the semaphore behavior directly.
        assert_eq!(pool.available_permits(), 2);

        // Acquire permits manually to simulate concurrent usage
        let sem = pool.semaphore.clone();
        let p1 = sem.acquire().await.unwrap();
        assert_eq!(pool.available_permits(), 1);
        let p2 = sem.acquire().await.unwrap();
        assert_eq!(pool.available_permits(), 0);

        drop(p1);
        assert_eq!(pool.available_permits(), 1);
        drop(p2);
        assert_eq!(pool.available_permits(), 2);
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
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out"), "expected timeout error: {err}");
    }

    #[tokio::test]
    async fn permit_released_after_cancel() {
        let (pool, runtime, store) = make_pool_and_runtime(2, 60, vec![text_response("x")]).await;
        let session = store.create_session("web").await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();

        // Even though this errors due to cancellation, permit should be released
        let _ = pool
            .execute(
                &runtime,
                &session.id,
                make_user_msg("cancel"),
                &default_agent(),
                cancel,
            )
            .await;

        assert_eq!(pool.available_permits(), 2);
    }
}
