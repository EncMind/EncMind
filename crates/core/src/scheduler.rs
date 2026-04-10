//! Shared scheduler types used across the runtime and lower layers.
//!
//! `QueryClass` and its task-local live here (rather than in
//! `encmind-agent`) so lower-level crates like `encmind-llm` can read
//! the current class for retry-policy decisions without creating a
//! circular dependency on `encmind-agent`.
//!
//! The concrete scheduler implementation (`TwoClassScheduler`) stays
//! in `encmind-agent::scheduler` because it uses runtime primitives
//! that belong alongside the agent runtime.

/// The priority class of an agent run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryClass {
    /// User-initiated request; served first.
    Interactive,
    /// Automated request (cron, webhook, timer); served after
    /// interactive drains (subject to the fairness cap).
    Background,
}

impl QueryClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Background => "background",
        }
    }
}

tokio::task_local! {
    /// Task-local priority class of the currently executing run.
    ///
    /// Set by `encmind_agent::runtime::AgentRuntime::run_inner` at the
    /// start of each run and read by nested tool handlers and lower
    /// layers (LLM retry policy) to inherit the parent's class.
    /// Flows through `buffer_unordered` and sequential awaits within
    /// the same task, but NOT across `tokio::spawn`; new spawns that
    /// should propagate the class must re-scope it explicitly.
    pub static CURRENT_QUERY_CLASS: QueryClass;
}

/// Read the current task-local query class, defaulting to `Interactive`
/// when unset (top-level calls from tests or outside of a run).
pub fn current_query_class() -> QueryClass {
    CURRENT_QUERY_CLASS
        .try_with(|c| *c)
        .unwrap_or(QueryClass::Interactive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_variant() {
        assert_eq!(QueryClass::Interactive.as_str(), "interactive");
        assert_eq!(QueryClass::Background.as_str(), "background");
    }

    #[tokio::test]
    async fn default_outside_scope_is_interactive() {
        assert_eq!(current_query_class(), QueryClass::Interactive);
    }

    #[tokio::test]
    async fn scope_sets_task_local() {
        let observed = CURRENT_QUERY_CLASS
            .scope(QueryClass::Background, async { current_query_class() })
            .await;
        assert_eq!(observed, QueryClass::Background);
    }

    #[tokio::test]
    async fn scope_flows_through_awaits() {
        let observed = CURRENT_QUERY_CLASS
            .scope(QueryClass::Background, async {
                tokio::task::yield_now().await;
                current_query_class()
            })
            .await;
        assert_eq!(observed, QueryClass::Background);
    }
}
