use std::sync::Arc;

use async_trait::async_trait;

use encmind_agent::approval::ToolApprovalChecker;
use encmind_core::config::BashMode;
use encmind_core::traits::ApprovalHandler;
use encmind_core::types::{ApprovalDecision, ApprovalRequest};

/// Approval handler used by the gateway runtime.
///
/// The gateway currently has no interactive approval UX, so any tool call that
/// requires approval is denied. Combined with `ToolApprovalChecker`, this still
/// allows commands explicitly permitted by policy (for example allowlisted bash
/// commands) while enforcing `deny`/`ask` semantics safely.
pub struct DenyApprovalHandler;

#[async_trait]
impl ApprovalHandler for DenyApprovalHandler {
    async fn request_approval(&self, _request: ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Denied {
            reason: "interactive approvals are not configured in gateway runtime".to_string(),
        }
    }
}

/// Build gateway approval components from security config.
pub fn gateway_approval_policy(
    bash_mode: BashMode,
    bash_effectively_enabled: bool,
) -> (Arc<dyn ApprovalHandler>, ToolApprovalChecker) {
    (
        Arc::new(DenyApprovalHandler),
        ToolApprovalChecker::with_bash_effective_mode(bash_mode, bash_effectively_enabled)
            .with_interactive_approval_available(false),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deny_handler_returns_denied() {
        let handler = DenyApprovalHandler;
        let decision = handler
            .request_approval(ApprovalRequest {
                tool_name: "bash_exec".to_string(),
                tool_input: serde_json::json!({"command": "ls"}),
                session_id: encmind_core::types::SessionId::new(),
                agent_id: encmind_core::types::AgentId::default(),
            })
            .await;

        match decision {
            ApprovalDecision::Denied { reason } => {
                assert!(reason.contains("interactive approvals"));
            }
            other => panic!("expected denied decision, got: {other:?}"),
        }
    }

    #[test]
    fn gateway_policy_treats_ask_as_denied_without_interactive_prompts() {
        let (_handler, checker) = gateway_approval_policy(BashMode::Ask, true);
        assert!(checker.is_denied("bash_exec"));
        assert!(checker.is_denied("node_bash_exec"));
    }
}
