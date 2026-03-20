use async_trait::async_trait;

use encmind_core::config::BashMode;
use encmind_core::traits::ApprovalHandler;
use encmind_core::types::{ApprovalDecision, ApprovalRequest};

/// An approval handler that auto-approves everything.
/// Used as the default for backward compatibility.
pub struct NoopApprovalHandler;

#[async_trait]
impl ApprovalHandler for NoopApprovalHandler {
    async fn request_approval(&self, _request: ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Approved
    }
}

/// Determines which tools require approval based on security policy.
#[derive(Clone)]
pub struct ToolApprovalChecker {
    bash_mode: BashMode,
}

impl ToolApprovalChecker {
    pub fn new(bash_mode: BashMode) -> Self {
        Self { bash_mode }
    }

    /// Returns `true` if the tool is categorically denied (e.g. `BashMode::Deny`
    /// for bash-related tools).
    pub fn is_denied(&self, tool_name: &str) -> bool {
        if Self::is_bash_tool(tool_name) {
            return matches!(self.bash_mode, BashMode::Deny);
        }
        false
    }

    /// Returns `true` if the tool call requires interactive approval before dispatch.
    pub fn requires_approval(&self, tool_name: &str, input: &serde_json::Value) -> bool {
        if !Self::is_bash_tool(tool_name) {
            return false;
        }

        match &self.bash_mode {
            BashMode::Ask => true,
            BashMode::Allowlist { patterns } => {
                // Extract the command from the input
                let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");

                // If the command matches any allowlist pattern, no approval needed
                !patterns.iter().any(|p| Self::pattern_matches(p, cmd))
            }
            BashMode::Deny => false, // handled by is_denied
        }
    }

    fn is_bash_tool(name: &str) -> bool {
        // Support both legacy dotted names and current underscore names.
        name == "bash.exec" || name == "bash_exec" || name == "bash" || name.ends_with("_bash_exec")
    }

    /// Simple pattern matching: supports prefix-glob (e.g. "ls *" matches "ls -la /tmp").
    fn pattern_matches(pattern: &str, command: &str) -> bool {
        let pattern = pattern.trim();
        let command = command.trim();

        if let Some(prefix) = pattern.strip_suffix('*') {
            command.starts_with(prefix)
        } else {
            // Exact match for non-wildcard patterns.
            command == pattern
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_handler_auto_approves() {
        let handler = NoopApprovalHandler;
        let req = ApprovalRequest {
            tool_name: "bash.exec".into(),
            tool_input: serde_json::json!({"command": "rm -rf /"}),
            session_id: encmind_core::types::SessionId::new(),
            agent_id: encmind_core::types::AgentId::default(),
        };
        let decision = handler.request_approval(req).await;
        assert_eq!(decision, ApprovalDecision::Approved);
    }

    #[test]
    fn deny_mode_blocks_bash() {
        let checker = ToolApprovalChecker::new(BashMode::Deny);
        assert!(checker.is_denied("bash.exec"));
        assert!(checker.is_denied("bash_exec"));
        assert!(checker.is_denied("bash"));
        assert!(checker.is_denied("node_bash_exec"));
        assert!(checker.is_denied("local_bash_exec"));
        assert!(!checker.is_denied("web_search"));
    }

    #[test]
    fn ask_mode_requires_approval_for_bash() {
        let checker = ToolApprovalChecker::new(BashMode::Ask);
        assert!(!checker.is_denied("bash.exec"));
        assert!(checker.requires_approval("bash.exec", &serde_json::json!({"command": "ls"})));
        assert!(!checker.is_denied("bash_exec"));
        assert!(checker.requires_approval("bash_exec", &serde_json::json!({"command": "ls"})));
        // Non-bash tools don't require approval
        assert!(!checker.requires_approval("web_search", &serde_json::json!({"query": "test"})));
    }

    #[test]
    fn allowlist_skips_approval_for_matching_pattern() {
        let checker = ToolApprovalChecker::new(BashMode::Allowlist {
            patterns: vec!["ls*".into(), "cat*".into()],
        });
        assert!(
            !checker.requires_approval("bash.exec", &serde_json::json!({"command": "ls -la /tmp"}))
        );
        assert!(!checker.requires_approval(
            "bash.exec",
            &serde_json::json!({"command": "cat /etc/hosts"})
        ));
        // Non-matching command requires approval
        assert!(checker.requires_approval("bash.exec", &serde_json::json!({"command": "rm -rf /"})));
    }

    #[test]
    fn exact_allowlist_pattern_does_not_overmatch() {
        let checker = ToolApprovalChecker::new(BashMode::Allowlist {
            patterns: vec!["git status".into()],
        });

        assert!(
            !checker.requires_approval("bash.exec", &serde_json::json!({"command": "git status"}))
        );
        assert!(checker.requires_approval("bash.exec", &serde_json::json!({"command": "git push"})));
    }

    #[test]
    fn space_sensitive_wildcard_pattern_does_not_match_other_commands() {
        let checker = ToolApprovalChecker::new(BashMode::Allowlist {
            patterns: vec!["ls *".into()],
        });

        assert!(
            !checker.requires_approval("bash.exec", &serde_json::json!({"command": "ls -la /tmp"}))
        );
        assert!(checker.requires_approval("bash.exec", &serde_json::json!({"command": "lsof -i"})));
    }

    #[test]
    fn non_bash_tools_never_denied_or_need_approval() {
        let checker = ToolApprovalChecker::new(BashMode::Deny);
        assert!(!checker.is_denied("echo"));
        assert!(!checker.requires_approval("echo", &serde_json::json!({})));
    }
}
