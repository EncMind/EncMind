use async_trait::async_trait;

use encmind_core::bash_allowlist;
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
    /// Whether bash execution is effectively enabled for **local** tools
    /// running on the gateway host. Setting this to `false` hides/denies
    /// only local bash tools (e.g. `bash_exec`, `local_bash_exec`) — it
    /// does **not** apply to remote/node bash tools (`node_bash_exec`),
    /// which live under a separate security domain and are gated only
    /// by `bash_mode`.
    local_bash_effectively_enabled: bool,
    /// Whether this runtime can actually present interactive approval
    /// prompts. When false, `bash_mode=ask` cannot be satisfied and is
    /// treated as a categorical denial for bash-family tools so they are
    /// filtered from prompt-visible tools and denied pre-dispatch.
    interactive_approval_available: bool,
}

impl ToolApprovalChecker {
    pub fn new(bash_mode: BashMode) -> Self {
        Self {
            bash_mode,
            local_bash_effectively_enabled: true,
            interactive_approval_available: true,
        }
    }

    /// Same as `new`, but allows callers to disable local bash-family
    /// tools (not node bash) based on additional runtime policy
    /// (`local_tools.bash_mode`, `local_tools.mode`).
    pub fn with_bash_effective_mode(
        bash_mode: BashMode,
        local_bash_effectively_enabled: bool,
    ) -> Self {
        Self {
            bash_mode,
            local_bash_effectively_enabled,
            interactive_approval_available: true,
        }
    }

    /// Mark whether interactive approval prompts are available in this
    /// runtime.
    pub fn with_interactive_approval_available(mut self, available: bool) -> Self {
        self.interactive_approval_available = available;
        self
    }

    /// Expose current interactive-approval capability so nested runtimes
    /// (subagents) can preserve parent behavior when rehydrating checker
    /// state from live config snapshots.
    pub fn interactive_approval_available(&self) -> bool {
        self.interactive_approval_available
    }

    /// Returns `true` if the tool is categorically denied.
    ///
    /// Policy layering:
    /// - `bash_mode = Deny` — master switch; denies every bash tool
    ///   including remote (`node_bash_exec`).
    /// - `local_bash_effectively_enabled = false` — denies only local
    ///   bash tools (`bash_exec`, `local_bash_exec`, bare `bash`, …).
    ///   Node bash remains visible and callable under this setting.
    pub fn is_denied(&self, tool_name: &str) -> bool {
        if !Self::is_bash_tool(tool_name) {
            return false;
        }
        if matches!(self.bash_mode, BashMode::Deny) {
            return true;
        }
        if !self.local_bash_effectively_enabled && Self::is_local_bash_tool(tool_name) {
            return true;
        }
        if !self.interactive_approval_available && matches!(self.bash_mode, BashMode::Ask) {
            return true;
        }
        false
    }

    /// Returns `true` if the tool call requires interactive approval before dispatch.
    pub fn requires_approval(&self, tool_name: &str, input: &serde_json::Value) -> bool {
        if self.is_denied(tool_name) {
            return false;
        }
        if !Self::is_bash_tool(tool_name) {
            return false;
        }

        match &self.bash_mode {
            BashMode::Ask => true,
            BashMode::Allowlist { patterns } => {
                // Extract the command from the input
                let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");

                // If the command matches any allowlist pattern, no approval needed
                !bash_allowlist::matches_any(patterns, cmd)
            }
            BashMode::Deny => false, // handled by is_denied
        }
    }

    fn is_bash_tool(name: &str) -> bool {
        // Match bash/shell tools including prefixed variants (node_bash_exec, local_bash_exec).
        // Kept in sync with risk_classifier::is_bash_tool().
        let lower = name.to_ascii_lowercase();
        lower.ends_with("bash_exec")
            || lower.ends_with("bash.exec")
            || lower == "bash"
            || lower == "shell"
            || lower.ends_with("execute_command")
    }

    /// Bash tools that run on the gateway host itself — as opposed to
    /// `node_*` variants which execute on a paired remote device under a
    /// separate security domain. The local-tools policy flag only
    /// scopes tools returned by this predicate.
    fn is_local_bash_tool(name: &str) -> bool {
        if !Self::is_bash_tool(name) {
            return false;
        }
        let lower = name.to_ascii_lowercase();
        // Keep this narrow and explicit to avoid leaking local-only
        // policy onto unrelated prefixed tools.
        matches!(
            lower.as_str(),
            "bash_exec" | "bash.exec" | "bash" | "shell" | "execute_command"
        ) || lower.starts_with("local_")
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
        // Boundary check: ls* should not match unrelated command prefix.
        assert!(checker.requires_approval("bash.exec", &serde_json::json!({"command": "lsblk"})));
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
        assert!(checker.requires_approval(
            "bash.exec",
            &serde_json::json!({"command": "ls -la; whoami"})
        ));
        assert!(checker.requires_approval(
            "bash.exec",
            &serde_json::json!({"command": "ls -la\nwhoami"})
        ));
    }

    #[test]
    fn non_bash_tools_never_denied_or_need_approval() {
        let checker = ToolApprovalChecker::new(BashMode::Deny);
        assert!(!checker.is_denied("echo"));
        assert!(!checker.requires_approval("echo", &serde_json::json!({})));
    }

    #[test]
    fn local_bash_effective_disabled_hides_local_bash_only() {
        // With bash_mode=Ask but local bash effectively disabled
        // (e.g. local_tools.mode=IsolatedAgents), the checker must
        // deny local bash tools AND leave node bash tools visible
        // because node bash lives in a separate security domain.
        let checker = ToolApprovalChecker::with_bash_effective_mode(BashMode::Ask, false);
        assert!(checker.is_denied("bash_exec"));
        assert!(checker.is_denied("local_bash_exec"));
        assert!(checker.is_denied("bash"));
        assert!(checker.is_denied("bash.exec"));
        // Node bash remains allowed — the local flag must not bleed.
        assert!(!checker.is_denied("node_bash_exec"));
        // Non-bash tools still unaffected.
        assert!(!checker.is_denied("file_read"));
        assert!(!checker.is_denied("web_search"));
    }

    #[test]
    fn bash_mode_deny_is_master_switch_over_node_bash_too() {
        // bash_mode=Deny must deny every bash tool, including node.
        let checker = ToolApprovalChecker::with_bash_effective_mode(BashMode::Deny, true);
        assert!(checker.is_denied("bash_exec"));
        assert!(checker.is_denied("local_bash_exec"));
        assert!(checker.is_denied("node_bash_exec"));
    }

    #[test]
    fn default_constructor_treats_all_bash_as_locally_enabled() {
        // `new()` defaults local_bash_effectively_enabled = true, so
        // under Ask/Allowlist modes nothing is categorically denied.
        let checker = ToolApprovalChecker::new(BashMode::Ask);
        assert!(!checker.is_denied("bash_exec"));
        assert!(!checker.is_denied("local_bash_exec"));
        assert!(!checker.is_denied("node_bash_exec"));
    }

    #[test]
    fn ask_mode_denies_bash_when_interactive_approval_is_unavailable() {
        let checker =
            ToolApprovalChecker::new(BashMode::Ask).with_interactive_approval_available(false);
        assert!(checker.is_denied("bash_exec"));
        assert!(checker.is_denied("node_bash_exec"));
        // Denied tools should not also request approval.
        assert!(!checker.requires_approval("bash_exec", &serde_json::json!({"command": "ls"})));
    }

    #[test]
    fn local_bash_scope_does_not_apply_to_unknown_prefixed_tools() {
        let checker = ToolApprovalChecker::with_bash_effective_mode(BashMode::Ask, false);
        assert!(!checker.is_denied("remote_bash_exec"));
    }
}
