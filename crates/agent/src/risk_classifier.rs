//! Speculative risk classifier for tool calls.
//!
//! Runs BEFORE hooks and permission checks as a pre-filter. Flags obviously
//! dangerous operations for extra scrutiny even in bypass mode. This is the
//! runtime enforcement point for the immutable deny-list.

use encmind_core::types::SessionId;
use tracing::warn;

/// Risk level assigned to a tool call by the classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRiskLevel {
    /// Safe read-only operation.
    Low,
    /// Potentially impactful but recoverable.
    Sensitive,
    /// Destructive or irreversible — requires extra scrutiny.
    Critical,
    /// Immutable deny-list match — blocked unconditionally.
    Denied,
}

/// Result of risk classification.
#[derive(Debug)]
pub struct RiskClassification {
    pub level: ToolRiskLevel,
    /// Human-readable reason (for logging and permission explainer).
    pub reason: &'static str,
}

/// Destructive shell patterns that match the immutable deny-list.
/// These are blocked even in bypass mode. Patterns are matched against
/// the lowercased, whitespace-normalized command.
const BASH_DENY_PATTERNS: &[(&str, &str)] = &[
    ("rm -rf /", "recursive delete from root"),
    ("rm -rf /*", "recursive delete from root"),
    ("rm -rf ~", "recursive delete of home directory"),
    ("rm -r /", "recursive delete from root"),
    ("rm -r /*", "recursive delete from root"),
    (":(){:|:&};:", "fork bomb"),
];

/// Credential path patterns for file write deny-list.
/// Matched against normalized path (lowercase, forward slashes).
/// Both absolute (/.ssh/) and relative (.ssh/) forms are checked.
const CREDENTIAL_PATHS: &[&str] = &[
    "/.ssh/",
    ".ssh/",
    "/.gnupg/",
    ".gnupg/",
    "/.env",
    ".env",
    "/credentials.json",
    "credentials.json",
    "/secrets.",
    "secrets.",
    "/.aws/credentials",
    ".aws/credentials",
];

/// Classify the risk level of a tool call.
///
/// This runs before hooks and permissions as a fast pre-filter.
/// `Denied` results are blocked unconditionally (immutable deny-list).
pub fn classify_tool_risk(
    tool_name: &str,
    input: &serde_json::Value,
    _session_id: &SessionId,
) -> RiskClassification {
    match tool_name {
        name if is_bash_tool(name) => classify_bash_risk(input),
        name if is_file_write_tool(name) => classify_file_write_risk(input),
        _ => RiskClassification {
            level: ToolRiskLevel::Low,
            reason: "non-destructive tool",
        },
    }
}

/// Match bash/shell tools including prefixed variants (node_bash_exec, local_bash_exec, etc.)
/// Kept in sync with ToolApprovalChecker::is_bash_tool().
fn is_bash_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("bash_exec")
        || lower.ends_with("bash.exec")
        || lower == "bash"
        || lower == "shell"
        || lower.ends_with("execute_command")
}

/// Match file write/edit tools including prefixed variants.
fn is_file_write_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("file_write")
        || lower.ends_with("file.write")
        || lower.ends_with("file_edit")
        || lower.ends_with("file.edit")
}

fn classify_bash_risk(input: &serde_json::Value) -> RiskClassification {
    let command = input.get("command").and_then(|v| v.as_str()).unwrap_or("");

    // Normalize: lowercase, collapse whitespace for consistent matching.
    let lower: String = command
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    // Immutable deny-list: blocked unconditionally.
    for (pattern, reason) in BASH_DENY_PATTERNS {
        if lower.contains(pattern) {
            warn!(
                command = %command,
                pattern = %pattern,
                "bash command blocked by immutable deny-list"
            );
            return RiskClassification {
                level: ToolRiskLevel::Denied,
                reason,
            };
        }
    }

    // Word-boundary checks for commands that can appear as substrings.
    // "mkfs" as a standalone command or with flags (mkfs -t ext4, mkfs.ext4).
    if lower.split_whitespace().any(|w| w.starts_with("mkfs")) {
        return RiskClassification {
            level: ToolRiskLevel::Denied,
            reason: "filesystem format",
        };
    }
    // "dd" with if= (raw disk write). Must be a standalone word, not part of "add".
    if lower.split_whitespace().any(|w| w == "dd") && lower.contains("if=") {
        return RiskClassification {
            level: ToolRiskLevel::Denied,
            reason: "raw disk write",
        };
    }

    // Critical patterns (not denied, but flagged).
    if lower.contains("drop table")
        || lower.contains("drop database")
        || lower.contains("truncate table")
    {
        return RiskClassification {
            level: ToolRiskLevel::Critical,
            reason: "destructive database operation",
        };
    }

    if lower.contains("rm -rf") || lower.contains("rm -r") {
        return RiskClassification {
            level: ToolRiskLevel::Critical,
            reason: "recursive file deletion",
        };
    }

    if lower.contains("chmod 777") || lower.contains("chmod -R") {
        return RiskClassification {
            level: ToolRiskLevel::Sensitive,
            reason: "permission modification",
        };
    }

    // Default for bash: Sensitive (it can do anything).
    RiskClassification {
        level: ToolRiskLevel::Sensitive,
        reason: "shell command execution",
    }
}

fn classify_file_write_risk(input: &serde_json::Value) -> RiskClassification {
    let path = input.get("path").and_then(|v| v.as_str()).unwrap_or("");

    // Normalize: lowercase + forward slashes for cross-platform matching.
    let normalized = path.to_lowercase().replace('\\', "/");

    for pattern in CREDENTIAL_PATHS {
        if normalized.contains(pattern) {
            return RiskClassification {
                level: ToolRiskLevel::Denied,
                reason: "write to credential path",
            };
        }
    }

    RiskClassification {
        level: ToolRiskLevel::Sensitive,
        reason: "file write operation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> SessionId {
        SessionId::new()
    }

    #[test]
    fn denies_rm_rf_root() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "rm -rf /"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn denies_credential_file_write() {
        let result = classify_tool_risk(
            "file.write",
            &serde_json::json!({"path": "/home/user/.ssh/id_rsa", "content": "key"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn flags_drop_table_as_critical() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "psql -c 'DROP TABLE users'"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Critical);
    }

    #[test]
    fn flags_rm_rf_as_critical() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "rm -rf ./build"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Critical);
    }

    #[test]
    fn normal_bash_is_sensitive() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "ls -la"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Sensitive);
    }

    #[test]
    fn normal_file_write_is_sensitive() {
        let result = classify_tool_risk(
            "file.write",
            &serde_json::json!({"path": "/home/user/project/main.rs", "content": "fn main() {}"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Sensitive);
    }

    #[test]
    fn read_only_tool_is_low() {
        let result = classify_tool_risk(
            "file.read",
            &serde_json::json!({"path": "/etc/hosts"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Low);
    }

    #[test]
    fn prefixed_node_bash_exec_is_classified() {
        let result = classify_tool_risk(
            "node_bash_exec",
            &serde_json::json!({"command": "rm -rf /"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn prefixed_local_file_write_is_classified() {
        let result = classify_tool_risk(
            "local_file_write",
            &serde_json::json!({"path": "/home/user/.ssh/id_rsa", "content": "key"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn windows_path_credential_write_denied() {
        let result = classify_tool_risk(
            "file.write",
            &serde_json::json!({"path": "C:\\Users\\me\\.ssh\\id_rsa", "content": "key"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn mkfs_with_flags_denied() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "mkfs -t ext4 /dev/sda1"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn mkfs_dot_variant_denied() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "mkfs.ext4 /dev/sda1"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn dd_raw_disk_denied() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "dd if=/dev/zero of=/dev/sda bs=1M"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn dd_without_if_not_denied() {
        // "dd" without "if=" could be an innocent command.
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "dd status=progress of=output.img"}),
            &sid(),
        );
        // No "if=" present, so not denied.
        assert_ne!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn whitespace_variant_still_denied() {
        let result = classify_tool_risk(
            "bash.exec",
            &serde_json::json!({"command": "rm   -rf    /"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn env_file_write_denied() {
        let result = classify_tool_risk(
            "file.write",
            &serde_json::json!({"path": "/app/.env", "content": "SECRET=abc"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn relative_env_file_denied() {
        let result = classify_tool_risk(
            "file.write",
            &serde_json::json!({"path": ".env", "content": "SECRET=abc"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }

    #[test]
    fn relative_ssh_dir_denied() {
        let result = classify_tool_risk(
            "file.write",
            &serde_json::json!({"path": ".ssh/authorized_keys", "content": "key"}),
            &sid(),
        );
        assert_eq!(result.level, ToolRiskLevel::Denied);
    }
}
