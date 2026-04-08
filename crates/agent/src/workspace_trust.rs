//! Workspace trust gate — restricts tool availability based on whether the
//! session's workspace path is in the trusted set.
//!
//! Untrusted workspaces only get built-in read-only tools. Plugin tools,
//! skill tools, MCP tools, and bash are blocked.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use encmind_core::config::WorkspaceTrustConfig;
use tracing::{debug, warn};

static EMPTY_TRUSTED_PATHS_WARNED: OnceLock<()> = OnceLock::new();

/// The trust decision for a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTrustLevel {
    /// Workspace is trusted — all tools available.
    Trusted,
    /// Workspace is untrusted — only read-only core tools allowed.
    ReadOnly,
    /// Workspace is untrusted and deny mode is active — all tools blocked.
    Denied,
    /// Trust gate is disabled — all tools available regardless of workspace.
    Disabled,
}

/// Built-in read-only tool names that are always allowed in untrusted mode.
/// These are the core tools that don't make network calls, execute processes,
/// or modify state.
const UNTRUSTED_ALLOWED_TOOLS: &[&str] = &[
    "file_read",
    "file_list",
    "local_file_read",
    "local_file_list",
];

/// Evaluate trust level for a workspace path.
pub fn evaluate_trust(
    workspace: Option<&Path>,
    config: &WorkspaceTrustConfig,
) -> WorkspaceTrustLevel {
    let action = config.untrusted_default.trim().to_ascii_lowercase();

    // If trust gate is disabled, everything is allowed.
    if action == "allow" {
        return WorkspaceTrustLevel::Disabled;
    }

    // If no workspace is set (e.g., channel-based session), apply explicit
    // no-workspace policy.
    let Some(workspace) = workspace else {
        return match config
            .no_workspace_default
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "readonly" => WorkspaceTrustLevel::ReadOnly,
            "deny" => WorkspaceTrustLevel::Denied,
            _ => WorkspaceTrustLevel::Trusted,
        };
    };

    // If no trusted_paths configured, treat as trusted (backward compat:
    // existing deployments without trust config should not break).
    if config.trusted_paths.is_empty() {
        if action != "allow" && EMPTY_TRUSTED_PATHS_WARNED.get().is_none() {
            warn!(
                action = %action,
                "workspace_trust.trusted_paths is empty; trust gate is effectively disabled for backward compatibility"
            );
            let _ = EMPTY_TRUSTED_PATHS_WARNED.set(());
        }
        return WorkspaceTrustLevel::Trusted;
    }

    let normalized_workspace = normalize_path(workspace);

    // Check if workspace is under any trusted path.
    for trusted in &config.trusted_paths {
        let normalized_trusted = normalize_path(trusted);
        if normalized_workspace.starts_with(&normalized_trusted) {
            return WorkspaceTrustLevel::Trusted;
        }
    }

    // Workspace is not in trusted set.
    debug!(
        workspace = %normalized_workspace.display(),
        action = %action,
        "workspace not in trusted_paths — applying trust restriction"
    );

    match action.as_str() {
        "deny" => WorkspaceTrustLevel::Denied,
        _ => WorkspaceTrustLevel::ReadOnly, // "readonly" or any unrecognized value
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };

    match absolute.canonicalize() {
        Ok(canon) => canon,
        Err(_) => lexical_normalize(&absolute),
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    use std::ffi::OsString;

    let mut prefix: Option<OsString> = None;
    let mut has_root = false;
    let mut parts: Vec<OsString> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_os_string()),
            Component::RootDir => {
                has_root = true;
                parts.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() && !has_root {
                    parts.push(OsString::from(".."));
                }
            }
            Component::Normal(seg) => parts.push(seg.to_os_string()),
        }
    }

    let mut out = PathBuf::new();
    if let Some(p) = prefix {
        out.push(p);
    }
    if has_root {
        out.push(std::path::MAIN_SEPARATOR.to_string());
    }
    for part in parts {
        out.push(part);
    }
    out
}

/// Check if a tool is allowed under the given trust level.
pub fn is_tool_allowed(tool_name: &str, trust_level: WorkspaceTrustLevel) -> bool {
    match trust_level {
        WorkspaceTrustLevel::Trusted | WorkspaceTrustLevel::Disabled => true,
        WorkspaceTrustLevel::Denied => false,
        WorkspaceTrustLevel::ReadOnly => UNTRUSTED_ALLOWED_TOOLS.contains(&tool_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config_with_trusted(paths: Vec<&str>, action: &str) -> WorkspaceTrustConfig {
        WorkspaceTrustConfig {
            trusted_paths: paths.into_iter().map(PathBuf::from).collect(),
            untrusted_default: action.to_string(),
            no_workspace_default: "trusted".to_string(),
        }
    }

    #[test]
    fn trusted_workspace_allows_all_tools() {
        let config = config_with_trusted(vec!["/home/user/projects"], "readonly");
        let level = evaluate_trust(Some(Path::new("/home/user/projects/myapp")), &config);
        assert_eq!(level, WorkspaceTrustLevel::Trusted);
        assert!(is_tool_allowed("bash.exec", level));
        assert!(is_tool_allowed("digest_summarize", level));
    }

    #[test]
    fn untrusted_workspace_readonly_blocks_plugins() {
        let config = config_with_trusted(vec!["/home/user/projects"], "readonly");
        let level = evaluate_trust(Some(Path::new("/tmp/untrusted")), &config);
        assert_eq!(level, WorkspaceTrustLevel::ReadOnly);
        assert!(is_tool_allowed("file_read", level));
        assert!(is_tool_allowed("file_list", level));
        assert!(!is_tool_allowed("bash.exec", level));
        assert!(!is_tool_allowed("node_file_read", level));
        assert!(!is_tool_allowed("digest_summarize", level));
        assert!(!is_tool_allowed("netprobe_search", level));
    }

    #[test]
    fn untrusted_workspace_deny_blocks_all() {
        let config = config_with_trusted(vec!["/home/user/projects"], "deny");
        let level = evaluate_trust(Some(Path::new("/tmp/untrusted")), &config);
        assert_eq!(level, WorkspaceTrustLevel::Denied);
        assert!(!is_tool_allowed("file_read", level));
        assert!(!is_tool_allowed("bash.exec", level));
    }

    #[test]
    fn disabled_trust_gate_allows_everything() {
        let config = config_with_trusted(vec!["/home/user/projects"], "allow");
        let level = evaluate_trust(Some(Path::new("/tmp/untrusted")), &config);
        assert_eq!(level, WorkspaceTrustLevel::Disabled);
        assert!(is_tool_allowed("bash.exec", level));
    }

    #[test]
    fn no_workspace_is_trusted() {
        let config = config_with_trusted(vec!["/home/user/projects"], "readonly");
        let level = evaluate_trust(None, &config);
        assert_eq!(level, WorkspaceTrustLevel::Trusted);
    }

    #[test]
    fn no_workspace_can_be_forced_readonly() {
        let mut config = config_with_trusted(vec!["/home/user/projects"], "readonly");
        config.no_workspace_default = "readonly".to_string();
        let level = evaluate_trust(None, &config);
        assert_eq!(level, WorkspaceTrustLevel::ReadOnly);
    }

    #[test]
    fn no_workspace_can_be_forced_deny() {
        let mut config = config_with_trusted(vec!["/home/user/projects"], "readonly");
        config.no_workspace_default = "deny".to_string();
        let level = evaluate_trust(None, &config);
        assert_eq!(level, WorkspaceTrustLevel::Denied);
    }

    #[test]
    fn empty_trusted_paths_is_trusted_for_backward_compat() {
        let config = config_with_trusted(vec![], "readonly");
        let level = evaluate_trust(Some(Path::new("/anywhere")), &config);
        assert_eq!(level, WorkspaceTrustLevel::Trusted);
    }

    #[test]
    fn nested_path_matches_trusted_parent() {
        let config = config_with_trusted(vec!["/home/user"], "readonly");
        let level = evaluate_trust(Some(Path::new("/home/user/projects/deep/nested")), &config);
        assert_eq!(level, WorkspaceTrustLevel::Trusted);
    }

    #[test]
    fn lexical_normalization_allows_relative_workspace_under_trusted_parent() {
        let current = std::env::current_dir().expect("cwd");
        let trusted = current.join("tmp-trusted");
        let relative_workspace = Path::new("tmp-trusted/project/../project/sub");
        let config = WorkspaceTrustConfig {
            trusted_paths: vec![trusted],
            untrusted_default: "readonly".to_string(),
            no_workspace_default: "trusted".to_string(),
        };

        let level = evaluate_trust(Some(relative_workspace), &config);
        assert_eq!(level, WorkspaceTrustLevel::Trusted);
    }
}
