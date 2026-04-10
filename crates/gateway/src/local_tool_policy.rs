use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use encmind_core::config::{
    AppConfig, BashMode, LocalToolsBashMode, LocalToolsMode, WorkspaceTrustConfig,
};
use encmind_core::types::AgentId;
use encmind_edge_lib::commands::LocalPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalToolPolicyStatus {
    pub mode: LocalToolsMode,
    pub bash_mode: LocalToolsBashMode,
    pub bash_effective_enabled: bool,
    pub scoped_agent_workspaces: usize,
    pub distinct_workspaces: usize,
    /// Number of operator-configured deny entries merged on top of the
    /// hardcoded default deny list.
    pub operator_denied_paths: usize,
}

/// Immutable snapshot of local tool policy derived from config.
#[derive(Debug, Clone)]
pub struct LocalToolPolicyEngine {
    base_policy: LocalPolicy,
    mode: LocalToolsMode,
    bash_mode: LocalToolsBashMode,
    security_bash_mode: BashMode,
    workspace_trust: WorkspaceTrustConfig,
    agent_workspaces: HashMap<String, PathBuf>,
    operator_denied_paths: usize,
}

/// Build a lightweight readiness snapshot from current config without creating a
/// full policy engine.
pub fn status_from_config(config: &AppConfig) -> LocalToolPolicyStatus {
    let cwd = std::env::current_dir().ok();
    let mut distinct = HashSet::new();
    let mut scoped_agent_workspaces = 0usize;

    for agent in &config.agents.list {
        if let Some(workspace) = &agent.workspace {
            if workspace.as_os_str().is_empty() {
                continue;
            }
            scoped_agent_workspaces += 1;
            distinct.insert(normalize_path_for_status(workspace, cwd.as_deref()));
        }
    }

    let bash_effective_enabled = config.security.local_bash_effectively_enabled();

    LocalToolPolicyStatus {
        mode: config.security.local_tools.mode.clone(),
        bash_mode: config.security.local_tools.bash_mode.clone(),
        bash_effective_enabled,
        scoped_agent_workspaces,
        distinct_workspaces: distinct.len(),
        operator_denied_paths: config.security.local_tools.denied_paths.len(),
    }
}

impl LocalToolPolicyEngine {
    pub fn from_config(config: &AppConfig) -> Self {
        // LocalPolicy::default() seeds the hardcoded default denylist
        // (/etc/shadow, ~/.ssh, ~/.gnupg, ~/.encmind, etc.). We layer
        // operator entries on top — the defaults are a floor, operators
        // can only add, never remove.
        let mut base_policy = LocalPolicy::default();
        let mut roots = Vec::new();

        if let Ok(cwd) = std::env::current_dir() {
            roots.push(cwd);
        }
        if let Some(parent) = config.storage.db_path.parent() {
            roots.push(parent.to_path_buf());
        }
        roots.push(std::env::temp_dir());
        for root in &config.security.local_tools.base_roots {
            roots.push(normalize_path(root));
        }
        roots.sort();
        roots.dedup();
        base_policy.allowed_roots = roots;

        // Merge operator-configured denied paths with the defaults.
        // Entries are normalized so equivalent representations dedup.
        for extra in &config.security.local_tools.denied_paths {
            base_policy.denied_paths.push(normalize_path(extra));
        }
        base_policy.denied_paths.sort();
        base_policy.denied_paths.dedup();

        if !config.security.local_bash_effectively_enabled() {
            base_policy.allow_bash_exec = false;
        }

        let mut agent_workspaces = HashMap::new();
        for agent in &config.agents.list {
            if let Some(workspace) = &agent.workspace {
                if !workspace.as_os_str().is_empty() {
                    agent_workspaces.insert(agent.id.clone(), normalize_path(workspace));
                }
            }
        }

        Self {
            base_policy,
            mode: config.security.local_tools.mode.clone(),
            bash_mode: config.security.local_tools.bash_mode.clone(),
            security_bash_mode: config.security.bash_mode.clone(),
            workspace_trust: config.security.workspace_trust.clone(),
            agent_workspaces,
            operator_denied_paths: config.security.local_tools.denied_paths.len(),
        }
    }

    pub fn effective_policy(&self, agent_id: &AgentId) -> LocalPolicy {
        self.effective_policy_for_workspace(self.agent_workspace(agent_id))
    }

    /// Build an effective local policy for a resolved workspace path.
    /// This is used by handlers that resolve workspace dynamically from the
    /// live agent registry at dispatch time.
    pub fn effective_policy_for_workspace(&self, workspace: Option<&Path>) -> LocalPolicy {
        let mut policy = self.base_policy.clone();
        if let Some(workspace) = workspace {
            policy.allowed_roots.push(workspace.to_path_buf());
            policy.allowed_roots.sort();
            policy.allowed_roots.dedup();
        }
        policy
    }

    pub fn status(&self) -> LocalToolPolicyStatus {
        let distinct_workspaces = self
            .agent_workspaces
            .values()
            .cloned()
            .collect::<HashSet<_>>()
            .len();

        LocalToolPolicyStatus {
            mode: self.mode.clone(),
            bash_mode: self.bash_mode.clone(),
            bash_effective_enabled: self.base_policy.allow_bash_exec,
            scoped_agent_workspaces: self.agent_workspaces.len(),
            distinct_workspaces,
            operator_denied_paths: self.operator_denied_paths,
        }
    }

    pub fn bash_effective_enabled(&self) -> bool {
        self.base_policy.allow_bash_exec
    }

    /// Look up an agent's configured workspace, if any. Returned path
    /// is already normalized (absolute + lexical resolve of `..`).
    pub fn agent_workspace(&self, agent_id: &AgentId) -> Option<&Path> {
        self.agent_workspaces
            .get(agent_id.as_str())
            .map(PathBuf::as_path)
    }

    /// Read-only view of the gateway's workspace trust configuration.
    /// Used by the local tool handler to evaluate trust per call.
    pub fn workspace_trust(&self) -> &WorkspaceTrustConfig {
        &self.workspace_trust
    }

    /// Read-only view of the operator-configured `BashMode`. The local
    /// tool handler uses this to enforce `BashMode::Allowlist` patterns
    /// directly at dispatch time (defense in depth vs. governance).
    pub fn security_bash_mode(&self) -> &BashMode {
        &self.security_bash_mode
    }
}

/// Lightweight per-call projection of the local policy for a single
/// workspace, without iterating every agent in the config.
///
/// Used on the hot path of `LocalToolHandler::handle` when a shared
/// live config is attached, so that operator config changes take effect
/// on the very next call without rebuilding the full
/// `LocalToolPolicyEngine` (which canonicalizes every agent's
/// workspace). Same semantics as
/// `LocalToolPolicyEngine::from_config(cfg).effective_policy_for_workspace(workspace)`,
/// but skips the per-agent canonicalization loop.
pub fn derive_call_policy_from_config(config: &AppConfig, workspace: Option<&Path>) -> LocalPolicy {
    let mut base_policy = LocalPolicy::default();

    let mut roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }
    if let Some(parent) = config.storage.db_path.parent() {
        roots.push(parent.to_path_buf());
    }
    roots.push(std::env::temp_dir());
    for root in &config.security.local_tools.base_roots {
        roots.push(normalize_path(root));
    }
    if let Some(ws) = workspace {
        roots.push(ws.to_path_buf());
    }
    roots.sort();
    roots.dedup();
    base_policy.allowed_roots = roots;

    // Layer operator-configured denied paths on top of the hardcoded
    // defaults seeded by `LocalPolicy::default()`.
    for extra in &config.security.local_tools.denied_paths {
        base_policy.denied_paths.push(normalize_path(extra));
    }
    base_policy.denied_paths.sort();
    base_policy.denied_paths.dedup();

    if !config.security.local_bash_effectively_enabled() {
        base_policy.allow_bash_exec = false;
    }

    base_policy
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

fn normalize_path_for_status(path: &Path, cwd: Option<&Path>) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(base) = cwd {
        base.join(path)
    } else {
        path.to_path_buf()
    };
    lexical_normalize(&absolute)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::path::Component;

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

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_core::config::{AgentConfigEntry, AppConfig, SubagentRuntimeConfig};

    #[test]
    fn isolated_mode_forces_bash_disabled() {
        let mut cfg = AppConfig::default();
        cfg.security.local_tools.mode = LocalToolsMode::IsolatedAgents;
        cfg.security.local_tools.bash_mode = LocalToolsBashMode::Host;

        let engine = LocalToolPolicyEngine::from_config(&cfg);
        assert!(!engine.status().bash_effective_enabled);
    }

    #[test]
    fn effective_policy_adds_current_agent_workspace_only() {
        let mut cfg = AppConfig::default();
        cfg.agents.list = vec![
            AgentConfigEntry {
                id: "a".into(),
                name: "A".into(),
                model: None,
                workspace: Some(PathBuf::from("/tmp/a")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
            AgentConfigEntry {
                id: "b".into(),
                name: "B".into(),
                model: None,
                workspace: Some(PathBuf::from("/tmp/b")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];

        let engine = LocalToolPolicyEngine::from_config(&cfg);
        let pa = engine.effective_policy(&AgentId::new("a"));
        let pb = engine.effective_policy(&AgentId::new("b"));

        assert!(pa.allowed_roots.iter().any(|p| p.ends_with("a")));
        assert!(!pa.allowed_roots.iter().any(|p| p.ends_with("b")));
        assert!(pb.allowed_roots.iter().any(|p| p.ends_with("b")));
    }

    #[test]
    fn status_from_config_matches_bash_disable_rules() {
        let mut cfg = AppConfig::default();
        cfg.security.local_tools.mode = LocalToolsMode::IsolatedAgents;
        let status = status_from_config(&cfg);
        assert!(!status.bash_effective_enabled);
        assert_eq!(status.mode, LocalToolsMode::IsolatedAgents);
    }

    #[test]
    fn status_from_config_counts_distinct_workspaces_lexically() {
        let mut cfg = AppConfig::default();
        cfg.agents.list = vec![
            AgentConfigEntry {
                id: "a".into(),
                name: "A".into(),
                model: None,
                workspace: Some(PathBuf::from("/tmp/ws")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
            AgentConfigEntry {
                id: "b".into(),
                name: "B".into(),
                model: None,
                workspace: Some(PathBuf::from("/tmp/../tmp/ws")),
                system_prompt: None,
                skills: Vec::new(),
                subagents: SubagentRuntimeConfig::default(),
                is_default: false,
            },
        ];
        let status = status_from_config(&cfg);
        assert_eq!(status.scoped_agent_workspaces, 2);
        assert_eq!(status.distinct_workspaces, 1);
    }
}
