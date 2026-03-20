use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use encmind_core::config::{AppConfig, BashMode, LocalToolsBashMode, LocalToolsMode};
use encmind_core::types::AgentId;
use encmind_edge_lib::commands::LocalPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalToolPolicyStatus {
    pub mode: LocalToolsMode,
    pub bash_mode: LocalToolsBashMode,
    pub bash_effective_enabled: bool,
    pub scoped_agent_workspaces: usize,
    pub distinct_workspaces: usize,
}

/// Immutable snapshot of local tool policy derived from config.
#[derive(Debug, Clone)]
pub struct LocalToolPolicyEngine {
    base_policy: LocalPolicy,
    mode: LocalToolsMode,
    bash_mode: LocalToolsBashMode,
    agent_workspaces: HashMap<String, PathBuf>,
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

    let bash_effective_enabled = !matches!(config.security.bash_mode, BashMode::Deny)
        && !matches!(
            config.security.local_tools.bash_mode,
            LocalToolsBashMode::Disabled
        )
        && !matches!(
            config.security.local_tools.mode,
            LocalToolsMode::IsolatedAgents
        );

    LocalToolPolicyStatus {
        mode: config.security.local_tools.mode.clone(),
        bash_mode: config.security.local_tools.bash_mode.clone(),
        bash_effective_enabled,
        scoped_agent_workspaces,
        distinct_workspaces: distinct.len(),
    }
}

impl LocalToolPolicyEngine {
    pub fn from_config(config: &AppConfig) -> Self {
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

        if matches!(config.security.bash_mode, BashMode::Deny)
            || matches!(
                config.security.local_tools.bash_mode,
                LocalToolsBashMode::Disabled
            )
            || matches!(
                config.security.local_tools.mode,
                LocalToolsMode::IsolatedAgents
            )
        {
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
            agent_workspaces,
        }
    }

    pub fn effective_policy(&self, agent_id: &AgentId) -> LocalPolicy {
        let mut policy = self.base_policy.clone();
        if let Some(workspace) = self.agent_workspaces.get(agent_id.as_str()) {
            policy.allowed_roots.push(workspace.clone());
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
        }
    }

    pub fn bash_effective_enabled(&self) -> bool {
        self.base_policy.allow_bash_exec
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
