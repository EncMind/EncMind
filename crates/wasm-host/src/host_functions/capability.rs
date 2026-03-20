use encmind_core::error::WasmHostError;
use encmind_core::traits::CapabilitySet;
use std::path::{Component, Path, PathBuf};

fn normalize_absolute_path(path: &str) -> Result<PathBuf, WasmHostError> {
    let input = Path::new(path);
    if !input.is_absolute() {
        return Err(WasmHostError::CapabilityDenied(format!(
            "path must be absolute: {path}"
        )));
    }

    let mut normalized = PathBuf::new();
    for component in input.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(WasmHostError::CapabilityDenied(format!(
                        "invalid path traversal: {path}"
                    )));
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    Ok(normalized)
}

/// Check whether outbound network access to a domain is allowed.
pub fn check_net_outbound(domain: &str, capabilities: &CapabilitySet) -> Result<(), WasmHostError> {
    if capabilities.net_outbound.is_empty() {
        return Err(WasmHostError::CapabilityDenied(format!(
            "net_outbound not granted for domain: {domain}"
        )));
    }

    let allowed = capabilities
        .net_outbound
        .iter()
        .any(|d| d == domain || d == "*");

    if !allowed {
        return Err(WasmHostError::CapabilityDenied(format!(
            "net_outbound denied for domain: {domain}"
        )));
    }

    Ok(())
}

/// Check whether reading a filesystem path is allowed.
pub fn check_fs_read(path: &str, capabilities: &CapabilitySet) -> Result<(), WasmHostError> {
    if capabilities.fs_read.is_empty() {
        return Err(WasmHostError::CapabilityDenied(format!(
            "fs_read not granted for path: {path}"
        )));
    }

    let normalized_path = normalize_absolute_path(path)?;
    let allowed = capabilities.fs_read.iter().any(|prefix| {
        if prefix == "*" {
            return true;
        }

        match normalize_absolute_path(prefix) {
            Ok(prefix_path) => normalized_path.starts_with(prefix_path),
            Err(_) => false,
        }
    });

    if !allowed {
        return Err(WasmHostError::CapabilityDenied(format!(
            "fs_read denied for path: {path}"
        )));
    }

    Ok(())
}

/// Check whether writing to a filesystem path is allowed.
pub fn check_fs_write(path: &str, capabilities: &CapabilitySet) -> Result<(), WasmHostError> {
    if capabilities.fs_write.is_empty() {
        return Err(WasmHostError::CapabilityDenied(format!(
            "fs_write not granted for path: {path}"
        )));
    }

    let normalized_path = normalize_absolute_path(path)?;
    let allowed = capabilities.fs_write.iter().any(|prefix| {
        if prefix == "*" {
            return true;
        }

        match normalize_absolute_path(prefix) {
            Ok(prefix_path) => normalized_path.starts_with(prefix_path),
            Err(_) => false,
        }
    });

    if !allowed {
        return Err(WasmHostError::CapabilityDenied(format!(
            "fs_write denied for path: {path}"
        )));
    }

    Ok(())
}

/// Check whether environment/secret access is allowed.
///
/// Always denied for third-party skills (`env_secrets` = false).
pub fn check_env_access(capabilities: &CapabilitySet) -> Result<(), WasmHostError> {
    if !capabilities.env_secrets {
        return Err(WasmHostError::CapabilityDenied(
            "env_secrets access denied".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_caps() -> CapabilitySet {
        CapabilitySet {
            net_outbound: vec![],
            fs_read: vec![],
            fs_write: vec![],
            exec_shell: false,
            env_secrets: false,
            kv: false,
            prompt_user: false,
            emit_events: vec![],
            hooks: vec![],
            schedule_timers: false,
            schedule_transforms: vec![],
        }
    }

    fn caps_with_net(domains: Vec<&str>) -> CapabilitySet {
        CapabilitySet {
            net_outbound: domains.into_iter().map(String::from).collect(),
            ..default_caps()
        }
    }

    fn caps_with_fs(read: Vec<&str>, write: Vec<&str>) -> CapabilitySet {
        CapabilitySet {
            fs_read: read.into_iter().map(String::from).collect(),
            fs_write: write.into_iter().map(String::from).collect(),
            ..default_caps()
        }
    }

    #[test]
    fn net_outbound_allowed_domain() {
        let caps = caps_with_net(vec!["api.example.com"]);
        assert!(check_net_outbound("api.example.com", &caps).is_ok());
    }

    #[test]
    fn net_outbound_denied_domain() {
        let caps = caps_with_net(vec!["api.example.com"]);
        assert!(check_net_outbound("evil.example.com", &caps).is_err());
    }

    #[test]
    fn net_outbound_wildcard() {
        let caps = caps_with_net(vec!["*"]);
        assert!(check_net_outbound("anything.com", &caps).is_ok());
    }

    #[test]
    fn net_outbound_empty_capabilities() {
        let caps = caps_with_net(vec![]);
        assert!(check_net_outbound("example.com", &caps).is_err());
    }

    #[test]
    fn fs_read_allowed_path() {
        let caps = caps_with_fs(vec!["/data/"], vec![]);
        assert!(check_fs_read("/data/file.txt", &caps).is_ok());
    }

    #[test]
    fn fs_read_denied_path() {
        let caps = caps_with_fs(vec!["/data/"], vec![]);
        assert!(check_fs_read("/etc/passwd", &caps).is_err());
    }

    #[test]
    fn fs_write_allowed_path() {
        let caps = caps_with_fs(vec![], vec!["/tmp/"]);
        assert!(check_fs_write("/tmp/output.txt", &caps).is_ok());
    }

    #[test]
    fn fs_write_denied_path() {
        let caps = caps_with_fs(vec![], vec!["/tmp/"]);
        assert!(check_fs_write("/root/.ssh/id_rsa", &caps).is_err());
    }

    #[test]
    fn fs_read_denied_path_traversal() {
        let caps = caps_with_fs(vec!["/data/"], vec![]);
        assert!(check_fs_read("/data/../etc/passwd", &caps).is_err());
    }

    #[test]
    fn fs_read_denied_prefix_collision() {
        let caps = caps_with_fs(vec!["/tmp/data"], vec![]);
        assert!(check_fs_read("/tmp/database/secret.txt", &caps).is_err());
    }

    #[test]
    fn env_access_denied_for_third_party() {
        let caps = default_caps();
        assert!(check_env_access(&caps).is_err());
    }

    #[test]
    fn env_access_allowed_when_granted() {
        let caps = CapabilitySet {
            env_secrets: true,
            ..default_caps()
        };
        assert!(check_env_access(&caps).is_ok());
    }
}
