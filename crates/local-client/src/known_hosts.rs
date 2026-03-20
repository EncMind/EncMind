use std::collections::HashMap;
use std::path::PathBuf;

use crate::tls::normalize_fingerprint;
use crate::url_utils::canonical_gateway_key;

/// Stores pinned TLS certificate fingerprints for known gateways (TOFU model).
/// Saved as a JSON map in `~/.encmind-edge/known_hosts`.
pub struct KnownHosts {
    path: PathBuf,
    hosts: HashMap<String, String>,
}

impl KnownHosts {
    /// Load known hosts from the default path, or create an empty store.
    pub fn load() -> Self {
        let path = default_known_hosts_path();
        let hosts = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|data| serde_json::from_str(&data).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self { path, hosts }
    }

    /// Look up the fingerprint for a given gateway URL.
    pub fn get(&self, gateway_url: &str) -> Option<&str> {
        if let Ok(key) = canonical_gateway_key(gateway_url) {
            if let Some(value) = self.hosts.get(&key) {
                return Some(value.as_str());
            }
        }
        self.hosts.get(gateway_url).map(|s| s.as_str())
    }

    /// Save a fingerprint for a gateway URL, persisting to disk.
    pub fn set(
        &mut self,
        gateway_url: &str,
        fingerprint: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let normalized = normalize_fingerprint(fingerprint)?;
        let key = canonical_gateway_key(gateway_url).unwrap_or_else(|_| gateway_url.to_string());
        if key != gateway_url {
            self.hosts.remove(gateway_url);
        }
        self.hosts.insert(key, normalized);
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(&self.hosts)?;
        std::fs::write(&self.path, data)?;
        Ok(())
    }
}

fn default_known_hosts_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".encmind-edge").join("known_hosts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        let mut hosts = KnownHosts {
            path: path.clone(),
            hosts: HashMap::new(),
        };

        hosts
            .set(
                "wss://example.com:8443",
                "SHA256:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            )
            .unwrap();

        // Load from same path
        let loaded = KnownHosts {
            path: path.clone(),
            hosts: std::fs::read_to_string(&path)
                .ok()
                .and_then(|d| serde_json::from_str(&d).ok())
                .unwrap_or_default(),
        };

        assert_eq!(
            loaded.get("wss://example.com:8443"),
            Some("SHA256:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")
        );
    }

    #[test]
    fn get_returns_none_for_unknown_host() {
        let hosts = KnownHosts {
            path: PathBuf::from("/tmp/nonexistent"),
            hosts: HashMap::new(),
        };
        assert!(hosts.get("wss://unknown:8443").is_none());
    }

    #[test]
    fn overwrite_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        let mut hosts = KnownHosts {
            path,
            hosts: HashMap::new(),
        };

        hosts
            .set(
                "wss://host:8443",
                "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            )
            .unwrap();
        hosts
            .set(
                "wss://host:8443/node",
                "SHA256:ff:ee:dd:cc:bb:aa:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            )
            .unwrap();

        assert_eq!(
            hosts.get("https://host:8443/"),
            Some("SHA256:ff:ee:dd:cc:bb:aa:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")
        );
    }

    #[test]
    fn invalid_fingerprint_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut hosts = KnownHosts {
            path,
            hosts: HashMap::new(),
        };
        let err = hosts
            .set("wss://host:8443", "not-a-fingerprint")
            .unwrap_err();
        assert!(err.to_string().contains("invalid SHA256 fingerprint"));
    }
}
