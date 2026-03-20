use std::path::{Path, PathBuf};

use encmind_crypto::device_id::DeviceId;
use encmind_crypto::keypair::{generate_keypair, keypair_from_bytes, keypair_to_bytes};
use serde::{Deserialize, Serialize};

/// On-disk identity for the bridge client.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    /// Ed25519 signing key (32 bytes, hex-encoded)
    signing_key: String,
}

pub struct LocalKeystore {
    #[allow(dead_code)]
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    path: PathBuf,
}

impl LocalKeystore {
    /// Load existing identity or create a new one.
    pub fn load_or_create(custom_path: Option<&str>) -> Result<Self, KeystoreError> {
        let path = resolve_identity_path(custom_path);

        if path.exists() {
            Self::load(&path)
        } else {
            Self::create(&path)
        }
    }

    fn load(path: &Path) -> Result<Self, KeystoreError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        let identity: IdentityFile =
            serde_json::from_str(&content).map_err(|e| KeystoreError::Parse(e.to_string()))?;

        let key_bytes =
            hex::decode(&identity.signing_key).map_err(|e| KeystoreError::Parse(e.to_string()))?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| KeystoreError::Parse("invalid key length".into()))?;

        let (signing_key, verifying_key) =
            keypair_from_bytes(&key_array).map_err(|e| KeystoreError::Parse(e.to_string()))?;

        Ok(Self {
            signing_key,
            verifying_key,
            path: path.to_path_buf(),
        })
    }

    fn create(path: &Path) -> Result<Self, KeystoreError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| KeystoreError::Io(e.to_string()))?;
        }

        let (signing_key, verifying_key) = generate_keypair();
        let key_bytes = keypair_to_bytes(&signing_key);
        let identity = IdentityFile {
            signing_key: hex::encode(key_bytes),
        };

        let content = serde_json::to_string_pretty(&identity)
            .map_err(|e| KeystoreError::Parse(e.to_string()))?;
        std::fs::write(path, content).map_err(|e| KeystoreError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|e| KeystoreError::Io(e.to_string()))?;
        }

        Ok(Self {
            signing_key,
            verifying_key,
            path: path.to_path_buf(),
        })
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_verifying_key(&self.verifying_key)
    }

    #[allow(dead_code)]
    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }

    #[allow(dead_code)]
    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
}

pub fn resolve_identity_path(custom_path: Option<&str>) -> PathBuf {
    if let Some(path) = custom_path {
        return PathBuf::from(path);
    }
    default_identity_path()
}

pub fn identity_exists(custom_path: Option<&str>) -> bool {
    resolve_identity_path(custom_path).exists()
}

fn default_identity_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    home.join(".encmind-edge/identity.json")
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_load_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let path_str = path.to_str().unwrap();

        // Create
        let ks = LocalKeystore::load_or_create(Some(path_str)).unwrap();
        let device_id = ks.device_id();

        // Load
        let ks2 = LocalKeystore::load_or_create(Some(path_str)).unwrap();
        assert_eq!(ks2.device_id(), device_id);
    }

    #[test]
    fn device_id_from_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let ks = LocalKeystore::load_or_create(Some(path.to_str().unwrap())).unwrap();
        let id = ks.device_id();
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn public_key_hex_is_64_chars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let ks = LocalKeystore::load_or_create(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(ks.public_key_hex().len(), 64);
    }
}
