use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

/// A device ID is the hex-encoded SHA-256 hash of the device's Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DeviceId(pub String);

impl DeviceId {
    /// Derive a device ID from a public (verifying) key.
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        Self(hex::encode(hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;

    #[test]
    fn deterministic_device_id() {
        let (_, verifying) = generate_keypair();
        let id1 = DeviceId::from_verifying_key(&verifying);
        let id2 = DeviceId::from_verifying_key(&verifying);
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_keys_different_ids() {
        let (_, v1) = generate_keypair();
        let (_, v2) = generate_keypair();
        let id1 = DeviceId::from_verifying_key(&v1);
        let id2 = DeviceId::from_verifying_key(&v2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn device_id_serde_roundtrip() {
        let (_, verifying) = generate_keypair();
        let id = DeviceId::from_verifying_key(&verifying);
        let json = serde_json::to_string(&id).unwrap();
        let id2: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn device_id_is_64_hex_chars() {
        let (_, verifying) = generate_keypair();
        let id = DeviceId::from_verifying_key(&verifying);
        assert_eq!(id.as_str().len(), 64);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
