use serde::{Deserialize, Serialize};

use chrono::Utc;
use encmind_core::traits::DeviceStore;
use encmind_core::types::{DevicePermissions, PairedDevice};
use encmind_crypto::challenge::generate_pairing_code;
use encmind_crypto::device_id::DeviceId;
use encmind_crypto::keypair::verifying_key_from_bytes;

/// Messages in the pairing protocol (client → server).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairingClientMessage {
    /// Client sends its public key to initiate pairing.
    PairRequest { public_key: String, name: String },
    /// Client confirms the pairing code shown on the server.
    PairConfirm { code: String },
}

/// Messages in the pairing protocol (server → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairingServerMessage {
    /// Server sends a pairing code for user confirmation.
    PairChallenge { code: String },
    /// Pairing completed successfully.
    PairComplete { device_id: String },
    /// Pairing error.
    PairError { message: String },
}

/// Typed errors from pairing completion.
#[derive(Debug)]
pub enum PairingError {
    /// The user-supplied code does not match.
    IncorrectCode,
    /// Underlying storage or other internal failure.
    StorageFailed(String),
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairingError::IncorrectCode => write!(f, "incorrect pairing code"),
            PairingError::StorageFailed(msg) => write!(f, "failed to store device: {msg}"),
        }
    }
}

/// Manages the pairing flow state.
#[derive(Clone)]
pub struct PairingSession {
    pub public_key_bytes: Vec<u8>,
    pub name: String,
    pub code: String,
    pub device_id: String,
    pub created_at: std::time::Instant,
}

impl PairingSession {
    /// Start a new pairing session from a client's public key.
    pub fn new(public_key_hex: &str, name: &str) -> Result<Self, String> {
        let public_key_bytes =
            hex::decode(public_key_hex).map_err(|e| format!("invalid public key hex: {e}"))?;

        if public_key_bytes.len() != 32 {
            return Err("public key must be 32 bytes".into());
        }

        let pk_array: [u8; 32] = public_key_bytes
            .clone()
            .try_into()
            .map_err(|_| "invalid key length")?;
        let verifying_key =
            verifying_key_from_bytes(&pk_array).map_err(|e| format!("invalid public key: {e}"))?;
        let device_id = DeviceId::from_verifying_key(&verifying_key);
        let code = generate_pairing_code();

        Ok(Self {
            public_key_bytes,
            name: name.to_string(),
            code,
            device_id: device_id.to_string(),
            created_at: std::time::Instant::now(),
        })
    }

    /// Complete pairing by storing the device with the given default permissions.
    pub async fn complete(
        &self,
        confirmed_code: &str,
        device_store: &dyn DeviceStore,
        default_permissions: &DevicePermissions,
    ) -> Result<String, PairingError> {
        if confirmed_code != self.code {
            return Err(PairingError::IncorrectCode);
        }

        let device = PairedDevice {
            id: self.device_id.clone(),
            name: self.name.clone(),
            public_key: self.public_key_bytes.clone(),
            permissions: default_permissions.clone(),
            paired_at: Utc::now(),
            last_seen: None,
        };

        device_store
            .add_device(&device)
            .await
            .map_err(|e| PairingError::StorageFailed(e.to_string()))?;

        Ok(self.device_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encmind_crypto::keypair::generate_keypair;
    use encmind_storage::device_store::SqliteDeviceStore;
    use encmind_storage::migrations::run_migrations;
    use encmind_storage::pool::create_test_pool;

    fn setup_device_store() -> SqliteDeviceStore {
        let pool = create_test_pool();
        {
            let conn = pool.get().unwrap();
            run_migrations(&conn).unwrap();
        }
        SqliteDeviceStore::new(pool)
    }

    #[test]
    fn pairing_code_format() {
        let (_, verifying) = generate_keypair();
        let pk_hex = hex::encode(verifying.to_bytes());
        let session = PairingSession::new(&pk_hex, "Test Device").unwrap();
        assert_eq!(session.code.len(), 6);
        assert!(session.code.chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn pairing_stores_device() {
        let device_store = setup_device_store();
        let (_, verifying) = generate_keypair();
        let pk_hex = hex::encode(verifying.to_bytes());

        let session = PairingSession::new(&pk_hex, "My Laptop").unwrap();
        let code = session.code.clone();

        let default_perms = DevicePermissions {
            chat: true,
            ..Default::default()
        };
        let device_id = session
            .complete(&code, &device_store, &default_perms)
            .await
            .unwrap();

        // Verify device was stored
        let device = device_store.get_device(&device_id).await.unwrap().unwrap();
        assert_eq!(device.name, "My Laptop");
        assert!(device.permissions.chat);
    }

    #[tokio::test]
    async fn wrong_code_rejected() {
        let device_store = setup_device_store();
        let (_, verifying) = generate_keypair();
        let pk_hex = hex::encode(verifying.to_bytes());

        let session = PairingSession::new(&pk_hex, "Device").unwrap();
        let default_perms = DevicePermissions::default();
        let result = session
            .complete("000000", &device_store, &default_perms)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn duplicate_pairing_updates() {
        let device_store = setup_device_store();
        let (_, verifying) = generate_keypair();
        let pk_hex = hex::encode(verifying.to_bytes());
        let default_perms = DevicePermissions {
            chat: true,
            ..Default::default()
        };

        // First pairing
        let session1 = PairingSession::new(&pk_hex, "First").unwrap();
        let code1 = session1.code.clone();
        let device_id = session1
            .complete(&code1, &device_store, &default_perms)
            .await
            .unwrap();

        // Second pairing with same key should succeed (upsert) and update the name
        let session2 = PairingSession::new(&pk_hex, "Second").unwrap();
        let code2 = session2.code.clone();
        session2
            .complete(&code2, &device_store, &default_perms)
            .await
            .unwrap();

        let device = device_store.get_device(&device_id).await.unwrap().unwrap();
        assert_eq!(device.name, "Second");
    }

    #[test]
    fn pairing_message_serde() {
        let msg = PairingClientMessage::PairRequest {
            public_key: "abcdef".into(),
            name: "Device".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: PairingClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            PairingClientMessage::PairRequest { public_key, name } => {
                assert_eq!(public_key, "abcdef");
                assert_eq!(name, "Device");
            }
            _ => panic!("Expected PairRequest"),
        }

        let srv = PairingServerMessage::PairChallenge {
            code: "123456".into(),
        };
        let json = serde_json::to_string(&srv).unwrap();
        let back: PairingServerMessage = serde_json::from_str(&json).unwrap();
        match back {
            PairingServerMessage::PairChallenge { code } => assert_eq!(code, "123456"),
            _ => panic!("Expected PairChallenge"),
        }
    }
}
