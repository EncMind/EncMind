use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use encmind_core::error::GatewayError;
use encmind_core::traits::DeviceStore;
use encmind_crypto::challenge::{generate_nonce, verify_nonce};
use encmind_crypto::keypair::verifying_key_from_bytes;

/// Manages nonce challenges for device authentication.
pub struct NonceStore {
    /// Maps nonce (hex) → device_id
    pending: Mutex<HashMap<String, PendingChallenge>>,
}

const NONCE_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING_NONCES: usize = 4096;
const MAX_PENDING_PER_DEVICE: usize = 32;

struct PendingChallenge {
    device_id: String,
    nonce: [u8; 32],
    created_at: Instant,
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a nonce challenge for a device.
    pub fn issue_nonce(&self, device_id: &str) -> String {
        let nonce = generate_nonce();
        let nonce_hex = hex::encode(nonce);
        let mut pending = self.pending.lock().unwrap();
        Self::prune_expired_locked(&mut pending);

        // Bound per-device growth.
        let device_pending_count = pending
            .values()
            .filter(|entry| entry.device_id == device_id)
            .count();
        if device_pending_count >= MAX_PENDING_PER_DEVICE {
            if let Some(oldest_key) = pending
                .iter()
                .filter(|(_, entry)| entry.device_id == device_id)
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(key, _)| key.clone())
            {
                pending.remove(&oldest_key);
            }
        }

        // Bound global growth.
        if pending.len() >= MAX_PENDING_NONCES {
            if let Some(oldest_key) = pending
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(key, _)| key.clone())
            {
                pending.remove(&oldest_key);
            }
        }

        pending.insert(
            nonce_hex.clone(),
            PendingChallenge {
                device_id: device_id.to_string(),
                nonce,
                created_at: Instant::now(),
            },
        );
        nonce_hex
    }

    /// Cleanup expired nonce challenges.
    pub fn cleanup_expired(&self) {
        let mut pending = self.pending.lock().unwrap();
        Self::prune_expired_locked(&mut pending);
    }

    fn prune_expired_locked(pending: &mut HashMap<String, PendingChallenge>) {
        pending.retain(|_, entry| entry.created_at.elapsed() < NONCE_TTL);
    }

    /// Verify a challenge response. Returns `(device_id, permissions)` on success,
    /// so callers don't need a second device lookup.
    pub async fn verify_challenge(
        &self,
        nonce_hex: &str,
        signature_hex: &str,
        device_store: &dyn DeviceStore,
    ) -> Result<(String, encmind_core::types::DevicePermissions), GatewayError> {
        let challenge = {
            let mut pending = self.pending.lock().unwrap();
            Self::prune_expired_locked(&mut pending);
            pending
                .remove(nonce_hex)
                .ok_or_else(|| GatewayError::AuthFailed("unknown nonce".into()))?
        };

        if challenge.created_at.elapsed() >= NONCE_TTL {
            return Err(GatewayError::AuthFailed("nonce expired".into()));
        }

        let device = device_store
            .get_device(&challenge.device_id)
            .await
            .map_err(|e| GatewayError::AuthFailed(e.to_string()))?
            .ok_or_else(|| GatewayError::DeviceNotPaired(challenge.device_id.clone()))?;

        let pub_key_bytes: [u8; 32] = device
            .public_key
            .try_into()
            .map_err(|_| GatewayError::AuthFailed("invalid public key length".into()))?;

        let verifying_key = verifying_key_from_bytes(&pub_key_bytes)
            .map_err(|e| GatewayError::AuthFailed(e.to_string()))?;

        let signature_bytes =
            hex::decode(signature_hex).map_err(|e| GatewayError::AuthFailed(e.to_string()))?;

        verify_nonce(&verifying_key, &challenge.nonce, &signature_bytes)
            .map_err(|_| GatewayError::AuthFailed("signature verification failed".into()))?;

        Ok((challenge.device_id, device.permissions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use encmind_core::traits::DeviceStore;
    use encmind_core::types::{DevicePermissions, PairedDevice};
    use encmind_crypto::challenge::sign_nonce;
    use encmind_crypto::device_id::DeviceId;
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
    fn nonce_issued() {
        let store = NonceStore::new();
        let nonce = store.issue_nonce("dev-1");
        assert_eq!(nonce.len(), 64); // 32 bytes hex-encoded
    }

    #[tokio::test]
    async fn challenge_verified() {
        let nonce_store = NonceStore::new();
        let device_store = setup_device_store();

        let (signing, verifying) = generate_keypair();
        let device_id = DeviceId::from_verifying_key(&verifying);

        // Add device
        device_store
            .add_device(&PairedDevice {
                id: device_id.as_str().to_string(),
                name: "Test".into(),
                public_key: verifying.to_bytes().to_vec(),
                permissions: DevicePermissions::default(),
                paired_at: Utc::now(),
                last_seen: None,
            })
            .await
            .unwrap();

        // Issue nonce
        let nonce_hex = nonce_store.issue_nonce(device_id.as_str());

        // Sign nonce
        let nonce_bytes = hex::decode(&nonce_hex).unwrap();
        let sig = sign_nonce(&signing, &nonce_bytes);
        let sig_hex = hex::encode(&sig);

        // Verify
        let result = nonce_store
            .verify_challenge(&nonce_hex, &sig_hex, &device_store)
            .await;
        assert!(result.is_ok());
        let (verified_id, _perms) = result.unwrap();
        assert_eq!(verified_id, device_id.as_str());
    }

    #[tokio::test]
    async fn wrong_signature_fails() {
        let nonce_store = NonceStore::new();
        let device_store = setup_device_store();

        let (_, verifying) = generate_keypair();
        let (wrong_signing, _) = generate_keypair();
        let device_id = DeviceId::from_verifying_key(&verifying);

        device_store
            .add_device(&PairedDevice {
                id: device_id.as_str().to_string(),
                name: "Test".into(),
                public_key: verifying.to_bytes().to_vec(),
                permissions: DevicePermissions::default(),
                paired_at: Utc::now(),
                last_seen: None,
            })
            .await
            .unwrap();

        let nonce_hex = nonce_store.issue_nonce(device_id.as_str());
        let nonce_bytes = hex::decode(&nonce_hex).unwrap();
        let bad_sig = sign_nonce(&wrong_signing, &nonce_bytes);
        let bad_sig_hex = hex::encode(&bad_sig);

        let result = nonce_store
            .verify_challenge(&nonce_hex, &bad_sig_hex, &device_store)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unknown_nonce_rejected() {
        let nonce_store = NonceStore::new();
        let device_store = setup_device_store();

        let result = nonce_store
            .verify_challenge("deadbeef", "sig", &device_store)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn nonce_consumed_after_use() {
        let nonce_store = NonceStore::new();
        let device_store = setup_device_store();

        let (signing, verifying) = generate_keypair();
        let device_id = DeviceId::from_verifying_key(&verifying);

        device_store
            .add_device(&PairedDevice {
                id: device_id.as_str().to_string(),
                name: "Test".into(),
                public_key: verifying.to_bytes().to_vec(),
                permissions: DevicePermissions::default(),
                paired_at: Utc::now(),
                last_seen: None,
            })
            .await
            .unwrap();

        let nonce_hex = nonce_store.issue_nonce(device_id.as_str());
        let nonce_bytes = hex::decode(&nonce_hex).unwrap();
        let sig = sign_nonce(&signing, &nonce_bytes);
        let sig_hex = hex::encode(&sig);

        // First use succeeds
        assert!(nonce_store
            .verify_challenge(&nonce_hex, &sig_hex, &device_store)
            .await
            .is_ok());

        // Second use fails (nonce consumed)
        assert!(nonce_store
            .verify_challenge(&nonce_hex, &sig_hex, &device_store)
            .await
            .is_err());
    }

    #[test]
    fn nonce_store_bounds_per_device_growth() {
        let nonce_store = NonceStore::new();
        for _ in 0..(MAX_PENDING_PER_DEVICE + 8) {
            let _ = nonce_store.issue_nonce("dev-bound");
        }

        let pending = nonce_store.pending.lock().unwrap();
        let count = pending
            .values()
            .filter(|entry| entry.device_id == "dev-bound")
            .count();
        assert!(count <= MAX_PENDING_PER_DEVICE);
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let nonce_store = NonceStore::new();
        let nonce = nonce_store.issue_nonce("dev-expire");

        {
            let mut pending = nonce_store.pending.lock().unwrap();
            if let Some(entry) = pending.get_mut(&nonce) {
                entry.created_at = Instant::now() - (NONCE_TTL + Duration::from_secs(1));
            }
        }

        nonce_store.cleanup_expired();

        let pending = nonce_store.pending.lock().unwrap();
        assert!(!pending.contains_key(&nonce));
    }
}
