use std::path::Path;

use argon2::Argon2;
use rand::RngExt;

use encmind_core::config::KeySource;
use encmind_core::error::StorageError;
use encmind_core::traits::TeeProvider;

/// Derive a 32-byte encryption key from the configured key source.
pub async fn derive_key(
    source: &KeySource,
    tee: &dyn TeeProvider,
    data_dir: &Path,
) -> Result<[u8; 32], StorageError> {
    match source {
        KeySource::Passphrase { passphrase_env } => {
            let passphrase = std::env::var(passphrase_env)?;
            let salt = load_or_create_salt(data_dir)?;
            argon2id_derive(&passphrase, &salt)
        }
        KeySource::TeeSeal => {
            let sealed = load_sealed_key(data_dir)?;
            let master = tee
                .unseal_key(&sealed)
                .await
                .map_err(|e| StorageError::KeyDerivationFailed(e.to_string()))?;
            master.try_into().map_err(|_| {
                StorageError::KeyDerivationFailed("unsealed key is not 32 bytes".into())
            })
        }
        KeySource::EnvVar { var_name } => {
            let hex_str = std::env::var(var_name)?;
            let bytes = hex::decode(&hex_str)
                .map_err(|e| StorageError::KeyDerivationFailed(format!("invalid hex: {e}")))?;
            bytes
                .try_into()
                .map_err(|_| StorageError::KeyDerivationFailed("key is not 32 bytes".into()))
        }
        KeySource::ExternalVault { .. } => Err(StorageError::KeyDerivationFailed(
            "External vault key source not yet implemented (Phase 2)".into(),
        )),
    }
}

/// Derive a 32-byte key from a passphrase using Argon2id.
fn argon2id_derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], StorageError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| StorageError::KeyDerivationFailed(format!("argon2id: {e}")))?;
    Ok(key)
}

/// Load or create a 16-byte salt file in the data directory.
fn load_or_create_salt(data_dir: &Path) -> Result<Vec<u8>, StorageError> {
    let salt_path = data_dir.join("salt");
    if salt_path.exists() {
        std::fs::read(&salt_path).map_err(StorageError::Io)
    } else {
        let mut salt = vec![0u8; 16];
        rand::rng().fill(&mut salt[..]);
        // Ensure parent directory exists
        if let Some(parent) = salt_path.parent() {
            std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }
        std::fs::write(&salt_path, &salt).map_err(StorageError::Io)?;
        Ok(salt)
    }
}

/// Load the TEE-sealed key file from the data directory.
fn load_sealed_key(data_dir: &Path) -> Result<Vec<u8>, StorageError> {
    let key_path = data_dir.join("sealed_key");
    if key_path.exists() {
        std::fs::read(&key_path).map_err(StorageError::Io)
    } else {
        Err(StorageError::KeyDerivationFailed(
            "sealed key file not found — run initial setup first".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_deterministic() {
        let salt = b"test-salt-16byte";
        let key1 = argon2id_derive("my-passphrase", salt).unwrap();
        let key2 = argon2id_derive("my-passphrase", salt).unwrap();
        assert_eq!(key1, key2, "Same passphrase+salt must produce same key");
    }

    #[test]
    fn argon2id_different_passphrase() {
        let salt = b"test-salt-16byte";
        let key1 = argon2id_derive("password-1", salt).unwrap();
        let key2 = argon2id_derive("password-2", salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn argon2id_different_salt() {
        let key1 = argon2id_derive("same-pass", b"salt-aaaaaaaaaa16").unwrap();
        let key2 = argon2id_derive("same-pass", b"salt-bbbbbbbbbb16").unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn load_or_create_salt_creates_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let salt1 = load_or_create_salt(dir.path()).unwrap();
        assert_eq!(salt1.len(), 16);

        let salt2 = load_or_create_salt(dir.path()).unwrap();
        assert_eq!(salt1, salt2, "Re-loading should return the same salt");
    }

    #[tokio::test]
    async fn env_var_key_source() {
        let key_hex = "aa".repeat(32); // 32 bytes as hex
        std::env::set_var("TEST_KEY_HEX", &key_hex);

        let source = KeySource::EnvVar {
            var_name: "TEST_KEY_HEX".into(),
        };
        let tee = encmind_tee::NoopTeeProvider;
        let dir = tempfile::tempdir().unwrap();

        let key = derive_key(&source, &tee, dir.path()).await.unwrap();
        assert_eq!(key, [0xaa; 32]);

        std::env::remove_var("TEST_KEY_HEX");
    }

    #[tokio::test]
    async fn external_vault_key_source_not_implemented() {
        let source = KeySource::ExternalVault {
            provider: encmind_core::config::VaultProvider::AzureKeyVault {
                vault_url: "https://my-vault.vault.azure.net".into(),
            },
            key_id: "encmind-master-key".into(),
        };
        let tee = encmind_tee::NoopTeeProvider;
        let dir = tempfile::tempdir().unwrap();

        let result = derive_key(&source, &tee, dir.path()).await;
        assert!(result.is_err());
    }
}
