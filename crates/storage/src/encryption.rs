use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};

use encmind_core::error::StorageError;
use encmind_core::traits::EncryptionAdapter;

/// AES-256-GCM encryption adapter for at-rest data.
///
/// Each call to `encrypt` generates a unique random 12-byte nonce,
/// ensuring that the same plaintext produces different ciphertext each time.
pub struct Aes256GcmAdapter {
    cipher: Aes256Gcm,
}

impl Aes256GcmAdapter {
    /// Create a new adapter from a 32-byte encryption key.
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }
}

impl EncryptionAdapter for Aes256GcmAdapter {
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| StorageError::EncryptionFailed)?;
        Ok((ciphertext, nonce.to_vec()))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, StorageError> {
        if nonce.len() != 12 {
            return Err(StorageError::DecryptionFailed);
        }
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)
    }

    fn encrypt_with_aad(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| StorageError::EncryptionFailed)?;
        Ok((ciphertext, nonce.to_vec()))
    }

    fn decrypt_with_aad(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        if nonce.len() != 12 {
            return Err(StorageError::DecryptionFailed);
        }
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| StorageError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let plaintext = b"Hello, encrypted world!";

        let (ciphertext, nonce) = adapter.encrypt(plaintext).unwrap();
        let decrypted = adapter.decrypt(&ciphertext, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces_each_call() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let plaintext = b"same input";

        let (_, nonce1) = adapter.encrypt(plaintext).unwrap();
        let (_, nonce2) = adapter.encrypt(plaintext).unwrap();

        assert_ne!(nonce1, nonce2, "Each encryption must use a unique nonce");
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let adapter1 = Aes256GcmAdapter::new(&[0x42u8; 32]);
        let adapter2 = Aes256GcmAdapter::new(&[0x99u8; 32]);

        let (ciphertext, nonce) = adapter1.encrypt(b"secret").unwrap();
        let result = adapter2.decrypt(&ciphertext, &nonce);

        assert!(result.is_err());
        match result.unwrap_err() {
            StorageError::DecryptionFailed => {}
            other => panic!("Expected DecryptionFailed, got: {other}"),
        }
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let plaintext = b"This should not appear in ciphertext";
        let (ciphertext, _) = adapter.encrypt(plaintext).unwrap();
        assert_ne!(&ciphertext, plaintext);
    }

    #[test]
    fn nonce_is_12_bytes() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let (_, nonce) = adapter.encrypt(b"test").unwrap();
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn empty_plaintext() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let (ciphertext, nonce) = adapter.encrypt(b"").unwrap();
        let decrypted = adapter.decrypt(&ciphertext, &nonce).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn invalid_nonce_length_fails_without_panic() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let (ciphertext, _) = adapter.encrypt(b"test").unwrap();
        let result = adapter.decrypt(&ciphertext, b"bad");
        assert!(result.is_err());
    }

    #[test]
    fn aad_roundtrip() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let plaintext = b"sk-secret-key";
        let aad = b"openai";
        let (ciphertext, nonce) = adapter.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = adapter.decrypt_with_aad(&ciphertext, &nonce, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aad_mismatch_fails_decryption() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let (ciphertext, nonce) = adapter.encrypt_with_aad(b"sk-key", b"openai").unwrap();
        let result = adapter.decrypt_with_aad(&ciphertext, &nonce, b"anthropic");
        assert!(result.is_err(), "wrong AAD should fail decryption");
    }

    #[test]
    fn aad_missing_fails_decryption() {
        let adapter = Aes256GcmAdapter::new(&test_key());
        let (ciphertext, nonce) = adapter.encrypt_with_aad(b"sk-key", b"openai").unwrap();
        // Decrypt without AAD (using base method) should also fail because
        // AES-GCM tag was computed with AAD.
        let result = adapter.decrypt(&ciphertext, &nonce);
        assert!(result.is_err(), "missing AAD should fail decryption");
    }
}
