use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;

use crate::CryptoError;

/// Generate a random 32-byte nonce for challenge-response auth.
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill(&mut nonce);
    nonce
}

/// Sign a nonce with the device's signing key.
pub fn sign_nonce(signing_key: &SigningKey, nonce: &[u8]) -> Vec<u8> {
    let signature = signing_key.sign(nonce);
    signature.to_bytes().to_vec()
}

/// Verify a signed nonce against the device's public key.
pub fn verify_nonce(
    verifying_key: &VerifyingKey,
    nonce: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let sig = ed25519_dalek::Signature::from_slice(signature_bytes)
        .map_err(|e| CryptoError::InvalidKeyBytes(e.to_string()))?;
    verifying_key
        .verify(nonce, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Generate a 6-digit numeric pairing code.
pub fn generate_pairing_code() -> String {
    let n: u32 = rand::random_range(0..1_000_000);
    format!("{n:06}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;

    #[test]
    fn sign_and_verify_nonce() {
        let (signing, verifying) = generate_keypair();
        let nonce = generate_nonce();
        let signature = sign_nonce(&signing, &nonce);
        assert!(verify_nonce(&verifying, &nonce, &signature).is_ok());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (signing, _) = generate_keypair();
        let (_, wrong_verifying) = generate_keypair();
        let nonce = generate_nonce();
        let signature = sign_nonce(&signing, &nonce);
        assert!(verify_nonce(&wrong_verifying, &nonce, &signature).is_err());
    }

    #[test]
    fn wrong_nonce_fails_verification() {
        let (signing, verifying) = generate_keypair();
        let nonce = generate_nonce();
        let different_nonce = generate_nonce();
        let signature = sign_nonce(&signing, &nonce);
        assert!(verify_nonce(&verifying, &different_nonce, &signature).is_err());
    }

    #[test]
    fn pairing_code_is_6_digits() {
        for _ in 0..100 {
            let code = generate_pairing_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn nonce_is_32_bytes() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn nonces_are_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }
}
