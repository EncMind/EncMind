use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::CryptoError;

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut rand_core_06::OsRng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Serialize a signing key to 32 bytes.
pub fn keypair_to_bytes(signing: &SigningKey) -> [u8; 32] {
    signing.to_bytes()
}

/// Deserialize a signing key from 32 bytes.
pub fn keypair_from_bytes(bytes: &[u8; 32]) -> Result<(SigningKey, VerifyingKey), CryptoError> {
    let signing = SigningKey::from_bytes(bytes);
    let verifying = signing.verifying_key();
    Ok((signing, verifying))
}

/// Deserialize a verifying (public) key from 32 bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, CryptoError> {
    VerifyingKey::from_bytes(bytes).map_err(|e| CryptoError::InvalidKeyBytes(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let (signing, verifying) = generate_keypair();
        let bytes = keypair_to_bytes(&signing);
        let (signing2, verifying2) = keypair_from_bytes(&bytes).unwrap();
        assert_eq!(signing.to_bytes(), signing2.to_bytes());
        assert_eq!(verifying, verifying2);
    }

    #[test]
    fn verifying_key_roundtrip() {
        let (_, verifying) = generate_keypair();
        let bytes = verifying.to_bytes();
        let verifying2 = verifying_key_from_bytes(&bytes).unwrap();
        assert_eq!(verifying, verifying2);
    }
}
