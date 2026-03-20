pub mod challenge;
pub mod device_id;
pub mod keypair;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key bytes: {0}")]
    InvalidKeyBytes(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),
}
