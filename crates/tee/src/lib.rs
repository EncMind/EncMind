use std::path::Path;

use async_trait::async_trait;
use tracing::warn;

use encmind_core::error::TeeError;
use encmind_core::traits::{AttestationReport, TeeProvider};

/// Detect the available TEE platform and return the appropriate provider.
pub fn detect_tee() -> Box<dyn TeeProvider> {
    if Path::new("/dev/sev-guest").exists() {
        warn!(
            "AMD SEV-SNP device detected, but sealing/attestation is not yet implemented; running without hardware-backed key sealing"
        );
        Box::new(NoopTeeProvider)
    } else {
        warn!("No TEE detected — running without hardware-backed key sealing");
        Box::new(NoopTeeProvider)
    }
}

// ── NoopTeeProvider ──

/// Fallback provider when no TEE hardware is available.
/// All sealing/attestation operations return `TeeError::NotAvailable`.
pub struct NoopTeeProvider;

#[async_trait]
impl TeeProvider for NoopTeeProvider {
    fn is_available(&self) -> bool {
        false
    }

    async fn get_attestation_report(&self) -> Result<AttestationReport, TeeError> {
        Err(TeeError::NotAvailable)
    }

    async fn seal_key(&self, _key: &[u8]) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::NotAvailable)
    }

    async fn unseal_key(&self, _sealed: &[u8]) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::NotAvailable)
    }
}

// ── SevSnpProvider ──

/// AMD SEV-SNP TEE provider.
///
/// On Linux with `/dev/sev-guest`, this provider issues attestation requests
/// via ioctl, seals keys via a KDF tied to the platform measurement, etc.
///
/// Currently stubbed — the ioctl interface requires an actual SEV-SNP VM.
/// The full implementation will be completed when deploying to AMD SEV-SNP hardware.
pub struct SevSnpProvider {
    _private: (),
}

impl SevSnpProvider {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SevSnpProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeeProvider for SevSnpProvider {
    fn is_available(&self) -> bool {
        false
    }

    async fn get_attestation_report(&self) -> Result<AttestationReport, TeeError> {
        Err(TeeError::NotAvailable)
    }

    async fn seal_key(&self, key: &[u8]) -> Result<Vec<u8>, TeeError> {
        // TODO: Derive sealing key from VMPCK and platform measurement,
        // then encrypt the provided key with it.
        //
        // Seal = AES-256-GCM(sealing_key, key)
        // The sealing_key is derived from:
        //   HKDF-SHA256(VMPCK[0], measurement || "key-seal")

        let _ = key; // suppress unused warning
        Err(TeeError::NotAvailable)
    }

    async fn unseal_key(&self, sealed: &[u8]) -> Result<Vec<u8>, TeeError> {
        // TODO: Re-derive sealing key and decrypt
        let _ = sealed;
        Err(TeeError::NotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_provider_is_not_available() {
        let provider = NoopTeeProvider;
        assert!(!provider.is_available());
    }

    #[tokio::test]
    async fn noop_provider_seal_returns_not_available() {
        let provider = NoopTeeProvider;
        let result = provider.seal_key(b"test-key").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TeeError::NotAvailable => {}
            other => panic!("Expected NotAvailable, got: {other}"),
        }
    }

    #[tokio::test]
    async fn noop_provider_unseal_returns_not_available() {
        let provider = NoopTeeProvider;
        let result = provider.unseal_key(b"sealed-data").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TeeError::NotAvailable => {}
            other => panic!("Expected NotAvailable, got: {other}"),
        }
    }

    #[tokio::test]
    async fn noop_provider_attestation_returns_not_available() {
        let provider = NoopTeeProvider;
        let result = provider.get_attestation_report().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TeeError::NotAvailable => {}
            other => panic!("Expected NotAvailable, got: {other}"),
        }
    }

    #[test]
    fn detect_tee_returns_noop_on_non_sev() {
        // On macOS (and most dev machines), /dev/sev-guest doesn't exist
        let provider = detect_tee();
        // We can't assert which type it is since it's boxed, but we can check availability
        // On dev machines, this should be false
        if !Path::new("/dev/sev-guest").exists() {
            assert!(!provider.is_available());
        }
    }

    #[test]
    fn sev_provider_reports_available() {
        let provider = SevSnpProvider::new();
        assert!(!provider.is_available());
    }
}
