use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
/// Returns a string in the format `SHA256:xx:yy:zz:...`.
pub fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    let hex_parts: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("SHA256:{}", hex_parts.join(":"))
}

/// Normalize a user-provided SHA256 fingerprint string to `SHA256:xx:yy:...`.
pub fn normalize_fingerprint(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = input.trim();
    let body = trimmed
        .strip_prefix("SHA256:")
        .or_else(|| trimmed.strip_prefix("sha256:"))
        .unwrap_or(trimmed);
    let hex: String = body
        .chars()
        .filter(|c| *c != ':' && !c.is_ascii_whitespace())
        .collect();

    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid SHA256 fingerprint format".into());
    }

    let hex = hex.to_ascii_lowercase();
    let pairs = hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    Ok(format!("SHA256:{}", pairs.join(":")))
}

fn default_crypto_provider() -> Result<Arc<CryptoProvider>, Box<dyn std::error::Error>> {
    CryptoProvider::get_default()
        .cloned()
        .or_else(|| {
            CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider()).ok();
            CryptoProvider::get_default().cloned()
        })
        .ok_or_else(|| "no rustls CryptoProvider available".into())
}

/// Build a rustls `ClientConfig` that verifies the server certificate by fingerprint
/// instead of CA validation. The server's certificate must match the expected fingerprint.
pub fn build_fingerprint_tls_config(
    fingerprint: &str,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let provider = default_crypto_provider()?;
    let normalized = normalize_fingerprint(fingerprint)?;

    let verifier = FingerprintVerifier {
        expected: normalized,
        provider,
    };

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    Ok(config)
}

/// Build a `tokio_tungstenite::Connector` for fingerprint-pinned TLS connections.
pub fn build_ws_connector(
    fingerprint: Option<&str>,
) -> Result<Option<tokio_tungstenite::Connector>, Box<dyn std::error::Error>> {
    match fingerprint {
        Some(fp) => {
            let config = build_fingerprint_tls_config(fp)?;
            Ok(Some(tokio_tungstenite::Connector::Rustls(Arc::new(config))))
        }
        None => Ok(None),
    }
}

/// Build a `reqwest::Client` that verifies by fingerprint (for pairing HTTP requests).
pub fn build_http_client_with_fingerprint(
    fingerprint: &str,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let tls_config = build_fingerprint_tls_config(fingerprint)?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    Ok(client)
}

/// Probe a TLS gateway and return its presented certificate fingerprint.
/// Used for interactive TOFU first-connect prompts.
pub async fn probe_server_fingerprint(
    gateway_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = Url::parse(gateway_url)?;
    match url.scheme() {
        "wss" | "https" => {}
        _ => return Err("gateway URL must use wss:// or https:// for fingerprint probing".into()),
    }
    let host = url
        .host_str()
        .ok_or("gateway URL is missing host")?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or("gateway URL is missing port")?;

    let provider = default_crypto_provider()?;
    let captured = Arc::new(Mutex::new(None::<String>));
    let verifier = CaptureFingerprintVerifier {
        captured: Arc::clone(&captured),
        provider,
    };
    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.clone())
            .map_err(|_| format!("invalid TLS server name: {host}"))?
    };
    let _tls_stream = connector.connect(server_name, tcp).await?;

    let fingerprint = captured
        .lock()
        .map_err(|_| "fingerprint capture mutex poisoned")?
        .clone()
        .ok_or("server did not present a certificate")?;
    Ok(fingerprint)
}

/// A TLS certificate verifier that checks the server's certificate fingerprint
/// instead of validating against a CA chain. This enables TOFU (Trust On First Use)
/// connections to servers with self-signed certificates.
struct FingerprintVerifier {
    expected: String,
    provider: Arc<CryptoProvider>,
}

struct CaptureFingerprintVerifier {
    captured: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for FingerprintVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FingerprintVerifier")
            .field("expected", &self.expected)
            .finish()
    }
}

impl fmt::Debug for CaptureFingerprintVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureFingerprintVerifier").finish()
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fingerprint = compute_cert_fingerprint(end_entity.as_ref());
        if fingerprint == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {fingerprint}",
                self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for CaptureFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fingerprint = compute_cert_fingerprint(end_entity.as_ref());
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(fingerprint);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Walk the error chain looking for TLS certificate validation errors.
/// Returns `true` if any error in the chain is a `rustls::Error` or
/// contains a well-known certificate-failure substring.
pub fn is_tls_validation_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if e.downcast_ref::<Error>().is_some() {
            return true;
        }

        let msg = e.to_string().to_ascii_lowercase();
        if msg.contains("certificate verify failed")
            || msg.contains("invalid peer certificate")
            || msg.contains("unknown issuer")
            || msg.contains("self signed")
            || msg.contains("certificate has expired")
            || msg.contains("invalid certificate")
        {
            return true;
        }
        current = e.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format_is_correct() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let fp = compute_cert_fingerprint(cert.cert.der().as_ref());
        assert!(fp.starts_with("SHA256:"));
        // 32 bytes → 32 hex pairs separated by ':'
        let parts: Vec<&str> = fp.strip_prefix("SHA256:").unwrap().split(':').collect();
        assert_eq!(parts.len(), 32);
        for part in &parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let fp1 = compute_cert_fingerprint(cert.cert.der().as_ref());
        let fp2 = compute_cert_fingerprint(cert.cert.der().as_ref());
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_certs_have_different_fingerprints() {
        let cert1 = rcgen::generate_simple_self_signed(vec!["a.example".into()]).unwrap();
        let cert2 = rcgen::generate_simple_self_signed(vec!["b.example".into()]).unwrap();
        let fp1 = compute_cert_fingerprint(cert1.cert.der().as_ref());
        let fp2 = compute_cert_fingerprint(cert2.cert.der().as_ref());
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn build_fingerprint_config_succeeds() {
        let config = build_fingerprint_tls_config("SHA256:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89");
        assert!(config.is_ok());
    }

    #[test]
    fn normalize_fingerprint_accepts_mixed_input() {
        let fp = normalize_fingerprint(
            "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        )
        .unwrap();
        assert_eq!(
            fp,
            "SHA256:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
        );
    }

    #[test]
    fn normalize_fingerprint_rejects_invalid_length() {
        assert!(normalize_fingerprint("SHA256:aa:bb").is_err());
    }

    #[test]
    fn build_ws_connector_with_fingerprint() {
        let connector = build_ws_connector(Some("SHA256:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"));
        assert!(connector.is_ok());
        assert!(connector.unwrap().is_some());
    }

    #[test]
    fn build_ws_connector_without_fingerprint() {
        let connector = build_ws_connector(None);
        assert!(connector.is_ok());
        assert!(connector.unwrap().is_none());
    }
}
