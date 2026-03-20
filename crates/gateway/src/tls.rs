#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};

use encmind_core::config::TlsLifecycleConfig;

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

/// Manages TLS certificate lifecycle: self-signed generation, file loading,
/// and hot-reload via ArcSwap.
pub struct TlsLifecycleManager {
    config_swap: Arc<ArcSwap<ServerConfig>>,
    _lifecycle_config: TlsLifecycleConfig,
}

impl TlsLifecycleManager {
    /// Create a manager with a self-signed certificate for localhost only.
    pub fn self_signed(lifecycle_config: &TlsLifecycleConfig) -> Result<Self, TlsError> {
        Self::self_signed_with_sans(vec!["localhost".into()], lifecycle_config)
    }

    /// Create a manager with a self-signed certificate that includes the given SANs.
    /// Each SAN string can be a DNS name or an IP address (rcgen auto-detects).
    pub fn self_signed_with_sans(
        sans: Vec<String>,
        lifecycle_config: &TlsLifecycleConfig,
    ) -> Result<Self, TlsError> {
        let cert = rcgen::generate_simple_self_signed(sans)
            .map_err(|e| TlsError::CertGeneration(e.to_string()))?;

        let cert_der = cert.cert.der().clone();
        let key_der = cert.key_pair.serialize_der();

        let server_config = build_server_config(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )?;

        Ok(Self {
            config_swap: Arc::new(ArcSwap::new(Arc::new(server_config))),
            _lifecycle_config: lifecycle_config.clone(),
        })
    }

    /// Load certificates from PEM files.
    pub fn from_files(
        cert_path: &Path,
        key_path: &Path,
        lifecycle_config: &TlsLifecycleConfig,
    ) -> Result<Self, TlsError> {
        let (certs, key) = load_pem_files(cert_path, key_path)?;
        let server_config = build_server_config(certs, key)?;

        Ok(Self {
            config_swap: Arc::new(ArcSwap::new(Arc::new(server_config))),
            _lifecycle_config: lifecycle_config.clone(),
        })
    }

    /// Load existing auto-TLS cert from `tls_dir`, or generate a new self-signed
    /// cert with the given SANs, save it to disk, and return the manager + fingerprint.
    pub fn auto_tls(
        tls_dir: &Path,
        sans: Vec<String>,
        lifecycle_config: &TlsLifecycleConfig,
    ) -> Result<(Self, String), TlsError> {
        let cert_path = tls_dir.join("cert.pem");
        let key_path = tls_dir.join("key.pem");

        if cert_path.exists() && key_path.exists() {
            // Load existing cert and compute fingerprint
            let (certs, key) = load_pem_files(&cert_path, &key_path)?;
            let fingerprint = compute_cert_fingerprint(certs[0].as_ref());
            let server_config = build_server_config(certs, key)?;
            let mgr = Self {
                config_swap: Arc::new(ArcSwap::new(Arc::new(server_config))),
                _lifecycle_config: lifecycle_config.clone(),
            };
            return Ok((mgr, fingerprint));
        }

        // Generate new self-signed cert
        let cert = rcgen::generate_simple_self_signed(sans)
            .map_err(|e| TlsError::CertGeneration(e.to_string()))?;

        let cert_der = cert.cert.der().clone();
        let key_der = cert.key_pair.serialize_der();
        let fingerprint = compute_cert_fingerprint(cert_der.as_ref());

        // Save to disk with single-operator permissions:
        // - tls dir: 0700
        // - cert.pem: 0644
        // - key.pem: 0600
        create_secure_tls_dir(tls_dir)?;
        write_tls_file(&cert_path, cert.cert.pem().as_bytes(), TlsFileKind::Cert)?;
        write_tls_file(
            &key_path,
            cert.key_pair.serialize_pem().as_bytes(),
            TlsFileKind::Key,
        )?;

        let server_config = build_server_config(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )?;
        let mgr = Self {
            config_swap: Arc::new(ArcSwap::new(Arc::new(server_config))),
            _lifecycle_config: lifecycle_config.clone(),
        };
        Ok((mgr, fingerprint))
    }

    /// Hot-reload certificates from PEM files without restarting.
    pub fn reload(&self, cert_path: &Path, key_path: &Path) -> Result<(), TlsError> {
        let (certs, key) = load_pem_files(cert_path, key_path)?;
        let server_config = build_server_config(certs, key)?;
        self.config_swap.store(Arc::new(server_config));
        Ok(())
    }

    /// Get a reference to the current server config for use with TLS acceptor.
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.config_swap.load_full()
    }
}

#[derive(Clone, Copy)]
enum TlsFileKind {
    Cert,
    Key,
}

fn create_secure_tls_dir(tls_dir: &Path) -> Result<(), TlsError> {
    if tls_dir.exists() {
        if !tls_dir.is_dir() {
            return Err(TlsError::FileWrite(format!(
                "TLS path exists but is not a directory: {}",
                tls_dir.display()
            )));
        }
    } else {
        #[cfg(unix)]
        {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(tls_dir).map_err(|e| {
                TlsError::FileWrite(format!(
                    "failed to create TLS dir '{}': {e}",
                    tls_dir.display()
                ))
            })?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(tls_dir).map_err(|e| {
                TlsError::FileWrite(format!(
                    "failed to create TLS dir '{}': {e}",
                    tls_dir.display()
                ))
            })?;
        }
    }

    #[cfg(unix)]
    {
        std::fs::set_permissions(tls_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            TlsError::FileWrite(format!(
                "failed to set TLS dir permissions '{}': {e}",
                tls_dir.display()
            ))
        })?;
    }

    Ok(())
}

fn write_tls_file(path: &Path, content: &[u8], kind: TlsFileKind) -> Result<(), TlsError> {
    #[cfg(unix)]
    {
        let mode = match kind {
            TlsFileKind::Cert => 0o644,
            TlsFileKind::Key => 0o600,
        };
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .map_err(|e| {
                TlsError::FileWrite(format!(
                    "failed to open '{}' for write: {e}",
                    path.display()
                ))
            })?;
        file.write_all(content).map_err(|e| {
            TlsError::FileWrite(format!("failed to write '{}': {e}", path.display()))
        })?;
        file.sync_all().map_err(|e| {
            TlsError::FileWrite(format!("failed to fsync '{}': {e}", path.display()))
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
            TlsError::FileWrite(format!(
                "failed to set permissions on '{}': {e}",
                path.display()
            ))
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = kind;
        std::fs::write(path, content).map_err(|e| {
            TlsError::FileWrite(format!("failed to write '{}': {e}", path.display()))
        })?;
        Ok(())
    }
}

/// Compute the SHA-256 fingerprint of a DER-encoded certificate.
/// Returns a string in the format `SHA256:xx:yy:zz:...`.
pub fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    let hex_parts: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("SHA256:{}", hex_parts.join(":"))
}

/// Build the list of SANs for an auto-generated self-signed certificate.
/// Always includes `localhost` and `127.0.0.1`. Adds the system hostname
/// if it can be detected and differs from `localhost`.
pub fn auto_tls_sans() -> Vec<String> {
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    if let Some(hostname) = get_hostname() {
        let hostname = hostname.trim().to_string();
        if !hostname.is_empty()
            && hostname != "localhost"
            && !sans.iter().any(|s| s.eq_ignore_ascii_case(&hostname))
        {
            sans.push(hostname);
        }
    }

    sans
}

fn get_hostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

fn load_pem_files(
    cert_path: &Path,
    key_path: &Path,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    TlsError,
> {
    let cert_file =
        std::fs::File::open(cert_path).map_err(|e| TlsError::FileRead(e.to_string()))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::FileRead(e.to_string()))?;

    if certs.is_empty() {
        return Err(TlsError::FileRead("no certificates found".into()));
    }

    let key_file = std::fs::File::open(key_path).map_err(|e| TlsError::FileRead(e.to_string()))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| TlsError::FileRead(e.to_string()))?
        .ok_or_else(|| TlsError::FileRead("no private key found".into()))?;

    Ok((certs, key))
}

fn build_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    // Advertise HTTP/2 and HTTP/1.1 over TLS. WebSocket upgrades continue to use HTTP/1.1.
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server_config)
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate generation error: {0}")]
    CertGeneration(String),

    #[error("file read error: {0}")]
    FileRead(String),

    #[error("file write error: {0}")]
    FileWrite(String),

    #[error("TLS config error: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensure a rustls CryptoProvider is installed (needed when both
    /// `aws-lc-rs` and `ring` features are active in the dep tree).
    fn ensure_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn self_signed_creates_valid_config() {
        ensure_crypto_provider();
        let config = TlsLifecycleConfig::default();
        let mgr = TlsLifecycleManager::self_signed(&config).unwrap();
        // ServerConfig was created successfully — alpn can be inspected
        let sc = mgr.server_config();
        assert_eq!(
            sc.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn self_signed_returns_server_config() {
        ensure_crypto_provider();
        let config = TlsLifecycleConfig::default();
        let mgr = TlsLifecycleManager::self_signed(&config).unwrap();
        // Getting the server config twice returns equivalent configs (ArcSwap)
        let sc1 = mgr.server_config();
        let sc2 = mgr.server_config();
        assert!(std::sync::Arc::ptr_eq(&sc1, &sc2));
    }

    #[test]
    fn from_files_missing_cert_errors() {
        let config = TlsLifecycleConfig::default();
        let result = TlsLifecycleManager::from_files(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            &config,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reload_with_self_signed_works() {
        ensure_crypto_provider();
        // Generate self-signed certs to PEM files, then reload
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let config = TlsLifecycleConfig::default();
        let mgr = TlsLifecycleManager::self_signed(&config).unwrap();
        mgr.reload(&cert_path, &key_path).unwrap();
    }

    #[test]
    fn self_signed_with_sans_includes_all_names() {
        ensure_crypto_provider();
        let config = TlsLifecycleConfig::default();
        let mgr = TlsLifecycleManager::self_signed_with_sans(
            vec!["localhost".into(), "127.0.0.1".into(), "myhost".into()],
            &config,
        );
        assert!(mgr.is_ok());
    }

    #[test]
    fn compute_fingerprint_deterministic() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().as_ref();
        let fp1 = compute_cert_fingerprint(der);
        let fp2 = compute_cert_fingerprint(der);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
        // SHA-256 produces 32 bytes → 32 hex pairs joined by ':'
        assert_eq!(fp1.len(), "SHA256:".len() + 32 * 3 - 1);
    }

    #[test]
    fn auto_tls_generates_and_persists_cert() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let tls_dir = dir.path().join("tls");
        let config = TlsLifecycleConfig::default();

        // First call: generates new cert
        let (_, fp1) =
            TlsLifecycleManager::auto_tls(&tls_dir, vec!["localhost".into()], &config).unwrap();
        assert!(fp1.starts_with("SHA256:"));
        assert!(tls_dir.join("cert.pem").exists());
        assert!(tls_dir.join("key.pem").exists());

        // Second call: loads existing cert, same fingerprint
        let (_, fp2) =
            TlsLifecycleManager::auto_tls(&tls_dir, vec!["localhost".into()], &config).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn auto_tls_sans_includes_localhost() {
        let sans = auto_tls_sans();
        assert!(sans.contains(&"localhost".to_string()));
        assert!(sans.contains(&"127.0.0.1".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn auto_tls_writes_single_operator_permissions() {
        ensure_crypto_provider();
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let tls_dir = dir.path().join("tls");
        let config = TlsLifecycleConfig::default();
        let _ = TlsLifecycleManager::auto_tls(&tls_dir, vec!["localhost".into()], &config).unwrap();

        let dir_mode = std::fs::metadata(&tls_dir).unwrap().permissions().mode() & 0o777;
        let cert_mode = std::fs::metadata(tls_dir.join("cert.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(tls_dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(dir_mode, 0o700);
        assert_eq!(cert_mode, 0o644);
        assert_eq!(key_mode, 0o600);
    }
}
