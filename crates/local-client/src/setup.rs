use std::io::Write;
use std::time::Duration;
use url::Url;

use crate::tls::is_tls_validation_error;

#[derive(Debug)]
pub struct SetupError {
    message: String,
    tls_retry_gateway: Option<String>,
}

impl SetupError {
    fn new(message: impl Into<String>, tls_retry_gateway: Option<String>) -> Self {
        Self {
            message: message.into(),
            tls_retry_gateway,
        }
    }

    pub fn tls_retry_gateway(&self) -> Option<&str> {
        self.tls_retry_gateway.as_deref()
    }
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SetupError {}

/// Run the guided setup wizard: discover → pair → ready.
pub async fn run_setup(
    gateway_url: Option<&str>,
    identity_path: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let gateway_input = if let Some(url) = gateway_url {
        url.trim().to_string()
    } else {
        // Discover gateways on LAN.
        eprintln!("Scanning for EncMind gateways on your network...");
        let found = discover_gateways(5).await;

        match found.len() {
            0 => {
                eprintln!("No gateways found on the local network.");
                eprint!("Enter gateway URL manually: ");
                std::io::stderr().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let url = input.trim().to_string();
                if url.is_empty() {
                    return Err("No gateway URL provided.".into());
                }
                url
            }
            1 => {
                let gw = &found[0];
                eprintln!("Found: {gw}");
                gw.clone()
            }
            _ => {
                eprintln!("Found {} gateways:", found.len());
                for (i, gw) in found.iter().enumerate() {
                    eprintln!("  [{}] {gw}", i + 1);
                }
                eprint!("Select gateway [1-{}]: ", found.len());
                std::io::stderr().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let choice: usize = input.trim().parse().map_err(|_| "invalid selection")?;
                if choice == 0 || choice > found.len() {
                    return Err("selection out of range".into());
                }
                found[choice - 1].clone()
            }
        }
    };

    let mut last_err: Option<String> = None;
    let mut last_tls_retry_gateway: Option<String> = None;
    let candidates = gateway_candidates(&gateway_input, fingerprint)?;
    for (i, gateway) in candidates.iter().enumerate() {
        if candidates.len() > 1 {
            eprintln!("Pairing with {gateway}... ({}/{})", i + 1, candidates.len());
        } else {
            eprintln!("Pairing with {gateway}...");
        }

        match crate::pair::run_pair(gateway, "encmind-edge", identity_path, fingerprint).await {
            Ok(()) => {
                eprintln!();
                eprintln!("Ready! Run 'encmind-edge' to start chatting.");
                return Ok(gateway.clone());
            }
            Err(e) => {
                if is_tls_validation_error(e.as_ref()) {
                    last_tls_retry_gateway = Some(gateway.clone());
                }
                last_err = Some(e.to_string());
            }
        }
    }

    let message = format!(
        "pairing failed for '{gateway_input}': {}",
        last_err.unwrap_or_else(|| "unknown error".to_string())
    );
    Err(Box::new(SetupError::new(message, last_tls_retry_gateway)))
}

/// Discover gateways via mDNS. Returns a list of gateway URLs.
async fn discover_gateways(timeout_secs: u64) -> Vec<String> {
    use std::collections::HashSet;

    let mdns = match mdns_sd::ServiceDaemon::new() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let receiver = match mdns.browse("_encmind._tcp.local.") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let deadline = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(deadline);

    let mut gateways = Vec::new();
    let mut seen = HashSet::new();

    loop {
        tokio::select! {
            _ = &mut deadline => break,
            event = tokio::task::spawn_blocking({
                let receiver = receiver.clone();
                move || receiver.recv_timeout(Duration::from_millis(500))
            }) => {
                if let Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) = event {
                    let host = info.get_hostname().trim_end_matches('.');
                    let port = info.get_port();
                    let endpoint = format!("{host}:{port}");
                    if seen.insert(endpoint.clone()) {
                        gateways.push(endpoint);
                    }
                }
            }
        }
    }

    let _ = mdns.stop_browse("_encmind._tcp.local.");
    let _ = mdns.shutdown();

    gateways
}

fn gateway_candidates(
    gateway_input: &str,
    fingerprint: Option<&str>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let trimmed = gateway_input.trim();
    if trimmed.is_empty() {
        return Err("No gateway URL provided.".into());
    }

    // If URL is explicit and uses a supported scheme, honor exactly what user selected.
    if let Ok(parsed) = Url::parse(trimmed) {
        if matches!(parsed.scheme(), "ws" | "wss" | "http" | "https") {
            return Ok(vec![trimmed.to_string()]);
        }
    }

    // mDNS discovery currently yields host:port. Try ws first for local profile,
    // then wss for TLS-enabled deployments. If fingerprint is provided, only TLS.
    if fingerprint.is_some() {
        Ok(vec![format!("wss://{trimmed}")])
    } else {
        Ok(vec![format!("ws://{trimmed}"), format!("wss://{trimmed}")])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_candidates_keep_explicit_url() {
        let candidates = gateway_candidates("wss://example.com:8443", None).unwrap();
        assert_eq!(candidates, vec!["wss://example.com:8443".to_string()]);
    }

    #[test]
    fn gateway_candidates_no_scheme_tries_ws_then_wss() {
        let candidates = gateway_candidates("example.com:8443", None).unwrap();
        assert_eq!(
            candidates,
            vec![
                "ws://example.com:8443".to_string(),
                "wss://example.com:8443".to_string()
            ]
        );
    }

    #[test]
    fn gateway_candidates_with_fingerprint_only_uses_wss() {
        let fp = Some("SHA256:012345678901234567890123456789012345678901234567890123456789abcd");
        let candidates = gateway_candidates("example.com:8443", fp).unwrap();
        assert_eq!(candidates, vec!["wss://example.com:8443".to_string()]);
    }

    #[test]
    fn gateway_candidates_reject_empty() {
        let err = gateway_candidates("   ", None).unwrap_err();
        assert!(err.to_string().contains("No gateway URL provided"));
    }
}
