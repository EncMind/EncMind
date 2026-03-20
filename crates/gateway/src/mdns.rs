use tracing::{info, warn};

const SERVICE_TYPE: &str = "_encmind._tcp.local.";

/// Advertises the EncMind gateway on the local network via mDNS.
pub struct MdnsAdvertiser {
    daemon: mdns_sd::ServiceDaemon,
    fullname: String,
}

impl MdnsAdvertiser {
    /// Start advertising on the local network.
    pub fn new(port: u16, name: &str) -> Result<Self, MdnsError> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| MdnsError::Start(e.to_string()))?;

        let hostname = format!("{name}.local.");
        let service_info = mdns_sd::ServiceInfo::new(SERVICE_TYPE, name, &hostname, "", port, None)
            .map_err(|e| MdnsError::Start(e.to_string()))?;

        let fullname = service_info.get_fullname().to_string();

        daemon
            .register(service_info)
            .map_err(|e| MdnsError::Start(e.to_string()))?;

        info!(
            service_type = SERVICE_TYPE,
            name, port, "mDNS advertising started"
        );
        Ok(Self { daemon, fullname })
    }

    /// Stop advertising.
    pub fn shutdown(self) -> Result<(), MdnsError> {
        self.daemon
            .unregister(&self.fullname)
            .map_err(|e| MdnsError::Stop(e.to_string()))?;

        if let Err(e) = self.daemon.shutdown() {
            warn!("mDNS daemon shutdown error: {e}");
        }
        info!("mDNS advertising stopped");
        Ok(())
    }

    /// Get the service type being advertised.
    pub fn service_type(&self) -> &str {
        SERVICE_TYPE
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MdnsError {
    #[error("mDNS start error: {0}")]
    Start(String),

    #[error("mDNS stop error: {0}")]
    Stop(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_is_correct() {
        assert_eq!(SERVICE_TYPE, "_encmind._tcp.local.");
    }

    #[test]
    fn mdns_advertiser_creates_and_shuts_down() {
        // Note: mDNS requires network access; this test verifies API correctness
        let result = MdnsAdvertiser::new(8443, "test-encmind");
        match result {
            Ok(advertiser) => {
                assert_eq!(advertiser.service_type(), SERVICE_TYPE);
                // Shutdown
                advertiser.shutdown().unwrap();
            }
            Err(e) => {
                // mDNS may not work in all CI/test environments
                eprintln!("mDNS not available in test env: {e}");
            }
        }
    }
}
