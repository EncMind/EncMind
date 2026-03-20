use std::time::Duration;

const SERVICE_TYPE: &str = "_encmind._tcp.local.";

pub async fn run_discover(timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("Scanning for EncMind gateways ({timeout_secs}s)...");

    let mdns = mdns_sd::ServiceDaemon::new()?;
    let receiver = mdns.browse(SERVICE_TYPE)?;

    let deadline = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(deadline);

    let mut found = 0;

    loop {
        tokio::select! {
            _ = &mut deadline => break,
            event = tokio::task::spawn_blocking({
                let receiver = receiver.clone();
                move || receiver.recv_timeout(Duration::from_millis(500))
            }) => {
                if let Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) = event {
                    found += 1;
                    println!(
                        "  Found: {} at {}:{}",
                        info.get_fullname(),
                        info.get_hostname(),
                        info.get_port()
                    );
                }
            }
        }
    }

    mdns.stop_browse(SERVICE_TYPE)?;
    if let Err(e) = mdns.shutdown() {
        tracing::warn!("mDNS shutdown: {e}");
    }

    if found == 0 {
        println!("No EncMind gateways found on the local network.");
    } else {
        println!("Found {found} gateway(s).");
    }

    Ok(())
}
