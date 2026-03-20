use crate::keystore::LocalKeystore;
use crate::url_utils::{normalize_http_url, validate_fingerprint_transport};
use std::time::Duration;

const PAIR_CONNECT_TIMEOUT_SECS: u64 = 10;
const PAIR_REQUEST_TIMEOUT_SECS: u64 = 30;

pub async fn run_pair(
    gateway_url: &str,
    name: &str,
    identity_path: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ks = LocalKeystore::load_or_create(identity_path)?;

    println!("Device ID: {}", ks.device_id());
    println!("Public key: {}", ks.public_key_hex());
    println!("Pairing with gateway: {gateway_url}");
    println!("Device name: {name}");
    if let Some(fp) = fingerprint {
        println!("Using pinned fingerprint: {fp}");
    }

    let base_url = normalize_http_url(gateway_url)?;
    validate_fingerprint_transport(&base_url, fingerprint)?;
    let client = if let Some(fp) = fingerprint {
        crate::tls::build_http_client_with_fingerprint(fp)?
    } else {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(PAIR_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(PAIR_REQUEST_TIMEOUT_SECS))
            .build()?
    };

    // Step 1: Start pairing
    let start_url = base_url.join("pair/start")?;
    let start_body = serde_json::json!({
        "public_key": ks.public_key_hex(),
        "name": name,
    });

    let resp = client.post(start_url).json(&start_body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("pair/start failed ({status}): {body}").into());
    }

    let start_resp: serde_json::Value = resp.json().await?;
    let pairing_id = start_resp
        .get("pairing_id")
        .and_then(|v| v.as_str())
        .ok_or("missing pairing_id in response")?
        .to_string();

    println!();
    println!("Pairing started (id: {pairing_id}).");
    println!("Read the 6-digit pairing code from the server logs, then enter it below.");
    println!();

    // Step 2: Read code from stdin
    eprint!("Pairing code: ");
    std::io::Write::flush(&mut std::io::stderr())?;
    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let code = code.trim().to_string();

    if code.is_empty() {
        return Err("pairing code cannot be empty".into());
    }

    // Step 3: Confirm pairing
    let confirm_url = base_url.join("pair/confirm")?;
    let confirm_body = serde_json::json!({
        "pairing_id": pairing_id,
        "code": code,
    });

    let resp = client.post(confirm_url).json(&confirm_body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("pair/confirm failed ({status}): {body}").into());
    }

    let confirm_resp: serde_json::Value = resp.json().await?;
    let device_id = confirm_resp
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("Pairing successful! Device registered as: {device_id}");
    Ok(())
}

#[cfg(test)]
mod tests {}
