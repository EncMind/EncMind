use crate::chat::{connect_and_auth, send_req};
use crate::keystore::{identity_exists, KeystoreError, LocalKeystore};

/// Subcommands for `encmind-edge memory`.
#[derive(Debug, Clone, Default)]
pub enum MemorySubcmd {
    #[default]
    Status,
    Search {
        query: String,
    },
}

/// Run a memory subcommand.
pub async fn run_memory(
    subcmd: MemorySubcmd,
    gateway_url: &str,
    identity_path: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !identity_exists(identity_path) {
        return Err("Not set up yet. Run: encmind-edge setup".into());
    }

    let ks = match LocalKeystore::load_or_create(identity_path) {
        Ok(ks) => ks,
        Err(e @ KeystoreError::Parse(_)) => {
            return Err(format!(
                "Identity file is corrupted: {e}. Delete it and re-run: encmind-edge setup"
            )
            .into());
        }
        Err(e @ KeystoreError::Io(_)) => {
            return Err(format!(
                "Cannot read identity file: {e}. Check path/permissions, or re-run: encmind-edge setup"
            )
            .into());
        }
    };

    let mut ws = connect_and_auth(gateway_url, &ks, fingerprint).await?;

    match subcmd {
        MemorySubcmd::Status => {
            let result = send_req(&mut ws, "memory.status", serde_json::json!({})).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        }
        MemorySubcmd::Search { query } => {
            let result = send_req(
                &mut ws,
                "memory.search",
                serde_json::json!({"query": query}),
            )
            .await?;
            print_memory_search_results(&result);
        }
    }

    let _ = ws.close(None).await;
    Ok(())
}

fn print_memory_search_results(result: &serde_json::Value) {
    let results = result
        .as_array()
        .or_else(|| result.get("results").and_then(|v| v.as_array()));

    if let Some(results) = results {
        if results.is_empty() {
            println!("No memories found.");
            return;
        }

        for r in results {
            let score = r.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let summary = r
                .get("entry")
                .and_then(|v| v.get("summary"))
                .and_then(|v| v.as_str())
                .or_else(|| r.get("content").and_then(|v| v.as_str()))
                .unwrap_or("?");
            let preview: String = summary.chars().take(120).collect();
            println!("  [{score:.2}] {preview}");
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_subcmd_is_status() {
        assert!(matches!(MemorySubcmd::default(), MemorySubcmd::Status));
    }

    #[test]
    fn search_results_parse_top_level_array_shape() {
        let payload = serde_json::json!([
            {"score": 0.91, "entry": {"summary": "alpha memory"}},
            {"score": 0.77, "entry": {"summary": "beta memory"}}
        ]);
        // Smoke test: should not panic and should parse expected shape.
        print_memory_search_results(&payload);
    }

    #[test]
    fn search_results_parse_wrapped_results_shape() {
        let payload = serde_json::json!({
            "results": [{"score": 0.42, "content": "legacy shape"}]
        });
        // Smoke test for backward compatibility.
        print_memory_search_results(&payload);
    }
}
