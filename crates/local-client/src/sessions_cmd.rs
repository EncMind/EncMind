use crate::chat::{connect_and_auth, send_req};
use crate::keystore::{identity_exists, KeystoreError, LocalKeystore};

/// Subcommands for `encmind-edge sessions`.
#[derive(Debug, Clone, Default)]
pub enum SessionsSubcmd {
    #[default]
    List,
    Delete {
        id: String,
    },
    Rename {
        id: String,
        title: String,
    },
}

/// Run a sessions subcommand.
pub async fn run_sessions(
    subcmd: SessionsSubcmd,
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
        SessionsSubcmd::List => {
            let result = send_req(&mut ws, "sessions.list", serde_json::json!({})).await?;
            if let Some(sessions) = result["sessions"].as_array() {
                if sessions.is_empty() {
                    println!("No sessions.");
                } else {
                    for s in sessions {
                        let id = s["id"].as_str().unwrap_or("?");
                        let title = s["title"].as_str().unwrap_or("(untitled)");
                        println!("  {id}  \"{title}\"");
                    }
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            }
        }
        SessionsSubcmd::Delete { id } => {
            send_req(
                &mut ws,
                "sessions.delete",
                serde_json::json!({"session_id": id}),
            )
            .await?;
            println!("Deleted session: {id}");
        }
        SessionsSubcmd::Rename { id, title } => {
            send_req(
                &mut ws,
                "sessions.rename",
                serde_json::json!({"session_id": id, "title": title}),
            )
            .await?;
            println!("Renamed session {id} to \"{title}\"");
        }
    }

    let _ = ws.close(None).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_subcmd_is_list() {
        assert!(matches!(SessionsSubcmd::default(), SessionsSubcmd::List));
    }
}
