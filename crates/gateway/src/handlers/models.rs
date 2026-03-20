use crate::protocol::*;
use crate::state::AppState;

pub async fn handle_list(
    state: &AppState,
    _params: serde_json::Value,
    req_id: &str,
) -> ServerMessage {
    let config = state.config.read().await;
    let mut models = Vec::new();

    if let Some(local) = &config.llm.local {
        models.push(serde_json::json!({
            "name": local.model_name,
            "provider": "local",
            "base_url": serde_json::Value::Null,
        }));
    }

    for provider in &config.llm.api_providers {
        models.push(serde_json::json!({
            "name": provider.model,
            "provider": provider.name,
            "base_url": provider.base_url,
        }));
    }

    ServerMessage::Res {
        id: req_id.to_string(),
        result: serde_json::json!({ "models": models }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_test_state;
    use encmind_core::config::ApiProviderConfig;

    #[tokio::test]
    async fn models_list_returns_configured_providers() {
        let state = make_test_state();
        {
            let mut config = state.config.write().await;
            config.llm.api_providers.push(ApiProviderConfig {
                name: "openai".into(),
                model: "gpt-4".into(),
                base_url: Some("https://api.openai.com/v1".into()),
            });
        }

        let result = handle_list(&state, serde_json::json!({}), "req-15-1").await;
        match result {
            ServerMessage::Res { id, result } => {
                assert_eq!(id, "req-15-1");
                let models = result["models"].as_array().expect("models should be array");
                assert_eq!(models.len(), 1);
                assert_eq!(models[0]["name"], "gpt-4");
                assert_eq!(models[0]["provider"], "openai");
                assert_eq!(models[0]["base_url"], "https://api.openai.com/v1");
            }
            other => panic!("expected Res, got: {other:?}"),
        }
    }
}
