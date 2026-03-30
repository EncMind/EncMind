use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use encmind_core::error::LlmError;
use encmind_core::traits::*;
use encmind_core::types::*;

use crate::sse;

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const API_VERSION: &str = "2023-06-01";

/// Anthropic Messages API backend.
pub struct AnthropicBackend {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicBackend {
    pub fn new(api_key: String, model: String, base_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            base_url: base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        }
    }
}

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    messages: Vec<ApiMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ApiTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<ThinkingParam>,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: Vec<ApiContentBlock>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ApiContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

#[derive(Serialize)]
struct ApiTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Serialize)]
struct ThinkingParam {
    #[serde(rename = "type")]
    thinking_type: String,
    budget_tokens: u32,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum StreamEvent {
    #[serde(rename = "message_start")]
    MessageStart {},
    #[serde(rename = "content_block_start")]
    ContentBlockStart {
        index: usize,
        content_block: ContentBlockInfo,
    },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: usize, delta: DeltaInfo },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: usize },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: MessageDeltaInfo },
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "error")]
    Error { error: ApiErrorInfo },
}

#[derive(Deserialize)]
struct ContentBlockInfo {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::enum_variant_names)] // names match Anthropic API's JSON tags
enum DeltaInfo {
    #[serde(rename = "text_delta")]
    TextDelta { text: String },
    #[serde(rename = "thinking_delta")]
    ThinkingDelta { thinking: String },
    #[serde(rename = "input_json_delta")]
    InputJsonDelta { partial_json: String },
}

#[derive(Deserialize)]
struct MessageDeltaInfo {
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct ApiErrorInfo {
    message: String,
}

fn convert_messages(messages: &[Message]) -> (Option<String>, Vec<ApiMessage>) {
    let mut system = None;
    let mut api_messages = Vec::new();

    for msg in messages {
        if msg.role == Role::System {
            let text: String = msg
                .content
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            system = Some(text);
            continue;
        }

        let role = match msg.role {
            Role::Assistant => "assistant",
            _ => "user",
        };

        let content = msg
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text { text } => Some(ApiContentBlock::Text { text: text.clone() }),
                ContentBlock::ToolUse { id, name, input } => Some(ApiContentBlock::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                    input: sanitize_tool_use_input_for_anthropic(input),
                }),
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => Some(ApiContentBlock::ToolResult {
                    tool_use_id: tool_use_id.clone(),
                    content: content.clone(),
                }),
                _ => None,
            })
            .collect();

        api_messages.push(ApiMessage {
            role: role.to_string(),
            content,
        });
    }

    (system, api_messages)
}

fn sanitize_tool_use_input_for_anthropic(input: &serde_json::Value) -> serde_json::Value {
    match input {
        serde_json::Value::Object(_) => input.clone(),
        _ => serde_json::json!({}),
    }
}

fn convert_tools(tools: &[ToolDefinition]) -> Vec<ApiTool> {
    tools
        .iter()
        .map(|t| ApiTool {
            name: t.name.clone(),
            description: t.description.clone(),
            input_schema: t.parameters.clone(),
        })
        .collect()
}

/// Track per-content-block state during streaming.
struct BlockState {
    block_type: String,
    tool_id: Option<String>,
    tool_name: Option<String>,
    tool_json: String,
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    async fn complete(
        &self,
        messages: &[Message],
        params: CompletionParams,
        cancel: CancellationToken,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
    {
        let (system, api_messages) = convert_messages(messages);
        let selected_model = params.model.clone().unwrap_or_else(|| self.model.clone());

        let thinking = params.thinking.as_ref().and_then(|t| {
            t.enabled.then(|| ThinkingParam {
                thinking_type: "enabled".to_string(),
                budget_tokens: t.budget_tokens,
            })
        });

        let request = MessagesRequest {
            model: selected_model,
            messages: api_messages,
            max_tokens: params.max_tokens,
            temperature: Some(params.temperature),
            stream: true,
            system,
            tools: convert_tools(&params.tools),
            thinking,
        };

        let url = format!("{}/v1/messages", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::ApiError(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if status.as_u16() == 429 {
                return Err(LlmError::RateLimited {
                    retry_after_secs: None,
                });
            }
            return Err(LlmError::ApiError(format!("HTTP {status}: {body}")));
        }

        let byte_stream = response.bytes_stream();
        let sse_stream = sse::parse_sse(byte_stream);

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn(async move {
            let mut stream = Box::pin(sse_stream);
            let mut blocks: Vec<BlockState> = Vec::new();

            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        let _ = tx.send(Err(LlmError::Cancelled)).await;
                        return;
                    }
                    event = stream.next() => {
                        let event = match event {
                            Some(Ok(e)) => e,
                            Some(Err(e)) => { let _ = tx.send(Err(e)).await; return; }
                            None => return,
                        };

                        let parsed: Result<StreamEvent, _> =
                            serde_json::from_str(&event.data);
                        let stream_event = match parsed {
                            Ok(e) => e,
                            Err(e) => {
                                let _ = tx
                                    .send(Err(LlmError::StreamError(e.to_string())))
                                    .await;
                                return;
                            }
                        };

                        let delta = match stream_event {
                            StreamEvent::ContentBlockStart { index, content_block } => {
                                while blocks.len() <= index {
                                    blocks.push(BlockState {
                                        block_type: String::new(),
                                        tool_id: None,
                                        tool_name: None,
                                        tool_json: String::new(),
                                    });
                                }
                                blocks[index].block_type = content_block.block_type;
                                blocks[index].tool_id = content_block.id;
                                blocks[index].tool_name = content_block.name;
                                None
                            }
                            StreamEvent::ContentBlockDelta { index, delta } => {
                                match delta {
                                    DeltaInfo::TextDelta { text } => Some(CompletionDelta {
                                        text: Some(text),
                                        thinking: None,
                                        tool_use: None,
                                        finish_reason: None,
                                    }),
                                    DeltaInfo::ThinkingDelta { thinking } => {
                                        Some(CompletionDelta {
                                            text: None,
                                            thinking: Some(thinking),
                                            tool_use: None,
                                            finish_reason: None,
                                        })
                                    }
                                    DeltaInfo::InputJsonDelta { partial_json } => {
                                        if let Some(block) = blocks.get_mut(index) {
                                            block.tool_json.push_str(&partial_json);
                                        }
                                        None
                                    }
                                }
                            }
                            StreamEvent::ContentBlockStop { index } => {
                                blocks.get(index).and_then(|block| {
                                    (block.block_type == "tool_use").then(|| {
                                        CompletionDelta {
                                            text: None,
                                            thinking: None,
                                            tool_use: Some(ToolUseDelta {
                                                id: block.tool_id.clone().unwrap_or_default(),
                                                name: block.tool_name.clone().unwrap_or_default(),
                                                input_json: block.tool_json.clone(),
                                            }),
                                            finish_reason: None,
                                        }
                                    })
                                })
                            }
                            StreamEvent::MessageDelta { delta: msg_delta } => {
                                msg_delta.stop_reason.map(|r| {
                                    let reason = match r.as_str() {
                                        "end_turn" | "stop" => FinishReason::Stop,
                                        "max_tokens" => FinishReason::Length,
                                        "tool_use" => FinishReason::ToolUse,
                                        _ => FinishReason::Stop,
                                    };
                                    CompletionDelta {
                                        text: None,
                                        thinking: None,
                                        tool_use: None,
                                        finish_reason: Some(reason),
                                    }
                                })
                            }
                            StreamEvent::Error { error } => {
                                let _ = tx
                                    .send(Err(LlmError::ApiError(error.message)))
                                    .await;
                                return;
                            }
                            _ => None,
                        };

                        if let Some(d) = delta {
                            if tx.send(Ok(d)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn count_tokens(&self, messages: &[Message]) -> Result<u32, LlmError> {
        let total_chars: usize = messages
            .iter()
            .flat_map(|m| m.content.iter())
            .map(|block| match block {
                ContentBlock::Text { text } | ContentBlock::Thinking { text } => text.len(),
                ContentBlock::ToolUse { input, .. } => input.to_string().len(),
                ContentBlock::ToolResult { content, .. } => content.len(),
                ContentBlock::Image { data, .. } => data.len() / 3,
            })
            .sum();
        Ok((total_chars / 4) as u32)
    }

    fn model_info(&self) -> ModelInfo {
        ModelInfo {
            id: self.model.clone(),
            name: self.model.clone(),
            context_window: 200_000,
            provider: "anthropic".to_string(),
            supports_tools: true,
            supports_streaming: true,
            supports_thinking: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_messages_extracts_system() {
        let messages = vec![
            Message {
                id: MessageId::new(),
                role: Role::System,
                content: vec![ContentBlock::Text {
                    text: "You are helpful.".into(),
                }],
                created_at: chrono::Utc::now(),
                token_count: None,
            },
            Message {
                id: MessageId::new(),
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "Hello".into(),
                }],
                created_at: chrono::Utc::now(),
                token_count: None,
            },
        ];

        let (system, api_msgs) = convert_messages(&messages);
        assert_eq!(system.as_deref(), Some("You are helpful."));
        assert_eq!(api_msgs.len(), 1);
        assert_eq!(api_msgs[0].role, "user");
    }

    #[test]
    fn convert_tools_maps_correctly() {
        let tools = vec![ToolDefinition {
            name: "search".into(),
            description: "Search the web".into(),
            parameters: serde_json::json!({"type": "object"}),
        }];
        let api_tools = convert_tools(&tools);
        assert_eq!(api_tools.len(), 1);
        assert_eq!(api_tools[0].name, "search");
    }

    #[test]
    fn model_info_anthropic() {
        let backend =
            AnthropicBackend::new("key".into(), "claude-sonnet-4-5-20250929".into(), None);
        let info = backend.model_info();
        assert_eq!(info.provider, "anthropic");
        assert!(info.supports_thinking);
    }

    #[test]
    fn token_count_estimate() {
        let backend =
            AnthropicBackend::new("key".into(), "claude-sonnet-4-5-20250929".into(), None);
        let messages = vec![Message {
            id: MessageId::new(),
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "a".repeat(400),
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        }];

        let rt = tokio::runtime::Runtime::new().unwrap();
        let count = rt.block_on(backend.count_tokens(&messages)).unwrap();
        assert_eq!(count, 100); // 400 chars / 4
    }

    #[test]
    fn convert_messages_coerces_non_object_tool_input() {
        let messages = vec![Message {
            id: MessageId::new(),
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "t1".into(),
                name: "digest_file".into(),
                input: serde_json::Value::String("/tmp/x.pdf".into()),
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        }];

        let (_system, api_msgs) = convert_messages(&messages);
        assert_eq!(api_msgs.len(), 1);
        match &api_msgs[0].content[0] {
            ApiContentBlock::ToolUse { input, .. } => {
                assert!(input.is_object(), "tool_use.input must be object");
            }
            _ => panic!("expected tool_use block"),
        }
    }

    #[tokio::test]
    async fn stream_event_text_delta_parses() {
        let json = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        match event {
            StreamEvent::ContentBlockDelta {
                delta: DeltaInfo::TextDelta { text },
                ..
            } => assert_eq!(text, "Hello"),
            _ => panic!("expected ContentBlockDelta"),
        }
    }

    #[tokio::test]
    async fn stream_event_thinking_delta_parses() {
        let json = r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Let me think..."}}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        match event {
            StreamEvent::ContentBlockDelta {
                delta: DeltaInfo::ThinkingDelta { thinking },
                ..
            } => assert_eq!(thinking, "Let me think..."),
            _ => panic!("expected ThinkingDelta"),
        }
    }

    #[tokio::test]
    async fn stream_event_message_delta_stop_reason() {
        let json = r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        match event {
            StreamEvent::MessageDelta { delta } => {
                assert_eq!(delta.stop_reason.as_deref(), Some("end_turn"));
            }
            _ => panic!("expected MessageDelta"),
        }
    }
}
