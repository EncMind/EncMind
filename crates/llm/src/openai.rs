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

const DEFAULT_BASE_URL: &str = "https://api.openai.com";

/// OpenAI Chat Completions API backend.
pub struct OpenAiBackend {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl OpenAiBackend {
    pub fn new(api_key: String, model: String, base_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            base_url: base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        }
    }
}

// ── Request types ──

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    stream: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ChatTool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stop: Vec<String>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ChatToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
struct ChatTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: ChatFunction,
}

#[derive(Serialize)]
struct ChatFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Serialize)]
struct ChatToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    function: ChatToolCallFunction,
}

#[derive(Serialize)]
struct ChatToolCallFunction {
    name: String,
    arguments: String,
}

// ── Response types ──

#[derive(Deserialize)]
struct ChatChunk {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    delta: ChatDelta,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatDelta {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<ChatToolCallDelta>>,
}

#[derive(Deserialize)]
struct ChatToolCallDelta {
    #[serde(default)]
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<ChatToolCallFunctionDelta>,
}

#[derive(Deserialize)]
struct ChatToolCallFunctionDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

fn convert_messages(messages: &[Message]) -> Vec<ChatMessage> {
    let mut chat_messages = Vec::new();

    for msg in messages {
        match msg.role {
            Role::System => {
                let text = extract_text(&msg.content);
                chat_messages.push(ChatMessage {
                    role: "system".into(),
                    content: Some(text),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            Role::User => {
                let text = extract_text(&msg.content);
                chat_messages.push(ChatMessage {
                    role: "user".into(),
                    content: Some(text),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            Role::Assistant => {
                let text = extract_text(&msg.content);
                let tool_calls: Vec<ChatToolCall> = msg
                    .content
                    .iter()
                    .filter_map(|b| match b {
                        ContentBlock::ToolUse { id, name, input } => Some(ChatToolCall {
                            id: id.clone(),
                            call_type: "function".into(),
                            function: ChatToolCallFunction {
                                name: name.clone(),
                                arguments: input.to_string(),
                            },
                        }),
                        _ => None,
                    })
                    .collect();

                chat_messages.push(ChatMessage {
                    role: "assistant".into(),
                    content: if text.is_empty() { None } else { Some(text) },
                    tool_calls: if tool_calls.is_empty() {
                        None
                    } else {
                        Some(tool_calls)
                    },
                    tool_call_id: None,
                });
            }
            Role::Tool => {
                for block in &msg.content {
                    if let ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        chat_messages.push(ChatMessage {
                            role: "tool".into(),
                            content: Some(content.clone()),
                            tool_calls: None,
                            tool_call_id: Some(tool_use_id.clone()),
                        });
                    }
                }
            }
        }
    }

    chat_messages
}

fn extract_text(content: &[ContentBlock]) -> String {
    content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn convert_tools(tools: &[ToolDefinition]) -> Vec<ChatTool> {
    tools
        .iter()
        .map(|t| ChatTool {
            tool_type: "function".into(),
            function: ChatFunction {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters: t.parameters.clone(),
            },
        })
        .collect()
}

/// Track accumulated tool call state across streaming chunks.
struct ToolCallAccumulator {
    id: String,
    name: String,
    arguments: String,
}

#[async_trait]
impl LlmBackend for OpenAiBackend {
    async fn complete(
        &self,
        messages: &[Message],
        params: CompletionParams,
        cancel: CancellationToken,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<CompletionDelta, LlmError>> + Send>>, LlmError>
    {
        let chat_messages = convert_messages(messages);
        let selected_model = params.model.clone().unwrap_or_else(|| self.model.clone());

        let request = ChatRequest {
            model: selected_model,
            messages: chat_messages,
            max_tokens: Some(params.max_tokens),
            temperature: Some(params.temperature),
            stream: true,
            tools: convert_tools(&params.tools),
            stop: params.stop_sequences.clone(),
        };

        let url = format!("{}/v1/chat/completions", self.base_url);
        let mut req = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json");
        if let Some(ref id) = params.request_id {
            req = req.header("x-request-id", id);
        }
        let response = req
            .json(&request)
            .send()
            .await
            .map_err(|e| LlmError::ApiError(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            // Only numeric delta-seconds; HTTP-date format ignored.
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(crate::parse_retry_after);
            let body = response.text().await.unwrap_or_default();
            if status.as_u16() == 429 {
                return Err(LlmError::RateLimited {
                    retry_after_secs: retry_after,
                });
            }
            return Err(LlmError::ApiError(format!("HTTP {status}: {body}")));
        }

        let byte_stream = response.bytes_stream();
        let sse_stream = sse::parse_sse(byte_stream);

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn(async move {
            let mut stream = Box::pin(sse_stream);
            let mut tool_calls: Vec<ToolCallAccumulator> = Vec::new();

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
                            None => {
                                // Stream ended — flush accumulated tool calls
                                for tc in &tool_calls {
                                    let _ = tx.send(Ok(CompletionDelta {
                                        text: None,
                                        thinking: None,
                                        tool_use: Some(ToolUseDelta {
                                            id: tc.id.clone(),
                                            name: tc.name.clone(),
                                            input_json: tc.arguments.clone(),
                                        }),
                                        finish_reason: None,
                                    })).await;
                                }
                                return;
                            }
                        };

                        // OpenAI terminates with "data: [DONE]"
                        if event.data.trim() == "[DONE]" {
                            // Flush tool calls
                            for tc in &tool_calls {
                                let _ = tx.send(Ok(CompletionDelta {
                                    text: None,
                                    thinking: None,
                                    tool_use: Some(ToolUseDelta {
                                        id: tc.id.clone(),
                                        name: tc.name.clone(),
                                        input_json: tc.arguments.clone(),
                                    }),
                                    finish_reason: None,
                                })).await;
                            }
                            return;
                        }

                        let chunk: ChatChunk = match serde_json::from_str(&event.data) {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = tx.send(Err(LlmError::StreamError(e.to_string()))).await;
                                return;
                            }
                        };

                        for choice in &chunk.choices {
                            // Text content
                            if let Some(ref text) = choice.delta.content {
                                if tx.send(Ok(CompletionDelta {
                                    text: Some(text.clone()),
                                    thinking: None,
                                    tool_use: None,
                                    finish_reason: None,
                                })).await.is_err() {
                                    return;
                                }
                            }

                            // Tool call deltas — accumulate
                            if let Some(ref tcs) = choice.delta.tool_calls {
                                for tc_delta in tcs {
                                    while tool_calls.len() <= tc_delta.index {
                                        tool_calls.push(ToolCallAccumulator {
                                            id: String::new(),
                                            name: String::new(),
                                            arguments: String::new(),
                                        });
                                    }
                                    let acc = &mut tool_calls[tc_delta.index];
                                    if let Some(ref id) = tc_delta.id {
                                        acc.id = id.clone();
                                    }
                                    if let Some(ref f) = tc_delta.function {
                                        if let Some(ref name) = f.name {
                                            acc.name = name.clone();
                                        }
                                        if let Some(ref args) = f.arguments {
                                            acc.arguments.push_str(args);
                                        }
                                    }
                                }
                            }

                            // Finish reason
                            if let Some(ref reason) = choice.finish_reason {
                                let r = match reason.as_str() {
                                    "stop" => FinishReason::Stop,
                                    "length" => FinishReason::Length,
                                    "tool_calls" => FinishReason::ToolUse,
                                    _ => FinishReason::Stop,
                                };
                                let _ = tx.send(Ok(CompletionDelta {
                                    text: None,
                                    thinking: None,
                                    tool_use: None,
                                    finish_reason: Some(r),
                                })).await;
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
            context_window: 128_000,
            provider: "openai".to_string(),
            supports_tools: true,
            supports_streaming: true,
            supports_thinking: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_messages_includes_system() {
        let messages = vec![
            Message {
                id: MessageId::new(),
                role: Role::System,
                content: vec![ContentBlock::Text {
                    text: "Be helpful.".into(),
                }],
                created_at: chrono::Utc::now(),
                token_count: None,
            },
            Message {
                id: MessageId::new(),
                role: Role::User,
                content: vec![ContentBlock::Text { text: "Hi".into() }],
                created_at: chrono::Utc::now(),
                token_count: None,
            },
        ];

        let chat_msgs = convert_messages(&messages);
        assert_eq!(chat_msgs.len(), 2);
        assert_eq!(chat_msgs[0].role, "system");
        assert_eq!(chat_msgs[0].content.as_deref(), Some("Be helpful."));
        assert_eq!(chat_msgs[1].role, "user");
    }

    #[test]
    fn convert_tool_result_messages() {
        let messages = vec![Message {
            id: MessageId::new(),
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "call_123".into(),
                content: "result text".into(),
                is_error: false,
            }],
            created_at: chrono::Utc::now(),
            token_count: None,
        }];

        let chat_msgs = convert_messages(&messages);
        assert_eq!(chat_msgs.len(), 1);
        assert_eq!(chat_msgs[0].role, "tool");
        assert_eq!(chat_msgs[0].tool_call_id.as_deref(), Some("call_123"));
    }

    #[test]
    fn convert_tools_wraps_in_function() {
        let tools = vec![ToolDefinition {
            name: "calc".into(),
            description: "Calculate".into(),
            parameters: serde_json::json!({}),
        }];
        let chat_tools = convert_tools(&tools);
        assert_eq!(chat_tools[0].tool_type, "function");
        assert_eq!(chat_tools[0].function.name, "calc");
    }

    #[test]
    fn model_info_openai() {
        let backend = OpenAiBackend::new("key".into(), "gpt-4".into(), None);
        let info = backend.model_info();
        assert_eq!(info.provider, "openai");
        assert!(!info.supports_thinking);
    }

    #[test]
    fn chat_chunk_parses() {
        let json = r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#;
        let chunk: ChatChunk = serde_json::from_str(json).unwrap();
        assert_eq!(chunk.choices.len(), 1);
        assert_eq!(chunk.choices[0].delta.content.as_deref(), Some("Hello"));
        assert!(chunk.choices[0].finish_reason.is_none());
    }

    #[test]
    fn chat_chunk_with_finish_reason() {
        let json = r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
        let chunk: ChatChunk = serde_json::from_str(json).unwrap();
        assert_eq!(chunk.choices[0].finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn chat_chunk_with_tool_call() {
        let json = r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"search","arguments":"{\"q\":"}}]},"finish_reason":null}]}"#;
        let chunk: ChatChunk = serde_json::from_str(json).unwrap();
        let tc = &chunk.choices[0].delta.tool_calls.as_ref().unwrap()[0];
        assert_eq!(tc.id.as_deref(), Some("call_1"));
        assert_eq!(
            tc.function.as_ref().unwrap().name.as_deref(),
            Some("search")
        );
    }
}
