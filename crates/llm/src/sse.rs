use bytes::Bytes;
use futures::Stream;
use tokio_stream::StreamExt;

use encmind_core::error::LlmError;

/// A parsed Server-Sent Event.
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: String,
}

/// Parse a byte stream into SSE events.
///
/// Handles the standard SSE format: `event:`, `data:`, comments, and
/// blank-line delimiters.
pub fn parse_sse<S, E>(byte_stream: S) -> impl Stream<Item = Result<SseEvent, LlmError>> + Send
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: std::error::Error + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(32);

    tokio::spawn(async move {
        let mut stream = Box::pin(byte_stream);
        let mut buffer = String::new();
        let mut current_event_type: Option<String> = None;
        let mut current_data: Vec<String> = Vec::new();

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(b) => String::from_utf8_lossy(&b).to_string(),
                Err(e) => {
                    let _ = tx.send(Err(LlmError::StreamError(e.to_string()))).await;
                    return;
                }
            };

            buffer.push_str(&chunk);

            while let Some(pos) = buffer.find('\n') {
                let line = buffer[..pos].trim_end_matches('\r').to_string();
                buffer = buffer[pos + 1..].to_string();

                if line.is_empty() {
                    if !current_data.is_empty() {
                        let event = SseEvent {
                            event_type: current_event_type.take(),
                            data: current_data.join("\n"),
                        };
                        current_data.clear();
                        if tx.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                } else if line.starts_with(':') {
                    // Comment — ignore
                } else if let Some(rest) = line.strip_prefix("data:") {
                    current_data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
                } else if let Some(rest) = line.strip_prefix("event:") {
                    current_event_type = Some(rest.strip_prefix(' ').unwrap_or(rest).to_string());
                }
                // id: and retry: fields are not used
            }
        }

        // Flush remaining data
        if !current_data.is_empty() {
            let event = SseEvent {
                event_type: current_event_type.take(),
                data: current_data.join("\n"),
            };
            let _ = tx.send(Ok(event)).await;
        }
    });

    tokio_stream::wrappers::ReceiverStream::new(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    fn mock_stream(
        data: &str,
    ) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
        let bytes = Bytes::from(data.to_string());
        stream::once(async move { Ok(bytes) })
    }

    #[tokio::test]
    async fn parse_single_event() {
        let events: Vec<_> = parse_sse(mock_stream("data: hello\n\n")).collect().await;
        assert_eq!(events.len(), 1);
        let event = events[0].as_ref().unwrap();
        assert_eq!(event.data, "hello");
        assert!(event.event_type.is_none());
    }

    #[tokio::test]
    async fn parse_event_with_type() {
        let events: Vec<_> = parse_sse(mock_stream("event: message\ndata: hello\n\n"))
            .collect()
            .await;
        assert_eq!(events.len(), 1);
        let event = events[0].as_ref().unwrap();
        assert_eq!(event.event_type.as_deref(), Some("message"));
        assert_eq!(event.data, "hello");
    }

    #[tokio::test]
    async fn parse_multiple_events() {
        let raw = "data: first\n\ndata: second\n\n";
        let events: Vec<_> = parse_sse(mock_stream(raw)).collect().await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].as_ref().unwrap().data, "first");
        assert_eq!(events[1].as_ref().unwrap().data, "second");
    }

    #[tokio::test]
    async fn parse_multiline_data() {
        let raw = "data: line1\ndata: line2\n\n";
        let events: Vec<_> = parse_sse(mock_stream(raw)).collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().data, "line1\nline2");
    }

    #[tokio::test]
    async fn ignore_comments() {
        let raw = ": this is a comment\ndata: hello\n\n";
        let events: Vec<_> = parse_sse(mock_stream(raw)).collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().data, "hello");
    }

    #[tokio::test]
    async fn parse_chunked_delivery() {
        // Data arrives in two chunks, split mid-event
        let chunk1 = Bytes::from("data: hel");
        let chunk2 = Bytes::from("lo\n\n");
        let s = stream::iter(vec![Ok::<_, std::io::Error>(chunk1), Ok(chunk2)]);
        let events: Vec<_> = parse_sse(s).collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().data, "hello");
    }

    #[tokio::test]
    async fn empty_stream_yields_no_events() {
        let events: Vec<_> = parse_sse(mock_stream("")).collect().await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn data_without_space_after_colon() {
        let events: Vec<_> = parse_sse(mock_stream("data:hello\n\n")).collect().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().data, "hello");
    }
}
