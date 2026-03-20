use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use encmind_core::error::ChannelError;
use encmind_core::types::{InboundMessage, OutboundMessage};

/// A channel transform that can modify inbound/outbound messages.
/// Only content and attachments may be mutated; routing identity fields
/// (channel, sender_id, timestamp) are frozen by the TransformChain.
#[async_trait]
pub trait ChannelTransform: Send + Sync {
    /// Human-readable name for logging/debugging.
    fn name(&self) -> &str;

    /// Transform an inbound message. Return `None` to drop the message.
    async fn transform_inbound(
        &self,
        msg: InboundMessage,
    ) -> Result<Option<InboundMessage>, ChannelError>;

    /// Transform an outbound message. Return `None` to drop the message.
    async fn transform_outbound(
        &self,
        msg: OutboundMessage,
    ) -> Result<Option<OutboundMessage>, ChannelError>;
}

/// An ordered chain of transforms applied to messages on a specific channel.
/// Enforces identity freeze: routing fields are restored after each transform step.
#[derive(Clone)]
pub struct TransformChain {
    transforms: Vec<Arc<dyn ChannelTransform>>,
    inbound_fail_open: bool,
    outbound_fail_open: bool,
}

impl TransformChain {
    pub fn new(
        transforms: Vec<Arc<dyn ChannelTransform>>,
        inbound_fail_open: bool,
        outbound_fail_open: bool,
    ) -> Self {
        Self {
            transforms,
            inbound_fail_open,
            outbound_fail_open,
        }
    }

    /// Apply inbound transforms in order. Freezes routing identity fields
    /// (channel, sender_id, timestamp) — any mutation by the transform is
    /// silently reverted after each step.
    pub async fn apply_inbound(
        &self,
        msg: InboundMessage,
    ) -> Result<Option<InboundMessage>, ChannelError> {
        let frozen_channel = msg.channel.clone();
        let frozen_sender_id = msg.sender_id.clone();
        let frozen_timestamp = msg.timestamp;

        let mut current = msg;
        for transform in &self.transforms {
            match transform.transform_inbound(current.clone()).await {
                Ok(Some(mut transformed)) => {
                    // Restore frozen identity fields
                    transformed.channel = frozen_channel.clone();
                    transformed.sender_id = frozen_sender_id.clone();
                    transformed.timestamp = frozen_timestamp;
                    current = transformed;
                }
                Ok(None) => {
                    // Transform dropped the message
                    return Ok(None);
                }
                Err(e) => {
                    warn!(
                        transform = transform.name(),
                        error = %e,
                        direction = "inbound",
                        "channel_transform.error"
                    );
                    if self.inbound_fail_open {
                        // Continue with unmodified message
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(Some(current))
    }

    /// Apply outbound transforms in order. Same identity-freeze guarantee
    /// (outbound messages don't have routing fields, so only content/attachments survive).
    pub async fn apply_outbound(
        &self,
        msg: OutboundMessage,
    ) -> Result<Option<OutboundMessage>, ChannelError> {
        let mut current = msg;
        for transform in &self.transforms {
            match transform.transform_outbound(current.clone()).await {
                Ok(Some(transformed)) => {
                    current = transformed;
                }
                Ok(None) => {
                    return Ok(None);
                }
                Err(e) => {
                    warn!(
                        transform = transform.name(),
                        error = %e,
                        direction = "outbound",
                        "channel_transform.error"
                    );
                    if self.outbound_fail_open {
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(Some(current))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use encmind_core::types::ContentBlock;

    fn make_inbound(channel: &str, text: &str) -> InboundMessage {
        InboundMessage {
            channel: channel.into(),
            sender_id: "user-1".into(),
            content: vec![ContentBlock::Text { text: text.into() }],
            attachments: vec![],
            timestamp: Utc::now(),
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        }
    }

    fn make_outbound(text: &str) -> OutboundMessage {
        OutboundMessage {
            content: vec![ContentBlock::Text { text: text.into() }],
            attachments: vec![],
            thread_id: None,
            reply_to_id: None,
            subject: None,
        }
    }

    /// A passthrough transform that doesn't modify messages.
    struct PassthroughTransform;

    #[async_trait]
    impl ChannelTransform for PassthroughTransform {
        fn name(&self) -> &str {
            "passthrough"
        }
        async fn transform_inbound(
            &self,
            msg: InboundMessage,
        ) -> Result<Option<InboundMessage>, ChannelError> {
            Ok(Some(msg))
        }
        async fn transform_outbound(
            &self,
            msg: OutboundMessage,
        ) -> Result<Option<OutboundMessage>, ChannelError> {
            Ok(Some(msg))
        }
    }

    /// A transform that drops all messages.
    struct DropTransform;

    #[async_trait]
    impl ChannelTransform for DropTransform {
        fn name(&self) -> &str {
            "drop"
        }
        async fn transform_inbound(
            &self,
            _msg: InboundMessage,
        ) -> Result<Option<InboundMessage>, ChannelError> {
            Ok(None)
        }
        async fn transform_outbound(
            &self,
            _msg: OutboundMessage,
        ) -> Result<Option<OutboundMessage>, ChannelError> {
            Ok(None)
        }
    }

    /// A transform that always errors.
    struct FailingTransform;

    #[async_trait]
    impl ChannelTransform for FailingTransform {
        fn name(&self) -> &str {
            "failing"
        }
        async fn transform_inbound(
            &self,
            _msg: InboundMessage,
        ) -> Result<Option<InboundMessage>, ChannelError> {
            Err(ChannelError::SendFailed("forced failure".into()))
        }
        async fn transform_outbound(
            &self,
            _msg: OutboundMessage,
        ) -> Result<Option<OutboundMessage>, ChannelError> {
            Err(ChannelError::SendFailed("forced failure".into()))
        }
    }

    /// A transform that mutates routing identity fields (should be reverted by chain).
    struct SpoofTransform;

    #[async_trait]
    impl ChannelTransform for SpoofTransform {
        fn name(&self) -> &str {
            "spoof"
        }
        async fn transform_inbound(
            &self,
            mut msg: InboundMessage,
        ) -> Result<Option<InboundMessage>, ChannelError> {
            msg.channel = "spoofed-channel".into();
            msg.sender_id = "spoofed-sender".into();
            msg.timestamp = chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc);
            // Also modify content (this should survive)
            msg.content = vec![ContentBlock::Text {
                text: "spoofed-content".into(),
            }];
            Ok(Some(msg))
        }
        async fn transform_outbound(
            &self,
            _msg: OutboundMessage,
        ) -> Result<Option<OutboundMessage>, ChannelError> {
            Ok(Some(OutboundMessage {
                content: vec![ContentBlock::Text {
                    text: "spoofed-out".into(),
                }],
                attachments: vec![],
                thread_id: None,
                reply_to_id: None,
                subject: None,
            }))
        }
    }

    #[tokio::test]
    async fn inbound_passthrough() {
        let chain = TransformChain::new(vec![Arc::new(PassthroughTransform)], true, true);
        let msg = make_inbound("telegram", "hello");
        let result = chain.apply_inbound(msg).await.unwrap();
        assert!(result.is_some());
        let out = result.unwrap();
        assert_eq!(out.channel, "telegram");
        match &out.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn inbound_drop() {
        let chain = TransformChain::new(vec![Arc::new(DropTransform)], true, true);
        let msg = make_inbound("telegram", "hello");
        let result = chain.apply_inbound(msg).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn outbound_passthrough() {
        let chain = TransformChain::new(vec![Arc::new(PassthroughTransform)], true, true);
        let msg = make_outbound("goodbye");
        let result = chain.apply_outbound(msg).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn outbound_drop() {
        let chain = TransformChain::new(vec![Arc::new(DropTransform)], true, true);
        let msg = make_outbound("goodbye");
        let result = chain.apply_outbound(msg).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn freezes_routing_identity() {
        let chain = TransformChain::new(vec![Arc::new(SpoofTransform)], true, true);
        let original_ts = Utc::now();
        let msg = InboundMessage {
            channel: "telegram".into(),
            sender_id: "real-user".into(),
            content: vec![ContentBlock::Text {
                text: "original".into(),
            }],
            attachments: vec![],
            timestamp: original_ts,
            is_dm: None,
            is_mention: false,
            thread_id: None,
            reply_to_id: None,
            metadata: Default::default(),
        };
        let result = chain.apply_inbound(msg).await.unwrap().unwrap();

        // Routing fields must be frozen
        assert_eq!(result.channel, "telegram");
        assert_eq!(result.sender_id, "real-user");
        assert_eq!(result.timestamp, original_ts);

        // Content mutation should survive
        match &result.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "spoofed-content"),
            _ => panic!("expected text"),
        }
    }

    #[tokio::test]
    async fn inbound_fail_open_on_error() {
        let chain = TransformChain::new(
            vec![Arc::new(FailingTransform)],
            true, // fail-open
            true,
        );
        let msg = make_inbound("telegram", "hello");
        let result = chain.apply_inbound(msg).await.unwrap();
        assert!(result.is_some(), "fail-open should pass through on error");
    }

    #[tokio::test]
    async fn inbound_fail_closed_on_error() {
        let chain = TransformChain::new(
            vec![Arc::new(FailingTransform)],
            false, // fail-closed
            false,
        );
        let msg = make_inbound("telegram", "hello");
        let result = chain.apply_inbound(msg).await;
        assert!(result.is_err(), "fail-closed should propagate error");
    }

    #[tokio::test]
    async fn outbound_fail_open_on_error() {
        let chain = TransformChain::new(
            vec![Arc::new(FailingTransform)],
            true,
            true, // fail-open outbound
        );
        let msg = make_outbound("goodbye");
        let result = chain.apply_outbound(msg).await.unwrap();
        assert!(result.is_some(), "fail-open should pass through on error");
    }

    #[tokio::test]
    async fn outbound_fail_closed_on_error() {
        let chain = TransformChain::new(
            vec![Arc::new(FailingTransform)],
            false,
            false, // fail-closed outbound
        );
        let msg = make_outbound("goodbye");
        let result = chain.apply_outbound(msg).await;
        assert!(result.is_err(), "fail-closed should propagate error");
    }
}
