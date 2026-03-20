use encmind_core::types::{ContentBlock, InboundMessage};

pub(crate) fn has_non_empty_text(msg: &InboundMessage) -> bool {
    msg.content.iter().any(|block| {
        matches!(
            block,
            ContentBlock::Text { text } if !text.trim().is_empty()
        )
    })
}

pub(crate) fn set_media_unavailable_fallback(msg: &mut InboundMessage, note: &str) {
    if has_non_empty_text(msg) || !msg.attachments.is_empty() {
        return;
    }
    msg.content = vec![ContentBlock::Text {
        text: format!("Received a media message, but attachments could not be retrieved ({note})."),
    }];
}
