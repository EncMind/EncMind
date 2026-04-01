//! Message normalization pipeline — validates and fixes messages before LLM calls.
//!
//! Prevents `invalid_request_error` 400s caused by:
//! - tool_use input that isn't a JSON object
//! - tool_result without a matching tool_use_id in the conversation
//! - consecutive messages with the same role
//! - empty content blocks

use std::collections::HashSet;

use encmind_core::types::{ContentBlock, Message, MessageId, Role};
use tracing::warn;

/// Validation issues found and auto-fixed by [`normalize_for_api`].
#[derive(Debug, Default)]
pub struct NormalizationReport {
    /// Number of tool_use inputs coerced from non-object to empty object.
    pub tool_use_inputs_coerced: u32,
    /// Number of orphaned tool_results removed (no matching tool_use_id).
    pub orphaned_tool_results_removed: u32,
    /// Number of consecutive same-role message pairs merged.
    pub consecutive_roles_merged: u32,
    /// Number of empty messages removed.
    pub empty_messages_removed: u32,
    /// Number of content blocks dropped for role incompatibility.
    pub role_incompatible_blocks_dropped: u32,
    /// Number of synthetic error tool_results injected for unmatched tool_use blocks.
    pub synthetic_tool_results_injected: u32,
    /// Number of duplicate tool_use blocks removed (same ID seen earlier).
    pub duplicate_tool_uses_removed: u32,
    /// Number of duplicate tool_result blocks removed (same tool_use_id seen earlier).
    pub duplicate_tool_results_removed: u32,
}

/// Placeholder content for synthetic tool_result blocks injected when a
/// tool_use has no matching result (crash recovery, stream interruption).
const SYNTHETIC_TOOL_RESULT_PLACEHOLDER: &str = "[tool did not return a result]";

/// Allowed content block types per role.
fn is_block_allowed_for_role(role: &Role, block: &ContentBlock) -> bool {
    match role {
        Role::User => matches!(block, ContentBlock::Text { .. } | ContentBlock::Image { .. }),
        Role::Assistant => matches!(
            block,
            ContentBlock::Text { .. }
                | ContentBlock::Thinking { .. }
                | ContentBlock::ToolUse { .. }
        ),
        Role::Tool => matches!(block, ContentBlock::ToolResult { .. }),
        Role::System => matches!(block, ContentBlock::Text { .. }),
    }
}

/// Normalize a message list in-place before sending to the LLM API.
///
/// This is the single enforcement point — called before every `LlmBackend::complete()`.
/// Returns a report of what was fixed (for diagnostics/logging).
pub fn normalize_for_api(messages: &mut Vec<Message>) -> NormalizationReport {
    let mut report = NormalizationReport::default();

    // Pass 1: Fix tool_use inputs (must be JSON objects).
    for msg in messages.iter_mut() {
        for block in msg.content.iter_mut() {
            if let ContentBlock::ToolUse { id, name, input } = block {
                if !input.is_object() {
                    warn!(
                        tool_use_id = %id,
                        tool_name = %name,
                        input_type = %json_type_name(input),
                        "normalizing tool_use input to empty object"
                    );
                    *input = serde_json::json!({});
                    report.tool_use_inputs_coerced += 1;
                }
            }
        }
    }

    // Pass 2: Drop content blocks that are invalid for their message's role.
    for msg in messages.iter_mut() {
        let before_len = msg.content.len();
        let role = msg.role.clone();
        msg.content.retain(|block| {
            let allowed = is_block_allowed_for_role(&role, block);
            if !allowed {
                warn!(
                    role = ?role,
                    block_type = %block_type_name(block),
                    "dropping content block incompatible with message role"
                );
            }
            allowed
        });
        report.role_incompatible_blocks_dropped += (before_len - msg.content.len()) as u32;
    }

    // Pass 3: Dedup duplicate tool_use IDs (cross-message).
    // If the same tool_use ID appears in multiple messages (corruption, compaction
    // artifact), the API rejects with "tool_use ids must be unique".
    {
        let mut seen_tool_use_ids = HashSet::new();
        for msg in messages.iter_mut() {
            let before_len = msg.content.len();
            msg.content.retain(|block| {
                if let ContentBlock::ToolUse { id, .. } = block {
                    if !seen_tool_use_ids.insert(id.clone()) {
                        warn!(
                            tool_use_id = %id,
                            "removing duplicate tool_use — ID already seen in earlier message"
                        );
                        return false;
                    }
                }
                true
            });
            report.duplicate_tool_uses_removed += (before_len - msg.content.len()) as u32;
        }
    }

    // Pass 4: Dedup duplicate tool_results + remove orphans.
    // Also collect tool_use IDs from prior messages for orphan detection and
    // synthetic injection in pass 5.
    {
        let mut known_tool_use_ids = HashSet::new();
        let mut seen_tool_result_ids = HashSet::new();
        let mut i = 0;
        while i < messages.len() {
            // Check tool_results BEFORE collecting tool_use IDs from this message.
            // Count duplicates and orphans separately.
            let mut dup_count = 0u32;
            let mut orphan_count = 0u32;
            messages[i].content.retain(|block| {
                if let ContentBlock::ToolResult { tool_use_id, .. } = block {
                    // Dedup: same tool_use_id answered twice.
                    if !seen_tool_result_ids.insert(tool_use_id.clone()) {
                        warn!(
                            tool_use_id = %tool_use_id,
                            "removing duplicate tool_result — already seen"
                        );
                        dup_count += 1;
                        return false;
                    }
                    // Orphan: no matching tool_use in prior messages.
                    if !known_tool_use_ids.contains(tool_use_id) {
                        warn!(
                            tool_use_id = %tool_use_id,
                            "removing orphaned tool_result — no matching tool_use_id in prior messages"
                        );
                        orphan_count += 1;
                        return false;
                    }
                }
                true
            });
            report.duplicate_tool_results_removed += dup_count;
            report.orphaned_tool_results_removed += orphan_count;

            // Collect tool_use IDs from this message for future messages.
            for block in &messages[i].content {
                if let ContentBlock::ToolUse { id, .. } = block {
                    known_tool_use_ids.insert(id.clone());
                }
            }

            i += 1;
        }
    }

    // Pass 5: Inject synthetic error tool_results for unmatched tool_use blocks.
    // If a tool_use has no matching tool_result anywhere in the conversation,
    // the API returns 400 ("every tool_use must have a corresponding tool_result").
    // This happens on crash recovery or stream interruption.
    //
    // Insertion order matters: synthetic results must follow the assistant message
    // containing their tool_use, before the next non-tool turn. This is required
    // by OpenAI and preferred by Anthropic for correct tool call sequencing.
    {
        // First pass: collect all tool_result IDs.
        let mut all_tool_result_ids = HashSet::new();
        for msg in messages.iter() {
            for block in &msg.content {
                if let ContentBlock::ToolResult { tool_use_id, .. } = block {
                    all_tool_result_ids.insert(tool_use_id.clone());
                }
            }
        }

        // Second pass: walk messages, find assistant messages with unmatched
        // tool_use blocks, and insert synthetic Tool messages right after them.
        let mut i = 0;
        while i < messages.len() {
            if matches!(messages[i].role, Role::Assistant) {
                let missing_ids: Vec<String> = messages[i]
                    .content
                    .iter()
                    .filter_map(|block| {
                        if let ContentBlock::ToolUse { id, .. } = block {
                            if !all_tool_result_ids.contains(id) {
                                return Some(id.clone());
                            }
                        }
                        None
                    })
                    .collect();

                if !missing_ids.is_empty() {
                    let synthetic_blocks: Vec<ContentBlock> = missing_ids
                        .iter()
                        .map(|id| {
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: SYNTHETIC_TOOL_RESULT_PLACEHOLDER.to_owned(),
                                is_error: true,
                            }
                        })
                        .collect();

                    report.synthetic_tool_results_injected +=
                        synthetic_blocks.len() as u32;

                    // Insert right after this assistant message (position i+1).
                    // If i+1 is already a Tool message, merge into it.
                    // Otherwise, insert a new Tool message.
                    let insert_pos = i + 1;
                    if insert_pos < messages.len()
                        && matches!(messages[insert_pos].role, Role::Tool)
                    {
                        // Merge synthetics into existing Tool message.
                        messages[insert_pos]
                            .content
                            .extend(synthetic_blocks);
                    } else {
                        // Insert new Tool message.
                        messages.insert(
                            insert_pos,
                            Message {
                                id: MessageId::new(),
                                role: Role::Tool,
                                content: synthetic_blocks,
                                created_at: chrono::Utc::now(),
                                token_count: None,
                            },
                        );
                    }
                    // Mark these IDs as resolved so we don't re-inject.
                    for id in &missing_ids {
                        all_tool_result_ids.insert(id.clone());
                    }
                    // Skip past the Tool message we just inserted/merged.
                    i += 2;
                    continue;
                }
            }
            i += 1;
        }
    }

    // Pass 6: Remove messages with empty content (may result from passes 2-4).
    messages.retain(|msg| {
        if msg.content.is_empty() && !matches!(msg.role, Role::System) {
            report.empty_messages_removed += 1;
            false
        } else {
            true
        }
    });

    // Pass 7: Merge consecutive same-role messages (except System).
    // The Anthropic API rejects consecutive user or assistant messages.
    let mut i = 1;
    while i < messages.len() {
        if messages[i].role == messages[i - 1].role
            && !matches!(messages[i].role, Role::System)
        {
            warn!(
                role = ?messages[i].role,
                "merging consecutive same-role messages"
            );
            let blocks = std::mem::take(&mut messages[i].content);
            messages[i - 1].content.extend(blocks);
            messages.remove(i);
            report.consecutive_roles_merged += 1;
        } else {
            i += 1;
        }
    }

    report
}

fn block_type_name(block: &ContentBlock) -> &'static str {
    match block {
        ContentBlock::Text { .. } => "text",
        ContentBlock::Thinking { .. } => "thinking",
        ContentBlock::ToolUse { .. } => "tool_use",
        ContentBlock::ToolResult { .. } => "tool_result",
        ContentBlock::Image { .. } => "image",
    }
}

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use encmind_core::types::MessageId;

    fn msg(role: Role, blocks: Vec<ContentBlock>) -> Message {
        Message {
            id: MessageId::new(),
            role,
            content: blocks,
            created_at: Utc::now(),
            token_count: None,
        }
    }

    #[test]
    fn coerces_non_object_tool_use_input() {
        let mut messages = vec![msg(
            Role::Assistant,
            vec![ContentBlock::ToolUse {
                id: "t1".into(),
                name: "test".into(),
                input: serde_json::json!("not an object"),
            }],
        )];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.tool_use_inputs_coerced, 1);

        match &messages[0].content[0] {
            ContentBlock::ToolUse { input, .. } => assert!(input.is_object()),
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn removes_orphaned_tool_result() {
        let mut messages = vec![
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({}),
                }],
            ),
            msg(
                Role::Tool,
                vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "ok".into(),
                        is_error: false,
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "t999".into(), // orphan
                        content: "orphan".into(),
                        is_error: false,
                    },
                ],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.orphaned_tool_results_removed, 1);
        assert_eq!(messages[1].content.len(), 1);
    }

    #[test]
    fn removes_empty_messages_after_orphan_removal() {
        let mut messages = vec![
            msg(Role::User, vec![ContentBlock::Text { text: "hi".into() }]),
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t999".into(), // orphan — no matching tool_use
                    content: "orphan".into(),
                    is_error: false,
                }],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.orphaned_tool_results_removed, 1);
        assert_eq!(report.empty_messages_removed, 1);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn merges_consecutive_same_role() {
        let mut messages = vec![
            msg(Role::User, vec![ContentBlock::Text { text: "a".into() }]),
            msg(Role::User, vec![ContentBlock::Text { text: "b".into() }]),
            msg(
                Role::Assistant,
                vec![ContentBlock::Text { text: "c".into() }],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.consecutive_roles_merged, 1);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content.len(), 2); // merged
    }

    #[test]
    fn no_changes_on_valid_messages() {
        let mut messages = vec![
            msg(Role::User, vec![ContentBlock::Text { text: "hi".into() }]),
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({"key": "value"}),
                }],
            ),
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            ),
            msg(
                Role::Assistant,
                vec![ContentBlock::Text {
                    text: "done".into(),
                }],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.tool_use_inputs_coerced, 0);
        assert_eq!(report.orphaned_tool_results_removed, 0);
        assert_eq!(report.consecutive_roles_merged, 0);
        assert_eq!(report.empty_messages_removed, 0);
        assert_eq!(messages.len(), 4);
    }

    #[test]
    fn preserves_system_messages_even_if_empty() {
        let mut messages = vec![
            msg(Role::System, vec![]),
            msg(Role::User, vec![ContentBlock::Text { text: "hi".into() }]),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.empty_messages_removed, 0);
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn handles_multiple_issues_in_one_pass() {
        let mut messages = vec![
            msg(Role::User, vec![ContentBlock::Text { text: "a".into() }]),
            msg(Role::User, vec![ContentBlock::Text { text: "b".into() }]), // consecutive
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!(42), // non-object
                }],
            ),
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t999".into(), // orphan
                    content: "orphan".into(),
                    is_error: false,
                }],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.tool_use_inputs_coerced, 1);
        assert_eq!(report.orphaned_tool_results_removed, 1);
        assert_eq!(report.synthetic_tool_results_injected, 1);
        // Trace the final state to verify correctness:
        // After all passes: User(a), User(b), Assistant(t1), Tool(synthetic for t1)
        // Pass 7 merges User(a)+User(b) → 3 messages.
        // But if empty_messages_removed fires first on the orphan Tool,
        // the layout may differ. Assert on final structure instead:
        let roles: Vec<_> = messages.iter().map(|m| m.role.clone()).collect();
        // Must end with: ...Assistant, Tool (for t1 synthetic)
        assert!(
            roles.len() >= 2,
            "expected at least 2 messages, got {roles:?}"
        );
        assert_eq!(
            roles[roles.len() - 2],
            Role::Assistant,
            "second-to-last should be Assistant, got {roles:?}"
        );
        assert_eq!(
            roles[roles.len() - 1],
            Role::Tool,
            "last should be Tool (synthetic), got {roles:?}"
        );
    }

    #[test]
    fn orphan_check_uses_prior_messages_only() {
        // A tool_result in the same message as its tool_use should be orphaned
        // because tool_use IDs are only collected AFTER checking tool_results.
        // In practice this shouldn't happen (tool_use is assistant, tool_result
        // is tool role), but the role-compat pass (pass 2) would catch it first.
        // This tests the ordering guarantee of pass 3 directly.
        let mut messages = vec![
            // First message: assistant with tool_use
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({}),
                }],
            ),
            // Second message: tool result referencing t1 (valid — t1 is in prior msg)
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            ),
            // Third message: assistant with new tool_use t2
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t2".into(),
                    name: "test2".into(),
                    input: serde_json::json!({}),
                }],
            ),
            // Fourth message: tool result referencing t2 (valid)
            // AND a tool_result referencing t3 (orphan — t3 never defined)
            msg(
                Role::Tool,
                vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t2".into(),
                        content: "ok".into(),
                        is_error: false,
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "t3".into(),
                        content: "orphan".into(),
                        is_error: false,
                    },
                ],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.orphaned_tool_results_removed, 1);
        // t2 result survives, t3 orphan removed
        assert_eq!(messages[3].content.len(), 1);
    }

    #[test]
    fn drops_role_incompatible_blocks() {
        let mut messages = vec![
            // Assistant message containing a tool_result (invalid — should be Tool role)
            msg(
                Role::Assistant,
                vec![
                    ContentBlock::Text {
                        text: "thinking".into(),
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "misplaced".into(),
                        is_error: false,
                    },
                ],
            ),
            // User message containing a tool_use (invalid — should be Assistant role)
            msg(
                Role::User,
                vec![
                    ContentBlock::Text {
                        text: "question".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t2".into(),
                        name: "test".into(),
                        input: serde_json::json!({}),
                    },
                ],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.role_incompatible_blocks_dropped, 2);
        // Assistant keeps Text, drops ToolResult
        assert_eq!(messages[0].content.len(), 1);
        assert!(matches!(messages[0].content[0], ContentBlock::Text { .. }));
        // User keeps Text, drops ToolUse
        assert_eq!(messages[1].content.len(), 1);
        assert!(matches!(messages[1].content[0], ContentBlock::Text { .. }));
    }

    #[test]
    fn tool_message_with_text_block_is_cleaned() {
        // Tool role message should only contain ToolResult blocks
        let mut messages = vec![msg(
            Role::Tool,
            vec![
                ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: false,
                },
                ContentBlock::Text {
                    text: "extra text in tool msg".into(),
                },
            ],
        )];

        // Need a prior tool_use so t1 isn't orphaned
        messages.insert(
            0,
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({}),
                }],
            ),
        );

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.role_incompatible_blocks_dropped, 1);
        assert_eq!(messages[1].content.len(), 1);
        assert!(matches!(
            messages[1].content[0],
            ContentBlock::ToolResult { .. }
        ));
    }

    #[test]
    fn injects_synthetic_tool_result_for_unmatched_tool_use() {
        let mut messages = vec![
            msg(Role::User, vec![ContentBlock::Text { text: "go".into() }]),
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({}),
                }],
            ),
            // No tool_result for t1 — stream was interrupted.
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.synthetic_tool_results_injected, 1);
        // A synthetic Tool message should be appended.
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[2].role, Role::Tool);
        match &messages[2].content[0] {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                assert_eq!(tool_use_id, "t1");
                assert!(content.contains("did not return"));
                assert!(*is_error);
            }
            _ => panic!("expected synthetic ToolResult"),
        }
    }

    #[test]
    fn deduplicates_tool_use_ids_across_messages() {
        let mut messages = vec![
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({}),
                }],
            ),
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            ),
            // Duplicate t1 in a later assistant message (corruption).
            msg(
                Role::Assistant,
                vec![
                    ContentBlock::Text {
                        text: "thinking".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(), // duplicate
                        name: "test".into(),
                        input: serde_json::json!({}),
                    },
                ],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.duplicate_tool_uses_removed, 1);
        // Third message should only have the Text block.
        assert_eq!(messages[2].content.len(), 1);
        assert!(matches!(messages[2].content[0], ContentBlock::Text { .. }));
    }

    #[test]
    fn synthetic_result_inserted_after_its_assistant_message() {
        // Synthetic results must follow the assistant message containing
        // their tool_use, not be appended at the end.
        let mut messages = vec![
            msg(Role::User, vec![ContentBlock::Text { text: "go".into() }]),
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "first".into(),
                    input: serde_json::json!({}),
                }],
            ),
            // No result for t1 — missing
            msg(
                Role::User,
                vec![ContentBlock::Text {
                    text: "continue".into(),
                }],
            ),
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t2".into(),
                    name: "second".into(),
                    input: serde_json::json!({}),
                }],
            ),
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t2".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.synthetic_tool_results_injected, 1);

        // Synthetic for t1 should be at index 2 (right after assistant(t1)),
        // NOT appended at the end.
        assert_eq!(messages[2].role, Role::Tool);
        match &messages[2].content[0] {
            ContentBlock::ToolResult { tool_use_id, .. } => {
                assert_eq!(tool_use_id, "t1");
            }
            _ => panic!("expected synthetic ToolResult at position 2"),
        }

        // User message should now be at index 3.
        assert_eq!(messages[3].role, Role::User);
        // Original t2 flow should be intact at indices 4-5.
        assert_eq!(messages[4].role, Role::Assistant);
        assert_eq!(messages[5].role, Role::Tool);
    }

    #[test]
    fn synthetic_merges_into_existing_tool_message() {
        // If there's already a Tool message right after the assistant,
        // synthetics should merge into it rather than creating a new message.
        let mut messages = vec![
            msg(
                Role::Assistant,
                vec![
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "first".into(),
                        input: serde_json::json!({}),
                    },
                    ContentBlock::ToolUse {
                        id: "t2".into(),
                        name: "second".into(),
                        input: serde_json::json!({}),
                    },
                ],
            ),
            msg(
                Role::Tool,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            ),
            // t2 has no result
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.synthetic_tool_results_injected, 1);
        // Should NOT create a third message — merged into existing Tool msg.
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1].content.len(), 2); // t1 result + t2 synthetic
    }

    #[test]
    fn deduplicates_tool_results_for_same_id() {
        let mut messages = vec![
            msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "test".into(),
                    input: serde_json::json!({}),
                }],
            ),
            msg(
                Role::Tool,
                vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "first".into(),
                        is_error: false,
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(), // duplicate
                        content: "second".into(),
                        is_error: false,
                    },
                ],
            ),
        ];

        let report = normalize_for_api(&mut messages);
        assert_eq!(report.duplicate_tool_results_removed, 1);
        assert_eq!(report.orphaned_tool_results_removed, 0);
        assert_eq!(messages[1].content.len(), 1);
        // First result survives.
        match &messages[1].content[0] {
            ContentBlock::ToolResult { content, .. } => assert_eq!(content, "first"),
            _ => panic!("expected ToolResult"),
        }
    }
}
