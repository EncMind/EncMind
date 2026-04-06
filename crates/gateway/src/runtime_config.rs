use std::collections::HashMap;

use encmind_core::traits::ToolInterruptBehavior;
use tracing::warn;

pub(crate) fn parse_tool_interrupt_behavior_map(
    configured: &HashMap<String, String>,
) -> HashMap<String, ToolInterruptBehavior> {
    let mut pairs: Vec<_> = configured.iter().collect();
    // Deterministic ordering for logs and collision handling.
    pairs.sort_by(|(left, _), (right, _)| left.cmp(right));

    let mut parsed = HashMap::with_capacity(pairs.len());
    for (name, behavior) in pairs {
        let normalized_name = name.trim().to_ascii_lowercase();
        if normalized_name.is_empty() {
            warn!(
                tool = %name,
                behavior = %behavior,
                "invalid interrupt behavior config key; tool name must not be empty"
            );
            continue;
        }

        let normalized_behavior = behavior.trim().to_ascii_lowercase();
        let value = match normalized_behavior.as_str() {
            "block" => ToolInterruptBehavior::Block,
            "cancel" => ToolInterruptBehavior::Cancel,
            _ => {
                warn!(
                    tool = %name,
                    behavior = %behavior,
                    "invalid interrupt behavior in config; expected 'cancel' or 'block'"
                );
                continue;
            }
        };

        if let Some(previous) = parsed.insert(normalized_name.clone(), value) {
            warn!(
                tool = %normalized_name,
                previous = ?previous,
                new = ?value,
                "duplicate normalized interrupt behavior key; last value wins"
            );
        }
    }

    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interrupt_behavior_map_normalizes_tool_keys() {
        let mut raw = HashMap::new();
        raw.insert(" NetProbe_Fetch ".to_string(), " block ".to_string());

        let parsed = parse_tool_interrupt_behavior_map(&raw);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed.get("netprobe_fetch"),
            Some(&ToolInterruptBehavior::Block)
        );
    }

    #[test]
    fn parse_interrupt_behavior_map_skips_invalid_entries() {
        let mut raw = HashMap::new();
        raw.insert("   ".to_string(), "cancel".to_string());
        raw.insert("netprobe_fetch".to_string(), "pause".to_string());

        let parsed = parse_tool_interrupt_behavior_map(&raw);
        assert!(parsed.is_empty());
    }
}
