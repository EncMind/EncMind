//! Static model pricing table for computing `cost_usd` on api_usage rows.
//!
//! Prices are per 1 million tokens (input and output separately).
//! Unknown models produce `None` — the caller should persist a null
//! cost rather than guess.
//!
//! Prices here are list prices as of 2026-04. Operators can override
//! by configuring custom model IDs that match their negotiated rates
//! (future: a `pricing_overrides` config section).

use std::collections::HashMap;
use std::sync::LazyLock;

/// Per-model pricing entry.
#[derive(Debug, Clone, Copy)]
pub struct ModelPricing {
    /// USD per 1 million input tokens.
    pub input_per_1m: f64,
    /// USD per 1 million output tokens.
    pub output_per_1m: f64,
}

static PRICING: LazyLock<HashMap<&'static str, ModelPricing>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    // Anthropic (2026-04 list prices)
    m.insert(
        "claude-opus-4-6",
        ModelPricing {
            input_per_1m: 15.0,
            output_per_1m: 75.0,
        },
    );
    m.insert(
        "claude-sonnet-4-6",
        ModelPricing {
            input_per_1m: 3.0,
            output_per_1m: 15.0,
        },
    );
    m.insert(
        "claude-haiku-4-5",
        ModelPricing {
            input_per_1m: 0.80,
            output_per_1m: 4.0,
        },
    );
    // Older models still in use
    m.insert(
        "claude-sonnet-4-5",
        ModelPricing {
            input_per_1m: 3.0,
            output_per_1m: 15.0,
        },
    );
    m.insert(
        "claude-3-5-sonnet-20241022",
        ModelPricing {
            input_per_1m: 3.0,
            output_per_1m: 15.0,
        },
    );
    m.insert(
        "claude-3-5-haiku-20241022",
        ModelPricing {
            input_per_1m: 0.80,
            output_per_1m: 4.0,
        },
    );

    // OpenAI (2026-04 approximate list prices)
    m.insert(
        "gpt-4o",
        ModelPricing {
            input_per_1m: 2.50,
            output_per_1m: 10.0,
        },
    );
    m.insert(
        "gpt-4o-mini",
        ModelPricing {
            input_per_1m: 0.15,
            output_per_1m: 0.60,
        },
    );
    m.insert(
        "gpt-4-turbo",
        ModelPricing {
            input_per_1m: 10.0,
            output_per_1m: 30.0,
        },
    );
    m.insert(
        "o3-mini",
        ModelPricing {
            input_per_1m: 1.10,
            output_per_1m: 4.40,
        },
    );

    // Google
    m.insert(
        "gemini-2.5-pro",
        ModelPricing {
            input_per_1m: 1.25,
            output_per_1m: 10.0,
        },
    );
    m.insert(
        "gemini-2.5-flash",
        ModelPricing {
            input_per_1m: 0.15,
            output_per_1m: 0.60,
        },
    );

    m
});

/// Look up the pricing for a model ID. Tries an exact match first,
/// then strips a trailing date suffix (e.g. `-20250929`) since
/// providers version model IDs but pricing is per-family.
pub fn lookup(model_id: &str) -> Option<&'static ModelPricing> {
    if let Some(p) = PRICING.get(model_id) {
        return Some(p);
    }
    // Strip trailing -YYYYMMDD date suffix for versioned model IDs
    // (e.g. "claude-sonnet-4-5-20250929" → "claude-sonnet-4-5").
    let stripped = strip_date_suffix(model_id);
    if stripped != model_id {
        if let Some(p) = PRICING.get(stripped) {
            return Some(p);
        }
    }
    None
}

/// Strip a trailing `-YYYYMMDD` date suffix if present.
fn strip_date_suffix(model_id: &str) -> &str {
    // Date suffixes are exactly 8 digits preceded by a hyphen.
    if model_id.len() >= 10 {
        let candidate = &model_id[model_id.len() - 9..];
        if candidate.starts_with('-') && candidate[1..].bytes().all(|b| b.is_ascii_digit()) {
            return &model_id[..model_id.len() - 9];
        }
    }
    model_id
}

/// Compute the USD cost for a turn given token counts.
/// Returns `None` when the model isn't in the pricing table.
pub fn compute_cost(model_id: &str, input_tokens: u32, output_tokens: u32) -> Option<f64> {
    let pricing = lookup(model_id)?;
    let input_cost = (input_tokens as f64 / 1_000_000.0) * pricing.input_per_1m;
    let output_cost = (output_tokens as f64 / 1_000_000.0) * pricing.output_per_1m;
    Some(input_cost + output_cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_model_returns_pricing() {
        let p = lookup("claude-sonnet-4-6").expect("sonnet should be known");
        assert_eq!(p.input_per_1m, 3.0);
        assert_eq!(p.output_per_1m, 15.0);
    }

    #[test]
    fn unknown_model_returns_none() {
        assert!(lookup("my-custom-model").is_none());
    }

    #[test]
    fn versioned_model_id_matches_via_date_suffix_strip() {
        // Real Anthropic model IDs include a date suffix.
        let p = lookup("claude-sonnet-4-5-20250929").expect("versioned sonnet should match");
        assert_eq!(p.input_per_1m, 3.0);

        let p2 = lookup("claude-3-5-haiku-20241022").expect("versioned haiku should match");
        assert_eq!(p2.input_per_1m, 0.80);
    }

    #[test]
    fn strip_date_suffix_only_strips_8_digit_dates() {
        assert_eq!(strip_date_suffix("claude-sonnet-4-5-20250929"), "claude-sonnet-4-5");
        assert_eq!(strip_date_suffix("claude-sonnet-4-5"), "claude-sonnet-4-5"); // no suffix
        assert_eq!(strip_date_suffix("gpt-4o"), "gpt-4o"); // too short
        assert_eq!(strip_date_suffix("model-abc"), "model-abc"); // non-digit suffix
    }

    #[test]
    fn compute_cost_for_known_model() {
        // 1000 input tokens @ $3/1M = $0.003
        // 500 output tokens @ $15/1M = $0.0075
        let cost = compute_cost("claude-sonnet-4-6", 1000, 500).unwrap();
        assert!((cost - 0.0105).abs() < 1e-9);
    }

    #[test]
    fn compute_cost_returns_none_for_unknown() {
        assert!(compute_cost("unknown-model", 1000, 500).is_none());
    }

    #[test]
    fn zero_tokens_is_zero_cost() {
        let cost = compute_cost("claude-opus-4-6", 0, 0).unwrap();
        assert_eq!(cost, 0.0);
    }
}
