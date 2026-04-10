//! Structured permission decisions — provenance and typed context for
//! why a tool call was denied or what path it took through governance.
//!
//! This replaces the old `deny_reason: Option<String>` pattern with a
//! typed record that carries:
//!   - which subsystem made the decision (`source`),
//!   - an optional stable rule identifier (`rule_id`),
//!   - a human-readable `reason`, and
//!   - an optional short fingerprint of the input that triggered it.
//!
//! It is emitted in `AfterToolCall` hook payloads and in audit logs so
//! operators can answer "why did this get denied?" without parsing strings.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Which governance subsystem produced the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    /// Immutable deny-list classifier (`risk_classifier`).
    RiskClassifier,
    /// Workspace trust gate (`workspace_trust`).
    WorkspaceTrust,
    /// Egress firewall check on tool inputs (URLs, hostnames).
    Firewall,
    /// Operator-configured approval policy (ask/allow/deny).
    Approval,
    /// Plugin hook aborted the call.
    Hook,
    /// Rate limiting (per-run or per-session tool-call cap).
    RateLimit,
    /// Schema validation rejected the input.
    Schema,
}

impl DecisionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RiskClassifier => "risk_classifier",
            Self::WorkspaceTrust => "workspace_trust",
            Self::Firewall => "firewall",
            Self::Approval => "approval",
            Self::Hook => "hook",
            Self::RateLimit => "rate_limit",
            Self::Schema => "schema",
        }
    }
}

/// A structured record of a governance decision.
///
/// Carries the provenance of a tool-call denial (or, in the future, any
/// other gating decision). `reason` is free-form; `rule_id` is a stable
/// opaque identifier that callers can match against for programmatic
/// routing (e.g. metrics buckets, audit filters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionDecision {
    pub source: DecisionSource,
    /// Optional stable rule identifier (e.g. `"fs.credential_path"`).
    /// Absent when the decision has no sub-rule granularity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Human-readable explanation. Safe to show to operators.
    pub reason: String,
    /// Short SHA-256 prefix of the serialized input that triggered the
    /// decision. Useful for correlating audit events without logging
    /// full inputs. `None` when the input is unavailable or not relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_fingerprint: Option<String>,
}

impl PermissionDecision {
    /// Construct a decision without an input fingerprint.
    pub fn new(source: DecisionSource, reason: impl Into<String>) -> Self {
        Self {
            source,
            rule_id: None,
            reason: reason.into(),
            input_fingerprint: None,
        }
    }

    /// Attach a rule id.
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Compute and attach an input fingerprint from the given JSON input.
    /// Silently no-ops on serialization failure.
    pub fn with_input_fingerprint(mut self, input: &serde_json::Value) -> Self {
        if let Some(fp) = fingerprint_input(input) {
            self.input_fingerprint = Some(fp);
        }
        self
    }
}

/// Compute a short SHA-256 prefix (12 hex chars, 6 bytes) of the canonical
/// JSON form of `input`. Used as an opaque correlation id for audit logs.
/// Returns `None` only if serialization fails (should not happen in practice).
pub fn fingerprint_input(input: &serde_json::Value) -> Option<String> {
    // serde_json::to_vec is canonical enough for fingerprinting — two
    // identical values produce the same bytes within a single process
    // because object key order is preserved by serde_json::Value.
    let bytes = serde_json::to_vec(input).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    // 12 hex chars = 48 bits — plenty for human-readable correlation.
    Some(hex_encode(&digest[..6]))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_source_as_str_is_stable() {
        assert_eq!(DecisionSource::RiskClassifier.as_str(), "risk_classifier");
        assert_eq!(DecisionSource::WorkspaceTrust.as_str(), "workspace_trust");
        assert_eq!(DecisionSource::Firewall.as_str(), "firewall");
        assert_eq!(DecisionSource::Approval.as_str(), "approval");
        assert_eq!(DecisionSource::Hook.as_str(), "hook");
        assert_eq!(DecisionSource::RateLimit.as_str(), "rate_limit");
        assert_eq!(DecisionSource::Schema.as_str(), "schema");
    }

    #[test]
    fn decision_source_roundtrips_json() {
        let value = serde_json::to_value(DecisionSource::RiskClassifier).unwrap();
        assert_eq!(value, serde_json::json!("risk_classifier"));
        let parsed: DecisionSource = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, DecisionSource::RiskClassifier);
    }

    #[test]
    fn permission_decision_minimal() {
        let d = PermissionDecision::new(DecisionSource::Approval, "user denied");
        assert_eq!(d.source, DecisionSource::Approval);
        assert!(d.rule_id.is_none());
        assert_eq!(d.reason, "user denied");
        assert!(d.input_fingerprint.is_none());
    }

    #[test]
    fn permission_decision_builder_attaches_rule_id() {
        let d = PermissionDecision::new(DecisionSource::RiskClassifier, "rm -rf / detected")
            .with_rule_id("bash.rm_rf_root");
        assert_eq!(d.rule_id.as_deref(), Some("bash.rm_rf_root"));
    }

    #[test]
    fn permission_decision_with_fingerprint_is_deterministic() {
        let input = serde_json::json!({"cmd": "ls", "dir": "/tmp"});
        let d1 =
            PermissionDecision::new(DecisionSource::Approval, "ask").with_input_fingerprint(&input);
        let d2 =
            PermissionDecision::new(DecisionSource::Approval, "ask").with_input_fingerprint(&input);
        assert!(d1.input_fingerprint.is_some());
        assert_eq!(d1.input_fingerprint, d2.input_fingerprint);
        assert_eq!(d1.input_fingerprint.as_ref().unwrap().len(), 12);
    }

    #[test]
    fn fingerprint_differs_for_different_inputs() {
        let fp1 = fingerprint_input(&serde_json::json!({"a": 1})).unwrap();
        let fp2 = fingerprint_input(&serde_json::json!({"a": 2})).unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_is_hex_of_expected_length() {
        let fp = fingerprint_input(&serde_json::json!({"k": "v"})).unwrap();
        assert_eq!(fp.len(), 12);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn permission_decision_json_skips_none_fields() {
        let d = PermissionDecision::new(DecisionSource::Firewall, "blocked host");
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["source"], "firewall");
        assert_eq!(v["reason"], "blocked host");
        assert!(v.get("rule_id").is_none());
        assert!(v.get("input_fingerprint").is_none());
    }

    #[test]
    fn permission_decision_json_includes_set_fields() {
        let d = PermissionDecision::new(DecisionSource::WorkspaceTrust, "not trusted")
            .with_rule_id("workspace.untrusted")
            .with_input_fingerprint(&serde_json::json!({"path": "/etc/passwd"}));
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["rule_id"], "workspace.untrusted");
        assert!(v["input_fingerprint"].is_string());
    }
}
