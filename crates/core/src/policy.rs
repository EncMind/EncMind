use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::PluginError;
use crate::traits::SkillManifest;

/// Risk level of a capability requested by a skill/plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRiskLevel {
    Low,
    Sensitive,
    Critical,
}

/// Explicit policy action for an operator rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
}

/// Result of evaluating a skill's capabilities against the operator policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// All requested capabilities are allowed.
    Allowed,
    /// Some capabilities need user confirmation before proceeding.
    NeedsPrompt(Vec<String>),
    /// The skill is denied outright.
    Denied(String),
}

/// Operator-level policy configuration for plugins/skills.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPolicyConfig {
    /// Which risk levels are automatically allowed. Default: `[Low, Sensitive]`.
    #[serde(default = "default_allow_risk_levels")]
    pub allow_risk_levels: Vec<CapabilityRiskLevel>,
    /// Capabilities that are always denied regardless of risk level.
    #[serde(default)]
    pub deny_capabilities: Vec<String>,
    /// Skills blocked by name.
    #[serde(default)]
    pub deny_skills: Vec<String>,
    /// Per-skill overrides that grant or deny specific capabilities.
    #[serde(default)]
    pub skill_overrides: HashMap<String, SkillOverride>,
    /// Operator-defined resource ceilings for skills.
    #[serde(default)]
    pub resource_ceiling: SkillResourceCeiling,
}

fn default_allow_risk_levels() -> Vec<CapabilityRiskLevel> {
    vec![CapabilityRiskLevel::Low, CapabilityRiskLevel::Sensitive]
}

impl Default for PluginPolicyConfig {
    fn default() -> Self {
        Self {
            allow_risk_levels: default_allow_risk_levels(),
            deny_capabilities: Vec::new(),
            deny_skills: Vec::new(),
            skill_overrides: HashMap::new(),
            resource_ceiling: SkillResourceCeiling::default(),
        }
    }
}

/// Per-skill capability overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillOverride {
    /// Capabilities explicitly allowed for this skill.
    ///
    /// This can override risk-level gating (for example allow a Sensitive
    /// capability when only Low is globally allowed), but it does NOT override
    /// `PluginPolicyConfig::deny_capabilities`.
    #[serde(default)]
    pub allow_capabilities: Vec<String>,
    /// Capabilities explicitly denied for this skill.
    #[serde(default)]
    pub deny_capabilities: Vec<String>,
}

/// Evaluates skill capabilities against an operator policy.
pub struct PolicyEnforcer {
    config: PluginPolicyConfig,
}

impl PolicyEnforcer {
    pub fn new(config: PluginPolicyConfig) -> Self {
        Self { config }
    }

    /// Classify a capability string into a risk level.
    ///
    /// - Low: `kv.get`, `kv.list`, `config.get`, `log.structured`,
    ///   `net_outbound` with specific domains (non-wildcard entries)
    /// - Sensitive: `net.http_request`, `net.fetch`, `hooks.emit_event`,
    ///   `kv.set`, `kv.delete`, `fs_read`, `fs_write`,
    ///   `net_outbound` (wildcard `*`)
    /// - Critical: `hooks.register` (including scoped forms like
    ///   `hooks.register:before_tool_call`), `exec_shell`, `env_secrets`,
    ///   `approval.prompt_user`
    pub fn classify(cap: &str) -> CapabilityRiskLevel {
        match cap {
            // Critical capabilities
            "hooks.register" | "exec_shell" | "env_secrets" | "approval.prompt_user" => {
                CapabilityRiskLevel::Critical
            }
            other if other.starts_with("hooks.register:") => CapabilityRiskLevel::Critical,
            other if other.starts_with("schedule.transform:") => CapabilityRiskLevel::Critical,

            // Sensitive capabilities
            "net.http_request" | "net.fetch" | "hooks.emit_event" | "kv.set" | "kv.delete"
            | "fs_read" | "fs_write" | "net_outbound" | "schedule.timer" => {
                CapabilityRiskLevel::Sensitive
            }
            other if other.starts_with("hooks.emit_event:") => CapabilityRiskLevel::Sensitive,

            // Low capabilities
            "kv.get" | "kv.list" | "config.get" | "log.structured" => CapabilityRiskLevel::Low,

            // Domain-specific net_outbound (e.g. "net_outbound:api.example.com") = Low
            other if other.starts_with("net_outbound:") => CapabilityRiskLevel::Low,

            // Unknown capabilities default to Sensitive
            _ => CapabilityRiskLevel::Sensitive,
        }
    }

    /// Evaluate a skill manifest against the operator policy.
    ///
    /// **Precedence (highest to lowest):**
    /// 1. Operator explicit deny (`deny_capabilities`, `deny_skills`)
    /// 2. Per-skill overrides (`skill_overrides[name].allow_capabilities`)
    /// 3. Operator explicit allow (`allow_risk_levels`)
    /// 4. Default: `NeedsPrompt` for Sensitive, `Denied` for Critical
    pub fn check_skill(&self, manifest: &SkillManifest) -> Result<PolicyDecision, PluginError> {
        // 1. Check deny_skills
        if self.config.deny_skills.contains(&manifest.name) {
            return Ok(PolicyDecision::Denied(format!(
                "skill '{}' is blocked by operator policy",
                manifest.name
            )));
        }

        // Collect capability strings from the manifest
        let caps = manifest_capabilities(manifest);

        if caps.is_empty() {
            return Ok(PolicyDecision::Allowed);
        }

        let skill_override = self.config.skill_overrides.get(&manifest.name);
        let mut needs_prompt = Vec::new();

        for cap in &caps {
            // 1. Check operator explicit deny
            if self
                .config
                .deny_capabilities
                .iter()
                .any(|rule| deny_rule_matches_capability(rule, cap))
            {
                return Ok(PolicyDecision::Denied(format!(
                    "capability '{cap}' is denied by operator policy"
                )));
            }

            // Check per-skill deny override
            if let Some(ov) = skill_override {
                if ov
                    .deny_capabilities
                    .iter()
                    .any(|rule| deny_rule_matches_capability(rule, cap))
                {
                    return Ok(PolicyDecision::Denied(format!(
                        "capability '{cap}' is denied by skill override for '{}'",
                        manifest.name
                    )));
                }
            }

            let risk = Self::classify(cap);

            // 2. Per-skill override allows
            if let Some(ov) = skill_override {
                if ov.allow_capabilities.contains(cap) {
                    continue;
                }
            }

            // 3. Operator allow_risk_levels
            if self.config.allow_risk_levels.contains(&risk) {
                continue;
            }

            // 4. Default: NeedsPrompt for Sensitive, Denied for Critical
            match risk {
                CapabilityRiskLevel::Low => {
                    // Low should always be allowed, but if operator explicitly
                    // removed Low from allow_risk_levels, prompt
                    needs_prompt.push(cap.clone());
                }
                CapabilityRiskLevel::Sensitive => {
                    needs_prompt.push(cap.clone());
                }
                CapabilityRiskLevel::Critical => {
                    return Ok(PolicyDecision::Denied(format!(
                        "critical capability '{cap}' requires explicit approval"
                    )));
                }
            }
        }

        if needs_prompt.is_empty() {
            Ok(PolicyDecision::Allowed)
        } else {
            Ok(PolicyDecision::NeedsPrompt(needs_prompt))
        }
    }
}

pub(crate) fn deny_rule_matches_capability(rule: &str, capability: &str) -> bool {
    if rule == capability {
        return true;
    }
    capability
        .strip_prefix(rule)
        .is_some_and(|suffix| suffix.starts_with(':'))
}

/// Operator-defined maximum resource limits for skills.
/// Effective limit = min(skill_requested, operator_ceiling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResourceCeiling {
    #[serde(default = "default_max_fuel")]
    pub max_fuel: u64,
    #[serde(default = "default_max_wall_clock_ms")]
    pub max_wall_clock_ms: u64,
    #[serde(default = "default_max_invocations_per_minute")]
    pub max_invocations_per_minute: u32,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
}

fn default_max_fuel() -> u64 {
    1_000_000_000
}
fn default_max_wall_clock_ms() -> u64 {
    30_000
}
fn default_max_invocations_per_minute() -> u32 {
    60
}
fn default_max_concurrent() -> u32 {
    2
}

impl Default for SkillResourceCeiling {
    fn default() -> Self {
        Self {
            max_fuel: default_max_fuel(),
            max_wall_clock_ms: default_max_wall_clock_ms(),
            max_invocations_per_minute: default_max_invocations_per_minute(),
            max_concurrent: default_max_concurrent(),
        }
    }
}

/// Resolve effective resource limits by applying operator ceiling.
/// Each field is the minimum of the skill-requested value and the operator ceiling.
pub fn resolve_resource_limits(
    skill_fuel: Option<u64>,
    skill_wall_clock: Option<u64>,
    skill_invocations: Option<u32>,
    skill_concurrent: Option<u32>,
    ceiling: &SkillResourceCeiling,
) -> crate::types::ResolvedResourceLimits {
    crate::types::ResolvedResourceLimits {
        fuel_per_invocation: skill_fuel
            .map(|v| v.min(ceiling.max_fuel))
            .unwrap_or(ceiling.max_fuel),
        wall_clock_ms: skill_wall_clock
            .map(|v| v.min(ceiling.max_wall_clock_ms))
            .unwrap_or(ceiling.max_wall_clock_ms),
        invocations_per_minute: skill_invocations
            .map(|v| v.min(ceiling.max_invocations_per_minute))
            .unwrap_or(ceiling.max_invocations_per_minute),
        max_concurrent: skill_concurrent
            .map(|v| v.min(ceiling.max_concurrent))
            .unwrap_or(ceiling.max_concurrent),
    }
}

/// Extract capability strings from a `SkillManifest`'s `CapabilitySet`.
///
/// Mapping:
/// - `net_outbound: ["*"]` → `"net_outbound"` (Sensitive wildcard)
/// - `net_outbound: ["api.example.com"]` → `"net_outbound:api.example.com"` (Low)
/// - `fs_read: ["/tmp"]` → `"fs_read"`
/// - `fs_write: ["/tmp"]` → `"fs_write"`
/// - `exec_shell: true` → `"exec_shell"`
/// - `env_secrets: true` → `"env_secrets"`
pub fn manifest_capabilities(manifest: &SkillManifest) -> Vec<String> {
    let mut caps = Vec::new();

    for domain in &manifest.capabilities.net_outbound {
        if domain == "*" {
            if !caps.contains(&"net_outbound".to_string()) {
                caps.push("net_outbound".to_string());
            }
        } else {
            caps.push(format!("net_outbound:{domain}"));
        }
    }

    if !manifest.capabilities.fs_read.is_empty() {
        caps.push("fs_read".to_string());
    }

    if !manifest.capabilities.fs_write.is_empty() {
        caps.push("fs_write".to_string());
    }

    if manifest.capabilities.exec_shell {
        caps.push("exec_shell".to_string());
    }

    if manifest.capabilities.env_secrets {
        caps.push("env_secrets".to_string());
    }

    if manifest.capabilities.kv {
        caps.push("kv.get".to_string());
        caps.push("kv.list".to_string());
        caps.push("kv.set".to_string());
        caps.push("kv.delete".to_string());
    }

    if manifest.capabilities.prompt_user {
        caps.push("approval.prompt_user".to_string());
    }

    for event in &manifest.capabilities.emit_events {
        caps.push(format!("hooks.emit_event:{event}"));
    }

    for hook in &manifest.capabilities.hooks {
        caps.push(format!("hooks.register:{hook}"));
    }

    if manifest.capabilities.schedule_timers {
        caps.push("schedule.timer".to_string());
    }

    for channel in &manifest.capabilities.schedule_transforms {
        caps.push(format!("schedule.transform:{channel}"));
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CapabilitySet;

    fn make_manifest(name: &str, caps: CapabilitySet) -> SkillManifest {
        SkillManifest {
            name: name.into(),
            version: "1.0.0".into(),
            description: String::new(),
            host_abi: "v1".into(),
            capabilities: caps,
        }
    }

    fn empty_caps() -> CapabilitySet {
        CapabilitySet {
            net_outbound: vec![],
            fs_read: vec![],
            fs_write: vec![],
            exec_shell: false,
            env_secrets: false,
            kv: false,
            prompt_user: false,
            emit_events: vec![],
            hooks: vec![],
            schedule_timers: false,
            schedule_transforms: vec![],
        }
    }

    #[test]
    fn classify_low_capabilities() {
        assert_eq!(PolicyEnforcer::classify("kv.get"), CapabilityRiskLevel::Low);
        assert_eq!(
            PolicyEnforcer::classify("kv.list"),
            CapabilityRiskLevel::Low
        );
        assert_eq!(
            PolicyEnforcer::classify("config.get"),
            CapabilityRiskLevel::Low
        );
        assert_eq!(
            PolicyEnforcer::classify("log.structured"),
            CapabilityRiskLevel::Low
        );
        assert_eq!(
            PolicyEnforcer::classify("net_outbound:api.example.com"),
            CapabilityRiskLevel::Low
        );
    }

    #[test]
    fn classify_sensitive_capabilities() {
        assert_eq!(
            PolicyEnforcer::classify("net.http_request"),
            CapabilityRiskLevel::Sensitive
        );
        assert_eq!(
            PolicyEnforcer::classify("fs_read"),
            CapabilityRiskLevel::Sensitive
        );
        assert_eq!(
            PolicyEnforcer::classify("fs_write"),
            CapabilityRiskLevel::Sensitive
        );
        assert_eq!(
            PolicyEnforcer::classify("net_outbound"),
            CapabilityRiskLevel::Sensitive
        );
        assert_eq!(
            PolicyEnforcer::classify("kv.set"),
            CapabilityRiskLevel::Sensitive
        );
    }

    #[test]
    fn classify_critical_capabilities() {
        assert_eq!(
            PolicyEnforcer::classify("exec_shell"),
            CapabilityRiskLevel::Critical
        );
        assert_eq!(
            PolicyEnforcer::classify("env_secrets"),
            CapabilityRiskLevel::Critical
        );
        assert_eq!(
            PolicyEnforcer::classify("hooks.register"),
            CapabilityRiskLevel::Critical
        );
        assert_eq!(
            PolicyEnforcer::classify("approval.prompt_user"),
            CapabilityRiskLevel::Critical
        );
        assert_eq!(
            PolicyEnforcer::classify("hooks.register:before_tool_call"),
            CapabilityRiskLevel::Critical
        );
    }

    #[test]
    fn check_skill_all_low_caps_allowed() {
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig::default());
        let manifest = make_manifest(
            "safe-skill",
            CapabilitySet {
                net_outbound: vec!["api.example.com".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn check_skill_sensitive_cap_needs_prompt_when_sensitive_not_allowed() {
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            allow_risk_levels: vec![CapabilityRiskLevel::Low],
            ..Default::default()
        });
        let manifest = make_manifest(
            "net-skill",
            CapabilitySet {
                fs_read: vec!["/tmp".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::NeedsPrompt(ref caps) if caps.contains(&"fs_read".to_string())),
            "expected NeedsPrompt, got {decision:?}"
        );
    }

    #[test]
    fn check_skill_critical_cap_denied_by_default() {
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig::default());
        let manifest = make_manifest(
            "dangerous",
            CapabilitySet {
                exec_shell: true,
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(_)),
            "expected Denied, got {decision:?}"
        );
    }

    #[test]
    fn per_skill_override_allows_otherwise_denied_cap() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "trusted".to_string(),
            SkillOverride {
                allow_capabilities: vec!["fs_read".into()],
                deny_capabilities: vec![],
            },
        );
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            allow_risk_levels: vec![CapabilityRiskLevel::Low],
            skill_overrides: overrides,
            ..Default::default()
        });
        let manifest = make_manifest(
            "trusted",
            CapabilitySet {
                fs_read: vec!["/tmp".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn global_deny_cannot_be_overridden_by_per_skill_allow() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "trusted".to_string(),
            SkillOverride {
                allow_capabilities: vec!["exec_shell".into()],
                deny_capabilities: vec![],
            },
        );
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            allow_risk_levels: vec![
                CapabilityRiskLevel::Low,
                CapabilityRiskLevel::Sensitive,
                CapabilityRiskLevel::Critical,
            ],
            deny_capabilities: vec!["exec_shell".into()],
            skill_overrides: overrides,
            ..Default::default()
        });
        let manifest = make_manifest(
            "trusted",
            CapabilitySet {
                exec_shell: true,
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(ref msg) if msg.contains("exec_shell")),
            "expected Denied(exec_shell), got {decision:?}"
        );
    }

    #[test]
    fn deny_capabilities_overrides_allow_risk_levels() {
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            allow_risk_levels: vec![CapabilityRiskLevel::Low, CapabilityRiskLevel::Sensitive],
            deny_capabilities: vec!["fs_read".into()],
            ..Default::default()
        });
        let manifest = make_manifest(
            "reader",
            CapabilitySet {
                fs_read: vec!["/tmp".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(ref msg) if msg.contains("fs_read")),
            "expected Denied, got {decision:?}"
        );
    }

    #[test]
    fn deny_net_outbound_blocks_domain_scoped_capability() {
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            deny_capabilities: vec!["net_outbound".into()],
            ..Default::default()
        });
        let manifest = make_manifest(
            "net-skill",
            CapabilitySet {
                net_outbound: vec!["api.example.com".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(ref msg) if msg.contains("net_outbound:api.example.com")),
            "expected Denied(net_outbound:*), got {decision:?}"
        );
    }

    #[test]
    fn per_skill_deny_net_outbound_blocks_domain_scoped_capability() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "restricted".to_string(),
            SkillOverride {
                allow_capabilities: vec![],
                deny_capabilities: vec!["net_outbound".into()],
            },
        );
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            skill_overrides: overrides,
            ..Default::default()
        });
        let manifest = make_manifest(
            "restricted",
            CapabilitySet {
                net_outbound: vec!["api.example.com".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(ref msg) if msg.contains("net_outbound:api.example.com")),
            "expected Denied(net_outbound:*), got {decision:?}"
        );
    }

    #[test]
    fn deny_skills_blocks_by_name() {
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig {
            deny_skills: vec!["evil-skill".into()],
            ..Default::default()
        });
        let manifest = make_manifest("evil-skill", empty_caps());
        let decision = enforcer.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(ref msg) if msg.contains("evil-skill")),
            "expected Denied, got {decision:?}"
        );
    }

    #[test]
    fn default_policy_allows_low_needs_prompt_sensitive_when_only_low_allowed() {
        // With default policy (Low + Sensitive allowed), sensitive caps are allowed
        let enforcer = PolicyEnforcer::new(PluginPolicyConfig::default());
        let manifest = make_manifest(
            "mixed",
            CapabilitySet {
                net_outbound: vec!["api.example.com".into()],
                fs_read: vec!["/data".into()],
                ..empty_caps()
            },
        );
        let decision = enforcer.check_skill(&manifest).unwrap();
        // Default allows both Low and Sensitive
        assert_eq!(decision, PolicyDecision::Allowed);

        // Now with only Low allowed, Sensitive should need prompt
        let strict = PolicyEnforcer::new(PluginPolicyConfig {
            allow_risk_levels: vec![CapabilityRiskLevel::Low],
            ..Default::default()
        });
        let decision = strict.check_skill(&manifest).unwrap();
        assert!(
            matches!(decision, PolicyDecision::NeedsPrompt(_)),
            "expected NeedsPrompt, got {decision:?}"
        );
    }

    #[test]
    fn manifest_capabilities_includes_schedule_timer() {
        let manifest = make_manifest(
            "timer-skill",
            CapabilitySet {
                schedule_timers: true,
                ..empty_caps()
            },
        );
        let caps = manifest_capabilities(&manifest);
        assert!(caps.contains(&"schedule.timer".to_string()));
    }

    #[test]
    fn manifest_capabilities_includes_schedule_transform() {
        let manifest = make_manifest(
            "transform-skill",
            CapabilitySet {
                schedule_transforms: vec!["telegram".into(), "slack".into()],
                ..empty_caps()
            },
        );
        let caps = manifest_capabilities(&manifest);
        assert!(caps.contains(&"schedule.transform:telegram".to_string()));
        assert!(caps.contains(&"schedule.transform:slack".to_string()));
    }

    #[test]
    fn classify_schedule_timer_is_sensitive() {
        assert_eq!(
            PolicyEnforcer::classify("schedule.timer"),
            CapabilityRiskLevel::Sensitive
        );
    }

    #[test]
    fn classify_schedule_transform_prefix_match_is_critical() {
        assert_eq!(
            PolicyEnforcer::classify("schedule.transform:telegram"),
            CapabilityRiskLevel::Critical
        );
        assert_eq!(
            PolicyEnforcer::classify("schedule.transform:slack"),
            CapabilityRiskLevel::Critical
        );
    }

    #[test]
    fn resource_ceiling_min_applied() {
        use super::SkillResourceCeiling;
        let ceiling = SkillResourceCeiling::default();
        assert_eq!(ceiling.max_fuel, 1_000_000_000);
        assert_eq!(ceiling.max_wall_clock_ms, 30_000);
        assert_eq!(ceiling.max_invocations_per_minute, 60);
        assert_eq!(ceiling.max_concurrent, 2);
    }

    #[test]
    fn resource_ceiling_defaults_when_skill_omits() {
        use super::SkillResourceCeiling;
        let json = "{}";
        let ceiling: SkillResourceCeiling = serde_json::from_str(json).unwrap();
        assert_eq!(ceiling.max_fuel, 1_000_000_000);
        assert_eq!(ceiling.max_wall_clock_ms, 30_000);
    }
}
