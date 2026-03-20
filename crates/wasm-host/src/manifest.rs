use std::collections::HashMap;

use serde::Deserialize;

use encmind_core::error::{PluginError, WasmHostError};
use encmind_core::policy::{manifest_capabilities, PolicyDecision, PolicyEnforcer};
use encmind_core::traits::{
    CapabilitySet, SkillDefinition, SkillManifest, SKILL_HOST_ABI_JAVY, SKILL_HOST_ABI_V1,
};

/// Raw TOML structure for a skill manifest file.
#[derive(Deserialize)]
pub struct ManifestFile {
    pub skill: SkillSection,
    #[serde(default)]
    pub capabilities: CapabilitiesSection,
    #[serde(default)]
    pub hooks: HooksSection,
    #[serde(default)]
    pub tool: Option<ToolSection>,
    #[serde(default)]
    pub schedule: ScheduleSection,
    #[serde(default)]
    pub config: ConfigSection,
    #[serde(default)]
    pub resources: Option<ResourcesSection>,
    #[serde(default)]
    pub output: Option<OutputSection>,
}

/// Output schema section in the manifest.
#[derive(Deserialize)]
pub struct OutputSection {
    pub schema: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SkillSection {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_host_abi")]
    pub host_abi: String,
}

fn default_host_abi() -> String {
    SKILL_HOST_ABI_V1.to_string()
}

#[derive(Deserialize, Default)]
pub struct CapabilitiesSection {
    #[serde(default)]
    pub net_outbound: Vec<String>,
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub exec_shell: bool,
    #[serde(default)]
    pub env_secrets: bool,
    #[serde(default)]
    pub kv: bool,
    #[serde(default)]
    pub prompt_user: bool,
    #[serde(default)]
    pub emit_events: Vec<String>,
    #[serde(default)]
    pub hooks: Vec<String>,
}

/// Mapping of hook points to exported WASM function names.
#[derive(Deserialize, Default)]
pub struct HooksSection {
    #[serde(default)]
    pub before_tool_call: Option<String>,
    #[serde(default)]
    pub after_tool_call: Option<String>,
    #[serde(default)]
    pub message_received: Option<String>,
    #[serde(default)]
    pub message_sending: Option<String>,
    #[serde(default)]
    pub message_sent: Option<String>,
    #[serde(default)]
    pub session_start: Option<String>,
    #[serde(default)]
    pub session_end: Option<String>,
}

/// Tool definition section in the manifest.
#[derive(Deserialize)]
pub struct ToolSection {
    pub name: String,
    pub description: String,
    #[serde(default = "default_tool_params")]
    pub parameters: serde_json::Value,
}

fn default_tool_params() -> serde_json::Value {
    serde_json::json!({"type": "object", "properties": {}})
}

#[derive(Deserialize, Default)]
pub struct ScheduleSection {
    #[serde(default)]
    pub timers: Vec<TimerDeclaration>,
    #[serde(default)]
    pub transforms: Vec<TransformDeclaration>,
}

/// A timer declared in the skill manifest.
#[derive(Deserialize, Clone, Debug)]
pub struct TimerDeclaration {
    pub name: String,
    pub interval_secs: u64,
    pub export_fn: String,
    #[serde(default)]
    pub description: String,
}

/// A channel transform declared in the skill manifest.
#[derive(Deserialize, Clone, Debug)]
pub struct TransformDeclaration {
    pub channel: String,
    #[serde(default)]
    pub inbound_fn: Option<String>,
    #[serde(default)]
    pub outbound_fn: Option<String>,
    #[serde(default)]
    pub priority: i32,
}

/// Resource limits requested by a skill.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct ResourcesSection {
    pub max_fuel_per_invocation: Option<u64>,
    pub max_wall_clock_ms: Option<u64>,
    pub max_invocations_per_minute: Option<u32>,
    pub max_concurrent: Option<u32>,
}

/// Runtime config declaration for skills.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct ConfigSection {
    #[serde(default)]
    pub required_keys: Vec<String>,
}

/// Parsed hook bindings from the manifest.
#[derive(Debug, Clone, Default)]
pub struct ParsedHooks {
    /// Maps hook point name → exported WASM function name.
    pub bindings: HashMap<String, String>,
}

/// Full parsed manifest including hooks, tool definition, timers, transforms, and resource limits.
#[derive(Debug, Clone)]
pub struct ParsedManifest {
    pub manifest: SkillManifest,
    pub hooks: ParsedHooks,
    pub tool: Option<SkillDefinition>,
    pub timers: Vec<TimerDeclaration>,
    pub transforms: Vec<TransformDeclaration>,
    pub required_config_keys: Vec<String>,
    pub resources: ResourcesSection,
}

/// Parse a TOML manifest string into a `SkillManifest`.
pub fn parse_manifest(toml_str: &str) -> Result<SkillManifest, WasmHostError> {
    let parsed = parse_manifest_full(toml_str)?;
    Ok(parsed.manifest)
}

/// Parse a TOML manifest string into the full `ParsedManifest` including hooks and tool definition.
pub fn parse_manifest_full(toml_str: &str) -> Result<ParsedManifest, WasmHostError> {
    let file: ManifestFile =
        toml::from_str(toml_str).map_err(|e| WasmHostError::ManifestParseError(e.to_string()))?;

    if file.skill.host_abi != SKILL_HOST_ABI_V1 && file.skill.host_abi != SKILL_HOST_ABI_JAVY {
        return Err(WasmHostError::ManifestParseError(format!(
            "unsupported host_abi '{}'; supported values: {}, {}",
            file.skill.host_abi, SKILL_HOST_ABI_V1, SKILL_HOST_ABI_JAVY
        )));
    }
    encmind_core::skill_id::validate_skill_id(&file.skill.name)
        .map_err(|e| WasmHostError::ManifestParseError(e.replace("skill_id", "skill.name")))?;

    if file.output.is_some() && file.tool.is_none() {
        return Err(WasmHostError::ManifestParseError(
            "[output] section requires a [tool] section".into(),
        ));
    }

    let mut capabilities = CapabilitySet {
        net_outbound: file.capabilities.net_outbound,
        fs_read: file.capabilities.fs_read,
        fs_write: file.capabilities.fs_write,
        exec_shell: file.capabilities.exec_shell,
        env_secrets: file.capabilities.env_secrets,
        kv: file.capabilities.kv,
        prompt_user: file.capabilities.prompt_user,
        emit_events: file.capabilities.emit_events,
        hooks: file.capabilities.hooks,
        schedule_timers: false,
        schedule_transforms: vec![],
    };

    let mut hook_bindings = HashMap::new();
    if let Some(f) = file.hooks.before_tool_call {
        hook_bindings.insert("before_tool_call".into(), f);
    }
    if let Some(f) = file.hooks.after_tool_call {
        hook_bindings.insert("after_tool_call".into(), f);
    }
    if let Some(f) = file.hooks.message_received {
        hook_bindings.insert("message_received".into(), f);
    }
    if let Some(f) = file.hooks.message_sending.or(file.hooks.message_sent) {
        hook_bindings.insert("message_sent".into(), f);
    }
    if let Some(f) = file.hooks.session_start {
        hook_bindings.insert("session_start".into(), f);
    }
    if let Some(f) = file.hooks.session_end {
        hook_bindings.insert("session_end".into(), f);
    }

    // Hook bindings declared under [hooks] are capabilities that must pass policy
    // validation, even when the manifest omits an explicit capabilities.hooks list.
    let mut declared_hook_caps: Vec<String> = hook_bindings.keys().cloned().collect();
    declared_hook_caps.sort();
    for hook_name in declared_hook_caps {
        if !capabilities.hooks.iter().any(|h| h == &hook_name) {
            capabilities.hooks.push(hook_name);
        }
    }

    // Validate and parse timers
    let timers = file.schedule.timers;
    for timer in &timers {
        if timer.interval_secs < 60 {
            return Err(WasmHostError::ManifestParseError(format!(
                "timer '{}' interval_secs must be >= 60, got {}",
                timer.name, timer.interval_secs
            )));
        }
        if timer.export_fn.trim().is_empty() {
            return Err(WasmHostError::ManifestParseError(format!(
                "timer '{}' export_fn must not be empty",
                timer.name
            )));
        }
    }

    // Validate transforms (must have at least one function)
    let transforms = file.schedule.transforms;
    for transform in &transforms {
        if transform.inbound_fn.is_none() && transform.outbound_fn.is_none() {
            return Err(WasmHostError::ManifestParseError(format!(
                "transform for channel '{}' must declare at least one of inbound_fn or outbound_fn",
                transform.channel
            )));
        }
        if transform
            .inbound_fn
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(WasmHostError::ManifestParseError(format!(
                "transform for channel '{}' inbound_fn must not be empty",
                transform.channel
            )));
        }
        if transform
            .outbound_fn
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(WasmHostError::ManifestParseError(format!(
                "transform for channel '{}' outbound_fn must not be empty",
                transform.channel
            )));
        }
    }

    // Auto-populate capabilities from schedule declarations
    if !timers.is_empty() {
        capabilities.schedule_timers = true;
    }
    for transform in &transforms {
        if !capabilities
            .schedule_transforms
            .contains(&transform.channel)
        {
            capabilities
                .schedule_transforms
                .push(transform.channel.clone());
        }
    }

    let mut required_config_keys = Vec::new();
    for raw_key in file.config.required_keys {
        let key = raw_key.trim();
        if key != raw_key {
            return Err(WasmHostError::ManifestParseError(format!(
                "config.required_keys entry '{raw_key}' must not have leading/trailing whitespace"
            )));
        }
        if key.is_empty() {
            return Err(WasmHostError::ManifestParseError(
                "config.required_keys entries must not be empty".into(),
            ));
        }
        if key.len() > 128 {
            return Err(WasmHostError::ManifestParseError(format!(
                "config.required_keys entry '{key}' exceeds 128 characters"
            )));
        }
        if key.chars().any(char::is_control) {
            return Err(WasmHostError::ManifestParseError(format!(
                "config.required_keys entry '{key}' contains control characters"
            )));
        }
        if !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        {
            return Err(WasmHostError::ManifestParseError(format!(
                "config.required_keys entry '{key}' may only contain [A-Za-z0-9._-]"
            )));
        }
        if !required_config_keys.iter().any(|existing| existing == key) {
            required_config_keys.push(key.to_string());
        }
    }

    let manifest = SkillManifest {
        name: file.skill.name,
        version: file.skill.version,
        description: file.skill.description,
        host_abi: file.skill.host_abi,
        capabilities,
    };

    let output_schema = file.output.map(|o| o.schema);
    let tool = file.tool.map(|t| SkillDefinition {
        name: t.name,
        description: t.description,
        parameters: t.parameters,
        output_schema: output_schema.clone(),
    });

    let resources = file.resources.unwrap_or_default();

    Ok(ParsedManifest {
        manifest,
        hooks: ParsedHooks {
            bindings: hook_bindings,
        },
        tool,
        timers,
        transforms,
        required_config_keys,
        resources,
    })
}

/// Validate a manifest for third-party skill constraints.
///
/// Third-party skills are never allowed `exec_shell` or `env_secrets`.
pub fn validate_third_party(manifest: &SkillManifest) -> Result<(), WasmHostError> {
    if manifest.capabilities.exec_shell {
        return Err(WasmHostError::CapabilityDenied(
            "exec_shell is not allowed for third-party skills".into(),
        ));
    }
    if manifest.capabilities.env_secrets {
        return Err(WasmHostError::CapabilityDenied(
            "env_secrets is not allowed for third-party skills".into(),
        ));
    }
    Ok(())
}

/// Validate a skill manifest against the operator's plugin policy.
///
/// Converts the manifest's `CapabilitySet` into capability strings using
/// [`manifest_capabilities`] and delegates to [`PolicyEnforcer::check_skill`].
pub fn validate_against_policy(
    manifest: &SkillManifest,
    enforcer: &PolicyEnforcer,
) -> Result<PolicyDecision, PluginError> {
    // manifest_capabilities already converts CapabilitySet → Vec<String>
    // and check_skill consumes the manifest directly.
    let _ = manifest_capabilities(manifest); // ensure the conversion is sound
    enforcer.check_skill(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_caps() -> CapabilitySet {
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
    fn parse_full_manifest() {
        let toml = r#"
[skill]
name = "web-search"
version = "1.0.0"
description = "Search the web"

[capabilities]
net_outbound = ["www.googleapis.com", "www.bing.com"]
fs_read = []
fs_write = []
exec_shell = false
env_secrets = false
"#;
        let m = parse_manifest(toml).unwrap();
        assert_eq!(m.name, "web-search");
        assert_eq!(m.version, "1.0.0");
        assert_eq!(m.description, "Search the web");
        assert_eq!(m.capabilities.net_outbound.len(), 2);
        assert!(!m.capabilities.exec_shell);
        assert!(!m.capabilities.env_secrets);
    }

    #[test]
    fn parse_minimal_manifest() {
        let toml = r#"
[skill]
name = "hello"
version = "0.1.0"
"#;
        let m = parse_manifest(toml).unwrap();
        assert_eq!(m.name, "hello");
        assert!(m.capabilities.net_outbound.is_empty());
        assert!(!m.capabilities.exec_shell);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let result = parse_manifest("not valid toml {{{}");
        assert!(result.is_err());
        match result.unwrap_err() {
            WasmHostError::ManifestParseError(_) => {}
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn missing_skill_section_returns_error() {
        let result = parse_manifest("[capabilities]\nnet_outbound = []");
        assert!(result.is_err());
    }

    #[test]
    fn validate_third_party_ok() {
        let m = SkillManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            description: String::new(),
            host_abi: SKILL_HOST_ABI_V1.into(),
            capabilities: CapabilitySet {
                net_outbound: vec!["example.com".into()],
                ..default_caps()
            },
        };
        assert!(validate_third_party(&m).is_ok());
    }

    #[test]
    fn validate_third_party_rejects_exec_shell() {
        let m = SkillManifest {
            name: "evil".into(),
            version: "1.0.0".into(),
            description: String::new(),
            host_abi: SKILL_HOST_ABI_V1.into(),
            capabilities: CapabilitySet {
                exec_shell: true,
                ..default_caps()
            },
        };
        assert!(validate_third_party(&m).is_err());
    }

    #[test]
    fn validate_third_party_rejects_env_secrets() {
        let m = SkillManifest {
            name: "evil".into(),
            version: "1.0.0".into(),
            description: String::new(),
            host_abi: SKILL_HOST_ABI_V1.into(),
            capabilities: CapabilitySet {
                env_secrets: true,
                ..default_caps()
            },
        };
        assert!(validate_third_party(&m).is_err());
    }

    #[test]
    fn validate_against_policy_low_caps_allowed() {
        use encmind_core::policy::{PluginPolicyConfig, PolicyDecision, PolicyEnforcer};

        let enforcer = PolicyEnforcer::new(PluginPolicyConfig::default());
        let m = SkillManifest {
            name: "safe".into(),
            version: "1.0.0".into(),
            description: String::new(),
            host_abi: SKILL_HOST_ABI_V1.into(),
            capabilities: CapabilitySet {
                net_outbound: vec!["api.example.com".into()],
                ..default_caps()
            },
        };
        let decision = validate_against_policy(&m, &enforcer).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn validate_against_policy_exec_shell_denied() {
        use encmind_core::policy::{PluginPolicyConfig, PolicyDecision, PolicyEnforcer};

        let enforcer = PolicyEnforcer::new(PluginPolicyConfig::default());
        let m = SkillManifest {
            name: "dangerous".into(),
            version: "1.0.0".into(),
            description: String::new(),
            host_abi: SKILL_HOST_ABI_V1.into(),
            capabilities: CapabilitySet {
                exec_shell: true,
                ..default_caps()
            },
        };
        let decision = validate_against_policy(&m, &enforcer).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn parse_manifest_with_new_capabilities() {
        let toml = r#"
[skill]
name = "kv-skill"
version = "1.0.0"

[capabilities]
kv = true
prompt_user = true
emit_events = ["custom.data_ready"]
hooks = ["before_tool_call"]
"#;
        let m = parse_manifest(toml).unwrap();
        assert!(m.capabilities.kv);
        assert!(m.capabilities.prompt_user);
        assert_eq!(m.capabilities.emit_events, vec!["custom.data_ready"]);
        assert_eq!(m.capabilities.hooks, vec!["before_tool_call"]);
    }

    #[test]
    fn parse_manifest_defaults_host_abi_to_v1() {
        let toml = r#"
[skill]
name = "default-abi"
version = "1.0.0"
"#;
        let m = parse_manifest(toml).unwrap();
        assert_eq!(m.host_abi, SKILL_HOST_ABI_V1);
    }

    #[test]
    fn parse_manifest_accepts_javy_host_abi() {
        let toml = r#"
[skill]
name = "javy-skill"
version = "1.0.0"
host_abi = "javy"

[tool]
name = "javy_tool"
description = "A Javy skill"
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(parsed.manifest.host_abi, SKILL_HOST_ABI_JAVY);
        assert_eq!(parsed.manifest.name, "javy-skill");
    }

    #[test]
    fn parse_manifest_rejects_unsupported_host_abi() {
        let toml = r#"
[skill]
name = "future-abi"
version = "1.0.0"
host_abi = "v9"
"#;
        match parse_manifest_full(toml).unwrap_err() {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("unsupported host_abi"), "got: {msg}");
                assert!(
                    msg.contains("javy"),
                    "error should mention javy as supported: {msg}"
                );
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_manifest_rejects_invalid_skill_name() {
        let toml = r#"
[skill]
name = "bad/skill"
version = "1.0.0"
"#;
        match parse_manifest_full(toml).unwrap_err() {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("invalid skill.name"), "got: {msg}");
                assert!(msg.contains("allowed characters"), "got: {msg}");
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_manifest_with_hooks_section() {
        let toml = r#"
[skill]
name = "hooked"
version = "1.0.0"

[hooks]
before_tool_call = "__on_before_tool_call"
message_received = "__on_message_received"
message_sending = "__on_message_sending"
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(parsed.hooks.bindings.len(), 3);
        assert_eq!(
            parsed.hooks.bindings.get("before_tool_call").unwrap(),
            "__on_before_tool_call"
        );
        assert_eq!(
            parsed.hooks.bindings.get("message_received").unwrap(),
            "__on_message_received"
        );
        assert_eq!(
            parsed.hooks.bindings.get("message_sent").unwrap(),
            "__on_message_sending"
        );
        assert!(parsed
            .manifest
            .capabilities
            .hooks
            .contains(&"before_tool_call".to_string()));
        assert!(parsed
            .manifest
            .capabilities
            .hooks
            .contains(&"message_received".to_string()));
        assert!(parsed
            .manifest
            .capabilities
            .hooks
            .contains(&"message_sent".to_string()));
    }

    #[test]
    fn parse_manifest_message_sent_backward_compat() {
        let toml = r#"
[skill]
name = "hooked"
version = "1.0.0"

[hooks]
message_sent = "__on_message_sent"
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(
            parsed.hooks.bindings.get("message_sent").unwrap(),
            "__on_message_sent"
        );
    }

    #[test]
    fn parse_manifest_with_tool_section() {
        let toml = r#"
[skill]
name = "search"
version = "1.0.0"

[tool]
name = "web_search"
description = "Search the web for information"
parameters = { type = "object" }
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        let tool = parsed.tool.unwrap();
        assert_eq!(tool.name, "web_search");
        assert_eq!(tool.description, "Search the web for information");
        assert!(tool.parameters.is_object());
    }

    #[test]
    fn parse_manifest_with_schedule_timers() {
        let toml = r#"
[skill]
name = "timer-skill"
version = "1.0.0"

[[schedule.timers]]
name = "daily_check"
interval_secs = 3600
export_fn = "__on_daily_check"
description = "Check daily"
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(parsed.timers.len(), 1);
        assert_eq!(parsed.timers[0].name, "daily_check");
        assert_eq!(parsed.timers[0].interval_secs, 3600);
        assert_eq!(parsed.timers[0].export_fn, "__on_daily_check");
        assert!(parsed.manifest.capabilities.schedule_timers);
    }

    #[test]
    fn parse_manifest_with_schedule_transforms() {
        let toml = r#"
[skill]
name = "transform-skill"
version = "1.0.0"

[[schedule.transforms]]
channel = "telegram"
inbound_fn = "__transform_inbound"
priority = 10
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(parsed.transforms.len(), 1);
        assert_eq!(parsed.transforms[0].channel, "telegram");
        assert_eq!(
            parsed.transforms[0].inbound_fn,
            Some("__transform_inbound".into())
        );
        assert!(parsed.transforms[0].outbound_fn.is_none());
        assert_eq!(parsed.transforms[0].priority, 10);
        assert!(parsed
            .manifest
            .capabilities
            .schedule_transforms
            .contains(&"telegram".to_string()));
    }

    #[test]
    fn parse_manifest_with_resources() {
        let toml = r#"
[skill]
name = "resource-skill"
version = "1.0.0"

[resources]
max_fuel_per_invocation = 5000000
max_wall_clock_ms = 10000
max_invocations_per_minute = 30
max_concurrent = 1
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(parsed.resources.max_fuel_per_invocation, Some(5_000_000));
        assert_eq!(parsed.resources.max_wall_clock_ms, Some(10_000));
        assert_eq!(parsed.resources.max_invocations_per_minute, Some(30));
        assert_eq!(parsed.resources.max_concurrent, Some(1));
    }

    #[test]
    fn parse_manifest_backward_compat_no_new_sections() {
        let toml = r#"
[skill]
name = "old-skill"
version = "1.0.0"

[capabilities]
net_outbound = ["example.com"]
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert!(parsed.timers.is_empty());
        assert!(parsed.transforms.is_empty());
        assert!(!parsed.manifest.capabilities.schedule_timers);
        assert!(parsed.manifest.capabilities.schedule_transforms.is_empty());
        assert_eq!(parsed.resources.max_fuel_per_invocation, None);
    }

    #[test]
    fn timer_declaration_rejects_interval_below_60() {
        let toml = r#"
[skill]
name = "fast-timer"
version = "1.0.0"

[[schedule.timers]]
name = "too_fast"
interval_secs = 30
export_fn = "__tick"
"#;
        let result = parse_manifest_full(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("interval_secs must be >= 60"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn timer_declaration_rejects_empty_export_fn() {
        let toml = r#"
[skill]
name = "timer-empty-export"
version = "1.0.0"

[[schedule.timers]]
name = "tick"
interval_secs = 60
export_fn = "   "
"#;
        let result = parse_manifest_full(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("export_fn must not be empty"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn transform_requires_at_least_one_fn() {
        let toml = r#"
[skill]
name = "no-fn-transform"
version = "1.0.0"

[[schedule.transforms]]
channel = "telegram"
"#;
        let result = parse_manifest_full(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("at least one of inbound_fn or outbound_fn"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn transform_rejects_empty_inbound_fn() {
        let toml = r#"
[skill]
name = "empty-inbound-transform"
version = "1.0.0"

[[schedule.transforms]]
channel = "telegram"
inbound_fn = "   "
"#;
        let result = parse_manifest_full(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("inbound_fn must not be empty"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn transform_rejects_empty_outbound_fn() {
        let toml = r#"
[skill]
name = "empty-outbound-transform"
version = "1.0.0"

[[schedule.transforms]]
channel = "telegram"
outbound_fn = "   "
"#;
        let result = parse_manifest_full(toml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("outbound_fn must not be empty"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn manifest_with_output_schema_parses() {
        let toml = r#"
[skill]
name = "summarize"
version = "1.0.0"
description = "Summarize text"

[tool]
name = "summarize"
description = "Summarize input text"

[output]
schema = { type = "object", properties = { summary = { type = "string" } } }
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        let tool = parsed.tool.as_ref().unwrap();
        assert!(tool.output_schema.is_some());
        let schema = tool.output_schema.as_ref().unwrap();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["summary"].is_object());
    }

    #[test]
    fn manifest_without_output_schema_defaults_none() {
        let toml = r#"
[skill]
name = "echo"
version = "1.0.0"

[tool]
name = "echo"
description = "Echo input"
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        let tool = parsed.tool.as_ref().unwrap();
        assert!(tool.output_schema.is_none());
    }

    #[test]
    fn manifest_with_output_schema_but_no_tool_fails() {
        let toml = r#"
[skill]
name = "bad-skill"
version = "1.0.0"

[output]
schema = { type = "object", properties = { summary = { type = "string" } } }
"#;
        let err = parse_manifest_full(toml).unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("[output] section requires a [tool] section"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }

    #[test]
    fn manifest_with_required_config_keys_parses() {
        let toml = r#"
[skill]
name = "requires-config"
version = "1.0.0"

[config]
required_keys = ["api_key", "api_key", "base_url"]
"#;
        let parsed = parse_manifest_full(toml).unwrap();
        assert_eq!(
            parsed.required_config_keys,
            vec!["api_key".to_string(), "base_url".to_string()]
        );
    }

    #[test]
    fn manifest_rejects_required_config_key_with_whitespace() {
        let toml = r#"
[skill]
name = "bad-required-config"
version = "1.0.0"

[config]
required_keys = [" api_key "]
"#;
        let err = parse_manifest_full(toml).unwrap_err();
        match err {
            WasmHostError::ManifestParseError(msg) => {
                assert!(msg.contains("must not have leading/trailing whitespace"));
            }
            other => panic!("expected ManifestParseError, got {other:?}"),
        }
    }
}
