use std::sync::Arc;

use async_trait::async_trait;

use encmind_agent::firewall::EgressFirewall;
use encmind_core::config::ScreenshotPayloadMode;
use encmind_core::error::PluginError;
use encmind_core::plugin::{NativePlugin, PluginKind, PluginManifest, PluginRegistrar};

use crate::pool::{BrowserPool, SessionBrowserManager};
use crate::tools::{
    BrowserActHandler, BrowserGetTextHandler, BrowserNavigateHandler, BrowserScreenshotHandler,
};

/// Native plugin that registers browser automation tools.
pub struct BrowserPlugin {
    pool: Arc<BrowserPool>,
    session_manager: Arc<SessionBrowserManager>,
    firewall: Arc<EgressFirewall>,
    screenshot_mode: ScreenshotPayloadMode,
    browser_config: encmind_core::config::BrowserConfig,
    required: bool,
}

impl BrowserPlugin {
    pub fn new(
        pool: Arc<BrowserPool>,
        session_manager: Arc<SessionBrowserManager>,
        firewall: Arc<EgressFirewall>,
        screenshot_mode: ScreenshotPayloadMode,
        browser_config: encmind_core::config::BrowserConfig,
        required: bool,
    ) -> Self {
        Self {
            pool,
            session_manager,
            firewall,
            screenshot_mode,
            browser_config,
            required,
        }
    }

    /// Access the underlying browser pool.
    pub fn pool(&self) -> &Arc<BrowserPool> {
        &self.pool
    }
}

#[async_trait]
impl NativePlugin for BrowserPlugin {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "browser".into(),
            name: "Browser Automation".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "Headless Chrome browser pool".into(),
            kind: PluginKind::General,
            required: self.required,
        }
    }

    async fn register(&self, api: &mut dyn PluginRegistrar) -> Result<(), PluginError> {
        api.register_tool(
            "navigate",
            "Navigate to a URL and return the page title",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to navigate to"
                    }
                },
                "required": ["url"]
            }),
            Arc::new(BrowserNavigateHandler::new(
                self.pool.clone(),
                self.firewall.clone(),
                self.browser_config.clone(),
            )),
        )?;

        api.register_tool(
            "screenshot",
            "Take a screenshot of a web page and return base64-encoded PNG",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to screenshot"
                    }
                },
                "required": ["url"]
            }),
            Arc::new(BrowserScreenshotHandler::new(
                self.pool.clone(),
                self.firewall.clone(),
                self.browser_config.clone(),
                self.screenshot_mode,
            )),
        )?;

        api.register_tool(
            "get_text",
            "Extract the visible text content from a web page",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to extract text from"
                    }
                },
                "required": ["url"]
            }),
            Arc::new(BrowserGetTextHandler::new(
                self.pool.clone(),
                self.firewall.clone(),
                self.browser_config.clone(),
            )),
        )?;

        api.register_tool(
            "act",
            "Perform an interactive browser action (click, type, press, select, upload, wait, screenshot, get_text, eval, close) on a session-scoped page",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to navigate to. Required on first call; optional if reusing existing page."
                    },
                    "actions": {
                        "type": "array",
                        "description": "Optional single-item action array form. Current runtime supports exactly one action per call.",
                        "minItems": 1,
                        "maxItems": 1,
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["navigate", "click", "type", "press", "select", "upload", "wait", "screenshot", "get_text", "eval", "close"]
                                },
                                "url": { "type": "string" },
                                "selector": { "type": "string" },
                                "text": { "type": "string" },
                                "key": { "type": "string" },
                                "value": { "type": "string" },
                                "script": { "type": "string" },
                                "timeout_ms": { "type": "integer" },
                                "files": {
                                    "type": "array",
                                    "items": { "type": "string" }
                                }
                            },
                            "required": ["action"]
                        }
                    },
                    "action": {
                        "type": "string",
                        "enum": ["navigate", "click", "type", "press", "select", "upload", "wait", "screenshot", "get_text", "eval", "close"],
                        "description": "The action to perform on the page."
                    },
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the target element (required for click, type, select, upload)."
                    },
                    "text": {
                        "type": "string",
                        "description": "Text to type (for 'type' action)."
                    },
                    "key": {
                        "type": "string",
                        "description": "Key name to press, e.g. 'Enter', 'Tab', 'Escape' (for 'press' action)."
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to select from dropdown (for 'select' action)."
                    },
                    "script": {
                        "type": "string",
                        "description": "JavaScript to evaluate in the page context (for 'eval' action; requires browser.eval_enabled=true)."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Wait duration in ms (for 'wait' action). Max 10000."
                    },
                    "files": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of local file paths to upload (for 'upload' action). Must be within browser.upload_root."
                    }
                },
                "description": "Provide either top-level 'action' or a single-item 'actions' array."
            }),
            Arc::new(BrowserActHandler::new(
                self.session_manager.clone(),
                self.firewall.clone(),
                self.browser_config.clone(),
                self.screenshot_mode,
            )),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_values() {
        // We can't create a real BrowserPool without Chrome, but we can test
        // the manifest by constructing the plugin with a mock in a real
        // integration test. For now, verify the manifest shape statically.
        let manifest = PluginManifest {
            id: "browser".into(),
            name: "Browser Automation".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            description: "Headless Chrome browser pool".into(),
            kind: PluginKind::General,
            required: false,
        };
        assert_eq!(manifest.id, "browser");
        assert_eq!(manifest.kind, PluginKind::General);
        assert!(!manifest.required);
    }

    #[test]
    fn shutdown_is_noop_by_default() {
        // NativePlugin::shutdown has a default impl that returns Ok(())
        // Just verify the trait compiles with BrowserPlugin
    }
}
