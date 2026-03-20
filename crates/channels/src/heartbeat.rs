use std::future::Future;
use std::path::Path;

use chrono::{DateTime, FixedOffset, Timelike, Utc};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use encmind_core::config::HeartbeatConfig;

pub struct HeartbeatRunner {
    config: HeartbeatConfig,
    cancel: CancellationToken,
    last_result: Mutex<Option<(String, DateTime<Utc>)>>,
}

impl HeartbeatRunner {
    pub fn new(config: HeartbeatConfig, cancel: CancellationToken) -> Self {
        Self {
            config,
            cancel,
            last_result: Mutex::new(None),
        }
    }

    /// Check if the current time is within the configured active hours.
    /// Returns true if no active_hours are configured.
    /// Respects `active_hours.timezone` — supports "UTC" and fixed offsets
    /// like "+05:30" / "-08:00". Falls back to UTC for unrecognized values.
    pub fn is_within_active_hours(&self) -> bool {
        let hours = match &self.config.active_hours {
            Some(h) => h,
            None => return true,
        };

        let offset = parse_timezone_offset(&hours.timezone);
        let now_local = Utc::now().with_timezone(&offset);
        let current_minutes = now_local.hour() * 60 + now_local.minute();

        let start = parse_hhmm(&hours.start).unwrap_or(0);
        let end = parse_hhmm(&hours.end).unwrap_or(24 * 60);

        if start <= end {
            current_minutes >= start && current_minutes < end
        } else {
            // Wraps midnight: e.g. 22:00 - 06:00
            current_minutes >= start || current_minutes < end
        }
    }

    /// Read the workspace file, returning its content or None if missing/empty.
    pub fn read_workspace_file(&self, workspace_dir: &Path) -> Option<String> {
        let path = workspace_dir.join(&self.config.workspace_file);
        let content = std::fs::read_to_string(path).ok()?;
        if content.trim().is_empty() {
            None
        } else {
            Some(content)
        }
    }

    /// Check if the result text duplicates the last result within the dedup window.
    pub async fn is_duplicate(&self, result_text: &str) -> bool {
        let guard = self.last_result.lock().await;
        match guard.as_ref() {
            Some((last_text, last_time)) => {
                if last_text != result_text {
                    return false;
                }
                let window = chrono::Duration::hours(self.config.dedup_window_hours as i64);
                Utc::now() - *last_time < window
            }
            None => false,
        }
    }

    /// Record a result for dedup tracking.
    pub async fn record_result(&self, text: &str) {
        let mut guard = self.last_result.lock().await;
        *guard = Some((text.to_string(), Utc::now()));
    }

    /// Build the heartbeat prompt from workspace content.
    pub fn build_prompt(workspace_content: &str) -> String {
        format!(
            "{}\n\nCurrent time: {}",
            workspace_content,
            Utc::now().to_rfc3339()
        )
    }

    /// Run the heartbeat loop. `execute_fn` is called with the prompt and returns
    /// the result text (provided by the gateway/agent layer).
    pub async fn run_loop<F, Fut>(&self, execute_fn: F, workspace_dir: &Path)
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        let interval = std::time::Duration::from_secs(self.config.interval_minutes as u64 * 60);
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate tick

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = ticker.tick() => {
                    if !self.is_within_active_hours() {
                        continue;
                    }

                    let content = match self.read_workspace_file(workspace_dir) {
                        Some(c) => c,
                        None => continue,
                    };

                    let prompt = Self::build_prompt(&content);

                    if let Some(result_text) = execute_fn(prompt).await {
                        if !self.is_duplicate(&result_text).await {
                            self.record_result(&result_text).await;
                        }
                    }
                }
            }
        }
    }
}

fn parse_hhmm_parts(s: &str) -> Option<(u32, u32)> {
    let (h, m) = s.split_once(':')?;
    let h: u32 = h.parse().ok()?;
    let m: u32 = m.parse().ok()?;
    Some((h, m))
}

/// Parse "HH:MM" into total minutes for active hours.
/// Accepts 00:00..23:59 and 24:00.
fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = parse_hhmm_parts(s)?;
    if m > 59 {
        return None;
    }
    if h > 24 {
        return None;
    }
    if h == 24 && m != 0 {
        return None;
    }
    Some(h * 60 + m)
}

/// Parse a timezone string into a FixedOffset.
/// Supports "UTC", "+HH:MM", "-HH:MM". Falls back to UTC for unrecognized values.
fn parse_timezone_offset(tz: &str) -> FixedOffset {
    let trimmed = tz.trim();
    if trimmed.eq_ignore_ascii_case("utc") || trimmed == "+00:00" || trimmed == "Z" {
        return FixedOffset::east_opt(0).unwrap();
    }
    // Try "+HH:MM" or "-HH:MM"
    if (trimmed.starts_with('+') || trimmed.starts_with('-')) && trimmed.len() >= 5 {
        let sign: i32 = if trimmed.starts_with('-') { -1 } else { 1 };
        let rest = &trimmed[1..];
        if let Some((hours, minutes)) = parse_hhmm_parts(rest) {
            // Fixed offsets allow 00:00..23:59.
            if hours > 23 || minutes > 59 {
                tracing::warn!(
                    "invalid timezone offset '{tz}', falling back to UTC. \
                     Hour must be 00-23 and minute 00-59."
                );
                return FixedOffset::east_opt(0).unwrap();
            }
            let total_minutes = hours * 60 + minutes;
            let secs = sign * (total_minutes as i32) * 60;
            if let Some(offset) = FixedOffset::east_opt(secs) {
                return offset;
            }
        }
    }
    tracing::warn!(
        "unrecognized timezone '{tz}', falling back to UTC. \
         Use '+HH:MM' / '-HH:MM' / 'UTC' format."
    );
    FixedOffset::east_opt(0).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;
    use encmind_core::config::{ActiveHours, HeartbeatConfig};

    fn config_with_hours(start: &str, end: &str) -> HeartbeatConfig {
        HeartbeatConfig {
            enabled: true,
            active_hours: Some(ActiveHours {
                start: start.into(),
                end: end.into(),
                timezone: "UTC".into(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn active_hours_within_range() {
        // We use a wide range 00:00 - 23:59 so the test always passes regardless of time
        let config = config_with_hours("00:00", "23:59");
        let cancel = CancellationToken::new();
        let runner = HeartbeatRunner::new(config, cancel);
        assert!(runner.is_within_active_hours());

        // No active hours → always within
        let config_none = HeartbeatConfig {
            active_hours: None,
            ..Default::default()
        };
        let runner2 = HeartbeatRunner::new(config_none, CancellationToken::new());
        assert!(runner2.is_within_active_hours());
    }

    #[tokio::test]
    async fn dedup_detects_identical_message() {
        let config = HeartbeatConfig {
            dedup_window_hours: 24,
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let runner = HeartbeatRunner::new(config, cancel);

        assert!(!runner.is_duplicate("first").await);
        runner.record_result("first").await;
        assert!(runner.is_duplicate("first").await);
        assert!(!runner.is_duplicate("different").await);
    }

    #[test]
    fn parse_timezone_offset_handles_formats() {
        let utc = super::parse_timezone_offset("UTC");
        assert_eq!(utc, FixedOffset::east_opt(0).unwrap());

        let plus = super::parse_timezone_offset("+05:30");
        assert_eq!(plus, FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap());

        let minus = super::parse_timezone_offset("-08:00");
        assert_eq!(minus, FixedOffset::east_opt(-8 * 3600).unwrap());

        // Unrecognized falls back to UTC
        let fallback = super::parse_timezone_offset("America/New_York");
        assert_eq!(fallback, FixedOffset::east_opt(0).unwrap());

        // Out-of-range offsets are rejected and fall back to UTC
        let invalid = super::parse_timezone_offset("+25:99");
        assert_eq!(invalid, FixedOffset::east_opt(0).unwrap());
    }

    #[test]
    fn parse_hhmm_validates_ranges() {
        assert_eq!(super::parse_hhmm("00:00"), Some(0));
        assert_eq!(super::parse_hhmm("23:59"), Some(23 * 60 + 59));
        assert_eq!(super::parse_hhmm("24:00"), Some(24 * 60));
        assert_eq!(super::parse_hhmm("24:01"), None);
        assert_eq!(super::parse_hhmm("25:00"), None);
        assert_eq!(super::parse_hhmm("10:60"), None);
    }

    #[test]
    fn build_prompt_includes_timestamp() {
        let prompt = HeartbeatRunner::build_prompt("Check the workspace");
        assert!(prompt.starts_with("Check the workspace"));
        assert!(prompt.contains("Current time:"));
        // Verify it contains an ISO-8601-ish timestamp
        assert!(prompt.contains("T"));
    }
}
