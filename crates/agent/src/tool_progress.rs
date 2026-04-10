//! Task-local progress sink for long-running tool handlers.
//!
//! Tool handlers can report intermediate progress by calling
//! [`report_progress`] with a status message and optional fraction.
//! The runtime sets up the sink around each tool dispatch and
//! forwards events into the streaming `ChatEvent::ToolProgress`
//! channel. If no sink is active (non-streaming run, unit tests,
//! direct dispatch), calls are silently dropped.
//!
//! Design notes:
//!
//! - The sink is a `mpsc::Sender<ProgressUpdate>` stored in a tokio
//!   task-local, so it flows through awaits within the same task
//!   without requiring changes to the `InternalToolHandler` trait
//!   signature.
//! - Writes are `try_send` and drop on full channel — progress is
//!   best-effort. A long-running tool must not block waiting for the
//!   channel buffer.
//! - The sink is unset outside of a tool dispatch scope, so tools
//!   can safely call `report_progress` even when they aren't sure
//!   whether streaming is enabled.

use tokio::sync::mpsc;

/// A progress update emitted by a tool handler.
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    /// Short human-readable message (e.g. "fetching", "parsing 3/10").
    pub message: String,
    /// Optional progress fraction in `[0.0, 1.0]`. `None` means the
    /// tool has no known total (unbounded progress).
    pub fraction: Option<f32>,
}

tokio::task_local! {
    /// Task-local progress sink scoped around each tool dispatch by
    /// `AgentRuntime`. Unset outside of a dispatch scope.
    pub static TOOL_PROGRESS_SINK: mpsc::Sender<ProgressUpdate>;
}

/// Report a progress update to the current tool dispatch's sink.
///
/// Silently no-ops when no sink is active (non-streaming run, tests,
/// direct calls). Non-blocking: uses `try_send` so a full buffer
/// drops the update rather than stalling the handler.
///
/// **Fraction sanitization**: `serde_json` cannot serialize `NaN` or
/// `±∞`, and a serialization failure in the streaming path would
/// cancel the entire run (see `send_stream_event` in the gateway).
/// To insulate the runtime from buggy handlers, non-finite fractions
/// are dropped to `None` and finite values are clamped to `[0.0, 1.0]`
/// at the source.
pub fn report_progress(message: impl Into<String>, fraction: Option<f32>) {
    let fraction = sanitize_fraction(fraction);
    let update = ProgressUpdate {
        message: message.into(),
        fraction,
    };
    let _ = TOOL_PROGRESS_SINK.try_with(|sink| {
        let _ = sink.try_send(update);
    });
}

/// Convenience: report a message without a progress fraction.
pub fn report_status(message: impl Into<String>) {
    report_progress(message, None);
}

/// Normalize a fraction to a JSON-safe value: drop non-finite values
/// (NaN/±∞) to `None`, clamp finite values to `[0.0, 1.0]`. `None`
/// stays `None`. Exposed as a separate function so tests can verify
/// the exact transformation without round-tripping through the sink.
pub(crate) fn sanitize_fraction(fraction: Option<f32>) -> Option<f32> {
    fraction.and_then(|f| {
        if f.is_finite() {
            Some(f.clamp(0.0, 1.0))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn report_outside_scope_is_noop() {
        // Must not panic or block.
        report_status("ignored");
        report_progress("ignored too", Some(0.5));
    }

    #[tokio::test]
    async fn report_inside_scope_reaches_sink() {
        let (tx, mut rx) = mpsc::channel::<ProgressUpdate>(4);
        TOOL_PROGRESS_SINK
            .scope(tx, async {
                report_status("first");
                report_progress("second", Some(0.5));
            })
            .await;

        let first = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.message, "first");
        assert!(first.fraction.is_none());

        let second = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.message, "second");
        assert_eq!(second.fraction, Some(0.5));
    }

    #[test]
    fn sanitize_fraction_drops_nan_and_infinities() {
        assert_eq!(sanitize_fraction(None), None);
        assert_eq!(sanitize_fraction(Some(f32::NAN)), None);
        assert_eq!(sanitize_fraction(Some(f32::INFINITY)), None);
        assert_eq!(sanitize_fraction(Some(f32::NEG_INFINITY)), None);
    }

    #[test]
    fn sanitize_fraction_clamps_finite_values_to_unit_range() {
        assert_eq!(sanitize_fraction(Some(0.0)), Some(0.0));
        assert_eq!(sanitize_fraction(Some(0.5)), Some(0.5));
        assert_eq!(sanitize_fraction(Some(1.0)), Some(1.0));
        // Out-of-range finite values clamp, not drop, so a handler
        // that accidentally reports 1.2 still produces a visible
        // progress event.
        assert_eq!(sanitize_fraction(Some(-0.25)), Some(0.0));
        assert_eq!(sanitize_fraction(Some(1.25)), Some(1.0));
        assert_eq!(sanitize_fraction(Some(f32::MAX)), Some(1.0));
        assert_eq!(sanitize_fraction(Some(f32::MIN)), Some(0.0));
    }

    #[tokio::test]
    async fn report_progress_drops_nan_to_none() {
        let (tx, mut rx) = mpsc::channel::<ProgressUpdate>(4);
        TOOL_PROGRESS_SINK
            .scope(tx, async {
                report_progress("bad", Some(f32::NAN));
                report_progress("also bad", Some(f32::INFINITY));
                report_progress("ok", Some(2.0));
            })
            .await;

        let a = rx.recv().await.unwrap();
        assert_eq!(a.message, "bad");
        assert!(a.fraction.is_none(), "NaN must sanitize to None");

        let b = rx.recv().await.unwrap();
        assert_eq!(b.message, "also bad");
        assert!(b.fraction.is_none(), "inf must sanitize to None");

        let c = rx.recv().await.unwrap();
        assert_eq!(c.message, "ok");
        assert_eq!(c.fraction, Some(1.0), "2.0 must clamp to 1.0");
    }

    #[tokio::test]
    async fn progress_update_is_json_serializable_after_sanitize() {
        // Build a ChatEvent-equivalent struct and verify it serializes.
        // The actual ChatEvent lives in runtime.rs; here we just verify
        // that after sanitize_fraction the value is JSON-safe.
        for raw in [
            Some(f32::NAN),
            Some(f32::INFINITY),
            Some(f32::NEG_INFINITY),
            Some(0.0),
            Some(0.5),
            Some(1.0),
            Some(42.0),
            Some(-1.0),
            None,
        ] {
            let sanitized = sanitize_fraction(raw);
            // serde_json::to_value on Option<f32> will fail for NaN/inf;
            // sanitize_fraction must have removed those.
            let json = serde_json::to_value(sanitized);
            assert!(
                json.is_ok(),
                "sanitize_fraction({raw:?}) -> {sanitized:?} must be JSON-safe"
            );
        }
    }

    #[tokio::test]
    async fn full_channel_drops_updates() {
        // Channel of capacity 1 — second send must drop without
        // blocking or panicking.
        let (tx, mut rx) = mpsc::channel::<ProgressUpdate>(1);
        TOOL_PROGRESS_SINK
            .scope(tx, async {
                report_status("kept");
                report_status("dropped");
            })
            .await;

        let kept = rx.recv().await.unwrap();
        assert_eq!(kept.message, "kept");
        // No second message — dropped by try_send on full channel.
        assert!(rx.try_recv().is_err());
    }
}
