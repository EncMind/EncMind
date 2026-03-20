/// Violation types detected by the loop detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopViolation {
    /// Total tool call cap exceeded.
    ToolCallCapExceeded { limit: u32, actual: u32 },
    /// Same tool failed consecutively too many times.
    ConsecutiveFailures { tool: String, count: u32 },
    /// A repeating pattern of tool calls was detected.
    RepeatingPattern {
        pattern_len: usize,
        repetitions: usize,
    },
}

impl std::fmt::Display for LoopViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolCallCapExceeded { limit, actual } => {
                write!(f, "tool call cap exceeded ({actual}/{limit})")
            }
            Self::ConsecutiveFailures { tool, count } => {
                write!(f, "tool '{tool}' failed {count} times consecutively")
            }
            Self::RepeatingPattern {
                pattern_len,
                repetitions,
            } => {
                write!(
                    f,
                    "repeating pattern detected (length {pattern_len}, {repetitions} repetitions)"
                )
            }
        }
    }
}

/// Tracks tool call history and detects runaway loops.
pub struct LoopDetector {
    history: Vec<(String, bool)>, // (tool_name, is_error)
    cap: u32,
    consecutive_failure_threshold: u32,
}

impl LoopDetector {
    /// Create a new detector with the given tool call cap.
    pub fn new(cap: u32) -> Self {
        Self {
            history: Vec::new(),
            cap,
            consecutive_failure_threshold: 5,
        }
    }

    /// Record a tool call and check for violations.
    /// Returns `Some(violation)` if a loop condition is detected.
    pub fn record_and_check(&mut self, tool_name: &str, is_error: bool) -> Option<LoopViolation> {
        self.history.push((tool_name.to_string(), is_error));

        // Check 1: total cap
        let total = self.history.len() as u32;
        if total > self.cap {
            return Some(LoopViolation::ToolCallCapExceeded {
                limit: self.cap,
                actual: total,
            });
        }

        // Check 2: consecutive failures of the same tool
        if is_error {
            let consecutive = self
                .history
                .iter()
                .rev()
                .take_while(|(name, err)| name == tool_name && *err)
                .count() as u32;
            if consecutive >= self.consecutive_failure_threshold {
                return Some(LoopViolation::ConsecutiveFailures {
                    tool: tool_name.to_string(),
                    count: consecutive,
                });
            }
        }

        // Check 3: repeating pattern (pattern length 2-4, at least 3 repetitions)
        if let Some(violation) = self.detect_repeating_pattern() {
            return Some(violation);
        }

        None
    }

    fn detect_repeating_pattern(&self) -> Option<LoopViolation> {
        let names: Vec<&str> = self.history.iter().map(|(n, _)| n.as_str()).collect();
        let len = names.len();

        for pattern_len in 2..=4 {
            let min_reps = 3;
            let needed = pattern_len * min_reps;
            if len < needed {
                continue;
            }

            // Check if the last `needed` entries form a repeating pattern
            let tail = &names[len - needed..];
            let pattern = &tail[..pattern_len];
            let mut reps = 0;
            for chunk in tail.chunks_exact(pattern_len) {
                if chunk == pattern {
                    reps += 1;
                } else {
                    break;
                }
            }
            if reps >= min_reps {
                return Some(LoopViolation::RepeatingPattern {
                    pattern_len,
                    repetitions: reps,
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_cap() {
        let mut det = LoopDetector::new(10);
        for i in 0..10 {
            assert!(det.record_and_check(&format!("tool_{i}"), false).is_none());
        }
    }

    #[test]
    fn rejects_over_cap() {
        let mut det = LoopDetector::new(3);
        assert!(det.record_and_check("a", false).is_none());
        assert!(det.record_and_check("b", false).is_none());
        assert!(det.record_and_check("c", false).is_none());
        let v = det.record_and_check("d", false);
        assert!(matches!(
            v,
            Some(LoopViolation::ToolCallCapExceeded {
                limit: 3,
                actual: 4
            })
        ));
    }

    #[test]
    fn detects_consecutive_failures() {
        let mut det = LoopDetector::new(100);
        for _ in 0..4 {
            assert!(det.record_and_check("bad_tool", true).is_none());
        }
        let v = det.record_and_check("bad_tool", true);
        assert!(
            matches!(v, Some(LoopViolation::ConsecutiveFailures { tool, count: 5 }) if tool == "bad_tool")
        );
    }

    #[test]
    fn detects_repeating_pattern() {
        let mut det = LoopDetector::new(100);
        // Pattern: [a, b] repeated 3 times
        for _ in 0..2 {
            assert!(det.record_and_check("a", false).is_none());
            assert!(det.record_and_check("b", false).is_none());
        }
        assert!(det.record_and_check("a", false).is_none());
        let v = det.record_and_check("b", false);
        assert!(matches!(
            v,
            Some(LoopViolation::RepeatingPattern {
                pattern_len: 2,
                repetitions: 3
            })
        ));
    }

    #[test]
    fn no_false_positive() {
        let mut det = LoopDetector::new(100);
        // Varied sequence should not trigger pattern detection
        for name in &["a", "b", "c", "d", "a", "c", "b", "d", "a", "b", "d", "c"] {
            assert!(det.record_and_check(name, false).is_none());
        }
    }

    #[test]
    fn consecutive_threshold_exact() {
        let mut det = LoopDetector::new(100);
        // 4 failures should not trigger (threshold is 5)
        for _ in 0..4 {
            assert!(det.record_and_check("bad_tool", true).is_none());
        }
        // A success breaks the streak (use a different tool name to avoid repeating-pattern
        // detection on the uniform name sequence)
        assert!(det.record_and_check("other_tool", false).is_none());
        // One failure after a break starts a fresh streak of 1, well under threshold
        assert!(det.record_and_check("bad_tool", true).is_none());
    }
}
