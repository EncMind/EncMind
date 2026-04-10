//! Shared bash allowlist pattern matching helpers.
//!
//! Semantics:
//! - Exact pattern (no trailing `*`) requires exact command match.
//! - Prefix-glob pattern (`...*`) requires prefix match and a command
//!   boundary after the prefix.
//! - Boundary is end-of-command or a simple argv separator (` ` or `\t`).
//! - If the prefix already ends with whitespace (e.g. `"ls *"`), the
//!   boundary is implicit in `starts_with`.
//! - Multiline/chained commands (`\n`, `\r`, `;`, `&&`, `||`, `|`) are
//!   never matched by non-exact wildcard patterns.

fn has_disallowed_separators(command: &str) -> bool {
    command.contains('\n')
        || command.contains('\r')
        || command.contains(';')
        || command.contains("&&")
        || command.contains("||")
        || command.contains('|')
}

fn is_argv_separator(ch: char) -> bool {
    ch == ' ' || ch == '\t'
}

/// Returns true when `command` matches the single allowlist `pattern`.
pub fn pattern_matches(pattern: &str, command: &str) -> bool {
    let pattern = pattern.trim();
    let command = command.trim();

    if let Some(prefix) = pattern.strip_suffix('*') {
        if has_disallowed_separators(command) {
            return false;
        }
        if prefix.is_empty() {
            // Backward compatibility: "*" means allow any single command
            // (chained/multiline forms are blocked above).
            return true;
        }
        if !command.starts_with(prefix) {
            return false;
        }
        if prefix.chars().next_back().is_some_and(char::is_whitespace) {
            return true;
        }
        if command.len() == prefix.len() {
            return true;
        }
        return command[prefix.len()..]
            .chars()
            .next()
            .is_some_and(is_argv_separator);
    }

    command == pattern
}

/// Returns true when `command` matches any pattern in `patterns`.
pub fn matches_any(patterns: &[String], command: &str) -> bool {
    patterns.iter().any(|p| pattern_matches(p, command))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pattern() {
        assert!(pattern_matches("git status", "git status"));
        assert!(!pattern_matches("git status", "git status --short"));
    }

    #[test]
    fn prefix_glob_respects_boundary() {
        assert!(pattern_matches("ls*", "ls"));
        assert!(pattern_matches("ls*", "ls -la"));
        assert!(!pattern_matches("ls*", "lsblk"));
    }

    #[test]
    fn whitespace_prefix_glob() {
        assert!(pattern_matches("ls *", "ls -la /tmp"));
        assert!(!pattern_matches("ls *", "ls"));
        assert!(!pattern_matches("ls *", "lsof -i"));
    }

    #[test]
    fn matches_any_works() {
        let patterns = vec!["echo*".to_string(), "git status".to_string()];
        assert!(matches_any(&patterns, "echo hi"));
        assert!(matches_any(&patterns, "git status"));
        assert!(!matches_any(&patterns, "git push"));
    }

    #[test]
    fn wildcard_star_matches_any_command() {
        assert!(pattern_matches("*", "ls -la"));
        assert!(pattern_matches("*", "echo hi"));
        assert!(pattern_matches("*", ""));
    }

    #[test]
    fn wildcard_rejects_multiline_and_chained_commands() {
        assert!(!pattern_matches("ls*", "ls\nrm -rf /"));
        assert!(!pattern_matches("ls *", "ls -la; rm -rf /"));
        assert!(!pattern_matches("ls *", "ls -la | cat"));
        assert!(!pattern_matches("ls *", "ls -la && whoami"));
    }
}
