use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Commands that can be executed on the local client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LocalCommand {
    FileRead { path: String },
    FileWrite { path: String, content: String },
    FileList { path: String },
    BashExec { command: String },
}

/// Result of a local command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub output: String,
}

/// Check if a command is permitted by the local policy.
pub fn is_command_permitted(command: &LocalCommand, policy: &LocalPolicy) -> bool {
    match command {
        LocalCommand::FileRead { .. } => policy.allow_file_read,
        LocalCommand::FileWrite { .. } => policy.allow_file_write,
        LocalCommand::FileList { .. } => policy.allow_file_list,
        LocalCommand::BashExec { .. } => policy.allow_bash_exec,
    }
}

/// Local permission policy.
#[derive(Debug, Clone)]
pub struct LocalPolicy {
    pub allow_file_read: bool,
    pub allow_file_write: bool,
    pub allow_file_list: bool,
    pub allow_bash_exec: bool,
    /// If non-empty, file operations are restricted to these directory trees.
    /// An empty list means no path restriction (all paths allowed).
    pub allowed_roots: Vec<PathBuf>,
    /// Paths that are always denied, even if they fall under an allowed root.
    /// Defaults to common sensitive paths (~/.ssh, ~/.gnupg, ~/.aws, etc.).
    pub denied_paths: Vec<PathBuf>,
}

impl Default for LocalPolicy {
    fn default() -> Self {
        Self {
            allow_file_read: true,
            allow_file_write: true,
            allow_file_list: true,
            allow_bash_exec: true,
            allowed_roots: Vec::new(),
            denied_paths: default_denied_paths(),
        }
    }
}

/// Sensitive paths that should never be accessed by remote commands.
fn default_denied_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/shadow"), PathBuf::from("/etc/sudoers")];
    if let Some(home) = home_dir() {
        paths.extend([
            home.join(".ssh"),
            home.join(".gnupg"),
            home.join(".aws"),
            home.join(".config/gcloud"),
            home.join(".azure"),
            home.join(".kube"),
            home.join(".docker/config.json"),
            home.join(".netrc"),
            home.join(".git-credentials"),
            home.join(".encmind"),
        ]);
    }
    paths
}

fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home));
        }
    }

    #[cfg(windows)]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            if !profile.is_empty() {
                return Some(PathBuf::from(profile));
            }
        }
    }

    #[cfg(unix)]
    {
        if let Ok(user) = std::env::var("USER") {
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
                for line in passwd.lines() {
                    if let Some(rest) = line.strip_prefix(&(user.clone() + ":")) {
                        let fields: Vec<&str> = rest.split(':').collect();
                        if fields.len() >= 5 {
                            let home = fields[4];
                            if !home.is_empty() {
                                return Some(PathBuf::from(home));
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    None
}

/// Validate that a file path is allowed by the local policy.
/// Returns the canonicalized path on success, or an error message on failure.
pub fn validate_file_path(path: &str, policy: &LocalPolicy) -> Result<PathBuf, String> {
    let p = Path::new(path);

    // For paths that don't exist yet (e.g. file.write), canonicalize the
    // nearest existing ancestor and append the remaining components.
    let canonical = best_effort_canonicalize(p);

    // Check denied paths first (deny always wins)
    for denied in &policy.denied_paths {
        let denied_canon = best_effort_canonicalize(denied);
        if canonical.starts_with(&denied_canon) {
            return Err(format!(
                "access denied: path is under restricted location {}",
                denied.display()
            ));
        }
    }

    // Check allowed roots (if configured)
    if !policy.allowed_roots.is_empty() {
        let in_allowed = policy.allowed_roots.iter().any(|root| {
            let root_canon = best_effort_canonicalize(root);
            canonical.starts_with(&root_canon)
        });
        if !in_allowed {
            return Err("access denied: path is outside allowed roots".to_string());
        }
    }

    Ok(canonical)
}

/// Canonicalize as much of the path as possible. If the full path doesn't exist,
/// walk up to the nearest existing ancestor, canonicalize that, and re-join
/// the remaining components.
fn best_effort_canonicalize(p: &Path) -> PathBuf {
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };

    if let Ok(c) = absolute.canonicalize() {
        return c;
    }

    // Walk up until we find an existing ancestor
    let mut existing = absolute.clone();
    let mut remaining = Vec::new();
    loop {
        if existing.exists() {
            break;
        }
        if let Some(file_name) = existing.file_name() {
            remaining.push(file_name.to_owned());
            existing.pop();
        } else {
            // No existing ancestor found; return a lexically normalized absolute path.
            return lexical_normalize(&absolute);
        }
    }

    let mut result = existing.canonicalize().unwrap_or(existing);
    for component in remaining.into_iter().rev() {
        result.push(component);
    }
    lexical_normalize(&result)
}

/// Normalize `.` and `..` components without requiring the path to exist.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut prefix: Option<OsString> = None;
    let mut has_root = false;
    let mut parts: Vec<OsString> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_os_string()),
            Component::RootDir => {
                has_root = true;
                parts.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() && !has_root {
                    parts.push(OsString::from(".."));
                }
            }
            Component::Normal(value) => parts.push(value.to_os_string()),
        }
    }

    let mut normalized = PathBuf::new();
    if let Some(prefix) = prefix {
        normalized.push(prefix);
    }
    if has_root {
        normalized.push(std::path::MAIN_SEPARATOR.to_string());
    }
    for part in parts {
        normalized.push(part);
    }
    if normalized.as_os_str().is_empty() {
        if has_root {
            PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
        } else {
            PathBuf::from(".")
        }
    } else {
        normalized
    }
}

/// Maximum file size for file.read (1 MiB).
const MAX_READ_SIZE: u64 = 1024 * 1024;

/// Bash execution timeout in seconds.
const BASH_TIMEOUT_SECS: u64 = 30;
/// Maximum combined stdout/stderr captured from bash.exec.
const MAX_BASH_OUTPUT_BYTES: usize = 256 * 1024;

/// Execute a local command and return the result.
/// File operations are subject to path validation against the local policy.
pub async fn execute_command(command: &LocalCommand, policy: &LocalPolicy) -> CommandResult {
    match command {
        LocalCommand::FileRead { path } => execute_file_read(path, policy).await,
        LocalCommand::FileWrite { path, content } => {
            execute_file_write(path, content, policy).await
        }
        LocalCommand::FileList { path } => execute_file_list(path, policy).await,
        LocalCommand::BashExec { command } => execute_bash(command).await,
    }
}

async fn execute_file_read(path: &str, policy: &LocalPolicy) -> CommandResult {
    let path = path.to_string();
    let policy = policy.clone();
    match tokio::task::spawn_blocking(move || execute_file_read_blocking(&path, &policy)).await {
        Ok(result) => result,
        Err(e) => CommandResult {
            success: false,
            output: format!("read task failed: {e}"),
        },
    }
}

fn execute_file_read_blocking(path: &str, policy: &LocalPolicy) -> CommandResult {
    use std::io::Read;

    let validated_path = match validate_file_path(path, policy) {
        Ok(path) => path,
        Err(e) => {
            return CommandResult {
                success: false,
                output: e,
            };
        }
    };

    if let Ok(true) = path_is_symlink(&validated_path) {
        return CommandResult {
            success: false,
            output: "access denied: symlink targets are not allowed".into(),
        };
    }

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(&validated_path) {
        Ok(file) => file,
        Err(e) => {
            return CommandResult {
                success: false,
                output: format!("cannot stat file: {e}"),
            };
        }
    };

    if !path_points_to_open_file(&validated_path, &file) {
        return CommandResult {
            success: false,
            output: "access denied: path changed during open".into(),
        };
    }

    match file.metadata() {
        Ok(meta) => {
            if meta.len() > MAX_READ_SIZE {
                return CommandResult {
                    success: false,
                    output: format!(
                        "file too large: {} bytes (max {})",
                        meta.len(),
                        MAX_READ_SIZE
                    ),
                };
            }
        }
        Err(e) => {
            return CommandResult {
                success: false,
                output: format!("cannot stat file: {e}"),
            };
        }
    }

    let mut content = String::new();
    match file.read_to_string(&mut content) {
        Ok(_) => CommandResult {
            success: true,
            output: content,
        },
        Err(e) => CommandResult {
            success: false,
            output: format!("read error: {e}"),
        },
    }
}

async fn execute_file_write(path: &str, content: &str, policy: &LocalPolicy) -> CommandResult {
    let path = path.to_string();
    let content = content.to_string();
    let policy = policy.clone();
    match tokio::task::spawn_blocking(move || execute_file_write_blocking(&path, &content, &policy))
        .await
    {
        Ok(result) => result,
        Err(e) => CommandResult {
            success: false,
            output: format!("write task failed: {e}"),
        },
    }
}

fn execute_file_write_blocking(path: &str, content: &str, policy: &LocalPolicy) -> CommandResult {
    use std::io::Write;

    let validated_path = match validate_file_path(path, policy) {
        Ok(path) => path,
        Err(e) => {
            return CommandResult {
                success: false,
                output: e,
            };
        }
    };

    // Create parent directories if needed.
    if let Some(parent) = validated_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return CommandResult {
                success: false,
                output: format!("cannot create parent dirs: {e}"),
            };
        }
    }

    if let Ok(true) = path_is_symlink(&validated_path) {
        return CommandResult {
            success: false,
            output: "access denied: symlink targets are not allowed".into(),
        };
    }

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(&validated_path) {
        Ok(file) => file,
        Err(e) => {
            return CommandResult {
                success: false,
                output: format!("write error: {e}"),
            };
        }
    };

    if !path_points_to_open_file(&validated_path, &file) {
        return CommandResult {
            success: false,
            output: "access denied: path changed during open".into(),
        };
    }

    if let Err(e) = file.set_len(0) {
        return CommandResult {
            success: false,
            output: format!("write error: {e}"),
        };
    }

    if let Err(e) = file.write_all(content.as_bytes()) {
        return CommandResult {
            success: false,
            output: format!("write error: {e}"),
        };
    }
    if let Err(e) = file.flush() {
        return CommandResult {
            success: false,
            output: format!("write error: {e}"),
        };
    }

    CommandResult {
        success: true,
        output: "ok".into(),
    }
}

async fn execute_file_list(path: &str, policy: &LocalPolicy) -> CommandResult {
    let path = path.to_string();
    let policy = policy.clone();
    match tokio::task::spawn_blocking(move || execute_file_list_blocking(&path, &policy)).await {
        Ok(result) => result,
        Err(e) => CommandResult {
            success: false,
            output: format!("list task failed: {e}"),
        },
    }
}

fn execute_file_list_blocking(path: &str, policy: &LocalPolicy) -> CommandResult {
    let validated_path = match validate_file_path(path, policy) {
        Ok(path) => path,
        Err(e) => {
            return CommandResult {
                success: false,
                output: e,
            };
        }
    };

    if let Ok(true) = path_is_symlink(&validated_path) {
        return CommandResult {
            success: false,
            output: "access denied: symlink targets are not allowed".into(),
        };
    }

    #[cfg(unix)]
    let entries = {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        let dir = match options.open(&validated_path) {
            Ok(dir) => dir,
            Err(e) => {
                return CommandResult {
                    success: false,
                    output: format!("read_dir error: {e}"),
                };
            }
        };

        if !path_points_to_open_file(&validated_path, &dir) {
            return CommandResult {
                success: false,
                output: "access denied: path changed during open".into(),
            };
        }
        match list_directory_entries_via_fd(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                return CommandResult {
                    success: false,
                    output: format!("read_dir error: {e}"),
                };
            }
        }
    };

    #[cfg(not(unix))]
    let entries = {
        match std::fs::read_dir(&validated_path) {
            Ok(rd) => {
                let mut names = Vec::new();
                for entry in rd {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            return CommandResult {
                                success: false,
                                output: format!("read_dir error: {e}"),
                            };
                        }
                    };

                    let mut name = entry.file_name().to_string_lossy().to_string();
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        name.push('/');
                    }
                    names.push(name);
                }
                names
            }
            Err(e) => {
                return CommandResult {
                    success: false,
                    output: format!("read_dir error: {e}"),
                };
            }
        }
    };
    let mut names = entries;
    names.sort_unstable();

    CommandResult {
        success: true,
        output: names.join("\n"),
    }
}

#[cfg(unix)]
fn list_directory_entries_via_fd(dir: &std::fs::File) -> Result<Vec<String>, std::io::Error> {
    use std::ffi::{CStr, CString};
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    // We need two independent fd copies:
    // - One for fdopendir (which takes ownership of its fd)
    // - One for fstatat (to query entries when d_type == DT_UNKNOWN)
    let dir_fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if dir_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat_fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if stat_fd < 0 {
        let e = std::io::Error::last_os_error();
        let _ = unsafe { libc::close(dir_fd) };
        return Err(e);
    }

    let dirp = unsafe { libc::fdopendir(dir_fd) };
    if dirp.is_null() {
        let e = std::io::Error::last_os_error();
        // dir_fd is not owned by dirp on failure, so close both
        let _ = unsafe { libc::close(dir_fd) };
        let _ = unsafe { libc::close(stat_fd) };
        return Err(e);
    }

    let mut names = Vec::new();
    loop {
        unsafe { *errno_location() = 0 };
        let entry_ptr = unsafe { libc::readdir(dirp) };
        if entry_ptr.is_null() {
            let errno = unsafe { *errno_location() };
            if errno != 0 {
                let _ = unsafe { libc::close(stat_fd) };
                let _ = unsafe { libc::closedir(dirp) };
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            break;
        }

        let entry = unsafe { &*entry_ptr };
        let name_cstr = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
        let name = name_cstr.to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }

        let mut rendered = name.to_string();
        let mut is_dir = entry.d_type == libc::DT_DIR;
        if entry.d_type == libc::DT_UNKNOWN {
            let c_name = CString::new(name_cstr.to_bytes()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid directory entry")
            })?;
            let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    stat_fd,
                    c_name.as_ptr(),
                    stat_buf.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                let mode = unsafe { stat_buf.assume_init().st_mode };
                is_dir = (mode & libc::S_IFMT) == libc::S_IFDIR;
            }
        }
        if is_dir {
            rendered.push('/');
        }
        names.push(rendered);
    }

    let _ = unsafe { libc::close(stat_fd) };
    if unsafe { libc::closedir(dirp) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(names)
}

#[cfg(unix)]
unsafe fn errno_location() -> *mut libc::c_int {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        libc::__errno_location()
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        libc::__error()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        libc::__errno_location()
    }
}

fn path_is_symlink(path: &Path) -> Result<bool, std::io::Error> {
    Ok(std::fs::symlink_metadata(path)?.file_type().is_symlink())
}

fn path_points_to_open_file(path: &Path, file: &std::fs::File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // Use symlink_metadata so a post-check symlink swap does not validate.
        let path_meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        let file_meta = match file.metadata() {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        path_meta.dev() == file_meta.dev() && path_meta.ino() == file_meta.ino()
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = file;
        true
    }
}

async fn execute_bash(command: &str) -> CommandResult {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;

    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Ensure timed-out commands are terminated when their future is dropped.
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return CommandResult {
                success: false,
                output: format!("exec error: {e}"),
            };
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return CommandResult {
                success: false,
                output: "exec error: stdout not captured".to_string(),
            };
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return CommandResult {
                success: false,
                output: "exec error: stderr not captured".to_string(),
            };
        }
    };

    let stdout_task = tokio::spawn(async move {
        let mut reader = stdout;
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut truncated = false;

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let remaining = MAX_BASH_OUTPUT_BYTES.saturating_sub(out.len());
            if remaining == 0 {
                truncated = true;
                continue;
            }
            let take = remaining.min(n);
            out.extend_from_slice(&buf[..take]);
            if take < n {
                truncated = true;
            }
        }

        Ok::<(Vec<u8>, bool), std::io::Error>((out, truncated))
    });

    let stderr_task = tokio::spawn(async move {
        let mut reader = stderr;
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut truncated = false;

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let remaining = MAX_BASH_OUTPUT_BYTES.saturating_sub(out.len());
            if remaining == 0 {
                truncated = true;
                continue;
            }
            let take = remaining.min(n);
            out.extend_from_slice(&buf[..take]);
            if take < n {
                truncated = true;
            }
        }

        Ok::<(Vec<u8>, bool), std::io::Error>((out, truncated))
    });

    let (status, timed_out) = match tokio::time::timeout(
        std::time::Duration::from_secs(BASH_TIMEOUT_SECS),
        child.wait(),
    )
    .await
    {
        Ok(Ok(status)) => (status, false),
        Ok(Err(e)) => {
            return CommandResult {
                success: false,
                output: format!("exec error: {e}"),
            };
        }
        Err(_) => {
            let _ = child.kill().await;
            let status = match child.wait().await {
                Ok(status) => status,
                Err(e) => {
                    return CommandResult {
                        success: false,
                        output: format!("exec error: {e}"),
                    };
                }
            };
            (status, true)
        }
    };

    let (stdout, stdout_truncated) = match stdout_task.await {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => {
            return CommandResult {
                success: false,
                output: format!("exec error: {e}"),
            };
        }
        Err(e) => {
            return CommandResult {
                success: false,
                output: format!("exec error: {e}"),
            };
        }
    };
    let (stderr, stderr_truncated) = match stderr_task.await {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => {
            return CommandResult {
                success: false,
                output: format!("exec error: {e}"),
            };
        }
        Err(e) => {
            return CommandResult {
                success: false,
                output: format!("exec error: {e}"),
            };
        }
    };

    if timed_out {
        return CommandResult {
            success: false,
            output: format!("command timed out after {BASH_TIMEOUT_SECS}s"),
        };
    }

    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    let mut combined = if stderr.is_empty() {
        stdout.to_string()
    } else {
        format!("{stdout}{stderr}")
    };

    if stdout_truncated || stderr_truncated {
        combined.push_str(&format!(
            "\n\n[output truncated to {MAX_BASH_OUTPUT_BYTES} bytes per stream]"
        ));
    }

    CommandResult {
        success: status.success(),
        output: combined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn file_read_permitted() {
        let policy = LocalPolicy {
            allow_file_read: true,
            allow_file_write: false,
            allow_file_list: false,
            allow_bash_exec: false,
            ..Default::default()
        };
        let cmd = LocalCommand::FileRead {
            path: "/tmp/test".into(),
        };
        assert!(is_command_permitted(&cmd, &policy));
    }

    #[test]
    fn file_read_denied() {
        let policy = LocalPolicy {
            allow_file_read: false,
            allow_file_write: false,
            allow_file_list: false,
            allow_bash_exec: false,
            ..Default::default()
        };
        let cmd = LocalCommand::FileRead {
            path: "/tmp/test".into(),
        };
        assert!(!is_command_permitted(&cmd, &policy));
    }

    #[test]
    fn bash_exec_permitted() {
        let policy = LocalPolicy {
            allow_bash_exec: true,
            ..Default::default()
        };
        let cmd = LocalCommand::BashExec {
            command: "ls".into(),
        };
        assert!(is_command_permitted(&cmd, &policy));
    }

    #[test]
    fn bash_exec_denied() {
        let policy = LocalPolicy {
            allow_file_read: false,
            allow_file_write: false,
            allow_file_list: false,
            allow_bash_exec: false,
            ..Default::default()
        };
        let cmd = LocalCommand::BashExec {
            command: "rm -rf /".into(),
        };
        assert!(!is_command_permitted(&cmd, &policy));
    }

    #[test]
    fn file_write_denied_when_only_read() {
        let policy = LocalPolicy {
            allow_file_read: true,
            allow_file_write: false,
            allow_file_list: false,
            allow_bash_exec: false,
            ..Default::default()
        };
        let cmd = LocalCommand::FileWrite {
            path: "/tmp/test".into(),
            content: "data".into(),
        };
        assert!(!is_command_permitted(&cmd, &policy));
    }

    fn permissive_policy() -> LocalPolicy {
        LocalPolicy {
            denied_paths: Vec::new(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn execute_file_read_success() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();

        let policy = permissive_policy();
        let cmd = LocalCommand::FileRead {
            path: file.to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert_eq!(result.output, "hello world");
    }

    #[tokio::test]
    async fn execute_file_read_nonexistent() {
        let policy = permissive_policy();
        let cmd = LocalCommand::FileRead {
            path: "/tmp/encmind_nonexistent_file_12345".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(!result.success);
        assert!(result.output.contains("cannot stat file"));
    }

    #[tokio::test]
    async fn execute_file_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("output.txt");

        let policy = permissive_policy();
        let cmd = LocalCommand::FileWrite {
            path: file.to_string_lossy().to_string(),
            content: "written data".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "written data");
    }

    #[tokio::test]
    async fn execute_file_write_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("a/b/c/deep.txt");

        let policy = permissive_policy();
        let cmd = LocalCommand::FileWrite {
            path: file.to_string_lossy().to_string(),
            content: "deep".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "deep");
    }

    #[tokio::test]
    async fn execute_file_list_returns_sorted() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();
        std::fs::write(dir.path().join("a.txt"), "").unwrap();
        std::fs::create_dir(dir.path().join("c_dir")).unwrap();

        let policy = permissive_policy();
        let cmd = LocalCommand::FileList {
            path: dir.path().to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        let lines: Vec<&str> = result.output.lines().collect();
        assert_eq!(lines, vec!["a.txt", "b.txt", "c_dir/"]);
    }

    #[tokio::test]
    async fn execute_file_list_empty_dir() {
        let dir = TempDir::new().unwrap();

        let policy = permissive_policy();
        let cmd = LocalCommand::FileList {
            path: dir.path().to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert_eq!(result.output, "");
    }

    #[tokio::test]
    async fn execute_bash_echo() {
        let policy = permissive_policy();
        let cmd = LocalCommand::BashExec {
            command: "echo hello".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert_eq!(result.output.trim(), "hello");
    }

    #[tokio::test]
    async fn file_read_denied_by_denied_path() {
        let dir = TempDir::new().unwrap();
        let secret_dir = dir.path().join("secrets");
        std::fs::create_dir(&secret_dir).unwrap();
        let secret_file = secret_dir.join("key.pem");
        std::fs::write(&secret_file, "private key data").unwrap();

        let policy = LocalPolicy {
            denied_paths: vec![secret_dir.clone()],
            ..Default::default()
        };
        let cmd = LocalCommand::FileRead {
            path: secret_file.to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(!result.success);
        assert!(result.output.contains("access denied"));
    }

    #[tokio::test]
    async fn file_write_denied_by_denied_path() {
        let dir = TempDir::new().unwrap();
        let secret_dir = dir.path().join("protected");
        std::fs::create_dir(&secret_dir).unwrap();

        let policy = LocalPolicy {
            denied_paths: vec![secret_dir.clone()],
            ..Default::default()
        };
        let cmd = LocalCommand::FileWrite {
            path: secret_dir.join("evil.sh").to_string_lossy().to_string(),
            content: "malicious".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(!result.success);
        assert!(result.output.contains("access denied"));
    }

    #[tokio::test]
    async fn file_list_denied_by_denied_path() {
        let dir = TempDir::new().unwrap();
        let secret_dir = dir.path().join("private");
        std::fs::create_dir(&secret_dir).unwrap();

        let policy = LocalPolicy {
            denied_paths: vec![secret_dir.clone()],
            ..Default::default()
        };
        let cmd = LocalCommand::FileList {
            path: secret_dir.to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(!result.success);
        assert!(result.output.contains("access denied"));
    }

    #[tokio::test]
    async fn file_read_outside_allowed_roots_denied() {
        let allowed_dir = TempDir::new().unwrap();
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("forbidden.txt");
        std::fs::write(&outside_file, "nope").unwrap();

        let policy = LocalPolicy {
            allowed_roots: vec![allowed_dir.path().to_path_buf()],
            denied_paths: Vec::new(),
            ..Default::default()
        };
        let cmd = LocalCommand::FileRead {
            path: outside_file.to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(!result.success);
        assert!(result.output.contains("outside allowed roots"));
    }

    #[tokio::test]
    async fn file_read_inside_allowed_roots_permitted() {
        let allowed_dir = TempDir::new().unwrap();
        let file = allowed_dir.path().join("ok.txt");
        std::fs::write(&file, "allowed").unwrap();

        let policy = LocalPolicy {
            allowed_roots: vec![allowed_dir.path().to_path_buf()],
            denied_paths: Vec::new(),
            ..Default::default()
        };
        let cmd = LocalCommand::FileRead {
            path: file.to_string_lossy().to_string(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert_eq!(result.output, "allowed");
    }

    #[test]
    fn validate_path_symlink_traversal_blocked() {
        // Create a symlink that tries to escape allowed roots
        let allowed = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").unwrap();

        let link_path = allowed.path().join("escape");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();

        let policy = LocalPolicy {
            allowed_roots: vec![allowed.path().to_path_buf()],
            denied_paths: Vec::new(),
            ..Default::default()
        };

        // The symlink resolves outside allowed_roots, so it should be denied
        let target = link_path.join("secret.txt");
        let result = validate_file_path(&target.to_string_lossy(), &policy);
        assert!(result.is_err(), "symlink traversal should be blocked");
        assert!(result.unwrap_err().contains("outside allowed roots"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_path_symlink_to_nonexistent_file_is_blocked_by_containment() {
        // Symlink points outside the allowed root to a path that does
        // NOT yet exist. file.write through that link must still be
        // rejected — canonicalization walks up to the nearest existing
        // ancestor (the symlink target dir) and checks containment.
        let allowed = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();

        let link_path = allowed.path().join("escape_dir");
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();

        let policy = LocalPolicy {
            allowed_roots: vec![allowed.path().to_path_buf()],
            denied_paths: Vec::new(),
            ..Default::default()
        };

        // Path looks like it's inside `allowed` but `escape_dir` is a
        // symlink to `outside`, and `new_file.txt` does not exist yet.
        let write_target = link_path.join("new_file.txt");
        let result = validate_file_path(&write_target.to_string_lossy(), &policy);
        assert!(
            result.is_err(),
            "file.write through escaping symlink must be blocked, got: {result:?}"
        );
        assert!(result.unwrap_err().contains("outside allowed roots"));
    }

    #[test]
    fn validate_path_dot_dot_traversal_blocked() {
        let allowed = TempDir::new().unwrap();
        let policy = LocalPolicy {
            allowed_roots: vec![allowed.path().to_path_buf()],
            denied_paths: Vec::new(),
            ..Default::default()
        };

        // Path with .. that goes above allowed root
        let evil_path = format!("{}/../../../etc/passwd", allowed.path().display());
        let result = validate_file_path(&evil_path, &policy);
        assert!(result.is_err(), "dot-dot traversal should be blocked");
    }

    #[test]
    fn validate_path_missing_segment_dot_dot_traversal_blocked() {
        let allowed = TempDir::new().unwrap();
        let policy = LocalPolicy {
            allowed_roots: vec![allowed.path().to_path_buf()],
            denied_paths: Vec::new(),
            ..Default::default()
        };

        // Non-existing segment before ".." used to bypass prefix checks.
        let evil_path = format!("{}/missing/../../etc/passwd", allowed.path().display());
        let result = validate_file_path(&evil_path, &policy);
        assert!(
            result.is_err(),
            "dot-dot traversal via missing segment should be blocked"
        );
    }

    #[tokio::test]
    async fn execute_bash_denied_by_policy() {
        let policy = LocalPolicy {
            allow_file_read: true,
            allow_file_write: true,
            allow_file_list: true,
            allow_bash_exec: false,
            ..Default::default()
        };
        let cmd = LocalCommand::BashExec {
            command: "echo should not run".into(),
        };
        assert!(!is_command_permitted(&cmd, &policy));
    }

    #[cfg(unix)]
    #[test]
    fn path_points_to_open_file_rejects_symlink_path() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "secret").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let file = std::fs::File::open(&target).unwrap();
        assert!(
            !path_points_to_open_file(&link, &file),
            "symlink path must not validate against opened file"
        );
    }

    // --- bash.exec: stderr, exit code, truncation ---

    #[tokio::test]
    async fn execute_bash_captures_stderr() {
        let policy = permissive_policy();
        let cmd = LocalCommand::BashExec {
            command: "echo err >&2".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert!(
            result.output.contains("err"),
            "stderr should appear in output: {}",
            result.output
        );
    }

    #[tokio::test]
    async fn execute_bash_nonzero_exit_code() {
        let policy = permissive_policy();
        let cmd = LocalCommand::BashExec {
            command: "exit 42".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(!result.success, "non-zero exit should report failure");
    }

    #[tokio::test]
    async fn execute_bash_mixed_stdout_and_stderr() {
        let policy = permissive_policy();
        let cmd = LocalCommand::BashExec {
            command: "echo out && echo err >&2".into(),
        };
        let result = execute_command(&cmd, &policy).await;
        assert!(result.success);
        assert!(
            result.output.contains("out"),
            "missing stdout: {}",
            result.output
        );
        assert!(
            result.output.contains("err"),
            "missing stderr: {}",
            result.output
        );
    }
}
