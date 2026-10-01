//! Safe, bounded command execution for verification checks.
//!
//! Design rules:
//!
//! * commands are represented structurally ([`CommandSpec`]) and spawned with
//!   [`std::process::Command`] — never through a shell;
//! * captured stdout/stderr are bounded; a hostile process cannot exhaust
//!   memory (truncation is recorded as evidence);
//! * every command carries a timeout; Unix process groups are terminated and
//!   confirmed before a timeout is recorded, and capture has its own deadline;
//! * the default environment policy removes secret-like variables and
//!   records only an allowlist of selected variables in evidence.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use scirust_verify_model::digest::Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PROCESS_GROUP_CONFIRM_TIMEOUT: Duration = Duration::from_secs(1);
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const PROCESS_GROUP_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Environment handling for a command execution.
///
/// The base environment is inherited minus `removed` entries. Secret-like
/// variable names are always removed regardless of configuration
/// (defense in depth, not perfect detection).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EnvPolicy {
    /// Variables explicitly set for the command.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
    /// Variable names removed from the inherited environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

/// Names matching any of these substrings are stripped from the environment
/// before spawn and their values are never recorded.
const SECRET_NAME_MARKERS: [&str; 6] = [
    "TOKEN",
    "PASSWORD",
    "SECRET",
    "API_KEY",
    "AUTHORIZATION",
    "PRIVATE_KEY",
];

/// Environment variables recorded in evidence when present. Values are part
/// of the run's reproducibility contract; none of them may carry secrets.
const RECORDED_ENV_VARS: [&str; 7] = [
    "PATH",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_NET_OFFLINE",
    "CI",
];

fn name_is_secret_like(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_NAME_MARKERS.iter().any(|m| upper.contains(m))
}

/// A fully specified command ready to execute.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// Program to spawn.
    pub program: String,
    /// Arguments passed verbatim.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: PathBuf,
    /// Environment policy applied on top of the inherited environment.
    pub env: EnvPolicy,
    /// Wall-clock timeout; the child is killed when it elapses.
    pub timeout: Duration,
    /// Maximum stdout bytes retained (excess is discarded and flagged).
    pub stdout_limit: u64,
    /// Maximum stderr bytes retained (excess is discarded and flagged).
    pub stderr_limit: u64,
}

impl CommandSpec {
    /// Builds a spec with SciRust-Verify defaults (10 min timeout, 8 MiB
    /// capture limits).
    pub fn new(program: impl Into<String>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: cwd.into(),
            env: EnvPolicy::default(),
            timeout: Duration::from_secs(600),
            stdout_limit: 8 * 1024 * 1024,
            stderr_limit: 8 * 1024 * 1024,
        }
    }

    /// Appends arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets the timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets both capture limits.
    pub fn capture_limits(mut self, bytes: u64) -> Self {
        self.stdout_limit = bytes;
        self.stderr_limit = bytes;
        self
    }

    /// Sets an explicit environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.set.insert(key.into(), value.into());
        self
    }

    /// Removes an inherited environment variable.
    pub fn remove_env(mut self, key: impl Into<String>) -> Self {
        self.env.remove.push(key.into());
        self
    }

    /// Returns the environment that will be visible to the child, after
    /// removal of secret-like and explicitly removed variables.
    pub fn effective_environment(&self) -> BTreeMap<String, String> {
        let mut env: BTreeMap<String, String> = std::env::vars()
            .filter(|(k, _)| !name_is_secret_like(k))
            .filter(|(k, _)| !self.env.remove.iter().any(|r| r == k))
            .collect();
        for (k, v) in &self.env.set {
            if !name_is_secret_like(k) {
                env.insert(k.clone(), v.clone());
            }
        }
        env
    }

    /// The subset of the effective environment recorded into evidence.
    pub fn recorded_environment(&self) -> BTreeMap<String, String> {
        let effective = self.effective_environment();
        let mut out = BTreeMap::new();
        for key in RECORDED_ENV_VARS {
            if let Some(v) = effective.get(key) {
                out.insert((*key).to_owned(), v.clone());
            }
        }
        // Explicitly-set variables are always recorded unless secret-like
        // (they are part of the check's definition).
        for (k, v) in &self.env.set {
            if !name_is_secret_like(k) {
                out.insert(k.clone(), v.clone());
            }
        }
        out
    }
}

/// Captured output of one stream with truncation information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedStream {
    /// Bytes actually retained.
    pub data: Vec<u8>,
    /// Total bytes produced by the process before truncation.
    pub total_bytes: u64,
    /// True when `total_bytes` exceeded the capture limit.
    pub truncated: bool,
}

impl CapturedStream {
    fn empty() -> Self {
        Self {
            data: Vec::new(),
            total_bytes: 0,
            truncated: false,
        }
    }

    fn lossy(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// Terminal status of one executed command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ExitStatus {
    /// Process exited with the given code.
    Code(i32),
    /// Process was killed by the given signal number (Unix).
    Signal(i32),
    /// Process exceeded its timeout and was killed.
    TimedOut,
    /// Process could not be spawned.
    SpawnFailed {
        /// Underlying error message.
        reason: String,
    },
}

/// The full record of one command execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// Program that was requested.
    pub program: String,
    /// Arguments that were passed.
    pub args: Vec<String>,
    /// Working directory used.
    pub cwd: PathBuf,
    /// Environment subset recorded in evidence.
    pub recorded_env: BTreeMap<String, String>,
    /// Start instant (UTC RFC 3339).
    pub started_at_utc: String,
    /// End instant (UTC RFC 3339).
    pub ended_at_utc: String,
    /// Duration in nanoseconds.
    pub duration_ns: u64,
    /// Timeout configured for this execution.
    pub timeout_ms: u64,
    /// Terminal status.
    pub status: ExitStatus,
    /// Captured stdout.
    pub stdout: CapturedStream,
    /// Captured stderr.
    pub stderr: CapturedStream,
}

impl ExecutionRecord {
    /// Exit code when the process exited normally.
    pub fn exit_code(&self) -> Option<i32> {
        match self.status {
            ExitStatus::Code(c) => Some(c),
            _ => None,
        }
    }

    /// True when the process exited successfully (code 0).
    pub fn succeeded(&self) -> bool {
        self.exit_code() == Some(0)
    }

    /// True when the execution hit its timeout.
    pub fn timed_out(&self) -> bool {
        matches!(self.status, ExitStatus::TimedOut)
    }

    /// Stdout as lossy UTF-8.
    pub fn stdout_lossy(&self) -> String {
        self.stdout.lossy()
    }

    /// Stderr as lossy UTF-8.
    pub fn stderr_lossy(&self) -> String {
        self.stderr.lossy()
    }

    /// Digest of the raw stdout bytes.
    pub fn stdout_digest(&self) -> Digest {
        Digest::sha256_hex(&self.stdout.data)
    }

    /// Digest of the raw stderr bytes.
    pub fn stderr_digest(&self) -> Digest {
        Digest::sha256_hex(&self.stderr.data)
    }
}

/// Errors returned by the runner itself (as opposed to scientific failures
/// of the executed command).
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The working directory does not exist or is not accessible.
    #[error("working directory `{path}` is not usable: {source}")]
    BadWorkingDirectory {
        /// Offending path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// A process tree could not be stopped and confirmed before its deadline.
    #[error("process-group termination could not be confirmed: {reason}")]
    ProcessGroupTermination {
        /// Why termination could not be confirmed.
        reason: String,
    },
    /// Captured output did not reach a confirmed terminal state in time.
    #[error("{stream} capture incomplete: {reason}")]
    CaptureIncomplete {
        /// Name of the incomplete stream.
        stream: &'static str,
        /// Why capture could not be completed.
        reason: String,
    },
}

/// Executes `spec`, capturing bounded output and enforcing the timeout.
///
/// Output is drained by reader threads so a verbose child can neither block
/// on a full pipe nor exhaust memory beyond the configured limits.
pub fn execute(spec: &CommandSpec) -> Result<ExecutionRecord, RunnerError> {
    if !spec.cwd.is_dir() {
        return Err(RunnerError::BadWorkingDirectory {
            path: spec.cwd.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "directory not found"),
        });
    }

    let started_at_utc = chrono_utc_now();
    let start = Instant::now();

    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    // Apply environment policy: strip secrets/removed vars, then apply sets.
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy().into_owned();
        if name_is_secret_like(&name) || spec.env.remove.contains(&name) {
            cmd.env_remove(&k);
        }
    }
    for (k, v) in &spec.env.set {
        if !name_is_secret_like(k) {
            cmd.env(k, v);
        }
    }

    let recorded_env = spec.recorded_environment();

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let ended_at_utc = chrono_utc_now();
            return Ok(ExecutionRecord {
                program: spec.program.clone(),
                args: spec.args.clone(),
                cwd: spec.cwd.clone(),
                recorded_env,
                started_at_utc,
                ended_at_utc,
                duration_ns: start.elapsed().as_nanos() as u64,
                timeout_ms: spec.timeout.as_millis() as u64,
                status: ExitStatus::SpawnFailed {
                    reason: e.to_string(),
                },
                stdout: CapturedStream::empty(),
                stderr: CapturedStream::empty(),
            });
        }
    };
    let child_id = child.id();

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_handle = spawn_capturer(stdout_pipe, spec.stdout_limit);
    let stderr_handle = spawn_capturer(stderr_pipe, spec.stderr_limit);

    // Poll for completion up to the deadline.
    let deadline = start + spec.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break None;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                // A wait error is exceptional. Fail closed unless the entire
                // process group and both capture streams reach terminal state.
                terminate_and_confirm(&mut child, child_id, false)?;
                let (stdout, stderr) = collect_capturers(stdout_handle, stderr_handle)?;
                let ended_at_utc = chrono_utc_now();
                return Ok(ExecutionRecord {
                    program: spec.program.clone(),
                    args: spec.args.clone(),
                    cwd: spec.cwd.clone(),
                    recorded_env,
                    started_at_utc,
                    ended_at_utc,
                    duration_ns: start.elapsed().as_nanos() as u64,
                    timeout_ms: spec.timeout.as_millis() as u64,
                    status: ExitStatus::SpawnFailed {
                        reason: format!("wait failed: {e}"),
                    },
                    stdout,
                    stderr,
                });
            }
        }
    };

    let timed_out = status.is_none();
    terminate_and_confirm(&mut child, child_id, !timed_out)?;
    let (stdout, stderr) = collect_capturers(stdout_handle, stderr_handle)?;
    let ended_at_utc = chrono_utc_now();

    let status = match (status, timed_out) {
        (_, true) => ExitStatus::TimedOut,
        (Some(s), false) => match s.code() {
            Some(code) => ExitStatus::Code(code),
            #[cfg(unix)]
            None => ExitStatus::Signal(signal_number(s)),
            #[cfg(not(unix))]
            None => ExitStatus::Signal(-1),
        },
        (None, false) => unreachable!("loop only exits None when timed out"),
    };

    Ok(ExecutionRecord {
        program: spec.program.clone(),
        args: spec.args.clone(),
        cwd: spec.cwd.clone(),
        recorded_env,
        started_at_utc,
        ended_at_utc,
        duration_ns: start.elapsed().as_nanos() as u64,
        timeout_ms: spec.timeout.as_millis() as u64,
        status,
        stdout,
        stderr,
    })
}

#[cfg(unix)]
fn signal_number(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(-1)
}

struct CapturedPipe {
    receiver: Receiver<Result<CapturedStream, String>>,
}

fn spawn_capturer<R: Read + Send + 'static>(pipe: Option<R>, limit: u64) -> CapturedPipe {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut out = CapturedStream::empty();
        let result = if let Some(mut stream) = pipe {
            let mut chunk = [0u8; 8192];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break Ok(out),
                    Ok(n) => {
                        out.total_bytes += n as u64;
                        let remaining = limit.saturating_sub(out.data.len() as u64);
                        let keep = (n as u64).min(remaining) as usize;
                        if keep > 0 {
                            out.data.extend_from_slice(&chunk[..keep]);
                        }
                        if out.total_bytes > limit {
                            out.truncated = true;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => break Err(error.to_string()),
                }
            }
        } else {
            Ok(out)
        };
        let _ = sender.send(result);
    });
    CapturedPipe { receiver }
}

fn collect_capturers(
    stdout: CapturedPipe,
    stderr: CapturedPipe,
) -> Result<(CapturedStream, CapturedStream), RunnerError> {
    let deadline = Instant::now()
        .checked_add(PIPE_DRAIN_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let stdout = stdout.receive_before(deadline, "stdout")?;
    let stderr = stderr.receive_before(deadline, "stderr")?;
    Ok((stdout, stderr))
}

impl CapturedPipe {
    fn receive_before(
        self,
        deadline: Instant,
        stream: &'static str,
    ) -> Result<CapturedStream, RunnerError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.receiver.recv_timeout(remaining) {
            Ok(Ok(captured)) => Ok(captured),
            Ok(Err(reason)) => Err(RunnerError::CaptureIncomplete { stream, reason }),
            Err(RecvTimeoutError::Timeout) => Err(RunnerError::CaptureIncomplete {
                stream,
                reason: "drain deadline elapsed".to_owned(),
            }),
            Err(RecvTimeoutError::Disconnected) => Err(RunnerError::CaptureIncomplete {
                stream,
                reason: "reader disconnected".to_owned(),
            }),
        }
    }
}

#[cfg(unix)]
fn terminate_and_confirm(
    child: &mut std::process::Child,
    child_id: u32,
    parent_reaped: bool,
) -> Result<(), RunnerError> {
    use nix::errno::Errno;
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;

    let process_group = i32::try_from(child_id)
        .map(Pid::from_raw)
        .map_err(|error| RunnerError::ProcessGroupTermination {
            reason: format!("invalid process-group identifier: {error}"),
        })?;

    match killpg(process_group, Signal::SIGKILL) {
        Ok(()) => {}
        Err(Errno::ESRCH) if parent_reaped => return Ok(()),
        Err(error) => {
            return Err(RunnerError::ProcessGroupTermination {
                reason: format!("kill failed: {error}"),
            });
        }
    }

    if !parent_reaped {
        child
            .wait()
            .map_err(|error| RunnerError::ProcessGroupTermination {
                reason: format!("parent reap failed: {error}"),
            })?;
    }

    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_CONFIRM_TIMEOUT)
        .unwrap_or_else(Instant::now);
    loop {
        match killpg(process_group, Option::<Signal>::None) {
            Err(Errno::ESRCH) => return Ok(()),
            Ok(()) => {
                #[cfg(target_os = "linux")]
                if !linux_process_group_has_live_members(process_group.as_raw())? {
                    return Ok(());
                }
            }
            Err(error) => {
                return Err(RunnerError::ProcessGroupTermination {
                    reason: format!("termination probe failed: {error}"),
                });
            }
        }
        if Instant::now() >= deadline {
            return Err(RunnerError::ProcessGroupTermination {
                reason: "group still exists after confirmation deadline".to_owned(),
            });
        }
        thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn linux_process_group_has_live_members(process_group: i32) -> Result<bool, RunnerError> {
    let entries = std::fs::read_dir("/proc").map_err(|error| {
        RunnerError::ProcessGroupTermination {
            reason: format!("cannot inspect Linux process table: {error}"),
        }
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| RunnerError::ProcessGroupTermination {
            reason: format!("cannot inspect Linux process entry: {error}"),
        })?;
        if entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .is_err()
        {
            continue;
        }

        let stat_path = entry.path().join("stat");
        let stat = match std::fs::read_to_string(&stat_path) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(RunnerError::ProcessGroupTermination {
                    reason: format!("cannot inspect {}: {error}", stat_path.display()),
                });
            }
        };
        let (_, fields) = stat.rsplit_once(") ").ok_or_else(|| {
            RunnerError::ProcessGroupTermination {
                reason: format!("invalid Linux process stat record: {}", stat_path.display()),
            }
        })?;
        let mut fields = fields.split_whitespace();
        let state = fields.next().ok_or_else(|| {
            RunnerError::ProcessGroupTermination {
                reason: format!("missing process state in {}", stat_path.display()),
            }
        })?;
        let _parent = fields.next().ok_or_else(|| {
            RunnerError::ProcessGroupTermination {
                reason: format!("missing parent pid in {}", stat_path.display()),
            }
        })?;
        let member_group = fields
            .next()
            .ok_or_else(|| RunnerError::ProcessGroupTermination {
                reason: format!("missing process group in {}", stat_path.display()),
            })?
            .parse::<i32>()
            .map_err(|error| RunnerError::ProcessGroupTermination {
                reason: format!("invalid process group in {}: {error}", stat_path.display()),
            })?;

        if member_group == process_group && !matches!(state, "Z" | "X") {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(not(unix))]
fn terminate_and_confirm(
    child: &mut std::process::Child,
    _child_id: u32,
    parent_reaped: bool,
) -> Result<(), RunnerError> {
    if parent_reaped {
        return Ok(());
    }
    child
        .kill()
        .and_then(|()| child.wait().map(|_| ()))
        .map_err(|error| RunnerError::ProcessGroupTermination {
            reason: format!("child termination failed: {error}"),
        })
}

fn chrono_utc_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Resolves a program name through `PATH` without spawning it.
/// Returns `None` when the program is not found or is not executable.
pub fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let p = Path::new(program);
        return if p.is_file() && is_executable(p) {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(program);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_p: &Path) -> bool {
    true
}

/// Helper converting a path to a lossy string for evidence.
pub fn path_display(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_wait_is_bounded_and_fails_closed() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let capture = CapturedPipe { receiver };
        let started = Instant::now();
        let error = capture
            .receive_before(Instant::now() + Duration::from_millis(20), "stdout")
            .expect_err("an open writer must not be reported as complete capture");
        drop(sender);

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            error,
            RunnerError::CaptureIncomplete {
                stream: "stdout",
                reason
            } if reason == "drain deadline elapsed"
        ));
    }
}
