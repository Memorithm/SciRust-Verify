use std::time::Duration;

use scirust_verify_runner::{execute, which, CommandSpec, ExitStatus};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("svr-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn successful_execution_captures_output() {
    let cwd = tmpdir("ok");
    let spec = CommandSpec::new("printf", &cwd).args(["hello %s\n", "world"]);
    let rec = execute(&spec).unwrap();
    assert!(rec.succeeded(), "expected success, got {:?}", rec.status);
    assert_eq!(rec.stdout_lossy(), "hello world\n");
    assert!(!rec.stdout.truncated);
    assert!(rec.duration_ns > 0);
    assert!(!rec.started_at_utc.is_empty());
}

#[test]
fn nonzero_exit_is_recorded_not_raised() {
    let cwd = tmpdir("nonzero");
    let spec = CommandSpec::new("sh", &cwd)
        .args(["-c", "echo to-stderr >&2; exit 3"])
        .remove_env("UNUSED");
    let rec = execute(&spec).unwrap();
    assert_eq!(rec.exit_code(), Some(3));
    assert!(!rec.succeeded());
    assert!(rec.stderr_lossy().contains("to-stderr"));
}

#[test]
fn spawn_failure_is_a_recorded_state() {
    let cwd = tmpdir("spawn");
    let spec = CommandSpec::new("definitely-not-a-real-binary-xyz", &cwd);
    let rec = execute(&spec).unwrap();
    assert!(matches!(rec.status, ExitStatus::SpawnFailed { .. }));
}

#[test]
fn timeout_kills_process_and_is_distinct() {
    let cwd = tmpdir("timeout");
    let spec = CommandSpec::new("sleep", &cwd)
        .args(["30"])
        .timeout(Duration::from_millis(150));
    let rec = execute(&spec).unwrap();
    assert_eq!(rec.status, ExitStatus::TimedOut);
    assert!(rec.timed_out());
    // The kill happened promptly: total duration must be well below 30 s.
    assert!(rec.duration_ns < Duration::from_secs(5).as_nanos() as u64);
}

#[cfg(unix)]
#[test]
fn timeout_kills_descendants_holding_capture_pipes() {
    let cwd = tmpdir("timeout-descendants");
    let spec = CommandSpec::new("sh", &cwd)
        .args(["-c", "sleep 30 & wait"])
        .timeout(Duration::from_millis(150));
    let rec = execute(&spec).unwrap();
    assert_eq!(rec.status, ExitStatus::TimedOut);
    assert!(rec.duration_ns < Duration::from_secs(5).as_nanos() as u64);
}

#[test]
fn large_stdout_is_bounded_and_flagged() {
    let cwd = tmpdir("large");
    // ~4 MiB of output with a 64 KiB capture limit.
    let spec = CommandSpec::new("head", &cwd)
        .args(["-c", "4194304", "/dev/zero"])
        .capture_limits(64 * 1024);
    let rec = execute(&spec).unwrap();
    assert!(rec.succeeded());
    assert!(rec.stdout.truncated);
    assert_eq!(rec.stdout.data.len() as u64, 64 * 1024);
    assert_eq!(rec.stdout.total_bytes, 4_194_304);
}

#[test]
fn secrets_are_removed_from_child_environment() {
    let cwd = tmpdir("secrets");
    // Set a secret-like var in our own environment for the child to observe.
    // SAFETY-free approach: use a wrapper shell that prints whether the var
    // exists; the parent env cannot be mutated safely in tests in parallel,
    // so instead verify the policy logic directly.
    let spec = CommandSpec::new("true", &cwd)
        .env("MY_API_KEY", "super-secret")
        .env("PLAIN_VAR", "visible");
    let effective = spec.effective_environment();
    assert!(effective.contains_key("PLAIN_VAR"));
    // Secret-like explicit values are dropped even when explicitly set.
    assert!(!effective.contains_key("MY_API_KEY"));

    let recorded = spec.recorded_environment();
    assert_eq!(
        recorded.get("PLAIN_VAR").map(String::as_str),
        Some("visible")
    );
    assert!(!recorded.contains_key("MY_API_KEY"));
}

#[cfg(unix)]
#[test]
fn recorded_env_includes_path_when_present() {
    let cwd = tmpdir("path");
    let spec = CommandSpec::new("true", &cwd);
    let recorded = spec.recorded_environment();
    if std::env::var_os("PATH").is_some() {
        assert!(recorded.contains_key("PATH"));
    }
}

#[test]
fn missing_working_directory_is_an_error() {
    let spec = CommandSpec::new("true", "/nonexistent-dir-for-svr-test");
    assert!(matches!(
        execute(&spec),
        Err(scirust_verify_runner::RunnerError::BadWorkingDirectory { .. })
    ));
}

#[test]
fn which_finds_sh_but_not_nonsense() {
    #[cfg(unix)]
    assert!(which("sh").is_some());
    assert!(which("definitely-not-a-real-binary-xyz").is_none());
}
