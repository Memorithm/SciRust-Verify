//! Launch SciRust-Verify inside a Linux bubblewrap containment boundary.
//!
//! This is an opt-in execution boundary for hostile-project verification. It
//! uses Linux namespaces through `bubblewrap`; it is not a formal proof that
//! the contained process is harmless, and it never falls back to direct host
//! execution when containment is unavailable.

#![deny(missing_docs)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use clap::Parser;

const CONTAINMENT_ID: &str = "bubblewrap-v1";

#[derive(Debug, Parser)]
#[command(
    name = "scirust-verify-contain",
    version,
    about = "Run SciRust-Verify in a bubblewrap Linux containment boundary"
)]
struct Cli {
    /// Project directory to verify. The directory is the only host tree made
    /// writable inside the containment boundary.
    #[arg(default_value = ".")]
    project: PathBuf,

    /// Additional arguments passed to `scirust-verify verify` after the
    /// project argument, for example `--profile strict`.
    #[arg(last = true)]
    verify_args: Vec<OsString>,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    if !cfg!(target_os = "linux") {
        return Err("bubblewrap containment is supported only on Linux".into());
    }

    let project = cli.project.canonicalize().map_err(|error| {
        format!(
            "cannot resolve project `{}`: {error}",
            cli.project.display()
        )
    })?;
    if !project.is_dir() {
        return Err(format!(
            "project `{}` is not a directory",
            project.display()
        ));
    }

    let verifier = sibling_verifier()?;
    let args = build_bwrap_args(&project, &verifier, &cli.verify_args);

    let status = Command::new("bwrap")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| {
            format!(
                "failed to start bubblewrap; install `bwrap` and ensure unprivileged user namespaces are permitted: {error}"
            )
        })?;

    match status.code() {
        Some(code) if (0..=255).contains(&code) => Ok(ExitCode::from(code as u8)),
        Some(code) => Err(format!("bubblewrap returned unsupported exit code {code}")),
        None => Err("bubblewrap terminated by signal".into()),
    }
}

fn sibling_verifier() -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|error| format!("cannot locate containment launcher: {error}"))?;
    let directory = current
        .parent()
        .ok_or_else(|| "containment launcher has no parent directory".to_owned())?;
    let verifier = directory.join("scirust-verify");
    if verifier.is_file() {
        Ok(verifier)
    } else {
        Err(format!(
            "expected sibling verifier `{}`; build/install the complete scirust-verify-cli package",
            verifier.display()
        ))
    }
}

fn build_bwrap_args(project: &Path, verifier: &Path, verify_args: &[OsString]) -> Vec<OsString> {
    let mut args = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-net".into(),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--bind".into(),
        project.as_os_str().to_owned(),
        project.as_os_str().to_owned(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--chdir".into(),
        project.as_os_str().to_owned(),
        "--setenv".into(),
        "SCIRUST_VERIFY_CONTAINMENT".into(),
        CONTAINMENT_ID.into(),
        "--setenv".into(),
        "CARGO_NET_OFFLINE".into(),
        "true".into(),
        "--".into(),
        verifier.as_os_str().to_owned(),
        "verify".into(),
        ".".into(),
    ];
    args.extend(verify_args.iter().cloned());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn containment_is_fail_closed_and_network_isolated_by_construction() {
        let args = strings(build_bwrap_args(
            Path::new("/work/project"),
            Path::new("/opt/bin/scirust-verify"),
            &[],
        ));
        assert!(args.contains(&"--unshare-net".to_owned()));
        assert!(args.contains(&"--ro-bind".to_owned()));
        assert!(args.contains(&"--bind".to_owned()));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["CARGO_NET_OFFLINE", "true"]));
        assert!(!args.contains(&"--share-net".to_owned()));
    }

    #[test]
    fn only_project_is_explicitly_rebound_writable() {
        let args = strings(build_bwrap_args(
            Path::new("/work/project"),
            Path::new("/opt/bin/scirust-verify"),
            &[],
        ));
        let bind = args
            .iter()
            .position(|arg| arg == "--bind")
            .expect("project bind");
        assert_eq!(
            &args[bind + 1..=bind + 2],
            ["/work/project", "/work/project"]
        );
        assert_eq!(args.iter().filter(|arg| *arg == "--bind").count(), 1);
    }

    #[test]
    fn verifier_arguments_are_structural_not_shell_joined() {
        let args = strings(build_bwrap_args(
            Path::new("/work/project"),
            Path::new("/opt/bin/scirust-verify"),
            &["--profile".into(), "strict; touch /tmp/pwned".into()],
        ));
        let separator = args.iter().position(|arg| arg == "--").expect("separator");
        assert_eq!(args[separator + 1], "/opt/bin/scirust-verify");
        assert_eq!(args[separator + 2], "verify");
        assert_eq!(args[separator + 3], ".");
        assert_eq!(args[separator + 4], "--profile");
        assert_eq!(args[separator + 5], "strict; touch /tmp/pwned");
    }

    #[test]
    fn containment_identity_is_explicit() {
        let args = strings(build_bwrap_args(
            Path::new("/work/project"),
            Path::new("/opt/bin/scirust-verify"),
            &[],
        ));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["SCIRUST_VERIFY_CONTAINMENT", CONTAINMENT_ID]));
    }
}
