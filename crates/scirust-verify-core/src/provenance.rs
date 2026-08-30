//! Provenance and toolchain identity collection.

use std::collections::BTreeMap;
use std::path::Path;

use scirust_verify_model::provenance::{GitProvenance, ProvenanceDocument, ProvenanceProbe};
use scirust_verify_model::scope::{EnvironmentSnapshot, ExecutionBoundary};
use scirust_verify_model::Digest;

const CONTAINMENT_ENV: &str = "SCIRUST_VERIFY_CONTAINMENT";
const BUBBLEWRAP_V1: &str = "bubblewrap-v1";
const DECLARATION_SCOPE: &str = "producer_declared_not_attested";

/// Captures Git provenance plus structured probes for the given project root.
///
/// Only technically relevant facts are recorded; probe outputs are hashed,
/// not stored verbatim (the raw text is attached to run evidence by callers
/// when useful).
pub fn collect_provenance(root: &Path) -> ProvenanceDocument {
    let mut doc = ProvenanceDocument {
        schema_version: 1,
        ..Default::default()
    };

    if git_ok(root, &["rev-parse", "--is-inside-work-tree"])
        .map(|v| v.trim() == "true")
        .unwrap_or(false)
    {
        let mut gp = GitProvenance::default();
        if let Some(v) = git_opt(root, &["rev-parse", "HEAD"]) {
            gp.commit = Some(v);
        }
        if let Some(branch) = git_opt(root, &["branch", "--show-current"]) {
            if !branch.trim().is_empty() {
                gp.branch = Some(branch);
            }
        }
        if let Some(url) = git_opt(root, &["remote", "get-url", "origin"]) {
            gp.repository = Some(url);
        }
        if let Some(status) = git_opt(root, &["status", "--porcelain"]) {
            let count = status.lines().filter(|l| !l.trim().is_empty()).count() as u64;
            gp.dirty_count = Some(count);
        }
        doc.git = Some(gp);
    }

    // Toolchain probes (recorded as digests).
    for (name, args) in [
        ("rustc", vec!["rustc", "-V"]),
        ("cargo", vec!["cargo", "-V"]),
    ] {
        if let Some((digest, _)) = probe(root, &args) {
            doc.probes.push(ProvenanceProbe::new(name, digest));
        }
    }

    doc
}

fn git_opt(root: &Path, args: &[&str]) -> Option<String> {
    git_ok(root, args)
}

fn git_ok(root: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Runs a probe command, returning the stdout digest and text.
pub fn probe(cwd: &Path, argv: &[&str]) -> Option<(Digest, String)> {
    let mut cmd = std::process::Command::new(argv[0]);
    cmd.args(&argv[1..]).current_dir(cwd);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Some((Digest::sha256_hex(stdout.as_bytes()), stdout))
}

/// Builds the environment snapshot for a run.
pub fn collect_environment(root: &Path, target_triple: Option<&str>) -> EnvironmentSnapshot {
    let mut snap = EnvironmentSnapshot {
        taken_at_utc: Some(chrono::Utc::now()),
        ..Default::default()
    };

    if let Some((_, rustc_vv)) = probe(root, &["rustc", "-vV"]) {
        let host = rustc_vv.lines().find_map(|l| l.strip_prefix("host: "));
        snap.toolchain.rustc_version =
            probe(root, &["rustc", "-V"]).map(|(_, s)| s.trim_end().to_owned());
        snap.toolchain.host_triple = host.map(str::to_owned);
    } else {
        snap.toolchain.rustc_version =
            probe(root, &["rustc", "-V"]).map(|(_, s)| s.trim_end().to_owned());
    }
    snap.toolchain.cargo_version =
        probe(root, &["cargo", "-V"]).map(|(_, s)| s.trim_end().to_owned());
    snap.toolchain.target_triple = target_triple.map(str::to_owned);

    snap.host.triple = snap.toolchain.host_triple.clone();
    snap.host.cpu.arch = std::env::consts::ARCH.to_owned().into();
    snap.execution_boundary = declared_execution_boundary(
        std::env::var(CONTAINMENT_ENV).ok().as_deref(),
    );

    // Extra tools relevant to verification.
    for (name, argv) in [
        ("git", vec!["--version"]),
        ("cargo-deny", vec!["cargo-deny", "--version"]),
        ("rustfmt", vec!["rustfmt", "--version"]),
        ("clippy-driver", vec!["clippy-driver", "--version"]),
    ] {
        let mut full = vec![name];
        full.extend(argv);
        if let Some((_, version)) = probe(root, &full) {
            snap.extra_tools.insert(
                name.to_owned(),
                version.lines().next().unwrap_or("").to_owned(),
            );
        }
    }

    snap
}

fn declared_execution_boundary(marker: Option<&str>) -> Option<ExecutionBoundary> {
    match marker {
        Some(BUBBLEWRAP_V1) => Some(ExecutionBoundary {
            mechanism: "bubblewrap".to_owned(),
            profile: BUBBLEWRAP_V1.to_owned(),
            assertion_scope: DECLARATION_SCOPE.to_owned(),
        }),
        _ => None,
    }
}

/// Records the effective RUSTFLAGS visible to the run (if any).
pub fn record_rustflags(snapshot: &mut EnvironmentSnapshot) {
    if let Ok(flags) = std::env::var("RUSTFLAGS") {
        snapshot.toolchain.rustflags = Some(redact_secrets(&flags));
    }
}

/// Redacts values that look like embedded secrets in free-form strings.
/// Defense in depth only — never a guarantee.
pub fn redact_secrets(value: &str) -> String {
    const MARKERS: [&str; 6] = [
        "TOKEN",
        "PASSWORD",
        "SECRET",
        "API_KEY",
        "AUTHORIZATION",
        "PRIVATE_KEY",
    ];
    let upper = value.to_ascii_uppercase();
    for m in MARKERS {
        if upper.contains(m) {
            return "[REDACTED]".to_owned();
        }
    }
    value.to_owned()
}

/// Convenience wrapper used by the pipeline to build the recorded env map.
pub fn recorded_environment(spec_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    spec_env.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn redaction_catches_secret_like_flags() {
        assert_eq!(redact_secrets("MY_TOKEN=abc"), "[REDACTED]");
        assert_eq!(redact_secrets("-Ctarget-cpu=native"), "-Ctarget-cpu=native");
        assert_eq!(redact_secrets("api_key"), "[REDACTED]");
    }

    #[test]
    fn environment_probe_reports_toolchain_or_absence() {
        let dir = std::env::temp_dir();
        let snap = collect_environment(&dir, None);
        // In this repository rustc must exist.
        assert!(snap.toolchain.rustc_version.is_some());
        assert!(snap
            .toolchain
            .rustc_version
            .as_deref()
            .unwrap_or("")
            .contains("rustc"));
    }

    #[test]
    fn recognized_containment_marker_becomes_declared_boundary() {
        let boundary = declared_execution_boundary(Some("bubblewrap-v1")).expect("recognized");
        assert_eq!(boundary.mechanism, "bubblewrap");
        assert_eq!(boundary.profile, "bubblewrap-v1");
        assert_eq!(boundary.assertion_scope, "producer_declared_not_attested");
    }

    #[test]
    fn unknown_or_missing_containment_marker_creates_no_boundary_claim() {
        assert!(declared_execution_boundary(None).is_none());
        assert!(declared_execution_boundary(Some("bubblewrap-v999")).is_none());
        assert!(declared_execution_boundary(Some("container")).is_none());
    }

    #[test]
    fn provenance_of_self_is_git_backed() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .unwrap()
            .to_path_buf();
        let prov = collect_provenance(&root);
        let gp = prov.git.expect("repo has git");
        assert!(gp.commit.as_deref().is_some_and(|c| c.len() >= 40));
    }
}
