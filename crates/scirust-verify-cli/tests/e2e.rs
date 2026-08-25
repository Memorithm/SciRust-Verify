//! End-to-end CLI tests against the fixture projects.
//!
//! These tests exercise the real binary (`scirust-verify`) through
//! `assert_cmd`, producing real evidence dossiers in the fixtures. Each test
//! is independent; cargo build caching makes repeat runs fast.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("cli crate lives at crates/scirust-verify-cli")
}

fn fixture(name: &str) -> PathBuf {
    repo_root().join("fixtures").join(name)
}

/// Builds the CLI once so repeated invocations stay fast.
fn cli() -> Command {
    Command::cargo_bin("scirust-verify").expect("binary target scirust-verify")
}

static PREBUILT: OnceLock<()> = OnceLock::new();

/// Pre-builds every fixture that needs compiling, sequentially, so parallel
/// test threads do not fight over cargo locks on cold caches.
fn prebuild_fixtures() {
    PREBUILT.get_or_init(|| {
        for name in [
            "passing-project",
            "failing-tests",
            "deterministic-project",
            "nondeterministic-project",
            "timeout-project",
            "large-output-project",
            "numeric-pass",
            "numeric-fail",
        ] {
            let _ = std::process::Command::new("cargo")
                .arg("build")
                .arg("--quiet")
                .current_dir(fixture(name))
                .status();
        }
    });
}

fn latest_run(project: &Path) -> String {
    let runs = project.join(".scirust-verify/runs");
    let mut ids: Vec<_> = std::fs::read_dir(&runs)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("run-"))
        .collect();
    ids.sort();
    ids.last().expect("at least one run").clone()
}

/// Latest run id inside an explicit runs directory.
fn latest_run_in(runs: &Path) -> String {
    let mut ids: Vec<_> = std::fs::read_dir(runs)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("run-"))
        .collect();
    ids.sort();
    ids.last().expect("at least one run").clone()
}

#[test]
fn passing_project_verifies_and_seals_bundle() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("passing-store");
    let out = cli()
        .args([
            "verify",
            project.to_str().unwrap(),
            "--output",
            store.join(".scirust-verify").to_str().unwrap(),
        ])
        .env("CARGO_TARGET_DIR", project.join("target"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout/stderr: {}/{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("overall verdict: PASS"), "{stdout}");

    // Dossier structure.
    let run_dir = store
        .join(".scirust-verify/runs")
        .join(latest_run_in(&store.join(".scirust-verify/runs")));
    for file in [
        "run.json",
        "artifact.json",
        "environment.json",
        "provenance.json",
        "plan.json",
        "claims.json",
        "executions.json",
        "evaluations.json",
        "report.json",
        "report.md",
        "bundle.json",
    ] {
        assert!(run_dir.join(file).is_file(), "missing {file}");
    }

    // Integrity of a freshly sealed bundle must hold.
    let report_out = cli()
        .args([
            "report",
            &latest_run_in(&store.join(".scirust-verify/runs")),
            "--check-integrity",
            "--json",
        ])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        report_out.status.success(),
        "{}",
        String::from_utf8_lossy(&report_out.stderr)
    );
}

#[test]
fn failing_tests_fail_but_produce_valid_dossier() {
    prebuild_fixtures();
    let project = fixture("failing-tests");
    let out = cli()
        .args(["verify", project.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "verification failure exits 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tests_pass"), "{stdout}");
    assert!(stdout.contains("FAILED"), "{stdout}");

    // The bundle still exists and is sealed — failure is evidence too.
    let run_dir = project.join(format!(".scirust-verify/runs/{}", latest_run(&project)));
    assert!(run_dir.join("bundle.json").is_file());
}

#[test]
fn determinism_positive_and_negative() {
    prebuild_fixtures();
    let good = cli()
        .args(["verify", fixture("deterministic-project").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(good.status.success());
    assert!(String::from_utf8_lossy(&good.stdout).contains("PASS"));

    let bad = cli()
        .args([
            "verify",
            fixture("nondeterministic-project").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&bad.stdout);
    assert!(stdout.contains("cross_process_deterministic"), "{stdout}");
    assert!(stdout.contains("FAILED"), "{stdout}");

    // The comparison evidence derives from per-run evidences.
    let project = fixture("nondeterministic-project");
    let run_dir = project.join(format!(".scirust-verify/runs/{}", latest_run(&project)));
    let mut found_derived = false;
    for entry in evidence_files(&run_dir) {
        let text = std::fs::read_to_string(entry).unwrap();
        if text.contains("\"derived_from\"") && text.contains("\"kind\": \"fingerprint\"") {
            found_derived = true;
        }
    }
    assert!(
        found_derived,
        "comparison evidence must reference run evidences"
    );
}

#[test]
fn numeric_pass_and_fail_paths() {
    prebuild_fixtures();
    let ok = cli()
        .args(["verify", fixture("numeric-pass").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stdout)
    );

    let bad = cli()
        .args(["verify", fixture("numeric-fail").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&bad.stdout);
    assert!(stdout.contains("oracle_equivalent"), "{stdout}");
    assert!(stdout.contains("FAILED"), "{stdout}");

    // The verifier caught divergence although the program exited 0:
    // numeric re-evaluation independence is the whole point. NaN against a
    // finite oracle must also fail — never an accidental pass.
    let project = fixture("numeric-fail");
    let run_dir = project.join(format!(".scirust-verify/runs/{}", latest_run(&project)));
    let execs = std::fs::read_to_string(run_dir.join("executions.json")).unwrap();
    assert!(execs.contains("\"outcome\": \"failed\""), "{execs}");
    let mut saw_nan_observation = false;
    for entry in evidence_files(&run_dir) {
        let text = std::fs::read_to_string(entry).unwrap();
        if text.contains("nan_oracle") && text.contains("numeric_comparison") {
            saw_nan_observation = true;
        }
    }
    assert!(
        saw_nan_observation,
        "NaN observation must be captured as evidence"
    );
}

#[test]
fn timeout_is_not_a_crash_but_insufficient_evidence() {
    prebuild_fixtures();
    let project = fixture("timeout-project");
    let out = cli()
        .args(["verify", project.to_str().unwrap()])
        .timeout(std::time::Duration::from_secs(90))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("NOT_VERIFIED"), "{stdout}");
}

#[test]
fn large_output_is_bounded() {
    prebuild_fixtures();
    let project = fixture("large-output-project");
    let out = cli()
        .args(["verify", project.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());

    let run_dir = project.join(format!(".scirust-verify/runs/{}", latest_run(&project)));
    let mut saw_truncated = false;
    for entry in evidence_files(&run_dir) {
        let text = std::fs::read_to_string(entry).unwrap();
        if text.contains("\"stdout_truncated\"") && text.contains("true") {
            saw_truncated = true;
        }
    }
    assert!(saw_truncated, "truncation must be recorded as evidence");
}

#[test]
fn tampered_bundle_detected_end_to_end() {
    prebuild_fixtures();
    // Produce a clean run in an isolated store.
    let project = fixture("passing-project");
    let store = tempfile_dir("tamper-store");
    let _ = cli()
        .args([
            "verify",
            project.to_str().unwrap(),
            "--output",
            store.join(".scirust-verify").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let run_id = latest_run_in(&store.join(".scirust-verify/runs"));
    let run_dir = store.join(format!(".scirust-verify/runs/{run_id}"));

    // Tamper with a sealed file (artifact name).
    let artifact_path = run_dir.join("artifact.json");
    let original = std::fs::read_to_string(&artifact_path).unwrap();
    std::fs::write(&artifact_path, original.replace("passing-project", "evil")).unwrap();

    let out = cli()
        .args(["report", &run_id, "--check-integrity"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("INTEGRITY FAILURE"), "{stderr}");
    assert!(stderr.contains("artifact.json"), "{stderr}");
}

#[test]
fn invalid_manifest_is_rejected_without_running() {
    let tmp = tempfile_dir("invalid-manifest");
    std::fs::write(
        tmp.join("scirust-verify.toml"),
        "schema_version = 1\n[verification]\nprofile = \"ultra\"\n",
    )
    .unwrap();
    let out = cli()
        .args(["verify", tmp.to_str().unwrap()])
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        combined.contains("unknown verification profile"),
        "{combined}"
    );
}

#[test]
fn replay_creates_new_linked_run_and_diff_compares() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("replay-store");
    let out = cli()
        .args([
            "verify",
            project.to_str().unwrap(),
            "--output",
            store.join(".scirust-verify").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let first = latest_run_in(&store.join(".scirust-verify/runs"));

    let replay_out = cli()
        .args(["replay", &first, "--json"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        replay_out.status.success(),
        "{}",
        String::from_utf8_lossy(&replay_out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&replay_out.stdout).expect("valid JSON");
    let second = doc
        .get("new_run_id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_owned();
    assert_ne!(first, second);

    // Original bundle untouched; new run links back.
    let orig_doc_text =
        std::fs::read_to_string(store.join(format!(".scirust-verify/runs/{first}/run.json")))
            .unwrap();
    assert!(orig_doc_text.contains(&format!("\"run_id\": \"{first}\"")));

    // diff is informational and must succeed both ways.
    for (a, b) in [
        (first.as_str(), second.as_str()),
        (second.as_str(), first.as_str()),
    ] {
        let d = cli()
            .args(["diff", a, b])
            .current_dir(&store)
            .output()
            .unwrap();
        assert!(d.status.success(), "{}", String::from_utf8_lossy(&d.stderr));
    }
}

#[test]
fn verify_json_emits_parseable_machine_output() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let out = cli()
        .args(["verify", project.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("verify --json must emit valid JSON");
    assert_eq!(
        doc.get("overall_verdict").and_then(|v| v.as_str()),
        Some("PASS")
    );
    assert!(doc
        .get("run_id")
        .and_then(|v| v.as_str())
        .unwrap()
        .starts_with("run-"));
}

#[test]
fn scirust_protocol_ingestion_preserves_semantics() {
    // Synthetic protocol bundle exercising all three source statuses.
    let bundle = tempfile_dir("scirust-protocol-bundle");
    std::fs::write(
        bundle.join("summary.txt"),
        "commit=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\nbranch=master\ntimestamp=2026-08-25T00:00:00Z\npackages=90\ngate.fmt=PASS (required, 3s)\ngate.build=PASS (required, 100s)\ngate.test=FAIL (required, 200s -- 2 oracles diverged)\ngate.aarch64=SKIP (required, 0s)\ngate.gpu=SKIP (optional, 0s)\nverdict=FAIL\n",
    )
    .unwrap();

    let store = tempfile_dir("ingest-store");
    let out = cli()
        .args([
            "ingest-scirust",
            bundle.to_str().unwrap(),
            "--output",
            store.to_str().unwrap(),
            "--json",
        ])
        .current_dir(&store)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    // A FAIL protocol must not exit 0.
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON on stdout");
    assert_eq!(
        doc.get("overall_verdict").and_then(|v| v.as_str()),
        Some("FAIL")
    );

    // Inspect the dossier: original summary attached verbatim; SKIP stays SKIPPED.
    let run_id = doc.get("run_id").and_then(|v| v.as_str()).unwrap();
    let run_dir = store.join(format!(".scirust-verify/runs/{run_id}"));
    let summary_attached =
        std::fs::read_to_string(run_dir.join("logs/scirust-summary.txt")).unwrap();
    assert!(summary_attached.contains("verdict=FAIL"));

    let evals = std::fs::read_to_string(run_dir.join("evaluations.json")).unwrap();
    assert!(
        evals.contains("tests_pass@test"),
        "gate-linked claim id expected: {evals}"
    );
    assert!(evals.contains("\"failed\""), "{evals}");

    // Integrity of an ingested bundle holds.
    let integrity = cli()
        .args(["report", run_id, "--check-integrity"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        integrity.status.success(),
        "{}",
        String::from_utf8_lossy(&integrity.stderr)
    );
}

#[test]
fn primary_commands_have_help_and_stable_behavior() {
    for cmd in [
        "init", "inspect", "plan", "verify", "report", "replay", "diff", "doctor", "schema",
    ] {
        let out = cli().args([cmd, "--help"]).output().unwrap();
        assert!(out.status.success(), "{cmd} --help failed");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("Usage:"), "{cmd} help lacks usage");
    }

    // Nonexistent run => exit 1 with meaningful message, no panic.
    let out = cli()
        .args(["report", "run-does-not-exist"])
        .current_dir(tempfile_dir("empty"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("not found") || err.contains("run verify first"),
        "{err}"
    );

    // Invalid input (bad path) exits 2 with a meaningful message.
    let out = cli()
        .args(["inspect", "/definitely/not/a/real/path-xyz"])
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not usable"));
}

#[test]
fn doctor_and_schema_succeed() {
    let doc = cli().arg("doctor").output().unwrap();
    assert!(doc.status.success());
    assert!(String::from_utf8_lossy(&doc.stdout).contains("rustc"));

    let schema = cli().arg("schema").output().unwrap();
    assert!(schema.status.success());
    let text = String::from_utf8_lossy(&schema.stdout);
    assert!(text.contains("run.json") && text.contains("bundle.json"));
}

#[test]
fn init_generates_manifest_without_clobbering() {
    let dir = tempfile_dir("init-project");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]
name=\"initp\"\nversion=\"0.1.0\"\nedition=\"2021\"\n\n[workspace]\n",
    )
    .unwrap();

    // First init writes.
    let out = cli()
        .args(["init", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let manifest = dir.join("scirust-verify.toml");
    let first = std::fs::read_to_string(&manifest).unwrap();
    assert!(first.contains("schema_version = 1"));

    // Second init refuses to clobber.
    let out = cli()
        .args(["init", dir.to_str().unwrap()])
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force"), "{err}");

    // --force overwrites.
    let out = cli()
        .args(["init", dir.to_str().unwrap(), "--force"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn plan_lists_expected_cargo_checks() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let out = cli()
        .args(["plan", project.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("cargo:build"), "{text}");
    assert!(text.contains("cargo:test"), "{text}");
    assert!(text.contains("core:source-clean"), "{text}");
}

#[test]
fn paths_with_spaces_and_unicode_roundtrip() {
    prebuild_fixtures();
    let weird = tempfile_dir("weird path with spaces ünicode-Ω");
    let src = fixture("passing-project");
    // Copy fixture source (without target/.scirust-verify) into weird path.
    copy_dir(&src, &weird);

    let out = cli()
        .args([
            "verify",
            weird.to_str().unwrap(),
            "--output",
            weird
                .join("store")
                .join(".scirust-verify")
                .to_str()
                .unwrap(),
        ])
        .timeout(std::time::Duration::from_secs(180))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{} / {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn numeric_exit_zero_without_observation_is_not_verified() {
    prebuild_fixtures();
    let project = tempfile_dir("numeric-missing-evidence");
    copy_dir(&fixture("numeric-pass"), &project);
    std::fs::write(
        project.join("src/main.rs"),
        "fn main() { println!(\"plain output only\"); }\n",
    )
    .unwrap();
    let out = cli()
        .args(["verify", project.to_str().unwrap()])
        .timeout(std::time::Duration::from_secs(180))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("oracle_equivalent"), "{stdout}");
    assert!(stdout.contains("NOT_VERIFIED"), "{stdout}");
}

#[test]
fn structured_determinism_without_fingerprint_is_not_verified() {
    prebuild_fixtures();
    let project = tempfile_dir("determinism-missing-fingerprint");
    copy_dir(&fixture("deterministic-project"), &project);
    std::fs::write(
        project.join("src/main.rs"),
        "fn main() { println!(\"plain output only\"); }\n",
    )
    .unwrap();
    let out = cli()
        .args(["verify", project.to_str().unwrap()])
        .timeout(std::time::Duration::from_secs(180))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cross_process_deterministic"), "{stdout}");
    assert!(stdout.contains("NOT_VERIFIED"), "{stdout}");
}

#[test]
fn nested_git_project_detects_dirty_parent_worktree() {
    prebuild_fixtures();
    let root = tempfile_dir("nested-git-dirty");
    let project = root.join("nested/project");
    copy_dir(&fixture("passing-project"), &project);
    let manifest = project.join("scirust-verify.toml");
    let mut body = std::fs::read_to_string(&manifest).unwrap();
    body.push_str("\n[claims]\nsource_clean = \"required\"\n");
    std::fs::write(&manifest, body).unwrap();
    for args in [
        vec!["init"],
        vec!["config", "user.email", "ci@example.invalid"],
        vec!["config", "user.name", "SciRust Verify CI"],
        vec!["add", "."],
        vec!["commit", "-m", "fixture"],
    ] {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
    }
    std::fs::write(project.join("dirty.txt"), "dirty\n").unwrap();
    let out = cli()
        .args(["verify", project.to_str().unwrap()])
        .timeout(std::time::Duration::from_secs(180))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("source_clean"), "{stdout}");
    assert!(stdout.contains("FAILED"), "{stdout}");
}

#[test]
fn cargo_selection_flags_are_before_clippy_separator_and_absent_from_fmt() {
    prebuild_fixtures();
    let project = tempfile_dir("cargo-selection-plan");
    copy_dir(&fixture("passing-project"), &project);
    let manifest = project.join("scirust-verify.toml");
    let mut body = std::fs::read_to_string(&manifest).unwrap();
    body = body.replace(
        "profile = \"basic\"",
        "profile = \"basic\"\ntargets = [\"x86_64-unknown-linux-gnu\"]\nfeatures = [\"demo-feature\"]",
    );
    body = body.replace("fmt = false", "fmt = true");
    body = body.replace("clippy = false", "clippy = true");
    std::fs::write(&manifest, body).unwrap();
    let out = cli()
        .args(["plan", project.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let fmt = text
        .lines()
        .find(|line| line.contains("command: cargo fmt"))
        .unwrap();
    assert!(
        !fmt.contains("--target") && !fmt.contains("--features"),
        "{fmt}"
    );
    let clippy = text
        .lines()
        .find(|line| line.contains("command: cargo clippy"))
        .unwrap();
    let sep = clippy.find(" -- ").unwrap();
    let target = clippy.find("--target").unwrap();
    let features = clippy.find("--features").unwrap();
    assert!(target < sep && features < sep, "{clippy}");
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let name = entry.file_name();
        if name == "target" || name == ".scirust-verify" {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

#[test]
fn aggregate_reports_claim_across_runs() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("aggregate-store");
    let output_flag = store.join(".scirust-verify");
    let out_args = ["--output", output_flag.to_str().unwrap()];
    for _ in 0..2 {
        let out = cli()
            .args(["verify", project.to_str().unwrap()])
            .args(out_args)
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let ids = run_ids_in(&store.join(".scirust-verify/runs"));
    assert!(ids.len() >= 2);

    // Compatibility mode still answers whether all matching evaluations are VERIFIED,
    // but it now verifies bundle integrity and reports scope facts too.
    let agg = cli()
        .args(["aggregate", "tests_pass", &ids[0], &ids[1], "--json"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        agg.status.success(),
        "{}",
        String::from_utf8_lossy(&agg.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&agg.stdout).unwrap();
    assert_eq!(
        doc.get("all_verified").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        doc.pointer("/scope_assessment/source_consistency")
            .and_then(|v| v.as_str()),
        Some("verified")
    );
    assert_eq!(
        doc.pointer("/scope_assessment/scope_certified")
            .and_then(|v| v.as_bool()),
        Some(true)
    );

    // One normalized platform is enough only when explicitly requested.
    let scoped = cli()
        .args([
            "aggregate",
            "tests_pass",
            &ids[0],
            &ids[1],
            "--require-scope",
            "--min-platforms",
            "1",
            "--json",
        ])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        scoped.status.success(),
        "{}",
        String::from_utf8_lossy(&scoped.stderr)
    );

    // Requiring two distinct platforms on two same-host runs is NOT_VERIFIED.
    let multi = cli()
        .args([
            "aggregate",
            "tests_pass",
            &ids[0],
            &ids[1],
            "--require-scope",
            "--min-platforms",
            "2",
            "--json",
        ])
        .current_dir(&store)
        .output()
        .unwrap();
    assert_eq!(multi.status.code(), Some(1));
    let multi_doc: serde_json::Value = serde_json::from_slice(&multi.stdout).unwrap();
    assert_eq!(
        multi_doc
            .pointer("/scope_assessment/scope_certified")
            .and_then(|v| v.as_bool()),
        Some(false)
    );

    // A pattern matching nothing exits 1 (not-found contract).
    let miss = cli()
        .args(["aggregate", "no_such_claim", &ids[0], "--json"])
        .current_dir(&store)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert_eq!(miss.status.code(), Some(1));

    // Aggregation may never consume a tampered dossier as trustworthy input.
    let eval_path = store.join(format!(".scirust-verify/runs/{}/evaluations.json", ids[0]));
    let original = std::fs::read_to_string(&eval_path).unwrap();
    std::fs::write(&eval_path, original.replace("verified", "failed")).unwrap();
    let corrupt = cli()
        .args(["aggregate", "tests_pass", &ids[0], &ids[1], "--json"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert_eq!(corrupt.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&corrupt.stderr).contains("integrity"),
        "{}",
        String::from_utf8_lossy(&corrupt.stderr)
    );
}

fn run_ids_in(runs: &Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(runs)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("run-"))
        .collect();
    ids.sort();
    ids
}

fn evidence_files(run_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = run_dir.join("evidence");
    if !dir.is_dir() {
        return out;
    }
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out
}

#[test]
fn signed_dossier_roundtrip_and_wrong_key_rejection() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("signature-roundtrip");
    let output = store.join(".scirust-verify");
    let verify = cli()
        .args([
            "verify",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .env("CARGO_TARGET_DIR", project.join("target"))
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let run = latest_run_in(&output.join("runs"));

    let keys = store.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let private_a = keys.join("a.json");
    let public_a = keys.join("a.pub.json");
    let private_b = keys.join("b.json");
    let public_b = keys.join("b.pub.json");
    let keygen = cli()
        .args([
            "keygen",
            "--private-key",
            private_a.to_str().unwrap(),
            "--public-key",
            public_a.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let secret_doc = std::fs::read_to_string(&private_a).unwrap();
    let secret_hex = serde_json::from_str::<serde_json::Value>(&secret_doc).unwrap()
        ["secret_key_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!String::from_utf8_lossy(&keygen.stdout).contains(&secret_hex));

    let signed = cli()
        .args([
            "sign",
            &run,
            "--private-key",
            private_a.to_str().unwrap(),
            "--project",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let checked = cli()
        .args([
            "--json",
            "verify-signature",
            &run,
            "--public-key",
            public_a.to_str().unwrap(),
            "--project",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(doc["cryptographically_valid"].as_bool(), Some(true));
    assert!(doc["trust_scope"]
        .as_str()
        .unwrap()
        .contains("signer identity"));

    assert!(cli()
        .args([
            "keygen",
            "--private-key",
            private_b.to_str().unwrap(),
            "--public-key",
            public_b.to_str().unwrap(),
        ])
        .output()
        .unwrap()
        .status
        .success());
    let wrong = cli()
        .args([
            "verify-signature",
            &run,
            "--public-key",
            public_b.to_str().unwrap(),
            "--project",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
}

#[test]
fn corrupted_dossier_cannot_be_signed() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("signature-corrupt");
    let output = store.join(".scirust-verify");
    let verify = cli()
        .args([
            "verify",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .env("CARGO_TARGET_DIR", project.join("target"))
        .output()
        .unwrap();
    assert!(verify.status.success());
    let run = latest_run_in(&output.join("runs"));
    std::fs::write(
        output.join("runs").join(&run).join("report.md"),
        "tampered\n",
    )
    .unwrap();

    let private = store.join("private.json");
    let public = store.join("public.json");
    assert!(cli()
        .args([
            "keygen",
            "--private-key",
            private.to_str().unwrap(),
            "--public-key",
            public.to_str().unwrap(),
        ])
        .output()
        .unwrap()
        .status
        .success());
    let sign = cli()
        .args([
            "sign",
            &run,
            "--private-key",
            private.to_str().unwrap(),
            "--project",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(sign.status.code(), Some(1));
    assert!(!store.join(".scirust-verify/signatures").exists());
}

fn tempfile_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sve-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
