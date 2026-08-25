from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, got {count}")
    p.write_text(text.replace(old, new, 1))


# 1) Numeric checks must never verify without valid numeric SVOP evidence.
replace_once(
    "crates/scirust-verify-core/src/planning.rs",
    '''    // Structured observations (SVOP) parsed independently of exit status.\n    let svop: Option<Vec<_>> =\n        scirust_verify_numerics::parse_observations(&record.stdout_lossy()).ok();\n    let mut observations: Vec<Observation> = svop\n        .as_deref()\n        .unwrap_or(&[])\n        .iter()\n        .map(|o| o.to_model_observation())\n        .collect();\n\n    // Numeric re-evaluation against the scope tolerance — SciRust-Verify\n    // never trusts the program's own comparison verdict.\n    let tolerance = env.scope.tolerance.unwrap_or_default();\n    let mut numeric_fail = false;\n    if let Some(obs) = &svop {\n''',
    '''    // Structured observations (SVOP) are evidence, not decoration.\n    // Numeric checks require at least one valid numeric comparison and must\n    // never turn parse failures, missing observations or truncated stdout\n    // into a successful claim.\n    let svop_result = scirust_verify_numerics::parse_observations(&record.stdout_lossy());\n    let svop = svop_result.as_ref().ok();\n    let mut observations: Vec<Observation> = svop\n        .map(Vec::as_slice)\n        .unwrap_or(&[])\n        .iter()\n        .map(|o| o.to_model_observation())\n        .collect();\n\n    let mut structured_evidence_problem = None;\n    if producer == "numeric-provider" {\n        if record.stdout.truncated {\n            structured_evidence_problem = Some(\n                "numeric stdout was truncated; complete structured evidence was not captured"\n                    .to_owned(),\n            );\n        } else {\n            match &svop_result {\n                Err(err) => {\n                    structured_evidence_problem =\n                        Some(format!("invalid structured numeric evidence: {err}"));\n                }\n                Ok(obs)\n                    if !obs.iter().any(|o| {\n                        matches!(\n                            o,\n                            scirust_verify_numerics::ValidObservation::NumericComparison { .. }\n                        )\n                    }) =>\n                {\n                    structured_evidence_problem = Some(\n                        "numeric check emitted no valid numeric_comparison observation".to_owned(),\n                    );\n                }\n                Ok(_) => {}\n            }\n        }\n    }\n\n    // Numeric re-evaluation against the scope tolerance — SciRust-Verify\n    // never trusts the program's own comparison verdict.\n    let tolerance = env.scope.tolerance.unwrap_or_default();\n    let mut numeric_fail = false;\n    if let Some(obs) = svop {\n''',
)
replace_once(
    "crates/scirust-verify-core/src/planning.rs",
    '''    let (status, mut outcome, summary) =\n        crate::providers::interpret_exit(&record.status, *expect, check);\n    if numeric_fail && outcome == Verdict::Verified {\n        outcome = Verdict::Failed;\n    }\n''',
    '''    let (status, mut outcome, mut summary) =\n        crate::providers::interpret_exit(&record.status, *expect, check);\n    if let Some(problem) = structured_evidence_problem {\n        if outcome == Verdict::Verified {\n            outcome = Verdict::NotVerified;\n            summary = problem;\n        }\n    } else if numeric_fail && outcome == Verdict::Verified {\n        outcome = Verdict::Failed;\n        summary = "one or more numeric/property observations contradicted the requirement".into();\n    }\n''',
)

# 2) Source cleanliness: nested project roots inside a Git worktree must be probed.
replace_once(
    "crates/scirust-verify-core/src/providers.rs",
    '''        let dirty = match env.project_root.join(".git").exists() {\n            // Re-derive quickly; discovery result is not carried into execute.\n            true => {\n                let out = std::process::Command::new("git")\n                    .args(["status", "--porcelain"])\n                    .current_dir(env.project_root)\n                    .output();\n                match out {\n                    Ok(o) if o.status.success() => {\n                        let n = String::from_utf8_lossy(&o.stdout)\n                            .lines()\n                            .filter(|l| !l.trim().is_empty())\n                            .count();\n                        if n == 0 {\n                            None::<u64>\n                        } else {\n                            Some(n as u64)\n                        }\n                    }\n                    _ => None,\n                }\n            }\n            false => None,\n        };\n        let git_present = std::process::Command::new("git")\n            .args(["rev-parse", "--git-dir"])\n            .current_dir(env.project_root)\n            .output()\n            .map(|o| o.status.success())\n            .unwrap_or(false);\n''',
    '''        let git_present = std::process::Command::new("git")\n            .args(["rev-parse", "--is-inside-work-tree"])\n            .current_dir(env.project_root)\n            .output()\n            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")\n            .unwrap_or(false);\n        let dirty = if git_present {\n            std::process::Command::new("git")\n                .args(["status", "--porcelain"])\n                .current_dir(env.project_root)\n                .output()\n                .ok()\n                .filter(|o| o.status.success())\n                .map(|o| {\n                    String::from_utf8_lossy(&o.stdout)\n                        .lines()\n                        .filter(|l| !l.trim().is_empty())\n                        .count() as u64\n                })\n        } else {\n            None\n        };\n''',
)
replace_once(
    "crates/scirust-verify-core/src/providers.rs",
    '''            } else if dirty.unwrap_or(0) > 0 {\n                (\n                    scirust_verify_model::CheckStatus::Executed { exit_code: Some(0) },\n                    Verdict::Failed,\n                    format!("{} uncommitted change(s) present", dirty.unwrap_or(0)),\n                )\n            } else {\n                (\n                    scirust_verify_model::CheckStatus::Executed { exit_code: Some(0) },\n                    Verdict::Verified,\n                    "worktree clean".to_owned(),\n                )\n            };\n''',
    '''            } else if dirty.is_none() {\n                (\n                    scirust_verify_model::CheckStatus::Skipped {\n                        reason: "Git worktree detected but status could not be determined".into(),\n                    },\n                    Verdict::Skipped,\n                    "Git worktree detected but cleanliness is unknown".to_owned(),\n                )\n            } else if dirty.unwrap_or(0) > 0 {\n                (\n                    scirust_verify_model::CheckStatus::Executed { exit_code: Some(0) },\n                    Verdict::Failed,\n                    format!("{} uncommitted change(s) present", dirty.unwrap_or(0)),\n                )\n            } else {\n                (\n                    scirust_verify_model::CheckStatus::Executed { exit_code: Some(0) },\n                    Verdict::Verified,\n                    "worktree clean".to_owned(),\n                )\n            };\n''',
)
replace_once(
    "crates/scirust-verify-core/src/providers.rs",
    '''        .observation(Observation::new(\n            "worktree_dirty",\n            "git_status",\n            ObservedValue::Bool(dirty.unwrap_or(0) > 0 || !git_present),\n        ))\n        .meta(\n            "dirty_state",\n            match (git_present, dirty.unwrap_or(0)) {\n                (false, _) => DirtyState::Unknown,\n                (_, 0) => DirtyState::Clean,\n                (_, _) => DirtyState::Dirty,\n            },\n        )\n''',
    '''        .observation(Observation::new(\n            "worktree_dirty",\n            "git_status",\n            match dirty {\n                Some(n) => ObservedValue::Bool(n > 0),\n                None => ObservedValue::Text("unknown".into()),\n            },\n        ))\n        .meta(\n            "dirty_state",\n            match (git_present, dirty) {\n                (false, _) | (_, None) => DirtyState::Unknown,\n                (_, Some(0)) => DirtyState::Clean,\n                (_, Some(_)) => DirtyState::Dirty,\n            },\n        )\n''',
)

# 3) Cargo selection flags belong before `--`; fmt must not receive them.
replace_once(
    "crates/scirust-verify-cargo/src/lib.rs",
    '''        if self.section.fmt {\n            let mut args = vec!["fmt".into(), "--all".into(), "--".into(), "--check".into()];\n            target_args(&mut args);\n''',
    '''        if self.section.fmt {\n            let args = vec!["fmt".into(), "--all".into(), "--".into(), "--check".into()];\n''',
)
replace_once(
    "crates/scirust-verify-cargo/src/lib.rs",
    '''        if self.section.clippy {\n            let mut args = vec![\n                "clippy".into(),\n                "--workspace".into(),\n                "--all-targets".into(),\n                "--".into(),\n                "-D".into(),\n                "warnings".into(),\n            ];\n            target_args(&mut args);\n''',
    '''        if self.section.clippy {\n            let mut args = vec![\n                "clippy".into(),\n                "--workspace".into(),\n                "--all-targets".into(),\n            ];\n            target_args(&mut args);\n            args.extend(["--".into(), "-D".into(), "warnings".into()]);\n''',
)

# 4) Structured determinism requires real comparable fingerprints.
replace_once(
    "crates/scirust-verify-determinism/src/lib.rs",
    '''        let mut successful_runs = 0usize;\n        let mut run_evidence_ids = Vec::new();\n''',
    '''        let mut successful_runs = 0usize;\n        let mut fingerprint_errors = 0usize;\n        let mut run_evidence_ids = Vec::new();\n''',
)
replace_once(
    "crates/scirust-verify-determinism/src/lib.rs",
    '''            let ev_id = env.sink.next_id();\n            let fingerprint = fingerprint_of(&mode, &record);\n            fingerprints.insert(plan.label.clone(), fingerprint);\n''',
    '''            let ev_id = env.sink.next_id();\n            match fingerprint_of(&mode, &record) {\n                Ok(fingerprint) => {\n                    fingerprints.insert(plan.label.clone(), fingerprint);\n                }\n                Err(reason) => {\n                    all_ok = false;\n                    fingerprint_errors += 1;\n                    notes.push(format!("{}: {reason}", plan.label));\n                }\n            }\n''',
)
replace_once(
    "crates/scirust-verify-determinism/src/lib.rs",
    '''        .status(if all_ok && distinct.len() == 1 && successful_runs >= 2 {\n''',
    '''        .status(if all_ok\n            && fingerprint_errors == 0\n            && fingerprints.len() == plans.len()\n            && distinct.len() == 1\n            && successful_runs >= 2\n        {\n''',
)
replace_once(
    "crates/scirust-verify-determinism/src/lib.rs",
    '''        } else if successful_runs < 2 {\n            (\n                Verdict::NotVerified,\n                format!(\n                    "only {successful_runs} of {} executions completed; insufficient evidence",\n                    plans.len()\n                ),\n            )\n        } else if distinct.len() == 1 {\n''',
    '''        } else if successful_runs < 2 {\n            (\n                Verdict::NotVerified,\n                format!(\n                    "only {successful_runs} of {} executions completed; insufficient evidence",\n                    plans.len()\n                ),\n            )\n        } else if fingerprint_errors > 0 || fingerprints.len() != plans.len() {\n            (\n                Verdict::NotVerified,\n                format!(\n                    "{} execution(s) did not yield a complete comparable fingerprint",\n                    fingerprint_errors\n                ),\n            )\n        } else if distinct.len() == 1 {\n''',
)
start = Path("crates/scirust-verify-determinism/src/lib.rs")
text = start.read_text()
old = '''fn fingerprint_of(mode: &str, record: &scirust_verify_runner::ExecutionRecord) -> String {\n    match mode {\n        "structured" => {\n            // Canonical fingerprint over SVOP fingerprint observations only.\n            match scirust_verify_numerics::parse_observations(&record.stdout_lossy()) {\n                Ok(obs) => {\n                    let mut canonical = String::new();\n                    for o in &obs {\n                        if let scirust_verify_numerics::ValidObservation::Fingerprint {\n                            name,\n                            value,\n                        } = o\n                        {\n                            canonical.push_str(&format!("{name}={value}\\n"));\n                        }\n                    }\n                    scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()).value\n                }\n                Err(_) => "unparseable-structured-output".to_owned(),\n            }\n        }\n        _ => record.stdout_digest().value,\n    }\n}\n'''
new = '''fn fingerprint_of(\n    mode: &str,\n    record: &scirust_verify_runner::ExecutionRecord,\n) -> Result<String, String> {\n    if record.stdout.truncated {\n        return Err("stdout was truncated; fingerprint would cover incomplete output".into());\n    }\n    match mode {\n        "structured" => {\n            let obs = scirust_verify_numerics::parse_observations(&record.stdout_lossy())\n                .map_err(|e| format!("invalid structured fingerprint evidence: {e}"))?;\n            let mut pairs: Vec<(String, String)> = obs\n                .into_iter()\n                .filter_map(|o| match o {\n                    scirust_verify_numerics::ValidObservation::Fingerprint { name, value } => {\n                        Some((name, value))\n                    }\n                    _ => None,\n                })\n                .collect();\n            if pairs.is_empty() {\n                return Err("no structured fingerprint observation was emitted".into());\n            }\n            pairs.sort();\n            let mut canonical = String::new();\n            for (name, value) in pairs {\n                canonical.push_str(&format!("{name}={value}\\n"));\n            }\n            Ok(scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()).value)\n        }\n        _ => Ok(record.stdout_digest().value),\n    }\n}\n'''
if text.count(old) != 1:
    raise SystemExit("fingerprint_of source did not match")
start.write_text(text.replace(old, new, 1))

# 5) Timeouts terminate the whole Unix process group, not only the direct child.
replace_once(
    "crates/scirust-verify-runner/src/lib.rs",
    '''use std::process::{Command, Stdio};\n''',
    '''use std::process::{Command, Stdio};\n#[cfg(unix)]\nuse std::os::unix::process::CommandExt;\n''',
)
replace_once(
    "crates/scirust-verify-runner/src/lib.rs",
    '''    cmd.args(&spec.args)\n        .current_dir(&spec.cwd)\n        .stdin(Stdio::null())\n        .stdout(Stdio::piped())\n        .stderr(Stdio::piped());\n\n    // Apply environment policy: strip secrets/removed vars, then apply sets.\n''',
    '''    cmd.args(&spec.args)\n        .current_dir(&spec.cwd)\n        .stdin(Stdio::null())\n        .stdout(Stdio::piped())\n        .stderr(Stdio::piped());\n    #[cfg(unix)]\n    cmd.process_group(0);\n\n    // Apply environment policy: strip secrets/removed vars, then apply sets.\n''',
)
textp = Path("crates/scirust-verify-runner/src/lib.rs")
text = textp.read_text().replace('''                let _ = child.kill();\n                let _ = child.wait();\n''', '''                terminate_child_tree(&mut child);\n                let _ = child.wait();\n''', 1)
text = text.replace('''    if timed_out {\n        let _ = child.kill();\n        let _ = child.wait();\n    }\n''', '''    if timed_out {\n        terminate_child_tree(&mut child);\n        let _ = child.wait();\n    }\n''', 1)
needle = '''#[cfg(unix)]\nfn signal_number(status: std::process::ExitStatus) -> i32 {\n'''
helper = '''#[cfg(unix)]\nfn terminate_child_tree(child: &mut std::process::Child) {\n    // Every Unix child is placed in its own process group above. Killing the\n    // group closes inherited stdout/stderr pipes held by descendants, so the\n    // capture threads cannot outlive the verification deadline.\n    let group = format!("-{}", child.id());\n    let _ = Command::new("kill")\n        .args(["-KILL", "--", group.as_str()])\n        .stdin(Stdio::null())\n        .stdout(Stdio::null())\n        .stderr(Stdio::null())\n        .status();\n    let _ = child.kill();\n}\n\n#[cfg(not(unix))]\nfn terminate_child_tree(child: &mut std::process::Child) {\n    let _ = child.kill();\n}\n\n#[cfg(unix)]\nfn signal_number(status: std::process::ExitStatus) -> i32 {\n'''
if text.count(needle) != 1:
    raise SystemExit("runner helper insertion point not found")
textp.write_text(text.replace(needle, helper, 1))

# Runner regression: a descendant inheriting pipes must not defeat timeout.
p = Path("crates/scirust-verify-runner/tests/runner_tests.rs")
text = p.read_text()
anchor = '''#[test]\nfn large_stdout_is_bounded_and_flagged() {\n'''
test = '''#[cfg(unix)]\n#[test]\nfn timeout_kills_descendants_holding_capture_pipes() {\n    let cwd = tmpdir("timeout-descendants");\n    let spec = CommandSpec::new("sh", &cwd)\n        .args(["-c", "sleep 30 & wait"])\n        .timeout(Duration::from_millis(150));\n    let rec = execute(&spec).unwrap();\n    assert_eq!(rec.status, ExitStatus::TimedOut);\n    assert!(rec.duration_ns < Duration::from_secs(5).as_nanos() as u64);\n}\n\n#[test]\nfn large_stdout_is_bounded_and_flagged() {\n'''
if text.count(anchor) != 1:
    raise SystemExit("runner test insertion point not found")
p.write_text(text.replace(anchor, test, 1))

# E2E regressions for missing evidence, nested Git and Cargo argument ordering.
p = Path("crates/scirust-verify-cli/tests/e2e.rs")
text = p.read_text()
anchor = '''fn copy_dir(src: &Path, dst: &Path) {\n'''
regressions = r'''#[test]
fn numeric_exit_zero_without_observation_is_not_verified() {
    prebuild_fixtures();
    let project = tempfile_dir("numeric-missing-evidence");
    copy_dir(&fixture("numeric-pass"), &project);
    std::fs::write(project.join("src/main.rs"), "fn main() { println!(\"plain output only\"); }\n")
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
    std::fs::write(project.join("src/main.rs"), "fn main() { println!(\"plain output only\"); }\n")
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
    let body = std::fs::read_to_string(&manifest)
        .unwrap()
        .replace("source_clean = \"informational\"", "source_clean = \"required\"");
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
    std::fs::write(&manifest, body).unwrap();
    let out = cli()
        .args(["plan", project.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = doc["checks"].as_array().unwrap();
    let args_for = |id: &str| -> Vec<String> {
        let check = checks.iter().find(|c| c["id"] == id).unwrap();
        check["action"]["command"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let fmt = args_for("cargo:fmt");
    assert!(!fmt.iter().any(|a| a == "--target" || a == "--features"), "{fmt:?}");
    let clippy = args_for("cargo:clippy");
    let sep = clippy.iter().position(|a| a == "--").unwrap();
    let target = clippy.iter().position(|a| a == "--target").unwrap();
    let features = clippy.iter().position(|a| a == "--features").unwrap();
    assert!(target < sep && features < sep, "{clippy:?}");
}

fn copy_dir(src: &Path, dst: &Path) {
'''
if text.count(anchor) != 1:
    raise SystemExit("e2e insertion point not found")
p.write_text(text.replace(anchor, regressions, 1))

print("trust invariant fixes applied")
