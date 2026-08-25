//! Generic Cargo verification provider.
//!
//! Works with any Cargo package or workspace — SciRust not required. Checks
//! are configured through the manifest `[cargo]` section; feature sets are
//! always explicit (`--features a,b`), never `--all-features`, because
//! feature combinations may be mutually exclusive.

#![deny(missing_docs)]

use std::collections::BTreeMap;

use scirust_verify_core::manifest::{CargoSection, DenyMode};
use scirust_verify_core::planning::{
    Detection, ExecutionContext, PlanContext, ProviderError, VerificationProvider,
};
use scirust_verify_model::check::CheckAction;
use scirust_verify_model::{
    Check, CheckExecution, CheckId, CheckStatus, ClaimId, CommandTemplate, EvidenceKind,
    EvidenceStatus, ExitExpectation, Observation, ObservedValue, RequirementLevel, Verdict,
};
use scirust_verify_numerics::parse_observations;
use scirust_verify_runner::{execute as run_command, which};

/// The cargo provider.
pub struct CargoProvider {
    section: CargoSection,
}

impl CargoProvider {
    /// Builds the provider from the manifest's `[cargo]` section.
    pub fn from_section(section: CargoSection) -> Self {
        Self { section }
    }

    fn command_check(
        &self,
        slug: &str,
        purpose: &str,
        args: Vec<String>,
        claims: &[&str],
        request: &PlanContext<'_>,
        level: RequirementLevel,
    ) -> Option<Check> {
        if !self.section.enabled {
            return None;
        }
        let Some(first_claim) = claims.first() else {
            return None;
        };
        if !request.claim_levels.contains_key(*first_claim) {
            // Claim disabled ("off") in the manifest.
            return None;
        }
        let claim_level = claims
            .iter()
            .filter_map(|c| request.claim_levels.get(*c))
            .copied()
            .max()
            .unwrap_or(level);
        Some(Check {
            id: CheckId::new(format!("cargo:{slug}")),
            provider: "cargo".into(),
            purpose: purpose.to_owned(),
            claims: claims.iter().map(|c| ClaimId::from(*c)).collect(),
            requirement: claim_level,
            action: CheckAction::Command {
                command: CommandTemplate {
                    program: "cargo".into(),
                    args,
                    cwd: None,
                    env: Default::default(),
                },
                expect: ExitExpectation::Success,
            },
            timeout: request.default_timeout,
            stdout_limit_bytes: request.stdout_limit,
            stderr_limit_bytes: request.stderr_limit,
        })
    }
}

impl VerificationProvider for CargoProvider {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn detect(&self, ctx: &scirust_verify_core::discovery::DiscoveryContext) -> Detection {
        match &ctx.kind {
            scirust_verify_core::discovery::ProjectKind::Cargo { .. } => Detection::Detected {
                note: "Cargo.toml found at project root".to_owned(),
            },
            _ => Detection::NotDetected,
        }
    }

    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError> {
        let mut checks = Vec::new();

        let target_args = |args: &mut Vec<String>| {
            for t in request.targets {
                args.push("--target".into());
                args.push(t.clone());
            }
            if !request.features.is_empty() {
                args.push("--features".into());
                args.push(request.features.join(","));
            }
        };

        // Dependency snapshot first (informational evidence).
        if self.section.enabled && request.claim_levels.contains_key("dependency_snapshot") {
            checks.push(Check {
                id: CheckId::new("cargo:metadata"),
                provider: "cargo".into(),
                purpose: "Record resolved dependency graph via cargo metadata".into(),
                claims: vec![ClaimId::from("dependency_snapshot")],
                requirement: RequirementLevel::Informational,
                action: CheckAction::Command {
                    command: CommandTemplate {
                        program: "cargo".into(),
                        args: vec!["metadata".into(), "--format-version".into(), "1".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                    expect: ExitExpectation::Ignore,
                },
                timeout: request.default_timeout,
                stdout_limit_bytes: 64 * 1024 * 1024,
                stderr_limit_bytes: request.stderr_limit,
            });
        }

        if self.section.fmt {
            let mut args = vec!["fmt".into(), "--all".into(), "--".into(), "--check".into()];
            target_args(&mut args);
            checks.extend(self.command_check(
                "fmt",
                "`cargo fmt --check`: source formatting is canonical",
                args,
                &["fmt_clean"],
                request,
                RequirementLevel::Recommended,
            ));
        }

        if self.section.clippy {
            let mut args = vec![
                "clippy".into(),
                "--workspace".into(),
                "--all-targets".into(),
                "--".into(),
                "-D".into(),
                "warnings".into(),
            ];
            target_args(&mut args);
            checks.extend(self.command_check(
                "clippy",
                "`cargo clippy -D warnings`: no lint warnings",
                args,
                &["lint_clean"],
                request,
                RequirementLevel::Recommended,
            ));
        }

        if self.section.check {
            let mut args = vec!["check".into(), "--workspace".into(), "--all-targets".into()];
            target_args(&mut args);
            checks.extend(self.command_check(
                "check",
                "`cargo check --workspace --all-targets`",
                args,
                &["builds"],
                request,
                RequirementLevel::Required,
            ));
        }

        if self.section.build {
            let mut args = vec!["build".into(), "--workspace".into()];
            target_args(&mut args);
            checks.extend(self.command_check(
                "build",
                "`cargo build --workspace`: everything compiles",
                args,
                &["builds"],
                request,
                RequirementLevel::Required,
            ));
        }

        if self.section.test {
            let mut args = vec!["test".into(), "--workspace".into(), "--no-fail-fast".into()];
            target_args(&mut args);
            checks.extend(self.command_check(
                "test",
                "`cargo test --workspace`: oracle tests pass",
                args,
                &["tests_pass"],
                request,
                RequirementLevel::Required,
            ));
        }

        if self.section.doc {
            let mut args = vec!["doc".into(), "--workspace".into(), "--no-deps".into()];
            target_args(&mut args);
            checks.extend(self.command_check(
                "doc",
                "`cargo doc`: public API documents cleanly",
                args,
                &["docs_build"],
                request,
                RequirementLevel::Optional,
            ));
        }

        if self.section.deny != DenyMode::Off
            && request
                .claim_levels
                .contains_key("dependency_policy_passes")
        {
            checks.push(Check {
                id: CheckId::new("cargo:deny"),
                provider: "cargo".into(),
                purpose: "`cargo deny check`: licenses and advisories clean".into(),
                claims: vec![ClaimId::from("dependency_policy_passes")],
                requirement: match self.section.deny {
                    DenyMode::Required => RequirementLevel::Required,
                    _ => RequirementLevel::Optional,
                },
                action: CheckAction::Command {
                    command: CommandTemplate {
                        program: "cargo".into(),
                        args: vec!["deny".into(), "check".into()],
                        cwd: None,
                        env: Default::default(),
                    },
                    expect: ExitExpectation::Success,
                },
                timeout: request.default_timeout,
                stdout_limit_bytes: request.stdout_limit,
                stderr_limit_bytes: request.stderr_limit,
            });
        }

        Ok(checks)
    }

    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, scirust_verify_core::planning::PipelineFailure> {
        let CheckAction::Command { command, expect } = &check.action else {
            return Ok(CheckExecution::minimal(
                check.id.clone(),
                CheckStatus::Unsupported {
                    reason: "cargo provider only executes command checks".into(),
                },
            ));
        };

        // Availability probes produce honest SKIPPED evidence.
        let availability: Option<(&str, &str)> = match command.program.as_str() {
            "cargo" if check.id.as_str() == "cargo:fmt" => {
                if which("rustfmt").is_none() {
                    Some(("rustfmt", "rustfmt component is not installed"))
                } else {
                    None
                }
            }
            "cargo" if check.id.as_str() == "cargo:clippy" => {
                if which("clippy-driver").is_none() {
                    Some(("clippy-driver", "clippy component is not installed"))
                } else {
                    None
                }
            }
            "cargo" if check.id.as_str() == "cargo:deny" => {
                if which("cargo-deny").is_none() {
                    Some(("cargo-deny", "cargo-deny was not installed"))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some((_tool, reason)) = availability {
            let status = CheckStatus::Skipped {
                reason: reason.to_owned(),
            };
            return Ok(CheckExecution {
                outcome: status.base_verdict(),
                summary: format!("{reason}; check skipped"),
                ..CheckExecution::minimal(check.id.clone(), status)
            });
        }

        let cwd = env.resolve_cwd(command.cwd.as_deref());
        let spec = scirust_verify_runner::CommandSpec::new(command.program.clone(), cwd)
            .args(command.args.iter().cloned())
            .timeout(check.timeout)
            .env("TERM", "dumb");
        // Apply explicit template env vars.
        let spec = {
            let mut s = spec;
            for (k, v) in &command.env {
                s = s.env(k, v);
            }
            s.stdout_limit = check.stdout_limit_bytes.max(1);
            s.stderr_limit = check.stderr_limit_bytes.max(1);
            s
        };

        let started = chrono::Utc::now();
        let record = run_command(&spec)?;
        let ended = chrono::Utc::now();

        // Persist raw output as content-addressed attachments.
        let stdout_path = format!("logs/{}.out.log", check.id.as_str().replace(':', "-"));
        let stderr_path = format!("logs/{}.err.log", check.id.as_str().replace(':', "-"));
        let mut payloads = BTreeMap::new();
        payloads.insert(stdout_path.clone(), record.stdout.data.clone());
        payloads.insert(stderr_path.clone(), record.stderr.data.clone());

        let ev_id = env.sink.next_id();
        let evidence = scirust_verify_model::Evidence::builder(
            ev_id.clone(),
            EvidenceKind::CommandExecution,
            "cargo-provider",
        )
        .artifact(env.artifact.clone())
        .scope(env.scope.clone())
        .status(if record.timed_out() {
            EvidenceStatus::TimedOut
        } else if record.succeeded() {
            EvidenceStatus::Ok
        } else {
            EvidenceStatus::Failed
        })
        .observation(Observation::new(
            "exit_status",
            check.id.as_str(),
            ObservedValue::Int(record.exit_code().unwrap_or(-1) as i64),
        ))
        .observation(
            Observation::new(
                "duration",
                check.id.as_str(),
                ObservedValue::DurationNs(record.duration_ns),
            )
            .with_unit("ns"),
        )
        .output(scirust_verify_model::Digest::sha256_hex(
            &record.stdout.data,
        ))
        .output(scirust_verify_model::Digest::sha256_hex(
            &record.stderr.data,
        ))
        .attachment(scirust_verify_model::Attachment {
            path: stdout_path,
            size_bytes: record.stdout.data.len() as u64,
            digest: scirust_verify_model::Digest::sha256_hex(&record.stdout.data),
            media_type: Some("text/plain; charset=utf-8".into()),
        })
        .attachment(scirust_verify_model::Attachment {
            path: stderr_path,
            size_bytes: record.stderr.data.len() as u64,
            digest: scirust_verify_model::Digest::sha256_hex(&record.stderr.data),
            media_type: Some("text/plain; charset=utf-8".into()),
        })
        .meta("timeout_ms", record.timeout_ms)
        .build();
        env.sink.add_evidence(evidence, &payloads)?;

        // Structured observations from SVOP lines (numeric/fingerprint data).
        let svop: Option<Vec<_>> = parse_observations(&record.stdout_lossy()).ok();
        let mut observations: Vec<Observation> = svop
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|o| o.to_model_observation())
            .collect();

        let (status, outcome, summary): (CheckStatus, Verdict, String) =
            match (&record.status, expect) {
                (scirust_verify_runner::ExitStatus::TimedOut, _) => (
                    CheckStatus::TimedOut,
                    Verdict::NotVerified,
                    format!("timed out after {}ms", check.timeout.as_millis()),
                ),
                (scirust_verify_runner::ExitStatus::SpawnFailed { reason }, _) => (
                    CheckStatus::SpawnFailed {
                        reason: reason.clone(),
                    },
                    Verdict::NotVerified,
                    format!("could not spawn `{}`: {reason}", command.program),
                ),
                (scirust_verify_runner::ExitStatus::Code(code), ExitExpectation::Success) => {
                    if *code == 0 {
                        (
                            CheckStatus::Executed {
                                exit_code: Some(*code),
                            },
                            Verdict::Verified,
                            "command exited successfully".to_owned(),
                        )
                    } else {
                        let tail: String = record
                            .stderr_lossy()
                            .lines()
                            .last()
                            .unwrap_or("")
                            .chars()
                            .take(200)
                            .collect();
                        (
                            CheckStatus::Executed {
                                exit_code: Some(*code),
                            },
                            Verdict::Failed,
                            format!(
                                "exit code {code}{}",
                                if tail.is_empty() {
                                    String::new()
                                } else {
                                    format!("; last stderr: {tail}")
                                }
                            ),
                        )
                    }
                }
                (scirust_verify_runner::ExitStatus::Code(code), ExitExpectation::Ignore) => (
                    CheckStatus::Executed {
                        exit_code: Some(*code),
                    },
                    Verdict::Verified,
                    "informational capture (exit status ignored)".to_owned(),
                ),
                (scirust_verify_runner::ExitStatus::Signal(sig), _) => (
                    CheckStatus::Executed { exit_code: None },
                    Verdict::NotVerified,
                    format!("terminated by signal {sig}"),
                ),
            };

        // Attach SVOP observation count.
        observations.push(Observation::new(
            "structured_observation_count",
            check.id.as_str(),
            ObservedValue::UInt(svop.map(|v| v.len()).unwrap_or(0) as u64),
        ));

        Ok(CheckExecution {
            check_id: check.id.clone(),
            started_at_utc: Some(started),
            ended_at_utc: Some(ended),
            status,
            outcome,
            summary,
            observations,
            evidence_ids: vec![ev_id],
            notes: Vec::new(),
        })
    }
}
