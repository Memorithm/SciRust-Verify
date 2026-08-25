//! Built-in providers shipped with SciRust-Verify core.

use std::collections::BTreeMap;

use crate::planning::{
    Detection, ExecutionContext, PipelineFailure, PlanContext, ProviderError, VerificationProvider,
};
use scirust_verify_model::check::CheckAction;
use scirust_verify_model::{
    Check, CheckExecution, CheckId, ClaimId, CommandTemplate, DirtyState, EvidenceKind,
    EvidenceStatus, ExitExpectation, Observation, ObservedValue, RequirementLevel, Verdict,
};
use scirust_verify_runner::ExitStatus;

/// Reports the `source_clean` claim from discovery-time Git facts.
///
/// No process is spawned: cleanliness was already probed during discovery.
/// `clean` => Verified, `dirty` => Failed, `unknown` => Skipped. The claim
/// level (default informational) decides whether this gates anything.
pub struct SourceCleanProvider;

impl VerificationProvider for SourceCleanProvider {
    fn name(&self) -> &'static str {
        "core"
    }

    fn detect(&self, _ctx: &crate::discovery::DiscoveryContext) -> Detection {
        Detection::Detected {
            note: "built-in source hygiene probe".to_owned(),
        }
    }

    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError> {
        if !request.claim_levels.contains_key("source_clean") {
            return Ok(Vec::new());
        }
        Ok(vec![Check {
            id: CheckId::new("core:source-clean"),
            provider: Self::name(&Self).to_owned(),
            purpose: "Worktree has no uncommitted changes".into(),
            claims: vec![ClaimId::from("source_clean")],
            requirement: request
                .claim_levels
                .get("source_clean")
                .copied()
                .unwrap_or(RequirementLevel::Informational),
            action: CheckAction::Command {
                command: CommandTemplate {
                    program: String::new(),
                    args: vec![],
                    cwd: None,
                    env: Default::default(),
                },
                expect: Default::default(),
            },
            timeout: Duration::ZERO,
            stdout_limit_bytes: 1,
            stderr_limit_bytes: 1,
        }])
    }

    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, PipelineFailure> {
        let dirty = match env.project_root.join(".git").exists() {
            // Re-derive quickly; discovery result is not carried into execute.
            true => {
                let out = std::process::Command::new("git")
                    .args(["status", "--porcelain"])
                    .current_dir(env.project_root)
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        let n = String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .filter(|l| !l.trim().is_empty())
                            .count();
                        if n == 0 {
                            None::<u64>
                        } else {
                            Some(n as u64)
                        }
                    }
                    _ => None,
                }
            }
            false => None,
        };
        let git_present = std::process::Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .current_dir(env.project_root)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let ev_id = env.sink.next_id();
        let (status, outcome, summary): (scirust_verify_model::CheckStatus, Verdict, String) =
            if !git_present {
                (
                    scirust_verify_model::CheckStatus::Skipped {
                        reason: "not a Git worktree".into(),
                    },
                    Verdict::Skipped,
                    "Git unavailable; cleanliness unknown".to_owned(),
                )
            } else if dirty.unwrap_or(0) > 0 {
                (
                    scirust_verify_model::CheckStatus::Executed { exit_code: Some(0) },
                    Verdict::Failed,
                    format!("{} uncommitted change(s) present", dirty.unwrap_or(0)),
                )
            } else {
                (
                    scirust_verify_model::CheckStatus::Executed { exit_code: Some(0) },
                    Verdict::Verified,
                    "worktree clean".to_owned(),
                )
            };

        let evidence = scirust_verify_model::Evidence::builder(
            ev_id.clone(),
            EvidenceKind::GitProvenance,
            "core",
        )
        .artifact(env.artifact.clone())
        .scope(env.scope.clone())
        .status(if outcome == Verdict::Failed {
            EvidenceStatus::Failed
        } else if outcome == Verdict::Skipped {
            EvidenceStatus::Skipped
        } else {
            EvidenceStatus::Ok
        })
        .observation(Observation::new(
            "worktree_dirty",
            "git_status",
            ObservedValue::Bool(dirty.unwrap_or(0) > 0 || !git_present),
        ))
        .meta(
            "dirty_state",
            match (git_present, dirty.unwrap_or(0)) {
                (false, _) => DirtyState::Unknown,
                (_, 0) => DirtyState::Clean,
                (_, _) => DirtyState::Dirty,
            },
        )
        .build();
        env.sink.add_evidence(evidence, &BTreeMap::new())?;

        Ok(CheckExecution {
            check_id: check.id.clone(),
            started_at_utc: Some(chrono::Utc::now()),
            ended_at_utc: Some(chrono::Utc::now()),
            status,
            outcome,
            summary,
            observations: vec![],
            evidence_ids: vec![ev_id],
            notes: vec![],
        })
    }
}

use std::time::Duration;

/// Executes project-declared `[[custom_checks]]` commands.
pub struct CustomChecksProvider {
    /// Declared custom checks from the manifest.
    pub checks: Vec<crate::manifest::CustomCheck>,
}

impl VerificationProvider for CustomChecksProvider {
    fn name(&self) -> &'static str {
        "custom"
    }

    fn detect(&self, ctx: &crate::discovery::DiscoveryContext) -> Detection {
        if self.checks.is_empty() {
            Detection::NotDetected
        } else {
            Detection::Detected {
                note: format!("{} custom check(s) declared", self.checks.len()),
            }
        }
        .normalize(ctx)
    }

    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError> {
        let mut out = Vec::new();
        for c in &self.checks {
            let level = c
                .level
                .as_deref()
                .map(crate::manifest::parse_level)
                .transpose()
                .map_err(|e| ProviderError::InvalidContext {
                    provider: "custom",
                    reason: e,
                })?
                .unwrap_or(RequirementLevel::Required);
            let claim_kind = c.claim_kind.clone().unwrap_or_else(|| c.id.clone());
            let claim_id = format!("{claim_kind}@{}", c.id);
            out.push(Check {
                id: CheckId::new(format!("custom:{}", c.id)),
                provider: "custom".into(),
                purpose: format!("Custom check `{}`", c.id),
                claims: vec![ClaimId::from(claim_id)],
                requirement: level,
                action: CheckAction::Command {
                    command: CommandTemplate {
                        program: c.program.clone(),
                        args: c.args.clone(),
                        cwd: c.cwd.as_ref().map(std::path::PathBuf::from),
                        env: Default::default(),
                    },
                    expect: Default::default(),
                },
                timeout: Duration::from_secs(
                    c.timeout_secs
                        .unwrap_or_else(|| request.default_timeout.as_secs()),
                ),
                stdout_limit_bytes: request.stdout_limit,
                stderr_limit_bytes: request.stderr_limit,
            });
        }
        Ok(out)
    }

    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, PipelineFailure> {
        crate::planning::execute_command_check(check, env, "custom-provider")
    }
}

trait Normalize {
    fn normalize(self, ctx: &crate::discovery::DiscoveryContext) -> Detection;
}

impl Normalize for Detection {
    fn normalize(self, _ctx: &crate::discovery::DiscoveryContext) -> Detection {
        self
    }
}

pub(crate) fn interpret_exit(
    status: &ExitStatus,
    expect: scirust_verify_model::ExitExpectation,
    check: &Check,
) -> (scirust_verify_model::CheckStatus, Verdict, String) {
    match (status, expect) {
        (ExitStatus::TimedOut, _) => (
            scirust_verify_model::CheckStatus::TimedOut,
            Verdict::NotVerified,
            format!("timed out after {}ms", check.timeout.as_millis()),
        ),
        (ExitStatus::SpawnFailed { reason }, _) => (
            scirust_verify_model::CheckStatus::SpawnFailed {
                reason: reason.clone(),
            },
            Verdict::NotVerified,
            format!("could not spawn: {reason}"),
        ),
        (ExitStatus::Signal(sig), _) => (
            scirust_verify_model::CheckStatus::Executed { exit_code: None },
            Verdict::NotVerified,
            format!("terminated by signal {sig}"),
        ),
        (ExitStatus::Code(code), ExitExpectation::Success) => {
            if *code == 0 {
                (
                    scirust_verify_model::CheckStatus::Executed {
                        exit_code: Some(*code),
                    },
                    Verdict::Verified,
                    "command exited successfully".to_owned(),
                )
            } else {
                (
                    scirust_verify_model::CheckStatus::Executed {
                        exit_code: Some(*code),
                    },
                    Verdict::Failed,
                    format!("exit code {code} contradicts required success"),
                )
            }
        }
        (ExitStatus::Code(code), ExitExpectation::Ignore) => (
            scirust_verify_model::CheckStatus::Executed {
                exit_code: Some(*code),
            },
            Verdict::Verified,
            "informational capture (exit status ignored)".to_owned(),
        ),
    }
}

/// Executes `[[numeric_checks]]`: programs emitting SVOP v1 observations
/// whose numeric comparisons SciRust-Verify re-evaluates independently
/// against the configured tolerance.
pub struct NumericChecksProvider {
    /// Declared numeric SVOP checks from the manifest.
    pub checks: Vec<crate::manifest::NumericCheck>,
}

impl VerificationProvider for NumericChecksProvider {
    fn name(&self) -> &'static str {
        "numeric"
    }

    fn detect(&self, _ctx: &crate::discovery::DiscoveryContext) -> Detection {
        if self.checks.is_empty() {
            Detection::NotDetected
        } else {
            Detection::Detected {
                note: format!(
                    "{} numeric observation check(s) declared",
                    self.checks.len()
                ),
            }
        }
    }

    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError> {
        let mut out = Vec::new();
        for c in &self.checks {
            let level = c
                .level
                .as_deref()
                .map(crate::manifest::parse_level)
                .transpose()
                .map_err(|e| ProviderError::InvalidContext {
                    provider: "numeric",
                    reason: e,
                })?
                .unwrap_or(
                    request
                        .claim_levels
                        .get("numerically_close")
                        .copied()
                        .unwrap_or(RequirementLevel::Optional),
                );
            out.push(Check {
                id: CheckId::new(format!("numeric:{}", c.id)),
                provider: "numeric".into(),
                purpose: format!("SVOP numeric comparison `{}`", c.id),
                claims: vec![ClaimId::from(format!("oracle_equivalent@{}", c.id))],
                requirement: level,
                action: CheckAction::Command {
                    command: CommandTemplate {
                        program: c.program.clone(),
                        args: c.args.clone(),
                        cwd: c.cwd.as_ref().map(std::path::PathBuf::from),
                        env: Default::default(),
                    },
                    expect: ExitExpectation::Success,
                },
                timeout: Duration::from_secs(
                    c.timeout_secs
                        .unwrap_or_else(|| request.default_timeout.as_secs()),
                ),
                stdout_limit_bytes: request.stdout_limit,
                stderr_limit_bytes: request.stderr_limit,
            });
        }
        Ok(out)
    }

    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, PipelineFailure> {
        crate::planning::execute_command_check(check, env, "numeric-provider")
    }
}
