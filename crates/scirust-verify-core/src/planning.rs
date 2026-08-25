//! Provider architecture: detection, planning and execution interfaces.
//!
//! V0.1 uses statically compiled providers only. The traits below keep the
//! door open for future remote/sandboxed runners without redesigning the
//! domain model.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use scirust_verify_model::{
    ArtifactId, Check, CheckExecution, Evidence, EvidenceId, VerificationScope,
};
use scirust_verify_model::{
    CheckAction, EvidenceKind, EvidenceStatus, Observation, ObservedValue, Verdict,
};
use scirust_verify_runner::execute as run_command;
use thiserror::Error;

use crate::discovery::DiscoveryContext;

/// Errors providers may surface.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// The provider cannot plan/execute in the current context.
    #[error("provider `{provider}`: {reason}")]
    InvalidContext {
        /// Provider name.
        provider: &'static str,
        /// What is wrong.
        reason: String,
    },
}

/// Detection result reported by a provider.
#[derive(Debug, Clone, PartialEq)]
pub enum Detection {
    /// Provider applies to this project.
    Detected {
        /// Human-readable justification recorded in inspect output.
        note: String,
    },
    /// Provider does not apply.
    NotDetected,
}

/// Context for planning: discovery facts plus effective manifest settings.
pub struct PlanContext<'a> {
    /// Discovery results.
    pub ctx: &'a DiscoveryContext,
    /// Artifact id claims will attach to.
    pub artifact_id: ArtifactId,
    /// Effective claim requirement levels (slug => level), after profile
    /// precedence resolution.
    pub claim_levels: &'a BTreeMap<String, scirust_verify_model::RequirementLevel>,
    /// Default timeout applied when a check does not override it.
    pub default_timeout: std::time::Duration,
    /// Stdout capture limit in bytes.
    pub stdout_limit: u64,
    /// Stderr capture limit in bytes.
    pub stderr_limit: u64,
    /// Extra targets requested by configuration.
    pub targets: &'a [String],
    /// Explicit features requested by configuration.
    pub features: &'a [String],
}

/// Sink receiving evidence produced during execution.
///
/// Implementations persist evidence into the run store. Evidence ids are
/// sequential (`ev-0001`, ...) assigned in execution order; providers obtain
/// them up front via [`CheckSink::next_id`] so every evidence object is born
/// with its final identity.
pub trait CheckSink {
    /// Returns the next sequential evidence id.
    fn next_id(&mut self) -> EvidenceId;

    /// Persists one evidence object with its attachment payloads.
    fn add_evidence(
        &mut self,
        evidence: Evidence,
        attachments: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), PipelineFailure>;
}

/// Failures that can abort (or degrade) pipeline execution.
#[derive(Debug, Error)]
pub enum PipelineFailure {
    /// A provider could not proceed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Persisting evidence failed.
    #[error("evidence persistence failed: {0}")]
    Store(#[from] scirust_verify_store::StoreError),
    /// Command infrastructure failure (not a scientific failure).
    #[error("runner failure: {0}")]
    Runner(#[from] scirust_verify_runner::RunnerError),
}

/// Execution services handed to `VerificationProvider::execute`.
pub struct ExecutionContext<'a> {
    /// Project root (absolute).
    pub project_root: &'a Path,
    /// Subject artifact id.
    pub artifact: ArtifactId,
    /// Scope under which checks execute (host/toolchain snapshot).
    pub scope: VerificationScope,
    /// Evidence sink wired to the run store.
    pub sink: &'a mut dyn CheckSink,
    /// Working-directory helper resolving relative cwds against the root.
    pub cwd_base: PathBuf,
}

impl<'a> ExecutionContext<'a> {
    /// Resolves a possibly-relative cwd to an absolute directory.
    pub fn resolve_cwd(&self, cwd: Option<&Path>) -> PathBuf {
        match cwd {
            Some(p) if p.is_absolute() => p.to_path_buf(),
            Some(p) => self.cwd_base.join(p),
            None => self.cwd_base.to_path_buf(),
        }
    }
}

/// A verification provider.
pub trait VerificationProvider {
    /// Stable provider name used in check ids (`<provider>:...`).
    fn name(&self) -> &'static str;

    /// Does this provider apply to the discovered project?
    fn detect(&self, ctx: &DiscoveryContext) -> Detection;

    /// Plans the checks this provider would execute. Must be deterministic:
    /// identical inputs produce identically ordered plans.
    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError>;

    /// Executes one previously planned check, producing observations and
    /// evidence through the sink.
    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, PipelineFailure>;
}

/// Shared execution of a plain command check (used by custom + numeric).
pub fn execute_command_check(
    check: &Check,
    env: &mut ExecutionContext<'_>,
    producer: &'static str,
) -> Result<CheckExecution, PipelineFailure> {
    let CheckAction::Command { command, expect } = &check.action else {
        return Ok(CheckExecution::minimal(
            check.id.clone(),
            scirust_verify_model::CheckStatus::Unsupported {
                reason: "provider only executes command checks".into(),
            },
        ));
    };
    let cwd = env.resolve_cwd(command.cwd.as_deref());
    let mut spec = scirust_verify_runner::CommandSpec::new(command.program.clone(), cwd)
        .args(command.args.iter().cloned())
        .timeout(check.timeout);
    spec.stdout_limit = check.stdout_limit_bytes.max(1);
    spec.stderr_limit = check.stderr_limit_bytes.max(1);
    for (k, v) in &command.env {
        spec = spec.env(k, v);
    }

    let started = chrono::Utc::now();
    let record = run_command(&spec)?;
    let ended = chrono::Utc::now();

    let stdout_path = format!("logs/{}.out.log", check.id.as_str().replace(':', "-"));
    let stderr_path = format!("logs/{}.err.log", check.id.as_str().replace(':', "-"));
    let mut payloads = BTreeMap::new();
    payloads.insert(stdout_path.clone(), record.stdout.data.clone());
    payloads.insert(stderr_path.clone(), record.stderr.data.clone());

    // Structured observations (SVOP) are evidence, not decoration.
    // Numeric checks require at least one valid numeric comparison and must
    // never turn parse failures, missing observations or truncated stdout
    // into a successful claim. Parsed facts are attached to the evidence
    // object itself, not just to the execution record.
    let svop_result = scirust_verify_numerics::parse_observations(&record.stdout_lossy());
    let svop = svop_result.as_ref().ok();
    let svop_observations: Vec<Observation> = svop
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .map(|o| o.to_model_observation())
        .collect();

    let ev_id = env.sink.next_id();
    let evidence = scirust_verify_model::Evidence::builder(
        ev_id.clone(),
        EvidenceKind::CommandExecution,
        producer,
    )
    .observations(svop_observations.iter().cloned())
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
    .observations([
        Observation::new(
            "stdout_captured",
            check.id.as_str(),
            ObservedValue::Bytes(record.stdout.data.len() as u64),
        ),
        Observation::new(
            "stdout_truncated",
            check.id.as_str(),
            ObservedValue::Bool(record.stdout.truncated),
        ),
        Observation::new(
            "stdout_total_bytes",
            check.id.as_str(),
            ObservedValue::Bytes(record.stdout.total_bytes),
        ),
        Observation::new(
            "stderr_truncated",
            check.id.as_str(),
            ObservedValue::Bool(record.stderr.truncated),
        ),
        Observation::new(
            "duration",
            check.id.as_str(),
            ObservedValue::DurationNs(record.duration_ns),
        )
        .with_unit("ns"),
    ])
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

    let mut structured_evidence_problem = None;
    if producer == "numeric-provider" {
        if record.stdout.truncated {
            structured_evidence_problem = Some(
                "numeric stdout was truncated; complete structured evidence was not captured"
                    .to_owned(),
            );
        } else {
            match &svop_result {
                Err(err) => {
                    structured_evidence_problem =
                        Some(format!("invalid structured numeric evidence: {err}"));
                }
                Ok(obs)
                    if !obs.iter().any(|o| {
                        matches!(
                            o,
                            scirust_verify_numerics::ValidObservation::NumericComparison { .. }
                        )
                    }) =>
                {
                    structured_evidence_problem = Some(
                        "numeric check emitted no valid numeric_comparison observation".to_owned(),
                    );
                }
                Ok(_) => {}
            }
        }
    }

    let mut observations: Vec<Observation> = svop_observations.clone();
    // Numeric re-evaluation against the scope tolerance — SciRust-Verify
    // never trusts the program's own comparison verdict.
    let tolerance = env.scope.tolerance.unwrap_or_default();
    let mut numeric_fail = false;
    if let Some(obs) = svop {
        for o in obs {
            if let scirust_verify_numerics::ValidObservation::NumericComparison {
                name,
                expected,
                observed,
                ..
            } = o
            {
                let cmp = scirust_verify_numerics::compare(*expected, *observed, &tolerance);
                observations.push(Observation::new(
                    "numeric_verdict",
                    name,
                    ObservedValue::Bool(cmp.pass),
                ));
                // Non-finite errors (NaN pairs, mixed infinities) render as
                // canonical strings so persisted JSON stays round-trippable.
                let abs_error_value = match cmp.abs_error {
                    Some(err) if err.is_finite() => ObservedValue::Float(err),
                    Some(err) => ObservedValue::Text(
                        scirust_verify_numerics::json_f64(err)
                            .as_str()
                            .unwrap_or("NaN")
                            .to_owned(),
                    ),
                    None => ObservedValue::Text("undefined".to_owned()),
                };
                observations.push(Observation::new("max_abs_error", name, abs_error_value));
                if !cmp.pass {
                    numeric_fail = true;
                }
            }
            if let scirust_verify_numerics::ValidObservation::Property { name, holds, .. } = o {
                if !holds {
                    numeric_fail = true;
                    observations.push(Observation::new(
                        "property_failed",
                        name,
                        ObservedValue::Bool(false),
                    ));
                }
            }
        }
    }

    let (status, mut outcome, mut summary) =
        crate::providers::interpret_exit(&record.status, *expect, check);
    if let Some(problem) = structured_evidence_problem {
        if outcome == Verdict::Verified {
            outcome = Verdict::NotVerified;
            summary = problem;
        }
    } else if numeric_fail && outcome == Verdict::Verified {
        outcome = Verdict::Failed;
        summary = "one or more numeric/property observations contradicted the requirement".into();
    }

    Ok(CheckExecution {
        check_id: check.id.clone(),
        started_at_utc: Some(started),
        ended_at_utc: Some(ended),
        status,
        outcome,
        summary,
        observations,
        evidence_ids: vec![ev_id],
        notes: vec![],
    })
}

/// Ordered set of active providers.
pub struct ProviderRegistry {
    providers: Vec<Box<dyn VerificationProvider>>,
}

impl ProviderRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Registers a provider (order matters only for reporting).
    pub fn register(&mut self, provider: Box<dyn VerificationProvider>) {
        self.providers.push(provider);
    }

    /// All registered providers.
    pub fn providers(&self) -> &[Box<dyn VerificationProvider>] {
        &self.providers
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}
