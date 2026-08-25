//! End-to-end verification pipeline used by the CLI.
//!
//! Flow:
//! `discover → manifest → effective settings → provenance/environment →
//! plan → create run → execute checks sequentially → collect evidence →
//! evaluate claims → gate → reports → validate & seal dossier`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use scirust_verify_model::provenance::ProvenanceDocument;
use scirust_verify_model::{
    canonical_json, Artifact, ArtifactId, ArtifactKind, Check, Claim, ClaimKind, Digest,
    DossierVerdict, RequirementLevel, RunId, VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_policy::Profile;
use scirust_verify_store::{RunState, RunsRoot, StoreError};
use thiserror::Error;

use crate::discovery::DiscoveryContext;
use crate::manifest::Manifest;
use crate::planning::{CheckSink, ExecutionContext, PipelineFailure, ProviderRegistry};
use crate::verdict_engine::{evaluate_claims, ClaimGateInputs};

/// Options controlling a verification run.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Project directory to verify.
    pub project_root: PathBuf,
    /// Where `.scirust-verify/` lives (defaults to the project root).
    pub output_root: Option<PathBuf>,
    /// `--profile` override.
    pub cli_profile: Option<String>,
    /// Target triple override.
    pub target: Option<String>,
    /// Strict mode: skipped required checks escalate to NotVerified.
    pub strict: bool,
}

impl VerifyOptions {
    /// Options for verifying `root` with defaults everywhere else.
    pub fn for_root(root: impl Into<PathBuf>) -> Self {
        Self {
            project_root: root.into(),
            output_root: None,
            cli_profile: None,
            target: None,
            strict: false,
        }
    }
}

/// Pipeline failures that are *not* scientific results.
#[derive(Debug, Error)]
pub enum PipelineError {
    /// Discovery failed.
    #[error(transparent)]
    Discovery(#[from] crate::discovery::DiscoveryError),
    /// Manifest invalid or unreadable.
    #[error(transparent)]
    Manifest(#[from] crate::manifest::ManifestError),
    /// Provider/planning failure.
    #[error(transparent)]
    Provider(#[from] PipelineFailure),
    /// Storage failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Report generation failure.
    #[error("report generation failed: {0}")]
    Report(String),
    /// Filesystem failure outside the store.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result summary returned to the CLI.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    /// Created run id.
    pub run_id: RunId,
    /// Final dossier verdict after the policy gate.
    pub verdict: DossierVerdict,
    /// Per-claim verdict labels for CLI display.
    pub claim_lines: Vec<(String, RequirementLevel, String)>,
    /// Path of `report.json`.
    pub report_json: PathBuf,
    /// Path of `report.md`.
    pub report_md: PathBuf,
}

/// Effective settings after precedence resolution (used by providers).
#[derive(Debug, Clone)]
pub struct EffectiveSettings {
    /// Resolved policy profile.
    pub profile: Profile,
    /// Default check timeout.
    pub timeout: Duration,
    /// Stdout capture limit in bytes.
    pub stdout_limit: u64,
    /// Stderr capture limit in bytes.
    pub stderr_limit: u64,
    /// Resolved claim requirement levels (slug => level).
    pub claim_levels: BTreeMap<String, RequirementLevel>,
}

const DEFAULT_TIMEOUT_SECS: u64 = 600;
const DEFAULT_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;

fn default_claim_levels() -> BTreeMap<String, RequirementLevel> {
    use RequirementLevel::*;
    BTreeMap::from([
        ("builds".to_owned(), Required),
        ("tests_pass".to_owned(), Required),
        ("lint_clean".to_owned(), Recommended),
        ("fmt_clean".to_owned(), Recommended),
        ("docs_build".to_owned(), Optional),
        ("dependency_policy_passes".to_owned(), Optional),
        ("deterministic".to_owned(), Optional),
        ("cross_process_deterministic".to_owned(), Optional),
        ("thread_invariant".to_owned(), Optional),
        ("numerically_close".to_owned(), Optional),
        ("source_clean".to_owned(), Informational),
        ("reproducible".to_owned(), Optional),
    ])
}

pub(crate) fn resolve_settings(
    manifest: &Manifest,
    opts: &VerifyOptions,
) -> Result<EffectiveSettings, PipelineError> {
    // defaults < profile < manifest < CLI
    let mut levels = default_claim_levels();

    let manifest_profile = opts
        .cli_profile
        .clone()
        .or_else(|| manifest.verification.profile.clone());
    let profile = match &manifest_profile {
        Some(name) => Profile::parse(name).map_err(|e| PipelineError::Report(e.to_string()))?,
        None => Profile::Basic,
    };
    for (slug, level) in profile.level_overrides() {
        if let Some(level) = level {
            levels.insert(slug, level);
        }
    }
    for (slug, level_str) in &manifest.claims {
        if level_str == "off" {
            levels.remove(slug);
            continue;
        }
        let level = crate::manifest::parse_level(level_str)
            .map_err(|_| PipelineError::Report(format!("claim `{slug}` has invalid level")))?;
        levels.insert(slug.clone(), level);
    }

    Ok(EffectiveSettings {
        profile,
        timeout: Duration::from_secs(
            manifest
                .verification
                .timeout_secs
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .max(1),
        ),
        stdout_limit: manifest
            .verification
            .stdout_max_bytes
            .unwrap_or(DEFAULT_CAPTURE_BYTES)
            .max(1),
        stderr_limit: manifest
            .verification
            .stderr_max_bytes
            .unwrap_or(DEFAULT_CAPTURE_BYTES)
            .max(1),
        claim_levels: levels,
    })
}

/// Everything `plan` and `verify` share: discovery, settings, providers'
/// checks, claims, plan digest.
pub struct Prepared {
    /// Discovery results.
    pub ctx: DiscoveryContext,
    /// Loaded (or default) manifest.
    pub manifest: Manifest,
    /// Effective settings after precedence resolution.
    pub settings: EffectiveSettings,
    /// Deterministic check list (sorted by id).
    pub checks: Vec<Check>,
    /// Claims derived from check links.
    pub claims: Vec<Claim>,
    /// Map from check id to claim ids.
    pub check_claims: BTreeMap<String, Vec<String>>,
    /// Providers that detected the project.
    pub detected_notes: Vec<(String, String)>,
    /// Artifact id used for claims.
    pub artifact_id: ArtifactId,
    /// SHA-256 over canonical JSON of `checks`.
    pub plan_digest: Digest,
    /// Environment snapshot captured at prepare time.
    pub env_snapshot: scirust_verify_model::EnvironmentSnapshot,
}

/// Discovery + manifest + planning without any execution.
pub fn prepare(
    registry: &ProviderRegistry,
    opts: &VerifyOptions,
) -> Result<Prepared, PipelineError> {
    // 1. Discovery.
    let ctx = DiscoveryContext::discover(&opts.project_root)?;

    // 2. Manifest (explicit file required only when present; defaults otherwise).
    let manifest_path = ctx.project_root.join(crate::manifest::MANIFEST_FILE);
    let manifest = if manifest_path.is_file() {
        Some(Manifest::load(&manifest_path)?)
    } else {
        None
    };
    let empty_manifest = Manifest::default();
    let manifest_ref = manifest.as_ref().unwrap_or(&empty_manifest);

    let mut settings = resolve_settings(manifest_ref, opts)?;

    // 3. Provenance collection (environment snapshot happens in prepare()).
    let provenance_doc = crate::provenance::collect_provenance(&ctx.project_root);
    let _ = &provenance_doc;

    // 4. Plan.
    let artifact_id = ArtifactId::new(manifest_ref.artifact.name.clone().unwrap_or_else(|| {
        match &ctx.kind {
            crate::discovery::ProjectKind::Cargo { packages, .. } => packages
                .first()
                .cloned()
                .unwrap_or_else(|| "project".to_owned()),
            _ => "project".to_owned(),
        }
    }));

    let plan_ctx = crate::planning::PlanContext {
        ctx: &ctx,
        artifact_id: artifact_id.clone(),
        claim_levels: &settings.claim_levels,
        default_timeout: settings.timeout,
        stdout_limit: settings.stdout_limit,
        stderr_limit: settings.stderr_limit,
        targets: &manifest_ref.verification.targets,
        features: &manifest_ref.verification.features,
    };

    let mut checks = Vec::new();
    let mut detected_notes: Vec<(String, String)> = Vec::new();
    for provider in registry.providers() {
        match provider.detect(&ctx) {
            crate::planning::Detection::Detected { note } => {
                detected_notes.push((provider.name().to_owned(), note));
                checks.extend(
                    provider
                        .plan(&plan_ctx)
                        .map_err(PipelineFailure::Provider)?,
                );
            }
            crate::planning::Detection::NotDetected => {}
        }
    }

    // Claims derive from check->claim links plus configured levels.
    let mut claims: Vec<Claim> = Vec::new();
    let mut check_claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for check in &checks {
        let linked: Vec<String> = check.claims.iter().map(|c| c.as_str().to_owned()).collect();
        check_claims.insert(check.id.as_str().to_owned(), linked);
        for claim_id in &check.claims {
            if !claims.iter().any(|c| &c.id == claim_id) {
                let slug = claim_id.as_str();
                let kind = match slug.split_once('@') {
                    Some((base, _instance)) => ClaimKind::Custom {
                        id: base.to_owned(),
                    },
                    None => ClaimKind::from_slug(slug),
                };
                let level = settings
                    .claim_levels
                    .get(slug)
                    .copied()
                    .unwrap_or(check.requirement);
                settings
                    .claim_levels
                    .entry(slug.to_owned())
                    .or_insert(level);
                let statement = format!("`{}` holds for `{artifact_id}`", kind.slug());
                claims.push(Claim {
                    id: claim_id.clone(),
                    kind,
                    subject: artifact_id.clone(),
                    requirement: level,
                    statement,
                    parameters: Default::default(),
                });
            }
        }
    }

    // Deterministic plan order + digest over the canonical form.
    let mut checks = checks;
    checks.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let plan_canonical = canonical_json(&checks)
        .map_err(|e| PipelineError::Report(format!("canonicalization failed: {e}")))?;
    let plan_digest = Digest::sha256_hex(plan_canonical.as_bytes());

    // Provenance/environment snapshot for scope records.
    let env_snapshot = {
        let mut snap =
            crate::provenance::collect_environment(&ctx.project_root, opts.target.as_deref());
        snap.toolchain.target_triple = opts
            .target
            .clone()
            .or_else(|| snap.toolchain.host_triple.clone());
        crate::provenance::record_rustflags(&mut snap);
        snap
    };

    Ok(Prepared {
        ctx,
        manifest: manifest_ref.clone(),
        settings,
        checks,
        claims,
        check_claims,
        detected_notes,
        artifact_id,
        plan_digest,
        env_snapshot,
    })
}

/// Runs the full pipeline. See module docs.
pub fn run_verify(
    registry: &ProviderRegistry,
    opts: &VerifyOptions,
) -> Result<VerifyOutcome, PipelineError> {
    let prepared = prepare(registry, opts)?;
    let Prepared {
        ctx,
        manifest: manifest_ref,
        settings,
        checks,
        claims,
        check_claims,
        detected_notes,
        artifact_id,
        plan_digest,
        env_snapshot,
    } = prepared;

    // 5. Create run and persist pre-execution documents.
    let runs_root_dir = opts
        .output_root
        .clone()
        .unwrap_or_else(|| ctx.project_root.join(".scirust-verify"));
    let runs_root = RunsRoot::new(runs_root_dir.join("runs"));
    let store = runs_root.create_run()?;

    // Source-tree digest when Git identity is unavailable (honest fallback).
    let mut source = ctx.source.clone();
    if source.commit.is_none() && source.tree_digest.is_none() {
        source.tree_digest = Some(crate::tree_digest::tree_digest(&ctx.project_root)?);
    }
    let mut provenance_final = crate::provenance::collect_provenance(&ctx.project_root);
    if provenance_final.git.is_none() {
        provenance_final.tree_digest = source.tree_digest.clone();
    }

    store.write_artifact(&Artifact {
        id: artifact_id.clone(),
        kind: artifact_kind_of(&ctx.kind),
        name: artifact_id.as_str().to_owned(),
        version: None,
        path: ctx.project_root.clone(),
        source,
        content_digest: None,
    })?;
    store.write_environment(&env_snapshot)?;
    store.write_provenance(&ProvenanceDocument {
        schema_version: SCHEMA_VERSION,
        git: provenance_final.git,
        tree_digest: provenance_final.tree_digest,
        probes: provenance_final.probes,
    })?;
    store.write_plan(&checks, plan_digest)?;
    store.write_claims(&claims)?;
    store.set_state(RunState::Running)?;

    // 6. Execute checks sequentially with a sink bound to the store.
    let mut counter = 0usize;
    let mut executions = Vec::new();

    {
        let mut scope = VerificationScope {
            recorded_at_utc: Some(chrono::Utc::now()),
            execution_mode: Some("subprocess".to_owned()),
            ..Default::default()
        };
        scope.host = env_snapshot.host.clone();
        scope.toolchain = env_snapshot.toolchain.clone();
        scope.features = manifest_ref.verification.features.clone();
        scope.target_triple = opts
            .target
            .clone()
            .or_else(|| env_snapshot.toolchain.host_triple.clone());

        for check in &checks {
            let provider = registry
                .providers()
                .iter()
                .find(|p| p.name() == check.provider)
                .expect("provider present in registry");
            let mut exec_env = ExecutionContext {
                project_root: &ctx.project_root,
                artifact: artifact_id.clone(),
                scope: scope.clone(),
                sink: &mut StoreSink {
                    store: &store,
                    counter: &mut counter,
                },
                cwd_base: ctx.project_root.clone(),
            };
            match provider.execute(check, &mut exec_env) {
                Ok(execution) => executions.push(execution),
                Err(PipelineFailure::Provider(err)) => {
                    executions.push(scirust_verify_model::CheckExecution {
                        check_id: check.id.clone(),
                        started_at_utc: None,
                        ended_at_utc: Some(chrono::Utc::now()),
                        status: scirust_verify_model::CheckStatus::Unsupported {
                            reason: err.to_string(),
                        },
                        outcome: scirust_verify_model::Verdict::Unsupported,
                        summary: err.to_string(),
                        observations: vec![],
                        evidence_ids: vec![],
                        notes: vec![],
                    });
                }
                Err(other) => {
                    best_effort_abort(&store);
                    return Err(PipelineError::Provider(other));
                }
            }
        }
    }

    for execution in &executions {
        store.append_execution(execution.clone())?;
    }

    // 7. Evaluate claims and compute the gate.
    let claim_pairs: Vec<(Claim, RequirementLevel)> = claims
        .iter()
        .map(|c| {
            (
                c.clone(),
                settings
                    .claim_levels
                    .get(c.id.as_str())
                    .copied()
                    .unwrap_or(c.requirement),
            )
        })
        .collect();

    let inputs = ClaimGateInputs {
        claims: &claim_pairs,
        executions: &executions,
        check_claims: &check_claims,
        scope: VerificationScope {
            recorded_at_utc: Some(chrono::Utc::now()),
            execution_mode: Some("subprocess".to_owned()),
            host: env_snapshot.host.clone(),
            toolchain: env_snapshot.toolchain.clone(),
            features: manifest_ref.verification.features.clone(),
            target_triple: opts
                .target
                .clone()
                .or_else(|| env_snapshot.toolchain.host_triple.clone()),
            ..Default::default()
        },
    };

    let evaluations = evaluate_claims(&inputs);

    let mut gated: Vec<(RequirementLevel, scirust_verify_model::ClaimEvaluation)> = Vec::new();
    for (ev, level) in &evaluations {
        let mut ev = ev.clone();
        let mut level = *level;
        if opts.strict
            && level == RequirementLevel::Required
            && ev.verdict == scirust_verify_model::Verdict::Skipped
        {
            // Under --strict missing prerequisites are hard gaps.
            ev.verdict = scirust_verify_model::Verdict::Unsupported;
            level = RequirementLevel::Required;
        }
        gated.push((level, ev));
    }

    let verdict = scirust_verify_policy::evaluate_gate(&gated);

    // Persist evaluations for reporting.
    let evals_json: Vec<_> = gated
        .iter()
        .map(|(lvl, ev)| {
            serde_json::json!({
                "requirement_level": lvl.to_string(),
                "evaluation": ev,
            })
        })
        .collect();
    store.write_text(
        "evaluations.json",
        &serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "evaluations": evals_json,
        }))
        .map_err(|e| PipelineError::Report(e.to_string()))?,
    )?;

    // 8. Reports (regenerable; included in the sealed bundle).
    let report_ctx = scirust_verify_report::ReportInputs {
        tool_version: TOOL_IDENTITY.to_owned(),
        schema_version: SCHEMA_VERSION,
        detected_providers: detected_notes,
        strict: opts.strict,
    };
    let report_json = scirust_verify_report::render_json(&store, &report_ctx)
        .map_err(|e| PipelineError::Report(e.to_string()))?;
    let report_md = scirust_verify_report::render_markdown(&store, &report_ctx)
        .map_err(|e| PipelineError::Report(e.to_string()))?;
    store.write_text("report.json", &report_json)?;
    store.write_text("report.md", &report_md)?;

    // 9. Validate + seal.
    store.finalize()?;

    Ok(VerifyOutcome {
        run_id: store.run_id().clone(),
        verdict,
        claim_lines: evaluations
            .iter()
            .map(|(ev, lvl)| {
                (
                    ev.claim_id.as_str().to_owned(),
                    *lvl,
                    ev.verdict.to_string(),
                )
            })
            .collect(),
        report_json: runs_root
            .path()
            .join(store.run_id().as_str())
            .join("report.json"),
        report_md: runs_root
            .path()
            .join(store.run_id().as_str())
            .join("report.md"),
    })
}

fn artifact_kind_of(kind: &crate::discovery::ProjectKind) -> ArtifactKind {
    match kind {
        crate::discovery::ProjectKind::Cargo { .. } => ArtifactKind::CargoWorkspace,
        crate::discovery::ProjectKind::Unknown => ArtifactKind::SourceTree,
    }
}

fn best_effort_abort(store: &scirust_verify_store::RunStore) {
    let _ = store.set_state(RunState::Aborted);
}

/// Store-backed evidence sink assigning sequential ids.
struct StoreSink<'a> {
    store: &'a scirust_verify_store::RunStore,
    counter: &'a mut usize,
}

impl CheckSink for StoreSink<'_> {
    fn next_id(&mut self) -> scirust_verify_model::EvidenceId {
        *self.counter += 1;
        scirust_verify_model::EvidenceId::sequential(*self.counter)
    }

    fn add_evidence(
        &mut self,
        evidence: scirust_verify_model::Evidence,
        attachments: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), PipelineFailure> {
        self.store.add_evidence(&evidence, attachments)?;
        Ok(())
    }
}
