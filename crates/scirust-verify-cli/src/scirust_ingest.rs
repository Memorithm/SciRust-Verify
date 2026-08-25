//! Ingestion of SciRust functional-acceptance protocol evidence bundles.
//!
//! SciRust owns its internal acceptance; this module only normalizes a
//! completed protocol bundle into a SciRust-Verify dossier:
//!
//! * the original `summary.txt` is attached verbatim and anchored by digest,
//! * every gate becomes one check + one attestation evidence deriving from
//!   the summary evidence,
//! * source statuses map bijectively (`PASS→Verified`, `FAIL→Failed`,
//!   `SKIP→Skipped`) — nothing is flattened,
//! * facts not present in the bundle (toolchain, host, target) are recorded
//!   as absent, never invented.

use std::collections::BTreeMap;
use std::path::PathBuf;

use scirust_verify_core::pipeline::PipelineError;
use scirust_verify_model::provenance::{GitProvenance, ProvenanceDocument};
use scirust_verify_model::{
    canonical_json, Artifact, ArtifactId, ArtifactKind, Check, CheckAction, CheckExecution,
    CheckId, CheckStatus, Claim, ClaimEvaluation, ClaimId, ClaimKind, Digest, DirtyState,
    EnvironmentSnapshot, Evidence, EvidenceKind, EvidenceStatus, Observation, ObservedValue,
    RequirementLevel, RunId, SourceIdentity, VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_scirust::{GateStatus, ProtocolSummary};
use scirust_verify_store::{RunState, RunsRoot};

/// Ingestion options.
pub struct IngestOptions {
    /// Directory of the protocol bundle (must contain `summary.txt`).
    pub bundle_dir: PathBuf,
    /// Project root the dossier attaches to (default: current directory).
    pub project_root: PathBuf,
    /// Alternative output root for `.scirust-verify`.
    pub output_root: Option<PathBuf>,
}

/// Result of an ingestion.
pub struct IngestOutcome {
    /// Created run id.
    pub run_id: RunId,
    /// Overall verdict label.
    pub verdict_label: String,
    /// Per-claim (slug, level label, verdict label).
    pub claims: Vec<(String, String, String)>,
}

fn known_slug_for(gate_id: &str) -> Option<&'static str> {
    match gate_id {
        "fmt" => Some("fmt_clean"),
        "clippy" => Some("lint_clean"),
        "build" | "check" => Some("builds"),
        "test" => Some("tests_pass"),
        "doc" => Some("docs_build"),
        "deny" => Some("dependency_policy_passes"),
        "determinism" => Some("deterministic"),
        "gpu" => Some("cpu_gpu_parity"),
        _ => None,
    }
}

fn status_label(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Pass => "PASS",
        GateStatus::Fail => "FAIL",
        GateStatus::Skip => "SKIP",
    }
}

/// Performs the ingestion. See module docs.
pub fn ingest(opts: &IngestOptions) -> Result<IngestOutcome, PipelineError> {
    let summary_path = opts.bundle_dir.join("summary.txt");
    let summary_text = std::fs::read_to_string(&summary_path).map_err(|e| {
        PipelineError::Report(format!("cannot read {}: {e}", summary_path.display()))
    })?;
    let summary =
        ProtocolSummary::parse(&summary_text).map_err(|e| PipelineError::Report(e.to_string()))?;
    let source_digest = ProtocolSummary::source_digest(&summary_text);

    let artifact_id = ArtifactId::new(
        opts.bundle_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "scirust-protocol".to_owned()),
    );

    // One check per gate; claims combined per slug by the adapter's map.
    let claim_map = summary.claim_map();
    let mut checks = Vec::new();
    let mut claims: Vec<Claim> = Vec::new();
    let mut check_claims: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for gate in &summary.gates {
        let check_id = CheckId::new(format!("scirust:{}", gate.id));
        let slug = known_slug_for(&gate.id).unwrap_or(gate.id.as_str());
        let claim_id_str = format!("{slug}@{}", gate.id);
        check_claims.insert(check_id.as_str().to_owned(), vec![claim_id_str.clone()]);

        let requirement = if gate.required {
            RequirementLevel::Required
        } else {
            RequirementLevel::Optional
        };

        if !claims.iter().any(|c| c.id.as_str() == claim_id_str) {
            let kind = ClaimKind::from_slug(slug);
            let level = claim_map
                .get(slug)
                .map(|(_, any_required)| {
                    if *any_required {
                        RequirementLevel::Required
                    } else {
                        RequirementLevel::Optional
                    }
                })
                .unwrap_or(requirement);
            claims.push(Claim {
                id: ClaimId::from(claim_id_str.clone()),
                kind,
                subject: artifact_id.clone(),
                requirement: level,
                statement: format!("SciRust protocol gate `{}` supports `{slug}`", gate.id),
                parameters: Default::default(),
            });
        }

        let mut parameters = serde_json::Map::new();
        parameters.insert("gate_id".into(), serde_json::json!(gate.id));
        parameters.insert(
            "source_status".into(),
            serde_json::json!(status_label(gate.status)),
        );
        checks.push(Check {
            id: check_id,
            provider: "scirust".into(),
            purpose: format!("External attestation: SciRust protocol gate `{}`", gate.id),
            claims: vec![ClaimId::from(claim_id_str)],
            requirement,
            action: CheckAction::Composite {
                engine: "external-attestation".into(),
                parameters,
            },
            timeout: std::time::Duration::ZERO,
            stdout_limit_bytes: 1,
            stderr_limit_bytes: 1,
        });
    }

    checks.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let plan_canonical =
        canonical_json(&checks).map_err(|e| PipelineError::Report(e.to_string()))?;
    let plan_digest = Digest::sha256_hex(plan_canonical.as_bytes());

    // Create run and persist pre-execution documents.
    let runs_root_dir = opts
        .output_root
        .clone()
        .unwrap_or_else(|| opts.project_root.join(".scirust-verify"));
    let runs_root = RunsRoot::new(runs_root_dir.join("runs"));
    let store = runs_root.create_run()?;

    store.write_artifact(&Artifact {
        id: artifact_id.clone(),
        kind: ArtifactKind::SourceTree,
        name: artifact_id.as_str().to_owned(),
        version: None,
        path: opts.bundle_dir.clone(),
        source: SourceIdentity {
            repository: None,
            commit: summary.commit.clone(),
            branch: summary.branch.clone(),
            dirty: DirtyState::Unknown,
            tree_digest: None,
        },
        content_digest: None,
    })?;
    // Honest emptiness: the original execution environment is not part of
    // the protocol summary, so nothing is invented here.
    store.write_environment(&EnvironmentSnapshot::default())?;
    store.write_provenance(&ProvenanceDocument {
        schema_version: SCHEMA_VERSION,
        git: Some(GitProvenance {
            repository: None,
            commit: summary.commit.clone(),
            branch: summary.branch.clone(),
            dirty_count: None,
        }),
        tree_digest: None,
        probes: Vec::new(),
    })?;
    store.write_plan(&checks, plan_digest)?;
    store.write_claims(&claims)?;
    store.set_state(RunState::Running)?;

    // Evidence graph: verbatim summary first, then per-gate attestations.
    let mut counter = 0usize;
    let next_id = |counter: &mut usize| {
        *counter += 1;
        scirust_verify_model::EvidenceId::sequential(*counter)
    };

    let summary_ev_id = next_id(&mut counter);
    let mut payloads = BTreeMap::new();
    payloads.insert(
        "logs/scirust-summary.txt".to_owned(),
        summary_text.clone().into_bytes(),
    );
    let summary_evidence = Evidence::builder(
        summary_ev_id.clone(),
        EvidenceKind::ExternalAttestation,
        "scirust-adapter",
    )
    .artifact(artifact_id.clone())
    .status(EvidenceStatus::Ok)
    .observation(Observation::new(
        "protocol_verdict",
        "summary",
        ObservedValue::Text(
            summary
                .verdict
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "unknown".to_owned()),
        ),
    ))
    .observation(Observation::new(
        "packages",
        "workspace",
        ObservedValue::UInt(summary.packages.unwrap_or(0)),
    ))
    .attachment(scirust_verify_model::Attachment {
        path: "logs/scirust-summary.txt".into(),
        size_bytes: summary_text.len() as u64,
        digest: source_digest.clone(),
        media_type: Some("text/plain; charset=utf-8".into()),
    })
    .meta("ingested_by", TOOL_IDENTITY)
    .build();
    store.add_evidence(&summary_evidence, &payloads)?;

    let mut executions = Vec::new();
    for check in &checks {
        let gate_id = check.id.as_str().strip_prefix("scirust:").unwrap_or("");
        let Some(gate) = summary.gates.iter().find(|g| g.id == gate_id) else {
            continue;
        };
        let ev_id = next_id(&mut counter);
        let verdict = gate.status.to_verdict();
        let evidence = Evidence::builder(
            ev_id.clone(),
            EvidenceKind::ExternalAttestation,
            "scirust-adapter",
        )
        .artifact(artifact_id.clone())
        .status(match gate.status {
            GateStatus::Pass => EvidenceStatus::Ok,
            GateStatus::Fail => EvidenceStatus::Failed,
            GateStatus::Skip => EvidenceStatus::Skipped,
        })
        .observation(Observation::new(
            "gate_source_status",
            gate.id.as_str(),
            ObservedValue::Text(status_label(gate.status).to_owned()),
        ))
        .observations(gate.duration_secs.map(|d| {
            Observation::new(
                "duration",
                gate.id.as_str(),
                ObservedValue::DurationNs(d * 1_000_000_000),
            )
            .with_unit("ns")
        }))
        .derived_from([summary_ev_id.clone()])
        .meta("note", gate.note.clone())
        .meta("required", gate.required)
        .build();
        store.add_evidence(&evidence, &BTreeMap::new())?;

        executions.push(CheckExecution {
            check_id: check.id.clone(),
            started_at_utc: None,
            ended_at_utc: None,
            status: CheckStatus::Executed { exit_code: None },
            outcome: verdict,
            summary: format!(
                "SciRust protocol reported {} for gate `{}`{}",
                status_label(gate.status),
                gate.id,
                if gate.note.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", gate.note)
                }
            ),
            observations: Vec::new(),
            evidence_ids: vec![ev_id],
            notes: Vec::new(),
        });
    }

    for execution in &executions {
        store.append_execution(execution.clone())?;
    }

    // Claim evaluations with failure-dominates combination semantics
    // identical to the core verdict engine.
    let mut eval_lines: Vec<(RequirementLevel, ClaimEvaluation)> = Vec::new();
    let mut claim_lines = Vec::new();
    for claim in &claims {
        let mut verdicts = Vec::new();
        let mut ev_ids = Vec::new();
        let mut ck_ids = Vec::new();
        for exec in &executions {
            let supports = check_claims
                .get(exec.check_id.as_str())
                .is_some_and(|cs| cs.iter().any(|c| c == claim.id.as_str()));
            if !supports {
                continue;
            }
            verdicts.push(exec.outcome);
            ev_ids.extend(exec.evidence_ids.iter().cloned());
            ck_ids.push(exec.check_id.clone());
        }
        let verdict = if verdicts.is_empty() {
            scirust_verify_model::Verdict::NotVerified
        } else if verdicts.contains(&scirust_verify_model::Verdict::Failed) {
            scirust_verify_model::Verdict::Failed
        } else if verdicts.contains(&scirust_verify_model::Verdict::NotVerified) {
            scirust_verify_model::Verdict::NotVerified
        } else if verdicts.contains(&scirust_verify_model::Verdict::Verified) {
            scirust_verify_model::Verdict::Verified
        } else if verdicts
            .iter()
            .all(|v| *v == scirust_verify_model::Verdict::Unsupported)
        {
            scirust_verify_model::Verdict::Unsupported
        } else {
            scirust_verify_model::Verdict::Skipped
        };
        let evaluation = ClaimEvaluation {
            claim_id: claim.id.clone(),
            verdict,
            scope: VerificationScope {
                execution_mode: Some("external-attestation-ingestion".into()),
                ..Default::default()
            },
            reasoning: format!(
                "Derived from SciRust protocol gates: {}.",
                ck_ids
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_ids: ev_ids,
            check_ids: ck_ids,
        };
        claim_lines.push((
            claim.id.as_str().to_owned(),
            claim.requirement.to_string(),
            verdict.to_string(),
        ));
        eval_lines.push((claim.requirement, evaluation));
    }

    let evals_json: Vec<_> = eval_lines
        .iter()
        .map(|(lvl, ev)| {
            serde_json::json!({
                "requirement_level": lvl.to_string(),
                "evaluation": serde_json::to_value(ev).unwrap_or_default(),
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

    let report_ctx = scirust_verify_report::ReportInputs {
        tool_version: TOOL_IDENTITY.to_owned(),
        schema_version: SCHEMA_VERSION,
        detected_providers: vec![(
            "scirust".to_owned(),
            "functional-acceptance protocol ingestion".to_owned(),
        )],
        strict: false,
    };
    let report_json = scirust_verify_report::render_json(&store, &report_ctx)
        .map_err(|e| PipelineError::Report(e.to_string()))?;
    let report_md = scirust_verify_report::render_markdown(&store, &report_ctx)
        .map_err(|e| PipelineError::Report(e.to_string()))?;
    store.write_text("report.json", &report_json)?;
    store.write_text("report.md", &report_md)?;
    store.finalize()?;

    Ok(IngestOutcome {
        run_id: store.run_id().clone(),
        verdict_label: overall_from_evals(&eval_lines),
        claims: claim_lines,
    })
}

fn overall_from_evals(evals: &[(RequirementLevel, ClaimEvaluation)]) -> String {
    let items: Vec<_> = evals
        .iter()
        .map(|(level, ev)| scirust_verify_model::GatingItem {
            level: *level,
            verdict: ev.verdict,
        })
        .collect();
    scirust_verify_model::aggregate_dossier_verdict(&items)
        .label()
        .to_owned()
}
