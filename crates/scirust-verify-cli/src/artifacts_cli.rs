//! Dossier creation from ecosystem artifact formats.
//!
//! Both commands are *attestation ingests*: they verify structural and
//! integrity properties locally, attach the original artifact verbatim, and
//! never overstate what was established.

use std::collections::BTreeMap;
use std::path::PathBuf;

use scirust_verify_artifacts::forge::CandidateEnvelopeV1;
use scirust_verify_artifacts::scicap::CapsuleManifestV1;
use scirust_verify_core::pipeline::PipelineError;
use scirust_verify_model::provenance::ProvenanceDocument;
use scirust_verify_model::{
    canonical_json, Artifact, ArtifactId, ArtifactKind, Check, CheckExecution, CheckId,
    CheckStatus, Claim, ClaimEvaluation, ClaimId, ClaimKind, Digest, EnvironmentSnapshot, Evidence,
    EvidenceKind, EvidenceStatus, Observation, ObservedValue, RequirementLevel, RunId,
    SourceIdentity, VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_store::{RunState, RunsRoot};

/// Shared ingestion options.
pub struct IngestOptions {
    /// Input file or directory depending on the command.
    pub input: PathBuf,
    /// Project root for default output placement.
    pub project_root: PathBuf,
    /// Alternative output root for `.scirust-verify`.
    pub output_root: Option<PathBuf>,
}

/// Result summary.
pub struct IngestOutcome {
    /// Created run id.
    pub run_id: RunId,
    /// Overall verdict label.
    pub verdict_label: String,
    /// Per-claim (id, level label, verdict label).
    pub claims: Vec<(String, String, String)>,
}

struct DossierBuilder<'a> {
    runs_root: &'a RunsRoot,
}

impl<'a> DossierBuilder<'a> {
    fn persist(
        &self,
        artifact: &Artifact,
        checks: &[Check],
        claims: &[Claim],
        executions: Vec<CheckExecution>,
        evidence: Vec<(Evidence, BTreeMap<String, Vec<u8>>)>,
        scope: VerificationScope,
    ) -> Result<IngestOutcome, PipelineError> {
        let store = self.runs_root.create_run()?;
        let plan_canonical =
            canonical_json(&checks).map_err(|e| PipelineError::Report(e.to_string()))?;
        let plan_digest = Digest::sha256_hex(plan_canonical.as_bytes());
        store.write_artifact(artifact)?;
        // Ingestion does not re-observe the original execution environment;
        // recording the local host would be misleading.
        store.write_environment(&EnvironmentSnapshot::default())?;
        store.write_provenance(&ProvenanceDocument {
            schema_version: SCHEMA_VERSION,
            git: None,
            tree_digest: None,
            probes: vec![],
        })?;
        store.write_plan(checks, plan_digest)?;
        store.write_claims(claims)?;
        store.set_state(RunState::Running)?;

        let mut counter = 0usize;
        for (ev, payload) in &evidence {
            counter += 1;
            debug_assert_eq!(ev.id.as_str(), format!("ev-{counter:04}"));
            store.add_evidence(ev, payload)?;
        }
        for exec in &executions {
            store.append_execution(exec.clone())?;
        }

        // Evaluations derived 1:1 from execution outcomes.
        let mut eval_lines: Vec<(RequirementLevel, ClaimEvaluation)> = Vec::new();
        let mut claim_lines = Vec::new();
        for claim in claims {
            let supporting: Vec<&CheckExecution> = executions
                .iter()
                .filter(|exec| {
                    check_claims_for(checks, &exec.check_id)
                        .is_some_and(|cs| cs.iter().any(|c| c.as_str() == claim.id.as_str()))
                })
                .collect();
            let verdict = if supporting.is_empty() {
                scirust_verify_model::Verdict::NotVerified
            } else if supporting
                .iter()
                .any(|e| e.outcome == scirust_verify_model::Verdict::Failed)
            {
                scirust_verify_model::Verdict::Failed
            } else if supporting
                .iter()
                .any(|e| e.outcome == scirust_verify_model::Verdict::NotVerified)
            {
                scirust_verify_model::Verdict::NotVerified
            } else if supporting
                .iter()
                .any(|e| e.outcome == scirust_verify_model::Verdict::Verified)
            {
                scirust_verify_model::Verdict::Verified
            } else if supporting
                .iter()
                .all(|e| e.outcome == scirust_verify_model::Verdict::Unsupported)
            {
                scirust_verify_model::Verdict::Unsupported
            } else {
                scirust_verify_model::Verdict::Skipped
            };
            let reasoning = supporting
                .first()
                .map(|e| e.summary.clone())
                .unwrap_or_else(|| "no supporting execution".to_owned());
            let evaluation = ClaimEvaluation {
                claim_id: claim.id.clone(),
                verdict,
                scope: scope.clone(),
                reasoning,
                evidence_ids: supporting
                    .iter()
                    .flat_map(|e| e.evidence_ids.iter().cloned())
                    .collect(),
                check_ids: supporting.iter().map(|e| e.check_id.clone()).collect(),
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
            detected_providers: detected_provider_notes(checks),
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
            verdict_label: overall_label(&eval_lines),
            claims: claim_lines,
        })
    }
}

fn detected_provider_notes(checks: &[Check]) -> Vec<(String, String)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for c in checks {
        if seen.insert(c.provider.clone()) {
            out.push((c.provider.clone(), "artifact attestation ingest".to_owned()));
        }
    }
    out
}

fn overall_label(evals: &[(RequirementLevel, ClaimEvaluation)]) -> String {
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

fn check_claims_for<'a>(checks: &'a [Check], id: &CheckId) -> Option<&'a [ClaimId]> {
    checks
        .iter()
        .find(|c| &c.id == id)
        .map(|c| c.claims.as_slice())
}

// ---------------------------------------------------------------------------
// verify-capsule
// ---------------------------------------------------------------------------

/// Verifies a SciCapsule v1 bundle and produces its dossier.
pub fn verify_capsule(opts: &IngestOptions) -> Result<IngestOutcome, PipelineError> {
    let manifest_path = opts.input.join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path).map_err(|_| {
        PipelineError::Report(format!(
            "manifest.json not found under {} (SciCapsule v1 layout expected)",
            opts.input.display()
        ))
    })?;
    let name_hint = opts
        .input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capsule".to_owned());

    let parse_result = CapsuleManifestV1::parse(&manifest_text);
    let manifest_ok = parse_result.is_ok();
    let manifest = parse_result.as_ref().ok();
    let capsule_name = manifest
        .as_ref()
        .map(|m| m.name.clone())
        .unwrap_or(name_hint);
    let artifact_id = ArtifactId::new(capsule_name.clone());

    let mut checks = Vec::new();
    let mut claims = Vec::new();

    let manifest_claim = claim_id("scicap_manifest_valid", &capsule_name);
    let payloads_claim = claim_id("scicap_payloads_intact", &capsule_name);
    let execution_claim = claim_id("entrypoint_execution", &capsule_name);

    checks.push(check_for(
        "scicap:manifest",
        "Capsule manifest conforms to the v1 schema",
        std::slice::from_ref(&manifest_claim),
        RequirementLevel::Required,
    ));
    claims.push(Claim {
        id: ClaimId::from(manifest_claim),
        kind: ClaimKind::Custom {
            id: "scicap_manifest_valid".into(),
        },
        subject: artifact_id.clone(),
        requirement: RequirementLevel::Required,
        statement: "Capsule manifest is a valid v1 document".into(),
        parameters: Default::default(),
    });

    checks.push(check_for(
        "scicap:payloads",
        "Every payload matches its recorded digest and byte length",
        std::slice::from_ref(&payloads_claim),
        RequirementLevel::Required,
    ));
    claims.push(Claim {
        id: ClaimId::from(payloads_claim),
        kind: ClaimKind::Custom {
            id: "scicap_payloads_intact".into(),
        },
        subject: artifact_id.clone(),
        requirement: RequirementLevel::Required,
        statement: "All capsule payloads match their recorded digests".into(),
        parameters: Default::default(),
    });

    checks.push(check_for(
        "scicap:entrypoint-execution",
        "Entrypoint execution semantics are not defined upstream",
        std::slice::from_ref(&execution_claim),
        RequirementLevel::Informational,
    ));
    claims.push(Claim {
        id: ClaimId::from(execution_claim),
        kind: ClaimKind::Custom {
            id: "entrypoint_execution".into(),
        },
        subject: artifact_id.clone(),
        requirement: RequirementLevel::Informational,
        statement: "Executing the capsule entrypoint".into(),
        parameters: Default::default(),
    });

    // Executions + evidence.
    let mut executions = Vec::new();
    let mut evidence_list: Vec<(Evidence, BTreeMap<String, Vec<u8>>)> = Vec::new();
    let mut counter = 0usize;

    // Manifest evidence (attached regardless of validity).
    counter += 1;
    let manifest_ev_id = scirust_verify_model::EvidenceId::sequential(counter);
    let manifest_status = if manifest_ok {
        EvidenceStatus::Ok
    } else {
        EvidenceStatus::Failed
    };
    let manifest_reason = match &parse_result {
        Ok(_) => "manifest parsed and validated against the v1 schema".to_owned(),
        Err(e) => e.to_string(),
    };
    let mut payloads: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    payloads.insert(
        "logs/scicap-manifest.json".into(),
        manifest_text.clone().into_bytes(),
    );
    let evidence = Evidence::builder(
        manifest_ev_id.clone(),
        EvidenceKind::ExternalAttestation,
        "scicap-verifier",
    )
    .artifact(artifact_id.clone())
    .status(manifest_status)
    .observation(Observation::new(
        "schema_conformant",
        "manifest",
        ObservedValue::Bool(manifest_ok),
    ))
    .attachment(scirust_verify_model::Attachment {
        path: "logs/scicap-manifest.json".into(),
        size_bytes: manifest_text.len() as u64,
        digest: Digest::sha256_hex(manifest_text.as_bytes()),
        media_type: Some("application/json".into()),
    })
    .meta("detail", manifest_reason.clone())
    .build();
    evidence_list.push((evidence, payloads));

    executions.push(CheckExecution {
        check_id: CheckId::new("scicap:manifest"),
        started_at_utc: None,
        ended_at_utc: None,
        status: CheckStatus::Executed { exit_code: None },
        outcome: if manifest_ok {
            scirust_verify_model::Verdict::Verified
        } else {
            scirust_verify_model::Verdict::Failed
        },
        summary: if manifest_ok {
            "v1 schema validation passed".to_owned()
        } else {
            format!("schema validation failed: {manifest_reason}")
        },
        observations: vec![],
        evidence_ids: vec![manifest_ev_id],
        notes: vec![],
    });

    // Payload integrity only when the manifest itself is usable.
    let (payload_verdict, payload_summary, payload_evidence_ids) = match &manifest {
        Some(m) => {
            let results = m.verify_payloads(&opts.input);
            let all_ok = results.iter().all(|r| r.ok);
            counter += 1;
            let ev_id = scirust_verify_model::EvidenceId::sequential(counter);
            let detail = results
                .iter()
                .map(|r| format!("{}: {}", r.path, r.detail))
                .collect::<Vec<_>>()
                .join("; ");
            let evidence = Evidence::builder(
                ev_id.clone(),
                EvidenceKind::ArtifactDigest,
                "scicap-verifier",
            )
            .artifact(artifact_id.clone())
            .status(if all_ok {
                EvidenceStatus::Ok
            } else {
                EvidenceStatus::Failed
            })
            .observations(results.iter().map(|r| {
                Observation::new(
                    "payload_integrity",
                    r.path.clone(),
                    ObservedValue::Bool(r.ok),
                )
            }))
            .meta("detail", detail)
            .build();
            evidence_list.push((evidence, BTreeMap::new()));
            (
                if all_ok {
                    scirust_verify_model::Verdict::Verified
                } else {
                    scirust_verify_model::Verdict::Failed
                },
                if all_ok {
                    format!("{} payload(s) verified", results.len())
                } else {
                    "one or more payloads failed integrity verification".to_owned()
                },
                vec![ev_id],
            )
        }
        None => (
            scirust_verify_model::Verdict::NotVerified,
            "skipped because the manifest is invalid".to_owned(),
            vec![],
        ),
    };

    executions.push(CheckExecution {
        check_id: CheckId::new("scicap:payloads"),
        started_at_utc: None,
        ended_at_utc: None,
        status: CheckStatus::Executed { exit_code: None },
        outcome: payload_verdict,
        summary: payload_summary,
        observations: vec![],
        evidence_ids: payload_evidence_ids,
        notes: vec![],
    });

    // Honest UNSUPPORTED boundary for execution.
    executions.push(CheckExecution {
        check_id: CheckId::new("scicap:entrypoint-execution"),
        started_at_utc: None,
        ended_at_utc: None,
        status: CheckStatus::Unsupported {
            reason: "entrypoint execution semantics are not defined by the upstream schema".into(),
        },
        outcome: scirust_verify_model::Verdict::Unsupported,
        summary: "UNSUPPORTED: capsule execution belongs to higher layers not yet specified"
            .to_owned(),
        observations: vec![],
        evidence_ids: vec![],
        notes: vec![],
    });

    let runs_root_dir = opts
        .output_root
        .clone()
        .unwrap_or_else(|| opts.project_root.join(".scirust-verify"));
    let runs_root = RunsRoot::new(runs_root_dir.join("runs"));
    let builder = DossierBuilder {
        runs_root: &runs_root,
    };

    builder.persist(
        &Artifact {
            id: artifact_id.clone(),
            kind: ArtifactKind::SciCapsule,
            name: capsule_name.clone(),
            version: None,
            path: opts.input.clone(),
            source: SourceIdentity::default(),
            content_digest: None,
        },
        &checks,
        &claims,
        executions,
        evidence_list,
        VerificationScope {
            execution_mode: Some("local-integrity-verification".into()),
            ..Default::default()
        },
    )
}

// ---------------------------------------------------------------------------
// ingest-forge
// ---------------------------------------------------------------------------

/// Ingests a Forge candidate envelope as an integrity attestation.
///
/// The resulting dossier proves the ENVELOPE is internally consistent; it
/// never claims the candidate itself is correct — Forge's own evaluation is
/// not independent verification.
pub fn ingest_forge(opts: &IngestOptions) -> Result<IngestOutcome, PipelineError> {
    let envelope_text = std::fs::read_to_string(&opts.input)
        .map_err(|e| PipelineError::Report(format!("cannot read {}: {e}", opts.input.display())))?;
    let parse_result = CandidateEnvelopeV1::parse(&envelope_text);
    let candidate_id = match &parse_result {
        Ok(env) => env.candidate_id.clone(),
        Err(_) => "unknown-candidate".to_owned(),
    };
    let artifact_id = ArtifactId::new(candidate_id.clone());

    let verify_result: Result<String, scirust_verify_artifacts::forge::EnvelopeError> =
        match parse_result.as_ref() {
            Ok(env) => env.verify(),
            Err(e) => Err(e.clone()),
        };
    let intact = verify_result.is_ok();
    let recomputed_fp = verify_result.ok().unwrap_or_default();

    let mut checks = Vec::new();
    let mut claims = Vec::new();
    let intact_claim = claim_id("forge_envelope_intact", &candidate_id);
    checks.push(check_for(
        "forge:envelope-intact",
        "Candidate envelope fingerprint matches recomputed canonical bytes",
        std::slice::from_ref(&intact_claim),
        RequirementLevel::Required,
    ));
    claims.push(Claim {
        id: ClaimId::from(intact_claim),
        kind: ClaimKind::Custom {
            id: "forge_envelope_intact".into(),
        },
        subject: artifact_id.clone(),
        requirement: RequirementLevel::Required,
        statement: "Forge candidate envelope is internally consistent".into(),
        parameters: Default::default(),
    });

    let mut executions = Vec::new();
    let mut evidence_list: Vec<(Evidence, BTreeMap<String, Vec<u8>>)> = Vec::new();
    let mut payloads = BTreeMap::new();
    payloads.insert(
        "logs/forge-envelope.json".into(),
        envelope_text.clone().into_bytes(),
    );
    let evidence = Evidence::builder(
        scirust_verify_model::EvidenceId::sequential(1),
        EvidenceKind::ExternalAttestation,
        "forge-ingester",
    )
    .artifact(artifact_id.clone())
    .status(if intact {
        EvidenceStatus::Ok
    } else {
        EvidenceStatus::Failed
    })
    .observation(Observation::new(
        "envelope_fingerprint_verified",
        candidate_id.as_str(),
        ObservedValue::Bool(intact),
    ))
    .attachment(scirust_verify_model::Attachment {
        path: "logs/forge-envelope.json".into(),
        size_bytes: envelope_text.len() as u64,
        digest: Digest::sha256_hex(envelope_text.as_bytes()),
        media_type: Some("application/json".into()),
    })
    .meta("recomputed_fingerprint", recomputed_fp)
    .meta(
        "trust_scope",
        "verifies envelope internal consistency only; Forge's own correctness \
         evaluation is NOT independent verification",
    )
    .build();
    evidence_list.push((evidence, payloads));

    executions.push(CheckExecution {
        check_id: CheckId::new("forge:envelope-intact"),
        started_at_utc: None,
        ended_at_utc: None,
        status: CheckStatus::Executed { exit_code: None },
        outcome: if intact {
            scirust_verify_model::Verdict::Verified
        } else {
            scirust_verify_model::Verdict::Failed
        },
        summary: if intact {
            "recorded fingerprint matches recomputed canonical bytes".to_owned()
        } else {
            match &parse_result {
                Err(e) => format!("envelope invalid: {e}"),
                Ok(env) => match env.verify() {
                    Err(scirust_verify_artifacts::forge::EnvelopeError::FingerprintMismatch {
                        recorded,
                        recomputed,
                    }) => format!(
                        "fingerprint mismatch: recorded {recorded}, recomputed {recomputed}"
                    ),
                    Err(e) => format!("verification failed: {e}"),
                    Ok(_) => unreachable!(),
                },
            }
        },
        observations: vec![],
        evidence_ids: vec![scirust_verify_model::EvidenceId::sequential(1)],
        notes: vec!["Trust scope: this dossier attests envelope consistency only.".into()],
    });

    let runs_root_dir = opts
        .output_root
        .clone()
        .unwrap_or_else(|| opts.project_root.join(".scirust-verify"));
    let runs_root = RunsRoot::new(runs_root_dir.join("runs"));
    let builder = DossierBuilder {
        runs_root: &runs_root,
    };

    builder.persist(
        &Artifact {
            id: artifact_id.clone(),
            kind: ArtifactKind::ForgeCandidate,
            name: candidate_id.clone(),
            version: None,
            path: opts.input.clone(),
            source: SourceIdentity::default(),
            content_digest: None,
        },
        &checks,
        &claims,
        executions,
        evidence_list,
        VerificationScope {
            execution_mode: Some("external-attestation-ingestion".into()),
            ..Default::default()
        },
    )
}

fn check_for(slug: &str, purpose: &str, claim_ids: &[String], level: RequirementLevel) -> Check {
    Check {
        id: CheckId::from(slug),
        provider: slug.split(':').next().unwrap_or("artifacts").to_owned(),
        purpose: purpose.to_owned(),
        claims: claim_ids.iter().map(|c| ClaimId::from(c.clone())).collect(),
        requirement: level,
        action: scirust_verify_model::CheckAction::Composite {
            engine: "external-attestation".into(),
            parameters: Default::default(),
        },
        timeout: std::time::Duration::ZERO,
        stdout_limit_bytes: 1,
        stderr_limit_bytes: 1,
    }
}

fn claim_id(slug: &str, instance: &str) -> String {
    format!("{slug}@{instance}")
}
