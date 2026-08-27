//! CLI orchestration for comparison of two previously sealed runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use scirust_verify_model::{
    Artifact, Attachment, Check, CheckAction, CheckExecution, CheckId, CheckStatus, Claim,
    ClaimEvaluation, ClaimId, ClaimKind, Digest, Evidence, EvidenceId, EvidenceKind,
    EvidenceStatus, Observation, ObservedValue, RequirementLevel, Tolerance, Verdict,
    VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_parity::{
    classify_scope, compare_artifacts, compare_executions, execution_has_comparable_observations,
    EndpointRole, ParityResult, SourceRelation,
};
use scirust_verify_store::{RunState, RunsRoot};

/// Options for one cross-run comparison.
pub(crate) struct CompareRunsOptions<'a> {
    pub(crate) left_run: &'a str,
    pub(crate) right_run: &'a str,
    pub(crate) project: &'a Path,
    pub(crate) tolerance: Tolerance,
    pub(crate) require_cpu_gpu: bool,
}

/// Completed derived-dossier comparison.
pub(crate) struct CompareRunsOutcome {
    pub(crate) run_id: String,
    pub(crate) verdict: Verdict,
    pub(crate) document: serde_json::Value,
    pub(crate) human: String,
}

/// Error that prevents a trustworthy derived comparison dossier.
#[derive(Debug)]
pub(crate) struct CompareRunsError {
    message: String,
    exit_code: u8,
}

impl CompareRunsError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    fn not_verified(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 3,
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

impl std::fmt::Display for CompareRunsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

struct SourceRun {
    run_id: String,
    artifact: Artifact,
    provenance: scirust_verify_model::provenance::ProvenanceDocument,
    executions: Vec<CheckExecution>,
    bundle_digest: Digest,
    sealed_files: usize,
    role: EndpointRole,
    role_records: Vec<serde_json::Value>,
    input_sets: BTreeSet<String>,
    input_scope_complete: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum InputRelation {
    Same { input_set: String },
    Unspecified,
    NotVerified { reason: String },
}

impl InputRelation {
    fn compatible(&self) -> bool {
        !matches!(self, Self::NotVerified { .. })
    }

    fn reason(&self) -> String {
        match self {
            Self::Same { input_set } => format!("same recorded input_set `{input_set}`"),
            Self::Unspecified => "input_set was not recorded on either source run".into(),
            Self::NotVerified { reason } => reason.clone(),
        }
    }
}

/// Compares two sealed source runs and persists a new sealed derived dossier.
pub(crate) fn execute(
    options: &CompareRunsOptions<'_>,
) -> Result<CompareRunsOutcome, CompareRunsError> {
    if options.left_run == options.right_run {
        return Err(CompareRunsError::usage(
            "compare-runs requires two different source run ids",
        ));
    }
    options
        .tolerance
        .validate()
        .map_err(|error| CompareRunsError::usage(error.to_string()))?;

    let runs_root = RunsRoot::new(options.project.join(".scirust-verify").join("runs"));
    let left = load_source_run(&runs_root, options.left_run)?;
    let right = load_source_run(&runs_root, options.right_run)?;
    let source_relation = compare_artifacts(&left.artifact, &right.artifact);
    if !matches!(source_relation, SourceRelation::Same { .. }) {
        return Err(CompareRunsError::not_verified(format!(
            "source equivalence is not established: {}",
            source_relation_reason(&source_relation)
        )));
    }

    let input_relation = compare_input_identity(&left, &right);
    let comparison = compare_executions(&left.executions, &right.executions, &options.tolerance);
    let cpu_gpu_roles_established = matches!(
        (left.role, right.role),
        (EndpointRole::Cpu, EndpointRole::Gpu) | (EndpointRole::Gpu, EndpointRole::Cpu)
    );
    let claim_kind = if options.require_cpu_gpu {
        ClaimKind::CpuGpuParity
    } else {
        ClaimKind::Custom {
            id: "cross_run_output_parity".into(),
        }
    };
    let final_verdict = if !input_relation.compatible()
        || (options.require_cpu_gpu && !cpu_gpu_roles_established)
    {
        Verdict::NotVerified
    } else {
        comparison.verdict
    };

    let claim_id = ClaimId::from(format!("{}@comparison", claim_kind.slug()));
    let mut parameters = serde_json::Map::new();
    parameters.insert("left_run".into(), serde_json::json!(left.run_id));
    parameters.insert("right_run".into(), serde_json::json!(right.run_id));
    parameters.insert(
        "left_bundle_digest".into(),
        serde_json::json!(left.bundle_digest),
    );
    parameters.insert(
        "right_bundle_digest".into(),
        serde_json::json!(right.bundle_digest),
    );
    parameters.insert(
        "tolerance".into(),
        serde_json::to_value(options.tolerance)
            .map_err(|error| CompareRunsError::internal(error.to_string()))?,
    );
    parameters.insert(
        "require_cpu_gpu".into(),
        serde_json::json!(options.require_cpu_gpu),
    );
    parameters.insert(
        "input_relation".into(),
        serde_json::to_value(&input_relation)
            .map_err(|error| CompareRunsError::internal(error.to_string()))?,
    );

    let claim = Claim {
        id: claim_id.clone(),
        kind: claim_kind,
        subject: left.artifact.id.clone(),
        requirement: RequirementLevel::Required,
        statement: if options.require_cpu_gpu {
            format!(
                "CPU and GPU executions of `{}` agree for every comparable structured output under {}",
                left.artifact.id,
                options.tolerance.describe()
            )
        } else {
            format!(
                "sealed runs `{}` and `{}` of `{}` agree for every comparable structured output under {}",
                left.run_id,
                right.run_id,
                left.artifact.id,
                options.tolerance.describe()
            )
        },
        parameters,
    };

    let mut check_parameters = serde_json::Map::new();
    check_parameters.insert("left_run".into(), serde_json::json!(left.run_id));
    check_parameters.insert("right_run".into(), serde_json::json!(right.run_id));
    check_parameters.insert(
        "tolerance".into(),
        serde_json::to_value(options.tolerance)
            .map_err(|error| CompareRunsError::internal(error.to_string()))?,
    );
    check_parameters.insert(
        "require_cpu_gpu".into(),
        serde_json::json!(options.require_cpu_gpu),
    );
    check_parameters.insert(
        "input_relation".into(),
        serde_json::to_value(&input_relation)
            .map_err(|error| CompareRunsError::internal(error.to_string()))?,
    );
    let check = Check {
        id: CheckId::new("parity:compare-runs"),
        provider: "parity".into(),
        purpose: "Compare structured outputs from two sealed verification runs".into(),
        claims: vec![claim_id.clone()],
        requirement: RequirementLevel::Required,
        action: CheckAction::Composite {
            engine: "cross_run_output_parity".into(),
            parameters: check_parameters,
        },
        timeout: Duration::ZERO,
        stdout_limit_bytes: 0,
        stderr_limit_bytes: 0,
    };

    let derived = runs_root
        .create_run()
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .write_artifact(&left.artifact)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    let mut environment =
        scirust_verify_core::provenance::collect_environment(options.project, None);
    environment.toolchain.target_triple = environment.toolchain.host_triple.clone();
    derived
        .write_environment(&environment)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .write_provenance(&left.provenance)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    let plan_digest = Digest::of_canonical_json(&vec![check.clone()])
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .write_plan(std::slice::from_ref(&check), plan_digest)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .write_claims(std::slice::from_ref(&claim))
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .set_state(RunState::Running)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;

    let comparison_scope = VerificationScope {
        recorded_at_utc: Some(chrono::Utc::now()),
        execution_mode: Some("cross_run_output_comparison".into()),
        host: environment.host.clone(),
        toolchain: environment.toolchain.clone(),
        target_triple: environment.toolchain.target_triple.clone(),
        tolerance: Some(options.tolerance),
        ..Default::default()
    };
    let comparison_context = ComparisonContext {
        input_relation: &input_relation,
        cpu_gpu_roles_established,
        final_verdict,
    };
    let source_document = comparison_document(
        options,
        &left,
        &right,
        &source_relation,
        &comparison,
        &comparison_context,
    )?;
    let mut comparison_bytes = serde_json::to_vec_pretty(&source_document)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    comparison_bytes.push(b'\n');
    let comparison_digest = Digest::sha256_hex(&comparison_bytes);
    let attachment_path = format!("evidence/files/{}.json", comparison_digest.value);

    let summary_observations = vec![
        Observation::new(
            "parity_compared_outputs",
            "structured_outputs",
            ObservedValue::UInt(comparison.compared_outputs as u64),
        ),
        Observation::new(
            "parity_mismatched_outputs",
            "structured_outputs",
            ObservedValue::UInt(comparison.mismatched_outputs as u64),
        ),
        Observation::new(
            "parity_structural_gaps",
            "structured_outputs",
            ObservedValue::UInt(comparison.gaps.len() as u64),
        ),
        Observation::new(
            "cpu_gpu_roles_established",
            "source_scopes",
            ObservedValue::Bool(cpu_gpu_roles_established),
        ),
        Observation::new(
            "input_scopes_compatible",
            "source_scopes",
            ObservedValue::Bool(input_relation.compatible()),
        ),
    ];
    let evidence_id = EvidenceId::sequential(1);
    let evidence = Evidence::builder(
        evidence_id.clone(),
        EvidenceKind::CrossRunComparison,
        "parity-engine",
    )
    .artifact(left.artifact.id.clone())
    .scope(comparison_scope.clone())
    .status(if final_verdict == Verdict::Failed {
        EvidenceStatus::Failed
    } else {
        EvidenceStatus::Ok
    })
    .observations(summary_observations.clone())
    .input(left.bundle_digest.clone())
    .input(right.bundle_digest.clone())
    .attachment(Attachment {
        path: attachment_path.clone(),
        size_bytes: comparison_bytes.len() as u64,
        digest: comparison_digest,
        media_type: Some("application/json".into()),
    })
    .meta("left_run", &left.run_id)
    .meta("right_run", &right.run_id)
    .meta("left_role", left.role.as_str())
    .meta("right_role", right.role.as_str())
    .meta("require_cpu_gpu", options.require_cpu_gpu)
    .meta("input_relation", &input_relation)
    .build();
    let attachments = BTreeMap::from([(attachment_path, comparison_bytes)]);
    derived
        .add_evidence(&evidence, &attachments)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;

    let now = chrono::Utc::now();
    let summary = verdict_reason(
        options,
        &comparison,
        &input_relation,
        left.role,
        right.role,
        cpu_gpu_roles_established,
        final_verdict,
    );
    let execution = CheckExecution {
        check_id: check.id.clone(),
        started_at_utc: Some(now),
        ended_at_utc: Some(chrono::Utc::now()),
        status: CheckStatus::Executed { exit_code: None },
        outcome: final_verdict,
        summary: summary.clone(),
        observations: summary_observations,
        evidence_ids: vec![evidence_id.clone()],
        notes: source_limitations(options, &comparison, &input_relation, left.role, right.role),
    };
    derived
        .write_executions(std::slice::from_ref(&execution))
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;

    let evaluation = ClaimEvaluation {
        claim_id,
        verdict: final_verdict,
        scope: comparison_scope,
        reasoning: summary.clone(),
        evidence_ids: vec![evidence_id],
        check_ids: vec![check.id],
    };
    let evaluations = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "evaluations": [{
            "requirement_level": RequirementLevel::Required.to_string(),
            "evaluation": evaluation,
        }],
    });
    derived
        .write_text(
            "evaluations.json",
            &serde_json::to_string_pretty(&evaluations)
                .map_err(|error| CompareRunsError::internal(error.to_string()))?,
        )
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;

    let report_inputs = scirust_verify_report::ReportInputs {
        tool_version: TOOL_IDENTITY.into(),
        schema_version: SCHEMA_VERSION,
        detected_providers: vec![(
            "parity".into(),
            "comparison derived from two integrity-verified finalized runs".into(),
        )],
        strict: options.require_cpu_gpu,
    };
    let report_json = scirust_verify_report::render_json(&derived, &report_inputs)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    let report_md = scirust_verify_report::render_markdown(&derived, &report_inputs)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .write_text("report.json", &report_json)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .write_text("report.md", &report_md)
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;
    derived
        .finalize()
        .map_err(|error| CompareRunsError::internal(error.to_string()))?;

    let run_id = derived.run_id().as_str().to_owned();
    let document = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "generated_by": TOOL_IDENTITY,
        "run_id": run_id,
        "verdict": verdict_slug(final_verdict),
        "claim_kind": if options.require_cpu_gpu { "cpu_gpu_parity" } else { "cross_run_output_parity" },
        "left_run": left.run_id,
        "right_run": right.run_id,
        "left_role": left.role.as_str(),
        "right_role": right.role.as_str(),
        "cpu_gpu_roles_established": cpu_gpu_roles_established,
        "input_relation": input_relation,
        "comparison": comparison,
        "report_json": derived.path().join("report.json"),
        "report_md": derived.path().join("report.md"),
    });
    let human = format!(
        "derived run {}\nclaim: {}\nverdict: {}\nleft: {} ({})\nright: {} ({})\ncompared outputs: {} ({} mismatched, {} structural gap(s))\npolicy: {}\nreport: {}\n",
        run_id,
        if options.require_cpu_gpu { "cpu_gpu_parity" } else { "cross_run_output_parity" },
        final_verdict,
        left.run_id,
        left.role.as_str(),
        right.run_id,
        right.role.as_str(),
        comparison.compared_outputs,
        comparison.mismatched_outputs,
        comparison.gaps.len(),
        options.tolerance.describe(),
        derived.path().join("report.md").display(),
    );

    Ok(CompareRunsOutcome {
        run_id,
        verdict: final_verdict,
        document,
        human,
    })
}

fn load_source_run(runs_root: &RunsRoot, run_id: &str) -> Result<SourceRun, CompareRunsError> {
    let store = runs_root.open(run_id).map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}` cannot be opened: {error}"))
    })?;
    let sealed_files = store.verify_integrity().map_err(|error| {
        CompareRunsError::not_verified(format!(
            "source run `{run_id}` failed integrity verification: {error}"
        ))
    })?;
    let run_doc = store.read_run_document().map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}`: {error}"))
    })?;
    if run_doc.state != RunState::Finalized {
        return Err(CompareRunsError::not_verified(format!(
            "source run `{run_id}` is not finalized"
        )));
    }
    let artifact = store.read_artifact().map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}` artifact: {error}"))
    })?;
    let provenance = store.read_provenance().map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}` provenance: {error}"))
    })?;
    let executions = store.read_executions().map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}` executions: {error}"))
    })?;
    let evidence = store.read_all_evidence().map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}` evidence: {error}"))
    })?;
    let bundle = store.read_text("bundle.json").map_err(|error| {
        CompareRunsError::not_verified(format!("source run `{run_id}` bundle: {error}"))
    })?;
    let bundle_digest = Digest::sha256_hex(bundle.as_bytes());
    let (role, role_records, input_sets, input_scope_complete) =
        derive_role(&executions, &evidence);
    Ok(SourceRun {
        run_id: run_id.to_owned(),
        artifact,
        provenance,
        executions,
        bundle_digest,
        sealed_files,
        role,
        role_records,
        input_sets,
        input_scope_complete,
    })
}

fn derive_role(
    executions: &[CheckExecution],
    evidence: &[Evidence],
) -> (EndpointRole, Vec<serde_json::Value>, BTreeSet<String>, bool) {
    let evidence_by_id: BTreeMap<&str, &Evidence> = evidence
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect();
    let mut roles = BTreeSet::new();
    let mut records = Vec::new();
    let mut input_sets = BTreeSet::new();
    let mut input_scope_complete = true;
    for execution in executions
        .iter()
        .filter(|execution| execution_has_comparable_observations(execution))
    {
        if execution.evidence_ids.is_empty() {
            roles.insert(EndpointRole::Unknown);
            input_scope_complete = false;
            records.push(serde_json::json!({
                "check_id": execution.check_id.as_str(),
                "role": "unknown",
                "reason": "comparable execution has no evidence reference",
            }));
            continue;
        }
        for evidence_id in &execution.evidence_ids {
            let Some(item) = evidence_by_id.get(evidence_id.as_str()) else {
                roles.insert(EndpointRole::Unknown);
                input_scope_complete = false;
                records.push(serde_json::json!({
                    "check_id": execution.check_id.as_str(),
                    "evidence_id": evidence_id.as_str(),
                    "role": "unknown",
                    "reason": "referenced evidence was not loaded",
                }));
                continue;
            };
            let role = match item.scope.as_ref() {
                Some(scope) => {
                    match normalized_input_set(scope.input_set.as_deref()) {
                        Some(input_set) => {
                            input_sets.insert(input_set);
                        }
                        None => input_scope_complete = false,
                    }
                    classify_scope(scope)
                }
                None => {
                    input_scope_complete = false;
                    EndpointRole::Unknown
                }
            };
            roles.insert(role);
            records.push(serde_json::json!({
                "check_id": execution.check_id.as_str(),
                "evidence_id": evidence_id.as_str(),
                "role": role.as_str(),
                "scope": item.scope,
            }));
        }
    }
    let role = if roles.len() == 1 {
        roles
            .iter()
            .next()
            .copied()
            .unwrap_or(EndpointRole::Unknown)
    } else {
        EndpointRole::Unknown
    };
    (role, records, input_sets, input_scope_complete)
}

fn normalized_input_set(value: Option<&str>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn compare_input_identity(left: &SourceRun, right: &SourceRun) -> InputRelation {
    compare_input_sets(
        &left.input_sets,
        left.input_scope_complete,
        &right.input_sets,
        right.input_scope_complete,
    )
}

fn compare_input_sets(
    left: &BTreeSet<String>,
    left_complete: bool,
    right: &BTreeSet<String>,
    right_complete: bool,
) -> InputRelation {
    if left.len() > 1 || right.len() > 1 {
        return InputRelation::NotVerified {
            reason: format!(
                "comparable executions do not use a single recorded input_set per run (left={left:?}, right={right:?})"
            ),
        };
    }
    if left.is_empty() && right.is_empty() {
        return InputRelation::Unspecified;
    }
    let (Some(left_input), Some(right_input)) = (left.iter().next(), right.iter().next()) else {
        return InputRelation::NotVerified {
            reason: format!(
                "input_set identity is recorded on only one side (left={left:?}, right={right:?})"
            ),
        };
    };
    if left_input != right_input {
        return InputRelation::NotVerified {
            reason: format!(
                "recorded input_set values differ: left=`{left_input}`, right=`{right_input}`"
            ),
        };
    }
    if !left_complete || !right_complete {
        return InputRelation::NotVerified {
            reason: format!(
                "input_set `{left_input}` matches where recorded, but at least one comparable evidence scope lacks input identity"
            ),
        };
    }
    InputRelation::Same {
        input_set: left_input.clone(),
    }
}

struct ComparisonContext<'a> {
    input_relation: &'a InputRelation,
    cpu_gpu_roles_established: bool,
    final_verdict: Verdict,
}

fn comparison_document(
    options: &CompareRunsOptions<'_>,
    left: &SourceRun,
    right: &SourceRun,
    source_relation: &SourceRelation,
    comparison: &ParityResult,
    context: &ComparisonContext<'_>,
) -> Result<serde_json::Value, CompareRunsError> {
    let input_relation = context.input_relation;
    let cpu_gpu_roles_established = context.cpu_gpu_roles_established;
    let final_verdict = context.final_verdict;
    Ok(serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "generated_by": TOOL_IDENTITY,
        "left": {
            "run_id": left.run_id,
            "bundle_digest": left.bundle_digest,
            "sealed_files": left.sealed_files,
            "role": left.role.as_str(),
            "role_records": left.role_records,
            "input_sets": left.input_sets,
            "input_scope_complete": left.input_scope_complete,
        },
        "right": {
            "run_id": right.run_id,
            "bundle_digest": right.bundle_digest,
            "sealed_files": right.sealed_files,
            "role": right.role.as_str(),
            "role_records": right.role_records,
            "input_sets": right.input_sets,
            "input_scope_complete": right.input_scope_complete,
        },
        "source_relation": source_relation,
        "comparison_policy": {
            "tolerance": serde_json::to_value(options.tolerance)
                .map_err(|error| CompareRunsError::internal(error.to_string()))?,
            "tolerance_description": options.tolerance.describe(),
            "eligible_observations": ["numeric_comparison.observed", "fingerprint"],
            "require_cpu_gpu": options.require_cpu_gpu,
        },
        "cpu_gpu_roles_established": cpu_gpu_roles_established,
        "input_relation": input_relation,
        "comparison": comparison,
        "final_verdict": verdict_slug(final_verdict),
        "trust_boundary": "comparison covers only structured outputs present in both sealed source dossiers. Conflicting or one-sided recorded input_set identities prevent VERIFIED parity. CPU/GPU parity is certified only when one endpoint is recorded as CPU and the other has concrete, internally consistent GPU identity in the evidence scopes; CLI labels alone never establish endpoint identity.",
    }))
}

fn source_relation_reason(relation: &SourceRelation) -> String {
    match relation {
        SourceRelation::Same { .. } => "same source".into(),
        SourceRelation::Mismatched { reason } | SourceRelation::NotVerified { reason } => {
            reason.clone()
        }
    }
}

fn source_limitations(
    options: &CompareRunsOptions<'_>,
    comparison: &ParityResult,
    input_relation: &InputRelation,
    left: EndpointRole,
    right: EndpointRole,
) -> Vec<String> {
    let mut notes = vec![
        "only structured numeric_comparison.observed values and canonical fingerprints were compared".into(),
    ];
    if !comparison.gaps.is_empty() {
        notes.push(format!(
            "{} structural comparison gap(s) prevented complete parity verification",
            comparison.gaps.len()
        ));
    }
    match input_relation {
        InputRelation::Unspecified => notes.push(
            "input_set was not recorded on either source run; parity is limited to the paired structured outputs themselves".into(),
        ),
        InputRelation::NotVerified { reason } => {
            notes.push(format!("input identity prevented parity verification: {reason}"));
        }
        InputRelation::Same { .. } => {}
    }
    if options.require_cpu_gpu
        && !matches!(
            (left, right),
            (EndpointRole::Cpu, EndpointRole::Gpu) | (EndpointRole::Gpu, EndpointRole::Cpu)
        )
    {
        notes.push(
            "CPU/GPU endpoint identity was not established from source evidence scopes".into(),
        );
    }
    notes
}

fn verdict_reason(
    options: &CompareRunsOptions<'_>,
    comparison: &ParityResult,
    input_relation: &InputRelation,
    left: EndpointRole,
    right: EndpointRole,
    cpu_gpu_roles_established: bool,
    final_verdict: Verdict,
) -> String {
    if !input_relation.compatible() {
        return format!(
            "structured outputs were compared, but parity input identity is NOT_VERIFIED: {}",
            input_relation.reason()
        );
    }
    if options.require_cpu_gpu && !cpu_gpu_roles_established {
        return format!(
            "structured outputs were compared, but CPU/GPU endpoint identity is not established (left={}, right={}); cpu_gpu_parity is NOT_VERIFIED",
            left.as_str(),
            right.as_str()
        );
    }
    match final_verdict {
        Verdict::Verified => format!(
            "all {} comparable structured output(s) agree under {}",
            comparison.compared_outputs,
            options.tolerance.describe()
        ),
        Verdict::Failed => format!(
            "{} of {} comparable structured output(s) contradict parity under {}",
            comparison.mismatched_outputs,
            comparison.compared_outputs,
            options.tolerance.describe()
        ),
        Verdict::NotVerified => format!(
            "parity could not be established because {} structural comparison gap(s) remain",
            comparison.gaps.len()
        ),
        other => format!("parity evaluation ended as {other}"),
    }
}

fn verdict_slug(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Verified => "verified",
        Verdict::Failed => "failed",
        Verdict::NotVerified => "not_verified",
        Verdict::Skipped => "skipped",
        Verdict::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod input_identity_tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn equal_complete_input_sets_are_compatible() {
        let relation = compare_input_sets(&set(&["dataset-A"]), true, &set(&["dataset-A"]), true);
        assert!(matches!(relation, InputRelation::Same { .. }));
        assert!(relation.compatible());
    }

    #[test]
    fn conflicting_input_sets_are_not_verified() {
        let relation = compare_input_sets(&set(&["dataset-A"]), true, &set(&["dataset-B"]), true);
        assert!(matches!(relation, InputRelation::NotVerified { .. }));
        assert!(!relation.compatible());
    }

    #[test]
    fn one_sided_or_incomplete_input_identity_is_not_verified() {
        assert!(matches!(
            compare_input_sets(&set(&["dataset-A"]), true, &BTreeSet::new(), false),
            InputRelation::NotVerified { .. }
        ));
        assert!(matches!(
            compare_input_sets(&set(&["dataset-A"]), false, &set(&["dataset-A"]), true),
            InputRelation::NotVerified { .. }
        ));
    }

    #[test]
    fn both_unspecified_inputs_remain_output_only_comparable() {
        let relation = compare_input_sets(&BTreeSet::new(), false, &BTreeSet::new(), false);
        assert!(matches!(relation, InputRelation::Unspecified));
        assert!(relation.compatible());
    }
}
