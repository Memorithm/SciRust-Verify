//! Forge/SOUP evidence ingestion for the SciRust Hub v1 orchestration edge.
//!
//! This adapter validates the exact published source identities and the
//! deterministic Hub evidence tar, then exposes source-preserving observations.
//! It deliberately does **not** turn Forge fitness, Pareto rank, a SOUP dry-run
//! pass, or a benchmark score into a SciRust-Verify `Verified` verdict. Claim
//! thresholds and verdict policy remain a separate verification step.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use scirust_verify_model::{Digest as ModelDigest, DigestAlgorithm, Observation, ObservedValue};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Schema version of the Hub/Forge/SOUP evidence edge ingested here.
pub const FORGE_SOUP_EVIDENCE_SCHEMA_VERSION: u16 = 1;
/// Qualified Forge SOUP typed-domain merge.
pub const FORGE_SOUP_DOMAIN_MERGE: &str = "1385c71a541419f15a558a5e94bc8a4a60567a4a";
/// Qualified Forge process-runner merge.
pub const FORGE_SOUP_RUNNER_MERGE: &str = "9e1f3fc568c176f401735c121780d9fbe6834f5d";
/// Qualified SciRust Hub merge publishing `llm.optimize.forge_soup@1.0.0`.
pub const FORGE_SOUP_HUB_MERGE: &str = "074cf2c6e00a0b142fe46d1558c8b32df9228859";
/// SOUP source commit qualified by the published edge.
pub const FORGE_SOUP_QUALIFIED_SOUP_COMMIT: &str = "05b646523727925990530667e7012ede50bd30b2";
/// SOUP repository identity qualified by the published edge.
pub const FORGE_SOUP_REPOSITORY: &str = "MakazhanAlpamys/Soup";

const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TAR_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const MAX_EVIDENCE_FILES: usize = 250_000;
const MAX_EVIDENCE_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_EVIDENCE_RECORD_BYTES: u64 = 64 * 1024 * 1024;
const TAR_BLOCK: usize = 512;

/// Errors raised while validating or ingesting Forge/SOUP evidence.
#[derive(Debug, Error)]
pub enum ForgeSoupAdapterError {
    /// File-system or streaming failure.
    #[error("Forge/SOUP evidence I/O error: {0}")]
    Io(String),
    /// JSON does not match the published v1 contract.
    #[error("Forge/SOUP evidence JSON error: {0}")]
    Json(String),
    /// Source identity or cross-record invariant failed.
    #[error("Forge/SOUP evidence contract violation: {0}")]
    Contract(String),
    /// Tar structure is not the deterministic, regular-file-only Hub bundle.
    #[error("Forge/SOUP evidence tar violation: {0}")]
    Tar(String),
}

/// One source-preserving evaluator record from the Hub evidence bundle.
#[derive(Debug, Clone, PartialEq)]
pub enum ForgeSoupRecordSummary {
    /// SOUP `train --dry-run` verification evidence.
    Verify {
        /// Forge candidate id.
        candidate_id: u64,
        /// Forge trial seed.
        trial_seed: u64,
        /// Forge generation.
        generation: u64,
        /// Exact candidate recipe values sent to the Hub evaluator.
        candidate_values: BTreeMap<String, String>,
        /// SHA-256 of the materialized SOUP config used by this execution.
        config_sha256: String,
        /// Size of the immutable dataset consumed by the evaluator.
        dataset_bytes: u64,
        /// Source dry-run result. This is not a SciRust-Verify verdict.
        passed: bool,
        /// SOUP subprocess return code.
        returncode: i64,
        /// Monotonic elapsed duration recorded by the Hub evaluator.
        elapsed_ns: u64,
        /// Source environment fingerprint.
        environment_fingerprint: String,
        /// Source-provided evidence id retained as provenance, not trusted as a signature.
        source_evidence_id: String,
        /// SciRust-Verify SHA-256 digest of the exact JSON evidence record bytes.
        raw_record_digest: ModelDigest,
        /// Source environment payload retained without reinterpretation.
        environment: serde_json::Value,
        /// Source log metadata retained without reinterpretation.
        logs: serde_json::Value,
    },
    /// Executed SOUP training/benchmark measurement evidence.
    Measure {
        /// Forge candidate id.
        candidate_id: u64,
        /// Forge trial seed.
        trial_seed: u64,
        /// Forge generation.
        generation: u64,
        /// Exact candidate recipe values sent to the Hub evaluator.
        candidate_values: BTreeMap<String, String>,
        /// SHA-256 of the materialized SOUP config used by this execution.
        config_sha256: String,
        /// Size of the immutable dataset consumed by the evaluator.
        dataset_bytes: u64,
        /// Exact metric map emitted by the Hub evaluator.
        metrics: BTreeMap<String, f64>,
        /// Source environment fingerprint.
        environment_fingerprint: String,
        /// Source-provided evidence id retained as provenance, not trusted as a signature.
        source_evidence_id: String,
        /// SciRust-Verify SHA-256 digest of the exact JSON evidence record bytes.
        raw_record_digest: ModelDigest,
        /// SOUP benchmark details retained as raw structured source evidence.
        details: serde_json::Value,
        /// Source environment payload retained without reinterpretation.
        environment: serde_json::Value,
        /// Source log metadata retained without reinterpretation.
        logs: serde_json::Value,
    },
}

impl ForgeSoupRecordSummary {
    /// Candidate id bound to this source record.
    pub fn candidate_id(&self) -> u64 {
        match self {
            Self::Verify { candidate_id, .. } | Self::Measure { candidate_id, .. } => *candidate_id,
        }
    }

    /// Trial seed bound to this source record.
    pub fn trial_seed(&self) -> u64 {
        match self {
            Self::Verify { trial_seed, .. } | Self::Measure { trial_seed, .. } => *trial_seed,
        }
    }

    /// Generation bound to this source record.
    pub fn generation(&self) -> u64 {
        match self {
            Self::Verify { generation, .. } | Self::Measure { generation, .. } => *generation,
        }
    }

    /// Exact candidate recipe values bound to this source record.
    pub fn candidate_values(&self) -> &BTreeMap<String, String> {
        match self {
            Self::Verify {
                candidate_values, ..
            }
            | Self::Measure {
                candidate_values, ..
            } => candidate_values,
        }
    }

    /// Materialized SOUP config SHA-256 bound to this execution.
    pub fn config_sha256(&self) -> &str {
        match self {
            Self::Verify { config_sha256, .. } | Self::Measure { config_sha256, .. } => config_sha256,
        }
    }

    /// Dataset size bound to this execution.
    pub fn dataset_bytes(&self) -> u64 {
        match self {
            Self::Verify { dataset_bytes, .. } | Self::Measure { dataset_bytes, .. } => *dataset_bytes,
        }
    }

    /// Environment fingerprint reported by the Hub evaluator.
    pub fn environment_fingerprint(&self) -> &str {
        match self {
            Self::Verify {
                environment_fingerprint,
                ..
            }
            | Self::Measure {
                environment_fingerprint,
                ..
            } => environment_fingerprint,
        }
    }

    /// Converts this source record into typed observations without deriving a verdict.
    pub fn observations(&self) -> Vec<Observation> {
        let mut out = vec![
            Observation::new(
                "forge_soup_identity",
                "candidate_id",
                ObservedValue::UInt(self.candidate_id()),
            ),
            Observation::new(
                "forge_soup_identity",
                "trial_seed",
                ObservedValue::UInt(self.trial_seed()),
            ),
            Observation::new(
                "forge_soup_identity",
                "generation",
                ObservedValue::UInt(self.generation()),
            ),
            Observation::new(
                "forge_soup_identity",
                "candidate_values",
                ObservedValue::Json(
                    serde_json::to_value(self.candidate_values()).unwrap_or(serde_json::Value::Null),
                ),
            ),
            Observation::new(
                "forge_soup_provenance",
                "config_sha256",
                ObservedValue::Text(self.config_sha256().to_owned()),
            ),
            Observation::new(
                "forge_soup_provenance",
                "dataset_bytes",
                ObservedValue::Bytes(self.dataset_bytes()),
            ),
            Observation::new(
                "forge_soup_environment",
                "fingerprint",
                ObservedValue::Text(self.environment_fingerprint().to_owned()),
            ),
        ];
        match self {
            Self::Verify {
                passed,
                returncode,
                elapsed_ns,
                source_evidence_id,
                raw_record_digest,
                ..
            } => {
                out.extend([
                    Observation::new(
                        "forge_soup_verify",
                        "dry_run_passed",
                        ObservedValue::Bool(*passed),
                    ),
                    Observation::new(
                        "forge_soup_verify",
                        "returncode",
                        ObservedValue::Int(*returncode),
                    ),
                    Observation::new(
                        "forge_soup_verify",
                        "elapsed",
                        ObservedValue::DurationNs(*elapsed_ns),
                    ),
                    Observation::new(
                        "forge_soup_provenance",
                        "source_evidence_id",
                        ObservedValue::Text(source_evidence_id.clone()),
                    ),
                    Observation::new(
                        "forge_soup_provenance",
                        "raw_record_digest",
                        ObservedValue::Text(raw_record_digest.to_string()),
                    ),
                ]);
            }
            Self::Measure {
                metrics,
                source_evidence_id,
                raw_record_digest,
                ..
            } => {
                for (name, value) in metrics {
                    let observation = Observation::new(
                        "forge_soup_metric",
                        name.clone(),
                        ObservedValue::Float(*value),
                    );
                    out.push(if name.ends_with("_wall_ms") {
                        observation.with_unit("ms")
                    } else {
                        observation
                    });
                }
                out.extend([
                    Observation::new(
                        "forge_soup_provenance",
                        "source_evidence_id",
                        ObservedValue::Text(source_evidence_id.clone()),
                    ),
                    Observation::new(
                        "forge_soup_provenance",
                        "raw_record_digest",
                        ObservedValue::Text(raw_record_digest.to_string()),
                    ),
                ]);
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateExecutionBinding {
    generation: u64,
    candidate_values: BTreeMap<String, String>,
    config_sha256: String,
    dataset_bytes: u64,
}

impl CandidateExecutionBinding {
    fn from_record(record: &ForgeSoupRecordSummary) -> Self {
        Self {
            generation: record.generation(),
            candidate_values: record.candidate_values().clone(),
            config_sha256: record.config_sha256().to_owned(),
            dataset_bytes: record.dataset_bytes(),
        }
    }
}

/// Validated, source-preserving ingestion result.
#[derive(Debug, Clone, PartialEq)]
pub struct ForgeSoupIngest {
    domain_id: String,
    upstream_contract_sha256: String,
    verification_adapter_id: String,
    verification_adapter_sha256: String,
    report_digest: ModelDigest,
    evidence_bundle_digest: ModelDigest,
    records: Vec<ForgeSoupRecordSummary>,
    final_front_candidate_ids: Vec<u64>,
    objective_names: Vec<String>,
    limitations: Vec<String>,
}

impl ForgeSoupIngest {
    /// Forge domain id from the validated campaign report.
    pub fn domain_id(&self) -> &str {
        &self.domain_id
    }

    /// SHA-256 identity of the upstream semantic contract recorded by Forge.
    pub fn upstream_contract_sha256(&self) -> &str {
        &self.upstream_contract_sha256
    }

    /// Verification adapter identity recorded in the Forge campaign report.
    pub fn verification_adapter_id(&self) -> &str {
        &self.verification_adapter_id
    }

    /// Verification adapter SHA-256 recorded in the Forge campaign report.
    pub fn verification_adapter_sha256(&self) -> &str {
        &self.verification_adapter_sha256
    }

    /// SciRust-Verify digest of the exact Forge report bytes.
    pub fn report_digest(&self) -> &ModelDigest {
        &self.report_digest
    }

    /// SciRust-Verify digest of the exact Hub evidence tar bytes.
    pub fn evidence_bundle_digest(&self) -> &ModelDigest {
        &self.evidence_bundle_digest
    }

    /// Source evidence records after structural validation.
    pub fn records(&self) -> &[ForgeSoupRecordSummary] {
        &self.records
    }

    /// Candidate ids selected onto Forge's final Pareto front.
    ///
    /// Selection is retained as a source fact; membership is not a verification verdict.
    pub fn final_front_candidate_ids(&self) -> &[u64] {
        &self.final_front_candidate_ids
    }

    /// Objective names observed in valid Forge score objects.
    pub fn objective_names(&self) -> &[String] {
        &self.objective_names
    }

    /// Explicit limitations that callers must preserve when building claims/reports.
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    /// Flattens source records into typed observations without deriving claims/verdicts.
    pub fn observations(&self) -> Vec<Observation> {
        self.records
            .iter()
            .flat_map(ForgeSoupRecordSummary::observations)
            .collect()
    }
}

/// Loads and validates the Forge campaign report plus Hub evidence tar.
///
/// The adapter verifies source commit identities, report score consistency,
/// tar regular-file constraints, source evidence shapes, cross-record candidate
/// execution identity, and final-front coverage by executed measurement evidence.
/// It never evaluates a model-quality or performance claim by itself.
pub fn ingest_forge_soup(
    report_path: &Path,
    evidence_bundle_path: &Path,
) -> Result<ForgeSoupIngest, ForgeSoupAdapterError> {
    require_regular_file(report_path, "Forge report")?;
    require_regular_file(evidence_bundle_path, "Hub evidence bundle")?;

    let report_size = file_size(report_path)?;
    if report_size > MAX_REPORT_BYTES {
        return Err(ForgeSoupAdapterError::Contract(format!(
            "Forge report exceeds {MAX_REPORT_BYTES} bytes"
        )));
    }
    let bundle_size = file_size(evidence_bundle_path)?;
    if bundle_size > MAX_TAR_BYTES {
        return Err(ForgeSoupAdapterError::Tar(format!(
            "Hub evidence tar exceeds {MAX_TAR_BYTES} bytes"
        )));
    }

    let report_bytes =
        std::fs::read(report_path).map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    let report: CampaignReport = serde_json::from_slice(&report_bytes)
        .map_err(|error| ForgeSoupAdapterError::Json(error.to_string()))?;
    let report_facts = validate_report(&report)?;

    let mut records = parse_evidence_tar(evidence_bundle_path, &report.domain_id)?;
    if records.is_empty() {
        return Err(ForgeSoupAdapterError::Contract(
            "Hub evidence bundle contains no evaluator records".to_owned(),
        ));
    }

    let mut source_ids = BTreeSet::new();
    let mut measured_candidates = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut execution_bindings: BTreeMap<(u64, u64), CandidateExecutionBinding> = BTreeMap::new();
    for record in &records {
        let source_id = match record {
            ForgeSoupRecordSummary::Verify {
                source_evidence_id, ..
            }
            | ForgeSoupRecordSummary::Measure {
                source_evidence_id, ..
            } => source_evidence_id,
        };
        if !source_ids.insert(source_id.clone()) {
            return Err(ForgeSoupAdapterError::Contract(format!(
                "duplicate source evidence id {source_id}"
            )));
        }
        fingerprints.insert(record.environment_fingerprint().to_owned());

        let binding_key = (record.candidate_id(), record.trial_seed());
        let binding = CandidateExecutionBinding::from_record(record);
        if let Some(existing) = execution_bindings.get(&binding_key) {
            if existing != &binding {
                return Err(ForgeSoupAdapterError::Contract(format!(
                    "candidate {} trial {} changes recipe/config/dataset/generation across evidence records",
                    record.candidate_id(),
                    record.trial_seed()
                )));
            }
        } else {
            execution_bindings.insert(binding_key, binding);
        }

        if let Some(expected_values) = report_facts.candidate_values.get(&record.candidate_id()) {
            if expected_values != record.candidate_values() {
                return Err(ForgeSoupAdapterError::Contract(format!(
                    "candidate {} evidence recipe does not match Forge report",
                    record.candidate_id()
                )));
            }
        }

        if matches!(record, ForgeSoupRecordSummary::Measure { .. }) {
            measured_candidates.insert(record.candidate_id());
        }
    }

    for candidate_id in &report_facts.final_front_candidate_ids {
        if !measured_candidates.contains(candidate_id) {
            return Err(ForgeSoupAdapterError::Contract(format!(
                "final-front candidate {candidate_id} has no executed measurement evidence"
            )));
        }
    }
    if let Some(best) = report.best.as_ref() {
        if !measured_candidates.contains(&best.candidate_id) {
            return Err(ForgeSoupAdapterError::Contract(format!(
                "best candidate {} has no executed measurement evidence",
                best.candidate_id
            )));
        }
    }

    if !report_facts.objective_names.is_empty() {
        let expected: BTreeSet<&str> = report_facts
            .objective_names
            .iter()
            .map(String::as_str)
            .collect();
        for record in &records {
            if let ForgeSoupRecordSummary::Measure { metrics, .. } = record {
                let actual: BTreeSet<&str> = metrics.keys().map(String::as_str).collect();
                if actual != expected {
                    return Err(ForgeSoupAdapterError::Contract(
                        "measurement metric set does not match objective names in the Forge report"
                            .to_owned(),
                    ));
                }
            }
        }
    }

    let mut limitations = vec![
        "forge_candidate_score_and_pareto_membership_are_search_evidence_not_verified_claims"
            .to_owned(),
        "soup_dry_run_pass_is_source_verification_evidence_not_a_scirust_verify_verdict".to_owned(),
        "hub_local_process_execution_is_not_hostile_code_isolation".to_owned(),
        "hardware_scope_is_limited_to_the_recorded_environment_fingerprint".to_owned(),
    ];
    if fingerprints.len() > 1 {
        limitations.push(
            "multiple_environment_fingerprints_present_and_not_assumed_comparable".to_owned(),
        );
    }

    records.shrink_to_fit();
    Ok(ForgeSoupIngest {
        domain_id: report.domain_id,
        upstream_contract_sha256: report.upstream_contract_sha256,
        verification_adapter_id: report.verification_adapter_id,
        verification_adapter_sha256: report.verification_adapter_sha256,
        report_digest: ModelDigest::sha256_hex(&report_bytes),
        evidence_bundle_digest: digest_file(evidence_bundle_path)?,
        records,
        final_front_candidate_ids: report_facts.final_front_candidate_ids,
        objective_names: report_facts.objective_names,
        limitations,
    })
}

#[derive(Debug, Clone)]
struct ReportFacts {
    final_front_candidate_ids: Vec<u64>,
    objective_names: Vec<String>,
    candidate_values: BTreeMap<u64, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ObjectiveDirection {
    Minimize,
    Maximize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectiveValue {
    name: String,
    direction: ObjectiveDirection,
    value: f64,
    forge_minimized_value: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScoreWire {
    valid: bool,
    objectives: Vec<ObjectiveValue>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateResult {
    candidate_id: u64,
    values: BTreeMap<String, String>,
    score: ScoreWire,
    holdout_score: Option<ScoreWire>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineConfig {
    generations: u64,
    population: usize,
    survivors: usize,
    base_seed: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignReport {
    schema_version: u16,
    forge_domain_source_merge: String,
    domain_id: String,
    upstream_repository: String,
    upstream_commit_id: String,
    upstream_contract_sha256: String,
    verification_adapter_id: String,
    verification_adapter_sha256: String,
    engine: EngineConfig,
    best: Option<CandidateResult>,
    final_baseline: Option<ScoreWire>,
    holdout_best: Option<ScoreWire>,
    holdout_baseline: Option<ScoreWire>,
    history: Vec<f64>,
    failure_diagnostics: Vec<serde_json::Value>,
    final_front: Vec<CandidateResult>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateEnvelope {
    values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum EvidenceRecordWire {
    Verify {
        schema_version: u16,
        candidate_id: u64,
        trial_seed: u64,
        generation: u64,
        domain_id: String,
        candidate: CandidateEnvelope,
        config_sha256: String,
        dataset_bytes: u64,
        passed: bool,
        returncode: i64,
        elapsed_ns: u64,
        environment: serde_json::Value,
        environment_fingerprint: String,
        logs: serde_json::Value,
        evidence_id: String,
    },
    Measure {
        schema_version: u16,
        candidate_id: u64,
        trial_seed: u64,
        generation: u64,
        domain_id: String,
        candidate: CandidateEnvelope,
        config_sha256: String,
        dataset_bytes: u64,
        metrics: BTreeMap<String, f64>,
        details: serde_json::Value,
        environment: serde_json::Value,
        environment_fingerprint: String,
        logs: serde_json::Value,
        evidence_id: String,
    },
}

fn validate_report(report: &CampaignReport) -> Result<ReportFacts, ForgeSoupAdapterError> {
    if report.schema_version != FORGE_SOUP_EVIDENCE_SCHEMA_VERSION {
        return contract(format!(
            "unsupported report schema_version {}",
            report.schema_version
        ));
    }
    if report.forge_domain_source_merge != FORGE_SOUP_DOMAIN_MERGE {
        return contract("Forge domain source merge is not the qualified SOUP domain");
    }
    if report.domain_id.trim().is_empty() {
        return contract("report domain_id is empty");
    }
    if report.upstream_repository != FORGE_SOUP_REPOSITORY {
        return contract("report upstream repository is not MakazhanAlpamys/Soup");
    }
    if report.upstream_commit_id != FORGE_SOUP_QUALIFIED_SOUP_COMMIT {
        return contract("report SOUP commit is not the qualified commit");
    }
    require_sha256(&report.upstream_contract_sha256, "upstream_contract_sha256")?;
    if report.verification_adapter_id.trim().is_empty() {
        return contract("verification_adapter_id is empty");
    }
    require_sha256(
        &report.verification_adapter_sha256,
        "verification_adapter_sha256",
    )?;
    if report.engine.generations == 0
        || report.engine.population == 0
        || report.engine.survivors == 0
        || report.engine.survivors > report.engine.population
    {
        return contract("invalid Forge engine bounds in report");
    }
    let _base_seed = report.engine.base_seed;
    if report.history.iter().any(|value| !value.is_finite()) {
        return contract("report history contains non-finite values");
    }
    let _failure_count = report.failure_diagnostics.len();

    let mut objective_names = BTreeSet::new();
    for score in report
        .best
        .iter()
        .map(|candidate| &candidate.score)
        .chain(
            report
                .best
                .iter()
                .filter_map(|candidate| candidate.holdout_score.as_ref()),
        )
        .chain(report.final_baseline.iter())
        .chain(report.holdout_best.iter())
        .chain(report.holdout_baseline.iter())
        .chain(report.final_front.iter().map(|candidate| &candidate.score))
        .chain(
            report
                .final_front
                .iter()
                .filter_map(|candidate| candidate.holdout_score.as_ref()),
        )
    {
        validate_score(score, &mut objective_names)?;
    }

    let mut candidate_values = BTreeMap::new();
    let mut final_ids = BTreeSet::new();
    for candidate in &report.final_front {
        if candidate.values.is_empty() {
            return contract(format!(
                "final-front candidate {} has no candidate dimensions",
                candidate.candidate_id
            ));
        }
        if !candidate.score.valid {
            return contract(format!(
                "final-front candidate {} has an invalid score",
                candidate.candidate_id
            ));
        }
        if !final_ids.insert(candidate.candidate_id) {
            return contract(format!(
                "duplicate final-front candidate id {}",
                candidate.candidate_id
            ));
        }
        candidate_values.insert(candidate.candidate_id, candidate.values.clone());
    }
    if let Some(best) = &report.best {
        if best.values.is_empty() || !best.score.valid {
            return contract("best candidate is structurally invalid");
        }
        if let Some(existing) = candidate_values.get(&best.candidate_id) {
            if existing != &best.values {
                return contract("best candidate recipe conflicts with final-front recipe");
            }
        } else {
            candidate_values.insert(best.candidate_id, best.values.clone());
        }
    }

    Ok(ReportFacts {
        final_front_candidate_ids: final_ids.into_iter().collect(),
        objective_names: objective_names.into_iter().collect(),
        candidate_values,
    })
}

fn validate_score(
    score: &ScoreWire,
    names: &mut BTreeSet<String>,
) -> Result<(), ForgeSoupAdapterError> {
    if !score.valid {
        if !score.objectives.is_empty() {
            return contract("invalid Forge score unexpectedly carries objectives");
        }
        return Ok(());
    }
    if score.objectives.is_empty() {
        return contract("valid Forge score has no objectives");
    }
    let mut local = BTreeSet::new();
    for objective in &score.objectives {
        if objective.name.trim().is_empty() || !local.insert(objective.name.clone()) {
            return contract("Forge score contains empty or duplicate objective names");
        }
        if !objective.value.is_finite() || !objective.forge_minimized_value.is_finite() {
            return contract(format!(
                "objective {:?} contains a non-finite value",
                objective.name
            ));
        }
        let expected = match objective.direction {
            ObjectiveDirection::Minimize => objective.forge_minimized_value,
            ObjectiveDirection::Maximize => -objective.forge_minimized_value,
        };
        if objective.value != expected {
            return contract(format!(
                "objective {:?} does not preserve Forge direction normalization",
                objective.name
            ));
        }
        names.insert(objective.name.clone());
    }
    Ok(())
}

fn parse_evidence_tar(
    path: &Path,
    expected_domain_id: &str,
) -> Result<Vec<ForgeSoupRecordSummary>, ForgeSoupAdapterError> {
    let mut file =
        File::open(path).map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    let mut records = Vec::new();
    let mut total_payload = 0u64;
    let mut root_seen = false;
    let mut zero_blocks = 0usize;

    while let Some(header) = read_tar_block(&mut file)? {
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            continue;
        }
        if zero_blocks > 0 {
            return tar("non-zero tar data appears after the end-of-archive marker");
        }
        validate_tar_checksum(&header)?;
        let name = tar_string(&header[0..100], "name")?;
        let prefix = tar_string(&header[345..500], "prefix")?;
        if !prefix.is_empty() {
            return tar("tar path prefixes are not part of the Hub v1 evidence contract");
        }
        let size = parse_tar_octal(&header[124..136], "size")?;
        let typeflag = header[156];

        if typeflag == b'5' {
            if root_seen || !(name == "evidence" || name == "evidence/") || size != 0 {
                return tar("unexpected directory entry in evidence tar");
            }
            root_seen = true;
            continue;
        }
        if typeflag != 0 && typeflag != b'0' {
            return tar(format!(
                "unsupported tar entry type 0x{typeflag:02x}; links/PAX/devices are not accepted"
            ));
        }
        if !root_seen {
            return tar("regular evidence file appears before the evidence root directory");
        }
        validate_evidence_tar_name(&name)?;
        if size > MAX_EVIDENCE_RECORD_BYTES {
            return tar(format!(
                "evidence record {name:?} exceeds {MAX_EVIDENCE_RECORD_BYTES} bytes"
            ));
        }
        total_payload = total_payload.checked_add(size).ok_or_else(|| {
            ForgeSoupAdapterError::Tar("evidence payload size overflow".to_owned())
        })?;
        if total_payload > MAX_EVIDENCE_PAYLOAD_BYTES {
            return tar(format!(
                "evidence payload exceeds {MAX_EVIDENCE_PAYLOAD_BYTES} bytes"
            ));
        }
        if records.len() >= MAX_EVIDENCE_FILES {
            return tar(format!("evidence file count exceeds {MAX_EVIDENCE_FILES}"));
        }
        let size_usize = usize::try_from(size)
            .map_err(|_| ForgeSoupAdapterError::Tar("record size does not fit usize".to_owned()))?;
        let mut payload = vec![0u8; size_usize];
        file.read_exact(&mut payload)
            .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
        let padding = (TAR_BLOCK - (size_usize % TAR_BLOCK)) % TAR_BLOCK;
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            file.read_exact(&mut pad)
                .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
            if pad.iter().any(|byte| *byte != 0) {
                return tar("non-zero tar payload padding");
            }
        }
        let wire: EvidenceRecordWire = serde_json::from_slice(&payload)
            .map_err(|error| ForgeSoupAdapterError::Json(format!("{name}: {error}")))?;
        records.push(validate_evidence_record(
            wire,
            expected_domain_id,
            ModelDigest::sha256_hex(&payload),
        )?);
    }

    if zero_blocks < 2 {
        return tar("tar is missing the required two zero end-of-archive blocks");
    }
    Ok(records)
}

fn validate_evidence_record(
    wire: EvidenceRecordWire,
    expected_domain_id: &str,
    raw_digest: ModelDigest,
) -> Result<ForgeSoupRecordSummary, ForgeSoupAdapterError> {
    match wire {
        EvidenceRecordWire::Verify {
            schema_version,
            candidate_id,
            trial_seed,
            generation,
            domain_id,
            candidate,
            config_sha256,
            dataset_bytes,
            passed,
            returncode,
            elapsed_ns,
            environment,
            environment_fingerprint,
            logs,
            evidence_id,
        } => {
            validate_common_record(
                schema_version,
                &domain_id,
                expected_domain_id,
                &candidate,
                &config_sha256,
                dataset_bytes,
                &environment,
                &environment_fingerprint,
                &logs,
                &evidence_id,
            )?;
            if passed != (returncode == 0) {
                return contract("verify passed flag disagrees with SOUP dry-run return code");
            }
            Ok(ForgeSoupRecordSummary::Verify {
                candidate_id,
                trial_seed,
                generation,
                candidate_values: candidate.values,
                config_sha256,
                dataset_bytes,
                passed,
                returncode,
                elapsed_ns,
                environment_fingerprint,
                source_evidence_id: evidence_id,
                raw_record_digest: raw_digest,
                environment,
                logs,
            })
        }
        EvidenceRecordWire::Measure {
            schema_version,
            candidate_id,
            trial_seed,
            generation,
            domain_id,
            candidate,
            config_sha256,
            dataset_bytes,
            metrics,
            details,
            environment,
            environment_fingerprint,
            logs,
            evidence_id,
        } => {
            validate_common_record(
                schema_version,
                &domain_id,
                expected_domain_id,
                &candidate,
                &config_sha256,
                dataset_bytes,
                &environment,
                &environment_fingerprint,
                &logs,
                &evidence_id,
            )?;
            if metrics.is_empty()
                || metrics
                    .iter()
                    .any(|(name, value)| name.trim().is_empty() || !value.is_finite())
            {
                return contract("measurement metrics are empty or non-finite");
            }
            if !details.is_object() {
                return contract("measurement details must be a JSON object");
            }
            Ok(ForgeSoupRecordSummary::Measure {
                candidate_id,
                trial_seed,
                generation,
                candidate_values: candidate.values,
                config_sha256,
                dataset_bytes,
                metrics,
                environment_fingerprint,
                source_evidence_id: evidence_id,
                raw_record_digest: raw_digest,
                details,
                environment,
                logs,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_common_record(
    schema_version: u16,
    domain_id: &str,
    expected_domain_id: &str,
    candidate: &CandidateEnvelope,
    config_sha256: &str,
    _dataset_bytes: u64,
    environment: &serde_json::Value,
    environment_fingerprint: &str,
    logs: &serde_json::Value,
    evidence_id: &str,
) -> Result<(), ForgeSoupAdapterError> {
    if schema_version != FORGE_SOUP_EVIDENCE_SCHEMA_VERSION {
        return contract(format!(
            "unsupported evaluator evidence schema_version {schema_version}"
        ));
    }
    if domain_id != expected_domain_id {
        return contract("evaluator record domain_id does not match Forge report");
    }
    if candidate.values.is_empty()
        || candidate
            .values
            .iter()
            .any(|(name, value)| name.trim().is_empty() || value.is_empty())
    {
        return contract("evaluator candidate values are structurally invalid");
    }
    require_sha256(config_sha256, "config_sha256")?;
    require_fingerprint(environment_fingerprint)?;
    require_sha256(evidence_id, "source evidence_id")?;
    if !environment.is_object() || !logs.is_object() {
        return contract("evaluator environment/logs must be JSON objects");
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), ForgeSoupAdapterError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return contract(format!("{label} must be a regular non-symlink file"));
    }
    Ok(())
}

fn file_size(path: &Path) -> Result<u64, ForgeSoupAdapterError> {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))
}

fn require_sha256(value: &str, field: &str) -> Result<(), ForgeSoupAdapterError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return contract(format!("{field} must be lowercase SHA-256 hex"));
    }
    Ok(())
}

fn require_fingerprint(value: &str) -> Result<(), ForgeSoupAdapterError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return contract("environment fingerprint must use sha256:<hex>");
    };
    require_sha256(hex, "environment fingerprint")
}

fn validate_evidence_tar_name(name: &str) -> Result<(), ForgeSoupAdapterError> {
    let Some(file) = name.strip_prefix("evidence/") else {
        return tar(format!("unexpected evidence tar path {name:?}"));
    };
    if file.is_empty()
        || file.contains('/')
        || file == "."
        || file == ".."
        || !file.ends_with(".json")
        || !file
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return tar(format!("unsafe or unsupported evidence tar path {name:?}"));
    }
    Ok(())
}

fn read_tar_block(file: &mut File) -> Result<Option<[u8; TAR_BLOCK]>, ForgeSoupAdapterError> {
    let mut block = [0u8; TAR_BLOCK];
    let read = file
        .read(&mut block[..1])
        .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    if read == 0 {
        return Ok(None);
    }
    file.read_exact(&mut block[1..])
        .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    Ok(Some(block))
}

fn validate_tar_checksum(header: &[u8; TAR_BLOCK]) -> Result<(), ForgeSoupAdapterError> {
    let expected = parse_tar_octal(&header[148..156], "checksum")?;
    let actual: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if actual != expected {
        return tar(format!(
            "tar checksum mismatch: expected {expected}, computed {actual}"
        ));
    }
    Ok(())
}

fn parse_tar_octal(bytes: &[u8], field: &str) -> Result<u64, ForgeSoupAdapterError> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return tar(format!("base-256 tar {field} is not accepted"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ForgeSoupAdapterError::Tar(format!("tar {field} is not UTF-8/ASCII")))?
        .trim_matches(['\0', ' ']);
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return tar(format!("tar {field} is not octal"));
    }
    u64::from_str_radix(text, 8)
        .map_err(|error| ForgeSoupAdapterError::Tar(format!("invalid tar {field}: {error}")))
}

fn tar_string(bytes: &[u8], field: &str) -> Result<String, ForgeSoupAdapterError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = std::str::from_utf8(&bytes[..end])
        .map_err(|_| ForgeSoupAdapterError::Tar(format!("tar {field} is not UTF-8")))?;
    Ok(value.to_owned())
}

fn digest_file(path: &Path) -> Result<ModelDigest, ForgeSoupAdapterError> {
    let mut file =
        File::open(path).map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ForgeSoupAdapterError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let bytes = hasher.finalize();
    let mut value = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(ModelDigest {
        algorithm: DigestAlgorithm::Sha256,
        value,
    })
}

fn contract<T>(message: impl Into<String>) -> Result<T, ForgeSoupAdapterError> {
    Err(ForgeSoupAdapterError::Contract(message.into()))
}

fn tar<T>(message: impl Into<String>) -> Result<T, ForgeSoupAdapterError> {
    Err(ForgeSoupAdapterError::Tar(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "scirust-verify-forge-soup-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create test directory");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn report_json() -> String {
        serde_json::json!({
            "schema_version": 1,
            "forge_domain_source_merge": FORGE_SOUP_DOMAIN_MERGE,
            "domain_id": "soup/posttrain-v1",
            "upstream_repository": FORGE_SOUP_REPOSITORY,
            "upstream_commit_id": FORGE_SOUP_QUALIFIED_SOUP_COMMIT,
            "upstream_contract_sha256": "a".repeat(64),
            "verification_adapter_id": "hub/forge-soup-v1",
            "verification_adapter_sha256": "b".repeat(64),
            "engine": {"generations": 2, "population": 4, "survivors": 2, "base_seed": 7},
            "best": {
                "candidate_id": 42,
                "values": {"recipe.learning_rate": "2e-5"},
                "score": {"valid": true, "objectives": [
                    {"name": "benchmark:mmlu", "direction": "maximize", "value": 0.625, "forge_minimized_value": -0.625},
                    {"name": "train_wall_ms", "direction": "minimize", "value": 10.0, "forge_minimized_value": 10.0}
                ]},
                "holdout_score": null
            },
            "final_baseline": null,
            "holdout_best": null,
            "holdout_baseline": null,
            "history": [-0.625],
            "failure_diagnostics": [],
            "final_front": [{
                "candidate_id": 42,
                "values": {"recipe.learning_rate": "2e-5"},
                "score": {"valid": true, "objectives": [
                    {"name": "benchmark:mmlu", "direction": "maximize", "value": 0.625, "forge_minimized_value": -0.625},
                    {"name": "train_wall_ms", "direction": "minimize", "value": 10.0, "forge_minimized_value": 10.0}
                ]},
                "holdout_score": null
            }]
        })
        .to_string()
    }

    fn verify_record(fingerprint: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "phase": "verify",
            "candidate_id": 42,
            "trial_seed": 9,
            "generation": 1,
            "domain_id": "soup/posttrain-v1",
            "candidate": {"values": {"recipe.learning_rate": "2e-5"}},
            "config_sha256": "c".repeat(64),
            "dataset_bytes": 100,
            "passed": true,
            "returncode": 0,
            "elapsed_ns": 1234,
            "environment": {"machine": "test"},
            "environment_fingerprint": fingerprint,
            "logs": {"verify": {"stdout": {"sha256": "d".repeat(64)}}},
            "evidence_id": "e".repeat(64)
        }))
        .unwrap()
    }

    fn measure_record(fingerprint: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "phase": "measure",
            "candidate_id": 42,
            "trial_seed": 9,
            "generation": 1,
            "domain_id": "soup/posttrain-v1",
            "candidate": {"values": {"recipe.learning_rate": "2e-5"}},
            "config_sha256": "c".repeat(64),
            "dataset_bytes": 100,
            "metrics": {"benchmark:mmlu": 0.625, "train_wall_ms": 10.0},
            "details": {"benchmarks": {"mmlu": {"acc,none": 0.625}}},
            "environment": {"machine": "test"},
            "environment_fingerprint": fingerprint,
            "logs": {"train": {"stdout": {"sha256": "d".repeat(64)}}},
            "evidence_id": "f".repeat(64)
        }))
        .unwrap()
    }

    fn write_tar(path: &Path, entries: &[(&str, u8, &[u8])]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create tar");
        for (name, typeflag, payload) in entries {
            let mut header = [0u8; TAR_BLOCK];
            header[..name.len()].copy_from_slice(name.as_bytes());
            write_octal(&mut header[100..108], 0o644);
            write_octal(&mut header[108..116], 0);
            write_octal(&mut header[116..124], 0);
            write_octal(&mut header[124..136], payload.len() as u64);
            write_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = *typeflag;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            let text = format!("{checksum:06o}\0 ");
            header[148..156].copy_from_slice(text.as_bytes());
            file.write_all(&header).unwrap();
            file.write_all(payload).unwrap();
            let padding = (TAR_BLOCK - (payload.len() % TAR_BLOCK)) % TAR_BLOCK;
            file.write_all(&vec![0u8; padding]).unwrap();
        }
        file.write_all(&[0u8; TAR_BLOCK * 2]).unwrap();
    }

    fn write_octal(dst: &mut [u8], value: u64) {
        dst.fill(0);
        let width = dst.len() - 1;
        let text = format!("{value:0width$o}", width = width);
        dst[..width].copy_from_slice(text.as_bytes());
    }

    fn valid_fixture(fingerprint: &str) -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = TempDir::new();
        let report = dir.path.join("report.json");
        let bundle = dir.path.join("evidence.tar");
        fs::write(&report, report_json()).unwrap();
        let verify = verify_record(fingerprint);
        let measure = measure_record(fingerprint);
        write_tar(
            &bundle,
            &[
                ("evidence", b'5', b""),
                ("evidence/verify.json", b'0', verify.as_slice()),
                ("evidence/measure.json", b'0', measure.as_slice()),
            ],
        );
        (dir, report, bundle)
    }

    #[test]
    fn ingests_valid_bundle_without_creating_a_verdict() {
        let fingerprint = format!("sha256:{}", "1".repeat(64));
        let (_dir, report, bundle) = valid_fixture(&fingerprint);
        let ingest = ingest_forge_soup(&report, &bundle).expect("valid bundle");
        assert_eq!(ingest.domain_id(), "soup/posttrain-v1");
        assert_eq!(ingest.records().len(), 2);
        assert_eq!(ingest.final_front_candidate_ids(), [42]);
        assert_eq!(
            ingest.objective_names(),
            ["benchmark:mmlu".to_owned(), "train_wall_ms".to_owned()]
        );
        assert!(ingest
            .limitations()
            .iter()
            .any(|item| item.contains("not_verified_claims")));
        assert!(ingest.observations().iter().any(|observation| {
            observation.kind == "forge_soup_verify"
                && observation.name == "dry_run_passed"
                && observation.value == ObservedValue::Bool(true)
        }));
    }

    #[test]
    fn rejects_report_with_unqualified_forge_source() {
        let fingerprint = format!("sha256:{}", "1".repeat(64));
        let (dir, report, bundle) = valid_fixture(&fingerprint);
        let mut value: serde_json::Value = serde_json::from_str(&report_json()).unwrap();
        value["forge_domain_source_merge"] = serde_json::Value::String("0".repeat(40));
        fs::write(&report, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = ingest_forge_soup(&report, &bundle).expect_err("must reject source drift");
        assert!(error.to_string().contains("qualified SOUP domain"));
        drop(dir);
    }

    #[test]
    fn rejects_tar_links_or_extended_headers() {
        let fingerprint = format!("sha256:{}", "1".repeat(64));
        let (dir, report, bundle) = valid_fixture(&fingerprint);
        fs::remove_file(&bundle).unwrap();
        write_tar(
            &bundle,
            &[("evidence", b'5', b""), ("evidence/link.json", b'2', b"")],
        );
        let error = ingest_forge_soup(&report, &bundle).expect_err("links must fail");
        assert!(error.to_string().contains("unsupported tar entry type"));
        drop(dir);
    }

    #[test]
    fn final_front_requires_executed_measurement_evidence() {
        let fingerprint = format!("sha256:{}", "1".repeat(64));
        let dir = TempDir::new();
        let report = dir.path.join("report.json");
        let bundle = dir.path.join("evidence.tar");
        fs::write(&report, report_json()).unwrap();
        let verify = verify_record(&fingerprint);
        write_tar(
            &bundle,
            &[
                ("evidence", b'5', b""),
                ("evidence/verify.json", b'0', verify.as_slice()),
            ],
        );
        let error = ingest_forge_soup(&report, &bundle).expect_err("missing measure must fail");
        assert!(error
            .to_string()
            .contains("no executed measurement evidence"));
    }

    #[test]
    fn multiple_environments_are_preserved_as_a_limitation() {
        let dir = TempDir::new();
        let report = dir.path.join("report.json");
        let bundle = dir.path.join("evidence.tar");
        fs::write(&report, report_json()).unwrap();
        let first = format!("sha256:{}", "1".repeat(64));
        let second = format!("sha256:{}", "2".repeat(64));
        let verify = verify_record(&first);
        let measure = measure_record(&second);
        write_tar(
            &bundle,
            &[
                ("evidence", b'5', b""),
                ("evidence/verify.json", b'0', verify.as_slice()),
                ("evidence/measure.json", b'0', measure.as_slice()),
            ],
        );
        let ingest = ingest_forge_soup(&report, &bundle).expect("bundle remains ingestible");
        assert!(ingest
            .limitations()
            .iter()
            .any(|item| item.contains("multiple_environment_fingerprints")));
    }

    #[test]
    fn rejects_candidate_recipe_drift_between_evidence_records() {
        let fingerprint = format!("sha256:{}", "1".repeat(64));
        let dir = TempDir::new();
        let report = dir.path.join("report.json");
        let bundle = dir.path.join("evidence.tar");
        fs::write(&report, report_json()).unwrap();
        let verify = verify_record(&fingerprint);
        let mut measure: serde_json::Value =
            serde_json::from_slice(&measure_record(&fingerprint)).unwrap();
        measure["candidate"]["values"]["recipe.learning_rate"] =
            serde_json::Value::String("3e-5".to_owned());
        let measure = serde_json::to_vec(&measure).unwrap();
        write_tar(
            &bundle,
            &[
                ("evidence", b'5', b""),
                ("evidence/verify.json", b'0', verify.as_slice()),
                ("evidence/measure.json", b'0', measure.as_slice()),
            ],
        );
        let error = ingest_forge_soup(&report, &bundle).expect_err("recipe drift must fail");
        assert!(error.to_string().contains("recipe/config/dataset/generation"));
    }

    #[test]
    fn rejects_final_front_recipe_mismatch_against_report() {
        let fingerprint = format!("sha256:{}", "1".repeat(64));
        let dir = TempDir::new();
        let report = dir.path.join("report.json");
        let bundle = dir.path.join("evidence.tar");
        fs::write(&report, report_json()).unwrap();
        let mut verify: serde_json::Value =
            serde_json::from_slice(&verify_record(&fingerprint)).unwrap();
        verify["candidate"]["values"]["recipe.learning_rate"] =
            serde_json::Value::String("3e-5".to_owned());
        let mut measure: serde_json::Value =
            serde_json::from_slice(&measure_record(&fingerprint)).unwrap();
        measure["candidate"]["values"]["recipe.learning_rate"] =
            serde_json::Value::String("3e-5".to_owned());
        let verify = serde_json::to_vec(&verify).unwrap();
        let measure = serde_json::to_vec(&measure).unwrap();
        write_tar(
            &bundle,
            &[
                ("evidence", b'5', b""),
                ("evidence/verify.json", b'0', verify.as_slice()),
                ("evidence/measure.json", b'0', measure.as_slice()),
            ],
        );
        let error = ingest_forge_soup(&report, &bundle).expect_err("report mismatch must fail");
        assert!(error.to_string().contains("does not match Forge report"));
    }
}
