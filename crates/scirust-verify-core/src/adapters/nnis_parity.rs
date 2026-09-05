//! Source-preserving ingestion for qualified NNIS NNML1 parity validation.
//!
//! The adapter independently binds the exact parity-evidence bytes to the
//! producer validation result by SHA-256 and validates the narrow process
//! envelope published by NNIS. It deliberately does not reimplement NNIS
//! checkpoint, tokenizer, greedy-trajectory, logit-tolerance, or promotion
//! semantics.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use scirust_verify_model::{Digest, Observation, ObservedValue};
use serde_json::{Map, Value};
use thiserror::Error;

/// Qualified NNIS process contract consumed by this adapter.
pub const NNIS_PARITY_VALIDATION_CONTRACT: &str = "nnis.nnml1.parity-validation@1.0.0";
/// Media type of the NNIS validation result.
pub const NNIS_PARITY_VALIDATION_MEDIA_TYPE: &str =
    "application/vnd.nnis.nnml1.parity-validation.v1+json";
/// Media type of the original NNIS parity-evidence artifact.
pub const NNIS_PARITY_EVIDENCE_MEDIA_TYPE: &str =
    "application/vnd.nnis.nnml1.parity-evidence.v1+json";
/// Exact NNIS PR head qualified when this adapter was published.
pub const NNIS_PARITY_SOURCE_HEAD: &str = "c74b6b04c45e320c86cdd973b31f49f43c720681";
/// Exact NNIS merge commit qualified when this adapter was published.
pub const NNIS_PARITY_SOURCE_MERGE: &str = "0ae4b0d4659c8de9b8a8322ed6ab7f8e110b53f2";
/// Maximum accepted original parity-evidence artifact size.
pub const NNIS_PARITY_EVIDENCE_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum accepted NNIS validation-result artifact size.
pub const NNIS_PARITY_VALIDATION_MAX_BYTES: usize = 1024 * 1024;
/// NNIS exact-checkpoint parity record kind preserved by the adapter.
pub const NNIS_PARITY_RECORD_KIND: &str = "nnis-nnml1-reference-parity-record-v1";
/// NNIS same-head parity suite kind preserved by the adapter.
pub const NNIS_PARITY_SUITE_KIND: &str = "nnis-nnml1-multi-model-parity-suite-v1";
const VALIDATION_SCOPE: &str = "nnml1_exact_checkpoint_parity_contract_only";
const MAX_LIST_ITEMS: usize = 64;
const MAX_TEXT_BYTES: usize = 4096;

/// Validated cross-artifact binding between original NNIS parity evidence and
/// the qualified NNIS validation result.
#[derive(Clone, Debug)]
pub struct NnisParityIngest {
    evidence_digest: Digest,
    validation_digest: Digest,
    evidence_kind: String,
    execution_git_commit: String,
    distinct_checkpoint_count: u32,
    checkpoint_specs: Vec<String>,
    parity_levels: Vec<String>,
    reference_runtimes: Vec<String>,
    execution_backends: Vec<String>,
}

impl NnisParityIngest {
    /// Digest of the exact original parity-evidence bytes.
    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    /// Digest of the exact NNIS validation-result bytes.
    pub fn validation_digest(&self) -> &Digest {
        &self.validation_digest
    }

    /// Producer evidence kind (`record` or same-head `suite`).
    pub fn evidence_kind(&self) -> &str {
        &self.evidence_kind
    }

    /// Exact clean NNIS Git commit reported for the validated evidence.
    pub fn execution_git_commit(&self) -> &str {
        &self.execution_git_commit
    }

    /// Count of distinct exact checkpoint specifications in the validated artifact.
    pub const fn distinct_checkpoint_count(&self) -> u32 {
        self.distinct_checkpoint_count
    }

    /// Exact checkpoint specification names preserved from the NNIS result.
    pub fn checkpoint_specs(&self) -> &[String] {
        &self.checkpoint_specs
    }

    /// NNIS parity levels preserved without reinterpretation.
    pub fn parity_levels(&self) -> &[String] {
        &self.parity_levels
    }

    /// Trusted-reference runtime identities preserved from the NNIS result.
    pub fn reference_runtimes(&self) -> &[String] {
        &self.reference_runtimes
    }

    /// NNIS execution backend identities preserved from the NNIS result.
    pub fn execution_backends(&self) -> &[String] {
        &self.execution_backends
    }

    /// Converts the validated binding and producer-owned facts into observations.
    pub fn observations(&self) -> Vec<Observation> {
        vec![
            Observation::new(
                "nnis_parity",
                "source_contract",
                ObservedValue::Text(NNIS_PARITY_VALIDATION_CONTRACT.to_owned()),
            ),
            Observation::new(
                "nnis_parity",
                "source_merge",
                ObservedValue::Text(NNIS_PARITY_SOURCE_MERGE.to_owned()),
            ),
            Observation::new(
                "nnis_parity",
                "evidence_kind",
                ObservedValue::Text(self.evidence_kind.clone()),
            ),
            Observation::new(
                "nnis_parity",
                "evidence_sha256",
                ObservedValue::Text(self.evidence_digest.value.clone()),
            ),
            Observation::new(
                "nnis_parity",
                "validation_sha256",
                ObservedValue::Text(self.validation_digest.value.clone()),
            ),
            Observation::new(
                "nnis_parity",
                "execution_git_commit",
                ObservedValue::Text(self.execution_git_commit.clone()),
            ),
            Observation::new(
                "nnis_parity",
                "checkpoint_specs",
                ObservedValue::Json(serde_json::json!(self.checkpoint_specs)),
            ),
            Observation::new(
                "nnis_parity",
                "parity_levels",
                ObservedValue::Json(serde_json::json!(self.parity_levels)),
            ),
            Observation::new(
                "nnis_parity",
                "reference_runtimes",
                ObservedValue::Json(serde_json::json!(self.reference_runtimes)),
            ),
            Observation::new(
                "nnis_parity",
                "execution_backends",
                ObservedValue::Json(serde_json::json!(self.execution_backends)),
            ),
            Observation::new(
                "nnis_parity",
                "producer_non_claims",
                ObservedValue::Json(serde_json::json!({
                    "promotion_authorized": false,
                    "serving_performance_verified": false,
                    "general_model_family_support_verified": false,
                })),
            ),
        ]
    }

    /// Explicit limitations retained in every dossier using this adapter.
    pub fn limitations() -> impl Iterator<Item = &'static str> {
        [
            "SciRust-Verify independently checks the SHA-256 binding between the original NNIS parity-evidence bytes and the NNIS validation result, but does not reimplement NNIS checkpoint, tokenizer, greedy-trajectory, logit-tolerance, or same-head composition semantics.",
            "The NNIS validation result is producer-owned evidence; authentic origin of that result requires trusted execution/orchestration provenance for the qualified NNIS process.",
            "The adapter does not rerun NNIS, Transformers, CUDA, a checkpoint, or a reference campaign and therefore does not create new physical model-parity evidence.",
            "NNIS parity levels remain scoped source facts. This adapter does not establish general model-family support, serving performance, cross-host portability, or runtime/model-family promotion authorization.",
        ]
        .into_iter()
    }
}

/// Errors raised while reading or binding NNIS parity artifacts.
#[derive(Debug, Error)]
pub enum NnisParityAdapterError {
    /// One supplied artifact is not a regular non-symlink file.
    #[error("NNIS parity artifact is not a regular file: {0}")]
    NotRegularFile(&'static str),
    /// One supplied artifact exceeds its fixed byte bound.
    #[error("NNIS parity artifact exceeds its byte bound: {0}")]
    TooLarge(&'static str),
    /// JSON decoding failed.
    #[error("invalid NNIS parity JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The artifacts are valid JSON but violate the qualified binding contract.
    #[error("invalid NNIS parity evidence binding: {0}")]
    Invalid(String),
    /// An artifact could not be inspected or read.
    #[error("cannot read NNIS parity artifact: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads the original NNIS parity evidence and its qualified validation result,
/// validates the result envelope, and independently checks the exact-byte SHA-256
/// binding between them.
pub fn ingest_nnis_parity(
    evidence_path: &Path,
    validation_path: &Path,
) -> Result<NnisParityIngest, NnisParityAdapterError> {
    let evidence_bytes = read_regular_bounded(
        evidence_path,
        NNIS_PARITY_EVIDENCE_MAX_BYTES,
        "parity_evidence",
    )?;
    let validation_bytes = read_regular_bounded(
        validation_path,
        NNIS_PARITY_VALIDATION_MAX_BYTES,
        "validation",
    )?;
    let evidence_digest = Digest::sha256_hex(&evidence_bytes);
    let validation_digest = Digest::sha256_hex(&validation_bytes);
    let evidence_root: Value = serde_json::from_slice(&evidence_bytes)?;
    let validation_root: Value = serde_json::from_slice(&validation_bytes)?;
    ingest_values(
        evidence_root,
        validation_root,
        evidence_digest,
        validation_digest,
    )
}

fn ingest_values(
    evidence_root: Value,
    validation_root: Value,
    evidence_digest: Digest,
    validation_digest: Digest,
) -> Result<NnisParityIngest, NnisParityAdapterError> {
    let evidence_object = evidence_root
        .as_object()
        .ok_or_else(|| invalid("parity_evidence root must be an object"))?;
    let evidence_kind = require_bounded_text(evidence_object.get("kind"), "parity_evidence.kind")?;
    if evidence_kind != NNIS_PARITY_RECORD_KIND && evidence_kind != NNIS_PARITY_SUITE_KIND {
        return Err(invalid("unsupported parity_evidence kind"));
    }
    let evidence_commit = require_git_commit(
        evidence_object.get("execution_git_commit"),
        "parity_evidence.execution_git_commit",
    )?;

    let object = validation_root
        .as_object()
        .ok_or_else(|| invalid("validation root must be an object"))?;
    require_exact_keys(
        object,
        &[
            "schema_version",
            "contract",
            "media_type",
            "status",
            "validation_scope",
            "source",
            "execution_git_commit",
            "distinct_checkpoint_count",
            "checkpoint_specs",
            "parity_levels",
            "reference_runtimes",
            "execution_backends",
            "promotion_authorized",
            "serving_performance_verified",
            "general_model_family_support_verified",
            "claim_boundary",
        ],
        "validation",
    )?;
    if require_u64(object.get("schema_version"), "schema_version")? != 1 {
        return Err(invalid("unsupported validation schema_version"));
    }
    if require_string(object.get("contract"), "contract")? != NNIS_PARITY_VALIDATION_CONTRACT {
        return Err(invalid("unsupported validation contract"));
    }
    if require_string(object.get("media_type"), "media_type")? != NNIS_PARITY_VALIDATION_MEDIA_TYPE {
        return Err(invalid("unsupported validation media_type"));
    }
    if require_string(object.get("status"), "status")? != "validated" {
        return Err(invalid("validation status must be validated"));
    }
    if require_string(object.get("validation_scope"), "validation_scope")? != VALIDATION_SCOPE {
        return Err(invalid("unsupported validation_scope"));
    }

    let source = require_object(object.get("source"), "source")?;
    require_exact_keys(source, &["media_type", "kind", "sha256"], "source")?;
    if require_string(source.get("media_type"), "source.media_type")?
        != NNIS_PARITY_EVIDENCE_MEDIA_TYPE
    {
        return Err(invalid("unsupported source.media_type"));
    }
    if require_string(source.get("kind"), "source.kind")? != evidence_kind {
        return Err(invalid("source.kind does not match parity_evidence.kind"));
    }
    let referenced_sha = require_sha(source.get("sha256"), "source.sha256")?;
    if referenced_sha != evidence_digest.value {
        return Err(invalid(
            "source.sha256 does not match the exact supplied parity_evidence bytes",
        ));
    }

    let execution_git_commit = require_git_commit(
        object.get("execution_git_commit"),
        "execution_git_commit",
    )?;
    if execution_git_commit != evidence_commit {
        return Err(invalid(
            "validation execution_git_commit does not match parity_evidence",
        ));
    }

    let distinct_checkpoint_count_u64 = require_u64(
        object.get("distinct_checkpoint_count"),
        "distinct_checkpoint_count",
    )?;
    let distinct_checkpoint_count = u32::try_from(distinct_checkpoint_count_u64)
        .map_err(|_| invalid("distinct_checkpoint_count exceeds u32"))?;
    if distinct_checkpoint_count == 0 || distinct_checkpoint_count as usize > MAX_LIST_ITEMS {
        return Err(invalid("distinct_checkpoint_count is out of bounds"));
    }

    let checkpoint_specs = require_unique_text_array(
        object.get("checkpoint_specs"),
        "checkpoint_specs",
        MAX_LIST_ITEMS,
    )?;
    if checkpoint_specs.len() != distinct_checkpoint_count as usize {
        return Err(invalid(
            "checkpoint_specs length does not match distinct_checkpoint_count",
        ));
    }
    if evidence_kind == NNIS_PARITY_RECORD_KIND && distinct_checkpoint_count != 1 {
        return Err(invalid(
            "reference-parity record validation must contain one checkpoint",
        ));
    }
    if evidence_kind == NNIS_PARITY_SUITE_KIND && distinct_checkpoint_count < 2 {
        return Err(invalid(
            "multi-model parity suite validation must contain at least two checkpoints",
        ));
    }

    let parity_levels = require_unique_text_array(
        object.get("parity_levels"),
        "parity_levels",
        MAX_LIST_ITEMS,
    )?;
    for level in &parity_levels {
        if level != "generation_trajectory" && level != "logit_and_generation" {
            return Err(invalid("unsupported NNIS parity level"));
        }
    }
    let reference_runtimes = require_unique_text_array(
        object.get("reference_runtimes"),
        "reference_runtimes",
        MAX_LIST_ITEMS,
    )?;
    let execution_backends = require_unique_text_array(
        object.get("execution_backends"),
        "execution_backends",
        MAX_LIST_ITEMS,
    )?;

    for field in [
        "promotion_authorized",
        "serving_performance_verified",
        "general_model_family_support_verified",
    ] {
        if object.get(field).and_then(Value::as_bool) != Some(false) {
            return Err(invalid(format!("{field} must be false")));
        }
    }
    let claim_boundary = require_bounded_text(object.get("claim_boundary"), "claim_boundary")?;
    if !claim_boundary.contains("does not authorize runtime/model-family promotion")
        || !claim_boundary.contains("general model-family support")
        || !claim_boundary.contains("serving performance")
    {
        return Err(invalid("claim_boundary omits required NNIS non-claims"));
    }

    Ok(NnisParityIngest {
        evidence_digest,
        validation_digest,
        evidence_kind,
        execution_git_commit,
        distinct_checkpoint_count,
        checkpoint_specs,
        parity_levels,
        reference_runtimes,
        execution_backends,
    })
}

fn read_regular_bounded(
    path: &Path,
    max_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, NnisParityAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(NnisParityAdapterError::NotRegularFile(label));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes as u64 {
        return Err(NnisParityAdapterError::TooLarge(label));
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(NnisParityAdapterError::TooLarge(label));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid(format!("{label} size changed while reading")));
    }
    Ok(bytes)
}

fn require_object<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, NnisParityAdapterError> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(format!("{field} must be an object")))
}

fn require_string<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<&'a str, NnisParityAdapterError> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field} must be a string")))
}

fn require_u64(value: Option<&Value>, field: &str) -> Result<u64, NnisParityAdapterError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("{field} must be an unsigned integer")))
}

fn require_bounded_text(
    value: Option<&Value>,
    field: &str,
) -> Result<String, NnisParityAdapterError> {
    let text = require_string(value, field)?;
    if text.is_empty() || text.len() > MAX_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} is empty, oversized, or contains controls"
        )));
    }
    Ok(text.to_owned())
}

fn require_sha(value: Option<&Value>, field: &str) -> Result<String, NnisParityAdapterError> {
    let digest = require_string(value, field)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{field} must be a lowercase SHA-256 hex digest"
        )));
    }
    Ok(digest.to_owned())
}

fn require_git_commit(
    value: Option<&Value>,
    field: &str,
) -> Result<String, NnisParityAdapterError> {
    let commit = require_string(value, field)?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{field} must be a lowercase 40-hex Git commit"
        )));
    }
    Ok(commit.to_owned())
}

fn require_unique_text_array(
    value: Option<&Value>,
    field: &str,
    max_items: usize,
) -> Result<Vec<String>, NnisParityAdapterError> {
    let array = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{field} must be an array")))?;
    if array.is_empty() || array.len() > max_items {
        return Err(invalid(format!(
            "{field} must contain 1..={max_items} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(array.len());
    for item in array {
        let text = require_bounded_text(Some(item), field)?;
        if !seen.insert(text.clone()) {
            return Err(invalid(format!("{field} contains duplicate entries")));
        }
        output.push(text);
    }
    Ok(output)
}

fn require_exact_keys(
    object: &Map<String, Value>,
    expected: &[&str],
    field: &str,
) -> Result<(), NnisParityAdapterError> {
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(invalid(format!(
            "{field} contains missing or unknown fields"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> NnisParityAdapterError {
    NnisParityAdapterError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(commit: &str) -> Value {
        serde_json::json!({
            "schema_version": 1,
            "kind": NNIS_PARITY_RECORD_KIND,
            "execution_git_commit": commit,
            "promotion_authorized": false
        })
    }

    fn validation_for(evidence: &Value, digest: &Digest, commit: &str) -> Value {
        serde_json::json!({
            "schema_version": 1,
            "contract": NNIS_PARITY_VALIDATION_CONTRACT,
            "media_type": NNIS_PARITY_VALIDATION_MEDIA_TYPE,
            "status": "validated",
            "validation_scope": VALIDATION_SCOPE,
            "source": {
                "media_type": NNIS_PARITY_EVIDENCE_MEDIA_TYPE,
                "kind": evidence["kind"],
                "sha256": digest.value,
            },
            "execution_git_commit": commit,
            "distinct_checkpoint_count": 1,
            "checkpoint_specs": ["smollm2-135m-bf16"],
            "parity_levels": ["logit_and_generation"],
            "reference_runtimes": ["transformers@4.40.1"],
            "execution_backends": ["nnis-cuda"],
            "promotion_authorized": false,
            "serving_performance_verified": false,
            "general_model_family_support_verified": false,
            "claim_boundary": "NNIS exact-checkpoint parity evidence contract validation only; this result does not authorize runtime/model-family promotion, establish general model-family support, or establish serving performance"
        })
    }

    #[test]
    fn accepts_exact_byte_binding_without_reinterpreting_nnis_semantics() {
        let commit = "c".repeat(40);
        let evidence = record(&commit);
        let evidence_bytes = serde_json::to_vec(&evidence).unwrap();
        let evidence_digest = Digest::sha256_hex(&evidence_bytes);
        let validation = validation_for(&evidence, &evidence_digest, &commit);
        let ingest = ingest_values(
            evidence,
            validation,
            evidence_digest,
            Digest::sha256_hex(b"validation"),
        )
        .unwrap();
        assert_eq!(ingest.distinct_checkpoint_count(), 1);
        assert_eq!(ingest.parity_levels(), ["logit_and_generation"]);
        assert!(NnisParityIngest::limitations()
            .any(|limit| limit.contains("does not reimplement NNIS")));
    }

    #[test]
    fn rejects_validation_detached_from_exact_evidence_bytes() {
        let commit = "c".repeat(40);
        let evidence = record(&commit);
        let correct_digest = Digest::sha256_hex(&serde_json::to_vec(&evidence).unwrap());
        let mut validation = validation_for(&evidence, &correct_digest, &commit);
        validation["source"]["sha256"] = Value::String("0".repeat(64));
        assert!(ingest_values(
            evidence,
            validation,
            correct_digest,
            Digest::sha256_hex(b"validation")
        )
        .is_err());
    }

    #[test]
    fn rejects_promotion_or_serving_claim_inflation() {
        let commit = "c".repeat(40);
        let evidence = record(&commit);
        let digest = Digest::sha256_hex(&serde_json::to_vec(&evidence).unwrap());
        let mut validation = validation_for(&evidence, &digest, &commit);
        validation["promotion_authorized"] = Value::Bool(true);
        assert!(ingest_values(
            evidence,
            validation,
            digest,
            Digest::sha256_hex(b"validation")
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_validation_fields() {
        let commit = "c".repeat(40);
        let evidence = record(&commit);
        let digest = Digest::sha256_hex(&serde_json::to_vec(&evidence).unwrap());
        let mut validation = validation_for(&evidence, &digest, &commit);
        validation["unexpected"] = Value::Bool(true);
        assert!(ingest_values(
            evidence,
            validation,
            digest,
            Digest::sha256_hex(b"validation")
        )
        .is_err());
    }
}
