//! Source-preserving ingestion for SciCapsule Hub execution evidence v2.
//!
//! The adapter validates the published `capsule.execute@2.0.0` result shape and
//! preserves SciCapsule trust and bounded-execution facts as observations. It
//! never converts a SciCapsule trust decision into a scientific correctness
//! verdict and never describes bounded process execution as an OS sandbox.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use scirust_verify_model::{Digest, Observation, ObservedValue};
use serde_json::{Map, Value};
use thiserror::Error;

/// Published SciCapsule execution-evidence process contract accepted by this adapter.
pub const SCICAPSULE_EXECUTION_CONTRACT: &str = "capsule.execute@2.0.0";
/// Media type of the qualified SciCapsule Hub execution result.
pub const SCICAPSULE_EXECUTION_MEDIA_TYPE: &str =
    "application/vnd.scicapsule.hub-run-result.v2+json";
/// Media type of the v1 result embedded by identity in the v2 result.
pub const SCICAPSULE_SOURCE_RESULT_MEDIA_TYPE: &str =
    "application/vnd.scicapsule.hub-run-result.v1+json";
/// Exact SciCapsule PR head qualified when this adapter was published.
pub const SCICAPSULE_SOURCE_HEAD: &str = "bb79eea787f0d9562585b27dd38f5f57fa5b5ea9";
/// Exact SciCapsule merge commit qualified when this adapter was published.
pub const SCICAPSULE_SOURCE_MERGE: &str = "31e4a825c8a45837ce4f8ff69f936b46e53d3b82";
/// Maximum accepted SciCapsule execution-evidence artifact size in bytes.
pub const SCICAPSULE_EXECUTION_MAX_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURES: usize = 64;
const MAX_SIGNERS: usize = 64;
const MAX_TEXT_BYTES: usize = 4096;

/// Runtime identity preserved from one qualified SciCapsule v2 result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SciCapsuleRuntimeIdentity {
    /// SHA-256 identity reported for the v2 launcher binary.
    pub launcher_sha256: String,
    /// SHA-256 identity reported for the invoked SciCapsule binary.
    pub scicapsule_sha256: String,
    /// SciCapsule package version compiled into the producer.
    pub package_version: String,
}

/// Execution environment scope preserved from one qualified SciCapsule v2 result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SciCapsuleEnvironmentScope {
    /// Producer-reported operating system identifier.
    pub os: String,
    /// Producer-reported architecture identifier.
    pub arch: String,
    /// Qualified execution mode. V2 requires `bounded_process_unix`.
    pub execution_mode: String,
    /// Qualified sandbox declaration. V2 requires `none`.
    pub sandbox: String,
}

/// Validated, source-preserving view of one SciCapsule v2 execution result.
#[derive(Clone, Debug)]
pub struct SciCapsuleExecutionIngest {
    digest: Digest,
    capsule_sha256: String,
    policy_sha256: String,
    request_sha256: String,
    signature_envelope_sha256: Vec<String>,
    capsule_name: String,
    entrypoint: String,
    matched_signers: Vec<String>,
    required_signatures: u32,
    runtime: SciCapsuleRuntimeIdentity,
    environment: SciCapsuleEnvironmentScope,
    source_result_sha256: String,
}

impl SciCapsuleExecutionIngest {
    /// Returns the digest of the exact ingested v2 result bytes.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns the source-reported exact capsule SHA-256 identity.
    pub fn capsule_sha256(&self) -> &str {
        &self.capsule_sha256
    }

    /// Returns the source-reported exact trust-policy SHA-256 identity.
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    /// Returns the source-reported exact serialized Hub-request SHA-256 identity.
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    /// Returns producer-reported deterministic signature-envelope value identities.
    pub fn signature_envelope_sha256(&self) -> &[String] {
        &self.signature_envelope_sha256
    }

    /// Returns the capsule manifest name preserved by SciCapsule.
    pub fn capsule_name(&self) -> &str {
        &self.capsule_name
    }

    /// Returns the capsule entrypoint preserved by SciCapsule.
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Returns trusted signer identifiers matched by the SciCapsule trust policy.
    pub fn matched_signers(&self) -> &[String] {
        &self.matched_signers
    }

    /// Returns the threshold required by the SciCapsule trust policy.
    pub const fn required_signatures(&self) -> u32 {
        self.required_signatures
    }

    /// Returns the producer runtime identity.
    pub fn runtime(&self) -> &SciCapsuleRuntimeIdentity {
        &self.runtime
    }

    /// Returns the producer execution environment scope.
    pub fn environment(&self) -> &SciCapsuleEnvironmentScope {
        &self.environment
    }

    /// Returns the SHA-256 identity of the authoritative source v1 execution result.
    pub fn source_result_sha256(&self) -> &str {
        &self.source_result_sha256
    }

    /// Converts validated source facts into SciRust-Verify observations without reinterpreting trust.
    pub fn observations(&self) -> Vec<Observation> {
        vec![
            Observation::new(
                "scicapsule",
                "source_contract",
                ObservedValue::Text(SCICAPSULE_EXECUTION_CONTRACT.to_owned()),
            ),
            Observation::new(
                "scicapsule",
                "source_merge",
                ObservedValue::Text(SCICAPSULE_SOURCE_MERGE.to_owned()),
            ),
            Observation::new(
                "scicapsule",
                "capsule_sha256",
                ObservedValue::Text(self.capsule_sha256.clone()),
            ),
            Observation::new(
                "scicapsule",
                "policy_sha256",
                ObservedValue::Text(self.policy_sha256.clone()),
            ),
            Observation::new(
                "scicapsule",
                "request_sha256",
                ObservedValue::Text(self.request_sha256.clone()),
            ),
            Observation::new(
                "scicapsule",
                "signature_envelope_sha256",
                ObservedValue::Json(serde_json::json!(self.signature_envelope_sha256)),
            ),
            Observation::new(
                "scicapsule",
                "trust_decision",
                ObservedValue::Json(serde_json::json!({
                    "matched_signers": self.matched_signers,
                    "required_signatures": self.required_signatures,
                    "trust_is_scientific_verdict": false,
                })),
            ),
            Observation::new(
                "scicapsule",
                "runtime_identity",
                ObservedValue::Json(serde_json::json!({
                    "launcher_sha256": self.runtime.launcher_sha256,
                    "scicapsule_sha256": self.runtime.scicapsule_sha256,
                    "package_version": self.runtime.package_version,
                })),
            ),
            Observation::new(
                "scicapsule",
                "environment_scope",
                ObservedValue::Json(serde_json::json!({
                    "os": self.environment.os,
                    "arch": self.environment.arch,
                    "execution_mode": self.environment.execution_mode,
                    "sandbox": self.environment.sandbox,
                })),
            ),
            Observation::new(
                "scicapsule",
                "source_result_sha256",
                ObservedValue::Text(self.source_result_sha256.clone()),
            ),
        ]
    }

    /// Returns explicit non-claims that accompany every SciCapsule v2 evidence ingestion.
    pub fn limitations() -> impl Iterator<Item = &'static str> {
        [
            "SciCapsule trust authorization is a source fact, not a SciRust-Verify scientific correctness verdict.",
            "The adapter validates the v2 result structure but does not independently rehash the capsule, policy, request, signatures, or runtime binaries because those source bytes are not inputs to this adapter.",
            "The qualified execution mode is bounded_process_unix with sandbox=none; no OS sandbox, filesystem, network, syscall, CPU, memory, or device isolation claim is established.",
            "No model-quality, numerical-correctness, performance-superiority, cross-host, or hardware-portability claim is established by this adapter.",
        ]
        .into_iter()
    }
}

/// Errors raised while validating or reading qualified SciCapsule v2 execution evidence.
#[derive(Debug, Error)]
pub enum SciCapsuleAdapterError {
    /// The supplied path is not a regular non-symlink file.
    #[error("SciCapsule execution evidence is not a regular file")]
    NotRegularFile,
    /// The supplied artifact exceeds the adapter's fixed byte bound.
    #[error("SciCapsule execution evidence exceeds {SCICAPSULE_EXECUTION_MAX_BYTES} bytes")]
    TooLarge,
    /// The supplied bytes are not valid JSON.
    #[error("invalid SciCapsule execution evidence JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The JSON is valid but violates the qualified v2 contract.
    #[error("invalid SciCapsule execution evidence: {0}")]
    Invalid(String),
    /// The artifact could not be inspected or read from storage.
    #[error("cannot read SciCapsule execution evidence: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads and validates one qualified SciCapsule Hub execution result v2 file.
pub fn ingest_scicapsule_execution(
    path: &Path,
) -> Result<SciCapsuleExecutionIngest, SciCapsuleAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SciCapsuleAdapterError::NotRegularFile);
    }
    if metadata.len() > SCICAPSULE_EXECUTION_MAX_BYTES as u64 {
        return Err(SciCapsuleAdapterError::TooLarge);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > SCICAPSULE_EXECUTION_MAX_BYTES {
        return Err(SciCapsuleAdapterError::TooLarge);
    }
    let digest = Digest::sha256_hex(&bytes);
    let root: Value = serde_json::from_slice(&bytes)?;
    ingest_value(root, digest)
}

fn ingest_value(
    root: Value,
    digest: Digest,
) -> Result<SciCapsuleExecutionIngest, SciCapsuleAdapterError> {
    let object = root
        .as_object()
        .ok_or_else(|| invalid("root must be an object"))?;
    require_exact_keys(
        object,
        &[
            "schema_version",
            "contract",
            "media_type",
            "status",
            "capsule_sha256",
            "policy_sha256",
            "request_sha256",
            "signature_envelope_sha256",
            "capsule_name",
            "entrypoint",
            "matched_signers",
            "required_signatures",
            "runtime",
            "environment_scope",
            "source_result",
            "trust_is_scientific_verdict",
        ],
        "root",
    )?;
    require_u64(object.get("schema_version"), "schema_version")?
        .eq(&2)
        .then_some(())
        .ok_or_else(|| invalid("unsupported schema_version"))?;
    require_string(object.get("contract"), "contract")?
        .eq(SCICAPSULE_EXECUTION_CONTRACT)
        .then_some(())
        .ok_or_else(|| invalid("unsupported contract"))?;
    require_string(object.get("media_type"), "media_type")?
        .eq(SCICAPSULE_EXECUTION_MEDIA_TYPE)
        .then_some(())
        .ok_or_else(|| invalid("unsupported media_type"))?;
    require_string(object.get("status"), "status")?
        .eq("succeeded")
        .then_some(())
        .ok_or_else(|| invalid("qualified v2 adapter requires status=succeeded"))?;
    if object
        .get("trust_is_scientific_verdict")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(invalid("trust_is_scientific_verdict must be false"));
    }

    let capsule_sha256 = require_sha(object.get("capsule_sha256"), "capsule_sha256")?;
    let policy_sha256 = require_sha(object.get("policy_sha256"), "policy_sha256")?;
    let request_sha256 = require_sha(object.get("request_sha256"), "request_sha256")?;

    let signature_envelope_sha256 = require_sha_array(
        object.get("signature_envelope_sha256"),
        "signature_envelope_sha256",
        MAX_SIGNATURES,
    )?;
    if signature_envelope_sha256.is_empty() {
        return Err(invalid("signature_envelope_sha256 must not be empty"));
    }

    let capsule_name = require_bounded_text(object.get("capsule_name"), "capsule_name")?;
    let entrypoint = require_bounded_text(object.get("entrypoint"), "entrypoint")?;
    let matched_signers = require_unique_text_array(
        object.get("matched_signers"),
        "matched_signers",
        MAX_SIGNERS,
    )?;
    let required_signatures_u64 = require_u64(
        object.get("required_signatures"),
        "required_signatures",
    )?;
    let required_signatures = u32::try_from(required_signatures_u64)
        .map_err(|_| invalid("required_signatures exceeds u32"))?;
    if required_signatures == 0
        || usize::try_from(required_signatures).unwrap_or(usize::MAX) > matched_signers.len()
        || usize::try_from(required_signatures).unwrap_or(usize::MAX)
            > signature_envelope_sha256.len()
    {
        return Err(invalid(
            "required_signatures must be positive and covered by matched signers and request signatures",
        ));
    }

    let runtime_object = require_object(object.get("runtime"), "runtime")?;
    require_exact_keys(
        runtime_object,
        &["launcher_sha256", "scicapsule_sha256", "package_version"],
        "runtime",
    )?;
    let runtime = SciCapsuleRuntimeIdentity {
        launcher_sha256: require_sha(runtime_object.get("launcher_sha256"), "launcher_sha256")?,
        scicapsule_sha256: require_sha(
            runtime_object.get("scicapsule_sha256"),
            "scicapsule_sha256",
        )?,
        package_version: require_bounded_text(
            runtime_object.get("package_version"),
            "package_version",
        )?,
    };

    let environment_object = require_object(object.get("environment_scope"), "environment_scope")?;
    require_exact_keys(
        environment_object,
        &["os", "arch", "execution_mode", "sandbox"],
        "environment_scope",
    )?;
    let environment = SciCapsuleEnvironmentScope {
        os: require_bounded_text(environment_object.get("os"), "os")?,
        arch: require_bounded_text(environment_object.get("arch"), "arch")?,
        execution_mode: require_bounded_text(
            environment_object.get("execution_mode"),
            "execution_mode",
        )?,
        sandbox: require_bounded_text(environment_object.get("sandbox"), "sandbox")?,
    };
    if environment.execution_mode != "bounded_process_unix" || environment.sandbox != "none" {
        return Err(invalid(
            "qualified v2 environment requires execution_mode=bounded_process_unix and sandbox=none",
        ));
    }

    let source_result = require_object(object.get("source_result"), "source_result")?;
    require_exact_keys(
        source_result,
        &["schema_version", "media_type", "sha256"],
        "source_result",
    )?;
    if require_u64(source_result.get("schema_version"), "source_result.schema_version")? != 1 {
        return Err(invalid("source_result.schema_version must be 1"));
    }
    if require_string(source_result.get("media_type"), "source_result.media_type")?
        != SCICAPSULE_SOURCE_RESULT_MEDIA_TYPE
    {
        return Err(invalid("source_result.media_type is unsupported"));
    }
    let source_result_sha256 = require_sha(source_result.get("sha256"), "source_result.sha256")?;

    Ok(SciCapsuleExecutionIngest {
        digest,
        capsule_sha256,
        policy_sha256,
        request_sha256,
        signature_envelope_sha256,
        capsule_name,
        entrypoint,
        matched_signers,
        required_signatures,
        runtime,
        environment,
        source_result_sha256,
    })
}

fn require_object<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, SciCapsuleAdapterError> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(format!("{field} must be an object")))
}

fn require_string<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<&'a str, SciCapsuleAdapterError> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field} must be a string")))
}

fn require_u64(value: Option<&Value>, field: &str) -> Result<u64, SciCapsuleAdapterError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(format!("{field} must be an unsigned integer")))
}

fn require_bounded_text(
    value: Option<&Value>,
    field: &str,
) -> Result<String, SciCapsuleAdapterError> {
    let text = require_string(value, field)?;
    if text.is_empty() || text.len() > MAX_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} is empty, oversized, or contains controls"
        )));
    }
    Ok(text.to_owned())
}

fn require_sha(value: Option<&Value>, field: &str) -> Result<String, SciCapsuleAdapterError> {
    let digest = require_string(value, field)?;
    if !is_lower_hex_sha256(digest) {
        return Err(invalid(format!("{field} must be a lowercase SHA-256 hex digest")));
    }
    Ok(digest.to_owned())
}

fn require_sha_array(
    value: Option<&Value>,
    field: &str,
    max_items: usize,
) -> Result<Vec<String>, SciCapsuleAdapterError> {
    let array = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{field} must be an array")))?;
    if array.len() > max_items {
        return Err(invalid(format!("{field} exceeds item bound")));
    }
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(array.len());
    for item in array {
        let digest = require_sha(Some(item), field)?;
        if !seen.insert(digest.clone()) {
            return Err(invalid(format!("{field} contains duplicate identities")));
        }
        output.push(digest);
    }
    Ok(output)
}

fn require_unique_text_array(
    value: Option<&Value>,
    field: &str,
    max_items: usize,
) -> Result<Vec<String>, SciCapsuleAdapterError> {
    let array = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{field} must be an array")))?;
    if array.is_empty() || array.len() > max_items {
        return Err(invalid(format!("{field} must contain 1..={max_items} entries")));
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
) -> Result<(), SciCapsuleAdapterError> {
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(invalid(format!("{field} contains missing or unknown fields")));
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(message: impl Into<String>) -> SciCapsuleAdapterError {
    SciCapsuleAdapterError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn valid_value() -> Value {
        serde_json::json!({
            "schema_version": 2,
            "contract": SCICAPSULE_EXECUTION_CONTRACT,
            "media_type": SCICAPSULE_EXECUTION_MEDIA_TYPE,
            "status": "succeeded",
            "capsule_sha256": sha('a'),
            "policy_sha256": sha('b'),
            "request_sha256": sha('c'),
            "signature_envelope_sha256": [sha('d')],
            "capsule_name": "qualified-capsule",
            "entrypoint": "bin/run",
            "matched_signers": ["release-key"],
            "required_signatures": 1,
            "runtime": {
                "launcher_sha256": sha('e'),
                "scicapsule_sha256": sha('f'),
                "package_version": "0.1.0"
            },
            "environment_scope": {
                "os": "linux",
                "arch": "aarch64",
                "execution_mode": "bounded_process_unix",
                "sandbox": "none"
            },
            "source_result": {
                "schema_version": 1,
                "media_type": SCICAPSULE_SOURCE_RESULT_MEDIA_TYPE,
                "sha256": sha('0')
            },
            "trust_is_scientific_verdict": false
        })
    }

    #[test]
    fn accepts_qualified_v2_shape_without_strengthening_trust() {
        let ingest = ingest_value(valid_value(), Digest::sha256_hex(b"fixture")).unwrap();
        assert_eq!(ingest.required_signatures(), 1);
        assert_eq!(ingest.environment().sandbox, "none");
        assert!(SciCapsuleExecutionIngest::limitations()
            .any(|limit| limit.contains("not a SciRust-Verify scientific correctness verdict")));
    }

    #[test]
    fn rejects_trust_as_scientific_verdict() {
        let mut value = valid_value();
        value["trust_is_scientific_verdict"] = Value::Bool(true);
        assert!(ingest_value(value, Digest::sha256_hex(b"fixture")).is_err());
    }

    #[test]
    fn rejects_sandbox_inflation() {
        let mut value = valid_value();
        value["environment_scope"]["sandbox"] = Value::String("container".to_owned());
        assert!(ingest_value(value, Digest::sha256_hex(b"fixture")).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut value = valid_value();
        value["unexpected"] = Value::Bool(true);
        assert!(ingest_value(value, Digest::sha256_hex(b"fixture")).is_err());
    }
}
