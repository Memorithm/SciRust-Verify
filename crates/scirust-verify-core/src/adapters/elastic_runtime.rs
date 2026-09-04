//! Source-preserving ingestion for ElasticXxx runtime evidence.
//!
//! The adapter validates the published `elastic-runtime-evidence-v1` shape and
//! preserves ElasticXxx COMMIT/ROLLBACK decisions as source observations. It
//! never converts those decisions into SciRust-Verify verdicts.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use scirust_verify_model::{Digest, Observation, ObservedValue};
use serde_json::Value;
use thiserror::Error;

pub const ELASTIC_RUNTIME_EVIDENCE_SCHEMA: &str = "elastic-runtime-evidence-v1";
pub const ELASTIC_RUNTIME_MEDIA_TYPE: &str = "application/vnd.elastic.runtime-evidence.v1+json";
pub const ELASTIC_RUNTIME_CONTRACT: &str = "elastic.hub.run@1.0.0";
pub const ELASTIC_RUNTIME_SOURCE_HEAD: &str = "571d0deb8921df54502fbb35909dd8830cbf4fb4";
pub const ELASTIC_RUNTIME_SOURCE_MERGE: &str = "9e51879b96e54c812b6a265fe5901e960bbe6250";
pub const ELASTIC_RUNTIME_MAX_BYTES: usize = 1024 * 1024;
const MAX_CONTROLLERS: usize = 8192;
const MAX_CYCLES: usize = 8192;
const MAX_EVENTS: usize = 8192;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const MAX_EVENT_DETAIL_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElasticRuntimeDecision {
    pub resource_id: String,
    pub cycle_index: usize,
    pub committed: bool,
    pub rolled_back: bool,
    pub verification: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ElasticRuntimeIngest {
    digest: Digest,
    command: String,
    resource_ids: Vec<String>,
    event_count: usize,
    commit_count: usize,
    rollback_count: usize,
    decisions: Vec<ElasticRuntimeDecision>,
}

impl ElasticRuntimeIngest {
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn resource_ids(&self) -> &[String] {
        &self.resource_ids
    }

    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    pub const fn commit_count(&self) -> usize {
        self.commit_count
    }

    pub const fn rollback_count(&self) -> usize {
        self.rollback_count
    }

    pub fn decisions(&self) -> &[ElasticRuntimeDecision] {
        &self.decisions
    }

    pub fn observations(&self) -> Vec<Observation> {
        vec![
            Observation::new(
                "elastic_runtime",
                "source_contract",
                ObservedValue::Text(ELASTIC_RUNTIME_CONTRACT.to_owned()),
            ),
            Observation::new(
                "elastic_runtime",
                "source_merge",
                ObservedValue::Text(ELASTIC_RUNTIME_SOURCE_MERGE.to_owned()),
            ),
            Observation::new(
                "elastic_runtime",
                "command",
                ObservedValue::Text(self.command.clone()),
            ),
            Observation::new(
                "elastic_runtime",
                "resource_ids",
                ObservedValue::Json(serde_json::json!(self.resource_ids)),
            ),
            Observation::new(
                "elastic_runtime",
                "event_count",
                ObservedValue::UInt(self.event_count as u64),
            ),
            Observation::new(
                "elastic_runtime",
                "commit_count",
                ObservedValue::UInt(self.commit_count as u64),
            ),
            Observation::new(
                "elastic_runtime",
                "rollback_count",
                ObservedValue::UInt(self.rollback_count as u64),
            ),
            Observation::new(
                "elastic_runtime",
                "runtime_decisions",
                ObservedValue::Json(serde_json::json!(self
                    .decisions
                    .iter()
                    .map(|decision| serde_json::json!({
                        "resource_id": decision.resource_id,
                        "cycle_index": decision.cycle_index,
                        "committed": decision.committed,
                        "rolled_back": decision.rolled_back,
                        "verification": decision.verification,
                    }))
                    .collect::<Vec<_>>())),
            ),
        ]
    }

    pub fn limitations() -> impl Iterator<Item = &'static str> {
        [
            "ElasticXxx COMMIT/ROLLBACK remains a source runtime decision, not a SciRust-Verify verdict.",
            "The adapter establishes structural evidence-contract conformance only; it does not independently prove resource-policy optimality.",
            "No cross-host comparability, hardware portability, sandboxing, model-quality, or performance-superiority claim is established.",
        ]
        .into_iter()
    }
}

#[derive(Debug, Error)]
pub enum ElasticRuntimeAdapterError {
    #[error("Elastic runtime evidence is not a regular file")]
    NotRegularFile,
    #[error("Elastic runtime evidence exceeds {ELASTIC_RUNTIME_MAX_BYTES} bytes")]
    TooLarge,
    #[error("invalid Elastic runtime evidence JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid Elastic runtime evidence: {0}")]
    Invalid(String),
    #[error("cannot read Elastic runtime evidence: {0}")]
    Io(#[from] std::io::Error),
}

pub fn ingest_elastic_runtime(
    path: &Path,
) -> Result<ElasticRuntimeIngest, ElasticRuntimeAdapterError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ElasticRuntimeAdapterError::NotRegularFile);
    }
    if metadata.len() > ELASTIC_RUNTIME_MAX_BYTES as u64 {
        return Err(ElasticRuntimeAdapterError::TooLarge);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > ELASTIC_RUNTIME_MAX_BYTES {
        return Err(ElasticRuntimeAdapterError::TooLarge);
    }
    let digest = Digest::sha256_hex(&bytes);
    let root: Value = serde_json::from_slice(&bytes)?;
    ingest_value(root, digest)
}

fn ingest_value(
    root: Value,
    digest: Digest,
) -> Result<ElasticRuntimeIngest, ElasticRuntimeAdapterError> {
    let object = root
        .as_object()
        .ok_or_else(|| invalid("root must be an object"))?;
    require_string(object.get("evidence_schema"), "evidence_schema")?
        .eq(ELASTIC_RUNTIME_EVIDENCE_SCHEMA)
        .then_some(())
        .ok_or_else(|| invalid("unsupported evidence_schema"))?;
    let command = require_string(object.get("command"), "command")?.to_owned();
    if command != "run" {
        return Err(invalid("qualified v1 adapter requires command=run"));
    }
    if object.get("source").and_then(Value::as_str) != Some("operator-config") {
        return Err(invalid(
            "qualified v1 adapter requires source=operator-config",
        ));
    }
    if object.get("config_version").and_then(Value::as_u64) != Some(1) {
        return Err(invalid("qualified v1 adapter requires config_version=1"));
    }

    let controllers = object
        .get("controllers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("controllers must be an array"))?;
    if controllers.len() > MAX_CONTROLLERS {
        return Err(invalid("controller count exceeds bound"));
    }

    let mut seen_resources = BTreeSet::new();
    let mut resource_ids = Vec::with_capacity(controllers.len());
    let mut event_count = 0usize;
    let mut commit_count = 0usize;
    let mut rollback_count = 0usize;
    let mut decisions = Vec::new();

    for controller in controllers {
        let controller = controller
            .as_object()
            .ok_or_else(|| invalid("controller entry must be an object"))?;
        let resource_id = require_string(controller.get("resource_id"), "resource_id")?;
        if resource_id.is_empty()
            || resource_id.len() > MAX_RESOURCE_ID_BYTES
            || resource_id.chars().any(char::is_control)
        {
            return Err(invalid(
                "resource_id is empty, oversized, or contains controls",
            ));
        }
        if !seen_resources.insert(resource_id.to_owned()) {
            return Err(invalid("duplicate resource_id"));
        }
        resource_ids.push(resource_id.to_owned());

        if let Some(events) = controller.get("events") {
            let events = events
                .as_array()
                .ok_or_else(|| invalid("controller events must be an array"))?;
            event_count = event_count
                .checked_add(validate_event_slice(events)?)
                .ok_or_else(|| invalid("event count overflow"))?;
        }

        let cycles = controller
            .get("cycles")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("controller cycles must be an array"))?;
        if cycles.len() > MAX_CYCLES {
            return Err(invalid("cycle count exceeds bound"));
        }
        for (cycle_index, cycle) in cycles.iter().enumerate() {
            let cycle = cycle
                .as_object()
                .ok_or_else(|| invalid("cycle entry must be an object"))?;
            let committed = require_bool(cycle.get("committed"), "committed")?;
            let rolled_back = require_bool(cycle.get("rolled_back"), "rolled_back")?;
            if committed && rolled_back {
                return Err(invalid("one cycle cannot be committed and rolled_back"));
            }
            let events = cycle
                .get("events")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("cycle events must be an array"))?;
            event_count = event_count
                .checked_add(validate_event_slice(events)?)
                .ok_or_else(|| invalid("event count overflow"))?;
            let has_commit = event_kind_present(events, "CommitExecuted");
            let has_rollback = event_kind_present(events, "RollbackExecuted");
            if committed != has_commit {
                return Err(invalid(
                    "committed flag contradicts CommitExecuted evidence",
                ));
            }
            if rolled_back != has_rollback {
                return Err(invalid(
                    "rolled_back flag contradicts RollbackExecuted evidence",
                ));
            }
            if committed {
                commit_count += 1;
            }
            if rolled_back {
                rollback_count += 1;
            }
            decisions.push(ElasticRuntimeDecision {
                resource_id: resource_id.to_owned(),
                cycle_index,
                committed,
                rolled_back,
                verification: cycle
                    .get("verification")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
        }
    }

    Ok(ElasticRuntimeIngest {
        digest,
        command,
        resource_ids,
        event_count,
        commit_count,
        rollback_count,
        decisions,
    })
}

fn validate_event_slice(events: &[Value]) -> Result<usize, ElasticRuntimeAdapterError> {
    if events.len() > MAX_EVENTS {
        return Err(invalid("event count exceeds bound"));
    }
    for event in events {
        let event = event
            .as_object()
            .ok_or_else(|| invalid("event entry must be an object"))?;
        let kind = require_string(event.get("kind"), "event.kind")?;
        if kind.is_empty() || kind.len() > 128 {
            return Err(invalid("event kind is empty or oversized"));
        }
        let detail = require_string(event.get("details"), "event.details")?;
        if detail.len() > MAX_EVENT_DETAIL_BYTES {
            return Err(invalid("event details exceed bound"));
        }
    }
    Ok(events.len())
}

fn event_kind_present(events: &[Value], expected: &str) -> bool {
    events.iter().any(|event| {
        event
            .as_object()
            .and_then(|event| event.get("kind"))
            .and_then(Value::as_str)
            == Some(expected)
    })
}

fn require_string<'a>(
    value: Option<&'a Value>,
    name: &str,
) -> Result<&'a str, ElasticRuntimeAdapterError> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{name} must be a string")))
}

fn require_bool(value: Option<&Value>, name: &str) -> Result<bool, ElasticRuntimeAdapterError> {
    value
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(format!("{name} must be a boolean")))
}

fn invalid(message: impl Into<String>) -> ElasticRuntimeAdapterError {
    ElasticRuntimeAdapterError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Value {
        serde_json::json!({
            "evidence_schema": "elastic-runtime-evidence-v1",
            "command": "run",
            "source": "operator-config",
            "config_version": 1,
            "selected_resource": null,
            "controllers": [{
                "resource_id": "ram",
                "stop_reason": "Completed",
                "final_state": {"kind": "ram", "committed_bytes": 2048},
                "cycles": [{
                    "index": 0,
                    "forecast": null,
                    "candidate_target": 2048,
                    "validated": true,
                    "committed": true,
                    "rolled_back": false,
                    "verification": "Verified",
                    "events": [
                        {"kind": "ActuationApplied", "details": "applied"},
                        {"kind": "VerificationPerformed", "details": "verified"},
                        {"kind": "CommitExecuted", "details": "committed"}
                    ]
                }],
                "events": []
            }]
        })
    }

    #[test]
    fn preserves_commit_as_source_decision() {
        let ingest = ingest_value(valid(), Digest::sha256_hex(b"fixture")).unwrap();
        assert_eq!(ingest.resource_ids(), ["ram"]);
        assert_eq!(ingest.commit_count(), 1);
        assert_eq!(ingest.rollback_count(), 0);
        assert!(ingest.decisions()[0].committed);
    }

    #[test]
    fn rejects_transaction_flag_without_matching_event() {
        let mut value = valid();
        value["controllers"][0]["cycles"][0]["events"] = serde_json::json!([]);
        let error = ingest_value(value, Digest::sha256_hex(b"fixture")).unwrap_err();
        assert!(error.to_string().contains("CommitExecuted"));
    }

    #[test]
    fn rejects_duplicate_resource_identity() {
        let mut value = valid();
        let duplicate = value["controllers"][0].clone();
        value["controllers"].as_array_mut().unwrap().push(duplicate);
        let error = ingest_value(value, Digest::sha256_hex(b"fixture")).unwrap_err();
        assert!(error.to_string().contains("duplicate resource_id"));
    }

    #[test]
    fn rejects_non_run_evidence_for_qualified_process() {
        let mut value = valid();
        value["command"] = serde_json::json!("observe");
        let error = ingest_value(value, Digest::sha256_hex(b"fixture")).unwrap_err();
        assert!(error.to_string().contains("command=run"));
    }
}
