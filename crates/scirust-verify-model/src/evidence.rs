//! Evidence: first-class immutable records of what was actually done.

use crate::digest::Digest;
use crate::id::{ArtifactId, EvidenceId};
use crate::observation::Observation;
use crate::scope::VerificationScope;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A UTC timestamp persisted in RFC 3339 format.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DateTimeUtc(pub DateTime<Utc>);

impl DateTimeUtc {
    /// Current instant.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// The inner chrono instant.
    pub fn inner(self) -> DateTime<Utc> {
        self.0
    }
}

impl Serialize for DateTimeUtc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    }
}

impl<'de> Deserialize<'de> for DateTimeUtc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| Self(dt.with_timezone(&Utc)))
            .map_err(serde::de::Error::custom)
    }
}

/// The class of evidence captured.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// One command execution (spec + outcome + captured streams).
    CommandExecution,
    /// Result of a test run.
    TestResult,
    /// A content digest of an artifact or file.
    ArtifactDigest,
    /// Environment snapshot.
    EnvironmentSnapshot,
    /// Git-derived provenance.
    GitProvenance,
    /// Toolchain identity probe.
    ToolchainIdentity,
    /// A numeric comparison against expected values/tolerances.
    NumericComparison,
    /// Comparison against an independent oracle.
    OracleComparison,
    /// Canonical output fingerprint(s).
    Fingerprint,
    /// Dependency graph snapshot (`cargo metadata`).
    DependencyGraph,
    /// Benchmark-style timing observation.
    BenchmarkObservation,
    /// Memory usage observation.
    MemoryObservation,
    /// A generated report document.
    GeneratedReport,
    /// Attestation produced by an external tool (SciRust protocol, ...).
    ExternalAttestation,
}

/// Outcome recorded by the producer of the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// Producer completed successfully.
    Ok,
    /// Producer ran but reported failure (a *scientific* failure — this is
    /// evidence, not an internal error).
    Failed,
    /// Producer hit its timeout.
    TimedOut,
    /// Producer could not start.
    SpawnFailed,
    /// Producer skipped itself with a reason.
    Skipped,
}

/// A file attached to evidence, addressed by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Path of the attachment relative to the run directory
    /// (e.g. `logs/cargo-test-0.log`). Never absolute; never `..`.
    pub path: String,
    /// Size in bytes on disk.
    pub size_bytes: u64,
    /// Digest of the file contents.
    pub digest: Digest,
    /// IANA media type when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// One immutable evidence object.
///
/// Once persisted inside a finalized bundle, evidence must never be mutated;
/// corrections happen by adding new evidence that supersedes the old and
/// referencing it via `derived_from`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Identifier (`ev-NNNN`, sequential within a run).
    pub id: EvidenceId,
    /// Evidence class.
    pub kind: EvidenceKind,
    /// Producer identifier (e.g. `runner`, `cargo-provider`,
    /// `scirust-adapter`).
    pub producer: String,
    /// Subject artifact when the evidence is about one specific artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactId>,
    /// Scope under which the evidence was gathered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<VerificationScope>,
    /// Creation instant (UTC).
    pub recorded_at_utc: DateTimeUtc,
    /// Status as reported by the producer.
    pub status: EvidenceStatus,
    /// Facts extracted from the raw capture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<Observation>,
    /// Digests of inputs consumed by the producing activity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_digests: Vec<Digest>,
    /// Digests of primary outputs produced (in addition to attachments).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_digests: Vec<Digest>,
    /// Files attached to this evidence (logs, JSON captures, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    /// Evidence objects this one was derived from (explicit provenance
    /// within the evidence graph, e.g. a fingerprint comparison derived from
    /// three execution evidences).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<EvidenceId>,
    /// Structured metadata beyond the common fields.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

impl Evidence {
    /// Starts building evidence with required identity fields.
    pub fn builder(
        id: EvidenceId,
        kind: EvidenceKind,
        producer: impl Into<String>,
    ) -> EvidenceBuilder {
        EvidenceBuilder {
            evidence: Evidence {
                id,
                kind,
                producer: producer.into(),
                artifact: None,
                scope: None,
                recorded_at_utc: DateTimeUtc::now(),
                status: EvidenceStatus::Ok,
                observations: Vec::new(),
                input_digests: Vec::new(),
                output_digests: Vec::new(),
                attachments: Vec::new(),
                derived_from: Vec::new(),
                metadata: serde_json::Map::new(),
            },
        }
    }
}

/// Builder for [`Evidence`].
pub struct EvidenceBuilder {
    evidence: Evidence,
}

impl EvidenceBuilder {
    /// Sets the subject artifact.
    pub fn artifact(mut self, id: ArtifactId) -> Self {
        self.evidence.artifact = Some(id);
        self
    }

    /// Sets the scope.
    pub fn scope(mut self, scope: VerificationScope) -> Self {
        self.evidence.scope = Some(scope);
        self
    }

    /// Sets the status.
    pub fn status(mut self, status: EvidenceStatus) -> Self {
        self.evidence.status = status;
        self
    }

    /// Appends an observation.
    pub fn observation(mut self, obs: Observation) -> Self {
        self.evidence.observations.push(obs);
        self
    }

    /// Appends several observations.
    pub fn observations(mut self, obs: impl IntoIterator<Item = Observation>) -> Self {
        self.evidence.observations.extend(obs);
        self
    }

    /// Appends an input digest.
    pub fn input(mut self, digest: Digest) -> Self {
        self.evidence.input_digests.push(digest);
        self
    }

    /// Appends an output digest.
    pub fn output(mut self, digest: Digest) -> Self {
        self.evidence.output_digests.push(digest);
        self
    }

    /// Appends an attachment.
    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.evidence.attachments.push(attachment);
        self
    }

    /// Appends derivation links.
    pub fn derived_from(mut self, ids: impl IntoIterator<Item = EvidenceId>) -> Self {
        self.evidence.derived_from.extend(ids);
        self
    }

    /// Inserts a metadata entry.
    pub fn meta(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.evidence.metadata.insert(key.into(), v);
        }
        self
    }

    /// Finishes the evidence object.
    pub fn build(self) -> Evidence {
        self.evidence
    }
}
