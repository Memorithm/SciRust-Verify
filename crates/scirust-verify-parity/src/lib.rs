//! Pure cross-run structured-output comparison.
//!
//! The engine consumes already-recorded [`CheckExecution`] values. It never
//! executes user code and never trusts a producer's pass/fail assertion. Only
//! two structured observation kinds are comparison inputs in V1:
//!
//! * `numeric_comparison`: the independently persisted `observed` scalar is
//!   compared with SciRust-Verify's numeric tolerance engine;
//! * `fingerprint`: canonical hexadecimal fingerprints must match exactly.
//!
//! Missing, duplicate, malformed, or unit-incompatible observations yield
//! [`Verdict::NotVerified`]. Fully comparable but unequal outputs yield
//! [`Verdict::Failed`]. Only a complete match yields [`Verdict::Verified`].

#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use scirust_verify_model::{
    Artifact, CheckExecution, Digest, DirtyState, GpuIdentity, ObservedValue, Tolerance, Verdict,
    VerificationScope,
};
use serde::{Deserialize, Serialize};

/// Stable identity of one comparable observation inside a run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservationKey {
    /// Check that emitted the observation.
    pub check_id: String,
    /// Structured observation kind (`numeric_comparison` or `fingerprint`).
    pub kind: String,
    /// Producer-defined stable observation name.
    pub name: String,
}

/// Why a comparison could not be completed for some output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// The left run has an output with no right-run counterpart.
    MissingRight,
    /// The right run has an output with no left-run counterpart.
    MissingLeft,
    /// The left run emitted the same comparison key more than once.
    DuplicateLeft,
    /// The right run emitted the same comparison key more than once.
    DuplicateRight,
    /// A left-run structured observation was malformed.
    MalformedLeft,
    /// A right-run structured observation was malformed.
    MalformedRight,
    /// Matching numeric observations disagree about their unit.
    UnitMismatch,
    /// Neither run contained any eligible structured output.
    NoComparableObservations,
}

/// One incompleteness that prevents a complete parity verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonGap {
    /// Gap class.
    pub kind: GapKind,
    /// Output key when the gap is tied to one observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<ObservationKey>,
    /// Human-readable explanation.
    pub message: String,
}

/// Result for one output present and structurally comparable on both sides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonDetail {
    /// Compared output identity.
    pub key: ObservationKey,
    /// Whether this output matched under the selected policy.
    pub pass: bool,
    /// Canonical JSON rendering of the left value.
    pub left: serde_json::Value,
    /// Canonical JSON rendering of the right value.
    pub right: serde_json::Value,
    /// Optional unit, required to agree between runs when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Numeric acceptance criterion or `exact_fingerprint`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<String>,
    /// Absolute numeric error when defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abs_error: Option<f64>,
    /// Relative numeric error when defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel_error: Option<f64>,
    /// ULP distance when meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ulp_distance: Option<u64>,
}

/// Complete comparison result for two execution documents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParityResult {
    /// Scientific verdict derived solely from structured output comparison.
    pub verdict: Verdict,
    /// Number of structurally comparable outputs.
    pub compared_outputs: usize,
    /// Number of comparable outputs that matched.
    pub matched_outputs: usize,
    /// Number of comparable outputs that contradicted parity.
    pub mismatched_outputs: usize,
    /// Number of numeric outputs compared.
    pub numeric_outputs: usize,
    /// Number of canonical fingerprints compared.
    pub fingerprint_outputs: usize,
    /// Per-output comparisons.
    pub comparisons: Vec<ComparisonDetail>,
    /// Structural gaps. Any gap prevents a VERIFIED result.
    pub gaps: Vec<ComparisonGap>,
}

/// Strong source anchor used to decide whether two runs concern the same
/// artifact source state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceAnchor {
    /// Exact source-tree content digest.
    TreeDigest {
        /// Recorded digest.
        digest: Digest,
    },
    /// Git commit accepted only when both worktrees were recorded clean.
    CleanGitCommit {
        /// Full commit id.
        commit: String,
    },
}

/// Relationship between two source-run artifact identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SourceRelation {
    /// Artifact metadata and a strong source anchor agree.
    Same {
        /// Anchor establishing equivalence.
        anchor: SourceAnchor,
    },
    /// Available strong identities contradict one another.
    Mismatched {
        /// Explanation.
        reason: String,
    },
    /// Available metadata cannot prove equivalence.
    NotVerified {
        /// Explanation.
        reason: String,
    },
}

/// Coarse execution endpoint role derived from recorded scope, never from a
/// CLI label alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    /// Explicit CPU backend with no contradictory concrete GPU identity.
    Cpu,
    /// Concrete GPU identity plus a non-CPU backend.
    Gpu,
    /// A backend is recorded but is not sufficiently identified as CPU/GPU.
    Other,
    /// No usable backend identity is present.
    Unknown,
}

impl EndpointRole {
    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
enum ComparableValue {
    Numeric(f64),
    Fingerprint(String),
}

#[derive(Debug, Clone)]
struct Extracted {
    value: ComparableValue,
    unit: Option<String>,
}

/// True when an execution contains at least one V1-comparable structured
/// output observation.
pub fn execution_has_comparable_observations(execution: &CheckExecution) -> bool {
    execution.observations.iter().any(|observation| {
        matches!(
            observation.kind.as_str(),
            "numeric_comparison" | "fingerprint"
        )
    })
}

/// Compares all eligible structured outputs from two runs.
pub fn compare_executions(
    left: &[CheckExecution],
    right: &[CheckExecution],
    tolerance: &Tolerance,
) -> ParityResult {
    let (left_values, left_invalid, mut gaps) = extract(left, true);
    let (right_values, right_invalid, right_gaps) = extract(right, false);
    gaps.extend(right_gaps);

    let keys: BTreeSet<ObservationKey> = left_values
        .keys()
        .chain(right_values.keys())
        .cloned()
        .collect();
    let mut comparisons = Vec::new();
    let mut numeric_outputs = 0usize;
    let mut fingerprint_outputs = 0usize;

    for key in keys {
        if left_invalid.contains(&key) || right_invalid.contains(&key) {
            continue;
        }
        let left_value = left_values.get(&key);
        let right_value = right_values.get(&key);
        let (Some(left_value), Some(right_value)) = (left_value, right_value) else {
            let (kind, message) = if left_value.is_some() {
                (
                    GapKind::MissingRight,
                    format!(
                        "right run has no counterpart for {}:{}",
                        key.check_id, key.name
                    ),
                )
            } else {
                (
                    GapKind::MissingLeft,
                    format!(
                        "left run has no counterpart for {}:{}",
                        key.check_id, key.name
                    ),
                )
            };
            gaps.push(ComparisonGap {
                kind,
                key: Some(key),
                message,
            });
            continue;
        };

        if left_value.unit != right_value.unit {
            gaps.push(ComparisonGap {
                kind: GapKind::UnitMismatch,
                key: Some(key.clone()),
                message: format!(
                    "unit mismatch for {}:{}: left={:?}, right={:?}",
                    key.check_id, key.name, left_value.unit, right_value.unit
                ),
            });
            continue;
        }

        match (&left_value.value, &right_value.value) {
            (ComparableValue::Numeric(a), ComparableValue::Numeric(b)) => {
                numeric_outputs += 1;
                let outcome = scirust_verify_numerics::compare(*a, *b, tolerance);
                comparisons.push(ComparisonDetail {
                    key,
                    pass: outcome.pass,
                    left: scirust_verify_numerics::json_f64(*a),
                    right: scirust_verify_numerics::json_f64(*b),
                    unit: left_value.unit.clone(),
                    accepted_by: outcome.accepted_by.map(str::to_owned),
                    abs_error: outcome.abs_error,
                    rel_error: outcome.rel_error,
                    ulp_distance: outcome.ulp_distance,
                });
            }
            (ComparableValue::Fingerprint(a), ComparableValue::Fingerprint(b)) => {
                fingerprint_outputs += 1;
                let pass = a == b;
                comparisons.push(ComparisonDetail {
                    key,
                    pass,
                    left: serde_json::Value::String(a.clone()),
                    right: serde_json::Value::String(b.clone()),
                    unit: left_value.unit.clone(),
                    accepted_by: pass.then(|| "exact_fingerprint".to_owned()),
                    abs_error: None,
                    rel_error: None,
                    ulp_distance: None,
                });
            }
            _ => {
                gaps.push(ComparisonGap {
                    kind: GapKind::UnitMismatch,
                    key: Some(key.clone()),
                    message: format!(
                        "structured output type mismatch for {}:{}",
                        key.check_id, key.name
                    ),
                });
            }
        }
    }

    if comparisons.is_empty() && gaps.is_empty() {
        gaps.push(ComparisonGap {
            kind: GapKind::NoComparableObservations,
            key: None,
            message: "neither run contains numeric_comparison or fingerprint observations".into(),
        });
    }

    comparisons.sort_by(|a, b| a.key.cmp(&b.key));
    gaps.sort_by(|a, b| a.message.cmp(&b.message));
    let matched_outputs = comparisons.iter().filter(|item| item.pass).count();
    let mismatched_outputs = comparisons.len() - matched_outputs;
    let verdict = if !gaps.is_empty() {
        Verdict::NotVerified
    } else if mismatched_outputs > 0 {
        Verdict::Failed
    } else {
        Verdict::Verified
    };

    ParityResult {
        verdict,
        compared_outputs: comparisons.len(),
        matched_outputs,
        mismatched_outputs,
        numeric_outputs,
        fingerprint_outputs,
        comparisons,
        gaps,
    }
}

/// Determines whether two run artifacts identify the same source state.
pub fn compare_artifacts(left: &Artifact, right: &Artifact) -> SourceRelation {
    if left.id != right.id
        || left.kind != right.kind
        || left.name != right.name
        || left.version != right.version
    {
        return SourceRelation::Mismatched {
            reason: "artifact id/kind/name/version differ between source runs".into(),
        };
    }

    match (&left.source.tree_digest, &right.source.tree_digest) {
        (Some(a), Some(b)) => {
            if a == b {
                return SourceRelation::Same {
                    anchor: SourceAnchor::TreeDigest { digest: a.clone() },
                };
            }
            return SourceRelation::Mismatched {
                reason: format!("source tree digests differ: {a} vs {b}"),
            };
        }
        // A tree digest is a strong anchor only when both dossiers carry it.
        // If just one side has the supplemental digest, continue to the
        // identical-clean-commit fallback below instead of rejecting a pair
        // that can still be proven to share the same Git source state.
        (Some(_), None) | (None, Some(_)) => {}
        (None, None) => {}
    }

    if left.source.dirty == DirtyState::Clean && right.source.dirty == DirtyState::Clean {
        match (
            left.source.commit.as_deref(),
            right.source.commit.as_deref(),
        ) {
            (Some(a), Some(b)) if a == b => {
                return SourceRelation::Same {
                    anchor: SourceAnchor::CleanGitCommit {
                        commit: a.to_owned(),
                    },
                };
            }
            (Some(a), Some(b)) => {
                return SourceRelation::Mismatched {
                    reason: format!("clean Git commits differ: {a} vs {b}"),
                };
            }
            _ => {}
        }
    }

    SourceRelation::NotVerified {
        reason:
            "no common tree digest or identical clean Git commit establishes source equivalence"
                .into(),
    }
}

/// Classifies a recorded execution scope as CPU, GPU, other, or unknown.
///
/// A GPU role requires a concrete GPU device plus a non-CPU backend. Merely
/// recording `backend = "cuda"` without a device identity is intentionally
/// insufficient for CPU/GPU parity certification.
pub fn classify_scope(scope: &VerificationScope) -> EndpointRole {
    let scope_backend = normalized(scope.backend.as_deref());
    let nested_gpu_backend = scope
        .gpu
        .as_ref()
        .and_then(|gpu| normalized(gpu.backend.as_deref()));
    if let (Some(top), Some(nested)) = (&scope_backend, &nested_gpu_backend) {
        if top != nested {
            // Contradictory backend identities are evidence ambiguity, never
            // permission to choose whichever label would satisfy parity.
            return EndpointRole::Other;
        }
    }
    let gpu_backend = nested_gpu_backend.or_else(|| scope_backend.clone());
    let has_any_gpu = scope.gpu.as_ref().is_some_and(has_any_gpu_identity);
    let concrete_gpu = scope.gpu.as_ref().is_some_and(concrete_gpu_identity);

    if concrete_gpu
        && gpu_backend
            .as_deref()
            .is_some_and(|backend| backend != "cpu")
    {
        return EndpointRole::Gpu;
    }
    if scope_backend.as_deref() == Some("cpu") && !has_any_gpu {
        return EndpointRole::Cpu;
    }
    if scope_backend.is_some() || gpu_backend.is_some() || has_any_gpu {
        EndpointRole::Other
    } else {
        EndpointRole::Unknown
    }
}

fn has_any_gpu_identity(gpu: &GpuIdentity) -> bool {
    normalized(gpu.backend.as_deref()).is_some()
        || normalized(gpu.vendor.as_deref()).is_some()
        || normalized(gpu.device.as_deref()).is_some()
        || normalized(gpu.driver.as_deref()).is_some()
}

fn concrete_gpu_identity(gpu: &GpuIdentity) -> bool {
    normalized(gpu.device.as_deref()).is_some() && normalized(gpu.backend.as_deref()).is_some()
}

fn normalized(value: Option<&str>) -> Option<String> {
    value.and_then(|raw| {
        let normalized = raw.trim().to_ascii_lowercase();
        (!normalized.is_empty()).then_some(normalized)
    })
}

fn extract(
    executions: &[CheckExecution],
    left_side: bool,
) -> (
    BTreeMap<ObservationKey, Extracted>,
    BTreeSet<ObservationKey>,
    Vec<ComparisonGap>,
) {
    let mut values = BTreeMap::new();
    let mut invalid = BTreeSet::new();
    let mut gaps = Vec::new();
    for execution in executions {
        for observation in &execution.observations {
            if !matches!(
                observation.kind.as_str(),
                "numeric_comparison" | "fingerprint"
            ) {
                continue;
            }
            let key = ObservationKey {
                check_id: execution.check_id.as_str().to_owned(),
                kind: observation.kind.clone(),
                name: observation.name.clone(),
            };
            if invalid.contains(&key) {
                continue;
            }
            let parsed = parse_observation(observation);
            let parsed = match parsed {
                Ok(parsed) => parsed,
                Err(reason) => {
                    invalid.insert(key.clone());
                    values.remove(&key);
                    gaps.push(ComparisonGap {
                        kind: if left_side {
                            GapKind::MalformedLeft
                        } else {
                            GapKind::MalformedRight
                        },
                        key: Some(key),
                        message: reason,
                    });
                    continue;
                }
            };
            if values.insert(key.clone(), parsed).is_some() {
                values.remove(&key);
                invalid.insert(key.clone());
                gaps.push(ComparisonGap {
                    kind: if left_side {
                        GapKind::DuplicateLeft
                    } else {
                        GapKind::DuplicateRight
                    },
                    key: Some(key.clone()),
                    message: format!(
                        "{} run emitted duplicate structured output {}:{}:{}",
                        if left_side { "left" } else { "right" },
                        key.check_id,
                        key.kind,
                        key.name
                    ),
                });
            }
        }
    }
    (values, invalid, gaps)
}

fn parse_observation(observation: &scirust_verify_model::Observation) -> Result<Extracted, String> {
    match observation.kind.as_str() {
        "numeric_comparison" => {
            let ObservedValue::Json(payload) = &observation.value else {
                return Err(format!(
                    "numeric_comparison `{}` is not a JSON payload",
                    observation.name
                ));
            };
            let raw = payload.get("observed").ok_or_else(|| {
                format!(
                    "numeric_comparison `{}` has no `observed` value",
                    observation.name
                )
            })?;
            let value = parse_json_f64(raw).ok_or_else(|| {
                format!(
                    "numeric_comparison `{}` has invalid `observed` value {raw}",
                    observation.name
                )
            })?;
            Ok(Extracted {
                value: ComparableValue::Numeric(value),
                unit: observation.unit.clone(),
            })
        }
        "fingerprint" => {
            let ObservedValue::Text(value) = &observation.value else {
                return Err(format!("fingerprint `{}` is not textual", observation.name));
            };
            if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(format!(
                    "fingerprint `{}` is not non-empty hexadecimal text",
                    observation.name
                ));
            }
            Ok(Extracted {
                value: ComparableValue::Fingerprint(value.to_ascii_lowercase()),
                unit: observation.unit.clone(),
            })
        }
        _ => unreachable!("caller filters eligible kinds"),
    }
}

fn parse_json_f64(value: &serde_json::Value) -> Option<f64> {
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    match value.as_str()? {
        "NaN" => Some(f64::NAN),
        "inf" | "+inf" => Some(f64::INFINITY),
        "-inf" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_verify_model::{
        ArtifactId, ArtifactKind, CheckId, CheckStatus, Observation, SourceIdentity,
    };

    fn execution(check: &str, observations: Vec<Observation>) -> CheckExecution {
        CheckExecution {
            check_id: CheckId::new(check),
            started_at_utc: None,
            ended_at_utc: None,
            status: CheckStatus::Executed { exit_code: Some(0) },
            outcome: Verdict::Verified,
            summary: String::new(),
            observations,
            evidence_ids: vec![],
            notes: vec![],
        }
    }

    fn numeric(name: &str, value: serde_json::Value) -> Observation {
        Observation::new(
            "numeric_comparison",
            name,
            ObservedValue::Json(serde_json::json!({"expected": 0.0, "observed": value})),
        )
        .with_unit("unit")
    }

    fn fingerprint(name: &str, value: &str) -> Observation {
        Observation::new("fingerprint", name, ObservedValue::Text(value.into()))
    }

    #[test]
    fn exact_numeric_and_fingerprint_outputs_verify() {
        let left = execution(
            "numeric:demo",
            vec![
                numeric("x", serde_json::json!(1.0)),
                fingerprint("digest", "aabb"),
            ],
        );
        let right = left.clone();
        let result = compare_executions(&[left], &[right], &Tolerance::exact());
        assert_eq!(result.verdict, Verdict::Verified);
        assert_eq!(result.compared_outputs, 2);
        assert_eq!(result.numeric_outputs, 1);
        assert_eq!(result.fingerprint_outputs, 1);
    }

    #[test]
    fn numeric_tolerance_can_verify_non_exact_values() {
        let left = execution("numeric:demo", vec![numeric("x", serde_json::json!(1.0))]);
        let right = execution(
            "numeric:demo",
            vec![numeric("x", serde_json::json!(1.0000005))],
        );
        let result = compare_executions(
            &[left],
            &[right],
            &Tolerance {
                absolute: Some(1e-6),
                ..Default::default()
            },
        );
        assert_eq!(result.verdict, Verdict::Verified);
        assert_eq!(result.matched_outputs, 1);
    }

    #[test]
    fn comparable_mismatch_is_failed() {
        let left = execution("numeric:demo", vec![numeric("x", serde_json::json!(1.0))]);
        let right = execution("numeric:demo", vec![numeric("x", serde_json::json!(2.0))]);
        let result = compare_executions(&[left], &[right], &Tolerance::exact());
        assert_eq!(result.verdict, Verdict::Failed);
        assert_eq!(result.mismatched_outputs, 1);
    }

    #[test]
    fn missing_output_is_not_verified_not_failed() {
        let left = execution("numeric:demo", vec![numeric("x", serde_json::json!(1.0))]);
        let result = compare_executions(&[left], &[], &Tolerance::exact());
        assert_eq!(result.verdict, Verdict::NotVerified);
        assert_eq!(result.gaps[0].kind, GapKind::MissingRight);
    }

    #[test]
    fn duplicate_output_is_not_verified() {
        let left = execution(
            "numeric:demo",
            vec![
                numeric("x", serde_json::json!(1.0)),
                numeric("x", serde_json::json!(1.0)),
            ],
        );
        let right = execution("numeric:demo", vec![numeric("x", serde_json::json!(1.0))]);
        let result = compare_executions(&[left], &[right], &Tolerance::exact());
        assert_eq!(result.verdict, Verdict::NotVerified);
        assert!(result
            .gaps
            .iter()
            .any(|gap| gap.kind == GapKind::DuplicateLeft));
    }

    #[test]
    fn special_nan_values_compare_without_invalid_json() {
        let left = execution("numeric:demo", vec![numeric("x", serde_json::json!("NaN"))]);
        let right = left.clone();
        let result = compare_executions(&[left], &[right], &Tolerance::exact());
        assert_eq!(result.verdict, Verdict::Verified);
        assert_eq!(result.comparisons[0].left, serde_json::json!("NaN"));
    }

    fn artifact(source: SourceIdentity) -> Artifact {
        Artifact {
            id: ArtifactId::new("demo"),
            kind: ArtifactKind::CargoWorkspace,
            name: "demo".into(),
            version: Some("0.1".into()),
            path: ".".into(),
            source,
            content_digest: None,
        }
    }

    #[test]
    fn source_equivalence_is_conservative() {
        let clean = SourceIdentity {
            commit: Some("a".repeat(40)),
            dirty: DirtyState::Clean,
            ..Default::default()
        };
        assert!(matches!(
            compare_artifacts(&artifact(clean.clone()), &artifact(clean)),
            SourceRelation::Same { .. }
        ));
        let unknown = SourceIdentity {
            commit: Some("a".repeat(40)),
            dirty: DirtyState::Unknown,
            ..Default::default()
        };
        assert!(matches!(
            compare_artifacts(&artifact(unknown.clone()), &artifact(unknown)),
            SourceRelation::NotVerified { .. }
        ));
    }

    #[test]
    fn one_sided_tree_digest_can_fall_back_to_same_clean_commit() {
        let commit = "b".repeat(40);
        let left = SourceIdentity {
            commit: Some(commit.clone()),
            dirty: DirtyState::Clean,
            tree_digest: Some(Digest::sha256_hex(b"same-source")),
            ..Default::default()
        };
        let right = SourceIdentity {
            commit: Some(commit.clone()),
            dirty: DirtyState::Clean,
            ..Default::default()
        };
        assert_eq!(
            compare_artifacts(&artifact(left), &artifact(right)),
            SourceRelation::Same {
                anchor: SourceAnchor::CleanGitCommit { commit }
            }
        );
    }

    #[test]
    fn artifact_id_mismatch_prevents_source_equivalence() {
        let source = SourceIdentity {
            commit: Some("a".repeat(40)),
            dirty: DirtyState::Clean,
            ..Default::default()
        };
        let left = artifact(source.clone());
        let mut right = artifact(source);
        right.id = ArtifactId::new("different-subject");
        assert!(matches!(
            compare_artifacts(&left, &right),
            SourceRelation::Mismatched { .. }
        ));
    }

    #[test]
    fn endpoint_role_requires_concrete_gpu_identity() {
        let cpu = VerificationScope {
            backend: Some("cpu".into()),
            ..Default::default()
        };
        assert_eq!(classify_scope(&cpu), EndpointRole::Cpu);
        let ambiguous_cpu = VerificationScope {
            backend: Some("cpu".into()),
            gpu: Some(GpuIdentity {
                device: Some("partially-recorded-device".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(classify_scope(&ambiguous_cpu), EndpointRole::Other);
        let contradictory = VerificationScope {
            backend: Some("cpu".into()),
            gpu: Some(GpuIdentity {
                backend: Some("cuda".into()),
                vendor: Some("NVIDIA".into()),
                device: Some("Example GPU".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(classify_scope(&contradictory), EndpointRole::Other);
        let weak_gpu = VerificationScope {
            backend: Some("cuda".into()),
            ..Default::default()
        };
        assert_eq!(classify_scope(&weak_gpu), EndpointRole::Other);
        let gpu = VerificationScope {
            backend: Some("cuda".into()),
            gpu: Some(GpuIdentity {
                backend: Some("cuda".into()),
                vendor: Some("NVIDIA".into()),
                device: Some("Example GPU".into()),
                driver: Some("1.0".into()),
            }),
            ..Default::default()
        };
        assert_eq!(classify_scope(&gpu), EndpointRole::Gpu);
    }
}
