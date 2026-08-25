from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)

# ---------------------------------------------------------------------------
# 1. Persist explicit GPU identity inside VerificationScope.
# ---------------------------------------------------------------------------
scope_path = Path("crates/scirust-verify-model/src/scope.rs")
scope = scope_path.read_text()

scope = replace_once(
    scope,
    '''impl CpuIdentity {
    fn is_empty(&self) -> bool {
        self.arch.is_none() && self.features.is_empty()
    }
}
''',
    '''impl CpuIdentity {
    fn is_empty(&self) -> bool {
        self.arch.is_none() && self.features.is_empty()
    }
}

impl GpuIdentity {
    fn is_empty(&self) -> bool {
        self.backend.is_none()
            && self.vendor.is_none()
            && self.device.is_none()
            && self.driver.is_none()
    }
}
''',
    "gpu empty helper",
)

scope = replace_once(
    scope,
    '''    /// Execution backend (`cpu`, `wgpu`, `cuda`, ...), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Identifier of the input data set used, when applicable.
''',
    '''    /// Execution backend (`cpu`, `wgpu`, `cuda`, ...), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// GPU identity when a GPU-dependent check actually executed. The field is
    /// absent for CPU-only scopes and must never be populated from guesswork.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuIdentity>,
    /// Identifier of the input data set used, when applicable.
''',
    "gpu scope field",
)

scope = replace_once(
    scope,
    '''    pub fn gpu_is_unknown(&self) -> bool {
        // GPU identity lives in `backend`/environment notes in V0.1; a
        // dedicated field appears once real GPU checks exist.
        self.backend.as_deref().map(|b| !b.is_empty()) != Some(true)
            || self.backend.as_deref() == Some("cpu")
    }
''',
    '''    pub fn gpu_is_unknown(&self) -> bool {
        match &self.gpu {
            Some(gpu) => gpu.is_empty(),
            None => true,
        }
    }
''',
    "gpu unknown semantics",
)

insert = '''

    #[test]
    fn gpu_identity_is_explicit_scope_data() {
        let scope = VerificationScope {
            backend: Some("cuda".into()),
            gpu: Some(GpuIdentity {
                backend: Some("cuda".into()),
                vendor: Some("NVIDIA".into()),
                device: Some("Example GPU".into()),
                driver: Some("999.0".into()),
            }),
            ..Default::default()
        };
        assert!(!scope.gpu_is_unknown());
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("Example GPU"));
        let roundtrip: VerificationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, scope);

        let cpu_only = VerificationScope {
            backend: Some("cpu".into()),
            ..Default::default()
        };
        assert!(cpu_only.gpu_is_unknown());
    }
'''
idx = scope.rfind("\n}")
if idx < 0:
    raise SystemExit("scope test module closing brace not found")
scope = scope[:idx] + insert + scope[idx:]
scope_path.write_text(scope)

# ---------------------------------------------------------------------------
# 2. Add a dedicated aggregate CLI module. It is intentionally not a new
#    workspace crate: aggregation is currently a CLI/read-model concern and
#    splitting it further would be artificial.
# ---------------------------------------------------------------------------
aggregate_path = Path("crates/scirust-verify-cli/src/aggregate_cli.rs")
aggregate_path.write_text(r'''//! Cross-run claim aggregation and scope coverage assessment.
//!
//! The legacy aggregate command only answered "did these evaluations say
//! VERIFIED?". This module keeps that informational answer, but adds the
//! missing trust boundaries: bundle integrity, per-run claim presence,
//! claim-definition identity, source identity, and normalized execution
//! platform coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use scirust_verify_model::{
    Artifact, Claim, ClaimEvaluation, Digest, DirtyState, EnvironmentSnapshot, GpuIdentity,
    VerificationScope, Verdict, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_store::{RunState, RunsRoot};

/// Inputs to one aggregate operation.
pub(crate) struct AggregateOptions<'a> {
    pub(crate) claim_pattern: &'a str,
    pub(crate) runs: &'a [String],
    pub(crate) project: &'a Path,
    pub(crate) min_platforms: usize,
    pub(crate) require_scope: bool,
}

/// Completed aggregate assessment plus the compatibility success signal.
pub(crate) struct AggregateOutcome {
    pub(crate) document: serde_json::Value,
    pub(crate) human: String,
    pub(crate) all_verified: bool,
    pub(crate) scope_certified: bool,
}

/// User-visible aggregate failure with the CLI exit-code class it belongs to.
#[derive(Debug)]
pub(crate) struct AggregateError {
    message: String,
    exit_code: u8,
}

impl AggregateError {
    fn invalid(message: impl Into<String>) -> Self {
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

    pub(crate) fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

impl std::fmt::Display for AggregateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceAnchor {
    kind: &'static str,
    value: String,
}

impl SourceAnchor {
    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({ "kind": self.kind, "value": self.value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ArtifactMetadata {
    kind: String,
    name: String,
    version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PlatformIdentity {
    host_triple: Option<String>,
    target_triple: Option<String>,
    cpu_arch: Option<String>,
    cpu_features: Vec<String>,
    backend: Option<String>,
    gpu_backend: Option<String>,
    gpu_vendor: Option<String>,
    gpu_device: Option<String>,
    gpu_driver: Option<String>,
}

impl PlatformIdentity {
    fn from_scope(scope: &VerificationScope, env: &EnvironmentSnapshot) -> Self {
        let gpu = scope.gpu.as_ref();
        let mut cpu_features = if scope.host.cpu.features.is_empty() {
            env.host.cpu.features.clone()
        } else {
            scope.host.cpu.features.clone()
        };
        cpu_features = cpu_features
            .into_iter()
            .filter_map(|feature| normalize(Some(feature.as_str())))
            .collect();
        cpu_features.sort();
        cpu_features.dedup();

        let host_triple = normalize(
            scope
                .host
                .triple
                .as_deref()
                .or(env.host.triple.as_deref())
                .or(env.toolchain.host_triple.as_deref()),
        );
        let cpu_arch = normalize(
            scope
                .host
                .cpu
                .arch
                .as_deref()
                .or(env.host.cpu.arch.as_deref()),
        )
        .or_else(|| {
            host_triple
                .as_deref()
                .and_then(|triple| triple.split('-').next())
                .and_then(|arch| normalize(Some(arch)))
        });

        Self {
            host_triple,
            target_triple: normalize(
                scope
                    .target_triple
                    .as_deref()
                    .or(scope.toolchain.target_triple.as_deref())
                    .or(env.toolchain.target_triple.as_deref()),
            ),
            cpu_arch,
            cpu_features,
            backend: normalize(
                scope
                    .backend
                    .as_deref()
                    .or_else(|| gpu.and_then(|identity| identity.backend.as_deref())),
            ),
            gpu_backend: normalize(gpu.and_then(|identity| identity.backend.as_deref())),
            gpu_vendor: normalize(gpu.and_then(|identity| identity.vendor.as_deref())),
            gpu_device: normalize(gpu.and_then(|identity| identity.device.as_deref())),
            gpu_driver: normalize(gpu.and_then(|identity| identity.driver.as_deref())),
        }
    }

    fn identifiable(&self) -> bool {
        self.host_triple.is_some()
            || self.target_triple.is_some()
            || self.cpu_arch.is_some()
            || self.backend.is_some()
            || self.gpu_device.is_some()
    }

    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "host_triple": self.host_triple,
            "target_triple": self.target_triple,
            "cpu_arch": self.cpu_arch,
            "cpu_features": self.cpu_features,
            "backend": self.backend,
            "gpu": {
                "backend": self.gpu_backend,
                "vendor": self.gpu_vendor,
                "device": self.gpu_device,
                "driver": self.gpu_driver,
            },
        })
    }

    fn label(&self) -> String {
        let host = self.host_triple.as_deref().unwrap_or("?");
        let target = self.target_triple.as_deref().unwrap_or("?");
        let backend = self.backend.as_deref().unwrap_or("?");
        let gpu = self.gpu_device.as_deref().unwrap_or("-");
        format!("host={host} target={target} backend={backend} gpu={gpu}")
    }
}

#[derive(Debug, Clone)]
struct RunRecord {
    run_id: String,
    artifact: ArtifactMetadata,
    source_anchor: Option<SourceAnchor>,
    matched_claims: usize,
    integrity_files: usize,
}

#[derive(Debug, Clone)]
struct Row {
    run: String,
    claim: String,
    level: String,
    verdict: Verdict,
    reasoning: String,
    claim_definition_digest: Option<String>,
    platform: PlatformIdentity,
    rustc: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceConsistency {
    Verified,
    Mismatched,
    NotVerified,
}

impl SourceConsistency {
    fn slug(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatched => "mismatched",
            Self::NotVerified => "not_verified",
        }
    }
}

/// Executes an informational or scope-certified cross-run aggregation.
pub(crate) fn execute(options: &AggregateOptions<'_>) -> Result<AggregateOutcome, AggregateError> {
    if options.runs.is_empty() {
        return Err(AggregateError::invalid(
            "aggregate needs at least one run id",
        ));
    }
    if options.min_platforms == 0 {
        return Err(AggregateError::invalid(
            "--min-platforms must be at least 1",
        ));
    }

    let runs_root = RunsRoot::new(options.project.join(".scirust-verify").join("runs"));
    let mut records = Vec::new();
    let mut rows = Vec::new();

    for run_id in options.runs {
        let store = runs_root.open(run_id).map_err(|error| {
            AggregateError::not_verified(format!(
                "run `{run_id}` not found or unusable under {}: {error}",
                runs_root.path().display()
            ))
        })?;
        let integrity_files = store.verify_integrity().map_err(|error| {
            AggregateError::not_verified(format!(
                "run `{run_id}` failed dossier integrity verification: {error}"
            ))
        })?;
        let run_doc = store.read_run_document().map_err(|error| {
            AggregateError::not_verified(format!("run `{run_id}`: {error}"))
        })?;
        if run_doc.state != RunState::Finalized {
            return Err(AggregateError::not_verified(format!(
                "run `{run_id}` is {:?}, not finalized",
                run_doc.state
            )));
        }

        let artifact = store.read_artifact().map_err(|error| {
            AggregateError::not_verified(format!("run `{run_id}` artifact: {error}"))
        })?;
        let env = store.read_environment().map_err(|error| {
            AggregateError::not_verified(format!("run `{run_id}` environment: {error}"))
        })?;
        let claims = store.read_claims().map_err(|error| {
            AggregateError::not_verified(format!("run `{run_id}` claims: {error}"))
        })?;
        let claim_map: BTreeMap<String, Claim> = claims
            .into_iter()
            .map(|claim| (claim.id.as_str().to_owned(), claim))
            .collect();

        let eval_text = store.read_text("evaluations.json").map_err(|error| {
            AggregateError::not_verified(format!(
                "run `{run_id}` has no usable evaluations document: {error}"
            ))
        })?;
        let evals: serde_json::Value = serde_json::from_str(&eval_text).map_err(|error| {
            AggregateError::not_verified(format!(
                "run `{run_id}` has malformed evaluations.json: {error}"
            ))
        })?;
        let entries = evals
            .get("evaluations")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                AggregateError::not_verified(format!(
                    "run `{run_id}` evaluations.json has no evaluations array"
                ))
            })?;

        let mut matched_claims = 0usize;
        for entry in entries {
            let evaluation_value = entry.get("evaluation").cloned().ok_or_else(|| {
                AggregateError::not_verified(format!(
                    "run `{run_id}` contains an evaluation entry without `evaluation`"
                ))
            })?;
            let evaluation: ClaimEvaluation = serde_json::from_value(evaluation_value).map_err(|error| {
                AggregateError::not_verified(format!(
                    "run `{run_id}` contains an invalid claim evaluation: {error}"
                ))
            })?;
            let claim_id = evaluation.claim_id.as_str();
            if !claim_id.contains(options.claim_pattern) {
                continue;
            }
            matched_claims += 1;
            let claim_definition_digest = claim_map
                .get(claim_id)
                .map(Digest::of_canonical_json)
                .transpose()
                .map_err(|error| {
                    AggregateError::not_verified(format!(
                        "run `{run_id}` could not canonicalize claim `{claim_id}`: {error}"
                    ))
                })?
                .map(|digest| digest.to_string());
            let level = entry
                .get("requirement_level")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_owned();
            rows.push(Row {
                run: run_id.clone(),
                claim: claim_id.to_owned(),
                level,
                verdict: evaluation.verdict,
                reasoning: evaluation.reasoning,
                claim_definition_digest,
                platform: PlatformIdentity::from_scope(&evaluation.scope, &env),
                rustc: env.toolchain.rustc_version.clone(),
            });
        }

        records.push(RunRecord {
            run_id: run_id.clone(),
            artifact: artifact_metadata(&artifact),
            source_anchor: source_anchor(&artifact),
            matched_claims,
            integrity_files,
        });
    }

    if rows.is_empty() {
        return Err(AggregateError::not_verified(format!(
            "no claim matching `{}` found in the requested runs",
            options.claim_pattern
        )));
    }

    let all_runs_covered = records.iter().all(|record| record.matched_claims > 0);
    let all_verified = all_runs_covered && rows.iter().all(|row| row.verdict.is_verified());
    let source_consistency = assess_source_consistency(&records);
    let claim_definitions_consistent = claim_definitions_consistent(&rows);
    let all_platforms_identified = rows.iter().all(|row| row.platform.identifiable());
    let platforms: BTreeSet<PlatformIdentity> = rows
        .iter()
        .filter(|row| row.platform.identifiable())
        .map(|row| row.platform.clone())
        .collect();
    let distinct_platforms = platforms.len();
    let scope_certified = all_verified
        && source_consistency == SourceConsistency::Verified
        && claim_definitions_consistent
        && all_platforms_identified
        && distinct_platforms >= options.min_platforms;

    let mut limitations = Vec::new();
    for record in &records {
        if record.matched_claims == 0 {
            limitations.push(format!(
                "run `{}` contains no claim matching `{}`",
                record.run_id, options.claim_pattern
            ));
        }
    }
    match source_consistency {
        SourceConsistency::Verified => {}
        SourceConsistency::Mismatched => limitations.push(
            "requested runs do not identify the same artifact/source; cross-run scope cannot be certified"
                .to_owned(),
        ),
        SourceConsistency::NotVerified => limitations.push(
            "source identity is insufficient to prove that every run evaluated the same source state"
                .to_owned(),
        ),
    }
    if !claim_definitions_consistent {
        limitations.push(
            "matching claim definitions differ across runs or a definition is missing".to_owned(),
        );
    }
    if !all_platforms_identified {
        limitations.push(
            "at least one matching evaluation lacks enough recorded scope to normalize its execution platform"
                .to_owned(),
        );
    }
    if distinct_platforms < options.min_platforms {
        limitations.push(format!(
            "only {distinct_platforms} distinct normalized execution platform(s) recorded; {} required",
            options.min_platforms
        ));
    }
    if !all_verified {
        limitations.push(
            "not every requested run contains only VERIFIED matching evaluations".to_owned(),
        );
    }
    limitations.sort();
    limitations.dedup();

    let run_json = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "run": record.run_id,
                "integrity_verified": true,
                "sealed_files": record.integrity_files,
                "matched_claims": record.matched_claims,
                "artifact": {
                    "kind": record.artifact.kind,
                    "name": record.artifact.name,
                    "version": record.artifact.version,
                },
                "source_anchor": record.source_anchor.as_ref().map(SourceAnchor::as_json),
            })
        })
        .collect::<Vec<_>>();
    let row_json = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "run": row.run,
                "claim": row.claim,
                "level": row.level,
                "verdict": verdict_slug(row.verdict),
                "reasoning": row.reasoning,
                "claim_definition_digest": row.claim_definition_digest,
                "platform": row.platform.as_json(),
                "rustc": row.rustc,
            })
        })
        .collect::<Vec<_>>();
    let platform_json = platforms
        .iter()
        .map(PlatformIdentity::as_json)
        .collect::<Vec<_>>();

    let document = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "generated_by": TOOL_IDENTITY,
        "claim_pattern": options.claim_pattern,
        "requested_runs": options.runs,
        "runs": run_json,
        "matches": row_json,
        "all_runs_covered": all_runs_covered,
        "all_verified": all_verified,
        "scope_assessment": {
            "source_consistency": source_consistency.slug(),
            "claim_definitions_consistent": claim_definitions_consistent,
            "all_platforms_identified": all_platforms_identified,
            "distinct_platforms": distinct_platforms,
            "minimum_platforms": options.min_platforms,
            "platforms": platform_json,
            "scope_certified": scope_certified,
        },
        "limitations": limitations,
        "trust_boundary": "scope_certified means the stored matching claim evaluations are VERIFIED for the same identified source and claim definition across the recorded distinct execution scopes. Aggregation does not compare outputs by itself and does not imply CPU/GPU parity unless the aggregated claim itself establishes cpu_gpu_parity.",
    });

    let human = render_human(
        options,
        &rows,
        all_verified,
        source_consistency,
        claim_definitions_consistent,
        distinct_platforms,
        scope_certified,
        &limitations,
    );

    Ok(AggregateOutcome {
        document,
        human,
        all_verified,
        scope_certified,
    })
}

fn render_human(
    options: &AggregateOptions<'_>,
    rows: &[Row],
    all_verified: bool,
    source_consistency: SourceConsistency,
    claim_definitions_consistent: bool,
    distinct_platforms: usize,
    scope_certified: bool,
    limitations: &[String],
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "claim pattern `{}` across {} requested run(s):\n",
        options.claim_pattern,
        options.runs.len()
    ));
    for row in rows {
        out.push_str(&format!(
            "  {} [{:>13}] {:<40} {:<12} {}\n",
            row.run,
            row.level,
            row.claim,
            row.verdict.to_string(),
            row.platform.label(),
        ));
    }
    out.push_str(&format!(
        "all verified: {}\n",
        if all_verified { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "source consistency: {}\n",
        source_consistency.slug()
    ));
    out.push_str(&format!(
        "claim definitions consistent: {}\n",
        if claim_definitions_consistent { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "distinct normalized execution platforms: {} (minimum {})\n",
        distinct_platforms, options.min_platforms
    ));
    out.push_str(&format!(
        "scope certified: {}\n",
        if scope_certified { "yes" } else { "no" }
    ));
    if !limitations.is_empty() {
        out.push_str("limitations:\n");
        for limitation in limitations {
            out.push_str(&format!("  - {limitation}\n"));
        }
    }
    out.push_str(
        "trust boundary: aggregation certifies recorded scope coverage only; it does not compare outputs or establish CPU/GPU parity unless that property is itself the verified claim.\n",
    );
    out
}

fn artifact_metadata(artifact: &Artifact) -> ArtifactMetadata {
    let kind = serde_json::to_value(&artifact.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    ArtifactMetadata {
        kind,
        name: artifact.name.clone(),
        version: artifact.version.clone(),
    }
}

fn source_anchor(artifact: &Artifact) -> Option<SourceAnchor> {
    if let Some(digest) = &artifact.source.tree_digest {
        return Some(SourceAnchor {
            kind: "tree_digest",
            value: digest.to_string(),
        });
    }
    if artifact.source.dirty == DirtyState::Clean {
        if let Some(commit) = artifact.source.commit.as_deref().and_then(|value| normalize(Some(value))) {
            return Some(SourceAnchor {
                kind: "clean_git_commit",
                value: commit,
            });
        }
    }
    None
}

fn assess_source_consistency(records: &[RunRecord]) -> SourceConsistency {
    let Some(first) = records.first() else {
        return SourceConsistency::NotVerified;
    };
    if records.iter().any(|record| record.artifact != first.artifact) {
        return SourceConsistency::Mismatched;
    }
    let anchors = records
        .iter()
        .map(|record| record.source_anchor.as_ref())
        .collect::<Vec<_>>();
    if anchors.iter().any(|anchor| anchor.is_none()) {
        return SourceConsistency::NotVerified;
    }
    let first_anchor = anchors[0].expect("checked non-empty anchors");
    if anchors
        .iter()
        .all(|anchor| anchor.is_some_and(|value| value == first_anchor))
    {
        return SourceConsistency::Verified;
    }
    let comparable = anchors.iter().all(|anchor| {
        anchor
            .map(|value| value.kind == first_anchor.kind)
            .unwrap_or(false)
    });
    if comparable {
        SourceConsistency::Mismatched
    } else {
        SourceConsistency::NotVerified
    }
}

fn claim_definitions_consistent(rows: &[Row]) -> bool {
    let mut definitions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for row in rows {
        let Some(digest) = row.claim_definition_digest.as_deref() else {
            return false;
        };
        definitions.entry(row.claim.as_str()).or_default().insert(digest);
    }
    !definitions.is_empty() && definitions.values().all(|digests| digests.len() == 1)
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

fn normalize(value: Option<&str>) -> Option<String> {
    value.and_then(|raw| {
        let normalized = raw.trim().to_ascii_lowercase();
        (!normalized.is_empty()).then_some(normalized)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_verify_model::{CpuIdentity, HostIdentity, ToolchainIdentity};

    fn platform(host: &str, backend: &str, gpu: Option<&str>) -> PlatformIdentity {
        let scope = VerificationScope {
            host: HostIdentity {
                triple: Some(host.into()),
                cpu: CpuIdentity {
                    arch: Some(host.split('-').next().unwrap_or(host).into()),
                    features: vec!["SSE4.2".into(), "sse4.2".into()],
                },
                ..Default::default()
            },
            backend: Some(backend.into()),
            gpu: gpu.map(|device| GpuIdentity {
                backend: Some(backend.into()),
                vendor: Some("NVIDIA".into()),
                device: Some(device.into()),
                driver: Some("1.0".into()),
            }),
            ..Default::default()
        };
        let env = EnvironmentSnapshot {
            toolchain: ToolchainIdentity {
                target_triple: Some(host.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        PlatformIdentity::from_scope(&scope, &env)
    }

    fn record(id: &str, source: &str) -> RunRecord {
        RunRecord {
            run_id: id.into(),
            artifact: ArtifactMetadata {
                kind: "cargo_workspace".into(),
                name: "demo".into(),
                version: Some("0.1.0".into()),
            },
            source_anchor: Some(SourceAnchor {
                kind: "clean_git_commit",
                value: source.into(),
            }),
            matched_claims: 1,
            integrity_files: 10,
        }
    }

    #[test]
    fn platform_normalization_is_stable_and_gpu_sensitive() {
        let cpu = platform("X86_64-UNKNOWN-LINUX-GNU", "CPU", None);
        assert_eq!(cpu.host_triple.as_deref(), Some("x86_64-unknown-linux-gnu"));
        assert_eq!(cpu.cpu_features, vec!["sse4.2"]);
        let gpu_a = platform("x86_64-unknown-linux-gnu", "CUDA", Some("GPU A"));
        let gpu_b = platform("x86_64-unknown-linux-gnu", "cuda", Some("GPU B"));
        assert_ne!(cpu, gpu_a);
        assert_ne!(gpu_a, gpu_b);
    }

    #[test]
    fn source_consistency_requires_same_provable_source() {
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), record("b", "abc")]),
            SourceConsistency::Verified
        );
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), record("b", "def")]),
            SourceConsistency::Mismatched
        );
        let mut unknown = record("b", "abc");
        unknown.source_anchor = None;
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), unknown]),
            SourceConsistency::NotVerified
        );
    }
}
''')

# ---------------------------------------------------------------------------
# 3. Wire the module and flags into main.rs; remove the old unsafe aggregate
#    implementation so there is exactly one semantics source.
# ---------------------------------------------------------------------------
main_path = Path("crates/scirust-verify-cli/src/main.rs")
main = main_path.read_text()
main = replace_once(main, "mod artifacts_cli;\n", "mod aggregate_cli;\nmod artifacts_cli;\n", "aggregate module")

old_variant = '''    /// Report one claim's verdicts across multiple runs (read-only; informational).
    Aggregate {
        /// Claim id or substring to match (e.g. `cross_process`).
        claim: String,
        /// Run ids to aggregate (at least one).
        runs: Vec<String>,
        /// Project root containing `.scirust-verify/runs`.
        #[arg(long)]
        project: Option<PathBuf>,
    },
'''
new_variant = '''    /// Aggregate one claim across integrity-verified dossiers and assess scope coverage.
    Aggregate {
        /// Claim id or substring to match (e.g. `cross_process`).
        claim: String,
        /// Run ids to aggregate (at least one).
        runs: Vec<String>,
        /// Project root containing `.scirust-verify/runs`.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Minimum number of distinct normalized execution platforms required for scope certification.
        #[arg(long, default_value_t = 1)]
        min_platforms: usize,
        /// Exit 1 unless source/claim/platform scope is certified in addition to all verdicts being VERIFIED.
        #[arg(long)]
        require_scope: bool,
    },
'''
main = replace_once(main, old_variant, new_variant, "aggregate command variant")

old_arm = '''        Command::Aggregate {
            claim,
            runs,
            project,
        } => {
            let root = match project {
                Some(p) => p,
                None => locate_runs_root()?,
            };
            aggregate(&claim, &runs, &root, cli.json)
        }
'''
new_arm = '''        Command::Aggregate {
            claim,
            runs,
            project,
            min_platforms,
            require_scope,
        } => {
            let root = match project {
                Some(p) => p,
                None => locate_runs_root()?,
            };
            let outcome = aggregate_cli::execute(&aggregate_cli::AggregateOptions {
                claim_pattern: &claim,
                runs: &runs,
                project: &root,
                min_platforms,
                require_scope,
            })
            .map_err(|error| CliError {
                message: error.to_string(),
                exit_code: error.exit_code(),
            })?;
            if cli.json {
                println!("{}", outcome.document);
            } else {
                print!("{}", outcome.human);
            }
            let established = if require_scope {
                outcome.scope_certified
            } else {
                outcome.all_verified
            };
            Ok(if established {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
'''
main = replace_once(main, old_arm, new_arm, "aggregate dispatch")

start = main.find("\nfn aggregate(\n")
end = main.find("\nfn ingest_scirust(\n", start)
if start < 0 or end < 0:
    raise SystemExit("old aggregate function block not found")
main = main[:start] + "\n" + main[end:]
main_path.write_text(main)

# ---------------------------------------------------------------------------
# 4. Extend E2E coverage: compatibility behavior, explicit same-platform scope
#    certification, minimum-platform failure, and corruption rejection.
# ---------------------------------------------------------------------------
e2e_path = Path("crates/scirust-verify-cli/tests/e2e.rs")
e2e = e2e_path.read_text()
old_test = '''#[test]
fn aggregate_reports_claim_across_runs() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("aggregate-store");
    let output_flag = store.join(".scirust-verify");
    let out_args = ["--output", output_flag.to_str().unwrap()];
    for _ in 0..2 {
        let out = cli()
            .args(["verify", project.to_str().unwrap()])
            .args(out_args)
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let ids = run_ids_in(&store.join(".scirust-verify/runs"));
    assert!(ids.len() >= 2);

    // All-verified claim across both runs exits 0.
    let agg = cli()
        .args(["aggregate", "tests_pass", &ids[0], &ids[1], "--json"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        agg.status.success(),
        "{}",
        String::from_utf8_lossy(&agg.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&agg.stdout).unwrap();
    assert_eq!(
        doc.get("all_verified").and_then(|v| v.as_bool()),
        Some(true)
    );

    // A pattern matching nothing exits 1 (not-found contract).
    let miss = cli()
        .args(["aggregate", "no_such_claim", &ids[0], "--json"])
        .current_dir(&store)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert_eq!(miss.status.code(), Some(1));
}
'''
new_test = '''#[test]
fn aggregate_reports_claim_across_runs() {
    prebuild_fixtures();
    let project = fixture("passing-project");
    let store = tempfile_dir("aggregate-store");
    let output_flag = store.join(".scirust-verify");
    let out_args = ["--output", output_flag.to_str().unwrap()];
    for _ in 0..2 {
        let out = cli()
            .args(["verify", project.to_str().unwrap()])
            .args(out_args)
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let ids = run_ids_in(&store.join(".scirust-verify/runs"));
    assert!(ids.len() >= 2);

    // Compatibility mode still answers whether all matching evaluations are VERIFIED,
    // but it now verifies bundle integrity and reports scope facts too.
    let agg = cli()
        .args(["aggregate", "tests_pass", &ids[0], &ids[1], "--json"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        agg.status.success(),
        "{}",
        String::from_utf8_lossy(&agg.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&agg.stdout).unwrap();
    assert_eq!(doc.get("all_verified").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        doc.pointer("/scope_assessment/source_consistency")
            .and_then(|v| v.as_str()),
        Some("verified")
    );
    assert_eq!(
        doc.pointer("/scope_assessment/scope_certified")
            .and_then(|v| v.as_bool()),
        Some(true)
    );

    // One normalized platform is enough only when explicitly requested.
    let scoped = cli()
        .args([
            "aggregate",
            "tests_pass",
            &ids[0],
            &ids[1],
            "--require-scope",
            "--min-platforms",
            "1",
            "--json",
        ])
        .current_dir(&store)
        .output()
        .unwrap();
    assert!(
        scoped.status.success(),
        "{}",
        String::from_utf8_lossy(&scoped.stderr)
    );

    // Requiring two distinct platforms on two same-host runs is NOT_VERIFIED.
    let multi = cli()
        .args([
            "aggregate",
            "tests_pass",
            &ids[0],
            &ids[1],
            "--require-scope",
            "--min-platforms",
            "2",
            "--json",
        ])
        .current_dir(&store)
        .output()
        .unwrap();
    assert_eq!(multi.status.code(), Some(1));
    let multi_doc: serde_json::Value = serde_json::from_slice(&multi.stdout).unwrap();
    assert_eq!(
        multi_doc
            .pointer("/scope_assessment/scope_certified")
            .and_then(|v| v.as_bool()),
        Some(false)
    );

    // A pattern matching nothing exits 1 (not-found contract).
    let miss = cli()
        .args(["aggregate", "no_such_claim", &ids[0], "--json"])
        .current_dir(&store)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert_eq!(miss.status.code(), Some(1));

    // Aggregation may never consume a tampered dossier as trustworthy input.
    let eval_path = store.join(format!(
        ".scirust-verify/runs/{}/evaluations.json",
        ids[0]
    ));
    let original = std::fs::read_to_string(&eval_path).unwrap();
    std::fs::write(&eval_path, original.replace("verified", "failed")).unwrap();
    let corrupt = cli()
        .args(["aggregate", "tests_pass", &ids[0], &ids[1], "--json"])
        .current_dir(&store)
        .output()
        .unwrap();
    assert_eq!(corrupt.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&corrupt.stderr).contains("integrity"),
        "{}",
        String::from_utf8_lossy(&corrupt.stderr)
    );
}
'''
e2e = replace_once(e2e, old_test, new_test, "aggregate e2e")
e2e_path.write_text(e2e)

# ---------------------------------------------------------------------------
# 5. Document the exact trust boundary.
# ---------------------------------------------------------------------------
readme_path = Path("README.md")
readme = readme_path.read_text()
section = r'''

## Cross-run scope aggregation

`aggregate` can summarize a claim across multiple finalized dossiers and now verifies every
bundle before consuming it:

```bash
scirust-verify aggregate tests_pass RUN_A RUN_B --json
```

For an explicit scope-coverage gate, require a minimum number of distinct normalized execution
platforms:

```bash
scirust-verify aggregate cross_process_deterministic RUN_X86 RUN_ARM \
  --require-scope --min-platforms 2 --json
```

Scope certification requires all requested runs to contain matching `VERIFIED` evaluations,
identical claim definitions, a provably identical source state (tree digest, or a clean Git
commit), integrity-valid finalized dossiers, identifiable execution scope, and the requested
number of distinct normalized platforms. Platform identity uses host/target triples, CPU
architecture/features, backend, and explicit GPU vendor/device/driver data when recorded.

This is **coverage certification, not output comparison**. Two successful runs on CPU and CUDA
do not establish CPU/GPU parity merely because both are present; parity must itself be a verified
`cpu_gpu_parity` claim backed by comparison evidence.
'''
if "## Cross-run scope aggregation" not in readme:
    readme += section
readme_path.write_text(readme)

arch_path = Path("docs/ARCHITECTURE.md")
arch = arch_path.read_text()
arch_section = r'''

## Cross-run scope aggregation

Cross-run aggregation is a read-only operation over already finalized dossiers. It first verifies
`bundle.json` integrity for every input run, then evaluates whether the requested claim is present
and verified everywhere. Scope certification additionally requires compatible artifact metadata,
a common strong source anchor, canonical claim-definition identity, and enough distinct normalized
execution platforms. Missing platform/source data produces `NOT_VERIFIED` scope coverage rather
than an inferred identity.

`VerificationScope` carries optional explicit `GpuIdentity` data. The field is populated only by
checks that actually know the GPU backend/device/driver; an execution backend string alone is not
treated as a hardware identity. Aggregation never upgrades per-run success into CPU/GPU output
parity unless the underlying verified claim is itself `cpu_gpu_parity`.
'''
if "## Cross-run scope aggregation" not in arch:
    arch += arch_section
arch_path.write_text(arch)

print("V0.3 scope aggregation patch applied")
