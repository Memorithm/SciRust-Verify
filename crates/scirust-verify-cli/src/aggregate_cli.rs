//! Cross-run claim aggregation and scope coverage assessment.
//!
//! The legacy aggregate command only answered "did these evaluations say
//! VERIFIED?". This module keeps that informational answer, but adds the
//! missing trust boundaries: bundle integrity, per-run claim presence,
//! claim-definition identity, source identity, and normalized execution
//! platform coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use scirust_verify_model::{
    Artifact, Claim, ClaimEvaluation, Digest, DirtyState, EnvironmentSnapshot, Verdict,
    VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_store::{RunState, RunsRoot};

/// Inputs to one aggregate operation.
pub(crate) struct AggregateOptions<'a> {
    pub(crate) claim_pattern: &'a str,
    pub(crate) runs: &'a [String],
    pub(crate) project: &'a Path,
    pub(crate) min_platforms: usize,
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
        let run_doc = store
            .read_run_document()
            .map_err(|error| AggregateError::not_verified(format!("run `{run_id}`: {error}")))?;
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
            let evaluation: ClaimEvaluation =
                serde_json::from_value(evaluation_value).map_err(|error| {
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
        limitations
            .push("not every requested run contains only VERIFIED matching evaluations".to_owned());
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
    scope_certified: bool,
    limitations: &[String],
) -> String {
    let claim_definitions_consistent = claim_definitions_consistent(rows);
    let distinct_platforms = rows
        .iter()
        .filter(|row| row.platform.identifiable())
        .map(|row| row.platform.clone())
        .collect::<BTreeSet<_>>()
        .len();
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
        if claim_definitions_consistent {
            "yes"
        } else {
            "no"
        }
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
        if let Some(commit) = artifact
            .source
            .commit
            .as_deref()
            .and_then(|value| normalize(Some(value)))
        {
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
    if records
        .iter()
        .any(|record| record.artifact != first.artifact)
    {
        return SourceConsistency::Mismatched;
    }
    let Some(first_anchor) = first.source_anchor.as_ref() else {
        return SourceConsistency::NotVerified;
    };
    if records.iter().any(|record| record.source_anchor.is_none()) {
        return SourceConsistency::NotVerified;
    }
    if records
        .iter()
        .all(|record| record.source_anchor.as_ref() == Some(first_anchor))
    {
        return SourceConsistency::Verified;
    }
    let comparable = records.iter().all(|record| {
        record
            .source_anchor
            .as_ref()
            .is_some_and(|value| value.kind == first_anchor.kind)
    });
    if comparable {
        SourceConsistency::Mismatched
    } else {
        SourceConsistency::NotVerified
    }
}

fn claim_definitions_consistent(rows: &[Row]) -> bool {
    let mut per_run: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    for row in rows {
        let Some(digest) = row.claim_definition_digest.as_deref() else {
            return false;
        };
        let claims = per_run.entry(row.run.as_str()).or_default();
        if let Some(previous) = claims.insert(row.claim.as_str(), digest) {
            if previous != digest {
                return false;
            }
        }
    }
    let mut definitions = per_run.values();
    let Some(first) = definitions.next() else {
        return false;
    };
    definitions.all(|claims| claims == first)
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
    use scirust_verify_model::{CpuIdentity, GpuIdentity, HostIdentity, ToolchainIdentity};

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

    fn row(run: &str, claim: &str, digest: &str) -> Row {
        Row {
            run: run.into(),
            claim: claim.into(),
            level: "required".into(),
            verdict: Verdict::Verified,
            reasoning: "fixture".into(),
            claim_definition_digest: Some(digest.into()),
            platform: platform("x86_64-unknown-linux-gnu", "cpu", None),
            rustc: None,
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

    #[test]
    fn claim_consistency_requires_identical_claim_sets_per_run() {
        assert!(claim_definitions_consistent(&[
            row("run-a", "foo@same", "sha256:a"),
            row("run-b", "foo@same", "sha256:a"),
        ]));
        assert!(!claim_definitions_consistent(&[
            row("run-a", "foo@left", "sha256:a"),
            row("run-b", "foo@right", "sha256:b"),
        ]));
        assert!(!claim_definitions_consistent(&[
            row("run-a", "foo@same", "sha256:a"),
            row("run-b", "foo@same", "sha256:b"),
        ]));
    }
}
