//! Claims: what a subject says about itself, to be evaluated against evidence.

use crate::id::{ArtifactId, ClaimId, EvidenceId};
use crate::scope::VerificationScope;
use crate::verdict::Verdict;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The kind of property being claimed.
///
/// Serialization contract: every kind is persisted as its canonical slug
/// string (`builds`, `tests_pass`, ...). Unknown slugs from newer or
/// project-specific configurations deserialize into [`ClaimKind::Custom`],
/// which keeps forward compatibility without a giant untagged enum.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimKind {
    /// The artifact builds successfully.
    Builds,
    /// The test suite passes.
    TestsPass,
    /// `cargo clippy -D warnings` is clean.
    LintClean,
    /// `cargo fmt --check` is clean.
    FmtClean,
    /// Documentation builds without warnings.
    DocsBuild,
    /// Dependency/supply-chain policy passes (e.g. cargo-deny).
    DependencyPolicyPasses,
    /// Repeated in-process executions agree bit-for-bit.
    Deterministic,
    /// Independent OS processes produce identical canonical fingerprints.
    CrossProcessDeterministic,
    /// Results are invariant under thread-count variation.
    ThreadInvariant,
    /// Observed values are within tolerance of expected values.
    NumericallyClose,
    /// Outputs are bit-exact against a reference.
    BitExact,
    /// Matches an independent oracle on the tested inputs.
    OracleEquivalent,
    /// CPU and GPU backends agree within the stated comparison policy.
    CpuGpuParity,
    /// A stated invariant is preserved on the tested inputs.
    InvariantPreserved,
    /// A prior result can be reproduced from recorded inputs.
    Reproducible,
    /// Source tree has no uncommitted changes (or matches a pinned digest).
    SourceClean,
    /// Project-specific property identified by its slug.
    Custom {
        /// Slug of the custom claim kind (lowercase snake_case).
        id: String,
    },
}

impl ClaimKind {
    /// Parses a claim kind from its canonical slug, mapping unknown slugs to
    /// [`ClaimKind::Custom`].
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "builds" => Self::Builds,
            "tests_pass" => Self::TestsPass,
            "lint_clean" => Self::LintClean,
            "fmt_clean" => Self::FmtClean,
            "docs_build" => Self::DocsBuild,
            "dependency_policy_passes" => Self::DependencyPolicyPasses,
            "deterministic" => Self::Deterministic,
            "cross_process_deterministic" => Self::CrossProcessDeterministic,
            "thread_invariant" => Self::ThreadInvariant,
            "numerically_close" => Self::NumericallyClose,
            "bit_exact" => Self::BitExact,
            "oracle_equivalent" => Self::OracleEquivalent,
            "cpu_gpu_parity" => Self::CpuGpuParity,
            "invariant_preserved" => Self::InvariantPreserved,
            "reproducible" => Self::Reproducible,
            "source_clean" => Self::SourceClean,
            other => Self::Custom {
                id: other.to_owned(),
            },
        }
    }

    /// Canonical slug used in identifiers (`builds`, `tests_pass`, ...).
    pub fn slug(&self) -> &str {
        match self {
            Self::Builds => "builds",
            Self::TestsPass => "tests_pass",
            Self::LintClean => "lint_clean",
            Self::FmtClean => "fmt_clean",
            Self::DocsBuild => "docs_build",
            Self::DependencyPolicyPasses => "dependency_policy_passes",
            Self::Deterministic => "deterministic",
            Self::CrossProcessDeterministic => "cross_process_deterministic",
            Self::ThreadInvariant => "thread_invariant",
            Self::NumericallyClose => "numerically_close",
            Self::BitExact => "bit_exact",
            Self::OracleEquivalent => "oracle_equivalent",
            Self::CpuGpuParity => "cpu_gpu_parity",
            Self::InvariantPreserved => "invariant_preserved",
            Self::Reproducible => "reproducible",
            Self::SourceClean => "source_clean",
            Self::Custom { id } => id.as_str(),
        }
    }
}

impl Serialize for ClaimKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.slug())
    }
}

impl<'de> Deserialize<'de> for ClaimKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_slug(&s))
    }
}

impl fmt::Display for ClaimKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// A claim registered in a dossier: the property, who claims it about what,
/// how strongly it gates, and which evidence classes would support it.
///
/// A claim never carries its own truth value; verdicts live in
/// [`ClaimEvaluation`] produced by interpreting evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// Stable identifier (kind slug plus optional `@instance` suffix).
    pub id: ClaimId,
    /// What is being claimed.
    pub kind: ClaimKind,
    /// Artifact the claim is about.
    pub subject: ArtifactId,
    /// How strongly this claim gates the dossier.
    pub requirement: crate::verdict::RequirementLevel,
    /// Human-readable statement of the claim as configured.
    pub statement: String,
    /// Parameters that parameterize the eventual checks (runs count,
    /// tolerance reference, program, ...). Opaque to the model layer.
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

/// The outcome of evaluating a claim against evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimEvaluation {
    /// The claim this evaluation belongs to.
    pub claim_id: ClaimId,
    /// Verdict derived from evidence.
    pub verdict: Verdict,
    /// Scope under which the evaluation holds.
    pub scope: VerificationScope,
    /// Human-readable reasoning: what was observed and why the verdict
    /// follows. Mandatory — an unexplained verdict is not acceptable.
    pub reasoning: String,
    /// Evidence supporting (or contradicting) the claim.
    pub evidence_ids: Vec<EvidenceId>,
    /// Checks whose execution fed this evaluation.
    pub check_ids: Vec<crate::id::CheckId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_slugs_and_serde() {
        assert_eq!(ClaimKind::TestsPass.slug(), "tests_pass");
        assert_eq!(
            serde_json::to_string(&ClaimKind::CrossProcessDeterministic).unwrap(),
            "\"cross_process_deterministic\""
        );
        let custom: ClaimKind = serde_json::from_str("\"my_weird_property\"").unwrap();
        assert_eq!(
            custom,
            ClaimKind::Custom {
                id: "my_weird_property".into()
            }
        );
        // Roundtrip preserves custom kinds.
        assert_eq!(
            serde_json::from_str::<ClaimKind>(&serde_json::to_string(&custom).unwrap()).unwrap(),
            custom
        );
        // Known slugs never leak into Custom.
        assert_eq!(ClaimKind::from_slug("builds"), ClaimKind::Builds);
        assert_eq!(ClaimKind::Builds.slug(), "builds");
    }
}
