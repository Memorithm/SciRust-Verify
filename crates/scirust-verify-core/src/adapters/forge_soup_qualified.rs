//! Qualification wrapper for Forge/SOUP evidence produced through SciRust Hub.
//!
//! The raw parser validates the report and evidence bundle shapes. This wrapper
//! additionally requires the exact qualified Forge runner and Hub merge
//! identities before exposing ingestion to callers. Those identities must come
//! from trusted Hub provenance; passing arbitrary strings does not create trust.

use std::path::Path;

use scirust_verify_model::Observation;

use super::forge_soup::{
    ingest_forge_soup, ForgeSoupAdapterError, ForgeSoupIngest, ForgeSoupRecordSummary,
};
use super::{FORGE_SOUP_HUB_MERGE, FORGE_SOUP_RUNNER_MERGE};

/// Exact source identities required for the published Hub → Forge → SOUP edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeSoupSourceIdentity {
    /// Forge runner merge that executed the campaign process contract.
    pub forge_runner_merge: String,
    /// SciRust Hub merge that published `llm.optimize.forge_soup@1.0.0`.
    pub hub_merge: String,
}

impl ForgeSoupSourceIdentity {
    /// Constructs the currently qualified source identity.
    pub fn qualified_v1() -> Self {
        Self {
            forge_runner_merge: FORGE_SOUP_RUNNER_MERGE.to_owned(),
            hub_merge: FORGE_SOUP_HUB_MERGE.to_owned(),
        }
    }
}

/// Qualified ingestion result for the Hub → Forge → SOUP evidence edge.
///
/// This type deliberately carries limitations separately from any claim or
/// verdict. A Pareto winner, benchmark score, or SOUP dry-run pass remains an
/// observation until an independent verification policy evaluates it.
#[derive(Debug, Clone, PartialEq)]
pub struct ForgeSoupQualifiedIngest {
    inner: ForgeSoupIngest,
    source_identity: ForgeSoupSourceIdentity,
    qualification_limitations: Vec<String>,
}

impl ForgeSoupQualifiedIngest {
    /// Structurally validated Forge/SOUP ingestion result.
    pub fn inner(&self) -> &ForgeSoupIngest {
        &self.inner
    }

    /// Exact qualified source identity supplied by trusted Hub provenance.
    pub fn source_identity(&self) -> &ForgeSoupSourceIdentity {
        &self.source_identity
    }

    /// Source evidence records without any derived SciRust-Verify verdict.
    pub fn records(&self) -> &[ForgeSoupRecordSummary] {
        self.inner.records()
    }

    /// Source-preserving observations extracted from all evidence records.
    pub fn observations(&self) -> Vec<Observation> {
        self.inner.observations()
    }

    /// Limitations from raw ingestion plus qualification-boundary limitations.
    pub fn limitations(&self) -> impl Iterator<Item = &str> {
        self.inner
            .limitations()
            .iter()
            .map(String::as_str)
            .chain(self.qualification_limitations.iter().map(String::as_str))
    }
}

/// Validates the exact published Hub/Forge source identity and ingests the
/// corresponding Forge campaign report and Hub evidence bundle.
///
/// `source_identity` must be populated from trusted orchestration provenance.
/// This function only compares identity values; it does not authenticate their
/// origin and does not convert source measurements into a verified claim.
pub fn ingest_qualified_forge_soup(
    report_path: &Path,
    evidence_bundle_path: &Path,
    source_identity: ForgeSoupSourceIdentity,
) -> Result<ForgeSoupQualifiedIngest, ForgeSoupAdapterError> {
    if source_identity.forge_runner_merge != FORGE_SOUP_RUNNER_MERGE {
        return Err(ForgeSoupAdapterError::Contract(format!(
            "Forge runner merge is not the qualified source; expected {FORGE_SOUP_RUNNER_MERGE}"
        )));
    }
    if source_identity.hub_merge != FORGE_SOUP_HUB_MERGE {
        return Err(ForgeSoupAdapterError::Contract(format!(
            "Hub merge is not the qualified llm.optimize.forge_soup source; expected {FORGE_SOUP_HUB_MERGE}"
        )));
    }

    let inner = ingest_forge_soup(report_path, evidence_bundle_path)?;
    Ok(ForgeSoupQualifiedIngest {
        inner,
        source_identity,
        qualification_limitations: vec![
            "source_identity_values_require_trusted_hub_provenance_and_are_not_authenticated_by_this_adapter"
                .to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_identity_matches_published_merges() {
        let identity = ForgeSoupSourceIdentity::qualified_v1();
        assert_eq!(identity.forge_runner_merge, FORGE_SOUP_RUNNER_MERGE);
        assert_eq!(identity.hub_merge, FORGE_SOUP_HUB_MERGE);
    }

    #[test]
    fn mismatched_runner_fails_before_file_access() {
        let identity = ForgeSoupSourceIdentity {
            forge_runner_merge: "0".repeat(40),
            hub_merge: FORGE_SOUP_HUB_MERGE.to_owned(),
        };
        let error = ingest_qualified_forge_soup(
            Path::new("definitely-missing-report.json"),
            Path::new("definitely-missing-evidence.tar"),
            identity,
        )
        .expect_err("source drift must fail before touching inputs");
        assert!(error.to_string().contains("Forge runner merge"));
    }

    #[test]
    fn mismatched_hub_fails_before_file_access() {
        let identity = ForgeSoupSourceIdentity {
            forge_runner_merge: FORGE_SOUP_RUNNER_MERGE.to_owned(),
            hub_merge: "0".repeat(40),
        };
        let error = ingest_qualified_forge_soup(
            Path::new("definitely-missing-report.json"),
            Path::new("definitely-missing-evidence.tar"),
            identity,
        )
        .expect_err("Hub source drift must fail before touching inputs");
        assert!(error.to_string().contains("Hub merge"));
    }
}
