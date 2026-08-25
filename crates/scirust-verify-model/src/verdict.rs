//! Verdict semantics and requirement levels.
//!
//! # Verdict states
//!
//! * [`Verdict::Verified`] — the required property was established by
//!   recorded evidence under the recorded scope. This never implies the
//!   property holds outside that scope.
//! * [`Verdict::Failed`] — the check executed and evidence contradicts the
//!   requirement.
//! * [`Verdict::NotVerified`] — insufficient evidence to establish the claim
//!   (e.g. an execution was missing, output could not be parsed).
//! * [`Verdict::Skipped`] — an implementation exists but it could not run in
//!   this environment (e.g. optional tool not installed).
//! * [`Verdict::Unsupported`] — no implementation exists in this
//!   SciRust-Verify version for the requested verification.
//!
//! # Global (dossier) verdict
//!
//! Given per-check/claim results with their [`RequirementLevel`]:
//!
//! * any **required** `Failed`                => [`DossierVerdict::Fail`]
//! * else any **required** `Unsupported|NotVerified` => [`DossierVerdict::NotVerified`]
//! * else any **required** `Skipped`, or any **recommended** non-verified state,
//!   or any **required** claim missing entirely       => [`DossierVerdict::PassWithGaps`]
//! * else all required `Verified`                     => [`DossierVerdict::Pass`]
//!
//! `optional` and `informational` results never degrade the dossier below
//! `PassWithGaps`; their outcomes are reported but do not gate.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Outcome of a single check or claim evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Property established under the recorded scope.
    Verified,
    /// Evidence contradicts the requirement.
    Failed,
    /// Insufficient evidence to establish the claim.
    NotVerified,
    /// Implementation exists but could not run here.
    Skipped,
    /// No implementation exists for the requested verification.
    Unsupported,
}

impl Verdict {
    /// True for `Verified`.
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// True when the outcome represents a positive-or-neutral state that does
    /// not contradict the claim (`Verified`, `Skipped`, `Unsupported`).
    pub fn is_not_contradicted(self) -> bool {
        !matches!(self, Self::Failed | Self::NotVerified)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Verified => "VERIFIED",
            Self::Failed => "FAILED",
            Self::NotVerified => "NOT_VERIFIED",
            Self::Skipped => "SKIPPED",
            Self::Unsupported => "UNSUPPORTED",
        })
    }
}

/// How strongly a check or claim gates the overall result.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RequirementLevel {
    /// Must verify for a clean pass.
    #[default]
    Required,
    /// Expected to verify; failure produces a gap warning, not a hard fail.
    Recommended,
    /// Evaluated opportunistically; never gates.
    Optional,
    /// Pure observation; never gates and gaps are not reported for it.
    Informational,
}

impl fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Required => "required",
            Self::Recommended => "recommended",
            Self::Optional => "optional",
            Self::Informational => "informational",
        })
    }
}

/// Aggregated verdict for a whole evidence dossier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DossierVerdict {
    /// All required checks verified.
    Pass,
    /// All executed required checks verified, but coverage has gaps
    /// (skipped required checks, missing claims, degraded recommended items).
    PassWithGaps,
    /// Required properties could not be established.
    NotVerified,
    /// At least one required property failed on recorded evidence.
    Fail,
}

impl DossierVerdict {
    /// Process exit-code convention: pass-like => 0, otherwise 1.
    pub fn exit_success(self) -> bool {
        matches!(self, Self::Pass | Self::PassWithGaps)
    }

    /// Stable uppercase label used in reports.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::PassWithGaps => "PASS_WITH_GAPS",
            Self::NotVerified => "NOT_VERIFIED",
            Self::Fail => "FAIL",
        }
    }
}

impl fmt::Display for DossierVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One gating input to [`aggregate_dossier_verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatingItem {
    /// Requirement level of the item.
    pub level: RequirementLevel,
    /// Its individual verdict.
    pub verdict: Verdict,
}

/// Pure aggregation of individual verdicts into a dossier verdict.
///
/// The function is total and side-effect free so the policy can be tested
/// exhaustively without launching processes.
pub fn aggregate_dossier_verdict(items: &[GatingItem]) -> DossierVerdict {
    let mut fail = false;
    let mut not_established = false;
    let mut gaps = false;

    for item in items {
        match item.level {
            RequirementLevel::Required => match item.verdict {
                Verdict::Failed => fail = true,
                Verdict::NotVerified | Verdict::Unsupported => not_established = true,
                Verdict::Skipped => gaps = true,
                Verdict::Verified => {}
            },
            RequirementLevel::Recommended => {
                if !item.verdict.is_verified() {
                    // A recommended item that ran and failed is a stronger
                    // signal than one that merely could not run; both are
                    // treated as coverage gaps, never as hard failures.
                    gaps = true;
                }
            }
            RequirementLevel::Optional | RequirementLevel::Informational => {
                // Never gates. Failures of optional checks are surfaced as
                // limitations elsewhere, but they cannot degrade the dossier.
            }
        }
    }

    if fail {
        DossierVerdict::Fail
    } else if not_established {
        DossierVerdict::NotVerified
    } else if gaps {
        DossierVerdict::PassWithGaps
    } else {
        DossierVerdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(level: RequirementLevel, verdict: Verdict) -> GatingItem {
        GatingItem { level, verdict }
    }

    #[test]
    fn empty_is_pass() {
        assert_eq!(aggregate_dossier_verdict(&[]), DossierVerdict::Pass);
    }

    #[test]
    fn all_required_verified_is_pass() {
        let items = vec![item(RequirementLevel::Required, Verdict::Verified); 3];
        assert_eq!(aggregate_dossier_verdict(&items), DossierVerdict::Pass);
    }

    #[test]
    fn matrix() {
        use RequirementLevel::*;
        use Verdict::*;
        // (level, verdict, expected)
        let cases = [
            (Required, Verified, DossierVerdict::Pass),
            (Required, Failed, DossierVerdict::Fail),
            (Required, NotVerified, DossierVerdict::NotVerified),
            (Required, Unsupported, DossierVerdict::NotVerified),
            (Required, Skipped, DossierVerdict::PassWithGaps),
            (Recommended, Verified, DossierVerdict::Pass),
            (Recommended, Failed, DossierVerdict::PassWithGaps),
            (Recommended, Skipped, DossierVerdict::PassWithGaps),
            (Optional, Failed, DossierVerdict::Pass),
            (Optional, Skipped, DossierVerdict::Pass),
            (Optional, NotVerified, DossierVerdict::Pass),
            (Informational, Failed, DossierVerdict::Pass),
        ];
        for (level, verdict, expected) in cases {
            assert_eq!(
                aggregate_dossier_verdict(&[item(level, verdict)]),
                expected,
                "case {level:?}/{verdict:?}"
            );
        }
    }

    #[test]
    fn precedence_fail_beats_everything() {
        let items = vec![
            item(RequirementLevel::Required, Verdict::Skipped),
            item(RequirementLevel::Recommended, Verdict::Failed),
            item(RequirementLevel::Required, Verdict::NotVerified),
            item(RequirementLevel::Required, Verdict::Failed),
            item(RequirementLevel::Required, Verdict::Verified),
        ];
        assert_eq!(aggregate_dossier_verdict(&items), DossierVerdict::Fail);

        let items2 = vec![
            item(RequirementLevel::Required, Verdict::NotVerified),
            item(RequirementLevel::Required, Verdict::Skipped),
        ];
        assert_eq!(
            aggregate_dossier_verdict(&items2),
            DossierVerdict::NotVerified
        );
    }

    #[test]
    fn serde_roundtrip() {
        for v in [
            Verdict::Verified,
            Verdict::Failed,
            Verdict::NotVerified,
            Verdict::Skipped,
            Verdict::Unsupported,
        ] {
            assert_eq!(
                serde_json::from_str::<Verdict>(&serde_json::to_string(&v).unwrap()).unwrap(),
                v
            );
        }
        assert_eq!(
            serde_json::to_string(&DossierVerdict::PassWithGaps).unwrap(),
            "\"pass_with_gaps\""
        );
        assert_eq!(
            serde_json::to_string(&RequirementLevel::default()).unwrap(),
            "\"required\""
        );
    }
}
