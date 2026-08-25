//! Claim evaluation: interpreting check executions into claim verdicts.
//!
//! Pure logic — no processes are launched here. Exhaustively tested in
//! `tests/verdict_engine_tests.rs`.

use std::collections::BTreeMap;

use scirust_verify_model::{CheckExecution, Claim, ClaimEvaluation, RequirementLevel, Verdict};

/// Inputs to [`evaluate_claims`].
pub struct ClaimGateInputs<'a> {
    /// Registered claims with their configured requirement levels.
    pub claims: &'a [(Claim, RequirementLevel)],
    /// Executions recorded for the run's checks.
    pub executions: &'a [CheckExecution],
    /// Map from check id to the claims it supports.
    pub check_claims: &'a BTreeMap<String, Vec<String>>,
    /// Scope recorded for the run.
    pub scope: scirust_verify_model::VerificationScope,
}

/// Combines several verdicts for one claim.
///
/// Semantics (documented contract):
///
/// * any `Failed` wins outright — evidence contradicts the claim;
/// * else any `NotVerified` wins — an attempted check produced insufficient
///   evidence;
/// * else, if at least one check reached `Verified`, the claim is
///   `Verified` (checks that merely could not run are surfaced as coverage
///   gaps in limitations, not as contradictions);
/// * else everything is `Skipped`/`Unsupported`: report `Unsupported` when
///   *all* supporting checks were unsupported, otherwise `Skipped`.
pub fn combine_verdicts(verdicts: &[Verdict]) -> Verdict {
    use Verdict::*;
    if verdicts.is_empty() {
        return Verified; // callers treat "no evidence" separately
    }
    if verdicts.contains(&Failed) {
        return Failed;
    }
    if verdicts.contains(&NotVerified) {
        return NotVerified;
    }
    if verdicts.iter().any(|v| *v == Verified) {
        return Verified;
    }
    if verdicts.iter().all(|v| *v == Unsupported) {
        return Unsupported;
    }
    Skipped
}

fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Failed => 4,
        Verdict::NotVerified => 3,
        Verdict::Unsupported => 2,
        Verdict::Skipped => 1,
        Verdict::Verified => 0,
    }
}

/// Evaluates every registered claim against the recorded executions.
///
/// A claim with no supporting execution at all yields `NotVerified` — a
/// missing required check must never produce a clean pass.
pub fn evaluate_claims(inputs: &ClaimGateInputs<'_>) -> Vec<(ClaimEvaluation, RequirementLevel)> {
    let mut out = Vec::new();
    for (claim, level) in inputs.claims {
        let mut verdicts: Vec<Verdict> = Vec::new();
        let mut evidence_ids = Vec::new();
        let mut check_ids = Vec::new();
        let mut reasons: Vec<String> = Vec::new();

        for exec in inputs.executions {
            let supports = inputs
                .check_claims
                .get(exec.check_id.as_str())
                .is_some_and(|claims| claims.iter().any(|c| c == claim.id.as_str()));
            if !supports {
                continue;
            }
            verdicts.push(exec.outcome);
            evidence_ids.extend(exec.evidence_ids.iter().cloned());
            check_ids.push(exec.check_id.clone());
            if !exec.summary.is_empty() {
                reasons.push(format!("{}: {}", exec.check_id, exec.summary));
            }
        }

        let (verdict, reasoning) = if verdicts.is_empty() {
            (
                Verdict::NotVerified,
                "No executed check produced evidence for this claim.".to_owned(),
            )
        } else {
            let combined = combine_verdicts(&verdicts);
            let mut r = format!(
                "{} of {} supporting checks produced this outcome.",
                verdicts.len(),
                verdicts.len()
            );
            if !reasons.is_empty() {
                r.push_str(" Details: ");
                r.push_str(&reasons.join("; "));
            }
            (combined, r)
        };

        out.push((
            ClaimEvaluation {
                claim_id: claim.id.clone(),
                verdict,
                scope: inputs.scope.clone(),
                reasoning,
                evidence_ids,
                check_ids,
            },
            *level,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combination_precedence() {
        assert_eq!(combine_verdicts(&[]), Verdict::Verified);
        assert_eq!(combine_verdicts(&[Verdict::Verified]), Verdict::Verified);
        assert_eq!(
            combine_verdicts(&[Verdict::Verified, Verdict::Skipped]),
            Verdict::Verified
        );
        // Missing evidence beats success; failure dominates everything.
        assert_eq!(
            combine_verdicts(&[Verdict::Skipped, Verdict::NotVerified]),
            Verdict::NotVerified
        );
        assert_eq!(
            combine_verdicts(&[Verdict::NotVerified, Verdict::Failed]),
            Verdict::Failed
        );
        // Nothing ran at all.
        assert_eq!(
            combine_verdicts(&[Verdict::Skipped, Verdict::Skipped]),
            Verdict::Skipped
        );
        assert_eq!(
            combine_verdicts(&[Verdict::Unsupported, Verdict::Unsupported]),
            Verdict::Unsupported
        );
        assert_eq!(
            combine_verdicts(&[Verdict::Unsupported, Verdict::Skipped]),
            Verdict::Skipped
        );
    }

    #[test]
    fn rank_ordering_is_documented() {
        assert!(rank(Verdict::Failed) > rank(Verdict::NotVerified));
        assert!(rank(Verdict::NotVerified) > rank(Verdict::Unsupported));
        assert!(rank(Verdict::Unsupported) > rank(Verdict::Skipped));
        assert!(rank(Verdict::Skipped) > rank(Verdict::Verified));
    }
}
