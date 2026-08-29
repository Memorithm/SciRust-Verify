//! Evaluate a finalized evidence dossier against a declarative JSON policy.
//!
//! This evaluator never rewrites scientific verdicts. It only decides whether
//! integrity-verified recorded claim evaluations satisfy caller-supplied rules.

#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use scirust_verify_model::{ClaimEvaluation, Digest, Verdict};
use scirust_verify_store::{RunState, RunsRoot};
use serde::{Deserialize, Serialize};

const POLICY_SCHEMA_VERSION: u64 = 1;

#[derive(Parser)]
#[command(
    name = "scirust-verify-policy",
    version,
    about = "Evaluate a sealed SciRust-Verify dossier against a machine-readable policy"
)]
struct Cli {
    /// Finalized run id to evaluate.
    run: String,
    /// JSON policy document.
    #[arg(long)]
    policy: PathBuf,
    /// Project containing `.scirust-verify/runs`.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Emit JSON only.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MatchMode {
    Exact,
    Contains,
}

fn default_match_mode() -> MatchMode {
    MatchMode::Exact
}

fn default_allowed_verdicts() -> Vec<Verdict> {
    vec![Verdict::Verified]
}

fn default_min_matches() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyRule {
    id: String,
    claim: String,
    #[serde(default = "default_match_mode")]
    match_mode: MatchMode,
    #[serde(default = "default_allowed_verdicts")]
    allowed_verdicts: Vec<Verdict>,
    #[serde(default = "default_min_matches")]
    min_matches: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_matches: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    schema_version: u64,
    rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone)]
struct RecordedEvaluation {
    claim_id: String,
    verdict: Verdict,
}

#[derive(Debug, Serialize)]
struct MatchRecord {
    claim_id: String,
    verdict: String,
}

#[derive(Debug, Serialize)]
struct RuleResult {
    id: String,
    claim: String,
    match_mode: MatchMode,
    allowed_verdicts: Vec<String>,
    min_matches: usize,
    max_matches: Option<usize>,
    matched: usize,
    satisfied: bool,
    matches: Vec<MatchRecord>,
    reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PolicyOutcome {
    schema_version: u64,
    run_id: String,
    policy_sha256: String,
    verified_bundle_files: usize,
    status: &'static str,
    satisfied: bool,
    rules: Vec<RuleResult>,
    trust_boundary: &'static str,
}

#[derive(Debug)]
enum PolicyError {
    InvalidPolicy(String),
    Evidence(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl PolicyError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::InvalidPolicy(_) | Self::Json { .. } => 2,
            Self::Evidence(_) => 1,
            Self::Io { .. } => 3,
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPolicy(message) | Self::Evidence(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "filesystem error at `{}`: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(f, "invalid JSON at `{}`: {source}", path.display())
            }
        }
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match execute(&cli.run, &cli.policy, &cli.project) {
        Ok(outcome) => {
            print_outcome(&outcome, cli.json);
            if outcome.satisfied {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(error.exit_code())
        }
    }
}

fn print_outcome(outcome: &PolicyOutcome, json: bool) {
    if json {
        match serde_json::to_string_pretty(outcome) {
            Ok(document) => println!("{document}"),
            Err(error) => eprintln!("error: failed to serialize policy result: {error}"),
        }
        return;
    }

    println!("run               : {}", outcome.run_id);
    println!("policy sha256     : {}", outcome.policy_sha256);
    println!("bundle files      : {}", outcome.verified_bundle_files);
    println!("policy status     : {}", outcome.status);
    for rule in &outcome.rules {
        println!(
            "rule {:<20} : {} ({} match(es))",
            rule.id,
            if rule.satisfied {
                "SATISFIED"
            } else {
                "NOT_SATISFIED"
            },
            rule.matched
        );
    }
    println!("trust boundary    : {}", outcome.trust_boundary);
}

fn execute(run_id: &str, policy_path: &Path, project: &Path) -> Result<PolicyOutcome, PolicyError> {
    let policy_bytes = fs::read(policy_path).map_err(|source| PolicyError::Io {
        path: policy_path.to_path_buf(),
        source,
    })?;
    let policy: PolicyDocument =
        serde_json::from_slice(&policy_bytes).map_err(|source| PolicyError::Json {
            path: policy_path.to_path_buf(),
            source,
        })?;
    validate_policy(&policy)?;

    let runs = RunsRoot::new(project.join(".scirust-verify").join("runs"));
    let store = runs.open(run_id).map_err(|error| {
        PolicyError::Evidence(format!("run `{run_id}` is not available: {error}"))
    })?;
    let verified_bundle_files = store.verify_integrity().map_err(|error| {
        PolicyError::Evidence(format!(
            "run `{run_id}` failed dossier integrity verification: {error}"
        ))
    })?;
    let run_doc = store.read_run_document().map_err(|error| {
        PolicyError::Evidence(format!("run `{run_id}` has unusable run metadata: {error}"))
    })?;
    if run_doc.state != RunState::Finalized {
        return Err(PolicyError::Evidence(format!(
            "run `{run_id}` is {:?}, not finalized",
            run_doc.state
        )));
    }
    if run_doc.run_id.as_str() != run_id {
        return Err(PolicyError::Evidence(format!(
            "run id mismatch: requested `{run_id}`, dossier declares `{}`",
            run_doc.run_id
        )));
    }

    let text = store.read_text("evaluations.json").map_err(|error| {
        PolicyError::Evidence(format!(
            "run `{run_id}` has no usable sealed evaluations document: {error}"
        ))
    })?;
    let evaluations = parse_evaluations(&text)?;
    let rules = evaluate_policy(&policy, &evaluations);
    let satisfied = rules.iter().all(|rule| rule.satisfied);

    Ok(PolicyOutcome {
        schema_version: POLICY_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        policy_sha256: Digest::sha256_hex(&policy_bytes).value,
        verified_bundle_files,
        status: if satisfied {
            "satisfied"
        } else {
            "not_satisfied"
        },
        satisfied,
        rules,
        trust_boundary: "policy satisfaction over integrity-verified recorded claim evaluations only; this does not strengthen or replace their original verification semantics",
    })
}

fn validate_policy(policy: &PolicyDocument) -> Result<(), PolicyError> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::InvalidPolicy(format!(
            "unsupported policy schema version {} (expected {POLICY_SCHEMA_VERSION})",
            policy.schema_version
        )));
    }
    if policy.rules.is_empty() {
        return Err(PolicyError::InvalidPolicy(
            "policy must contain at least one rule".into(),
        ));
    }

    let mut ids = BTreeSet::new();
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            return Err(PolicyError::InvalidPolicy(
                "policy rule id must not be empty".into(),
            ));
        }
        if !ids.insert(rule.id.clone()) {
            return Err(PolicyError::InvalidPolicy(format!(
                "duplicate policy rule id `{}`",
                rule.id
            )));
        }
        if rule.claim.is_empty() {
            return Err(PolicyError::InvalidPolicy(format!(
                "policy rule `{}` has an empty claim selector",
                rule.id
            )));
        }
        if rule.allowed_verdicts.is_empty() {
            return Err(PolicyError::InvalidPolicy(format!(
                "policy rule `{}` accepts no verdicts",
                rule.id
            )));
        }
        if rule.min_matches == 0 {
            return Err(PolicyError::InvalidPolicy(format!(
                "policy rule `{}` must require at least one match",
                rule.id
            )));
        }
        if let Some(max_matches) = rule
            .max_matches
            .filter(|max_matches| *max_matches < rule.min_matches)
        {
            return Err(PolicyError::InvalidPolicy(format!(
                "policy rule `{}` has max_matches {max_matches} < min_matches {}",
                rule.id, rule.min_matches
            )));
        }
    }
    Ok(())
}

fn parse_evaluations(text: &str) -> Result<Vec<RecordedEvaluation>, PolicyError> {
    let document: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        PolicyError::Evidence(format!("sealed evaluations.json is malformed: {error}"))
    })?;
    let entries = document
        .get("evaluations")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            PolicyError::Evidence("sealed evaluations.json has no evaluations array".into())
        })?;

    entries
        .iter()
        .map(|entry| {
            let value = entry.get("evaluation").cloned().ok_or_else(|| {
                PolicyError::Evidence("evaluation entry is missing `evaluation`".into())
            })?;
            let evaluation: ClaimEvaluation = serde_json::from_value(value).map_err(|error| {
                PolicyError::Evidence(format!("invalid sealed claim evaluation: {error}"))
            })?;
            Ok(RecordedEvaluation {
                claim_id: evaluation.claim_id.as_str().to_owned(),
                verdict: evaluation.verdict,
            })
        })
        .collect()
}

fn evaluate_policy(policy: &PolicyDocument, evaluations: &[RecordedEvaluation]) -> Vec<RuleResult> {
    policy
        .rules
        .iter()
        .map(|rule| evaluate_rule(rule, evaluations))
        .collect()
}

fn evaluate_rule(rule: &PolicyRule, evaluations: &[RecordedEvaluation]) -> RuleResult {
    let matching: Vec<_> = evaluations
        .iter()
        .filter(|evaluation| match rule.match_mode {
            MatchMode::Exact => evaluation.claim_id == rule.claim,
            MatchMode::Contains => evaluation.claim_id.contains(&rule.claim),
        })
        .collect();

    let mut reasons = Vec::new();
    if matching.len() < rule.min_matches {
        reasons.push(format!(
            "found {} matching evaluation(s), policy requires at least {}",
            matching.len(),
            rule.min_matches
        ));
    }
    if let Some(max_matches) = rule
        .max_matches
        .filter(|max_matches| matching.len() > *max_matches)
    {
        reasons.push(format!(
            "found {} matching evaluation(s), policy allows at most {max_matches}",
            matching.len()
        ));
    }
    for evaluation in &matching {
        if !rule.allowed_verdicts.contains(&evaluation.verdict) {
            reasons.push(format!(
                "claim `{}` has verdict {}, which is not accepted by this rule",
                evaluation.claim_id, evaluation.verdict
            ));
        }
    }

    RuleResult {
        id: rule.id.clone(),
        claim: rule.claim.clone(),
        match_mode: rule.match_mode,
        allowed_verdicts: rule
            .allowed_verdicts
            .iter()
            .map(ToString::to_string)
            .collect(),
        min_matches: rule.min_matches,
        max_matches: rule.max_matches,
        matched: matching.len(),
        satisfied: reasons.is_empty(),
        matches: matching
            .into_iter()
            .map(|evaluation| MatchRecord {
                claim_id: evaluation.claim_id.clone(),
                verdict: evaluation.verdict.to_string(),
            })
            .collect(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, claim: &str) -> PolicyRule {
        PolicyRule {
            id: id.into(),
            claim: claim.into(),
            match_mode: MatchMode::Exact,
            allowed_verdicts: vec![Verdict::Verified],
            min_matches: 1,
            max_matches: None,
        }
    }

    fn policy(rules: Vec<PolicyRule>) -> PolicyDocument {
        PolicyDocument {
            schema_version: POLICY_SCHEMA_VERSION,
            rules,
        }
    }

    #[test]
    fn verified_exact_claim_satisfies_policy() {
        let result = evaluate_policy(
            &policy(vec![rule("tests", "tests_pass@cargo")]),
            &[RecordedEvaluation {
                claim_id: "tests_pass@cargo".into(),
                verdict: Verdict::Verified,
            }],
        );
        assert!(result[0].satisfied);
    }

    #[test]
    fn failed_claim_is_preserved_and_rejected() {
        let result = evaluate_policy(
            &policy(vec![rule("tests", "tests_pass@cargo")]),
            &[RecordedEvaluation {
                claim_id: "tests_pass@cargo".into(),
                verdict: Verdict::Failed,
            }],
        );
        assert!(!result[0].satisfied);
        assert_eq!(result[0].matches[0].verdict, "FAILED");
    }

    #[test]
    fn missing_claim_fails_closed() {
        let result = evaluate_policy(&policy(vec![rule("tests", "tests_pass@cargo")]), &[]);
        assert!(!result[0].satisfied);
        assert!(result[0].reasons[0].contains("requires at least 1"));
    }

    #[test]
    fn one_not_verified_match_prevents_satisfaction() {
        let mut selected = rule("numeric", "numerically_close");
        selected.match_mode = MatchMode::Contains;
        selected.min_matches = 2;
        let result = evaluate_policy(
            &policy(vec![selected]),
            &[
                RecordedEvaluation {
                    claim_id: "numerically_close@a".into(),
                    verdict: Verdict::Verified,
                },
                RecordedEvaluation {
                    claim_id: "numerically_close@b".into(),
                    verdict: Verdict::NotVerified,
                },
            ],
        );
        assert!(!result[0].satisfied);
        assert!(result[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("NOT_VERIFIED")));
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let document = policy(vec![rule("same", "a"), rule("same", "b")]);
        let error = validate_policy(&document).expect_err("duplicate ids must fail");
        assert!(error.to_string().contains("duplicate policy rule id"));
    }

    #[test]
    fn impossible_match_bounds_are_rejected() {
        let mut selected = rule("tests", "tests_pass@cargo");
        selected.min_matches = 2;
        selected.max_matches = Some(1);
        let error = validate_policy(&policy(vec![selected])).expect_err("bounds must fail");
        assert!(error.to_string().contains("max_matches 1 < min_matches 2"));
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let json = r#"{
          "schema_version": 1,
          "rules": [{"id":"tests","claim":"tests_pass@cargo","unexpected":true}]
        }"#;
        assert!(serde_json::from_str::<PolicyDocument>(json).is_err());
    }

    #[test]
    fn malformed_evaluation_document_fails_closed() {
        let error = parse_evaluations(r#"{"evaluations":[{}]}"#)
            .expect_err("missing evaluation object must fail");
        assert!(error.to_string().contains("missing `evaluation`"));
    }
}
