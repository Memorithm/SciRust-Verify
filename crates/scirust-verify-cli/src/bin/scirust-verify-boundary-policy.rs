//! Evaluate a finalized dossier's sealed execution boundary against JSON policy.
//!
//! This command evaluates producer-declared provenance only. A matching
//! boundary is not remote attestation and does not strengthen scientific
//! claim verdicts.

#![deny(missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use scirust_verify_model::{Digest, EnvironmentSnapshot};
use scirust_verify_store::{RunState, RunsRoot};
use serde::{Deserialize, Serialize};

const POLICY_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "scirust-verify-boundary-policy",
    version,
    about = "Evaluate a sealed execution-boundary declaration against JSON policy"
)]
struct Cli {
    /// Finalized run id to evaluate.
    run: String,
    /// Boundary policy JSON document.
    #[arg(long)]
    policy: PathBuf,
    /// Project containing `.scirust-verify/runs`.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Emit JSON only.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundaryPolicy {
    schema_version: u64,
    mechanism: String,
    profile: String,
    assertion_scope: String,
}

#[derive(Debug, Serialize)]
struct BoundaryOutcome {
    schema_version: u64,
    run_id: String,
    policy_sha256: String,
    verified_bundle_files: usize,
    status: &'static str,
    satisfied: bool,
    observed_mechanism: Option<String>,
    observed_profile: Option<String>,
    observed_assertion_scope: Option<String>,
    reasons: Vec<String>,
    trust_boundary: &'static str,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match execute(&cli.run, &cli.policy, &cli.project) {
        Ok(outcome) => {
            if cli.json {
                match serde_json::to_string_pretty(&outcome) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        eprintln!("error: cannot serialize result: {error}");
                        return std::process::ExitCode::from(3);
                    }
                }
            } else {
                println!("run               : {}", outcome.run_id);
                println!("policy sha256     : {}", outcome.policy_sha256);
                println!("policy status     : {}", outcome.status);
                for reason in &outcome.reasons {
                    println!("reason            : {reason}");
                }
                println!("trust boundary    : {}", outcome.trust_boundary);
            }
            if outcome.satisfied {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn execute(run_id: &str, policy_path: &Path, project: &Path) -> Result<BoundaryOutcome, String> {
    let policy_bytes = fs::read(policy_path)
        .map_err(|error| format!("cannot read policy `{}`: {error}", policy_path.display()))?;
    let policy: BoundaryPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|error| format!("invalid boundary policy JSON: {error}"))?;
    validate_policy(&policy)?;

    let runs = RunsRoot::new(project.join(".scirust-verify").join("runs"));
    let store = runs
        .open(run_id)
        .map_err(|error| format!("run `{run_id}` is not available: {error}"))?;
    let verified_bundle_files = store.verify_integrity().map_err(|error| {
        format!("run `{run_id}` failed dossier integrity verification: {error}")
    })?;
    let run_doc = store
        .read_run_document()
        .map_err(|error| format!("run `{run_id}` has unusable metadata: {error}"))?;
    if run_doc.state != RunState::Finalized {
        return Err(format!("run `{run_id}` is not finalized"));
    }
    if run_doc.run_id.as_str() != run_id {
        return Err(format!(
            "run id mismatch: requested `{run_id}`, dossier declares `{}`",
            run_doc.run_id
        ));
    }

    let environment_text = store
        .read_text("environment.json")
        .map_err(|error| format!("sealed environment.json is unavailable: {error}"))?;
    let environment: EnvironmentSnapshot = serde_json::from_str(&environment_text)
        .map_err(|error| format!("sealed environment.json is malformed: {error}"))?;

    let mut reasons = Vec::new();
    let (observed_mechanism, observed_profile, observed_assertion_scope) =
        match environment.execution_boundary {
            Some(boundary) => {
                if boundary.mechanism != policy.mechanism {
                    reasons.push(format!(
                        "mechanism `{}` does not match required `{}`",
                        boundary.mechanism, policy.mechanism
                    ));
                }
                if boundary.profile != policy.profile {
                    reasons.push(format!(
                        "profile `{}` does not match required `{}`",
                        boundary.profile, policy.profile
                    ));
                }
                if boundary.assertion_scope != policy.assertion_scope {
                    reasons.push(format!(
                        "assertion_scope `{}` does not match required `{}`",
                        boundary.assertion_scope, policy.assertion_scope
                    ));
                }
                (
                    Some(boundary.mechanism),
                    Some(boundary.profile),
                    Some(boundary.assertion_scope),
                )
            }
            None => {
                reasons.push("dossier records no execution boundary".to_owned());
                (None, None, None)
            }
        };

    let satisfied = reasons.is_empty();
    Ok(BoundaryOutcome {
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
        observed_mechanism,
        observed_profile,
        observed_assertion_scope,
        reasons,
        trust_boundary: "exact policy matching over an integrity-sealed producer-declared execution boundary; this is not remote attestation or a formal safety proof",
    })
}

fn validate_policy(policy: &BoundaryPolicy) -> Result<(), String> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported boundary policy schema version {} (expected {POLICY_SCHEMA_VERSION})",
            policy.schema_version
        ));
    }
    for (name, value) in [
        ("mechanism", policy.mechanism.as_str()),
        ("profile", policy.profile.as_str()),
        ("assertion_scope", policy.assertion_scope.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("boundary policy `{name}` must not be empty"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_verify_model::ExecutionBoundary;

    fn policy() -> BoundaryPolicy {
        BoundaryPolicy {
            schema_version: 1,
            mechanism: "bubblewrap".into(),
            profile: "bubblewrap-v1".into(),
            assertion_scope: "producer_declared_not_attested".into(),
        }
    }

    fn reasons_for(policy: &BoundaryPolicy, boundary: Option<ExecutionBoundary>) -> Vec<String> {
        let mut reasons = Vec::new();
        match boundary {
            Some(boundary) => {
                if boundary.mechanism != policy.mechanism {
                    reasons.push("mechanism mismatch".into());
                }
                if boundary.profile != policy.profile {
                    reasons.push("profile mismatch".into());
                }
                if boundary.assertion_scope != policy.assertion_scope {
                    reasons.push("assertion scope mismatch".into());
                }
            }
            None => reasons.push("missing boundary".into()),
        }
        reasons
    }

    #[test]
    fn exact_boundary_satisfies_policy_predicate() {
        let expected = policy();
        let boundary = ExecutionBoundary {
            mechanism: expected.mechanism.clone(),
            profile: expected.profile.clone(),
            assertion_scope: expected.assertion_scope.clone(),
        };
        assert!(reasons_for(&expected, Some(boundary)).is_empty());
    }

    #[test]
    fn missing_boundary_fails_closed() {
        assert!(!reasons_for(&policy(), None).is_empty());
    }

    #[test]
    fn wrong_profile_fails_closed() {
        let boundary = ExecutionBoundary {
            mechanism: "bubblewrap".into(),
            profile: "bubblewrap-v2".into(),
            assertion_scope: "producer_declared_not_attested".into(),
        };
        assert!(!reasons_for(&policy(), Some(boundary)).is_empty());
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let json = r#"{
          "schema_version":1,
          "mechanism":"bubblewrap",
          "profile":"bubblewrap-v1",
          "assertion_scope":"producer_declared_not_attested",
          "trusted":true
        }"#;
        assert!(serde_json::from_str::<BoundaryPolicy>(json).is_err());
    }

    #[test]
    fn empty_policy_identity_is_rejected() {
        let mut invalid = policy();
        invalid.profile.clear();
        assert!(validate_policy(&invalid).is_err());
    }
}
