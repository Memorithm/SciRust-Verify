//! Verify dossier signature validity and apply an explicit local key trust policy.
//!
//! The policy authorizes exact Ed25519 public-key fingerprints. It does not
//! assign human identity to keys, provide a PKI, or create trusted timestamps.

#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use scirust_verify_model::Digest;
use scirust_verify_signature::{read_public_key, verify_bundle_signature};
use scirust_verify_store::{RunState, RunsRoot};
use serde::{Deserialize, Serialize};

const POLICY_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "scirust-verify-signature-policy",
    version,
    about = "Verify a dossier signature and apply an explicit fingerprint trust policy"
)]
struct Cli {
    /// Finalized run id whose bundle was signed.
    run: String,
    /// Detached signature JSON file.
    #[arg(long)]
    signature: PathBuf,
    /// Ed25519 public-key JSON file used for cryptographic verification.
    #[arg(long)]
    public_key: PathBuf,
    /// Local trust policy JSON file.
    #[arg(long)]
    policy: PathBuf,
    /// Project containing `.scirust-verify/runs`.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Emit JSON only.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignatureTrustPolicy {
    schema_version: u64,
    allowed_fingerprints_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revoked_fingerprints_sha256: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TrustOutcome {
    schema_version: u64,
    run_id: String,
    policy_sha256: String,
    bundle_files_verified: usize,
    signature_cryptographically_valid: bool,
    key_id: String,
    public_key_fingerprint_sha256: String,
    status: &'static str,
    trusted_by_policy: bool,
    reasons: Vec<String>,
    trust_boundary: &'static str,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match execute(&cli) {
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
                println!("key id            : {}", outcome.key_id);
                println!("fingerprint       : {}", outcome.public_key_fingerprint_sha256);
                println!("policy status     : {}", outcome.status);
                for reason in &outcome.reasons {
                    println!("reason            : {reason}");
                }
                println!("trust boundary    : {}", outcome.trust_boundary);
            }
            if outcome.trusted_by_policy {
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

fn execute(cli: &Cli) -> Result<TrustOutcome, String> {
    let policy_bytes = fs::read(&cli.policy)
        .map_err(|error| format!("cannot read policy `{}`: {error}", cli.policy.display()))?;
    let policy: SignatureTrustPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|error| format!("invalid signature trust policy JSON: {error}"))?;
    validate_policy(&policy)?;

    let runs = RunsRoot::new(cli.project.join(".scirust-verify").join("runs"));
    let store = runs
        .open(&cli.run)
        .map_err(|error| format!("run `{}` is not available: {error}", cli.run))?;
    let bundle_files_verified = store
        .verify_integrity()
        .map_err(|error| format!("run `{}` failed dossier integrity verification: {error}", cli.run))?;
    let run_doc = store
        .read_run_document()
        .map_err(|error| format!("run `{}` has unusable metadata: {error}", cli.run))?;
    if run_doc.state != RunState::Finalized {
        return Err(format!("run `{}` is not finalized", cli.run));
    }
    if run_doc.run_id.as_str() != cli.run {
        return Err(format!(
            "run id mismatch: requested `{}`, dossier declares `{}`",
            cli.run, run_doc.run_id
        ));
    }

    let public = read_public_key(&cli.public_key)
        .map_err(|error| format!("public key validation failed: {error}"))?;
    let verification = verify_bundle_signature(
        &cli.run,
        &store.path().join("bundle.json"),
        &cli.signature,
        &cli.public_key,
    )
    .map_err(|error| format!("signature verification failed: {error}"))?;

    let mut reasons = Vec::new();
    if policy
        .revoked_fingerprints_sha256
        .contains(&public.fingerprint_sha256)
    {
        reasons.push("public-key fingerprint is explicitly revoked by policy".to_owned());
    }
    if !policy
        .allowed_fingerprints_sha256
        .contains(&public.fingerprint_sha256)
    {
        reasons.push("public-key fingerprint is not present in the policy allowlist".to_owned());
    }
    if verification.key_id != public.key_id {
        return Err("signature verification returned an unexpected key identity".to_owned());
    }

    let trusted_by_policy = reasons.is_empty();
    Ok(TrustOutcome {
        schema_version: POLICY_SCHEMA_VERSION,
        run_id: cli.run.clone(),
        policy_sha256: Digest::sha256_hex(&policy_bytes).value,
        bundle_files_verified,
        signature_cryptographically_valid: verification.cryptographically_valid,
        key_id: public.key_id,
        public_key_fingerprint_sha256: public.fingerprint_sha256,
        status: if trusted_by_policy {
            "trusted_by_policy"
        } else {
            "not_trusted_by_policy"
        },
        trusted_by_policy,
        reasons,
        trust_boundary: "cryptographically valid under the supplied Ed25519 public key and authorized by an explicit local fingerprint policy; this does not establish human identity, PKI certification, key provenance, or trusted time",
    })
}

fn validate_policy(policy: &SignatureTrustPolicy) -> Result<(), String> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported signature trust policy schema version {} (expected {POLICY_SCHEMA_VERSION})",
            policy.schema_version
        ));
    }
    if policy.allowed_fingerprints_sha256.is_empty() {
        return Err("signature trust policy allowlist must not be empty".to_owned());
    }

    let mut seen = BTreeSet::new();
    for fingerprint in policy
        .allowed_fingerprints_sha256
        .iter()
        .chain(policy.revoked_fingerprints_sha256.iter())
    {
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "invalid SHA-256 public-key fingerprint `{fingerprint}`; expected 64 lowercase hex characters"
            ));
        }
    }
    for fingerprint in &policy.allowed_fingerprints_sha256 {
        if !seen.insert(fingerprint) {
            return Err(format!("duplicate allowed fingerprint `{fingerprint}`"));
        }
    }
    seen.clear();
    for fingerprint in &policy.revoked_fingerprints_sha256 {
        if !seen.insert(fingerprint) {
            return Err(format!("duplicate revoked fingerprint `{fingerprint}`"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn policy() -> SignatureTrustPolicy {
        SignatureTrustPolicy {
            schema_version: 1,
            allowed_fingerprints_sha256: vec![FINGERPRINT.to_owned()],
            revoked_fingerprints_sha256: Vec::new(),
        }
    }

    #[test]
    fn exact_fingerprint_policy_is_valid() {
        assert!(validate_policy(&policy()).is_ok());
    }

    #[test]
    fn empty_allowlist_fails_closed() {
        let mut document = policy();
        document.allowed_fingerprints_sha256.clear();
        assert!(validate_policy(&document).is_err());
    }

    #[test]
    fn malformed_fingerprint_is_rejected() {
        let mut document = policy();
        document.allowed_fingerprints_sha256 = vec!["not-a-sha256".into()];
        assert!(validate_policy(&document).is_err());
    }

    #[test]
    fn duplicate_fingerprint_is_rejected() {
        let mut document = policy();
        document.allowed_fingerprints_sha256.push(FINGERPRINT.into());
        assert!(validate_policy(&document).is_err());
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let json = format!(
            r#"{{"schema_version":1,"allowed_fingerprints_sha256":["{FINGERPRINT}"],"identity":"alice"}}"#
        );
        assert!(serde_json::from_str::<SignatureTrustPolicy>(&json).is_err());
    }

    #[test]
    fn revocation_has_explicit_precedence_over_allowlist() {
        let mut document = policy();
        document.revoked_fingerprints_sha256.push(FINGERPRINT.into());
        assert!(validate_policy(&document).is_ok());
        assert!(document
            .revoked_fingerprints_sha256
            .contains(&FINGERPRINT.to_owned()));
    }
}
