//! CLI glue for detached evidence-dossier signatures.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use scirust_verify_signature::{
    generate_keypair, read_public_key, sign_bundle, signature_path, verify_bundle_signature,
    SignatureError,
};
use scirust_verify_store::RunsRoot;

use crate::{current_dir, locate_runs_root, CliError};

pub(crate) fn keygen(
    private_key: PathBuf,
    public_key: PathBuf,
    force: bool,
    json: bool,
) -> Result<ExitCode, CliError> {
    let public = generate_keypair(&private_key, &public_key, force)
        .map_err(|e| map_signature_error(e, false))?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "algorithm": public.algorithm,
                "key_id": public.key_id,
                "fingerprint_sha256": public.fingerprint_sha256,
                "private_key_path": private_key,
                "public_key_path": public_key,
                "private_key_printed": false,
            })
        );
    } else {
        println!("generated Ed25519 keypair");
        println!("  key id:      {}", public.key_id);
        println!("  fingerprint: {}", public.fingerprint_sha256);
        println!("  private key: {}", private_key.display());
        println!("  public key:  {}", public_key.display());
        println!("private key material is never printed by SciRust-Verify");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn sign(
    run: &str,
    private_key: PathBuf,
    project: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<ExitCode, CliError> {
    let root = resolve_project(project)?;
    let store = open_run_under(&root, run)?;
    store.verify_integrity().map_err(|e| CliError {
        message: format!("refusing to sign dossier with invalid integrity: {e}"),
        exit_code: 1,
    })?;
    let bundle = store.path().join("bundle.json");
    let signatures_root = root.join(".scirust-verify/signatures");
    let (signature, path) = sign_bundle(
        run,
        &bundle,
        &private_key,
        &signatures_root,
        force,
    )
    .map_err(|e| map_signature_error(e, false))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "run_id": run,
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
                "bundle_sha256": signature.bundle_sha256,
                "signature_path": path,
                "signed_at_utc": signature.signed_at_utc,
                "trusted_timestamp": false,
            })
        );
    } else {
        println!("signed finalized evidence dossier");
        println!("  run:         {run}");
        println!("  key id:      {}", signature.key_id);
        println!("  bundle hash: {}", signature.bundle_sha256);
        println!("  signature:   {}", path.display());
        println!("note: signed_at_utc is self-reported, not a trusted timestamp");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn verify_signature(
    run: &str,
    public_key: PathBuf,
    signature: Option<PathBuf>,
    project: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode, CliError> {
    let root = resolve_project(project)?;
    let store = open_run_under(&root, run)?;
    store.verify_integrity().map_err(|e| CliError {
        message: format!("dossier integrity verification failed before signature check: {e}"),
        exit_code: 1,
    })?;
    let public = read_public_key(&public_key).map_err(|e| map_signature_error(e, true))?;
    let signatures_root = root.join(".scirust-verify/signatures");
    let signature = signature.unwrap_or_else(|| signature_path(&signatures_root, run, &public.key_id));
    let verification = verify_bundle_signature(
        run,
        &store.path().join("bundle.json"),
        &signature,
        &public_key,
    )
    .map_err(|e| map_signature_error(e, true))?;

    if json {
        println!("{}", serde_json::to_string(&verification).map_err(|e| CliError {
            message: format!("serialize signature verification: {e}"),
            exit_code: 3,
        })?);
    } else {
        println!("signature: VALID");
        println!("  run:         {}", verification.run_id);
        println!("  key id:      {}", verification.key_id);
        println!("  bundle hash: {}", verification.bundle_sha256);
        println!("  trust scope: {}", verification.trust_scope);
    }
    Ok(ExitCode::SUCCESS)
}

fn resolve_project(project: Option<PathBuf>) -> Result<PathBuf, CliError> {
    match project {
        Some(path) => Ok(path.canonicalize().unwrap_or(path)),
        None => locate_runs_root().or_else(|_| Ok(current_dir())),
    }
}

fn open_run_under(root: &Path, run: &str) -> Result<scirust_verify_store::RunStore, CliError> {
    RunsRoot::new(root.join(".scirust-verify/runs"))
        .open(run)
        .map_err(|_| {
            CliError::not_found(format!(
                "run `{run}` not found under {}",
                root.join(".scirust-verify/runs").display()
            ))
        })
}

fn map_signature_error(error: SignatureError, verification: bool) -> CliError {
    let exit_code = if verification && error.is_verification_failure() {
        1
    } else {
        match error {
            SignatureError::Io { .. } | SignatureError::Json { .. } => 3,
            SignatureError::VerificationFailed
            | SignatureError::BundleDigestMismatch { .. }
            | SignatureError::PublicKeyMismatch { .. } => 1,
            SignatureError::InvalidKey(_)
            | SignatureError::InvalidSignatureDocument(_)
            | SignatureError::AlreadyExists(_)
            | SignatureError::SymlinkOutput(_) => 2,
        }
    };
    CliError {
        message: error.to_string(),
        exit_code,
    }
}
