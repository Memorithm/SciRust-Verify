//! SciRust Hub process adapter for authenticated dossier inspection.
//!
//! The adapter establishes that an authenticated transport reconstructed an
//! integrity-valid dossier and that its detached Ed25519 signature verified
//! under the exact public key transported with it. That transported key is not
//! authorized by this adapter; signer trust remains a separate local policy.

#![deny(missing_docs)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::Parser;
use serde::{Deserialize, Serialize};

const HUB_RESULT_SCHEMA_VERSION: u64 = 1;
const AUTH_TRANSPORT_MEDIA_TYPE: &str = "application/vnd.scirust.verify-authenticated-transport.v1";
const RESULT_MEDIA_TYPE: &str =
    "application/vnd.scirust.verify-hub-authenticated-inspection.v1+json";

#[derive(Parser)]
#[command(
    name = "scirust-verify-hub-auth",
    version,
    about = "SciRust Hub adapter for authenticated Verify dossier transports"
)]
struct Cli {
    /// Hub-materialized `.svat` input artifact.
    #[arg(long)]
    dossier: PathBuf,
    /// Hub-declared JSON output path.
    #[arg(long)]
    result: PathBuf,
}

#[derive(Debug, Deserialize)]
struct AuthTransportOutcome {
    operation: String,
    run_id: String,
    media_type: String,
    authenticated_transport_sha256: String,
    dossier_transport_sha256: String,
    key_id: String,
    public_key_fingerprint_sha256: String,
    imported_public_key_trusted: bool,
}

#[derive(Debug, Serialize)]
struct HubAuthenticatedInspectionResult {
    schema_version: u64,
    status: &'static str,
    run_id: String,
    input_media_type: &'static str,
    result_media_type: &'static str,
    authenticated_transport_sha256: String,
    dossier_transport_sha256: String,
    key_id: String,
    public_key_fingerprint_sha256: String,
    signer_authorized: bool,
    trust_boundary: &'static str,
}

#[derive(Debug)]
enum HubAuthError {
    Invalid(String),
    Child(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json(serde_json::Error),
}

impl HubAuthError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 2,
            Self::Child(_) => 1,
            Self::Io { .. } | Self::Json(_) => 3,
        }
    }
}

impl std::fmt::Display for HubAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Child(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "filesystem error at `{}`: {source}", path.display())
            }
            Self::Json(source) => write!(f, "invalid authenticated-transport JSON: {source}"),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match inspect(&cli.dossier, &cli.result) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn inspect(dossier: &Path, result: &Path) -> Result<(), HubAuthError> {
    if result.exists() {
        return Err(HubAuthError::Invalid(format!(
            "result path `{}` already exists; Hub adapter never overwrites outputs",
            result.display()
        )));
    }
    let metadata = fs::symlink_metadata(dossier).map_err(|source| io_error(dossier, source))?;
    if !metadata.file_type().is_file() {
        return Err(HubAuthError::Invalid(format!(
            "dossier input `{}` is not a regular file",
            dossier.display()
        )));
    }

    let temp_project = create_temp_project()?;
    let outcome = run_authenticated_unpack(dossier, &temp_project);
    let _ = fs::remove_dir_all(&temp_project);
    let inspection = inspection_from_outcome(outcome?)?;
    write_result(result, &inspection)
}

fn run_authenticated_unpack(
    dossier: &Path,
    project: &Path,
) -> Result<AuthTransportOutcome, HubAuthError> {
    let current = std::env::current_exe().map_err(|source| HubAuthError::Io {
        path: PathBuf::from("current executable"),
        source,
    })?;
    let sibling = current
        .parent()
        .ok_or_else(|| {
            HubAuthError::Invalid("Hub adapter executable has no parent directory".into())
        })?
        .join(executable_name("scirust-verify-auth-transport"));
    let output = Command::new(&sibling)
        .arg("--json")
        .arg("unpack")
        .arg(dossier)
        .arg("--project")
        .arg(project)
        .output()
        .map_err(|source| io_error(&sibling, source))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HubAuthError::Child(format!(
            "authenticated transport inspection failed with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(HubAuthError::Json)
}

fn inspection_from_outcome(
    outcome: AuthTransportOutcome,
) -> Result<HubAuthenticatedInspectionResult, HubAuthError> {
    if outcome.operation != "unpack" {
        return Err(HubAuthError::Invalid(format!(
            "unexpected authenticated transport operation `{}`",
            outcome.operation
        )));
    }
    if outcome.media_type != AUTH_TRANSPORT_MEDIA_TYPE {
        return Err(HubAuthError::Invalid(format!(
            "unexpected authenticated transport media type `{}`",
            outcome.media_type
        )));
    }
    if outcome.run_id.is_empty()
        || outcome.key_id.is_empty()
        || !is_canonical_sha256_hex(&outcome.authenticated_transport_sha256)
        || !is_canonical_sha256_hex(&outcome.dossier_transport_sha256)
        || !is_canonical_sha256_hex(&outcome.public_key_fingerprint_sha256)
    {
        return Err(HubAuthError::Invalid(
            "authenticated transport returned malformed identity/integrity data".into(),
        ));
    }
    if outcome.imported_public_key_trusted {
        return Err(HubAuthError::Invalid(
            "authenticated transport unexpectedly marked imported key material as trusted".into(),
        ));
    }

    Ok(HubAuthenticatedInspectionResult {
        schema_version: HUB_RESULT_SCHEMA_VERSION,
        status: "signature_valid_under_transported_key",
        run_id: outcome.run_id,
        input_media_type: AUTH_TRANSPORT_MEDIA_TYPE,
        result_media_type: RESULT_MEDIA_TYPE,
        authenticated_transport_sha256: outcome.authenticated_transport_sha256,
        dossier_transport_sha256: outcome.dossier_transport_sha256,
        key_id: outcome.key_id,
        public_key_fingerprint_sha256: outcome.public_key_fingerprint_sha256,
        signer_authorized: false,
        trust_boundary: "the authenticated transport reconstructed an integrity-valid dossier and its detached Ed25519 signature verified under the exact transported public key; this result does not authorize that key, establish signer identity, remote-host trust, trusted time, or strengthen scientific verdicts",
    })
}

fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_result(
    path: &Path,
    result: &HubAuthenticatedInspectionResult,
) -> Result<(), HubAuthError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    let mut bytes = serde_json::to_vec_pretty(result).map_err(HubAuthError::Json)?;
    bytes.push(b'\n');
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))
}

fn create_temp_project() -> Result<PathBuf, HubAuthError> {
    let base = std::env::temp_dir();
    for attempt in 0..16u8 {
        let name = format!(
            "scirust-verify-hub-auth-{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = base.join(name);
        match create_private_directory(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error(&path, source)),
        }
    }
    Err(HubAuthError::Invalid(
        "could not allocate a unique temporary Hub authenticated-inspection directory".into(),
    ))
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

fn executable_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> HubAuthError {
    HubAuthError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_outcome() -> AuthTransportOutcome {
        AuthTransportOutcome {
            operation: "unpack".into(),
            run_id: "run-20260830T000000Z-deadbeef".into(),
            media_type: AUTH_TRANSPORT_MEDIA_TYPE.into(),
            authenticated_transport_sha256: "ab".repeat(32),
            dossier_transport_sha256: "cd".repeat(32),
            key_id: "example-key".into(),
            public_key_fingerprint_sha256: "ef".repeat(32),
            imported_public_key_trusted: false,
        }
    }

    #[test]
    fn valid_signature_does_not_authorize_transported_key() {
        let result = inspection_from_outcome(valid_outcome()).expect("valid outcome");
        assert_eq!(result.status, "signature_valid_under_transported_key");
        assert!(!result.signer_authorized);
        assert!(result.trust_boundary.contains("does not authorize"));
        assert!(!result.trust_boundary.contains("VERIFIED"));
    }

    #[test]
    fn trusted_imported_key_claim_is_rejected() {
        let mut outcome = valid_outcome();
        outcome.imported_public_key_trusted = true;
        assert!(inspection_from_outcome(outcome).is_err());
    }

    #[test]
    fn incomplete_fingerprint_fails_closed() {
        let mut outcome = valid_outcome();
        outcome.public_key_fingerprint_sha256 = "abcd".into();
        assert!(inspection_from_outcome(outcome).is_err());
    }

    #[test]
    fn non_hex_fingerprint_fails_closed() {
        let mut outcome = valid_outcome();
        outcome.public_key_fingerprint_sha256 = "z".repeat(64);
        assert!(inspection_from_outcome(outcome).is_err());
    }

    #[test]
    fn non_canonical_digest_fields_fail_closed() {
        let mut outcome = valid_outcome();
        outcome.authenticated_transport_sha256 = "AB".repeat(32);
        assert!(inspection_from_outcome(outcome).is_err());

        let mut outcome = valid_outcome();
        outcome.dossier_transport_sha256 = "g0".repeat(32);
        assert!(inspection_from_outcome(outcome).is_err());
    }

    #[test]
    fn wrong_media_type_is_rejected() {
        let mut outcome = valid_outcome();
        outcome.media_type = "application/octet-stream".into();
        assert!(inspection_from_outcome(outcome).is_err());
    }

    #[test]
    fn canonical_sha256_validation_is_exact() {
        assert!(is_canonical_sha256_hex(&"0123456789abcdef".repeat(4)));
        assert!(!is_canonical_sha256_hex(&"0123456789ABCDEF".repeat(4)));
        assert!(!is_canonical_sha256_hex(&"0".repeat(63)));
        assert!(!is_canonical_sha256_hex(&"0".repeat(65)));
    }

    #[test]
    fn result_writer_never_overwrites_existing_file() {
        let root = create_temp_project().expect("temp");
        let path = root.join("result.json");
        fs::write(&path, b"keep").expect("seed result");
        let result = inspection_from_outcome(valid_outcome()).expect("valid outcome");
        assert!(write_result(&path, &result).is_err());
        assert_eq!(fs::read(&path).expect("read result"), b"keep");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn temp_project_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let root = create_temp_project().expect("temp");
        let mode = fs::metadata(&root).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let _ = fs::remove_dir_all(root);
    }
}
