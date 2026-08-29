//! SciRust Hub process adapter for sealed dossier integrity inspection.
//!
//! This adapter intentionally establishes only transport/dossier integrity. It
//! never upgrades scientific claim verdicts and never treats Hub provenance as
//! proof that a producing host, signer, or execution environment was trusted.

#![deny(missing_docs)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

const HUB_RESULT_SCHEMA_VERSION: u64 = 1;
const TRANSPORT_MEDIA_TYPE: &str = "application/vnd.scirust.verify-dossier-transport.v1";
const RESULT_MEDIA_TYPE: &str = "application/vnd.scirust.verify-hub-inspection.v1+json";

#[derive(Parser)]
#[command(
    name = "scirust-verify-hub",
    version,
    about = "SciRust Hub adapter for integrity inspection of sealed Verify dossier transports"
)]
struct Cli {
    #[command(subcommand)]
    command: HubCommand,
}

#[derive(Subcommand)]
enum HubCommand {
    /// Validate a transported dossier and write one machine-readable Hub result.
    Inspect {
        /// Hub-materialized `.svtr` input artifact.
        #[arg(long)]
        dossier: PathBuf,
        /// Hub-declared JSON output path.
        #[arg(long)]
        result: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct TransportOutcome {
    operation: String,
    run_id: String,
    media_type: String,
    transport_sha256: String,
    files: usize,
    payload_bytes: u64,
}

#[derive(Debug, Serialize)]
struct HubInspectionResult {
    schema_version: u64,
    status: &'static str,
    run_id: String,
    input_media_type: &'static str,
    result_media_type: &'static str,
    transport_sha256: String,
    dossier_entries: usize,
    dossier_payload_bytes: u64,
    trust_boundary: &'static str,
}

#[derive(Debug)]
enum HubError {
    Invalid(String),
    Child(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json(serde_json::Error),
}

impl HubError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 2,
            Self::Child(_) => 1,
            Self::Io { .. } | Self::Json(_) => 3,
        }
    }
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Child(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "filesystem error at `{}`: {source}", path.display())
            }
            Self::Json(source) => write!(f, "invalid transport JSON output: {source}"),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        HubCommand::Inspect { dossier, result } => inspect(&dossier, &result),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn inspect(dossier: &Path, result: &Path) -> Result<(), HubError> {
    if result.exists() {
        return Err(HubError::Invalid(format!(
            "result path `{}` already exists; Hub adapter never overwrites outputs",
            result.display()
        )));
    }
    let metadata = fs::symlink_metadata(dossier).map_err(|source| io_error(dossier, source))?;
    if !metadata.file_type().is_file() {
        return Err(HubError::Invalid(format!(
            "dossier input `{}` is not a regular file",
            dossier.display()
        )));
    }

    let temp_project = create_temp_project()?;
    let outcome = run_transport_unpack(dossier, &temp_project);
    let _ = fs::remove_dir_all(&temp_project);
    let outcome = outcome?;
    let inspection = inspection_from_transport(outcome)?;
    write_result(result, &inspection)
}

fn run_transport_unpack(dossier: &Path, project: &Path) -> Result<TransportOutcome, HubError> {
    let current = std::env::current_exe().map_err(|source| HubError::Io {
        path: PathBuf::from("current executable"),
        source,
    })?;
    let sibling = current
        .parent()
        .ok_or_else(|| HubError::Invalid("Hub adapter executable has no parent directory".into()))?
        .join(executable_name("scirust-verify-transport"));
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
        return Err(HubError::Child(format!(
            "transport integrity inspection failed with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(HubError::Json)
}

fn inspection_from_transport(outcome: TransportOutcome) -> Result<HubInspectionResult, HubError> {
    if outcome.operation != "unpack" {
        return Err(HubError::Invalid(format!(
            "unexpected transport operation `{}`",
            outcome.operation
        )));
    }
    if outcome.media_type != TRANSPORT_MEDIA_TYPE {
        return Err(HubError::Invalid(format!(
            "unexpected transport media type `{}`",
            outcome.media_type
        )));
    }
    if outcome.run_id.is_empty() || outcome.transport_sha256.len() != 64 || outcome.files == 0 {
        return Err(HubError::Invalid(
            "transport inspection returned incomplete identity/integrity data".into(),
        ));
    }
    Ok(HubInspectionResult {
        schema_version: HUB_RESULT_SCHEMA_VERSION,
        status: "integrity_valid",
        run_id: outcome.run_id,
        input_media_type: TRANSPORT_MEDIA_TYPE,
        result_media_type: RESULT_MEDIA_TYPE,
        transport_sha256: outcome.transport_sha256,
        dossier_entries: outcome.files,
        dossier_payload_bytes: outcome.payload_bytes,
        trust_boundary: "the transported dossier reconstructed successfully and passed its original bundle integrity seal; no scientific claim, signer identity, remote-host trust, or cross-platform property is established by this result",
    })
}

fn write_result(path: &Path, result: &HubInspectionResult) -> Result<(), HubError> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    let mut bytes = serde_json::to_vec_pretty(result).map_err(HubError::Json)?;
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

fn create_temp_project() -> Result<PathBuf, HubError> {
    let base = std::env::temp_dir();
    for attempt in 0..16u8 {
        let name = format!(
            "scirust-verify-hub-{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = base.join(name);
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error(&path, source)),
        }
    }
    Err(HubError::Invalid(
        "could not allocate a unique temporary Hub inspection directory".into(),
    ))
}

fn executable_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> HubError {
    HubError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_transport_outcome() -> TransportOutcome {
        TransportOutcome {
            operation: "unpack".into(),
            run_id: "run-20260829T000000Z-deadbeef".into(),
            media_type: TRANSPORT_MEDIA_TYPE.into(),
            transport_sha256: "ab".repeat(32),
            files: 12,
            payload_bytes: 4096,
        }
    }

    #[test]
    fn integrity_result_does_not_claim_scientific_verification() {
        let result = inspection_from_transport(valid_transport_outcome()).expect("valid outcome");
        assert_eq!(result.status, "integrity_valid");
        assert!(result.trust_boundary.contains("no scientific claim"));
        assert!(!result.trust_boundary.contains("VERIFIED"));
    }

    #[test]
    fn wrong_transport_media_type_is_rejected() {
        let mut outcome = valid_transport_outcome();
        outcome.media_type = "application/octet-stream".into();
        assert!(inspection_from_transport(outcome).is_err());
    }

    #[test]
    fn incomplete_transport_identity_fails_closed() {
        let mut outcome = valid_transport_outcome();
        outcome.transport_sha256 = "abcd".into();
        assert!(inspection_from_transport(outcome).is_err());
    }

    #[test]
    fn result_writer_never_overwrites_existing_file() {
        let root = create_temp_project().expect("temp");
        let path = root.join("result.json");
        fs::write(&path, b"keep").expect("seed result");
        let result = inspection_from_transport(valid_transport_outcome()).expect("valid outcome");
        assert!(write_result(&path, &result).is_err());
        assert_eq!(fs::read(&path).expect("read result"), b"keep");
        let _ = fs::remove_dir_all(root);
    }
}
