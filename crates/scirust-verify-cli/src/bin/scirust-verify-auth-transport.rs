//! Authenticated transport wrapper for a sealed SciRust-Verify dossier.
//!
//! This format carries three exact byte sequences together: the existing v1
//! `.svtr` dossier transport, one detached Ed25519 signature, and the matching
//! public-key document. The public key is portable key material, not a trust
//! root; consumers must still apply their own trust policy.

#![deny(missing_docs)]

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use scirust_verify_model::Digest;
use scirust_verify_signature::{read_public_key, signature_path, verify_bundle_signature};
use scirust_verify_store::RunsRoot;
use serde::Serialize;

const MAGIC: &[u8; 8] = b"SVAT\0\0\0\x01";
const MEDIA_TYPE: &str = "application/vnd.scirust.verify-authenticated-transport.v1";
// Exact v1 `.svtr` maximum: 1 GiB payload + 64 MiB framing allowance.
const MAX_INNER_TRANSPORT_BYTES: u64 = 1_140_850_688;
const MAX_SIGNATURE_BYTES: u64 = 1_048_576;
const MAX_PUBLIC_KEY_BYTES: u64 = 1_048_576;
const MAX_ENVELOPE_BYTES: u64 =
    MAX_INNER_TRANSPORT_BYTES + MAX_SIGNATURE_BYTES + MAX_PUBLIC_KEY_BYTES + 1024;

#[derive(Parser)]
#[command(
    name = "scirust-verify-auth-transport",
    version,
    about = "Pack or unpack a dossier transport with detached signature and public key"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Action {
    /// Pack one finalized dossier, detached signature, and matching public key.
    Pack {
        /// Finalized run id.
        run: String,
        /// Project containing `.scirust-verify`.
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Detached signature JSON file.
        #[arg(long)]
        signature: PathBuf,
        /// Public-key JSON file explicitly selected by the caller.
        #[arg(long)]
        public_key: PathBuf,
        /// Destination authenticated transport; never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify and import an authenticated transport.
    Unpack {
        /// Authenticated transport input.
        input: PathBuf,
        /// Project receiving the reconstructed run.
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
}

#[derive(Debug)]
enum AuthTransportError {
    Invalid(String),
    Integrity(String),
    Io { path: PathBuf, source: io::Error },
    Signature(String),
    Transport(String),
}

impl AuthTransportError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Integrity(_) | Self::Signature(_) => 1,
            Self::Invalid(_) => 2,
            Self::Io { .. } | Self::Transport(_) => 3,
        }
    }
}

impl std::fmt::Display for AuthTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::Integrity(message)
            | Self::Signature(message)
            | Self::Transport(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "filesystem error at `{}`: {source}", path.display())
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct Outcome {
    operation: &'static str,
    run_id: String,
    media_type: &'static str,
    authenticated_transport_sha256: String,
    dossier_transport_sha256: String,
    key_id: String,
    public_key_fingerprint_sha256: String,
    path: String,
    imported_public_key_trusted: bool,
    trust_boundary: &'static str,
}

struct Envelope {
    transport: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}

struct SignatureSnapshot {
    signature: Vec<u8>,
    public_key: Vec<u8>,
    signature_path: PathBuf,
    public_key_path: PathBuf,
}

impl SignatureSnapshot {
    fn capture(
        signature_input: &Path,
        public_key_input: &Path,
        anchor: &Path,
    ) -> Result<Self, AuthTransportError> {
        let signature = read_bounded(signature_input, MAX_SIGNATURE_BYTES)?;
        let public_key = read_bounded(public_key_input, MAX_PUBLIC_KEY_BYTES)?;
        let signature_path = temporary_sibling(anchor, ".signature.snapshot");
        let public_key_path = temporary_sibling(anchor, ".public-key.snapshot");

        write_new(&signature_path, &signature)?;
        if let Err(error) = write_new(&public_key_path, &public_key) {
            let _ = fs::remove_file(&signature_path);
            return Err(error);
        }

        Ok(Self {
            signature,
            public_key,
            signature_path,
            public_key_path,
        })
    }
}

impl Drop for SignatureSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.signature_path);
        let _ = fs::remove_file(&self.public_key_path);
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Action::Pack {
            run,
            project,
            signature,
            public_key,
            output,
        } => pack(&run, &project, &signature, &public_key, &output),
        Action::Unpack { input, project } => unpack(&input, &project),
    };
    match result {
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
                println!("operation          : {}", outcome.operation);
                println!("run                : {}", outcome.run_id);
                println!("media type         : {}", outcome.media_type);
                println!(
                    "transport sha256   : {}",
                    outcome.authenticated_transport_sha256
                );
                println!("key id             : {}", outcome.key_id);
                println!(
                    "key fingerprint    : {}",
                    outcome.public_key_fingerprint_sha256
                );
                println!("path               : {}", outcome.path);
                println!("trust boundary     : {}", outcome.trust_boundary);
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(error.exit_code())
        }
    }
}

fn pack(
    run_id: &str,
    project: &Path,
    signature_path_input: &Path,
    public_key_path: &Path,
    output: &Path,
) -> Result<Outcome, AuthTransportError> {
    let store = RunsRoot::new(project.join(".scirust-verify/runs"))
        .open(run_id)
        .map_err(|error| integrity(format!("run `{run_id}` is not available: {error}")))?;
    store.verify_integrity().map_err(|error| {
        integrity(format!(
            "run `{run_id}` failed dossier integrity verification: {error}"
        ))
    })?;

    let snapshot = SignatureSnapshot::capture(signature_path_input, public_key_path, output)?;
    let public = read_public_key(&snapshot.public_key_path)
        .map_err(|error| signature_error(format!("public key is invalid: {error}")))?;
    let verification = verify_bundle_signature(
        run_id,
        &store.path().join("bundle.json"),
        &snapshot.signature_path,
        &snapshot.public_key_path,
    )
    .map_err(|error| signature_error(format!("signature verification failed: {error}")))?;
    if verification.key_id != public.key_id {
        return Err(signature_error(
            "verified signature key identity differs from public key identity",
        ));
    }

    let inner_path = temporary_sibling(output, ".inner.svtr");
    let transport_result = (|| {
        run_transport(&[
            OsString::from("--json"),
            OsString::from("pack"),
            OsString::from(run_id),
            OsString::from("--project"),
            project.as_os_str().to_owned(),
            OsString::from("--output"),
            inner_path.as_os_str().to_owned(),
        ])?;
        read_bounded(&inner_path, MAX_INNER_TRANSPORT_BYTES)
    })();
    let _ = fs::remove_file(&inner_path);
    let transport = transport_result?;

    let envelope = encode_envelope(&Envelope {
        transport: transport.clone(),
        signature: snapshot.signature.clone(),
        public_key: snapshot.public_key.clone(),
    })?;
    publish_new_file(output, &envelope)?;

    Ok(Outcome {
        operation: "pack",
        run_id: run_id.to_owned(),
        media_type: MEDIA_TYPE,
        authenticated_transport_sha256: Digest::sha256_hex(&envelope).value,
        dossier_transport_sha256: Digest::sha256_hex(&transport).value,
        key_id: public.key_id,
        public_key_fingerprint_sha256: public.fingerprint_sha256,
        path: output.display().to_string(),
        imported_public_key_trusted: false,
        trust_boundary: "the enclosed dossier was integrity-valid and its detached Ed25519 signature verified under the exact snapshotted public-key/signature bytes carried by this envelope; key identity trust, revocation policy, remote-host trust and scientific claims remain external decisions",
    })
}

fn unpack(input: &Path, project: &Path) -> Result<Outcome, AuthTransportError> {
    let envelope_bytes = read_bounded(input, MAX_ENVELOPE_BYTES)?;
    let envelope = parse_envelope(&envelope_bytes)?;
    let stage_root = project
        .join(".scirust-verify")
        .join(unique_name(".authenticated-staging"));
    let stage_project = stage_root.join("project");
    fs::create_dir_all(&stage_project).map_err(|source| io_error(&stage_project, source))?;
    let stage_transport = stage_root.join("dossier.svtr");
    let stage_signature = stage_root.join("signature.json");
    let stage_key = stage_root.join("public-key.json");
    write_new(&stage_transport, &envelope.transport)?;
    write_new(&stage_signature, &envelope.signature)?;
    write_new(&stage_key, &envelope.public_key)?;

    let context = StagedImport {
        stage_project: &stage_project,
        stage_transport: &stage_transport,
        stage_signature: &stage_signature,
        stage_key: &stage_key,
        project,
        envelope_bytes: &envelope_bytes,
        transport_bytes: &envelope.transport,
        input,
    };
    let result = unpack_staged(&context);
    let _ = fs::remove_dir_all(&stage_root);
    result
}

struct StagedImport<'a> {
    stage_project: &'a Path,
    stage_transport: &'a Path,
    stage_signature: &'a Path,
    stage_key: &'a Path,
    project: &'a Path,
    envelope_bytes: &'a [u8],
    transport_bytes: &'a [u8],
    input: &'a Path,
}

fn unpack_staged(context: &StagedImport<'_>) -> Result<Outcome, AuthTransportError> {
    run_transport(&[
        OsString::from("--json"),
        OsString::from("unpack"),
        context.stage_transport.as_os_str().to_owned(),
        OsString::from("--project"),
        context.stage_project.as_os_str().to_owned(),
    ])?;

    let staged_runs = RunsRoot::new(context.stage_project.join(".scirust-verify/runs"));
    let ids = staged_runs
        .list_runs()
        .map_err(|error| integrity(format!("staged transport run listing failed: {error}")))?;
    if ids.len() != 1 {
        return Err(invalid(format!(
            "authenticated transport reconstructed {} runs; expected exactly one",
            ids.len()
        )));
    }
    let run_id = &ids[0];
    let staged = staged_runs
        .open(run_id)
        .map_err(|error| integrity(format!("staged run is unavailable: {error}")))?;
    staged.verify_integrity().map_err(|error| {
        integrity(format!(
            "staged dossier failed integrity verification: {error}"
        ))
    })?;

    let public = read_public_key(context.stage_key)
        .map_err(|error| signature_error(format!("transported public key is invalid: {error}")))?;
    let verification = verify_bundle_signature(
        run_id,
        &staged.path().join("bundle.json"),
        context.stage_signature,
        context.stage_key,
    )
    .map_err(|error| {
        signature_error(format!(
            "transported detached signature verification failed: {error}"
        ))
    })?;
    if verification.key_id != public.key_id {
        return Err(signature_error(
            "transported signature key identity differs from public key identity",
        ));
    }

    let verify_root = context.project.join(".scirust-verify");
    let final_runs = verify_root.join("runs");
    let final_run = final_runs.join(run_id);
    if final_run.exists() {
        return Err(invalid(format!(
            "destination run `{run_id}` already exists; authenticated import never overwrites evidence"
        )));
    }
    fs::create_dir_all(&final_runs).map_err(|source| io_error(&final_runs, source))?;

    let signatures_root = verify_root.join("signatures");
    let final_signature = signature_path(&signatures_root, run_id, &public.key_id)
        .map_err(|error| signature_error(format!("cannot derive signature path: {error}")))?;
    if final_signature.exists() {
        return Err(invalid(format!(
            "detached signature destination `{}` already exists",
            final_signature.display()
        )));
    }
    let key_dir = verify_root.join("imported-public-keys");
    let final_key = key_dir.join(format!("{}.json", public.fingerprint_sha256));

    let key_bytes =
        fs::read(context.stage_key).map_err(|source| io_error(context.stage_key, source))?;
    let key_created = publish_key_material(&final_key, &key_bytes)?;
    let signature_bytes = fs::read(context.stage_signature)
        .map_err(|source| io_error(context.stage_signature, source))?;
    if let Err(error) = publish_new_file(&final_signature, &signature_bytes) {
        if key_created {
            let _ = fs::remove_file(&final_key);
        }
        return Err(error);
    }

    if let Err(source) = fs::rename(staged.path(), &final_run) {
        let _ = fs::remove_file(&final_signature);
        if key_created {
            let _ = fs::remove_file(&final_key);
        }
        return Err(io_error(&final_run, source));
    }

    Ok(Outcome {
        operation: "unpack",
        run_id: run_id.clone(),
        media_type: MEDIA_TYPE,
        authenticated_transport_sha256: Digest::sha256_hex(context.envelope_bytes).value,
        dossier_transport_sha256: Digest::sha256_hex(context.transport_bytes).value,
        key_id: public.key_id,
        public_key_fingerprint_sha256: public.fingerprint_sha256,
        path: context.input.display().to_string(),
        imported_public_key_trusted: false,
        trust_boundary: "the imported dossier passed its original integrity seal and its detached Ed25519 signature verified under transported public-key bytes; the imported key is deliberately untrusted until an independent local policy authorizes its fingerprint",
    })
}

fn encode_envelope(envelope: &Envelope) -> Result<Vec<u8>, AuthTransportError> {
    validate_section_size(
        envelope.transport.len(),
        MAX_INNER_TRANSPORT_BYTES,
        "dossier transport",
    )?;
    validate_section_size(envelope.signature.len(), MAX_SIGNATURE_BYTES, "signature")?;
    validate_section_size(
        envelope.public_key.len(),
        MAX_PUBLIC_KEY_BYTES,
        "public key",
    )?;
    let mut out = Vec::with_capacity(
        8 + 24 + envelope.transport.len() + envelope.signature.len() + envelope.public_key.len(),
    );
    out.extend_from_slice(MAGIC);
    for section in [
        &envelope.transport,
        &envelope.signature,
        &envelope.public_key,
    ] {
        out.extend_from_slice(&(section.len() as u64).to_le_bytes());
        out.extend_from_slice(section);
    }
    Ok(out)
}

fn parse_envelope(bytes: &[u8]) -> Result<Envelope, AuthTransportError> {
    let mut cursor = io::Cursor::new(bytes);
    let mut magic = [0u8; 8];
    cursor
        .read_exact(&mut magic)
        .map_err(|_| invalid("truncated authenticated transport header"))?;
    if &magic != MAGIC {
        return Err(invalid(
            "unsupported or malformed authenticated transport magic/version",
        ));
    }
    let transport = read_section(&mut cursor, MAX_INNER_TRANSPORT_BYTES, "dossier transport")?;
    let signature = read_section(&mut cursor, MAX_SIGNATURE_BYTES, "signature")?;
    let public_key = read_section(&mut cursor, MAX_PUBLIC_KEY_BYTES, "public key")?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid(
            "trailing unframed bytes after authenticated transport sections",
        ));
    }
    Ok(Envelope {
        transport,
        signature,
        public_key,
    })
}

fn read_section(
    cursor: &mut io::Cursor<&[u8]>,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>, AuthTransportError> {
    let mut length = [0u8; 8];
    cursor
        .read_exact(&mut length)
        .map_err(|_| invalid(format!("truncated {label} length")))?;
    let length = u64::from_le_bytes(length);
    if length > limit {
        return Err(invalid(format!(
            "{label} is {length} bytes, limit is {limit}"
        )));
    }
    let length = usize::try_from(length)
        .map_err(|_| invalid(format!("{label} length does not fit this platform")))?;
    let mut section = vec![0u8; length];
    cursor
        .read_exact(&mut section)
        .map_err(|_| invalid(format!("truncated {label} payload")))?;
    Ok(section)
}

fn validate_section_size(size: usize, limit: u64, label: &str) -> Result<(), AuthTransportError> {
    if size as u64 > limit {
        Err(invalid(format!(
            "{label} is {size} bytes, limit is {limit}"
        )))
    } else {
        Ok(())
    }
}

fn run_transport(args: &[OsString]) -> Result<(), AuthTransportError> {
    let current =
        std::env::current_exe().map_err(|source| io_error("current executable", source))?;
    let parent = current
        .parent()
        .ok_or_else(|| invalid("current executable has no parent directory"))?;
    let sibling = parent.join(format!(
        "scirust-verify-transport{}",
        std::env::consts::EXE_SUFFIX
    ));
    let output = Command::new(&sibling)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| io_error(&sibling, source))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(AuthTransportError::Transport(format!(
        "dossier transport subprocess failed with status {}: {}",
        output.status,
        stderr.trim()
    )))
}

fn publish_key_material(path: &Path, bytes: &[u8]) -> Result<bool, AuthTransportError> {
    if path.exists() {
        require_regular_file(path)?;
        let existing = fs::read(path).map_err(|source| io_error(path, source))?;
        if existing == bytes {
            return Ok(false);
        }
        return Err(invalid(format!(
            "imported public-key path `{}` exists with different bytes",
            path.display()
        )));
    }
    publish_new_file(path, bytes)?;
    Ok(true)
}

fn publish_new_file(path: &Path, bytes: &[u8]) -> Result<(), AuthTransportError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    if path.exists() {
        return Err(invalid(format!(
            "destination `{}` already exists; authenticated transport never overwrites",
            path.display()
        )));
    }

    let staging = temporary_sibling(path, ".publish");
    let result = (|| {
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|source| io_error(&staging, source))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error(&staging, source))?;
        drop(file);

        fs::hard_link(&staging, path).map_err(|source| {
            if path.exists() {
                invalid(format!(
                    "destination `{}` already exists; authenticated transport never overwrites",
                    path.display()
                ))
            } else {
                io_error(path, source)
            }
        })?;
        Ok(())
    })();
    let _ = fs::remove_file(&staging);
    result
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AuthTransportError> {
    publish_new_file(path, bytes)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, AuthTransportError> {
    require_regular_file(path)?;
    let metadata = fs::metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.len() > limit {
        return Err(invalid(format!(
            "`{}` is {} bytes, limit is {limit}",
            path.display(),
            metadata.len()
        )));
    }
    fs::read(path).map_err(|source| io_error(path, source))
}

fn require_regular_file(path: &Path) -> Result<(), AuthTransportError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(invalid(format!(
            "`{}` is not a regular file",
            path.display()
        )))
    }
}

fn temporary_sibling(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}{}{}",
        path.display(),
        suffix,
        unique_name(".tmp")
    ))
}

fn unique_name(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn invalid(message: impl Into<String>) -> AuthTransportError {
    AuthTransportError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> AuthTransportError {
    AuthTransportError::Integrity(message.into())
}

fn signature_error(message: impl Into<String>) -> AuthTransportError {
    AuthTransportError::Signature(message.into())
}

fn io_error(path: impl Into<PathBuf>, source: io::Error) -> AuthTransportError {
    AuthTransportError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope {
            transport: b"transport".to_vec(),
            signature: b"signature".to_vec(),
            public_key: b"public-key".to_vec(),
        }
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(unique_name(label));
        fs::create_dir_all(&path).expect("create test directory");
        path
    }

    #[test]
    fn framing_round_trips_exact_bytes() {
        let encoded = encode_envelope(&sample()).expect("encode");
        let decoded = parse_envelope(&encoded).expect("decode");
        assert_eq!(decoded.transport, b"transport");
        assert_eq!(decoded.signature, b"signature");
        assert_eq!(decoded.public_key, b"public-key");
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = encode_envelope(&sample()).expect("encode");
        encoded.push(0);
        assert!(parse_envelope(&encoded).is_err());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut encoded = encode_envelope(&sample()).expect("encode");
        encoded[0] ^= 0xff;
        assert!(parse_envelope(&encoded).is_err());
    }

    #[test]
    fn oversized_signature_length_is_rejected_before_allocation() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&0u64.to_le_bytes());
        encoded.extend_from_slice(&(MAX_SIGNATURE_BYTES + 1).to_le_bytes());
        assert!(parse_envelope(&encoded).is_err());
    }

    #[test]
    fn imported_key_material_is_never_reported_trusted() {
        let outcome = Outcome {
            operation: "unpack",
            run_id: "run-test".into(),
            media_type: MEDIA_TYPE,
            authenticated_transport_sha256: "a".repeat(64),
            dossier_transport_sha256: "b".repeat(64),
            key_id: "ed25519-test".into(),
            public_key_fingerprint_sha256: "c".repeat(64),
            path: "x".into(),
            imported_public_key_trusted: false,
            trust_boundary: "test",
        };
        assert!(!outcome.imported_public_key_trusted);
    }

    #[test]
    fn signature_snapshot_keeps_exact_captured_bytes() {
        let dir = temp_test_dir("auth-snapshot");
        let signature = dir.join("signature.json");
        let public_key = dir.join("public-key.json");
        let anchor = dir.join("envelope.svat");
        fs::write(&signature, b"signed-bytes-v1").expect("signature input");
        fs::write(&public_key, b"key-bytes-v1").expect("key input");

        let snapshot = SignatureSnapshot::capture(&signature, &public_key, &anchor)
            .expect("capture stable inputs");
        fs::write(&signature, b"attacker-signature").expect("replace signature input");
        fs::write(&public_key, b"attacker-key").expect("replace key input");

        assert_eq!(snapshot.signature, b"signed-bytes-v1");
        assert_eq!(snapshot.public_key, b"key-bytes-v1");
        assert_eq!(
            fs::read(&snapshot.signature_path).expect("snapshot signature"),
            b"signed-bytes-v1"
        );
        assert_eq!(
            fs::read(&snapshot.public_key_path).expect("snapshot public key"),
            b"key-bytes-v1"
        );
        let signature_snapshot = snapshot.signature_path.clone();
        let public_key_snapshot = snapshot.public_key_path.clone();
        drop(snapshot);
        assert!(!signature_snapshot.exists());
        assert!(!public_key_snapshot.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_publish_never_overwrites_existing_destination() {
        let dir = temp_test_dir("auth-atomic-publish");
        let destination = dir.join("evidence.svat");
        publish_new_file(&destination, b"first complete payload").expect("initial publish");
        let error = publish_new_file(&destination, b"replacement")
            .expect_err("second publish must fail closed");
        assert!(error.to_string().contains("never overwrites"));
        assert_eq!(
            fs::read(&destination).expect("published bytes"),
            b"first complete payload"
        );
        let entries = fs::read_dir(&dir).expect("list test directory").count();
        assert_eq!(entries, 1, "temporary publish files must be cleaned up");
        let _ = fs::remove_dir_all(dir);
    }
}
