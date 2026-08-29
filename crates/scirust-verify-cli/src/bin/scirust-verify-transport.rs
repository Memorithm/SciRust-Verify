//! Deterministic single-file transport for finalized SciRust-Verify dossiers.
//!
//! The transport is an envelope around an existing integrity-sealed dossier.
//! It does not create new verification evidence and does not imply signer,
//! producer, remote-host, or transport trust.

#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use clap::{Parser, Subcommand};
use scirust_verify_model::Digest;
use scirust_verify_store::{BundleManifest, RunDocument, RunState, RunsRoot};
use serde::Serialize;

const MAGIC: &[u8; 8] = b"SVTR\0\0\0\x01";
const MAX_FILES: usize = 10_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TOTAL_BYTES: u64 = 1_073_741_824;
const MEDIA_TYPE: &str = "application/vnd.scirust.verify-dossier-transport.v1";

#[derive(Parser)]
#[command(
    name = "scirust-verify-transport",
    version,
    about = "Pack or unpack an integrity-sealed SciRust-Verify dossier as one deterministic file"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Pack one finalized run into a deterministic transport file.
    Pack {
        /// Finalized run id.
        run: String,
        /// Project containing `.scirust-verify/runs`.
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Destination transport file. Existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Unpack one transport file into a project's run store.
    Unpack {
        /// Transport file produced by `pack`.
        input: PathBuf,
        /// Project receiving `.scirust-verify/runs/<run-id>`.
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
}

#[derive(Debug)]
enum TransportError {
    Invalid(String),
    Integrity(String),
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl TransportError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid(_) => 2,
            Self::Integrity(_) => 1,
            Self::Io { .. } | Self::Json { .. } => 3,
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Integrity(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "filesystem error at `{}`: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(f, "invalid JSON at `{}`: {source}", path.display())
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct Outcome {
    operation: &'static str,
    run_id: String,
    media_type: &'static str,
    transport_sha256: String,
    files: usize,
    payload_bytes: u64,
    path: String,
    trust_boundary: &'static str,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Pack {
            run,
            project,
            output,
        } => pack(&run, &project, &output),
        Command::Unpack { input, project } => unpack(&input, &project),
    };

    match result {
        Ok(outcome) => {
            print_outcome(&outcome, cli.json);
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(error.exit_code())
        }
    }
}

fn print_outcome(outcome: &Outcome, json: bool) {
    if json {
        match serde_json::to_string_pretty(outcome) {
            Ok(document) => println!("{document}"),
            Err(error) => eprintln!("error: failed to serialize transport result: {error}"),
        }
        return;
    }
    println!("operation          : {}", outcome.operation);
    println!("run                : {}", outcome.run_id);
    println!("media type         : {}", outcome.media_type);
    println!("transport sha256   : {}", outcome.transport_sha256);
    println!("files              : {}", outcome.files);
    println!("payload bytes      : {}", outcome.payload_bytes);
    println!("path               : {}", outcome.path);
    println!("trust boundary     : {}", outcome.trust_boundary);
}

fn pack(run_id: &str, project: &Path, output: &Path) -> Result<Outcome, TransportError> {
    if output.exists() {
        return Err(TransportError::Invalid(format!(
            "destination `{}` already exists; transport export never overwrites",
            output.display()
        )));
    }

    let runs = RunsRoot::new(project.join(".scirust-verify").join("runs"));
    let store = runs.open(run_id).map_err(|error| {
        TransportError::Integrity(format!("run `{run_id}` is not available: {error}"))
    })?;
    store.verify_integrity().map_err(|error| {
        TransportError::Integrity(format!(
            "run `{run_id}` failed dossier integrity verification: {error}"
        ))
    })?;
    let run_doc = store.read_run_document().map_err(|error| {
        TransportError::Integrity(format!("run `{run_id}` metadata is unusable: {error}"))
    })?;
    if run_doc.state != RunState::Finalized || run_doc.run_id.as_str() != run_id {
        return Err(TransportError::Integrity(format!(
            "run `{run_id}` is not a finalized identity-matching dossier"
        )));
    }

    let bundle_path = store.path().join("bundle.json");
    let bundle_bytes = read_bounded(&bundle_path, MAX_TOTAL_BYTES)?;
    let manifest: BundleManifest = serde_json::from_slice(&bundle_bytes).map_err(|source| {
        TransportError::Json {
            path: bundle_path.clone(),
            source,
        }
    })?;
    validate_manifest(&manifest)?;

    let mut paths: Vec<String> = manifest.files.keys().cloned().collect();
    paths.push("bundle.json".into());
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_FILES {
        return Err(TransportError::Invalid(format!(
            "transport contains {} files, limit is {MAX_FILES}",
            paths.len()
        )));
    }

    let mut entries = Vec::with_capacity(paths.len());
    let mut total = 0u64;
    for rel in &paths {
        validate_relative_path(rel)?;
        let path = store.path().join(rel);
        let metadata = fs::symlink_metadata(&path).map_err(|source| TransportError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(TransportError::Invalid(format!(
                "sealed path `{rel}` is not a regular file"
            )));
        }
        let bytes = read_bounded(&path, MAX_TOTAL_BYTES.saturating_sub(total))?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| TransportError::Invalid("transport size overflow".into()))?;
        if total > MAX_TOTAL_BYTES {
            return Err(TransportError::Invalid(format!(
                "transport payload exceeds {MAX_TOTAL_BYTES} bytes"
            )));
        }
        if rel == "bundle.json" {
            if bytes != bundle_bytes {
                return Err(TransportError::Integrity(
                    "bundle.json changed during transport packing".into(),
                ));
            }
        } else {
            let expected = manifest.files.get(rel).expect("path sourced from manifest");
            let actual = Digest::sha256_hex(&bytes).value;
            if &actual != expected {
                return Err(TransportError::Integrity(format!(
                    "sealed file `{rel}` changed during transport packing"
                )));
            }
        }
        entries.push((rel.clone(), bytes));
    }

    if let Some(parent) = output.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| TransportError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let tmp = temporary_sibling(output);
    let write_result = write_transport(&tmp, &entries);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    fs::rename(&tmp, output).map_err(|source| TransportError::Io {
        path: output.to_path_buf(),
        source,
    })?;

    let transport_bytes = read_bounded(output, MAX_TOTAL_BYTES + 64 * 1024 * 1024)?;
    Ok(Outcome {
        operation: "pack",
        run_id: run_id.to_owned(),
        media_type: MEDIA_TYPE,
        transport_sha256: Digest::sha256_hex(&transport_bytes).value,
        files: entries.len(),
        payload_bytes: total,
        path: output.display().to_string(),
        trust_boundary: "deterministic transport of an integrity-verified dossier only; producer, signer, remote host and scientific claims retain their original trust semantics",
    })
}

fn unpack(input: &Path, project: &Path) -> Result<Outcome, TransportError> {
    let transport_bytes = read_bounded(input, MAX_TOTAL_BYTES + 64 * 1024 * 1024)?;
    let transport_sha256 = Digest::sha256_hex(&transport_bytes).value;
    let entries = parse_transport(&transport_bytes)?;
    let payload_bytes = entries
        .values()
        .map(|bytes| bytes.len() as u64)
        .sum::<u64>();

    let run_bytes = entries
        .get("run.json")
        .ok_or_else(|| TransportError::Invalid("transport has no run.json".into()))?;
    let run_doc: RunDocument = serde_json::from_slice(run_bytes).map_err(|source| {
        TransportError::Json {
            path: PathBuf::from("run.json"),
            source,
        }
    })?;
    if run_doc.state != RunState::Finalized {
        return Err(TransportError::Integrity(format!(
            "transported run `{}` is not finalized",
            run_doc.run_id
        )));
    }
    let run_id = run_doc.run_id.as_str().to_owned();

    let runs_dir = project.join(".scirust-verify").join("runs");
    fs::create_dir_all(&runs_dir).map_err(|source| TransportError::Io {
        path: runs_dir.clone(),
        source,
    })?;
    let destination = runs_dir.join(&run_id);
    if destination.exists() {
        return Err(TransportError::Invalid(format!(
            "destination run `{run_id}` already exists; transport import never overwrites evidence"
        )));
    }

    let stage_root = runs_dir.join(format!(
        ".transport-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let stage_run = stage_root.join(&run_id);
    let result = (|| {
        fs::create_dir_all(&stage_run).map_err(|source| TransportError::Io {
            path: stage_run.clone(),
            source,
        })?;
        for (rel, bytes) in &entries {
            let target = stage_run.join(rel);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|source| TransportError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            fs::write(&target, bytes).map_err(|source| TransportError::Io {
                path: target,
                source,
            })?;
        }

        let staged = RunsRoot::new(&stage_root).open(&run_id).map_err(|error| {
            TransportError::Integrity(format!("staged run identity is invalid: {error}"))
        })?;
        let verified = staged.verify_integrity().map_err(|error| {
            TransportError::Integrity(format!(
                "transported dossier failed integrity verification after extraction: {error}"
            ))
        })?;
        if verified + 1 != entries.len() {
            return Err(TransportError::Integrity(format!(
                "transport contains {} entries but sealed dossier accounts for {}",
                entries.len(),
                verified + 1
            )));
        }
        fs::rename(&stage_run, &destination).map_err(|source| TransportError::Io {
            path: destination.clone(),
            source,
        })?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&stage_root);
    result?;

    Ok(Outcome {
        operation: "unpack",
        run_id,
        media_type: MEDIA_TYPE,
        transport_sha256,
        files: entries.len(),
        payload_bytes,
        path: destination.display().to_string(),
        trust_boundary: "transport bytes were structurally bounded and the reconstructed dossier passed its original integrity seal; this does not establish producer, signer, remote-host or scientific trust",
    })
}

fn validate_manifest(manifest: &BundleManifest) -> Result<(), TransportError> {
    if manifest.algorithm != "sha256" {
        return Err(TransportError::Invalid(format!(
            "unsupported dossier digest algorithm `{}`",
            manifest.algorithm
        )));
    }
    if manifest.files.len() + 1 > MAX_FILES {
        return Err(TransportError::Invalid(format!(
            "dossier contains too many sealed files (limit {MAX_FILES})"
        )));
    }
    for path in manifest.files.keys() {
        validate_relative_path(path)?;
        if path == "bundle.json" {
            return Err(TransportError::Invalid(
                "bundle manifest must not seal itself".into(),
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(rel: &str) -> Result<(), TransportError> {
    if rel.is_empty() || rel.len() > MAX_PATH_BYTES || rel.contains('\\') {
        return Err(TransportError::Invalid(format!(
            "unsafe transport path `{rel}`"
        )));
    }
    let path = Path::new(rel);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(TransportError::Invalid(format!(
            "unsafe transport path `{rel}`"
        )));
    }
    Ok(())
}

fn write_transport(path: &Path, entries: &[(String, Vec<u8>)]) -> Result<(), TransportError> {
    let mut file = File::create_new(path).map_err(|source| TransportError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(MAGIC).map_err(|source| TransportError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let count = u32::try_from(entries.len())
        .map_err(|_| TransportError::Invalid("too many transport entries".into()))?;
    file.write_all(&count.to_le_bytes())
        .map_err(|source| TransportError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    for (rel, bytes) in entries {
        validate_relative_path(rel)?;
        let path_len = u16::try_from(rel.len())
            .map_err(|_| TransportError::Invalid("transport path too long".into()))?;
        file.write_all(&path_len.to_le_bytes())
            .and_then(|()| file.write_all(rel.as_bytes()))
            .and_then(|()| file.write_all(&(bytes.len() as u64).to_le_bytes()))
            .and_then(|()| file.write_all(bytes))
            .map_err(|source| TransportError::Io {
                path: path.to_path_buf(),
                source,
            })?;
    }
    file.sync_all().map_err(|source| TransportError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_transport(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, TransportError> {
    let mut cursor = io::Cursor::new(bytes);
    let mut magic = [0u8; 8];
    cursor
        .read_exact(&mut magic)
        .map_err(|_| TransportError::Invalid("truncated transport header".into()))?;
    if &magic != MAGIC {
        return Err(TransportError::Invalid(
            "unsupported or malformed transport magic/version".into(),
        ));
    }
    let count = read_u32(&mut cursor)? as usize;
    if count == 0 || count > MAX_FILES {
        return Err(TransportError::Invalid(format!(
            "transport file count {count} is outside 1..={MAX_FILES}"
        )));
    }

    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for _ in 0..count {
        let path_len = read_u16(&mut cursor)? as usize;
        if path_len == 0 || path_len > MAX_PATH_BYTES {
            return Err(TransportError::Invalid(
                "transport entry has invalid path length".into(),
            ));
        }
        let mut path_bytes = vec![0u8; path_len];
        cursor
            .read_exact(&mut path_bytes)
            .map_err(|_| TransportError::Invalid("truncated transport path".into()))?;
        let rel = String::from_utf8(path_bytes)
            .map_err(|_| TransportError::Invalid("transport path is not UTF-8".into()))?;
        validate_relative_path(&rel)?;
        let len = read_u64(&mut cursor)?;
        total = total
            .checked_add(len)
            .ok_or_else(|| TransportError::Invalid("transport payload size overflow".into()))?;
        if total > MAX_TOTAL_BYTES || len > usize::MAX as u64 {
            return Err(TransportError::Invalid(format!(
                "transport payload exceeds {MAX_TOTAL_BYTES} bytes"
            )));
        }
        let mut payload = vec![0u8; len as usize];
        cursor
            .read_exact(&mut payload)
            .map_err(|_| TransportError::Invalid("truncated transport payload".into()))?;
        if entries.insert(rel.clone(), payload).is_some() {
            return Err(TransportError::Invalid(format!(
                "duplicate transport path `{rel}`"
            )));
        }
    }
    if cursor.position() != bytes.len() as u64 {
        return Err(TransportError::Invalid(
            "trailing unframed bytes after transport entries".into(),
        ));
    }
    if !entries.contains_key("bundle.json") {
        return Err(TransportError::Invalid(
            "transport has no bundle.json".into(),
        ));
    }
    Ok(entries)
}

fn read_u16(cursor: &mut io::Cursor<&[u8]>) -> Result<u16, TransportError> {
    let mut bytes = [0u8; 2];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| TransportError::Invalid("truncated transport integer".into()))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(cursor: &mut io::Cursor<&[u8]>) -> Result<u32, TransportError> {
    let mut bytes = [0u8; 4];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| TransportError::Invalid("truncated transport integer".into()))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut io::Cursor<&[u8]>) -> Result<u64, TransportError> {
    let mut bytes = [0u8; 8];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| TransportError::Invalid("truncated transport integer".into()))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, TransportError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| TransportError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(TransportError::Invalid(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > limit {
        return Err(TransportError::Invalid(format!(
            "`{}` is {} bytes, limit is {limit}",
            path.display(),
            metadata.len()
        )));
    }
    fs::read(path).map_err(|source| TransportError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let suffix = format!(
        ".tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    PathBuf::from(format!("{}{}", path.display(), suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_verify_model::{RunId, SCHEMA_VERSION, TOOL_IDENTITY};

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "scirust-verify-transport-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temp directory");
        path
    }

    fn sealed_run(project: &Path, run_id: &str) -> PathBuf {
        let run = project.join(".scirust-verify/runs").join(run_id);
        fs::create_dir_all(&run).expect("create run");
        let run_doc = RunDocument {
            schema_version: SCHEMA_VERSION,
            run_id: RunId::from_string(run_id),
            state: RunState::Finalized,
            created_at_utc: "2026-08-29T00:00:00Z".into(),
            finalized_at_utc: Some("2026-08-29T00:00:01Z".into()),
            replay_of: None,
            tool_version: TOOL_IDENTITY.into(),
        };
        let mut run_bytes = serde_json::to_vec_pretty(&run_doc).expect("serialize run");
        run_bytes.push(b'\n');
        fs::write(run.join("run.json"), &run_bytes).expect("write run");
        fs::write(run.join("evidence.bin"), b"evidence\0bytes").expect("write evidence");
        let manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            algorithm: "sha256".into(),
            sealed_by: TOOL_IDENTITY.into(),
            files: BTreeMap::from([
                ("run.json".into(), Digest::sha256_hex(&run_bytes).value),
                (
                    "evidence.bin".into(),
                    Digest::sha256_hex(b"evidence\0bytes").value,
                ),
            ]),
        };
        let mut bundle = serde_json::to_vec_pretty(&manifest).expect("serialize bundle");
        bundle.push(b'\n');
        fs::write(run.join("bundle.json"), bundle).expect("write bundle");
        run
    }

    #[test]
    fn pack_is_byte_deterministic_for_same_sealed_dossier() {
        let project = temp_dir("pack-deterministic");
        sealed_run(&project, "run-transport-deterministic");
        let first = project.join("first.svtr");
        let second = project.join("second.svtr");
        pack("run-transport-deterministic", &project, &first).expect("pack first");
        pack("run-transport-deterministic", &project, &second).expect("pack second");
        assert_eq!(fs::read(first).expect("first"), fs::read(second).expect("second"));
        let _ = fs::remove_dir_all(project);
    }

    #[test]
    fn round_trip_preserves_original_dossier_bytes_and_seal() {
        let source = temp_dir("roundtrip-source");
        let destination = temp_dir("roundtrip-destination");
        let original = sealed_run(&source, "run-transport-roundtrip");
        let transport = source.join("run.svtr");
        pack("run-transport-roundtrip", &source, &transport).expect("pack");
        unpack(&transport, &destination).expect("unpack");
        let imported = destination
            .join(".scirust-verify/runs")
            .join("run-transport-roundtrip");
        assert_eq!(
            fs::read(original.join("bundle.json")).expect("source bundle"),
            fs::read(imported.join("bundle.json")).expect("imported bundle")
        );
        let store = RunsRoot::new(destination.join(".scirust-verify/runs"))
            .open("run-transport-roundtrip")
            .expect("open imported");
        assert_eq!(store.verify_integrity().expect("integrity"), 2);
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(destination);
    }

    #[test]
    fn parser_rejects_traversal_duplicate_and_trailing_bytes() {
        let entries = vec![("../escape".to_owned(), b"x".to_vec())];
        let path = temp_dir("bad-path").join("bad.svtr");
        assert!(write_transport(&path, &entries).is_err());

        let mut raw = Vec::new();
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&2u32.to_le_bytes());
        for _ in 0..2 {
            raw.extend_from_slice(&10u16.to_le_bytes());
            raw.extend_from_slice(b"bundle.json");
            raw.extend_from_slice(&1u64.to_le_bytes());
            raw.push(b'x');
        }
        assert!(parse_transport(&raw).is_err());

        raw.clear();
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&10u16.to_le_bytes());
        raw.extend_from_slice(b"bundle.json");
        raw.extend_from_slice(&1u64.to_le_bytes());
        raw.push(b'x');
        raw.push(b'!');
        assert!(parse_transport(&raw).is_err());
    }

    #[test]
    fn corrupted_payload_never_publishes_run() {
        let source = temp_dir("corrupt-source");
        let destination = temp_dir("corrupt-destination");
        sealed_run(&source, "run-transport-corrupt");
        let transport = source.join("run.svtr");
        pack("run-transport-corrupt", &source, &transport).expect("pack");
        let mut bytes = fs::read(&transport).expect("transport");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&transport, bytes).expect("corrupt transport");
        assert!(unpack(&transport, &destination).is_err());
        assert!(!destination
            .join(".scirust-verify/runs/run-transport-corrupt")
            .exists());
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(destination);
    }

    #[test]
    fn unpack_refuses_existing_run_without_modifying_it() {
        let source = temp_dir("collision-source");
        let destination = temp_dir("collision-destination");
        sealed_run(&source, "run-transport-collision");
        let transport = source.join("run.svtr");
        pack("run-transport-collision", &source, &transport).expect("pack");
        let existing = destination
            .join(".scirust-verify/runs")
            .join("run-transport-collision");
        fs::create_dir_all(&existing).expect("existing run");
        fs::write(existing.join("sentinel"), b"keep").expect("sentinel");
        assert!(unpack(&transport, &destination).is_err());
        assert_eq!(
            fs::read(existing.join("sentinel")).expect("read sentinel"),
            b"keep"
        );
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(destination);
    }

    #[test]
    fn invalid_magic_and_oversized_count_fail_closed() {
        assert!(parse_transport(b"not-a-transport").is_err());
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.extend_from_slice(&((MAX_FILES as u32) + 1).to_le_bytes());
        assert!(parse_transport(&bytes).is_err());
    }
}
