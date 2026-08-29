//! Deterministic single-file transport for finalized SciRust-Verify dossiers.
//!
//! The envelope preserves existing sealed bytes. It creates no evidence and
//! establishes no signer, producer, remote-host, or scientific trust.

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
const MAX_TRANSPORT_BYTES: u64 = MAX_TOTAL_BYTES + 64 * 1024 * 1024;
const MEDIA_TYPE: &str = "application/vnd.scirust.verify-dossier-transport.v1";

#[derive(Parser)]
#[command(
    name = "scirust-verify-transport",
    version,
    about = "Pack or unpack one sealed SciRust-Verify dossier as a deterministic file"
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
        /// Destination file; never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Unpack a transport file into a project's run store.
    Unpack {
        /// Transport file produced by `pack`.
        input: PathBuf,
        /// Project receiving the run.
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
    let store = RunsRoot::new(project.join(".scirust-verify/runs"))
        .open(run_id)
        .map_err(|error| integrity(format!("run `{run_id}` is not available: {error}")))?;
    store.verify_integrity().map_err(|error| {
        integrity(format!(
            "run `{run_id}` failed dossier integrity verification: {error}"
        ))
    })?;
    let run_doc = store
        .read_run_document()
        .map_err(|error| integrity(format!("run `{run_id}` metadata is unusable: {error}")))?;
    if run_doc.state != RunState::Finalized || run_doc.run_id.as_str() != run_id {
        return Err(integrity(format!(
            "run `{run_id}` is not a finalized identity-matching dossier"
        )));
    }

    let bundle_path = store.path().join("bundle.json");
    let bundle_bytes = read_bounded(&bundle_path, MAX_TOTAL_BYTES)?;
    let manifest: BundleManifest =
        serde_json::from_slice(&bundle_bytes).map_err(|source| TransportError::Json {
            path: bundle_path.clone(),
            source,
        })?;
    validate_manifest(&manifest)?;

    let mut paths: Vec<String> = manifest.files.keys().cloned().collect();
    paths.push("bundle.json".into());
    paths.sort();
    paths.dedup();
    if paths.len() > MAX_FILES {
        return Err(invalid(format!(
            "transport contains {} files, limit is {MAX_FILES}",
            paths.len()
        )));
    }

    let mut total = 0u64;
    let mut entries = Vec::with_capacity(paths.len());
    for rel in paths {
        validate_relative_path(&rel)?;
        let path = store.path().join(&rel);
        require_regular_file(&path)?;
        let bytes = read_bounded(&path, MAX_TOTAL_BYTES.saturating_sub(total))?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("transport payload size overflow"))?;
        if total > MAX_TOTAL_BYTES {
            return Err(invalid(format!(
                "transport payload exceeds {MAX_TOTAL_BYTES} bytes"
            )));
        }
        verify_entry_bytes(&rel, &bytes, &bundle_bytes, &manifest)?;
        entries.push((rel, bytes));
    }

    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    let tmp = temporary_sibling(output);
    let result = (|| {
        write_transport(&tmp, &entries)?;
        fs::hard_link(&tmp, output).map_err(|source| {
            if output.exists() {
                invalid(format!(
                    "destination `{}` already exists; transport export never overwrites",
                    output.display()
                ))
            } else {
                io_error(output, source)
            }
        })?;
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    result?;

    let transport_bytes = read_bounded(output, MAX_TRANSPORT_BYTES)?;
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

fn verify_entry_bytes(
    rel: &str,
    bytes: &[u8],
    bundle_bytes: &[u8],
    manifest: &BundleManifest,
) -> Result<(), TransportError> {
    if rel == "bundle.json" {
        if bytes != bundle_bytes {
            return Err(integrity("bundle.json changed during transport packing"));
        }
        return Ok(());
    }
    let expected = manifest
        .files
        .get(rel)
        .ok_or_else(|| integrity(format!("unsealed file `{rel}` selected for packing")))?;
    let actual = Digest::sha256_hex(bytes).value;
    if &actual != expected {
        return Err(integrity(format!(
            "sealed file `{rel}` changed during transport packing"
        )));
    }
    Ok(())
}

fn unpack(input: &Path, project: &Path) -> Result<Outcome, TransportError> {
    let transport_bytes = read_bounded(input, MAX_TRANSPORT_BYTES)?;
    let transport_sha256 = Digest::sha256_hex(&transport_bytes).value;
    let entries = parse_transport(&transport_bytes)?;
    let payload_bytes = entries
        .values()
        .map(|bytes| bytes.len() as u64)
        .sum::<u64>();
    let run_doc = parse_run_document(&entries)?;
    if run_doc.state != RunState::Finalized {
        return Err(integrity(format!(
            "transported run `{}` is not finalized",
            run_doc.run_id
        )));
    }
    let run_id = run_doc.run_id.as_str().to_owned();

    let runs_dir = project.join(".scirust-verify/runs");
    fs::create_dir_all(&runs_dir).map_err(|source| io_error(&runs_dir, source))?;
    let destination = runs_dir.join(&run_id);
    if destination.exists() {
        return Err(invalid(format!(
            "destination run `{run_id}` already exists; transport import never overwrites evidence"
        )));
    }

    let stage_root = runs_dir.join(unique_name(".transport"));
    let stage_run = stage_root.join(&run_id);
    let result = (|| {
        fs::create_dir_all(&stage_run).map_err(|source| io_error(&stage_run, source))?;
        materialize_entries(&stage_run, &entries)?;
        let staged = RunsRoot::new(&stage_root)
            .open(&run_id)
            .map_err(|error| integrity(format!("staged run identity is invalid: {error}")))?;
        let verified = staged.verify_integrity().map_err(|error| {
            integrity(format!(
                "transported dossier failed integrity verification after extraction: {error}"
            ))
        })?;
        if verified + 1 != entries.len() {
            return Err(integrity(format!(
                "transport contains {} entries but sealed dossier accounts for {}",
                entries.len(),
                verified + 1
            )));
        }
        if destination.exists() {
            return Err(invalid(format!(
                "destination run `{run_id}` appeared during import; refusing publication"
            )));
        }
        fs::rename(&stage_run, &destination).map_err(|source| io_error(&destination, source))?;
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

fn parse_run_document(entries: &BTreeMap<String, Vec<u8>>) -> Result<RunDocument, TransportError> {
    let bytes = entries
        .get("run.json")
        .ok_or_else(|| invalid("transport has no run.json"))?;
    serde_json::from_slice(bytes).map_err(|source| TransportError::Json {
        path: PathBuf::from("run.json"),
        source,
    })
}

fn materialize_entries(
    root: &Path,
    entries: &BTreeMap<String, Vec<u8>>,
) -> Result<(), TransportError> {
    for (rel, bytes) in entries {
        validate_relative_path(rel)?;
        let target = root.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        }
        File::options()
            .write(true)
            .create_new(true)
            .open(&target)
            .and_then(|mut file| file.write_all(bytes))
            .map_err(|source| io_error(&target, source))?;
    }
    Ok(())
}

fn validate_manifest(manifest: &BundleManifest) -> Result<(), TransportError> {
    if manifest.algorithm != "sha256" {
        return Err(invalid(format!(
            "unsupported dossier digest algorithm `{}`",
            manifest.algorithm
        )));
    }
    if manifest.files.len() + 1 > MAX_FILES {
        return Err(invalid(format!(
            "dossier contains too many sealed files (limit {MAX_FILES})"
        )));
    }
    for path in manifest.files.keys() {
        validate_relative_path(path)?;
        if path == "bundle.json" {
            return Err(invalid("bundle manifest must not seal itself"));
        }
    }
    Ok(())
}

fn validate_relative_path(rel: &str) -> Result<(), TransportError> {
    if rel.is_empty() || rel.len() > MAX_PATH_BYTES || rel.contains('\\') {
        return Err(invalid(format!("unsafe transport path `{rel}`")));
    }
    let path = Path::new(rel);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!("unsafe transport path `{rel}`")));
    }
    Ok(())
}

fn write_transport(path: &Path, entries: &[(String, Vec<u8>)]) -> Result<(), TransportError> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(MAGIC)
        .and_then(|()| file.write_all(&(entries.len() as u32).to_le_bytes()))
        .map_err(|source| io_error(path, source))?;
    for (rel, bytes) in entries {
        validate_relative_path(rel)?;
        let path_len = u16::try_from(rel.len())
            .map_err(|_| invalid("transport path is too long for v1 framing"))?;
        file.write_all(&path_len.to_le_bytes())
            .and_then(|()| file.write_all(rel.as_bytes()))
            .and_then(|()| file.write_all(&(bytes.len() as u64).to_le_bytes()))
            .and_then(|()| file.write_all(bytes))
            .map_err(|source| io_error(path, source))?;
    }
    file.sync_all().map_err(|source| io_error(path, source))
}

fn parse_transport(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, TransportError> {
    let mut cursor = io::Cursor::new(bytes);
    let mut magic = [0u8; 8];
    cursor
        .read_exact(&mut magic)
        .map_err(|_| invalid("truncated transport header"))?;
    if &magic != MAGIC {
        return Err(invalid("unsupported or malformed transport magic/version"));
    }
    let count = read_u32(&mut cursor)? as usize;
    if count == 0 || count > MAX_FILES {
        return Err(invalid(format!(
            "transport file count {count} is outside 1..={MAX_FILES}"
        )));
    }

    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for _ in 0..count {
        let rel = read_path(&mut cursor)?;
        let len = read_u64(&mut cursor)?;
        total = total
            .checked_add(len)
            .ok_or_else(|| invalid("transport payload size overflow"))?;
        if total > MAX_TOTAL_BYTES || len > usize::MAX as u64 {
            return Err(invalid(format!(
                "transport payload exceeds {MAX_TOTAL_BYTES} bytes"
            )));
        }
        let mut payload = vec![0u8; len as usize];
        cursor
            .read_exact(&mut payload)
            .map_err(|_| invalid("truncated transport payload"))?;
        if entries.insert(rel.clone(), payload).is_some() {
            return Err(invalid(format!("duplicate transport path `{rel}`")));
        }
    }
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid("trailing unframed bytes after transport entries"));
    }
    if !entries.contains_key("bundle.json") {
        return Err(invalid("transport has no bundle.json"));
    }
    Ok(entries)
}

fn read_path(cursor: &mut io::Cursor<&[u8]>) -> Result<String, TransportError> {
    let path_len = read_u16(cursor)? as usize;
    if path_len == 0 || path_len > MAX_PATH_BYTES {
        return Err(invalid("transport entry has invalid path length"));
    }
    let mut bytes = vec![0u8; path_len];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| invalid("truncated transport path"))?;
    let rel = String::from_utf8(bytes).map_err(|_| invalid("transport path is not UTF-8"))?;
    validate_relative_path(&rel)?;
    Ok(rel)
}

fn read_u16(cursor: &mut io::Cursor<&[u8]>) -> Result<u16, TransportError> {
    let mut bytes = [0u8; 2];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| invalid("truncated transport integer"))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(cursor: &mut io::Cursor<&[u8]>) -> Result<u32, TransportError> {
    let mut bytes = [0u8; 4];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| invalid("truncated transport integer"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(cursor: &mut io::Cursor<&[u8]>) -> Result<u64, TransportError> {
    let mut bytes = [0u8; 8];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| invalid("truncated transport integer"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, TransportError> {
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

fn require_regular_file(path: &Path) -> Result<(), TransportError> {
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

fn temporary_sibling(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}{}", path.display(), unique_name(".tmp")))
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

fn invalid(message: impl Into<String>) -> TransportError {
    TransportError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> TransportError {
    TransportError::Integrity(message.into())
}

fn io_error(path: impl Into<PathBuf>, source: io::Error) -> TransportError {
    TransportError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_verify_model::{RunId, SCHEMA_VERSION, TOOL_IDENTITY};

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(unique_name(&format!(
            "scirust-verify-transport-{label}"
        )));
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
        assert_eq!(
            fs::read(first).expect("first"),
            fs::read(second).expect("second")
        );
        let _ = fs::remove_dir_all(project);
    }

    #[test]
    fn round_trip_preserves_bundle_bytes_and_seal() {
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
        let path = temp_dir("bad-path").join("bad.svtr");
        assert!(write_transport(&path, &[("../escape".into(), vec![b'x'])]).is_err());

        let duplicate = raw_transport(&[
            ("bundle.json", b"x"),
            ("bundle.json", b"y"),
        ]);
        assert!(parse_transport(&duplicate).is_err());

        let mut trailing = raw_transport(&[("bundle.json", b"x")]);
        trailing.push(b'!');
        assert!(parse_transport(&trailing).is_err());
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
        bytes[last] ^= 1;
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

    fn raw_transport(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (path, payload) in entries {
            bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
            bytes.extend_from_slice(path.as_bytes());
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(payload);
        }
        bytes
    }
}
