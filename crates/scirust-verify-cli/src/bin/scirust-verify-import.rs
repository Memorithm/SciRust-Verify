//! Import a finalized evidence dossier produced on another host or in CI.
//!
//! This command treats transport and the source directory as untrusted. It
//! verifies the source dossier seal, copies only sealed regular files into a
//! staging root, verifies the staged copy again, and only then atomically
//! publishes the run into the local run store. Detached signatures are not
//! imported and signer trust is deliberately outside this command's scope.

#![deny(missing_docs)]

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use clap::Parser;
use scirust_verify_model::{Digest, SCHEMA_VERSION};
use scirust_verify_store::{BundleManifest, RunState, RunsRoot};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "scirust-verify-import",
    version,
    about = "Import an integrity-valid finalized SciRust-Verify dossier from CI or another host"
)]
struct Cli {
    /// Finalized run directory containing run.json and bundle.json.
    bundle_dir: PathBuf,
    /// Project whose `.scirust-verify/runs` store receives the dossier.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug)]
enum ImportError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    InvalidSource(String),
    Store(scirust_verify_store::StoreError),
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "filesystem error at `{}`: {source}", path.display())
            }
            Self::InvalidSource(reason) => f.write_str(reason),
            Self::Store(error) => error.fmt(f),
            Self::Json { path, source } => {
                write!(f, "invalid JSON at `{}`: {source}", path.display())
            }
        }
    }
}

impl From<scirust_verify_store::StoreError> for ImportError {
    fn from(value: scirust_verify_store::StoreError) -> Self {
        Self::Store(value)
    }
}

#[derive(Debug, Serialize)]
struct ImportOutcome {
    run_id: String,
    bundle_digest: String,
    verified_files: usize,
    destination: String,
    signer_trust: &'static str,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match import_bundle(&cli.bundle_dir, &cli.project) {
        Ok(outcome) => {
            if cli.json {
                match serde_json::to_string_pretty(&outcome) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        eprintln!("error: failed to serialize output: {error}");
                        return std::process::ExitCode::from(3);
                    }
                }
            } else {
                println!("imported run      : {}", outcome.run_id);
                println!("bundle sha256     : {}", outcome.bundle_digest);
                println!("verified files    : {}", outcome.verified_files);
                println!("destination       : {}", outcome.destination);
                println!("signer trust      : {}", outcome.signer_trust);
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn import_bundle(bundle_dir: &Path, project: &Path) -> Result<ImportOutcome, ImportError> {
    let source = bundle_dir
        .canonicalize()
        .map_err(|source| ImportError::Io {
            path: bundle_dir.to_path_buf(),
            source,
        })?;
    if !source.is_dir() {
        return Err(ImportError::InvalidSource(format!(
            "`{}` is not a run directory",
            source.display()
        )));
    }

    reject_symlinks(&source, &source)?;

    let run_id = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ImportError::InvalidSource("run directory name is not valid UTF-8".into()))?
        .to_owned();
    let source_parent = source
        .parent()
        .ok_or_else(|| ImportError::InvalidSource("run directory has no parent".into()))?;
    let source_store = RunsRoot::new(source_parent).open(&run_id)?;
    let source_doc = source_store.read_run_document()?;
    if source_doc.schema_version > SCHEMA_VERSION {
        return Err(ImportError::InvalidSource(format!(
            "run `{run_id}` uses unsupported schema version {} (supported: <= {SCHEMA_VERSION})",
            source_doc.schema_version
        )));
    }
    if source_doc.run_id.as_str() != run_id {
        return Err(ImportError::InvalidSource(format!(
            "run identity mismatch: directory is `{run_id}` but run.json declares `{}`",
            source_doc.run_id
        )));
    }
    if source_doc.state != RunState::Finalized {
        return Err(ImportError::InvalidSource(format!(
            "run `{run_id}` is not finalized"
        )));
    }

    // Parse and validate manifest paths before asking the existing store
    // verifier to resolve any path from an untrusted manifest. This prevents
    // a hostile `../` entry from making integrity verification read outside
    // the supplied run directory.
    let manifest_path = source.join("bundle.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|source| ImportError::Io {
        path: manifest_path.clone(),
        source,
    })?;
    let manifest: BundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| ImportError::Json {
            path: manifest_path.clone(),
            source,
        })?;
    validate_manifest_paths(&manifest)?;

    let verified_files = source_store.verify_integrity()?;
    let bundle_digest = Digest::sha256_hex(&manifest_bytes).value;

    let runs_dir = project.join(".scirust-verify").join("runs");
    fs::create_dir_all(&runs_dir).map_err(|source| ImportError::Io {
        path: runs_dir.clone(),
        source,
    })?;
    let destination = runs_dir.join(&run_id);
    if destination.exists() {
        return Err(ImportError::InvalidSource(format!(
            "destination run `{run_id}` already exists; imports never overwrite evidence"
        )));
    }

    let stage_root = runs_dir.join(format!(
        ".import-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let stage_run = stage_root.join(&run_id);

    let result = (|| {
        fs::create_dir_all(&stage_run).map_err(|source| ImportError::Io {
            path: stage_run.clone(),
            source,
        })?;
        for rel in manifest
            .files
            .keys()
            .map(String::as_str)
            .chain(["bundle.json"])
        {
            copy_regular_file(&source, &stage_run, rel)?;
        }

        let staged = RunsRoot::new(&stage_root).open(&run_id)?;
        let staged_doc = staged.read_run_document()?;
        if staged_doc.run_id.as_str() != run_id || staged_doc.state != RunState::Finalized {
            return Err(ImportError::InvalidSource(
                "staged dossier identity/lifecycle changed during import".into(),
            ));
        }
        let staged_count = staged.verify_integrity()?;
        if staged_count != verified_files {
            return Err(ImportError::InvalidSource(format!(
                "staged dossier file count changed: source {verified_files}, staged {staged_count}"
            )));
        }
        let staged_bundle =
            fs::read(stage_run.join("bundle.json")).map_err(|source| ImportError::Io {
                path: stage_run.join("bundle.json"),
                source,
            })?;
        if Digest::sha256_hex(&staged_bundle).value != bundle_digest {
            return Err(ImportError::InvalidSource(
                "bundle.json changed while evidence was being imported".into(),
            ));
        }

        fs::rename(&stage_run, &destination).map_err(|source| ImportError::Io {
            path: destination.clone(),
            source,
        })?;
        Ok(())
    })();

    let _ = fs::remove_dir_all(&stage_root);
    result?;

    Ok(ImportOutcome {
        run_id,
        bundle_digest,
        verified_files,
        destination: destination.display().to_string(),
        signer_trust: "not evaluated; detached signatures are separate from bundle integrity",
    })
}

fn validate_manifest_paths(manifest: &BundleManifest) -> Result<(), ImportError> {
    if manifest.schema_version > SCHEMA_VERSION {
        return Err(ImportError::InvalidSource(format!(
            "bundle uses unsupported schema version {} (supported: <= {SCHEMA_VERSION})",
            manifest.schema_version
        )));
    }
    if manifest.algorithm != "sha256" {
        return Err(ImportError::InvalidSource(format!(
            "unsupported bundle digest algorithm `{}`",
            manifest.algorithm
        )));
    }
    for rel in manifest.files.keys() {
        validate_relative_path(rel)?;
        if rel == "bundle.json" {
            return Err(ImportError::InvalidSource(
                "bundle manifest must not seal itself".into(),
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(rel: &str) -> Result<(), ImportError> {
    if rel.is_empty() || rel.contains('\\') {
        return Err(ImportError::InvalidSource(format!(
            "unsafe sealed path `{rel}`"
        )));
    }
    let path = Path::new(rel);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ImportError::InvalidSource(format!(
            "unsafe sealed path `{rel}`"
        )));
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path, rel: &str) -> Result<(), ImportError> {
    validate_relative_path(rel)?;
    let from = source.join(rel);
    let metadata = fs::symlink_metadata(&from).map_err(|source| ImportError::Io {
        path: from.clone(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ImportError::InvalidSource(format!(
            "sealed path `{rel}` is not a regular file"
        )));
    }
    let bytes = fs::read(&from).map_err(|source| ImportError::Io {
        path: from.clone(),
        source,
    })?;
    let to = destination.join(rel);
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(|source| ImportError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(&to, bytes).map_err(|source| ImportError::Io { path: to, source })
}

fn reject_symlinks(root: &Path, dir: &Path) -> Result<(), ImportError> {
    for entry in fs::read_dir(dir).map_err(|source| ImportError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| ImportError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ImportError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            return Err(ImportError::InvalidSource(format!(
                "symbolic link `{}` is not allowed in imported evidence",
                rel.display()
            )));
        }
        if metadata.is_dir() {
            reject_symlinks(root, &path)?;
        } else if !metadata.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            return Err(ImportError::InvalidSource(format!(
                "special file `{}` is not allowed in imported evidence",
                rel.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_verify_model::{RunId, TOOL_IDENTITY};
    use scirust_verify_store::RunDocument;
    use std::collections::BTreeMap;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "scirust-verify-import-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn write_valid_bundle(root: &Path, run_id: &str) -> PathBuf {
        let run = root.join(run_id);
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
        fs::write(run.join("payload.txt"), b"remote evidence\n").expect("write payload");

        let files = BTreeMap::from([
            (
                "payload.txt".to_owned(),
                Digest::sha256_hex(b"remote evidence\n").value,
            ),
            ("run.json".to_owned(), Digest::sha256_hex(&run_bytes).value),
        ]);
        let manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            algorithm: "sha256".into(),
            sealed_by: TOOL_IDENTITY.into(),
            files,
        };
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
        manifest_bytes.push(b'\n');
        fs::write(run.join("bundle.json"), manifest_bytes).expect("write manifest");
        run
    }

    #[test]
    fn imports_only_after_two_integrity_checks() {
        let source_root = temp_dir("valid-source");
        let project = temp_dir("valid-project");
        let source = write_valid_bundle(&source_root, "run-remote-valid");

        let outcome = import_bundle(&source, &project).expect("import valid bundle");
        assert_eq!(outcome.run_id, "run-remote-valid");
        let imported = RunsRoot::new(project.join(".scirust-verify/runs"))
            .open("run-remote-valid")
            .expect("open imported");
        assert_eq!(imported.verify_integrity().expect("verify imported"), 2);

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(project);
    }

    #[test]
    fn rejects_tampered_source_without_publishing_destination() {
        let source_root = temp_dir("tamper-source");
        let project = temp_dir("tamper-project");
        let source = write_valid_bundle(&source_root, "run-remote-tampered");
        fs::write(source.join("payload.txt"), b"tampered\n").expect("tamper payload");

        let error = import_bundle(&source, &project).expect_err("tampering must fail");
        assert!(error.to_string().contains("modified"));
        assert!(!project
            .join(".scirust-verify/runs/run-remote-tampered")
            .exists());

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(project);
    }

    #[test]
    fn rejects_manifest_traversal_before_copy() {
        let mut manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            algorithm: "sha256".into(),
            sealed_by: TOOL_IDENTITY.into(),
            files: BTreeMap::new(),
        };
        manifest.files.insert("../escape".into(), "00".repeat(32));
        let error = validate_manifest_paths(&manifest).expect_err("traversal must fail");
        assert!(error.to_string().contains("unsafe sealed path"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_in_untrusted_bundle_tree() {
        use std::os::unix::fs::symlink;

        let source_root = temp_dir("symlink-source");
        let project = temp_dir("symlink-project");
        let source = write_valid_bundle(&source_root, "run-remote-symlink");
        symlink("/etc/passwd", source.join("leak")).expect("create symlink");

        let error = import_bundle(&source, &project).expect_err("symlink must fail");
        assert!(error.to_string().contains("symbolic link"));
        assert!(!project
            .join(".scirust-verify/runs/run-remote-symlink")
            .exists());

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(project);
    }

    #[test]
    fn refuses_existing_run_instead_of_overwriting() {
        let source_root = temp_dir("collision-source");
        let project = temp_dir("collision-project");
        let source = write_valid_bundle(&source_root, "run-remote-collision");
        let existing = project.join(".scirust-verify/runs/run-remote-collision");
        fs::create_dir_all(&existing).expect("create existing run");
        fs::write(existing.join("sentinel"), b"keep").expect("write sentinel");

        let error = import_bundle(&source, &project).expect_err("collision must fail");
        assert!(error.to_string().contains("never overwrite"));
        assert_eq!(
            fs::read(existing.join("sentinel")).expect("read sentinel"),
            b"keep"
        );

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(project);
    }
}
