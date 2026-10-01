//! Versioned evidence bundle storage.
//!
//! # Layout
//!
//! ```text
//! .scirust-verify/runs/<run-id>/
//! ├── run.json          RunDocument (state machine)
//! ├── artifact.json     Artifact
//! ├── environment.json  EnvironmentSnapshot
//! ├── provenance.json   ProvenanceDocument
//! ├── plan.json         PlanDocument (checks + plan digest)
//! ├── claims.json       ClaimsDocument
//! ├── executions.json   ExecutionsDocument
//! ├── evidence/
//! │   ├── ev-0001.json  Evidence objects (one file each)
//! │   └── files/        Content-addressed attachments (<sha256>.bin)
//! ├── report.json       Machine report (regenerable)
//! ├── report.md         Human report (regenerable)
//! └── bundle.json       Integrity manifest written last, at finalize time
//! ```
//!
//! Every persisted top-level document carries `schema_version`. Important
//! files are written atomically (temp + rename). A finalized bundle records
//! the digest of every other file in `bundle.json`; readers verify all
//! digests and reject tampered or missing content.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use scirust_verify_model::check::{Check, CheckExecution};
use scirust_verify_model::claim::Claim;
use scirust_verify_model::digest::Digest;
use scirust_verify_model::evidence::Evidence;
use scirust_verify_model::provenance::ProvenanceDocument;
use scirust_verify_model::scope::EnvironmentSnapshot;
use scirust_verify_model::{Artifact, RunId, SCHEMA_VERSION, TOOL_IDENTITY};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux_openat {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::raw::c_char;
    use std::os::unix::ffi::OsStrExt as _;

    const O_RDONLY: i32 = 0;
    const O_DIRECTORY: i32 = 0o200000;
    const O_NOFOLLOW: i32 = 0o400000;
    const O_CLOEXEC: i32 = 0o2000000;

    unsafe extern "C" {
        fn openat(dirfd: i32, pathname: *const c_char, flags: i32, ...) -> i32;
    }

    pub(super) fn open_directory(parent: &File, name: &OsStr) -> io::Result<File> {
        open(
            parent,
            name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
        )
    }

    pub(super) fn open_file(parent: &File, name: &OsStr) -> io::Result<File> {
        open(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    }

    fn open(parent: &File, name: &OsStr, flags: i32) -> io::Result<File> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: `name` is NUL-terminated and alive for the call, `parent`
        // owns a valid directory descriptor, no mode argument is needed
        // because O_CREAT is absent, and a successful descriptor is adopted
        // exactly once by `File`.
        let descriptor = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `openat` returned a new owned descriptor on success.
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }
}

const MAX_BUNDLE_FILES: usize = 16_384;
const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUNDLE_DEPTH: usize = 64;
static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
struct ReadBudget {
    files: usize,
    bytes: u64,
}

#[derive(Default)]
struct SemanticSnapshot {
    run: Option<RunDocument>,
    artifact: Option<Artifact>,
    plan: Option<PlanDocument>,
    claims: Option<ClaimsDocument>,
    executions: Option<ExecutionsDocument>,
    evidence: Vec<Evidence>,
    file_sizes: BTreeMap<String, u64>,
    evidence_dir_present: bool,
}

impl SemanticSnapshot {
    fn capture_directory(&mut self, relative: &Path) {
        if relative == Path::new("evidence") {
            self.evidence_dir_present = true;
        }
    }

    fn capture_file(&mut self, root: &Path, rel: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.file_sizes.insert(rel.to_owned(), bytes.len() as u64);
        let path = root.join(rel);
        match rel {
            "run.json" => self.run = Some(deserialize_snapshot(&path, bytes)?),
            "artifact.json" => self.artifact = Some(deserialize_snapshot(&path, bytes)?),
            "plan.json" => self.plan = Some(deserialize_snapshot(&path, bytes)?),
            "claims.json" => self.claims = Some(deserialize_snapshot(&path, bytes)?),
            "executions.json" => self.executions = Some(deserialize_snapshot(&path, bytes)?),
            _ if Path::new(rel).parent() == Some(Path::new("evidence"))
                && Path::new(rel).extension().and_then(|value| value.to_str()) == Some("json") =>
            {
                self.evidence.push(deserialize_snapshot(&path, bytes)?);
            }
            _ => {}
        }
        Ok(())
    }
}

impl ReadBudget {
    fn account_entry(&mut self, run_id: &str) -> Result<(), StoreError> {
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| StoreError::corrupt(run_id, "bundle entry counter overflowed"))?;
        if self.files > MAX_BUNDLE_FILES {
            return Err(StoreError::corrupt(
                run_id,
                format!("bundle exceeds the {MAX_BUNDLE_FILES} entry limit"),
            ));
        }
        Ok(())
    }

    fn account(&mut self, run_id: &str, rel: &str, size: u64) -> Result<(), StoreError> {
        if size > MAX_BUNDLE_FILE_BYTES {
            return Err(StoreError::corrupt(
                run_id,
                format!(
                    "file `{rel}` is {size} bytes, exceeding the per-file limit of {MAX_BUNDLE_FILE_BYTES}"
                ),
            ));
        }
        self.account_entry(run_id)?;
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or_else(|| StoreError::corrupt(run_id, "bundle byte counter overflowed"))?;
        if self.bytes > MAX_BUNDLE_BYTES {
            return Err(StoreError::corrupt(
                run_id,
                format!("bundle exceeds the {MAX_BUNDLE_BYTES} byte limit"),
            ));
        }
        Ok(())
    }
}

/// Lifecycle of a verification run.
///
/// An interrupted run keeps whatever state it had; it never looks final.
/// Only [`RunState::Finalized`] bundles carry an integrity manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Plan is being built.
    Planning,
    /// Checks are executing.
    Running,
    /// Dossier validation and final writes are in progress.
    Finalizing,
    /// Bundle complete and integrity-sealed.
    Finalized,
    /// Run aborted; evidence up to abort point is preserved.
    Aborted,
}

/// `run.json` — identity and lifecycle of one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDocument {
    /// Schema version.
    pub schema_version: u64,
    /// The run identifier.
    pub run_id: RunId,
    /// Current lifecycle state.
    pub state: RunState,
    /// Creation instant (UTC RFC 3339).
    pub created_at_utc: String,
    /// Finalization instant when finalized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_at_utc: Option<String>,
    /// Original run when this run is a replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<RunId>,
    /// SciRust-Verify version that produced the bundle.
    pub tool_version: String,
}

/// `plan.json` — the executed plan with its canonical digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanDocument {
    /// Schema version.
    pub schema_version: u64,
    /// SHA-256 over the canonical JSON of `checks`.
    pub plan_digest: Digest,
    /// Planned checks in deterministic order.
    pub checks: Vec<Check>,
}

/// `claims.json` — claims under evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsDocument {
    /// Schema version.
    pub schema_version: u64,
    /// Registered claims.
    pub claims: Vec<Claim>,
}

/// `executions.json` — recorded check executions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionsDocument {
    /// Schema version.
    pub schema_version: u64,
    /// Executions in check-plan order.
    pub executions: Vec<CheckExecution>,
}

/// `bundle.json` — the integrity manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Schema version.
    pub schema_version: u64,
    /// Digest algorithm (always sha256 in V1).
    pub algorithm: String,
    /// Tool that sealed the bundle.
    pub sealed_by: String,
    /// path => sha256 hex for every sealed file (bundle.json excluded).
    pub files: BTreeMap<String, String>,
}

/// Errors produced by the store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem failure.
    #[error("filesystem error at `{path}`: {source}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying OS error.
        source: std::io::Error,
    },
    /// JSON serialization/deserialization failure.
    #[error("serialization error for `{path}`: {source}")]
    Serde {
        /// Offending path.
        path: PathBuf,
        /// Underlying error.
        source: serde_json::Error,
    },
    /// Document schema version unsupported.
    #[error("`{path}` has unsupported schema version {found} (supported: <= {max})")]
    UnsupportedSchema {
        /// Offending path.
        path: PathBuf,
        /// Found schema version.
        found: u64,
        /// Maximum supported version.
        max: u64,
    },
    /// Attempted mutation of a finalized run.
    #[error("run `{0}` is finalized and cannot be modified")]
    Frozen(RunId),
    /// Structural corruption detected while loading.
    #[error("bundle corruption in `{run_id}`: {reason}")]
    Corrupt {
        /// Run id.
        run_id: String,
        /// What is wrong.
        reason: String,
    },
    /// The requested run does not exist.
    #[error("run `{0}` not found")]
    NotFound(String),
}

impl StoreError {
    pub(crate) fn corrupt(run_id: &str, reason: impl Into<String>) -> Self {
        Self::Corrupt {
            run_id: run_id.to_owned(),
            reason: reason.into(),
        }
    }
}

fn io_err(path: impl Into<PathBuf>, e: std::io::Error) -> StoreError {
    StoreError::Io {
        path: path.into(),
        source: e,
    }
}

/// Handle to one run directory inside a runs root.
pub struct RunStore {
    run_dir: PathBuf,
    run_id: RunId,
}

/// Root handle above all run directories (`.scirust-verify/runs`).
pub struct RunsRoot(PathBuf);

impl RunsRoot {
    /// Wraps a runs-root directory (created on demand).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// Creates a fresh run and returns its store handle.
    pub fn create_run(&self) -> Result<RunStore, StoreError> {
        let run_id = generate_run_id();
        self.create_run_with_id(run_id)
    }

    /// Creates a run with an explicit identifier (used by replay to keep the
    /// freshly generated id).
    pub fn create_run_with_id(&self, run_id: RunId) -> Result<RunStore, StoreError> {
        validate_run_id(run_id.as_str())?;
        let run_dir = self.0.join(run_id.as_str());
        if run_dir.exists() {
            return Err(StoreError::Corrupt {
                run_id: run_id.into_inner(),
                reason: "run directory already exists".into(),
            });
        }
        fs::create_dir_all(run_dir.join("evidence/files")).map_err(|e| io_err(&run_dir, e))?;
        let store = RunStore { run_dir, run_id };
        let now = chrono_now();
        store.write_json(
            "run.json",
            &RunDocument {
                schema_version: SCHEMA_VERSION,
                run_id: store.run_id.clone(),
                state: RunState::Planning,
                created_at_utc: now.clone(),
                finalized_at_utc: None,
                replay_of: None,
                tool_version: TOOL_IDENTITY.to_owned(),
            },
        )?;
        Ok(store)
    }

    /// Opens an existing run by id.
    pub fn open(&self, run_id: &str) -> Result<RunStore, StoreError> {
        validate_run_id(run_id)?;
        let run_dir = self.0.join(run_id);
        let metadata =
            fs::symlink_metadata(&run_dir).map_err(|_| StoreError::NotFound(run_id.to_owned()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StoreError::corrupt(
                run_id,
                "run path is not a real directory",
            ));
        }
        Ok(RunStore {
            run_dir,
            run_id: RunId::from_string(run_id),
        })
    }

    /// Lists run ids present under this root (sorted).
    pub fn list_runs(&self) -> Result<Vec<String>, StoreError> {
        let mut ids = Vec::new();
        let entries = fs::read_dir(&self.0).map_err(|e| io_err(&self.0, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err(&self.0, e))?;
            if entry
                .file_type()
                .map_err(|e| io_err(self.0.clone(), e))?
                .is_dir()
                && entry.path().join("run.json").is_file()
            {
                ids.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Absolute path of the root.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl RunStore {
    /// The run id handled by this store.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Path of the run directory.
    pub fn path(&self) -> &Path {
        &self.run_dir
    }

    /// Loads `run.json`.
    pub fn read_run_document(&self) -> Result<RunDocument, StoreError> {
        self.read_json("run.json")
    }

    /// Persists the lifecycle state.
    pub fn set_state(&self, state: RunState) -> Result<(), StoreError> {
        let mut doc: RunDocument = self.read_json("run.json")?;
        if doc.state == RunState::Finalized && state != RunState::Finalized {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }
        doc.state = state;
        if state == RunState::Finalized {
            doc.finalized_at_utc = Some(chrono_now());
        }
        self.write_json("run.json", &doc)
    }

    /// Marks the replay origin.
    pub fn set_replay_of(&self, original: RunId) -> Result<(), StoreError> {
        let mut doc: RunDocument = self.read_json("run.json")?;
        if doc.state == RunState::Finalized {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }
        doc.replay_of = Some(original);
        self.write_json("run.json", &doc)
    }

    /// Persists `artifact.json`.
    pub fn write_artifact(&self, artifact: &Artifact) -> Result<(), StoreError> {
        self.write_json("artifact.json", artifact)
    }

    /// Loads `artifact.json`.
    pub fn read_artifact(&self) -> Result<Artifact, StoreError> {
        self.read_json("artifact.json")
    }

    /// Persists `environment.json`.
    pub fn write_environment(&self, env: &EnvironmentSnapshot) -> Result<(), StoreError> {
        self.write_json("environment.json", env)
    }

    /// Loads `environment.json`.
    pub fn read_environment(&self) -> Result<EnvironmentSnapshot, StoreError> {
        self.read_json("environment.json")
    }

    /// Persists `provenance.json`.
    pub fn write_provenance(&self, prov: &ProvenanceDocument) -> Result<(), StoreError> {
        self.write_json("provenance.json", prov)
    }

    /// Loads `provenance.json`.
    pub fn read_provenance(&self) -> Result<ProvenanceDocument, StoreError> {
        self.read_json("provenance.json")
    }

    /// Persists `plan.json`.
    pub fn write_plan(&self, checks: &[Check], plan_digest: Digest) -> Result<(), StoreError> {
        self.write_json(
            "plan.json",
            &PlanDocument {
                schema_version: SCHEMA_VERSION,
                plan_digest,
                checks: checks.to_vec(),
            },
        )
    }

    /// Loads `plan.json`.
    pub fn read_plan(&self) -> Result<PlanDocument, StoreError> {
        let doc: PlanDocument = self.read_json("plan.json")?;
        // Verify the recorded digest matches the persisted checks so a
        // mutated plan cannot masquerade as the executed one.
        let actual = Digest::of_canonical_json(&doc.checks).map_err(|e| StoreError::Serde {
            path: self.run_dir.join("plan.json"),
            source: e,
        })?;
        if actual != doc.plan_digest {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!(
                    "plan digest mismatch: recorded {}, computed {}",
                    doc.plan_digest, actual
                ),
            ));
        }
        Ok(doc)
    }

    /// Persists `claims.json`, validating claim-id uniqueness first.
    pub fn write_claims(&self, claims: &[Claim]) -> Result<(), StoreError> {
        ensure_unique(claims.iter().map(|c| c.id.as_str()), "claim")?;
        self.write_json(
            "claims.json",
            &ClaimsDocument {
                schema_version: SCHEMA_VERSION,
                claims: claims.to_vec(),
            },
        )
    }

    /// Loads `claims.json`.
    pub fn read_claims(&self) -> Result<Vec<Claim>, StoreError> {
        let doc: ClaimsDocument = self.read_json("claims.json")?;
        Ok(doc.claims)
    }

    /// Appends one execution record to `executions.json`.
    pub fn append_execution(&self, execution: CheckExecution) -> Result<(), StoreError> {
        let mut doc: ExecutionsDocument = match self.read_json("executions.json") {
            Ok(d) => d,
            Err(StoreError::Io { .. }) => ExecutionsDocument {
                schema_version: SCHEMA_VERSION,
                executions: Vec::new(),
            },
            Err(e) => return Err(e),
        };
        doc.executions.push(execution);
        self.write_json("executions.json", &doc)
    }

    /// Replaces the full executions document (used by report regeneration).
    pub fn write_executions(&self, executions: &[CheckExecution]) -> Result<(), StoreError> {
        self.write_json(
            "executions.json",
            &ExecutionsDocument {
                schema_version: SCHEMA_VERSION,
                executions: executions.to_vec(),
            },
        )
    }

    /// Loads `executions.json` (empty when absent — pre-execution states).
    pub fn read_executions(&self) -> Result<Vec<CheckExecution>, StoreError> {
        match self.read_json::<ExecutionsDocument>("executions.json") {
            Ok(d) => Ok(d.executions),
            Err(StoreError::Io { .. }) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Writes one evidence object plus its attachment payloads.
    ///
    /// Attachments are stored content-addressed under `evidence/files/`;
    /// their recorded digests are computed here from the provided bytes so
    /// they can never drift from the stored content.
    pub fn add_evidence(
        &self,
        evidence: &Evidence,
        attachments: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), StoreError> {
        // Evidence ids are immutable once written: a second write with the
        // same id would silently rewrite history.
        let ev_file = format!("evidence/{}.json", evidence.id.as_str());
        if self.run_dir.join(&ev_file).exists() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!(
                    "evidence id {} already exists; ids are immutable once written",
                    evidence.id
                ),
            ));
        }
        // Validate attachment references against supplied payloads.
        let mut resolved = Vec::new();
        for att in &evidence.attachments {
            let payload = attachments.get(att.path.as_str()).ok_or_else(|| {
                StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("attachment payload missing for `{}`", att.path),
                )
            })?;
            let actual = Digest::sha256_hex(payload);
            if actual != att.digest || actual.value.len() != att.digest.value.len() {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!(
                        "attachment `{}` digest mismatch: expected {}, got {}",
                        att.path, att.digest, actual
                    ),
                ));
            }
            if att.size_bytes != payload.len() as u64 {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("attachment `{}` size mismatch", att.path),
                ));
            }
            let rel = sanitize_attachment_path(&att.path)?;
            let dest = self.run_dir.join(&rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| io_err(&dest, e))?;
            }
            atomic_write(&dest, payload).map_err(|e| io_err(dest, e))?;
            resolved.push((att.path.clone(), rel));
        }
        let _ = resolved; // paths inside evidence already point into the run dir

        self.write_json(&ev_file, evidence)
    }

    /// Loads every evidence object of the run (sorted by id).
    pub fn read_all_evidence(&self) -> Result<Vec<Evidence>, StoreError> {
        let dir = self.run_dir.join("evidence");
        let mut out = Vec::new();
        let metadata = match fs::symlink_metadata(&dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => return Err(io_err(&dir, error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                "`evidence` is not a real directory",
            ));
        }
        let entries = fs::read_dir(&dir).map_err(|e| io_err(&dir, e))?;
        let mut budget = ReadBudget::default();
        for entry in entries {
            let entry = entry.map_err(|e| io_err(&dir, e))?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| io_err(&path, e))?;
            if file_type.is_symlink() {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("symlink `{}` is not allowed in evidence", path.display()),
                ));
            }
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if !file_type.is_file() {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("evidence entry `{}` is not a regular file", path.display()),
                    ));
                }
                let relative = path.strip_prefix(&self.run_dir).map_err(|_| {
                    StoreError::corrupt(self.run_id.as_str(), "evidence path escaped run")
                })?;
                let rel = relative
                    .to_str()
                    .ok_or_else(|| {
                        StoreError::corrupt(
                            self.run_id.as_str(),
                            format!("evidence path `{}` is not valid UTF-8", relative.display()),
                        )
                    })?
                    .to_owned();
                let bytes = self.read_bounded_regular(&rel, &mut budget)?;
                let ev: Evidence =
                    serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde {
                        path: path.clone(),
                        source: e,
                    })?;
                out.push(ev);
            } else {
                budget.account_entry(self.run_id.as_str())?;
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Writes a regenerable text artifact (report.json / report.md / ...).
    pub fn write_text(&self, rel_path: &str, contents: &str) -> Result<(), StoreError> {
        let dest = self.run_dir.join(sanitize_attachment_path(rel_path)?);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(&dest, e))?;
        }
        atomic_write(&dest, contents.as_bytes()).map_err(|e| io_err(dest, e))
    }

    /// Reads a previously written text artifact.
    pub fn read_text(&self, rel_path: &str) -> Result<String, StoreError> {
        let rel = sanitize_attachment_path(rel_path)?;
        let path = self.run_dir.join(&rel);
        let mut budget = ReadBudget::default();
        let bytes = self.read_bounded_regular(&rel, &mut budget)?;
        String::from_utf8(bytes)
            .map_err(|error| io_err(path, io::Error::new(io::ErrorKind::InvalidData, error)))
    }

    /// Validates dossier structure and seals it with `bundle.json`.
    ///
    /// Validation performed:
    /// * every evidence id unique; every referenced attachment exists with
    ///   matching size/digest;
    /// * every evidence/check reference from executions resolves;
    /// * required documents exist (artifact, plan, claims);
    /// * no impossible lifecycle transition remains pending.
    pub fn finalize(&self) -> Result<BundleManifest, StoreError> {
        let current_doc = self.read_run_document()?;
        if current_doc.state == RunState::Finalized {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }

        // Parse semantic documents directly from the exact bytes read through
        // confined descriptors. No path-addressable snapshot is created for a
        // same-UID child process to mutate. The live tree must still match the
        // captured digest map before sealing.
        let mut validation_snapshot = BTreeMap::new();
        let mut validation_snapshot_budget = ReadBudget::default();
        let mut semantic_snapshot = SemanticSnapshot::default();
        self.collect_files(
            &self.run_dir,
            0,
            &mut validation_snapshot_budget,
            &mut validation_snapshot,
            Some(&mut semantic_snapshot),
        )?;
        let run_doc = semantic_snapshot.run.ok_or_else(|| {
            StoreError::corrupt(self.run_id.as_str(), "required file `run.json` is missing")
        })?;
        if run_doc.state == RunState::Finalized {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }
        if run_doc.schema_version > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema {
                path: self.run_dir.join("run.json"),
                found: run_doc.schema_version,
                max: SCHEMA_VERSION,
            });
        }

        // Required documents.
        let _artifact = semantic_snapshot.artifact.ok_or_else(|| {
            StoreError::corrupt(
                self.run_id.as_str(),
                "required file `artifact.json` is missing",
            )
        })?;
        let plan = semantic_snapshot.plan.ok_or_else(|| {
            StoreError::corrupt(self.run_id.as_str(), "required file `plan.json` is missing")
        })?;
        let claims = semantic_snapshot.claims.ok_or_else(|| {
            StoreError::corrupt(
                self.run_id.as_str(),
                "required file `claims.json` is missing",
            )
        })?;
        if !semantic_snapshot.evidence_dir_present {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                "required directory `evidence` is missing",
            ));
        }
        let executions = semantic_snapshot
            .executions
            .map(|document| document.executions)
            .unwrap_or_default();
        let mut evidence = semantic_snapshot.evidence;
        evidence.sort_by(|a, b| a.id.cmp(&b.id));
        let claims = claims.claims;

        let actual_plan_digest =
            Digest::of_canonical_json(&plan.checks).map_err(|source| StoreError::Serde {
                path: self.run_dir.join("plan.json"),
                source,
            })?;
        if actual_plan_digest != plan.plan_digest {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!(
                    "plan digest mismatch: recorded {}, computed {}",
                    plan.plan_digest, actual_plan_digest
                ),
            ));
        }

        // Uniqueness of evidence ids.
        let mut seen_ids = std::collections::BTreeSet::new();
        for ev in &evidence {
            if !seen_ids.insert(ev.id.as_str().to_owned()) {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("duplicate evidence id {}", ev.id),
                ));
            }
        }

        // Attachment existence + integrity.
        let mut validated_attachments: BTreeMap<String, (u64, String)> = BTreeMap::new();
        for ev in &evidence {
            for att in &ev.attachments {
                let rel = sanitize_attachment_path(&att.path)?;
                let expected = (att.size_bytes, att.digest.to_string());
                if let Some(previous) = validated_attachments.get(&rel) {
                    if previous != &expected {
                        return Err(StoreError::corrupt(
                            self.run_id.as_str(),
                            format!("attachment `{}` has conflicting metadata", att.path),
                        ));
                    }
                    continue;
                }
                let actual_size = semantic_snapshot.file_sizes.get(&rel).ok_or_else(|| {
                    StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("referenced attachment `{}` is missing", att.path),
                    )
                })?;
                if *actual_size != att.size_bytes {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("attachment `{}` size drifted", att.path),
                    ));
                }
                let actual_digest = validation_snapshot.get(&rel).ok_or_else(|| {
                    StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("referenced attachment `{}` is missing", att.path),
                    )
                })?;
                if actual_digest != &att.digest.value {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("attachment `{}` digest mismatch", att.path),
                    ));
                }
                validated_attachments.insert(rel, expected);
            }
        }

        // Reference validity: checks -> claims, executions -> checks/evidence.
        let claim_ids: std::collections::BTreeSet<&str> =
            claims.iter().map(|c| c.id.as_str()).collect();
        for check in &plan.checks {
            for cid in &check.claims {
                if !claim_ids.contains(cid.as_str()) {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("check {} references unknown claim {cid}", check.id),
                    ));
                }
            }
        }
        let check_ids: std::collections::BTreeSet<&str> =
            plan.checks.iter().map(|c| c.id.as_str()).collect();
        for exec in &executions {
            if !check_ids.contains(exec.check_id.as_str()) {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("execution references unknown check {}", exec.check_id),
                ));
            }
            for eid in &exec.evidence_ids {
                if !seen_ids.contains(eid.as_str()) {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("execution references missing evidence {eid}"),
                    ));
                }
            }
        }
        // Derivation links between evidence must resolve and must not be
        // self-referential.
        for ev in &evidence {
            for dep in &ev.derived_from {
                if dep == &ev.id {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("evidence {} derives from itself", ev.id),
                    ));
                }
                if !seen_ids.contains(dep.as_str()) {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("evidence {} derives from missing {}", ev.id, dep),
                    ));
                }
            }
        }

        // Traverse and enforce all shape/size limits before making the state
        // transition irreversible. The state change only alters run.json, so
        // replace that one digest after the transition.
        let mut files = BTreeMap::new();
        let mut budget = ReadBudget::default();
        self.collect_files(&self.run_dir, 0, &mut budget, &mut files, None)?;
        if files != validation_snapshot {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                "bundle changed during finalization validation",
            ));
        }
        let mut finalized_doc = run_doc.clone();
        finalized_doc.state = RunState::Finalized;
        finalized_doc.finalized_at_utc = Some(chrono_now());
        let run_path = self.run_dir.join("run.json");
        let finalized_run = serialize_json_document(&run_path, &finalized_doc)?;
        self.write_json("run.json", &finalized_doc)?;
        files.insert(
            "run.json".to_owned(),
            Digest::sha256_hex(&finalized_run).value,
        );
        let manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            algorithm: "sha256".to_owned(),
            sealed_by: TOOL_IDENTITY.to_owned(),
            files,
        };
        if let Err(error) = self.write_json("bundle.json", &manifest) {
            self.write_json("run.json", &run_doc)?;
            return Err(error);
        }
        Ok(manifest)
    }

    /// Verifies a finalized bundle against its manifest. Returns the number
    /// of verified files. Non-finalized runs are reported as such.
    pub fn verify_integrity(&self) -> Result<usize, StoreError> {
        let run_doc = self.read_run_document()?;
        if run_doc.state != RunState::Finalized {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("run is not finalized (state {:?})", run_doc.state),
            ));
        }
        let manifest: BundleManifest = self.read_json("bundle.json")?;
        if manifest.files.len() > MAX_BUNDLE_FILES {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("manifest exceeds the {MAX_BUNDLE_FILES} file limit"),
            ));
        }
        let mut sealed_budget = ReadBudget::default();
        for (rel, expected_hex) in &manifest.files {
            let safe_rel = sanitize_attachment_path(rel)?;
            if safe_rel == "bundle.json" {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    "manifest must not seal itself",
                ));
            }
            let bytes = self
                .read_bounded_regular(&safe_rel, &mut sealed_budget)
                .map_err(|_| {
                    StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("sealed file `{rel}` is missing"),
                    )
                })?;
            let actual = Digest::sha256_hex(&bytes);
            if &actual.value != expected_hex {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!(
                        "sealed file `{rel}` was modified: expected {}, found {}",
                        expected_hex, actual.value
                    ),
                ));
            }
        }
        // Every non-manifest file must be sealed too (detect additions).
        let mut present = BTreeMap::new();
        let mut present_budget = ReadBudget::default();
        self.collect_files(&self.run_dir, 0, &mut present_budget, &mut present, None)?;
        present.remove("bundle.json");
        if present != manifest.files {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                "bundle changed during integrity verification",
            ));
        }
        Ok(manifest.files.len())
    }

    fn write_json<T: Serialize>(&self, rel: &str, value: &T) -> Result<(), StoreError> {
        let path = self.run_dir.join(rel);
        if self.is_sealed(rel)? {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }
        let bytes = serialize_json_document(&path, value)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(&path, e))?;
        }
        atomic_write(&path, &bytes).map_err(|e| io_err(path, e))
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, rel: &str) -> Result<T, StoreError> {
        let rel = sanitize_attachment_path(rel)?;
        let path = self.run_dir.join(&rel);
        let mut budget = ReadBudget::default();
        let bytes = self.read_bounded_regular(&rel, &mut budget)?;
        serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde { path, source: e })
    }

    fn is_sealed(&self, rel: &str) -> Result<bool, StoreError> {
        if !self.run_dir.join("bundle.json").exists() {
            return Ok(false);
        }
        let manifest: BundleManifest = self.read_json("bundle.json")?;
        Ok(manifest.files.contains_key(rel))
    }

    fn read_bounded_regular(
        &self,
        rel: &str,
        budget: &mut ReadBudget,
    ) -> Result<Vec<u8>, StoreError> {
        let rel = sanitize_attachment_path(rel)?;

        #[cfg(target_os = "linux")]
        return self.read_bounded_regular_linux(&rel, budget);

        #[cfg(not(target_os = "linux"))]
        self.read_bounded_regular_portable(&rel, budget)
    }

    #[cfg(target_os = "linux")]
    fn read_bounded_regular_linux(
        &self,
        rel: &str,
        budget: &mut ReadBudget,
    ) -> Result<Vec<u8>, StoreError> {
        let root_before =
            fs::symlink_metadata(&self.run_dir).map_err(|error| io_err(&self.run_dir, error))?;
        if root_before.file_type().is_symlink() || !root_before.is_dir() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                "run root is not a real directory",
            ));
        }

        let mut root_options = fs::OpenOptions::new();
        root_options.read(true).custom_flags(0o600000); // O_DIRECTORY | O_NOFOLLOW
        let mut parent = root_options
            .open(&self.run_dir)
            .map_err(|error| io_err(&self.run_dir, error))?;
        let root_opened = parent
            .metadata()
            .map_err(|error| io_err(&self.run_dir, error))?;
        if root_before.dev() != root_opened.dev() || root_before.ino() != root_opened.ino() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                "run root changed while it was opened",
            ));
        }

        let components: Vec<_> = Path::new(rel).components().collect();
        for component in &components[..components.len() - 1] {
            let Component::Normal(name) = component else {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("unsafe path `{rel}`"),
                ));
            };
            let display_path = self.run_dir.join(rel);
            let opened = linux_openat::open_directory(&parent, name)
                .map_err(|error| io_err(&display_path, error))?;
            let opened_metadata = opened
                .metadata()
                .map_err(|error| io_err(&display_path, error))?;
            if !opened_metadata.is_dir() {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!(
                        "path component `{}` is not a real directory",
                        name.to_string_lossy()
                    ),
                ));
            }
            parent = opened;
        }

        let Component::Normal(file_name) = components[components.len() - 1] else {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("unsafe path `{rel}`"),
            ));
        };
        let display_path = self.run_dir.join(rel);
        let file = linux_openat::open_file(&parent, file_name)
            .map_err(|error| io_err(&display_path, error))?;
        let opened = file
            .metadata()
            .map_err(|error| io_err(&display_path, error))?;
        if !opened.is_file() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("`{rel}` is not a regular file"),
            ));
        }
        budget.account(self.run_id.as_str(), rel, opened.len())?;
        read_opened_file(file, &display_path, rel, opened.len(), self.run_id.as_str())
    }

    #[cfg(not(target_os = "linux"))]
    fn read_bounded_regular_portable(
        &self,
        rel: &str,
        budget: &mut ReadBudget,
    ) -> Result<Vec<u8>, StoreError> {
        let path = self.run_dir.join(&rel);
        reject_symlink_components(&self.run_dir, &rel, self.run_id.as_str())?;
        let before = fs::symlink_metadata(&path).map_err(|e| io_err(&path, e))?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("`{rel}` is not a regular file"),
            ));
        }
        budget.account(self.run_id.as_str(), &rel, before.len())?;

        let mut options = fs::OpenOptions::new();
        options.read(true);
        let file = options.open(&path).map_err(|e| io_err(&path, e))?;
        let opened = file.metadata().map_err(|e| io_err(&path, e))?;
        if !opened.is_file() {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("`{rel}` changed type while it was opened"),
            ));
        }
        read_opened_file(file, &path, rel, before.len(), self.run_id.as_str())
    }

    fn collect_files(
        &self,
        dir: &Path,
        depth: usize,
        budget: &mut ReadBudget,
        out: &mut BTreeMap<String, String>,
        mut semantic_snapshot: Option<&mut SemanticSnapshot>,
    ) -> Result<(), StoreError> {
        if depth > MAX_BUNDLE_DEPTH {
            return Err(StoreError::corrupt(
                self.run_id.as_str(),
                format!("bundle exceeds the {MAX_BUNDLE_DEPTH} directory-depth limit"),
            ));
        }
        let entries = fs::read_dir(dir).map_err(|e| io_err(dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err(dir, e))?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| io_err(&path, e))?;
            if file_type.is_symlink() {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("symlink `{}` is not allowed in a bundle", path.display()),
                ));
            }
            if file_type.is_dir() {
                budget.account_entry(self.run_id.as_str())?;
                let relative = path.strip_prefix(&self.run_dir).map_err(|_| {
                    StoreError::corrupt(self.run_id.as_str(), "bundle path escaped run")
                })?;
                relative.to_str().ok_or_else(|| {
                    StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("bundle path `{}` is not valid UTF-8", relative.display()),
                    )
                })?;
                if let Some(snapshot) = semantic_snapshot.as_deref_mut() {
                    snapshot.capture_directory(relative);
                }
                self.collect_files(
                    &path,
                    depth + 1,
                    budget,
                    out,
                    semantic_snapshot.as_deref_mut(),
                )?;
            } else if file_type.is_file() {
                let relative = path.strip_prefix(&self.run_dir).map_err(|_| {
                    StoreError::corrupt(self.run_id.as_str(), "bundle path escaped run")
                })?;
                let rel = relative
                    .to_str()
                    .ok_or_else(|| {
                        StoreError::corrupt(
                            self.run_id.as_str(),
                            format!("bundle path `{}` is not valid UTF-8", relative.display()),
                        )
                    })?
                    .replace('\\', "/");
                if rel == "bundle.json" {
                    continue;
                }
                let bytes = self.read_bounded_regular(&rel, budget)?;
                if let Some(snapshot) = semantic_snapshot.as_deref_mut() {
                    snapshot.capture_file(&self.run_dir, &rel, &bytes)?;
                }
                out.insert(rel, Digest::sha256_hex(&bytes).value);
            } else {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!(
                        "special file `{}` is not allowed in a bundle",
                        path.display()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Generates a fresh run id (`run-<UTC>-<8hex>`), collision-checked nowhere
/// else because the entropy input makes collisions negligible.
pub fn generate_run_id() -> RunId {
    use chrono::Utc;
    let now = Utc::now();
    let second = now.format("%Y%m%dT%H%M%SZ").to_string();
    let nanos = now.timestamp_subsec_nanos();
    let pid = std::process::id();
    let suffix = scirust_verify_model::new_run_id_suffix(&format!(
        "{second}|{nanos}|{pid}|{}",
        std::process::id()
    ));
    RunId::from_string(format!("run-{second}-{suffix}"))
}

fn ensure_unique<'a>(items: impl Iterator<Item = &'a str>, what: &str) -> Result<(), StoreError> {
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        if !seen.insert(item.to_owned()) {
            return Err(StoreError::corrupt(
                "(planning)",
                format!("duplicate {what} id `{item}`"),
            ));
        }
    }
    Ok(())
}

/// Rejects absolute paths and traversal outside the run directory.
pub(crate) fn sanitize_attachment_path(rel: &str) -> Result<String, StoreError> {
    let components: Vec<_> = Path::new(rel).components().collect();
    let is_safe = !rel.is_empty()
        && !rel.contains('\\')
        && !rel.contains(':')
        && rel
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && components.len() <= MAX_BUNDLE_DEPTH
        && components
            .iter()
            .all(|component| matches!(component, Component::Normal(_)));
    if !is_safe {
        return Err(StoreError::Corrupt {
            run_id: "(path)".to_owned(),
            reason: format!("unsafe attachment path `{rel}`"),
        });
    }
    Ok(rel.to_owned())
}

fn validate_run_id(run_id: &str) -> Result<(), StoreError> {
    let bytes = run_id.as_bytes();
    let valid = bytes.len() == 29
        && bytes.starts_with(b"run-")
        && bytes[4..12].iter().all(u8::is_ascii_digit)
        && bytes[12] == b'T'
        && bytes[13..19].iter().all(u8::is_ascii_digit)
        && bytes[19] == b'Z'
        && bytes[20] == b'-'
        && bytes[21..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
    if !valid {
        return Err(StoreError::corrupt(
            run_id,
            "invalid run id; expected run-<YYYYMMDDTHHMMSSZ>-<8 lowercase hex>",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reject_symlink_components(root: &Path, rel: &str, run_id: &str) -> Result<(), StoreError> {
    let mut current = root.to_path_buf();
    let components: Vec<_> = Path::new(rel).components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(StoreError::corrupt(run_id, format!("unsafe path `{rel}`")));
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).map_err(|e| io_err(&current, e))?;
        if metadata.file_type().is_symlink() {
            return Err(StoreError::corrupt(
                run_id,
                format!("symlink `{}` is not allowed", current.display()),
            ));
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err(StoreError::corrupt(
                run_id,
                format!("path component `{}` is not a directory", current.display()),
            ));
        }
    }
    Ok(())
}

fn read_opened_file(
    mut file: fs::File,
    path: &Path,
    rel: &str,
    expected_len: u64,
    run_id: &str,
) -> Result<Vec<u8>, StoreError> {
    let capacity = usize::try_from(expected_len.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(MAX_BUNDLE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_err(path, error))?;
    if bytes.len() as u64 != expected_len {
        return Err(StoreError::corrupt(
            run_id,
            format!("`{rel}` changed size while it was read"),
        ));
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}."))
        .unwrap_or_default();
    let (tmp, mut file) = loop {
        let nonce = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate =
            path.with_extension(format!("{extension}tmp-{}-{nonce}", std::process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(target_os = "linux")]
        let written = file.metadata()?;
        #[cfg(not(target_os = "linux"))]
        drop(file);
        fs::rename(&tmp, path)?;
        #[cfg(target_os = "linux")]
        {
            let mut options = fs::OpenOptions::new();
            options.read(true).custom_flags(0o400000); // O_NOFOLLOW
            let published = options.open(path)?;
            let published_metadata = published.metadata()?;
            if written.dev() != published_metadata.dev()
                || written.ino() != published_metadata.ino()
            {
                return Err(io::Error::other(
                    "atomic-write temporary was replaced before publication",
                ));
            }
            drop(file);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn serialize_json_document<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>, StoreError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|source| StoreError::Serde {
        path: path.to_path_buf(),
        source,
    })?;
    bytes.extend_from_slice(b"\n");
    Ok(bytes)
}

fn deserialize_snapshot<T: for<'de> Deserialize<'de>>(
    path: &Path,
    bytes: &[u8],
) -> Result<T, StoreError> {
    serde_json::from_slice(bytes).map_err(|source| StoreError::Serde {
        path: path.to_path_buf(),
        source,
    })
}

fn chrono_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

#[cfg(test)]
mod tests;
