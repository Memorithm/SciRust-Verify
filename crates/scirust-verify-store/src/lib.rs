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
use std::io::Write as _;
use std::path::{Path, PathBuf};

use scirust_verify_model::check::{Check, CheckExecution};
use scirust_verify_model::claim::Claim;
use scirust_verify_model::digest::Digest;
use scirust_verify_model::evidence::Evidence;
use scirust_verify_model::provenance::ProvenanceDocument;
use scirust_verify_model::scope::EnvironmentSnapshot;
use scirust_verify_model::{Artifact, RunId, SCHEMA_VERSION, TOOL_IDENTITY};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
        let run_dir = self.0.join(run_id);
        if !run_dir.is_dir() {
            return Err(StoreError::NotFound(run_id.to_owned()));
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
        if !dir.is_dir() {
            return Ok(out);
        }
        let entries = fs::read_dir(&dir).map_err(|e| io_err(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err(&dir, e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let bytes = fs::read(&path).map_err(|e| io_err(&path, e))?;
                let ev: Evidence =
                    serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde {
                        path: path.clone(),
                        source: e,
                    })?;
                out.push(ev);
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
        let path = self.run_dir.join(sanitize_attachment_path(rel_path)?);
        fs::read_to_string(&path).map_err(|e| io_err(path, e))
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
        let run_doc = self.read_run_document()?;
        if run_doc.schema_version > SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema {
                path: self.run_dir.join("run.json"),
                found: run_doc.schema_version,
                max: SCHEMA_VERSION,
            });
        }
        if run_doc.state == RunState::Finalized {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }

        // Required documents.
        let _artifact = self.read_artifact()?;
        let plan = self.read_plan()?;
        let claims = self.read_claims()?;
        let executions = self.read_executions()?;
        let evidence = self.read_all_evidence()?;

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
        for ev in &evidence {
            for att in &ev.attachments {
                let path = self.run_dir.join(&att.path);
                let bytes = fs::read(&path).map_err(|_| {
                    StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("referenced attachment `{}` is missing", att.path),
                    )
                })?;
                if bytes.len() as u64 != att.size_bytes {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("attachment `{}` size drifted", att.path),
                    ));
                }
                let digest = Digest::sha256_hex(&bytes);
                if digest != att.digest {
                    return Err(StoreError::corrupt(
                        self.run_id.as_str(),
                        format!("attachment `{}` digest mismatch", att.path),
                    ));
                }
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

        // Seal: mark finalized first (nothing is sealed yet), then digest
        // every file including the final run.json, then write bundle.json
        // last so the manifest covers the complete frozen content.
        self.set_state(RunState::Finalized)?;
        let mut files = BTreeMap::new();
        collect_files(&self.run_dir, self.run_dir.clone(), &mut files)?;
        let manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            algorithm: "sha256".to_owned(),
            sealed_by: TOOL_IDENTITY.to_owned(),
            files,
        };
        self.write_json("bundle.json", &manifest)?;
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
        for (rel, expected_hex) in &manifest.files {
            let path = self.run_dir.join(rel);
            let bytes = fs::read(&path).map_err(|_| {
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
        collect_files(&self.run_dir, self.run_dir.clone(), &mut present)?;
        present.remove("bundle.json");
        for rel in present.keys() {
            if !manifest.files.contains_key(rel) {
                return Err(StoreError::corrupt(
                    self.run_id.as_str(),
                    format!("unsealed file `{rel}` present in finalized bundle"),
                ));
            }
        }
        Ok(manifest.files.len())
    }

    fn write_json<T: Serialize>(&self, rel: &str, value: &T) -> Result<(), StoreError> {
        let path = self.run_dir.join(rel);
        if self.is_sealed(rel)? {
            return Err(StoreError::Frozen(self.run_id.clone()));
        }
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| StoreError::Serde {
            path: path.clone(),
            source: e,
        })?;
        bytes.extend_from_slice(b"\n");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(&path, e))?;
        }
        atomic_write(&path, &bytes).map_err(|e| io_err(path, e))
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, rel: &str) -> Result<T, StoreError> {
        let path = self.run_dir.join(rel);
        let bytes = fs::read(&path).map_err(|e| io_err(path.clone(), e))?;
        serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde { path, source: e })
    }

    fn is_sealed(&self, rel: &str) -> Result<bool, StoreError> {
        if !self.run_dir.join("bundle.json").exists() {
            return Ok(false);
        }
        let manifest: BundleManifest = self.read_json("bundle.json")?;
        Ok(manifest.files.contains_key(rel))
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
    if rel.is_empty() || rel.starts_with('/') || rel.split(['/', '\\']).any(|c| c == "..") {
        return Err(StoreError::Corrupt {
            run_id: "(path)".to_owned(),
            reason: format!("unsafe attachment path `{rel}`"),
        });
    }
    Ok(rel.to_owned())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}tmp-{}",
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| format!("{e}."))
            .unwrap_or_default(),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn collect_files(
    root: &Path,
    dir: PathBuf,
    out: &mut BTreeMap<String, String>,
) -> Result<(), StoreError> {
    let entries = fs::read_dir(&dir).map_err(|e| io_err(dir.clone(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err(&dir, e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .expect("strip_prefix of collected subpath")
                .to_string_lossy()
                .into_owned();
            if rel == "bundle.json" {
                continue;
            }
            let bytes = fs::read(&path).map_err(|e| io_err(path, e))?;
            out.insert(rel, Digest::sha256_hex(&bytes).value);
        }
    }
    Ok(())
}

fn chrono_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}
