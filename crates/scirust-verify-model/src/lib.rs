//! Domain model for SciRust-Verify.
//!
//! This crate defines the typed vocabulary shared by every other
//! SciRust-Verify component: artifacts, claims, checks, evidence,
//! observations, verification scope, verdicts and digests.
//!
//! The layer is intentionally free of process execution, filesystem layout
//! and I/O concerns: it describes *what* the concepts are, not how they are
//! produced or stored.
//!
//! # Identifier derivation (documented contract)
//!
//! * [`ArtifactId`] — the manifest `artifact.name`, falling back to the first
//!   Cargo package name. Never derived from content.
//! * [`ClaimId`] — the claim kind slug (e.g. `tests_pass`) plus an optional
//!   instance suffix separated by `@` when multiple claims of one kind exist.
//! * [`CheckId`] — `<provider>:<slug>[:<index>` where index disambiguates
//!   repeated providers of the same check within a plan. Stable for a given
//!   manifest + discovery result because planning sorts deterministically.
//! * [`EvidenceId`] — `ev-<NNNN>` with a zero-padded sequential number
//!   assigned in execution order inside a run. Deterministic given the run's
//!   check order (SciRust-Verify executes checks sequentially).
//! * [`RunId`] — `run-<YYYYMMDDTHHMMSSZ>-<8 lowercase hex>`; the hex part is a
//!   digest of the creation instant plus the run directory path so that two
//!   runs created in the same second remain distinct.

#![deny(missing_docs)]

pub mod artifact;
pub mod check;
pub mod claim;
pub mod digest;
pub mod evidence;
pub mod id;
pub mod observation;
pub mod provenance;
pub mod scope;
pub mod tolerance;
pub mod verdict;

pub use artifact::{Artifact, ArtifactKind, DirtyState, SourceIdentity};
pub use check::{
    Check, CheckAction, CheckExecution, CheckStatus, CommandTemplate, ExitExpectation,
};
pub use claim::{Claim, ClaimEvaluation, ClaimKind};
pub use digest::{canonical_json, Digest, DigestAlgorithm};
pub use evidence::{Attachment, Evidence, EvidenceKind, EvidenceStatus};
pub use id::{new_run_id_suffix, ArtifactId, CheckId, ClaimId, EvidenceId, RunId};
pub use observation::{Observation, ObservedValue};
pub use provenance::{GitProvenance, ProvenanceDocument, ProvenanceProbe};
pub use scope::{
    CpuIdentity, EnvironmentSnapshot, ExecutionBoundary, GpuIdentity, HostIdentity,
    ToolchainIdentity, VerificationScope,
};
pub use tolerance::Tolerance;
pub use verdict::{
    aggregate_dossier_verdict, DossierVerdict, GatingItem, RequirementLevel, Verdict,
};

/// Schema version of every persisted top-level document produced by this
/// version of SciRust-Verify. Readers must reject documents whose version is
/// higher than the highest supported version rather than guessing.
pub const SCHEMA_VERSION: u64 = 1;

/// Human-readable tool identity recorded in reports and dossiers.
pub const TOOL_IDENTITY: &str = concat!("scirust-verify ", env!("CARGO_PKG_VERSION"));
