//! Artifact identity and source identity.

use crate::digest::Digest;
use crate::id::ArtifactId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What kind of thing is being verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A Cargo package or workspace.
    CargoWorkspace,
    /// A single compiled binary.
    Binary,
    /// An arbitrary source directory.
    SourceTree,
    /// A candidate produced by the Forge engine (future integration).
    ForgeCandidate,
    /// A SciCapsule experiment capsule (future integration).
    SciCapsule,
    /// Anything else.
    Other,
}

/// Identity of the source the artifact was built from.
///
/// Distinguishes three honest states: Git identity known, content identity
/// known (tree digest without Git), and unknown. At least one should be
/// recorded whenever possible; `unknown` for both is legal but must be
/// surfaced as a limitation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceIdentity {
    /// Repository remote URL, when discoverable.
    pub repository: Option<String>,
    /// Full commit hash when inside a Git worktree.
    pub commit: Option<String>,
    /// Branch name when available (informational only).
    pub branch: Option<String>,
    /// Worktree cleanliness: clean / dirty / unknown.
    pub dirty: DirtyState,
    /// Content digest of the source tree (see provenance hashing rules),
    /// recorded when Git identity is unavailable or as a complement.
    pub tree_digest: Option<Digest>,
}

/// Whether the working tree contained uncommitted changes at verification time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyState {
    /// No uncommitted changes.
    Clean,
    /// Uncommitted changes present; changes are not itemized here.
    Dirty,
    /// Could not be determined (e.g. no Git).
    #[default]
    Unknown,
}

/// The subject of a verification dossier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Stable identifier within the dossier.
    pub id: ArtifactId,
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// Human-readable name (package name, binary name, ...).
    pub name: String,
    /// Declared version when known (Cargo package version).
    pub version: Option<String>,
    /// Absolute path to the artifact root at verification time.
    pub path: PathBuf,
    /// Source identity (Git/tree digests).
    pub source: SourceIdentity,
    /// Digest of the primary build output when applicable.
    pub content_digest: Option<Digest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_identity_defaults_to_unknown_dirty_state() {
        let s: SourceIdentity = serde_json::from_str("{}").unwrap();
        assert_eq!(s.dirty, DirtyState::Unknown);
        assert!(s.commit.is_none());
    }

    #[test]
    fn dirty_state_serde_names() {
        assert_eq!(
            serde_json::to_string(&DirtyState::Dirty).unwrap(),
            "\"dirty\""
        );
    }
}
