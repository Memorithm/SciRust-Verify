//! Provenance records: where the verified source came from.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};

/// Git-derived provenance captured before verification starts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitProvenance {
    /// First remote URL, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Full commit hash (`git rev-parse HEAD`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Branch name, detached HEAD yields `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Worktree cleanliness from `git status --porcelain`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty_count: Option<u64>,
}

/// A provenance-gathering command whose output was hashed into the record.
/// Raw outputs live in attachments; only identity and digests are kept here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceProbe {
    /// What was asked (e.g. `rustc -Vv`).
    pub command: String,
    /// Digest of the captured stdout.
    pub stdout_digest: Digest,
}

impl ProvenanceProbe {
    /// Convenience constructor.
    pub fn new(command: impl Into<String>, stdout_digest: Digest) -> Self {
        Self {
            command: command.into(),
            stdout_digest,
        }
    }
}

/// Top-level provenance document persisted as `provenance.json`.
///
/// Distinguishes three honest identity states: Git identity known
/// (git present), content-only identity known (tree digest), or unknown.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvenanceDocument {
    /// Schema marker.
    pub schema_version: u64,
    /// Git provenance when inside a worktree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitProvenance>,
    /// Source-tree digest when computed (see hashing rules in core).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree_digest: Option<Digest>,
    /// Probes recorded (command + output digest).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<ProvenanceProbe>,
}
