//! SciCapsule v1 manifest validation and payload-integrity verification.
//!
//! Mirrors the contract of `scirust-capsule-schema` v1
//! (`Memorithm/scirust`, `CAPSULE_SCHEMA_VERSION = 1`):
//!
//! * `schema_version` must equal 1;
//! * `name` must be non-empty;
//! * payload paths are relative, forward-slash separated, without empty,
//!   `.`, or `..` components; backslashes and colons are rejected;
//! * payload digests are exactly 64 lowercase hexadecimal characters;
//! * payloads are strictly ordered by path (sorted input is part of the
//!   invariant) with no duplicates;
//! * `entrypoint` must appear among the payloads.
//!
//! On top of schema validation this module verifies on-disk payloads:
//! recomputed SHA-256 and exact byte length must both match.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Schema version supported by this implementation.
pub const CAPSULE_SCHEMA_VERSION: u16 = 1;

/// Errors from capsule parsing/validation/verification.
#[derive(Debug, Error)]
pub enum ScicapError {
    /// The manifest JSON could not be read.
    #[error("cannot read capsule manifest: {0}")]
    Io(String),
    /// The manifest violated the v1 schema contract.
    #[error("invalid capsule manifest: {0}")]
    Invalid(String),
    /// A payload file failed integrity verification.
    #[error("payload `{path}` integrity failure: {reason}")]
    PayloadIntegrity {
        /// Payload path from the manifest.
        path: String,
        /// What went wrong.
        reason: String,
    },
}

/// A single payload descriptor from the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadDescriptor {
    /// Relative forward-slash path (validated).
    pub path: String,
    /// Lowercase hex SHA-256 of the payload bytes.
    pub sha256: String,
    /// Exact byte length of the payload.
    pub size_bytes: u64,
}

/// The SciCapsule v1 manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleManifestV1 {
    /// Must be 1.
    pub schema_version: u16,
    /// Human-readable capsule name.
    pub name: String,
    /// Entry point path; must be present in `payloads`.
    pub entrypoint: String,
    /// Strictly ordered payload descriptors.
    pub payloads: Vec<PayloadDescriptor>,
}

/// Validates a portable capsule path per the upstream rules.
pub fn validate_capsule_path(value: &str) -> Result<(), ScicapError> {
    let invalid = |reason: &str| ScicapError::Invalid(format!("path {value:?}: {reason}"));
    if value.is_empty() {
        return Err(invalid("empty"));
    }
    if value.contains('\\') || value.contains(':') {
        return Err(invalid("backslash and colon are not portable"));
    }
    if value.starts_with('/') || value.starts_with("./") || value.ends_with('/') {
        return Err(invalid("must be relative without leading/trailing slash"));
    }
    for component in value.split('/') {
        match component {
            "" => return Err(invalid("empty component")),
            "." => return Err(invalid("current-directory component")),
            ".." => return Err(invalid("parent-directory component")),
            _ => {}
        }
    }
    Ok(())
}

fn validate_sha256_hex(value: &str) -> Result<(), ScicapError> {
    if value.len() == 64
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && value.chars().all(|c| !c.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ScicapError::Invalid(format!(
            "digest {value:?}: expected exactly 64 lowercase hexadecimal characters"
        )))
    }
}

impl CapsuleManifestV1 {
    /// Parses and validates a manifest from JSON text.
    pub fn parse(text: &str) -> Result<Self, ScicapError> {
        let manifest: Self =
            serde_json::from_str(text).map_err(|e| ScicapError::Invalid(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Applies every structural invariant of the v1 schema.
    pub fn validate(&self) -> Result<(), ScicapError> {
        if self.schema_version != CAPSULE_SCHEMA_VERSION {
            return Err(ScicapError::Invalid(format!(
                "unsupported schema version {} (expected {CAPSULE_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        if self.name.trim().is_empty() {
            return Err(ScicapError::Invalid("name must not be empty".into()));
        }
        if self.payloads.is_empty() {
            return Err(ScicapError::Invalid("payloads must not be empty".into()));
        }
        validate_capsule_path(&self.entrypoint)?;
        for pair in self.payloads.windows(2) {
            match pair[0].path.cmp(&pair[1].path) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(ScicapError::Invalid(format!(
                        "duplicate payload path {}",
                        pair[0].path
                    )))
                }
                std::cmp::Ordering::Greater => {
                    return Err(ScicapError::Invalid(
                        "payloads must be strictly ordered by path".into(),
                    ))
                }
            }
        }
        for p in &self.payloads {
            validate_capsule_path(&p.path)?;
            validate_sha256_hex(&p.sha256)?;
        }
        if !self.payloads.iter().any(|p| p.path == self.entrypoint) {
            return Err(ScicapError::Invalid(format!(
                "entrypoint {:?} is not present in payloads",
                self.entrypoint
            )));
        }
        Ok(())
    }

    /// Verifies every on-disk payload under `bundle_dir` against its
    /// recorded digest and byte length. Returns one result per payload in
    /// manifest order.
    pub fn verify_payloads(&self, bundle_dir: &Path) -> Vec<PayloadResult> {
        self.payloads
            .iter()
            .map(|p| {
                let path = bundle_dir.join(&p.path);
                match std::fs::read(&path) {
                    Err(e) => PayloadResult {
                        path: p.path.clone(),
                        ok: false,
                        detail: format!("unreadable: {e}"),
                    },
                    Ok(bytes) => {
                        if bytes.len() as u64 != p.size_bytes {
                            return PayloadResult {
                                path: p.path.clone(),
                                ok: false,
                                detail: format!(
                                    "size mismatch: manifest {}, on-disk {}",
                                    p.size_bytes,
                                    bytes.len()
                                ),
                            };
                        }
                        let digest = hex::encode(Sha256::digest(&bytes));
                        if digest != p.sha256 {
                            return PayloadResult {
                                path: p.path.clone(),
                                ok: false,
                                detail: format!("digest mismatch: expected {}", p.sha256),
                            };
                        }
                        PayloadResult {
                            path: p.path.clone(),
                            ok: true,
                            detail: format!("{} bytes verified", bytes.len()),
                        }
                    }
                }
            })
            .collect()
    }
}

/// Outcome of verifying a single payload file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadResult {
    /// Payload path.
    pub path: String,
    /// Whether digest and size matched.
    pub ok: bool,
    /// Human detail.
    pub detail: String,
}

#[cfg(test)]
mod tests;
