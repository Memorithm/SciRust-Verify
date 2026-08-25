//! Forge candidate envelope v1: wire-format parsing and fingerprint
//! recomputation.
//!
//! Mirrors `forge-bridge::candidate_envelope::CandidateEnvelopeV1`
//! (Memorithm/forge). The fingerprint binds every field together:
//!
//! ```text
//! "memorithm.candidate-envelope.v1\0"
//! schema_version as u16 LE
//! len-prefixed candidate_id
//! optional producer_candidate_id
//! optional parent_candidate_id
//! 0x01 (origin Forge)
//! len-prefixed domain
//! len-prefixed source_sha256
//! optional proposal_sha256
//! trial_seed as u64 LE
//! ```
//!
//! where a length prefix is `u64 LE` and an optional is `0x01 + prefixed
//! value` or `0x00`.
//!
//! # Trust scope
//!
//! A matching fingerprint proves the *envelope* is internally consistent —
//! it does NOT certify that the candidate is correct. Forge's own evaluation
//! is explicitly not independent verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Schema version supported here.
pub const CANDIDATE_ENVELOPE_SCHEMA_VERSION: u16 = 1;

/// Domain-separation prefix of the canonical byte encoding.
pub const CANONICAL_PREFIX: &[u8] = b"memorithm.candidate-envelope.v1\0";

/// Errors from envelope handling.
#[derive(Debug, Clone, Error)]
pub enum EnvelopeError {
    /// The JSON could not be read.
    #[error("cannot read candidate envelope: {0}")]
    Io(String),
    /// Structural or semantic violation.
    #[error("invalid candidate envelope: {0}")]
    Invalid(String),
    /// The recorded fingerprint does not match the recomputed one.
    #[error("fingerprint mismatch: recorded {recorded}, recomputed {recomputed}")]
    FingerprintMismatch {
        /// Fingerprint value carried by the envelope.
        recorded: String,
        /// Value recomputed from the envelope fields.
        recomputed: String,
    },
}

/// The v1 envelope in wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEnvelopeV1 {
    /// Must be 1.
    pub schema_version: u16,
    /// Recorded fingerprint over the canonical byte encoding.
    pub fingerprint: String,
    /// Always `"forge"` for this envelope version.
    pub origin: String,
    /// Unique candidate identifier.
    pub candidate_id: String,
    /// Producer candidate id when present.
    pub producer_candidate_id: Option<String>,
    /// Parent candidate id when present.
    pub parent_candidate_id: Option<String>,
    /// Execution domain (`low_rank_compression`, `simd_gemm`, ...).
    pub domain: String,
    /// SHA-256 of the candidate source.
    pub source_sha256: String,
    /// Optional proposal digest.
    pub proposal_sha256: Option<String>,
    /// Trial seed, transported as a decimal string to survive JSON f64.
    pub trial_seed: String,
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            out.push(1);
            push_str(out, v);
        }
        None => out.push(0),
    }
}

impl CandidateEnvelopeV1 {
    /// Parses and validates an envelope from its wire JSON.
    pub fn parse(text: &str) -> Result<Self, EnvelopeError> {
        let env: Self =
            serde_json::from_str(text).map_err(|e| EnvelopeError::Invalid(e.to_string()))?;
        env.validate()?;
        Ok(env)
    }

    /// Applies structural rules; does NOT verify the fingerprint.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.schema_version != CANDIDATE_ENVELOPE_SCHEMA_VERSION {
            return Err(EnvelopeError::Invalid(format!(
                "unsupported schema version {}",
                self.schema_version
            )));
        }
        if self.origin != "forge" {
            return Err(EnvelopeError::Invalid(format!(
                "unknown origin `{}` (expected `forge`)",
                self.origin
            )));
        }
        validate_hex64(&self.fingerprint, "fingerprint")?;
        if self.candidate_id.trim().is_empty() {
            return Err(EnvelopeError::Invalid(
                "candidate_id must not be empty".into(),
            ));
        }
        if self.domain.trim().is_empty() {
            return Err(EnvelopeError::Invalid("domain must not be empty".into()));
        }
        validate_hex64(&self.source_sha256, "source_sha256")?;
        validate_optional_hex64(self.proposal_sha256.as_deref(), "proposal_sha256")?;
        for (field, value) in [
            (
                "producer_candidate_id",
                self.producer_candidate_id.as_deref(),
            ),
            ("parent_candidate_id", self.parent_candidate_id.as_deref()),
        ] {
            if let Some(v) = value {
                if v.trim().is_empty() {
                    return Err(EnvelopeError::Invalid(format!("{field} must not be empty")));
                }
            }
        }
        if self.trial_seed.parse::<u64>().is_err() {
            return Err(EnvelopeError::Invalid(
                "trial_seed must be a decimal u64 string".into(),
            ));
        }
        Ok(())
    }

    /// Recomputes the canonical fingerprint bytes per the upstream algorithm.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = CANONICAL_PREFIX.to_vec();
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        push_str(&mut out, &self.candidate_id);
        push_opt_str(&mut out, self.producer_candidate_id.as_deref());
        push_opt_str(&mut out, self.parent_candidate_id.as_deref());
        out.push(1); // CandidateOrigin::Forge
        push_str(&mut out, &self.domain);
        push_str(&mut out, &self.source_sha256);
        push_opt_str(&mut out, self.proposal_sha256.as_deref());
        // The upstream encodes trial_seed from its numeric value; our wire
        // form carries it as a string that must parse (validated above).
        let seed: u64 = self.trial_seed.parse().unwrap_or(0);
        out.extend_from_slice(&seed.to_le_bytes());
        out
    }

    /// Recomputes the fingerprint hex.
    pub fn computed_fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    /// Validates structure AND verifies the recorded fingerprint against the
    /// recomputed one. Returns the recomputed fingerprint on success.
    pub fn verify(&self) -> Result<String, EnvelopeError> {
        self.validate()?;
        let recomputed = self.computed_fingerprint();
        if self.fingerprint != recomputed {
            return Err(EnvelopeError::FingerprintMismatch {
                recorded: self.fingerprint.clone(),
                recomputed,
            });
        }
        Ok(recomputed)
    }
}

fn validate_hex64(value: &str, field: &str) -> Result<(), EnvelopeError> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(EnvelopeError::Invalid(format!(
            "{field} must be exactly 64 hexadecimal characters"
        )))
    }
}

fn validate_optional_hex64(value: Option<&str>, field: &str) -> Result<(), EnvelopeError> {
    match value {
        Some(v) => validate_hex64(v, field),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
