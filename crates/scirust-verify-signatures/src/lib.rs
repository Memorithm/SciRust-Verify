//! Ed25519 signing and verification for SciRust-Verify evidence bundles.
//!
//! # What is signed
//!
//! The raw bytes of a run's `bundle.json` integrity manifest. Because the
//! manifest already contains SHA-256 digests of every other file in the
//! bundle, a signature over it transitively covers the whole dossier:
//! modifying any sealed file breaks its digest; modifying the manifest
//! itself breaks the signature.
//!
//! # Algorithm, keys and trust semantics
//!
//! * Algorithm: **Ed25519** (RFC 8032) via `ed25519-dalek`.
//! * Key files: 32-byte hex seeds (secret) / 32-byte hex public keys.
//! * Key id: first 16 hex characters of SHA-256 over the public key bytes.
//! * A signature document embeds the public key for self-description. This
//!   does **not** make it trusted: trust comes from comparing the embedded
//!   key id against an expected value distributed out-of-band. Anyone with
//!   the secret key can produce a valid-looking signature; only pinning the
//!   key id makes forgeries detectable.
//! * A digest (SHA-256 of content) is not a signature: it proves content
//!   identity, never authorship.

#![deny(missing_docs)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Signature algorithm identifier used in signature documents.
pub const ALGORITHM: &str = "ed25519";

/// File name of the detached signature inside a run directory.
pub const SIGNATURE_FILE: &str = "bundle.sig";

/// The document that `bundle.sig` covers.
pub const SIGNED_DOCUMENT: &str = "bundle.json";

/// Errors from signing/verification.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// I/O failure on a key or signature file.
    #[error("key/signature IO error: {0}")]
    Io(String),
    /// A key file was malformed.
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// The signature did not verify.
    #[error("signature verification failed")]
    VerificationFailed,
    /// The signature document itself is malformed.
    #[error("malformed signature document: {0}")]
    MalformedDocument(String),
}

/// Generates a new Ed25519 keypair from OS randomness.
///
/// Returns `(seed_hex_32_bytes, public_key_hex)` — the seed is the secret
/// material and must be stored with restrictive permissions by the caller.
pub fn generate_keypair() -> Result<(Vec<u8>, String), SignatureError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| SignatureError::Io(format!("OS randomness unavailable: {e}")))?;
    let signing = SigningKey::from_bytes(&seed);
    Ok((
        seed.to_vec(),
        hex::encode(signing.verifying_key().as_bytes()),
    ))
}

/// Derives the stable key id (16 lowercase hex chars) for a public key hex string.
pub fn key_id(public_key_hex: &str) -> Result<String, SignatureError> {
    let bytes = decode_32(public_key_hex).map_err(SignatureError::InvalidKey)?;
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut id = hex::encode(&digest[..8]);
    id.truncate(16);
    Ok(id)
}

fn decode_32(hex_str: &str) -> Result<[u8; 32], String> {
    let trimmed = hex_str.trim();
    let bytes = hex::decode(trimmed).map_err(|e| format!("not valid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Loads a secret key from a hex seed file and returns its public key hex.
pub fn load_secret_key(path: &std::path::Path) -> Result<(SigningKey, String), SignatureError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| SignatureError::Io(format!("{path:?}: {e}")))?;
    let seed = decode_32(&text).map_err(SignatureError::InvalidKey)?;
    let signing = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing.verifying_key().as_bytes());
    Ok((signing, public_key))
}

/// Loads a public key from a hex file.
pub fn load_public_key(path: &std::path::Path) -> Result<String, SignatureError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| SignatureError::Io(format!("{path:?}: {e}")))?;
    let bytes = decode_32(&text).map_err(SignatureError::InvalidKey)?;
    // Normalize through dalek so malformed points are rejected here.
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| SignatureError::InvalidKey(format!("not a valid Ed25519 public key: {e}")))?;
    Ok(hex::encode(bytes))
}

/// The persisted `bundle.sig` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDocument {
    /// Schema version.
    pub schema_version: u64,
    /// Always `ed25519` in this version.
    pub algorithm: String,
    /// First 16 hex chars of SHA-256(public key).
    pub key_id: String,
    /// Public key (self-describing; trust via pinned key id out-of-band).
    pub public_key: String,
    /// Hex-encoded Ed25519 signature over the exact `bundle.json` bytes.
    pub signature: String,
    /// Which document was signed (always `bundle.json`).
    pub signed_document: String,
    /// UTC creation instant (RFC 3339).
    pub created_at_utc: String,
    /// Tool identity that produced the signature.
    pub tool_version: String,
}

impl SignatureDocument {
    /// Signs `manifest_bytes` with the key at `secret_path`.
    pub fn create(
        secret_path: &std::path::Path,
        manifest_bytes: &[u8],
    ) -> Result<Self, SignatureError> {
        let (signing, public_key) = load_secret_key(secret_path)?;
        let signature = signing.sign(manifest_bytes);
        Ok(Self {
            schema_version: scirust_verify_model::SCHEMA_VERSION,
            algorithm: ALGORITHM.to_owned(),
            key_id: key_id(&public_key)?,
            public_key,
            signature: hex::encode(signature.to_bytes()),
            signed_document: SIGNED_DOCUMENT.to_owned(),
            created_at_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            tool_version: scirust_verify_model::TOOL_IDENTITY.to_owned(),
        })
    }

    /// Parses a signature document from bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, SignatureError> {
        let doc: Self = serde_json::from_slice(bytes)
            .map_err(|e| SignatureError::MalformedDocument(e.to_string()))?;
        if doc.algorithm != ALGORITHM {
            return Err(SignatureError::MalformedDocument(format!(
                "unsupported algorithm `{}`",
                doc.algorithm
            )));
        }
        if doc.signed_document != SIGNED_DOCUMENT {
            return Err(SignatureError::MalformedDocument(format!(
                "signed_document must be `{SIGNED_DOCUMENT}`"
            )));
        }
        Ok(doc)
    }

    /// Cryptographically verifies this document against the given manifest
    /// bytes using the EMBEDDED public key.
    ///
    /// Success means the manifest bytes are authentic **for whoever holds
    /// the matching secret key** — it says nothing about who that is unless
    /// [`Self::key_id`] matches a value you pinned out-of-band.
    pub fn verify_embedded(&self, manifest_bytes: &[u8]) -> Result<(), SignatureError> {
        let key_bytes = decode_32(&self.public_key).map_err(SignatureError::MalformedDocument)?;
        let verifying = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| SignatureError::MalformedDocument(format!("bad public key: {e}")))?;
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| SignatureError::MalformedDocument(format!("bad signature hex: {e}")))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| SignatureError::MalformedDocument(format!("bad signature length: {e}")))?;
        verifying
            .verify(manifest_bytes, &sig)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Verifies and additionally requires the embedded key id to equal
    /// `expected_key_id` (the out-of-band pin).
    pub fn verify_pinned(
        &self,
        manifest_bytes: &[u8],
        expected_key_id: &str,
    ) -> Result<(), SignatureError> {
        if self.key_id != expected_key_id {
            return Err(SignatureError::VerificationFailed);
        }
        self.verify_embedded(manifest_bytes)
    }
}

/// Convenience: signs and serializes the signature document in one call.
pub fn sign_manifest(
    secret_path: &std::path::Path,
    manifest_bytes: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    let doc = SignatureDocument::create(secret_path, manifest_bytes)?;
    serde_json::to_vec_pretty(&doc)
        .map(|mut v| {
            v.extend_from_slice(b"\n");
            v
        })
        .map_err(|e| SignatureError::Io(e.to_string()))
}

#[cfg(test)]
mod tests;
