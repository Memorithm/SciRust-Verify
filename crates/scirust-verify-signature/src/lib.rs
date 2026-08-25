//! Detached Ed25519 signatures for finalized SciRust-Verify evidence dossiers.
//!
//! Signatures intentionally live outside the sealed run directory. A
//! signature binds the exact bytes of `bundle.json` together with the versioned
//! detached-signature metadata (including run id, key identity, signer-reported
//! time, and producing tool). `bundle.json` already contains SHA-256 digests for every sealed dossier
//! file, so this preserves the immutable evidence bundle while adding
//! cryptographic authorship of the finalized integrity manifest.
//!
//! A valid signature proves only that the holder of the corresponding private
//! key signed those bytes. It does not establish who controls that key, provide
//! a certificate chain, or provide a trusted timestamp.

#![deny(missing_docs)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand_core::OsRng;
use scirust_verify_model::{digest::Digest, SCHEMA_VERSION, TOOL_IDENTITY};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize as _;

const ALGORITHM: &str = "ed25519";
const SIGNATURE_VERSION: u64 = 1;
const CONTEXT: &[u8] = b"SciRust-Verify detached bundle signature v1\0";
const SIGNED_OBJECT: &str =
    "versioned detached-signature metadata and exact finalized bundle.json bytes";

/// Public-key document written by [`generate_keypair`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyDocument {
    /// Persisted-document schema version.
    pub schema_version: u64,
    /// Signature algorithm. V1 supports only `ed25519`.
    pub algorithm: String,
    /// Stable identifier derived from SHA-256 of the raw public key.
    pub key_id: String,
    /// Full SHA-256 fingerprint of the raw public key bytes.
    pub fingerprint_sha256: String,
    /// Raw 32-byte Ed25519 public key encoded as lowercase hexadecimal.
    pub public_key_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyDocument {
    schema_version: u64,
    algorithm: String,
    key_id: String,
    secret_key_hex: String,
}

impl Drop for PrivateKeyDocument {
    fn drop(&mut self) {
        self.secret_key_hex.zeroize();
    }
}

/// Detached signature metadata stored outside the immutable run directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureDocument {
    /// Persisted-document schema version.
    pub schema_version: u64,
    /// Version of the signature-envelope semantics.
    pub signature_version: u64,
    /// Signature algorithm (`ed25519`).
    pub algorithm: String,
    /// Run id cryptographically bound into the signature message.
    pub run_id: String,
    /// Human-readable description of what was signed.
    pub signed_object: String,
    /// SHA-256 of the exact `bundle.json` bytes, for diagnostics and indexing.
    pub bundle_sha256: String,
    /// Identifier of the signing public key.
    pub key_id: String,
    /// Full public-key fingerprint for explicit key matching.
    pub public_key_fingerprint_sha256: String,
    /// Raw public key embedded for portability, not as an identity trust root.
    pub public_key_hex: String,
    /// Ed25519 signature bytes encoded as lowercase hexadecimal.
    pub signature_hex: String,
    /// Self-reported signing instant in UTC. This is not a trusted timestamp.
    pub signed_at_utc: String,
    /// Tool identity that produced the detached signature metadata.
    pub signed_by_tool: String,
}

/// Successful signature verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerification {
    /// Run id that was verified.
    pub run_id: String,
    /// Verified signing key id.
    pub key_id: String,
    /// SHA-256 of the verified `bundle.json` bytes.
    pub bundle_sha256: String,
    /// Always true when this value is returned.
    pub cryptographically_valid: bool,
    /// Explicit trust limitation for machine and human consumers.
    pub trust_scope: String,
}

/// Signature and key-management errors.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Filesystem operation failed.
    #[error("filesystem error at `{path}`: {source}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        source: std::io::Error,
    },
    /// JSON document could not be decoded or encoded.
    #[error("signature document error at `{path}`: {source}")]
    Json {
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// A key document is malformed or internally inconsistent.
    #[error("invalid key document: {0}")]
    InvalidKey(String),
    /// A signature document is malformed or internally inconsistent.
    #[error("invalid signature document: {0}")]
    InvalidSignatureDocument(String),
    /// A requested output exists and overwrite was not enabled.
    #[error("refusing to overwrite existing path `{0}`")]
    AlreadyExists(PathBuf),
    /// A sensitive output path is a symbolic link and is therefore rejected.
    #[error("refusing to write through symbolic link `{0}`")]
    SymlinkOutput(PathBuf),
    /// The supplied public key does not match the key that authored the signature.
    #[error("supplied public key does not match signature key id `{signature_key_id}`")]
    PublicKeyMismatch {
        /// Key id recorded in the signature document.
        signature_key_id: String,
    },
    /// The current bundle bytes do not match the digest recorded at signing time.
    #[error("bundle digest mismatch: signed {expected}, current {actual}")]
    BundleDigestMismatch {
        /// Digest recorded in the signature document.
        expected: String,
        /// Digest computed from current bundle bytes.
        actual: String,
    },
    /// Ed25519 verification rejected the signature.
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
    /// Run id is not a portable, single filesystem component.
    #[error("unsafe run id `{0}`")]
    InvalidRunId(String),
    /// Versioned metadata could not be serialized for cryptographic binding.
    #[error("cannot serialize signed signature metadata: {0}")]
    SignedMetadataSerialization(String),
}

impl SignatureError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Whether this error means a requested signature verification did not
    /// establish cryptographic validity rather than an infrastructure failure.
    pub fn is_verification_failure(&self) -> bool {
        matches!(
            self,
            Self::InvalidKey(_)
                | Self::InvalidSignatureDocument(_)
                | Self::PublicKeyMismatch { .. }
                | Self::BundleDigestMismatch { .. }
                | Self::VerificationFailed
                | Self::InvalidRunId(_)
        )
    }
}

/// Generate a fresh Ed25519 keypair and persist it as two JSON documents.
///
/// The private key is a 32-byte Ed25519 signing seed encoded as hexadecimal.
/// On Unix it is created with mode `0600`. Existing paths are never replaced
/// unless `force` is true, and symbolic-link outputs are always rejected.
pub fn generate_keypair(
    private_path: &Path,
    public_path: &Path,
    force: bool,
) -> Result<PublicKeyDocument, SignatureError> {
    if private_path == public_path {
        return Err(SignatureError::InvalidKey(
            "private and public key paths must be different".to_owned(),
        ));
    }
    preflight_output(private_path, force)?;
    preflight_output(public_path, force)?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public = public_document(&verifying_key);
    let mut seed = signing_key.to_bytes();
    let private = PrivateKeyDocument {
        schema_version: SCHEMA_VERSION,
        algorithm: ALGORITHM.to_owned(),
        key_id: public.key_id.clone(),
        secret_key_hex: hex::encode(seed),
    };
    seed.zeroize();

    write_private_json(private_path, &private, force)?;
    if let Err(error) = write_public_json(public_path, &public, force) {
        let _ = fs::remove_file(private_path);
        return Err(error);
    }
    Ok(public)
}

/// Load and validate a public-key document.
pub fn read_public_key(path: &Path) -> Result<PublicKeyDocument, SignatureError> {
    let bytes = fs::read(path).map_err(|e| SignatureError::io(path, e))?;
    let doc: PublicKeyDocument = serde_json::from_slice(&bytes).map_err(|e| {
        SignatureError::InvalidKey(format!("cannot decode public-key document: {e}"))
    })?;
    validate_public_document(&doc)?;
    Ok(doc)
}

/// Sign the exact finalized `bundle.json` bytes and write a detached signature.
///
/// The caller is responsible for first checking SciRust-Verify bundle
/// integrity. The generated signature is stored under
/// `<signatures_root>/<run-id>/<key-id>.json`.
pub fn sign_bundle(
    run_id: &str,
    bundle_path: &Path,
    private_key_path: &Path,
    signatures_root: &Path,
    force: bool,
) -> Result<(SignatureDocument, PathBuf), SignatureError> {
    validate_run_id(run_id)?;
    let signing_key = read_private_key(private_key_path)?;
    let public = public_document(&signing_key.verifying_key());
    let bundle = fs::read(bundle_path).map_err(|e| SignatureError::io(bundle_path, e))?;
    let bundle_digest = Digest::sha256_hex(&bundle).value;
    let mut doc = SignatureDocument {
        schema_version: SCHEMA_VERSION,
        signature_version: SIGNATURE_VERSION,
        algorithm: ALGORITHM.to_owned(),
        run_id: run_id.to_owned(),
        signed_object: SIGNED_OBJECT.to_owned(),
        bundle_sha256: bundle_digest,
        key_id: public.key_id.clone(),
        public_key_fingerprint_sha256: public.fingerprint_sha256,
        public_key_hex: public.public_key_hex,
        signature_hex: String::new(),
        signed_at_utc: chrono_now(),
        signed_by_tool: TOOL_IDENTITY.to_owned(),
    };
    let message = signature_message(&doc, &bundle)?;
    let signature = signing_key.sign(&message);
    doc.signature_hex = hex::encode(signature.to_bytes());
    let path = signature_path(signatures_root, run_id, &doc.key_id)?;
    preflight_output(&path, force)?;
    write_public_json(&path, &doc, force)?;
    Ok((doc, path))
}

/// Compute the canonical detached-signature path for a run and key id.
///
/// The run id must be a portable single path component; traversal and platform
/// separator forms are rejected rather than normalized.
pub fn signature_path(
    signatures_root: &Path,
    run_id: &str,
    key_id: &str,
) -> Result<PathBuf, SignatureError> {
    validate_run_id(run_id)?;
    Ok(signatures_root.join(run_id).join(format!("{key_id}.json")))
}

/// Verify a detached signature against an explicit trusted-by-caller public key.
///
/// This verifies cryptographic validity only. The caller remains responsible
/// for deciding whether the supplied public key belongs to an identity it
/// trusts.
pub fn verify_bundle_signature(
    run_id: &str,
    bundle_path: &Path,
    signature_path: &Path,
    public_key_path: &Path,
) -> Result<SignatureVerification, SignatureError> {
    validate_run_id(run_id)?;
    let bundle = fs::read(bundle_path).map_err(|e| SignatureError::io(bundle_path, e))?;
    let signature_bytes =
        fs::read(signature_path).map_err(|e| SignatureError::io(signature_path, e))?;
    let doc: SignatureDocument = serde_json::from_slice(&signature_bytes).map_err(|e| {
        SignatureError::InvalidSignatureDocument(format!("cannot decode detached signature: {e}"))
    })?;
    validate_signature_document(&doc)?;
    if doc.run_id != run_id {
        return Err(SignatureError::InvalidSignatureDocument(format!(
            "signature is for run `{}`, not `{run_id}`",
            doc.run_id
        )));
    }

    let public = read_public_key(public_key_path)?;
    if doc.key_id != public.key_id
        || doc.public_key_hex != public.public_key_hex
        || doc.public_key_fingerprint_sha256 != public.fingerprint_sha256
    {
        return Err(SignatureError::PublicKeyMismatch {
            signature_key_id: doc.key_id,
        });
    }

    let current_digest = Digest::sha256_hex(&bundle).value;
    if current_digest != doc.bundle_sha256 {
        return Err(SignatureError::BundleDigestMismatch {
            expected: doc.bundle_sha256,
            actual: current_digest,
        });
    }

    let verifying_key = verifying_key_from_document(&public)?;
    let signature = decode_signature(&doc.signature_hex)?;
    verifying_key
        .verify_strict(&signature_message(&doc, &bundle)?, &signature)
        .map_err(|_| SignatureError::VerificationFailed)?;

    Ok(SignatureVerification {
        run_id: run_id.to_owned(),
        key_id: public.key_id,
        bundle_sha256: current_digest,
        cryptographically_valid: true,
        trust_scope: "valid under the explicitly supplied Ed25519 public key; signer identity, key provenance, revocation, and trusted timestamping are outside this verification".to_owned(),
    })
}

fn read_private_key(path: &Path) -> Result<SigningKey, SignatureError> {
    let mut bytes = fs::read(path).map_err(|e| SignatureError::io(path, e))?;
    let parsed = serde_json::from_slice(&bytes);
    bytes.zeroize();
    let doc: PrivateKeyDocument = parsed.map_err(|e| {
        SignatureError::InvalidKey(format!("cannot decode private-key document: {e}"))
    })?;
    if doc.schema_version > SCHEMA_VERSION || doc.algorithm != ALGORITHM {
        return Err(SignatureError::InvalidKey(
            "unsupported private-key schema or algorithm".to_owned(),
        ));
    }
    let mut raw = decode_fixed::<32>(&doc.secret_key_hex, "private key")?;
    let signing = SigningKey::from_bytes(&raw);
    raw.zeroize();
    let public = public_document(&signing.verifying_key());
    if doc.key_id != public.key_id {
        return Err(SignatureError::InvalidKey(
            "private-key key_id does not match its derived public key".to_owned(),
        ));
    }
    Ok(signing)
}

fn public_document(key: &VerifyingKey) -> PublicKeyDocument {
    let bytes = key.to_bytes();
    let fingerprint = Digest::sha256_hex(&bytes).value;
    PublicKeyDocument {
        schema_version: SCHEMA_VERSION,
        algorithm: ALGORITHM.to_owned(),
        key_id: format!("ed25519-{}", &fingerprint[..24]),
        fingerprint_sha256: fingerprint,
        public_key_hex: hex::encode(bytes),
    }
}

fn validate_public_document(doc: &PublicKeyDocument) -> Result<(), SignatureError> {
    if doc.schema_version > SCHEMA_VERSION || doc.algorithm != ALGORITHM {
        return Err(SignatureError::InvalidKey(
            "unsupported public-key schema or algorithm".to_owned(),
        ));
    }
    let key = verifying_key_from_document(doc)?;
    let expected = public_document(&key);
    if *doc != expected {
        return Err(SignatureError::InvalidKey(
            "public-key fingerprint or key_id is inconsistent with key bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validating_signature_fields(doc: &SignatureDocument) -> bool {
    doc.schema_version <= SCHEMA_VERSION
        && doc.signature_version == SIGNATURE_VERSION
        && doc.algorithm == ALGORITHM
        && doc.signed_object == SIGNED_OBJECT
        && !doc.run_id.is_empty()
        && !doc.key_id.is_empty()
}

fn validate_signature_document(doc: &SignatureDocument) -> Result<(), SignatureError> {
    if !validating_signature_fields(doc) {
        return Err(SignatureError::InvalidSignatureDocument(
            "unsupported schema, algorithm, or empty identity fields".to_owned(),
        ));
    }
    let public = PublicKeyDocument {
        schema_version: doc.schema_version,
        algorithm: doc.algorithm.clone(),
        key_id: doc.key_id.clone(),
        fingerprint_sha256: doc.public_key_fingerprint_sha256.clone(),
        public_key_hex: doc.public_key_hex.clone(),
    };
    validate_public_document(&public)?;
    let _ = decode_signature(&doc.signature_hex)?;
    if doc.bundle_sha256.len() != 64 || !doc.bundle_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SignatureError::InvalidSignatureDocument(
            "bundle_sha256 must be 32-byte hexadecimal".to_owned(),
        ));
    }
    Ok(())
}

fn verifying_key_from_document(doc: &PublicKeyDocument) -> Result<VerifyingKey, SignatureError> {
    let raw = decode_fixed::<32>(&doc.public_key_hex, "public key")?;
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| SignatureError::InvalidKey("invalid Ed25519 public key bytes".to_owned()))
}

fn decode_signature(value: &str) -> Result<Signature, SignatureError> {
    let bytes = hex::decode(value).map_err(|_| {
        SignatureError::InvalidSignatureDocument("signature is not valid hexadecimal".to_owned())
    })?;
    let raw: [u8; 64] = bytes.try_into().map_err(|_| {
        SignatureError::InvalidSignatureDocument(
            "signature must contain exactly 64 bytes".to_owned(),
        )
    })?;
    Ok(Signature::from_bytes(&raw))
}

fn decode_fixed<const N: usize>(value: &str, what: &str) -> Result<[u8; N], SignatureError> {
    let mut bytes = hex::decode(value)
        .map_err(|_| SignatureError::InvalidKey(format!("{what} is not valid hexadecimal")))?;
    if bytes.len() != N {
        bytes.zeroize();
        return Err(SignatureError::InvalidKey(format!(
            "{what} must contain exactly {N} bytes"
        )));
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

fn validate_run_id(run_id: &str) -> Result<(), SignatureError> {
    let valid = !run_id.is_empty()
        && run_id.len() <= 128
        && run_id != "."
        && run_id != ".."
        && run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !valid {
        return Err(SignatureError::InvalidRunId(run_id.to_owned()));
    }
    Ok(())
}

#[derive(Serialize)]
struct SignedMetadata<'a> {
    schema_version: u64,
    signature_version: u64,
    algorithm: &'a str,
    run_id: &'a str,
    signed_object: &'a str,
    bundle_sha256: &'a str,
    key_id: &'a str,
    public_key_fingerprint_sha256: &'a str,
    public_key_hex: &'a str,
    signed_at_utc: &'a str,
    signed_by_tool: &'a str,
}

fn signature_message(doc: &SignatureDocument, bundle: &[u8]) -> Result<Vec<u8>, SignatureError> {
    let signed = SignedMetadata {
        schema_version: doc.schema_version,
        signature_version: doc.signature_version,
        algorithm: &doc.algorithm,
        run_id: &doc.run_id,
        signed_object: &doc.signed_object,
        bundle_sha256: &doc.bundle_sha256,
        key_id: &doc.key_id,
        public_key_fingerprint_sha256: &doc.public_key_fingerprint_sha256,
        public_key_hex: &doc.public_key_hex,
        signed_at_utc: &doc.signed_at_utc,
        signed_by_tool: &doc.signed_by_tool,
    };
    let metadata = serde_json::to_vec(&signed)
        .map_err(|e| SignatureError::SignedMetadataSerialization(e.to_string()))?;
    let metadata_len = u64::try_from(metadata.len())
        .map_err(|_| SignatureError::SignedMetadataSerialization("metadata too large".into()))?;
    let mut message = Vec::with_capacity(CONTEXT.len() + 8 + metadata.len() + bundle.len());
    message.extend_from_slice(CONTEXT);
    message.extend_from_slice(&metadata_len.to_be_bytes());
    message.extend_from_slice(&metadata);
    message.extend_from_slice(bundle);
    Ok(message)
}

fn preflight_output(path: &Path, force: bool) -> Result<(), SignatureError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(SignatureError::SymlinkOutput(path.to_path_buf()));
            }
            if !force {
                return Err(SignatureError::AlreadyExists(path.to_path_buf()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(SignatureError::io(path, error)),
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SignatureError::io(parent, e))?;
    }
    Ok(())
}

fn write_public_json<T: Serialize>(
    path: &Path,
    value: &T,
    force: bool,
) -> Result<(), SignatureError> {
    preflight_output(path, force)?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| SignatureError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    bytes.push(b'\n');
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|e| SignatureError::io(path, e))?;
    file.write_all(&bytes)
        .map_err(|e| SignatureError::io(path, e))?;
    file.sync_all().map_err(|e| SignatureError::io(path, e))
}

fn write_private_json<T: Serialize>(
    path: &Path,
    value: &T,
    force: bool,
) -> Result<(), SignatureError> {
    preflight_output(path, force)?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| SignatureError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    bytes.push(b'\n');

    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| -> Result<(), SignatureError> {
        let mut file = options
            .open(path)
            .map_err(|e| SignatureError::io(path, e))?;
        file.write_all(&bytes)
            .map_err(|e| SignatureError::io(path, e))?;
        file.sync_all().map_err(|e| SignatureError::io(path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| SignatureError::io(path, e))?;
        }
        Ok(())
    })();
    bytes.zeroize();
    result
}

fn chrono_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sve-signature-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let dir = temp_dir("roundtrip");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{\"schema_version\":1}\n").unwrap();
        let pub_doc = generate_keypair(&private, &public, false).unwrap();
        let signatures = dir.join("signatures");
        let (signature, path) =
            sign_bundle("run-test", &bundle, &private, &signatures, false).unwrap();
        assert_eq!(signature.key_id, pub_doc.key_id);
        let verified = verify_bundle_signature("run-test", &bundle, &path, &public).unwrap();
        assert!(verified.cryptographically_valid);

        fs::write(&bundle, b"{\"schema_version\":2}\n").unwrap();
        assert!(matches!(
            verify_bundle_signature("run-test", &bundle, &path, &public),
            Err(SignatureError::BundleDigestMismatch { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let dir = temp_dir("wrong-key");
        let private_a = dir.join("a-private.json");
        let public_a = dir.join("a-public.json");
        let private_b = dir.join("b-private.json");
        let public_b = dir.join("b-public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{}\n").unwrap();
        generate_keypair(&private_a, &public_a, false).unwrap();
        generate_keypair(&private_b, &public_b, false).unwrap();
        let (_, path) = sign_bundle(
            "run-test",
            &bundle,
            &private_a,
            &dir.join("signatures"),
            false,
        )
        .unwrap();
        assert!(matches!(
            verify_bundle_signature("run-test", &bundle, &path, &public_b),
            Err(SignatureError::PublicKeyMismatch { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn run_id_is_cryptographically_bound() {
        let dir = temp_dir("run-id");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{}\n").unwrap();
        generate_keypair(&private, &public, false).unwrap();
        let (_, path) =
            sign_bundle("run-a", &bundle, &private, &dir.join("signatures"), false).unwrap();
        assert!(verify_bundle_signature("run-b", &bundle, &path, &public).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_metadata_tampering_invalidates_signature() {
        let dir = temp_dir("metadata-tamper");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{}\n").unwrap();
        generate_keypair(&private, &public, false).unwrap();
        let (_, path) = sign_bundle(
            "run-test",
            &bundle,
            &private,
            &dir.join("signatures"),
            false,
        )
        .unwrap();
        let bytes = fs::read(&path).unwrap();
        let mut doc: SignatureDocument = serde_json::from_slice(&bytes).unwrap();
        doc.signed_at_utc = "2099-01-01T00:00:00Z".to_owned();
        let mut replacement = serde_json::to_vec_pretty(&doc).unwrap();
        replacement.push(b'\n');
        fs::write(&path, replacement).unwrap();
        assert!(matches!(
            verify_bundle_signature("run-test", &bundle, &path, &public),
            Err(SignatureError::VerificationFailed)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unsafe_run_ids_are_rejected_before_path_construction() {
        let dir = temp_dir("unsafe-run-id");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{}\n").unwrap();
        generate_keypair(&private, &public, false).unwrap();
        for bad in [
            "../escape",
            "..\\escape",
            "/absolute",
            "run/child",
            "run:drive",
        ] {
            assert!(matches!(
                sign_bundle(bad, &bundle, &private, &dir.join("signatures"), false),
                Err(SignatureError::InvalidRunId(_))
            ));
            assert!(matches!(
                signature_path(&dir.join("signatures"), bad, "ed25519-deadbeef"),
                Err(SignatureError::InvalidRunId(_))
            ));
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("permissions");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        generate_keypair(&private, &public, false).unwrap();
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn output_overwrite_requires_force() {
        let dir = temp_dir("overwrite");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        generate_keypair(&private, &public, false).unwrap();
        assert!(matches!(
            generate_keypair(&private, &public, false),
            Err(SignatureError::AlreadyExists(_))
        ));
        generate_keypair(&private, &public, true).unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
