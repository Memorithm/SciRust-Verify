from pathlib import Path


def replace_once(path: str, old: str, new: str):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "Cargo.toml",
    'rand_core = { version = "0.6", features = ["getrandom"] }\n',
    'rand_core = { version = "0.6", features = ["getrandom"] }\nzeroize = "1"\n',
)
replace_once(
    "crates/scirust-verify-signature/Cargo.toml",
    'rand_core = { workspace = true }\n',
    'rand_core = { workspace = true }\nzeroize = { workspace = true }\n',
)

# Describe the stronger envelope semantics in crate-level docs.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''//! signature binds the exact bytes of `bundle.json` together with the run id.\n//! `bundle.json` already contains SHA-256 digests for every sealed dossier''',
    '''//! signature binds the exact bytes of `bundle.json` together with the versioned\n//! detached-signature metadata (including run id, key identity, signer-reported\n//! time, and producing tool). `bundle.json` already contains SHA-256 digests for every sealed dossier''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''use serde::{Deserialize, Serialize};\nuse thiserror::Error;''',
    '''use serde::{Deserialize, Serialize};\nuse thiserror::Error;\nuse zeroize::Zeroize as _;''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''const SIGNATURE_VERSION: u64 = 1;\nconst CONTEXT: &[u8] = b"SciRust-Verify detached bundle signature v1\\0";''',
    '''const SIGNATURE_VERSION: u64 = 1;\nconst CONTEXT: &[u8] = b"SciRust-Verify detached bundle signature v1\\0";\nconst SIGNED_OBJECT: &str =\n    "versioned detached-signature metadata and exact finalized bundle.json bytes";''',
)
# Reject unknown fields instead of silently accepting unsigned-looking extensions.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\npub struct PublicKeyDocument {''',
    '''#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct PublicKeyDocument {''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''#[derive(Serialize, Deserialize)]\nstruct PrivateKeyDocument {''',
    '''#[derive(Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct PrivateKeyDocument {''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\npub struct SignatureDocument {''',
    '''#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct SignatureDocument {''',
)
# Wipe the heap copy of the encoded private seed on drop.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''struct PrivateKeyDocument {\n    schema_version: u64,\n    algorithm: String,\n    key_id: String,\n    secret_key_hex: String,\n}\n\n/// Detached signature metadata''',
    '''struct PrivateKeyDocument {\n    schema_version: u64,\n    algorithm: String,\n    key_id: String,\n    secret_key_hex: String,\n}\n\nimpl Drop for PrivateKeyDocument {\n    fn drop(&mut self) {\n        self.secret_key_hex.zeroize();\n    }\n}\n\n/// Detached signature metadata''',
)
# Error for the (normally infallible) serialization of the metadata payload.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    /// Run id is not a portable, single filesystem component.\n    #[error("unsafe run id `{0}`")]\n    InvalidRunId(String),\n}''',
    '''    /// Run id is not a portable, single filesystem component.\n    #[error("unsafe run id `{0}`")]\n    InvalidRunId(String),\n    /// Versioned metadata could not be serialized for cryptographic binding.\n    #[error("cannot serialize signed signature metadata: {0}")]\n    SignedMetadataSerialization(String),\n}''',
)
# Zeroize seed copy during key generation.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let public = public_document(&verifying_key);\n    let private = PrivateKeyDocument {\n        schema_version: SCHEMA_VERSION,\n        algorithm: ALGORITHM.to_owned(),\n        key_id: public.key_id.clone(),\n        secret_key_hex: hex::encode(signing_key.to_bytes()),\n    };\n\n    write_private_json(private_path, &private, force)?;''',
    '''    let public = public_document(&verifying_key);\n    let mut seed = signing_key.to_bytes();\n    let private = PrivateKeyDocument {\n        schema_version: SCHEMA_VERSION,\n        algorithm: ALGORITHM.to_owned(),\n        key_id: public.key_id.clone(),\n        secret_key_hex: hex::encode(seed),\n    };\n    seed.zeroize();\n\n    write_private_json(private_path, &private, force)?;''',
)
# Malformed public-key JSON is caller input, not an internal serialization failure.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let bytes = fs::read(path).map_err(|e| SignatureError::io(path, e))?;\n    let doc: PublicKeyDocument =\n        serde_json::from_slice(&bytes).map_err(|e| SignatureError::Json {\n            path: path.to_path_buf(),\n            source: e,\n        })?;''',
    '''    let bytes = fs::read(path).map_err(|e| SignatureError::io(path, e))?;\n    let doc: PublicKeyDocument = serde_json::from_slice(&bytes).map_err(|e| {\n        SignatureError::InvalidKey(format!("cannot decode public-key document: {e}"))\n    })?;''',
)
# Build metadata first, then sign all of it together with the exact bundle bytes.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let bundle = fs::read(bundle_path).map_err(|e| SignatureError::io(bundle_path, e))?;\n    let bundle_digest = Digest::sha256_hex(&bundle).value;\n    let message = signature_message(run_id, &bundle);\n    let signature = signing_key.sign(&message);\n\n    let doc = SignatureDocument {\n        schema_version: SCHEMA_VERSION,\n        signature_version: SIGNATURE_VERSION,\n        algorithm: ALGORITHM.to_owned(),\n        run_id: run_id.to_owned(),\n        signed_object: "exact bytes of finalized bundle.json plus run-id domain binding".to_owned(),\n        bundle_sha256: bundle_digest,\n        key_id: public.key_id.clone(),\n        public_key_fingerprint_sha256: public.fingerprint_sha256,\n        public_key_hex: public.public_key_hex,\n        signature_hex: hex::encode(signature.to_bytes()),\n        signed_at_utc: chrono_now(),\n        signed_by_tool: TOOL_IDENTITY.to_owned(),\n    };''',
    '''    let bundle = fs::read(bundle_path).map_err(|e| SignatureError::io(bundle_path, e))?;\n    let bundle_digest = Digest::sha256_hex(&bundle).value;\n    let mut doc = SignatureDocument {\n        schema_version: SCHEMA_VERSION,\n        signature_version: SIGNATURE_VERSION,\n        algorithm: ALGORITHM.to_owned(),\n        run_id: run_id.to_owned(),\n        signed_object: SIGNED_OBJECT.to_owned(),\n        bundle_sha256: bundle_digest,\n        key_id: public.key_id.clone(),\n        public_key_fingerprint_sha256: public.fingerprint_sha256,\n        public_key_hex: public.public_key_hex,\n        signature_hex: String::new(),\n        signed_at_utc: chrono_now(),\n        signed_by_tool: TOOL_IDENTITY.to_owned(),\n    };\n    let message = signature_message(&doc, &bundle)?;\n    let signature = signing_key.sign(&message);\n    doc.signature_hex = hex::encode(signature.to_bytes());''',
)
# Malformed detached-signature JSON is a failed verification, not infrastructure failure.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let doc: SignatureDocument =\n        serde_json::from_slice(&signature_bytes).map_err(|e| SignatureError::Json {\n            path: signature_path.to_path_buf(),\n            source: e,\n        })?;''',
    '''    let doc: SignatureDocument = serde_json::from_slice(&signature_bytes).map_err(|e| {\n        SignatureError::InvalidSignatureDocument(format!(\n            "cannot decode detached signature: {e}"\n        ))\n    })?;''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    verifying_key\n        .verify_strict(&signature_message(run_id, &bundle), &signature)\n        .map_err(|_| SignatureError::VerificationFailed)?;''',
    '''    verifying_key\n        .verify_strict(&signature_message(&doc, &bundle)?, &signature)\n        .map_err(|_| SignatureError::VerificationFailed)?;''',
)
# Private key decode: classify malformed input and wipe serialized/raw secret copies.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''fn read_private_key(path: &Path) -> Result<SigningKey, SignatureError> {\n    let bytes = fs::read(path).map_err(|e| SignatureError::io(path, e))?;\n    let doc: PrivateKeyDocument =\n        serde_json::from_slice(&bytes).map_err(|e| SignatureError::Json {\n            path: path.to_path_buf(),\n            source: e,\n        })?;''',
    '''fn read_private_key(path: &Path) -> Result<SigningKey, SignatureError> {\n    let mut bytes = fs::read(path).map_err(|e| SignatureError::io(path, e))?;\n    let parsed = serde_json::from_slice(&bytes);\n    bytes.zeroize();\n    let doc: PrivateKeyDocument = parsed.map_err(|e| {\n        SignatureError::InvalidKey(format!("cannot decode private-key document: {e}"))\n    })?;''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let raw = decode_fixed::<32>(&doc.secret_key_hex, "private key")?;\n    let signing = SigningKey::from_bytes(&raw);''',
    '''    let mut raw = decode_fixed::<32>(&doc.secret_key_hex, "private key")?;\n    let signing = SigningKey::from_bytes(&raw);\n    raw.zeroize();''',
)
# Signed-object semantics are fixed and validated.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''        && doc.algorithm == ALGORITHM\n        && !doc.run_id.is_empty()\n        && !doc.key_id.is_empty()''',
    '''        && doc.algorithm == ALGORITHM\n        && doc.signed_object == SIGNED_OBJECT\n        && !doc.run_id.is_empty()\n        && !doc.key_id.is_empty()''',
)
# Signature hex gets a signature-document error, not a key error.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''fn decode_signature(value: &str) -> Result<Signature, SignatureError> {\n    let raw = decode_fixed::<64>(value, "signature")?;\n    Ok(Signature::from_bytes(&raw))\n}''',
    '''fn decode_signature(value: &str) -> Result<Signature, SignatureError> {\n    let bytes = hex::decode(value).map_err(|_| {\n        SignatureError::InvalidSignatureDocument(\n            "signature is not valid hexadecimal".to_owned(),\n        )\n    })?;\n    let raw: [u8; 64] = bytes.try_into().map_err(|_| {\n        SignatureError::InvalidSignatureDocument(\n            "signature must contain exactly 64 bytes".to_owned(),\n        )\n    })?;\n    Ok(Signature::from_bytes(&raw))\n}''',
)
# Zeroize temporary decoded buffers for key material (also harmless for public data).
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''fn decode_fixed<const N: usize>(value: &str, what: &str) -> Result<[u8; N], SignatureError> {\n    let bytes = hex::decode(value)\n        .map_err(|_| SignatureError::InvalidKey(format!("{what} is not valid hexadecimal")))?;\n    bytes\n        .try_into()\n        .map_err(|_| SignatureError::InvalidKey(format!("{what} must contain exactly {N} bytes")))\n}''',
    '''fn decode_fixed<const N: usize>(value: &str, what: &str) -> Result<[u8; N], SignatureError> {\n    let mut bytes = hex::decode(value)\n        .map_err(|_| SignatureError::InvalidKey(format!("{what} is not valid hexadecimal")))?;\n    if bytes.len() != N {\n        bytes.zeroize();\n        return Err(SignatureError::InvalidKey(format!(\n            "{what} must contain exactly {N} bytes"\n        )));\n    }\n    let mut out = [0_u8; N];\n    out.copy_from_slice(&bytes);\n    bytes.zeroize();\n    Ok(out)\n}''',
)
# Replace old message format with a length-delimited, versioned metadata envelope.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''fn signature_message(run_id: &str, bundle: &[u8]) -> Vec<u8> {\n    let mut message = Vec::with_capacity(CONTEXT.len() + run_id.len() + 1 + bundle.len());\n    message.extend_from_slice(CONTEXT);\n    message.extend_from_slice(run_id.as_bytes());\n    message.push(0);\n    message.extend_from_slice(bundle);\n    message\n}''',
    '''#[derive(Serialize)]\nstruct SignedMetadata<'a> {\n    schema_version: u64,\n    signature_version: u64,\n    algorithm: &'a str,\n    run_id: &'a str,\n    signed_object: &'a str,\n    bundle_sha256: &'a str,\n    key_id: &'a str,\n    public_key_fingerprint_sha256: &'a str,\n    public_key_hex: &'a str,\n    signed_at_utc: &'a str,\n    signed_by_tool: &'a str,\n}\n\nfn signature_message(\n    doc: &SignatureDocument,\n    bundle: &[u8],\n) -> Result<Vec<u8>, SignatureError> {\n    let signed = SignedMetadata {\n        schema_version: doc.schema_version,\n        signature_version: doc.signature_version,\n        algorithm: &doc.algorithm,\n        run_id: &doc.run_id,\n        signed_object: &doc.signed_object,\n        bundle_sha256: &doc.bundle_sha256,\n        key_id: &doc.key_id,\n        public_key_fingerprint_sha256: &doc.public_key_fingerprint_sha256,\n        public_key_hex: &doc.public_key_hex,\n        signed_at_utc: &doc.signed_at_utc,\n        signed_by_tool: &doc.signed_by_tool,\n    };\n    let metadata = serde_json::to_vec(&signed)\n        .map_err(|e| SignatureError::SignedMetadataSerialization(e.to_string()))?;\n    let metadata_len = u64::try_from(metadata.len())\n        .map_err(|_| SignatureError::SignedMetadataSerialization("metadata too large".into()))?;\n    let mut message = Vec::with_capacity(CONTEXT.len() + 8 + metadata.len() + bundle.len());\n    message.extend_from_slice(CONTEXT);\n    message.extend_from_slice(&metadata_len.to_be_bytes());\n    message.extend_from_slice(&metadata);\n    message.extend_from_slice(bundle);\n    Ok(message)\n}''',
)
# Zeroize the serialized private-key JSON buffer regardless of write result.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let mut file = options\n        .open(path)\n        .map_err(|e| SignatureError::io(path, e))?;\n    file.write_all(&bytes)\n        .map_err(|e| SignatureError::io(path, e))?;\n    file.sync_all().map_err(|e| SignatureError::io(path, e))?;\n    #[cfg(unix)]\n    {\n        use std::os::unix::fs::PermissionsExt as _;\n        fs::set_permissions(path, fs::Permissions::from_mode(0o600))\n            .map_err(|e| SignatureError::io(path, e))?;\n    }\n    Ok(())\n}\n\nfn chrono_now()''',
    '''    let result = (|| -> Result<(), SignatureError> {\n        let mut file = options\n            .open(path)\n            .map_err(|e| SignatureError::io(path, e))?;\n        file.write_all(&bytes)\n            .map_err(|e| SignatureError::io(path, e))?;\n        file.sync_all().map_err(|e| SignatureError::io(path, e))?;\n        #[cfg(unix)]\n        {\n            use std::os::unix::fs::PermissionsExt as _;\n            fs::set_permissions(path, fs::Permissions::from_mode(0o600))\n                .map_err(|e| SignatureError::io(path, e))?;\n        }\n        Ok(())\n    })();\n    bytes.zeroize();\n    result\n}\n\nfn chrono_now()''',
)
# Add metadata-tamper regression before path tests.
p = Path("crates/scirust-verify-signature/src/lib.rs")
text = p.read_text()
marker = '''    #[test]\n    fn unsafe_run_ids_are_rejected_before_path_construction()'''
if marker not in text:
    raise SystemExit("signature path test marker missing")
new_test = r'''    #[test]
    fn signed_metadata_tampering_invalidates_signature() {
        let dir = temp_dir("metadata-tamper");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{}\n").unwrap();
        generate_keypair(&private, &public, false).unwrap();
        let (_, path) =
            sign_bundle("run-test", &bundle, &private, &dir.join("signatures"), false).unwrap();
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

'''
text = text.replace(marker, new_test + marker, 1)
p.write_text(text)

# New error variant is an internal serialization failure in the CLI exit-code map.
replace_once(
    "crates/scirust-verify-cli/src/signature_cli.rs",
    '''            SignatureError::Io { .. } | SignatureError::Json { .. } => 3,''',
    '''            SignatureError::Io { .. }\n            | SignatureError::Json { .. }\n            | SignatureError::SignedMetadataSerialization(_) => 3,''',
)

# Documentation: metadata binding + unencrypted private-key limitation.
replace_once(
    "docs/SIGNATURES.md",
    '''2. the exact run id,\n3. the exact bytes of the finalized `bundle.json` file.\n\nThis means any change to the integrity manifest, any move to a different run id,''',
    '''2. a length-delimited serialization of all detached signature metadata except the signature bytes themselves (schema/signature versions, algorithm, run id, signed-object semantics, bundle digest, key id/fingerprint/public key, signer-reported time, and producing tool),\n3. the exact bytes of the finalized `bundle.json` file.\n\nThis means metadata cannot be rewritten without invalidating Ed25519. Any change to the integrity manifest, any move to a different run id,''',
)
replace_once(
    "docs/SIGNATURES.md",
    '''The private document contains a randomly generated 32-byte Ed25519 signing seed. On Unix, SciRust-Verify creates the private-key file with mode `0600`. Existing files are not overwritten unless `--force` is supplied. Symbolic-link outputs are rejected.\n\nSciRust-Verify never prints the private key material.''',
    '''The private document contains a randomly generated 32-byte Ed25519 signing seed. On Unix, SciRust-Verify creates the private-key file with mode `0600`. Existing files are not overwritten unless `--force` is supplied. Symbolic-link outputs are rejected.\n\n**V0.2 private-key files are not encrypted at rest.** Mode `0600` reduces accidental local disclosure on Unix but is not a substitute for encrypted storage, OS keyrings, HSMs, or hardware-backed signing. SciRust-Verify zeroizes its explicit transient seed/JSON buffers where practical, but cannot promise elimination of every compiler/runtime copy.\n\nSciRust-Verify never prints the private key material.''',
)
replace_once(
    "docs/SIGNATURES.md",
    '''The signature metadata records the SHA-256 of `bundle.json` for diagnostics and indexing, but the Ed25519 signature is over the full domain-separated message containing the exact manifest bytes.''',
    '''The signature metadata records the SHA-256 of `bundle.json` for diagnostics and indexing. All detached metadata fields except `signature_hex` are themselves cryptographically bound, and the Ed25519 signature also covers the exact manifest bytes.''',
)

print("signature metadata and secret-buffer hardening applied")
