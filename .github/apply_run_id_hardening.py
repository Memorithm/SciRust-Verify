from pathlib import Path


def replace_once(path: str, old: str, new: str):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


# Harden every store access by run id, including legacy report/replay/diff paths.
replace_once(
    "crates/scirust-verify-store/src/lib.rs",
    '''    /// The requested run does not exist.\n    #[error("run `{0}` not found")]\n    NotFound(String),\n}''',
    '''    /// The requested run does not exist.\n    #[error("run `{0}` not found")]\n    NotFound(String),\n    /// Run id is not a portable, single filesystem component.\n    #[error("unsafe run id `{0}`: expected 1-128 ASCII letters, digits, '.', '_' or '-'")]\n    InvalidRunId(String),\n}''',
)
replace_once(
    "crates/scirust-verify-store/src/lib.rs",
    '''    pub fn create_run_with_id(&self, run_id: RunId) -> Result<RunStore, StoreError> {\n        let run_dir = self.0.join(run_id.as_str());''',
    '''    pub fn create_run_with_id(&self, run_id: RunId) -> Result<RunStore, StoreError> {\n        validate_run_id(run_id.as_str())?;\n        let run_dir = self.0.join(run_id.as_str());''',
)
replace_once(
    "crates/scirust-verify-store/src/lib.rs",
    '''    pub fn open(&self, run_id: &str) -> Result<RunStore, StoreError> {\n        let run_dir = self.0.join(run_id);''',
    '''    pub fn open(&self, run_id: &str) -> Result<RunStore, StoreError> {\n        validate_run_id(run_id)?;\n        let run_dir = self.0.join(run_id);''',
)
replace_once(
    "crates/scirust-verify-store/src/lib.rs",
    '''/// Rejects absolute paths and traversal outside the run directory.\npub(crate) fn sanitize_attachment_path''',
    '''fn validate_run_id(run_id: &str) -> Result<(), StoreError> {\n    let valid = !run_id.is_empty()\n        && run_id.len() <= 128\n        && run_id != "."\n        && run_id != ".."\n        && run_id\n            .bytes()\n            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));\n    if !valid {\n        return Err(StoreError::InvalidRunId(run_id.to_owned()));\n    }\n    Ok(())\n}\n\n/// Rejects absolute paths and traversal outside the run directory.\npub(crate) fn sanitize_attachment_path''',
)

# Tests for store-wide traversal rejection.
p = Path("crates/scirust-verify-store/tests/store_tests.rs")
text = p.read_text()
text = text.replace(
    '    Claim, ClaimKind, Evidence, EvidenceKind, RequirementLevel, SourceIdentity, Verdict,\n',
    '    Claim, ClaimKind, Evidence, EvidenceKind, RequirementLevel, RunId, SourceIdentity, Verdict,\n',
    1,
)
marker = '\nfn sample_artifact() -> Artifact {'
if marker not in text:
    raise SystemExit("store test marker missing")
new_test = r'''

#[test]
fn run_ids_are_portable_single_path_components() {
    let root = tmp_root("run-id-safety");
    let runs = RunsRoot::new(root.join("runs"));
    for bad in [
        "",
        ".",
        "..",
        "../escape",
        "..\\escape",
        "/absolute",
        "run/child",
        "run\\child",
        "run:drive",
        "white space",
    ] {
        assert!(matches!(runs.open(bad), Err(StoreError::InvalidRunId(_))), "{bad:?}");
        assert!(matches!(
            runs.create_run_with_id(RunId::from_string(bad)),
            Err(StoreError::InvalidRunId(_))
        ), "{bad:?}");
    }

    let good = RunId::from_string("run-20260825T184500Z-deadbeef");
    let store = runs.create_run_with_id(good.clone()).unwrap();
    assert_eq!(store.run_id(), &good);
    assert!(runs.open(good.as_str()).is_ok());
    let _ = std::fs::remove_dir_all(root);
}
'''
text = text.replace(marker, new_test + marker, 1)
p.write_text(text)

# Signature layer independently rejects unsafe ids because it is a public library API.
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    /// Ed25519 verification rejected the signature.\n    #[error("Ed25519 signature verification failed")]\n    VerificationFailed,\n}''',
    '''    /// Ed25519 verification rejected the signature.\n    #[error("Ed25519 signature verification failed")]\n    VerificationFailed,\n    /// Run id is not a portable, single filesystem component.\n    #[error("unsafe run id `{0}`")]\n    InvalidRunId(String),\n}''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''                | Self::BundleDigestMismatch { .. }\n                | Self::VerificationFailed\n''',
    '''                | Self::BundleDigestMismatch { .. }\n                | Self::VerificationFailed\n                | Self::InvalidRunId(_)\n''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''pub fn sign_bundle(\n    run_id: &str,\n    bundle_path: &Path,\n    private_key_path: &Path,\n    signatures_root: &Path,\n    force: bool,\n) -> Result<(SignatureDocument, PathBuf), SignatureError> {\n    let signing_key = read_private_key(private_key_path)?;''',
    '''pub fn sign_bundle(\n    run_id: &str,\n    bundle_path: &Path,\n    private_key_path: &Path,\n    signatures_root: &Path,\n    force: bool,\n) -> Result<(SignatureDocument, PathBuf), SignatureError> {\n    validate_run_id(run_id)?;\n    let signing_key = read_private_key(private_key_path)?;''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''    let path = signature_path(signatures_root, run_id, &doc.key_id);\n    preflight_output(&path, force)?;''',
    '''    let path = signature_path(signatures_root, run_id, &doc.key_id)?;\n    preflight_output(&path, force)?;''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''/// Compute the canonical detached-signature path for a run and key id.\npub fn signature_path(signatures_root: &Path, run_id: &str, key_id: &str) -> PathBuf {\n    signatures_root.join(run_id).join(format!("{key_id}.json"))\n}''',
    '''/// Compute the canonical detached-signature path for a run and key id.\n///\n/// The run id must be a portable single path component; traversal and platform\n/// separator forms are rejected rather than normalized.\npub fn signature_path(\n    signatures_root: &Path,\n    run_id: &str,\n    key_id: &str,\n) -> Result<PathBuf, SignatureError> {\n    validate_run_id(run_id)?;\n    Ok(signatures_root.join(run_id).join(format!("{key_id}.json")))\n}''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    ''') -> Result<SignatureVerification, SignatureError> {\n    let bundle = fs::read(bundle_path).map_err(|e| SignatureError::io(bundle_path, e))?;''',
    ''') -> Result<SignatureVerification, SignatureError> {\n    validate_run_id(run_id)?;\n    let bundle = fs::read(bundle_path).map_err(|e| SignatureError::io(bundle_path, e))?;''',
)
replace_once(
    "crates/scirust-verify-signature/src/lib.rs",
    '''fn signature_message(run_id: &str, bundle: &[u8]) -> Vec<u8> {''',
    '''fn validate_run_id(run_id: &str) -> Result<(), SignatureError> {\n    let valid = !run_id.is_empty()\n        && run_id.len() <= 128\n        && run_id != "."\n        && run_id != ".."\n        && run_id\n            .bytes()\n            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));\n    if !valid {\n        return Err(SignatureError::InvalidRunId(run_id.to_owned()));\n    }\n    Ok(())\n}\n\nfn signature_message(run_id: &str, bundle: &[u8]) -> Vec<u8> {''',
)
# Add a direct public API regression to the signature crate.
p = Path("crates/scirust-verify-signature/src/lib.rs")
text = p.read_text()
marker = '''    #[cfg(unix)]\n    #[test]\n    fn private_key_is_mode_0600()'''
if marker not in text:
    raise SystemExit("signature test marker missing")
new_test = r'''    #[test]
    fn unsafe_run_ids_are_rejected_before_path_construction() {
        let dir = temp_dir("unsafe-run-id");
        let private = dir.join("private.json");
        let public = dir.join("public.json");
        let bundle = dir.join("bundle.json");
        fs::write(&bundle, b"{}\n").unwrap();
        generate_keypair(&private, &public, false).unwrap();
        for bad in ["../escape", "..\\escape", "/absolute", "run/child", "run:drive"] {
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

'''
text = text.replace(marker, new_test + marker, 1)
p.write_text(text)

# CLI adapts to signature_path now returning Result and classifies unsafe ids as verification failure.
replace_once(
    "crates/scirust-verify-cli/src/signature_cli.rs",
    '''    let signature =\n        signature.unwrap_or_else(|| signature_path(&signatures_root, run, &public.key_id));''',
    '''    let signature = match signature {\n        Some(path) => path,\n        None => signature_path(&signatures_root, run, &public.key_id)\n            .map_err(|e| map_signature_error(e, true))?,\n    };''',
)
replace_once(
    "crates/scirust-verify-cli/src/signature_cli.rs",
    '''            | SignatureError::PublicKeyMismatch { .. } => 1,\n            SignatureError::InvalidKey(_)''',
    '''            | SignatureError::PublicKeyMismatch { .. }\n            | SignatureError::InvalidRunId(_) => 1,\n            SignatureError::InvalidKey(_)''',
)

print("run-id path hardening applied")
