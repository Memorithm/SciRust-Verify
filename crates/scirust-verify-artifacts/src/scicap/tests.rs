use super::*;

fn valid_manifest_json() -> String {
    // Payloads sorted by path; entrypoint present.
    r#"{
  "schema_version": 1,
  "name": "demo-capsule",
  "entrypoint": "bin/run",
  "payloads": [
    {"path": "README.md", "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", "size_bytes": 11},
    {"path": "bin/run", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size_bytes": 4}
  ]
}"#
    .to_owned()
}

#[test]
fn valid_manifest_parses_and_validates() {
    let m = CapsuleManifestV1::parse(&valid_manifest_json()).unwrap();
    assert_eq!(m.name, "demo-capsule");
    assert_eq!(m.payloads.len(), 2);
    m.validate().unwrap();
}

#[test]
fn schema_version_is_strict() {
    let json = valid_manifest_json().replace("\"schema_version\": 1", "\"schema_version\": 2");
    let err = CapsuleManifestV1::parse(&json).unwrap_err();
    assert!(
        err.to_string().contains("unsupported schema version"),
        "{err}"
    );
}

#[test]
fn unsorted_payloads_rejected() {
    let json = r#"{
      "schema_version": 1,
      "name": "x",
      "entrypoint": "z",
      "payloads": [
        {"path": "zeta", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size_bytes": 1},
        {"path": "alpha", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size_bytes": 1}
      ]
    }"#;
    let err = CapsuleManifestV1::parse(json).unwrap_err();
    assert!(err.to_string().contains("strictly ordered"), "{err}");
}

#[test]
fn duplicate_paths_rejected() {
    let json = r#"{
      "schema_version": 1,
      "name": "x",
      "entrypoint": "same",
      "payloads": [
        {"path": "same", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size_bytes": 1},
        {"path": "same", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size_bytes": 1}
      ]
    }"#;
    let err = CapsuleManifestV1::parse(json).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
}

#[test]
fn path_rules_match_upstream() {
    for bad in [
        "",
        "/abs",
        "./rel",
        "../up",
        "a/../b",
        "back\\slash",
        "c:/win",
    ] {
        assert!(
            validate_capsule_path(bad).is_err(),
            "path {bad:?} must be rejected"
        );
    }
    for good in ["run", "bin/run", "deep/nested/file.txt"] {
        assert!(
            validate_capsule_path(good).is_ok(),
            "path {good:?} must pass"
        );
    }
}

#[test]
fn entrypoint_must_be_in_payloads() {
    let json =
        valid_manifest_json().replace("\"entrypoint\": \"bin/run\"", "\"entrypoint\": \"missing\"");
    let err = CapsuleManifestV1::parse(&json).unwrap_err();
    assert!(err.to_string().contains("not present in payloads"), "{err}");
}

#[test]
fn digests_must_be_lowercase_hex64() {
    let uppercase = valid_manifest_json().replace("a1b2c3d4", "A1B2C3D4");
    assert!(CapsuleManifestV1::parse(&uppercase).is_err());
    let short = valid_manifest_json().replace(
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "abcd",
    );
    assert!(CapsuleManifestV1::parse(&short).is_err());
}

#[test]
fn payload_integrity_detects_size_and_digest_drift() {
    let dir = std::env::temp_dir().join(format!("svcap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::write(dir.join("README.md"), b"hello world").unwrap();
    std::fs::write(dir.join("bin/run"), b"echo").unwrap();

    use sha2::{Digest as _, Sha256};
    let readme_digest = hex::encode(Sha256::digest(b"hello world"));
    let run_digest = hex::encode(Sha256::digest(b"echo"));
    let manifest = format!(
        r#"{{
          "schema_version": 1,
          "name": "real",
          "entrypoint": "bin/run",
          "payloads": [
            {{"path": "README.md", "sha256": "{readme_digest}", "size_bytes": 11}},
            {{"path": "bin/run", "sha256": "{run_digest}", "size_bytes": 4}}
          ]
        }}"#
    );
    let m = CapsuleManifestV1::parse(&manifest).unwrap();
    let results = m.verify_payloads(&dir);
    assert!(results.iter().all(|r| r.ok), "{results:?}");

    // Size drift detected.
    std::fs::write(dir.join("bin/run"), b"echo!").unwrap();
    let results = m.verify_payloads(&dir);
    assert!(!results[1].ok);
    assert!(results[1].detail.contains("size mismatch"));

    // Digest drift detected.
    std::fs::write(dir.join("bin/run"), b"ecgo").unwrap();
    let results = m.verify_payloads(&dir);
    assert!(results[1].detail.contains("digest mismatch"));
}
