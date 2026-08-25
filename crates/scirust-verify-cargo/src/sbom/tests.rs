use super::*;

const SAMPLE_METADATA: &str = r#"{
  "packages": [
    {
      "name": "my-app",
      "version": "0.1.0",
      "source": null,
      "license": "MIT OR Apache-2.0",
      "manifest_path": "/tmp/my-app/Cargo.toml"
    },
    {
      "name": "serde",
      "version": "1.0.200",
      "source": "registry+https://github.com/rust-lang/crates.io-index",
      "license": null,
      "manifest_path": "/home/u/.cargo/registry/src/serde-1.0.200/Cargo.toml"
    },
    {
      "name": "internal-dep",
      "version": "0.2.0",
      "source": null,
      "license": null,
      "manifest_path": "/tmp/my-app/internal/Cargo.toml"
    }
  ]
}"#;

#[test]
fn spdx_document_is_honest_and_spec_shaped() {
    let doc = from_cargo_metadata(
        SAMPLE_METADATA,
        "my-app",
        "2026-01-01T00:00:00Z",
        "scirust-verify 0.1.0",
    )
    .unwrap();
    assert_eq!(doc.spdx_version, "SPDX-2.3");
    assert_eq!(doc.data_license, "CC0-1.0");
    assert_eq!(doc.packages.len(), 3);

    // Registry package: derivable download location + purl, NOASSERTION license.
    let serde_pkg = doc.packages.iter().find(|p| p.name == "serde").unwrap();
    assert_eq!(
        serde_pkg.download_location,
        "https://crates.io/crates/serde/1.0.200"
    );
    let refs = serde_pkg.external_refs.as_ref().expect("purl for registry");
    assert_eq!(refs[0].reference_locator, "pkg:cargo/serde@1.0.200");
    assert_eq!(serde_pkg.license_declared, NO_ASSERTION);
    assert!(!serde_pkg.files_analyzed);

    // Declared license is carried through when present.
    let app = doc.packages.iter().find(|p| p.name == "my-app").unwrap();
    assert_eq!(app.license_declared, "MIT OR Apache-2.0");
    assert_eq!(app.download_location, NO_ASSERTION);

    // Relationships: document DESCRIBES every package.
    assert_eq!(doc.relationships.len(), 3);
    assert!(doc
        .relationships
        .iter()
        .all(|r| r.relationship_type == "DESCRIBES"));
}

#[test]
fn serialized_output_is_valid_json_with_required_fields() {
    let doc = from_cargo_metadata(SAMPLE_METADATA, "x", "2026-01-01T00:00:00Z", "t").unwrap();
    let text = serde_json::to_string(&doc).unwrap();
    let back: serde_json::Value = serde_json::from_str(&text).unwrap();
    for field in [
        "spdxVersion",
        "dataLicense",
        "SPDXID",
        "name",
        "creationInfo",
        "packages",
        "relationships",
    ] {
        assert!(back.get(field).is_some(), "missing {field}");
    }
}

#[test]
fn garbage_metadata_is_an_error_not_empty_sbom() {
    assert!(from_cargo_metadata("not json", "x", "now", "t").is_err());
    assert!(from_cargo_metadata("{}", "x", "now", "t").is_err());
}
