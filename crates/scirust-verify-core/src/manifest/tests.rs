use super::*;
use std::io::Write;

fn write_manifest(dir: &Path, contents: &str) -> std::path::PathBuf {
    let p = dir.join(MANIFEST_FILE);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    p
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "svm-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const VALID_MINIMAL: &str = r#"
schema_version = 1
"#;

#[test]
fn minimal_manifest_loads() {
    let dir = tmpdir("minimal");
    let m = Manifest::load(&write_manifest(&dir, VALID_MINIMAL)).unwrap();
    assert_eq!(m.schema_version, Some(1));
    assert!(m.cargo.enabled);
    assert_eq!(m.cargo.deny, DenyMode::Optional);
}

#[test]
fn missing_schema_version_is_rejected() {
    let dir = tmpdir("noschema");
    let err = Manifest::load(&write_manifest(
        &dir,
        r#"
[artifact]
name = "x"
"#,
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("missing `schema_version`"),
        "{err}"
    );
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let dir = tmpdir("badschema");
    let err = Manifest::load(&write_manifest(&dir, "schema_version = 99\n")).unwrap_err();
    assert!(err.to_string().contains("unsupported"), "{err}");
}

#[test]
fn unknown_fields_are_rejected() {
    let dir = tmpdir("unknown");
    let err = Manifest::load(&write_manifest(
        &dir,
        "schema_version = 1\nnonsense_section = 3\n",
    ))
    .unwrap_err();
    assert!(matches!(err, ManifestError::Parse { .. }));
}

#[test]
fn invalid_profile_rejected_at_load() {
    let dir = tmpdir("profile");
    let err = Manifest::load(&write_manifest(
        &dir,
        "schema_version = 1\n[verification]\nprofile = \"ultra\"\n",
    ))
    .unwrap_err();
    assert!(err.to_string().contains("unknown verification profile"));
}

#[test]
fn zero_and_negative_style_values_rejected() {
    let dir = tmpdir("zero");
    for toml_text in [
        "schema_version = 1\n[verification]\ntimeout_secs = 0\n",
        "schema_version = 1\n[determinism]\nenabled = true\nruns = 1\nprogram=[\"x\"]\n",
        "schema_version = 1\n[numerics]\nabsolute = -0.5\n",
        "schema_version = 1\n[numerics]\nrelative = \"inf\"\n",
    ] {
        // `relative = inf` parses as string in TOML -> type error; keep only
        // the numeric cases meaningful here.
        if toml_text.contains("\"inf\"") {
            continue;
        }
        let err = Manifest::load(&write_manifest(&dir, toml_text));
        assert!(err.is_err(), "should reject: {toml_text}");
    }
}

#[test]
fn duplicate_custom_check_ids_rejected() {
    let dir = tmpdir("dupes");
    let text = r#"
schema_version = 1

[[custom_checks]]
id = "same"
program = "true"

[[custom_checks]]
id = "same"
program = "true"
"#;
    let err = Manifest::load(&write_manifest(&dir, text)).unwrap_err();
    assert!(err.to_string().contains("duplicate check id"), "{err}");
}

#[test]
fn custom_checks_need_programs() {
    let dir = tmpdir("noprog");
    let text = r#"
schema_version = 1

[[custom_checks]]
id = "no-program"
args = ["a"]
"#;
    let err = Manifest::load(&write_manifest(&dir, text)).unwrap_err();
    assert!(err.to_string().contains("non-empty `program`"), "{err}");
}

#[test]
fn determinism_requires_program_when_enabled() {
    let dir = tmpdir("det");
    let text = "schema_version = 1\n[determinism]\nenabled = true\n";
    let err = Manifest::load(&write_manifest(&dir, text)).unwrap_err();
    assert!(err.to_string().contains("program"), "{err}");
}

#[test]
fn thread_levels_require_env_var() {
    let dir = tmpdir("threads");
    let text = r#"
schema_version = 1
[determinism]
enabled = true
runs = 3
program = ["app"]
thread_levels = [1, 4]
"#;
    let err = Manifest::load(&write_manifest(&dir, text)).unwrap_err();
    assert!(err.to_string().contains("thread_env"), "{err}");
}

#[test]
fn invalid_target_triples_rejected() {
    let dir = tmpdir("targets");
    let text = "schema_version = 1\n[verification]\ntargets = [\"x86_64 unknown\"]\n";
    let err = Manifest::load(&write_manifest(&dir, text)).unwrap_err();
    assert!(err.to_string().contains("invalid target"), "{err}");
}

#[test]
fn claim_levels_validated() {
    let dir = tmpdir("levels");
    let text = "schema_version = 1\n[claims]\nbuilds = \"mandatory\"\n";
    let err = Manifest::load(&write_manifest(&dir, text)).unwrap_err();
    assert!(err.to_string().contains("invalid level"), "{err}");
}
