use assert_cmd::Command;

#[test]
fn scicapsule_process_help_exposes_stable_artifact_ports() {
    let output = Command::cargo_bin("scirust-verify-scicapsule")
        .expect("SciCapsule process binary")
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(stdout.contains("--evidence"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("capsule.execute@2.0.0"));
}

#[test]
fn scicapsule_process_refuses_missing_source_artifact() {
    let output = Command::cargo_bin("scirust-verify-scicapsule")
        .expect("SciCapsule process binary")
        .args([
            "--evidence",
            "definitely-missing-scicapsule-evidence.json",
            "--output",
            "definitely-not-created-scicapsule-dossier.tar",
        ])
        .output()
        .expect("run process");
    assert_eq!(output.status.code(), Some(2));
    assert!(!std::path::Path::new("definitely-not-created-scicapsule-dossier.tar").exists());
}
