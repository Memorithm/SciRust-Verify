use assert_cmd::Command;

#[test]
fn nnis_parity_process_help_exposes_stable_artifact_ports() {
    let output = Command::cargo_bin("scirust-verify-nnis-parity")
        .expect("NNIS parity process binary")
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(stdout.contains("--parity-evidence"));
    assert!(stdout.contains("--validation"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("nnis.nnml1.parity-validation@1.0.0"));
}

#[test]
fn nnis_parity_process_refuses_missing_source_artifacts() {
    let output = Command::cargo_bin("scirust-verify-nnis-parity")
        .expect("NNIS parity process binary")
        .args([
            "--parity-evidence",
            "definitely-missing-nnis-parity.json",
            "--validation",
            "definitely-missing-nnis-validation.json",
            "--output",
            "definitely-not-created-nnis-dossier.tar",
        ])
        .output()
        .expect("run process");
    assert_eq!(output.status.code(), Some(2));
    assert!(!std::path::Path::new("definitely-not-created-nnis-dossier.tar").exists());
}
