use assert_cmd::Command;

#[test]
fn forge_soup_process_help_exposes_stable_artifact_ports() {
    let output = Command::cargo_bin("scirust-verify-forge-soup")
        .expect("Forge/SOUP process binary")
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(stdout.contains("--report"));
    assert!(stdout.contains("--evidence-bundle"));
    assert!(stdout.contains("--output"));
}

#[test]
fn forge_soup_process_refuses_missing_source_artifacts() {
    let output = Command::cargo_bin("scirust-verify-forge-soup")
        .expect("Forge/SOUP process binary")
        .args([
            "--report",
            "definitely-missing-report.json",
            "--evidence-bundle",
            "definitely-missing-evidence.tar",
            "--output",
            "definitely-not-created-dossier.tar",
        ])
        .output()
        .expect("run process");
    assert_eq!(output.status.code(), Some(2));
    assert!(!std::path::Path::new("definitely-not-created-dossier.tar").exists());
}
