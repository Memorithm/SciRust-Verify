use super::*;

const SAMPLE_PASS: &str = "\
commit=9301799abc
branch=master
timestamp=2026-08-20T10:00:00Z
packages=90
tests_passed=4210
tests_failed=0
tests_ignored=12
test_groups=88
determinism_tests=104
gate.fmt=PASS (required, 3s)
gate.clippy=PASS (required, 41s)
gate.build=PASS (required, 120s)
gate.test=PASS (required, 310s -- 4210 passed)
gate.simd=PASS (required, 55s)
gate.determinism=PASS (required, 60s)
gate.doc=PASS (required, 33s)
gate.aarch64=SKIP (required, 0s)
gate.deny=PASS (required, 8s)
gate.gpu=SKIP (optional, 0s)
verdict=PASS_WITH_GAPS
";

const SAMPLE_FAIL: &str = "\
commit=?
branch=?
timestamp=2026-08-20T10:00:00Z
packages=90
gate.fmt=FAIL (required, 2s -- formatting drift)
gate.build=PASS (required, 118s)
verdict=FAIL
";

#[test]
fn parses_complete_summary() {
    let s = ProtocolSummary::parse(SAMPLE_PASS).unwrap();
    assert_eq!(s.commit.as_deref(), Some("9301799abc"));
    assert_eq!(s.branch.as_deref(), Some("master"));
    assert_eq!(s.packages, Some(90));
    let tests = s.tests.unwrap();
    assert_eq!(
        (tests.passed, tests.failed, tests.ignored, tests.groups),
        (4210, 0, 12, 88)
    );
    assert_eq!(s.determinism_tests, Some(104));
    assert_eq!(s.verdict, Some(ProtocolVerdict::PassWithGaps));
    assert_eq!(s.gates.len(), 10);

    let det = s.gates.iter().find(|g| g.id == "determinism").unwrap();
    assert_eq!(det.status, GateStatus::Pass);
    assert!(det.required);
    assert_eq!(det.duration_secs, Some(60));

    let aarch = s.gates.iter().find(|g| g.id == "aarch64").unwrap();
    assert_eq!(aarch.status, GateStatus::Skip);
    // A skipped required gate is a gap — never verified.
    assert_eq!(aarch.status.to_verdict(), Verdict::Skipped);

    let gpu = s.gates.iter().find(|g| g.id == "gpu").unwrap();
    assert!(!gpu.required);
}

#[test]
fn parses_failure_and_preserves_note() {
    let s = ProtocolSummary::parse(SAMPLE_FAIL).unwrap();
    assert_eq!(s.verdict, Some(ProtocolVerdict::Fail));
    assert!(s.commit.is_none()); // "?" means unknown, not literal
    let fmt = s.gates.iter().find(|g| g.id == "fmt").unwrap();
    assert_eq!(fmt.status, GateStatus::Fail);
    assert_eq!(fmt.note, "formatting drift");
}

#[test]
fn unknown_keys_are_rejected_not_ignored() {
    let err = ProtocolSummary::parse("schema_version=1\n").unwrap_err();
    assert!(matches!(err, AdapterError::MalformedLine { line: 1, .. }));
    assert!(ProtocolSummary::parse("garbage line\n").is_err());
}

#[test]
fn verdict_mapping_is_bijective_with_source_vocabulary() {
    assert_eq!(
        ProtocolVerdict::Pass.to_dossier_verdict(),
        scirust_verify_model::DossierVerdict::Pass
    );
    assert_eq!(
        ProtocolVerdict::PassWithGaps.to_dossier_verdict(),
        scirust_verify_model::DossierVerdict::PassWithGaps
    );
    assert_eq!(
        ProtocolVerdict::Fail.to_dossier_verdict(),
        scirust_verify_model::DossierVerdict::Fail
    );
    // The dangerous flattening is impossible by construction:
    assert_ne!(GateStatus::Skip.to_verdict(), Verdict::Verified);
}

#[test]
fn claim_map_preserves_gate_semantics() {
    let s = ProtocolSummary::parse(SAMPLE_PASS).unwrap();
    let map = s.claim_map();

    let (fmt_v, fmt_req) = map["fmt_clean"];
    assert_eq!(fmt_v, Verdict::Verified);
    assert!(fmt_req);

    let (gpu_v, gpu_req) = map["cpu_gpu_parity"];
    assert_eq!(gpu_v, Verdict::Skipped); // never claimed without execution
    assert!(!gpu_req);

    // Unknown gates become custom claims named after the gate.
    assert!(map.contains_key("simd"));
    assert!(map.contains_key("aarch64"));

    // build + check both support `builds`; combined verdict stays honest.
    if let Some((v, _)) = map.get("builds") {
        assert_eq!(*v, Verdict::Verified);
    }
}

#[test]
fn failing_gate_fails_the_claim() {
    let s = ProtocolSummary::parse(SAMPLE_FAIL).unwrap();
    let map = s.claim_map();
    assert_eq!(map["fmt_clean"].0, Verdict::Failed);
}

#[test]
fn source_digest_anchors_original_artifact() {
    let d1 = ProtocolSummary::source_digest(SAMPLE_PASS);
    let d2 = ProtocolSummary::source_digest(SAMPLE_PASS);
    let d3 = ProtocolSummary::source_digest(&SAMPLE_PASS.replace("4210", "4211"));
    assert_eq!(d1, d2);
    assert_ne!(d1, d3);
}
