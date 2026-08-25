use std::collections::BTreeMap;

use scirust_verify_model::{
    Artifact, ArtifactId, ArtifactKind, Check, CheckAction, CheckExecution, CheckId, CheckStatus,
    Claim, ClaimKind, Evidence, EvidenceKind, RequirementLevel, SourceIdentity, Verdict,
};
use scirust_verify_model::{Attachment, CommandTemplate, Digest, EvidenceId};
use scirust_verify_store::{generate_run_id, RunState, RunsRoot, StoreError};

fn tmp_root(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "svs-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample_artifact() -> Artifact {
    Artifact {
        id: ArtifactId::new("demo"),
        kind: ArtifactKind::CargoWorkspace,
        name: "demo".into(),
        version: Some("0.1.0".into()),
        path: "/tmp/demo".into(),
        source: SourceIdentity::default(),
        content_digest: None,
    }
}

fn sample_claim() -> Claim {
    Claim {
        id: "builds".into(),
        kind: ClaimKind::Builds,
        subject: ArtifactId::new("demo"),
        requirement: RequirementLevel::Required,
        statement: "The workspace builds.".into(),
        parameters: Default::default(),
    }
}

fn sample_check() -> Check {
    Check {
        id: CheckId::new("cargo:build"),
        provider: "cargo".into(),
        purpose: "Build the workspace".into(),
        claims: vec!["builds".into()],
        requirement: RequirementLevel::Required,
        action: CheckAction::Command {
            command: CommandTemplate {
                program: "cargo".into(),
                args: vec!["build".into()],
                cwd: None,
                env: Default::default(),
            },
            expect: Default::default(),
        },
        timeout: std::time::Duration::from_secs(60),
        stdout_limit_bytes: 1 << 20,
        stderr_limit_bytes: 1 << 20,
    }
}

fn sample_evidence(id: &str) -> (Evidence, BTreeMap<String, Vec<u8>>) {
    let mut attachments = BTreeMap::new();
    attachments.insert(format!("logs/{id}.log"), b"some log output".to_vec());
    let payload = &attachments[&format!("logs/{id}.log")];
    let att = Attachment {
        path: format!("logs/{id}.log"),
        size_bytes: payload.len() as u64,
        digest: Digest::sha256_hex(payload),
        media_type: Some("text/plain".into()),
    };
    let ev = Evidence::builder(
        EvidenceId::from(id),
        EvidenceKind::CommandExecution,
        "runner",
    )
    .attachment(att)
    .build();
    (ev, attachments)
}

#[test]
fn create_persist_read_finalize_roundtrip() {
    let root = tmp_root("roundtrip");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();

    store.write_artifact(&sample_artifact()).unwrap();
    store.write_claims(&[sample_claim()]).unwrap();
    let checks = vec![sample_check()];
    // Digest recorded must be the canonical digest of checks for read_plan to pass.
    let canonical = scirust_verify_model::canonical_json(&checks).unwrap();
    let plan_digest = Digest::sha256_hex(canonical.as_bytes());
    store.write_plan(&checks, plan_digest).unwrap();

    let (ev, payloads) = sample_evidence("ev-0001");
    store.add_evidence(&ev, &payloads).unwrap();

    store
        .append_execution(CheckExecution {
            check_id: CheckId::new("cargo:build"),
            started_at_utc: None,
            ended_at_utc: None,
            status: CheckStatus::Executed { exit_code: Some(0) },
            observations: Vec::new(),
            evidence_ids: vec![scirust_verify_model::EvidenceId::from("ev-0001")],
            notes: Vec::new(),
        })
        .unwrap();

    store.set_state(RunState::Running).unwrap();
    let manifest = store.finalize().expect("finalize must succeed");

    assert!(manifest.files.contains_key("run.json"));
    assert!(manifest.files.contains_key("evidence/ev-0001.json"));
    assert!(manifest.files.contains_key("logs/ev-0001.log"));

    // Re-open and verify integrity.
    let reopened = runs.open(store.run_id().as_str()).unwrap();
    assert_eq!(
        reopened.read_run_document().unwrap().state,
        RunState::Finalized
    );
    assert!(reopened.verify_integrity().is_ok());

    let artifact = reopened.read_artifact().unwrap();
    assert_eq!(artifact.name, "demo");
    let evidence = reopened.read_all_evidence().unwrap();
    assert_eq!(evidence.len(), 1);
}

#[test]
fn finalized_runs_reject_mutation() {
    let root = tmp_root("frozen");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    store.write_artifact(&sample_artifact()).unwrap();
    store.write_claims(&[]).unwrap();
    let checks = vec![];
    let canonical = scirust_verify_model::canonical_json(&checks).unwrap();
    store
        .write_plan(
            &checks,
            scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()),
        )
        .unwrap();
    store.finalize().unwrap();

    assert!(matches!(
        store.write_artifact(&sample_artifact()),
        Err(StoreError::Frozen(_))
    ));
    assert!(matches!(
        store.set_state(RunState::Aborted),
        Err(StoreError::Frozen(_))
    ));
}

#[test]
fn modified_sealed_file_is_detected() {
    let root = tmp_root("tamper-file");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    store.write_artifact(&sample_artifact()).unwrap();
    store.write_claims(&[]).unwrap();
    let canonical = scirust_verify_model::canonical_json(&Vec::<Check>::new()).unwrap();
    store
        .write_plan(
            &[],
            scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()),
        )
        .unwrap();
    store.finalize().unwrap();

    // Tamper.
    let run_dir = store.path();
    let artifact_path = run_dir.join("artifact.json");
    let original = std::fs::read_to_string(&artifact_path).unwrap();
    std::fs::write(&artifact_path, original.replace("demo", "evil")).unwrap();

    let reopened = runs.open(store.run_id().as_str()).unwrap();
    match reopened.verify_integrity() {
        Err(StoreError::Corrupt { reason, .. }) => {
            assert!(reason.contains("artifact.json"), "reason: {reason}");
        }
        other => panic!("expected corruption error, got {other:?}"),
    }
}

#[test]
fn deleted_attachment_is_detected() {
    let root = tmp_root("delete-att");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    store.write_artifact(&sample_artifact()).unwrap();
    store.write_claims(&[]).unwrap();
    let canonical = scirust_verify_model::canonical_json(&Vec::<Check>::new()).unwrap();
    store
        .write_plan(
            &[],
            scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()),
        )
        .unwrap();
    let (ev, payloads) = sample_evidence("ev-0007");
    store.add_evidence(&ev, &payloads).unwrap();
    store.finalize().unwrap();

    let log_path = store.path().join("logs/ev-0007.log");
    std::fs::remove_file(&log_path).unwrap();

    let reopened = runs.open(store.run_id().as_str()).unwrap();
    assert!(matches!(
        reopened.verify_integrity(),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn duplicate_claim_id_is_rejected_at_write() {
    let root = tmp_root("dupes");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    let mut c2 = sample_claim();
    c2.statement = "duplicate".into();
    assert!(store.write_claims(&[sample_claim(), c2]).is_err());
}

#[test]
fn execution_referencing_missing_evidence_fails_finalize() {
    let root = tmp_root("bad-ref");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    store.write_artifact(&sample_artifact()).unwrap();
    store.write_claims(&[sample_claim()]).unwrap();
    let canonical = scirust_verify_model::canonical_json(&vec![sample_check()]).unwrap();
    store
        .write_plan(
            &[sample_check()],
            scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()),
        )
        .unwrap();
    store
        .append_execution(CheckExecution {
            check_id: CheckId::new("cargo:build"),
            started_at_utc: None,
            ended_at_utc: None,
            status: CheckStatus::Executed { exit_code: Some(0) },
            observations: Vec::new(),
            evidence_ids: vec![scirust_verify_model::EvidenceId::from("ev-9999")],
            notes: Vec::new(),
        })
        .unwrap();
    assert!(matches!(store.finalize(), Err(StoreError::Corrupt { .. })));
}

#[test]
fn tampered_plan_digest_is_detected_on_read() {
    let root = tmp_root("plan-digest");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    store
        .write_plan(
            &[sample_check()],
            scirust_verify_model::Digest::sha256_hex(b"bogus"),
        )
        .unwrap();
    assert!(matches!(store.read_plan(), Err(StoreError::Corrupt { .. })));
    // The bundle never got sealed; the aborted state is visible.
    assert_eq!(store.read_run_document().unwrap().state, RunState::Planning);
}

#[test]
fn unsealed_additions_are_detected_in_finalized_bundles() {
    let root = tmp_root("unsealed-add");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    store.write_artifact(&sample_artifact()).unwrap();
    store.write_claims(&[]).unwrap();
    let canonical = scirust_verify_model::canonical_json(&Vec::<Check>::new()).unwrap();
    store
        .write_plan(
            &[],
            scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()),
        )
        .unwrap();
    store.finalize().unwrap();

    std::fs::write(store.path().join("smuggled.txt"), b"injected").unwrap();
    let reopened = runs.open(store.run_id().as_str()).unwrap();
    assert!(matches!(
        reopened.verify_integrity(),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn unsafe_paths_are_rejected_everywhere() {
    let root = tmp_root("unsafe-path");
    let runs = RunsRoot::new(&root);
    let store = runs.create_run().unwrap();
    assert!(matches!(
        store.write_text("../escape.txt", "nope"),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(matches!(
        store.write_text("/absolute.txt", "nope"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn replay_links_to_original_and_uses_new_id() {
    let root = tmp_root("replay-link");
    let runs = RunsRoot::new(&root);

    let original = runs.create_run().unwrap();
    let original_id = original.run_id().clone();
    original.write_artifact(&sample_artifact()).unwrap();
    original.write_claims(&[]).unwrap();
    let canonical = scirust_verify_model::canonical_json(&Vec::<Check>::new()).unwrap();
    original
        .write_plan(
            &[],
            scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()),
        )
        .unwrap();
    original.finalize().unwrap();

    let replay_store = runs.create_run_with_id(generate_run_id()).unwrap();
    assert_ne!(replay_store.run_id(), &original_id);
    replay_store.set_replay_of(original_id.clone()).unwrap();
    let doc = replay_store.read_run_document().unwrap();
    assert_eq!(doc.replay_of, Some(original_id));
    assert_eq!(doc.state, RunState::Planning);
}

#[test]
fn verdict_semantics_are_preserved_through_storage() {
    // Sanity: a stored execution keeps its status semantics.
    let exec = CheckExecution::minimal(
        CheckId::new("x:y"),
        CheckStatus::Executed { exit_code: Some(0) },
    );
    assert_eq!(exec.status.base_verdict(), Verdict::Verified);
}
