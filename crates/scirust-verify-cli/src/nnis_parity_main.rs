//! Process-oriented NNIS NNML1 parity-evidence ingestion for SciRust Hub.
//!
//! This binary independently binds the original parity evidence to the qualified
//! NNIS validation result by SHA-256, preserves NNIS parity facts as source
//! observations, seals the validation result as a content-addressed attachment,
//! and exports the dossier as one tar. It does not rerun models or reinterpret
//! NNIS promotion semantics.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use scirust_verify_core::adapters::{
    ingest_nnis_parity, NnisParityIngest, NNIS_PARITY_EVIDENCE_MEDIA_TYPE,
    NNIS_PARITY_SOURCE_HEAD, NNIS_PARITY_SOURCE_MERGE, NNIS_PARITY_VALIDATION_CONTRACT,
    NNIS_PARITY_VALIDATION_MEDIA_TYPE,
};
use scirust_verify_model::provenance::ProvenanceDocument;
use scirust_verify_model::{
    canonical_json, Artifact, ArtifactId, ArtifactKind, Attachment, Check, CheckAction,
    CheckExecution, CheckId, CheckStatus, Claim, ClaimEvaluation, ClaimId, ClaimKind, DirtyState,
    EnvironmentSnapshot, Evidence, EvidenceId, EvidenceKind, EvidenceStatus, RequirementLevel,
    SourceIdentity, VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_store::{RunState, RunsRoot};

const DOSSIER_MEDIA_TYPE: &str = "application/vnd.scirust-verify.dossier.v1+tar";
const DOSSIER_CONTRACT: &str = "scirust-verify.nnis-parity-dossier@1.0.0";
const VALIDATION_ATTACHMENT: &str = "evidence/files/nnis-parity-validation.json";
const MAX_DOSSIER_BYTES: u64 = 512 * 1024 * 1024;
const TAR_BLOCK: usize = 512;

#[derive(Parser)]
#[command(
    name = "scirust-verify-nnis-parity",
    version,
    about = "Bind qualified NNIS parity evidence to its validation result and emit a sealed dossier"
)]
struct Cli {
    /// Original NNIS NNML1 parity record or same-head suite.
    #[arg(long)]
    parity_evidence: PathBuf,
    /// Result emitted by `nnis.nnml1.parity-validation@1.0.0` for those exact bytes.
    #[arg(long)]
    validation: PathBuf,
    /// Single dossier tar output path. The path must not already exist.
    #[arg(long)]
    output: PathBuf,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(summary) => {
            println!("{}", summary.to_json());
            ExitCode::SUCCESS
        }
        Err(ProcessError::Contract(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
        Err(ProcessError::Internal(message)) => {
            eprintln!("internal error: {message}");
            ExitCode::from(3)
        }
    }
}

#[derive(Debug)]
enum ProcessError {
    Contract(String),
    Internal(String),
}

impl ProcessError {
    fn internal(error: impl std::fmt::Display) -> Self {
        Self::Internal(error.to_string())
    }
}

struct ProcessSummary {
    run_id: String,
    evidence_kind: String,
    checkpoint_count: u32,
    output: String,
}

impl ProcessSummary {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "contract": DOSSIER_CONTRACT,
            "dossier_media_type": DOSSIER_MEDIA_TYPE,
            "contract_verdict": "VERIFIED",
            "contract_verdict_scope": "exact_byte_binding_and_validation_envelope_only",
            "nnis_semantics_owner": "NNIS",
            "evidence_kind": self.evidence_kind.as_str(),
            "distinct_checkpoint_count": self.checkpoint_count,
            "model_quality_verified": false,
            "serving_performance_verified": false,
            "general_model_family_support_verified": false,
            "promotion_authorized": false,
            "run_id": self.run_id.as_str(),
            "output": self.output.as_str(),
        })
    }
}

fn run(cli: Cli) -> Result<ProcessSummary, ProcessError> {
    if cli.output.exists() {
        return Err(ProcessError::Contract(format!(
            "output already exists: {}",
            cli.output.display()
        )));
    }
    let output_parent = cli.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_parent).map_err(ProcessError::internal)?;

    let ingested = ingest_nnis_parity(&cli.parity_evidence, &cli.validation)
        .map_err(|error| ProcessError::Contract(error.to_string()))?;
    let validation_bytes = fs::read(&cli.validation).map_err(ProcessError::internal)?;
    let validation_digest = scirust_verify_model::Digest::sha256_hex(&validation_bytes);
    if validation_digest != *ingested.validation_digest() {
        return Err(ProcessError::Contract(
            "NNIS validation artifact changed after contract validation".to_owned(),
        ));
    }

    let work_root = output_parent.join(format!(
        ".scirust-verify-nnis-parity-{}",
        std::process::id()
    ));
    if work_root.exists() {
        return Err(ProcessError::Internal(format!(
            "temporary work root already exists: {}",
            work_root.display()
        )));
    }
    fs::create_dir(&work_root).map_err(ProcessError::internal)?;
    let cleanup = CleanupDir(work_root.clone());

    let runs = RunsRoot::new(work_root.join("runs"));
    let store = runs.create_run().map_err(ProcessError::internal)?;
    let run_id = store.run_id().to_string();

    let parity_artifact_id = ArtifactId::new("nnis-parity-evidence");
    let claim_id = ClaimId::from("nnis_parity_evidence_binding_contract");
    let check_id = CheckId::new("nnis:parity-evidence-binding-v1");

    let mut parameters = serde_json::Map::new();
    parameters.insert("contract".to_owned(), serde_json::json!(DOSSIER_CONTRACT));
    parameters.insert(
        "source_contract".to_owned(),
        serde_json::json!(NNIS_PARITY_VALIDATION_CONTRACT),
    );
    parameters.insert(
        "source_evidence_media_type".to_owned(),
        serde_json::json!(NNIS_PARITY_EVIDENCE_MEDIA_TYPE),
    );
    parameters.insert(
        "source_validation_media_type".to_owned(),
        serde_json::json!(NNIS_PARITY_VALIDATION_MEDIA_TYPE),
    );
    parameters.insert(
        "source_head".to_owned(),
        serde_json::json!(NNIS_PARITY_SOURCE_HEAD),
    );
    parameters.insert(
        "source_merge".to_owned(),
        serde_json::json!(NNIS_PARITY_SOURCE_MERGE),
    );
    parameters.insert(
        "evidence_digest".to_owned(),
        serde_json::json!(ingested.evidence_digest().to_string()),
    );
    parameters.insert(
        "validation_digest".to_owned(),
        serde_json::json!(ingested.validation_digest().to_string()),
    );
    parameters.insert(
        "execution_git_commit".to_owned(),
        serde_json::json!(ingested.execution_git_commit()),
    );

    let claim = Claim {
        id: claim_id.clone(),
        kind: ClaimKind::from_slug("nnis_parity_evidence_binding_contract"),
        subject: parity_artifact_id.clone(),
        requirement: RequirementLevel::Required,
        statement: "The exact supplied NNIS parity-evidence bytes are SHA-256-bound to a validation result conforming to the qualified NNIS parity-validation process envelope. This does not independently re-run NNIS parity semantics, establish general model-family support or serving performance, or authorize runtime/model-family promotion."
            .to_owned(),
        parameters: parameters.clone(),
    };
    let check = Check {
        id: check_id.clone(),
        provider: "nnis-parity-adapter".to_owned(),
        purpose: "Verify exact-byte binding to the qualified NNIS validation envelope while preserving producer-owned parity semantics."
            .to_owned(),
        claims: vec![claim_id.clone()],
        requirement: RequirementLevel::Required,
        action: CheckAction::Composite {
            engine: "nnis-nnml1-parity-binding-v1".to_owned(),
            parameters,
        },
        timeout: std::time::Duration::ZERO,
        stdout_limit_bytes: 1,
        stderr_limit_bytes: 1,
    };
    let plan_digest = scirust_verify_model::Digest::sha256_hex(
        canonical_json(&std::slice::from_ref(&check))
            .map_err(ProcessError::internal)?
            .as_bytes(),
    );

    store
        .write_artifact(&Artifact {
            id: parity_artifact_id.clone(),
            kind: ArtifactKind::Other,
            name: "NNIS NNML1 parity evidence".to_owned(),
            version: Some("1.0.0".to_owned()),
            path: cli.parity_evidence.clone(),
            source: SourceIdentity {
                repository: Some("https://github.com/Memorithm/NNIS".to_owned()),
                commit: Some(ingested.execution_git_commit().to_owned()),
                branch: None,
                dirty: DirtyState::Unknown,
                tree_digest: None,
            },
            content_digest: Some(ingested.evidence_digest().clone()),
        })
        .map_err(ProcessError::internal)?;
    store
        .write_environment(&EnvironmentSnapshot::default())
        .map_err(ProcessError::internal)?;
    store
        .write_provenance(&ProvenanceDocument {
            schema_version: SCHEMA_VERSION,
            git: None,
            tree_digest: None,
            probes: Vec::new(),
        })
        .map_err(ProcessError::internal)?;
    store
        .write_plan(std::slice::from_ref(&check), plan_digest)
        .map_err(ProcessError::internal)?;
    store
        .write_claims(std::slice::from_ref(&claim))
        .map_err(ProcessError::internal)?;
    store
        .set_state(RunState::Running)
        .map_err(ProcessError::internal)?;

    let evidence_id = EvidenceId::sequential(1);
    let limitations: Vec<String> = NnisParityIngest::limitations().map(str::to_owned).collect();
    let mut observations = ingested.observations();
    observations.push(scirust_verify_model::Observation::new(
        "nnis_parity",
        "limitations",
        scirust_verify_model::ObservedValue::Json(serde_json::json!(limitations)),
    ));

    let validation_attachment = Attachment {
        path: VALIDATION_ATTACHMENT.to_owned(),
        size_bytes: validation_bytes.len() as u64,
        digest: ingested.validation_digest().clone(),
        media_type: Some(NNIS_PARITY_VALIDATION_MEDIA_TYPE.to_owned()),
    };
    let evidence = Evidence::builder(
        evidence_id.clone(),
        EvidenceKind::ExternalAttestation,
        "nnis-parity-adapter",
    )
    .artifact(parity_artifact_id)
    .scope(VerificationScope {
        execution_mode: Some("external-artifact-ingestion".to_owned()),
        ..Default::default()
    })
    .status(EvidenceStatus::Ok)
    .observations(observations)
    .input(ingested.evidence_digest().clone())
    .input(ingested.validation_digest().clone())
    .attachment(validation_attachment)
    .meta("contract", DOSSIER_CONTRACT)
    .meta("nnis_source_contract", NNIS_PARITY_VALIDATION_CONTRACT)
    .meta("nnis_source_head", NNIS_PARITY_SOURCE_HEAD)
    .meta("nnis_source_merge", NNIS_PARITY_SOURCE_MERGE)
    .meta("nnis_semantics_owner", "NNIS")
    .meta(
        "validation_digest",
        ingested.validation_digest().to_string(),
    )
    .meta("model_quality_verified", false)
    .meta("serving_performance_verified", false)
    .meta("general_model_family_support_verified", false)
    .meta("promotion_authorized", false)
    .build();
    let mut attachments = BTreeMap::new();
    attachments.insert(VALIDATION_ATTACHMENT.to_owned(), validation_bytes);
    store
        .add_evidence(&evidence, &attachments)
        .map_err(ProcessError::internal)?;

    store
        .append_execution(CheckExecution {
            check_id: check_id.clone(),
            started_at_utc: None,
            ended_at_utc: None,
            status: CheckStatus::Executed { exit_code: None },
            outcome: scirust_verify_model::Verdict::Verified,
            summary: "Exact NNIS parity-evidence bytes are bound to the qualified NNIS validation result; producer parity semantics remain source observations."
                .to_owned(),
            observations: Vec::new(),
            evidence_ids: vec![evidence_id.clone()],
            notes: NnisParityIngest::limitations().map(str::to_owned).collect(),
        })
        .map_err(ProcessError::internal)?;

    let evaluation = ClaimEvaluation {
        claim_id,
        verdict: scirust_verify_model::Verdict::Verified,
        scope: VerificationScope {
            execution_mode: Some("external-artifact-ingestion".to_owned()),
            ..Default::default()
        },
        reasoning: "The adapter independently hashed the exact original parity-evidence bytes, required the qualified NNIS validation result to reference that same SHA-256 and evidence kind, checked the validation contract/media/version/scope, matched the NNIS execution commit across both artifacts, sealed the exact validation result as a dossier attachment, and rejected promotion/serving/general-family claim inflation. NNIS remains authoritative for checkpoint, tokenizer, greedy-trajectory, logit-tolerance, and same-head parity semantics."
            .to_owned(),
        evidence_ids: vec![evidence_id],
        check_ids: vec![check_id],
    };
    store
        .write_text(
            "evaluations.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "evaluations": [{
                    "requirement_level": RequirementLevel::Required.to_string(),
                    "evaluation": evaluation,
                }]
            }))
            .map_err(ProcessError::internal)?,
        )
        .map_err(ProcessError::internal)?;

    let report_ctx = scirust_verify_report::ReportInputs {
        tool_version: TOOL_IDENTITY.to_owned(),
        schema_version: SCHEMA_VERSION,
        detected_providers: vec![(
            "nnis-parity-adapter".to_owned(),
            "qualified NNIS parity evidence exact-byte binding".to_owned(),
        )],
        strict: true,
    };
    let report_json =
        scirust_verify_report::render_json(&store, &report_ctx).map_err(ProcessError::internal)?;
    let report_md = scirust_verify_report::render_markdown(&store, &report_ctx)
        .map_err(ProcessError::internal)?;
    store
        .write_text("report.json", &report_json)
        .map_err(ProcessError::internal)?;
    store
        .write_text("report.md", &report_md)
        .map_err(ProcessError::internal)?;
    store.finalize().map_err(ProcessError::internal)?;
    store.verify_integrity().map_err(ProcessError::internal)?;

    archive_dossier(store.path(), &cli.output)?;
    let evidence_kind = ingested.evidence_kind().to_owned();
    let checkpoint_count = ingested.distinct_checkpoint_count();
    drop(cleanup);
    let _ = fs::remove_dir_all(&work_root);

    Ok(ProcessSummary {
        run_id,
        evidence_kind,
        checkpoint_count,
        output: cli.output.display().to_string(),
    })
}

struct CleanupDir(PathBuf);

impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn archive_dossier(run_dir: &Path, output: &Path) -> Result<(), ProcessError> {
    let mut files = Vec::new();
    collect_regular_files(run_dir, run_dir, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(ProcessError::internal)?;
    let mut total = 0u64;

    let result = (|| -> Result<(), ProcessError> {
        for (rel, path, size) in files {
            total = total
                .checked_add(size)
                .ok_or_else(|| ProcessError::Internal("dossier size overflow".to_owned()))?;
            if total > MAX_DOSSIER_BYTES {
                return Err(ProcessError::Internal(format!(
                    "sealed dossier exceeds {MAX_DOSSIER_BYTES} bytes"
                )));
            }
            let archive_name = format!("dossier/{rel}");
            write_tar_header(&mut writer, &archive_name, size)?;
            let mut input = File::open(&path).map_err(ProcessError::internal)?;
            std::io::copy(&mut input, &mut writer).map_err(ProcessError::internal)?;
            let padding = (TAR_BLOCK as u64 - (size % TAR_BLOCK as u64)) % TAR_BLOCK as u64;
            if padding > 0 {
                writer
                    .write_all(&vec![0u8; padding as usize])
                    .map_err(ProcessError::internal)?;
            }
        }
        writer
            .write_all(&[0u8; TAR_BLOCK * 2])
            .map_err(ProcessError::internal)?;
        writer.flush().map_err(ProcessError::internal)?;
        Ok(())
    })();

    if let Err(error) = result {
        drop(writer);
        let _ = fs::remove_file(output);
        return Err(error);
    }
    drop(writer);
    Ok(())
}

fn collect_regular_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf, u64)>,
) -> Result<(), ProcessError> {
    let mut entries = fs::read_dir(dir)
        .map_err(ProcessError::internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ProcessError::internal)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(ProcessError::internal)?;
        if metadata.file_type().is_symlink() {
            return Err(ProcessError::Internal(format!(
                "sealed dossier contains symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_regular_files(root, &path, out)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ProcessError::Internal(format!(
                "sealed dossier contains non-regular file: {}",
                path.display()
            )));
        }
        let rel = path
            .strip_prefix(root)
            .map_err(ProcessError::internal)?
            .to_string_lossy()
            .replace('\\', "/");
        validate_archive_path(&rel)?;
        out.push((rel, path, metadata.len()));
    }
    Ok(())
}

fn validate_archive_path(path: &str) -> Result<(), ProcessError> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !path.is_ascii()
        || format!("dossier/{path}").len() > 100
    {
        return Err(ProcessError::Internal(format!(
            "unsupported dossier archive path: {path:?}"
        )));
    }
    Ok(())
}

fn write_tar_header(writer: &mut File, name: &str, size: u64) -> Result<(), ProcessError> {
    let mut header = [0u8; TAR_BLOCK];
    if name.len() > 100 || !name.is_ascii() {
        return Err(ProcessError::Internal(format!(
            "unsupported tar path: {name:?}"
        )));
    }
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header[100..108], 0o644)?;
    write_octal(&mut header[108..116], 0)?;
    write_octal(&mut header[116..124], 0)?;
    write_octal(&mut header[124..136], size)?;
    write_octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    if checksum_text.len() != 8 {
        return Err(ProcessError::Internal("tar checksum overflow".to_owned()));
    }
    header[148..156].copy_from_slice(checksum_text.as_bytes());
    writer.write_all(&header).map_err(ProcessError::internal)
}

fn write_octal(field: &mut [u8], value: u64) -> Result<(), ProcessError> {
    let width = field.len().saturating_sub(1);
    let text = format!("{value:0width$o}", width = width);
    if text.len() != width {
        return Err(ProcessError::Internal(
            "tar numeric field overflow".to_owned(),
        ));
    }
    field.fill(0);
    field[..width].copy_from_slice(text.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn temp_dir() -> PathBuf {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "scirust-verify-nnis-parity-cli-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn archive_never_overwrites_existing_output() {
        let dir = temp_dir();
        fs::write(dir.join("run.json"), b"{}\n").unwrap();
        let output = dir.with_extension("tar");
        fs::write(&output, b"sentinel").unwrap();
        let error = archive_dossier(&dir, &output).expect_err("existing output must fail");
        assert!(matches!(error, ProcessError::Internal(_)));
        assert_eq!(fs::read(&output).unwrap(), b"sentinel");
        let _ = fs::remove_file(output);
        let _ = fs::remove_dir_all(dir);
    }
}
