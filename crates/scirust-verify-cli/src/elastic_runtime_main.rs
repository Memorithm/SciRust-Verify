//! Process-oriented ElasticXxx runtime evidence ingestion for SciRust Hub.
//!
//! This binary validates the published `elastic-runtime-evidence-v1` contract,
//! preserves ElasticXxx runtime decisions as source observations, integrity-seals
//! a SciRust-Verify dossier, and exports that dossier as one canonical tar.
//! COMMIT/ROLLBACK remains an ElasticXxx decision and is never promoted to a
//! SciRust-Verify claim verdict.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use scirust_verify_core::adapters::{
    ingest_elastic_runtime, ELASTIC_RUNTIME_CONTRACT, ELASTIC_RUNTIME_EVIDENCE_SCHEMA,
    ELASTIC_RUNTIME_MEDIA_TYPE, ELASTIC_RUNTIME_SOURCE_HEAD, ELASTIC_RUNTIME_SOURCE_MERGE,
};
use scirust_verify_model::provenance::ProvenanceDocument;
use scirust_verify_model::{
    canonical_json, Artifact, ArtifactId, ArtifactKind, Check, CheckAction, CheckExecution,
    CheckId, CheckStatus, Claim, ClaimEvaluation, ClaimId, ClaimKind, DirtyState,
    EnvironmentSnapshot, Evidence, EvidenceId, EvidenceKind, EvidenceStatus, RequirementLevel,
    SourceIdentity, VerificationScope, SCHEMA_VERSION, TOOL_IDENTITY,
};
use scirust_verify_store::{RunState, RunsRoot};

const DOSSIER_MEDIA_TYPE: &str = "application/vnd.scirust-verify.dossier.v1+tar";
const DOSSIER_CONTRACT: &str = "scirust-verify.elastic-runtime-dossier@1.0.0";
const MAX_DOSSIER_BYTES: u64 = 512 * 1024 * 1024;
const TAR_BLOCK: usize = 512;

#[derive(Parser)]
#[command(
    name = "scirust-verify-elastic",
    version,
    about = "Validate ElasticXxx runtime evidence and emit a sealed SciRust-Verify dossier"
)]
struct Cli {
    /// ElasticXxx runtime evidence produced by `elastic.hub.run@1.0.0`.
    #[arg(long)]
    evidence: PathBuf,
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
    commit_count: usize,
    rollback_count: usize,
    output: String,
}

impl ProcessSummary {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "contract": DOSSIER_CONTRACT,
            "dossier_media_type": DOSSIER_MEDIA_TYPE,
            "contract_verdict": "VERIFIED",
            "elastic_runtime_decision_owner": "ElasticXxx",
            "commit_count": self.commit_count,
            "rollback_count": self.rollback_count,
            "model_quality_verified": false,
            "performance_verified": false,
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

    let ingested = ingest_elastic_runtime(&cli.evidence)
        .map_err(|error| ProcessError::Contract(error.to_string()))?;

    let work_root = output_parent.join(format!(
        ".scirust-verify-elastic-{}",
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

    let artifact_id = ArtifactId::new("elastic-runtime-evidence");
    let claim_id = ClaimId::from("elastic_runtime_evidence_contract");
    let check_id = CheckId::new("elastic-runtime:evidence-v1");

    let mut parameters = serde_json::Map::new();
    parameters.insert("contract".to_owned(), serde_json::json!(DOSSIER_CONTRACT));
    parameters.insert(
        "source_contract".to_owned(),
        serde_json::json!(ELASTIC_RUNTIME_CONTRACT),
    );
    parameters.insert(
        "source_schema".to_owned(),
        serde_json::json!(ELASTIC_RUNTIME_EVIDENCE_SCHEMA),
    );
    parameters.insert(
        "source_media_type".to_owned(),
        serde_json::json!(ELASTIC_RUNTIME_MEDIA_TYPE),
    );
    parameters.insert(
        "source_head".to_owned(),
        serde_json::json!(ELASTIC_RUNTIME_SOURCE_HEAD),
    );
    parameters.insert(
        "source_merge".to_owned(),
        serde_json::json!(ELASTIC_RUNTIME_SOURCE_MERGE),
    );
    parameters.insert(
        "evidence_digest".to_owned(),
        serde_json::json!(ingested.digest().to_string()),
    );

    let claim = Claim {
        id: claim_id.clone(),
        kind: ClaimKind::from_slug("elastic_runtime_evidence_contract"),
        subject: artifact_id.clone(),
        requirement: RequirementLevel::Required,
        statement: "The supplied ElasticXxx artifact conforms to the qualified runtime-evidence v1 structural contract. This does not reinterpret ElasticXxx COMMIT/ROLLBACK, prove resource-policy optimality, or establish model quality or performance superiority."
            .to_owned(),
        parameters: parameters.clone(),
    };
    let check = Check {
        id: check_id.clone(),
        provider: "elastic-runtime-adapter".to_owned(),
        purpose: "Validate ElasticXxx runtime-evidence structure while preserving producer-owned runtime decisions."
            .to_owned(),
        claims: vec![claim_id.clone()],
        requirement: RequirementLevel::Required,
        action: CheckAction::Composite {
            engine: "elastic-runtime-evidence-v1".to_owned(),
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
            id: artifact_id.clone(),
            kind: ArtifactKind::Other,
            name: "ElasticXxx runtime evidence v1".to_owned(),
            version: Some("1.0.0".to_owned()),
            path: cli.evidence.clone(),
            source: SourceIdentity {
                repository: Some("https://github.com/Memorithm/ElasticXxx".to_owned()),
                commit: Some(ELASTIC_RUNTIME_SOURCE_MERGE.to_owned()),
                branch: None,
                dirty: DirtyState::Unknown,
                tree_digest: None,
            },
            content_digest: Some(ingested.digest().clone()),
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
    let limitations: Vec<String> =
        scirust_verify_core::adapters::ElasticRuntimeIngest::limitations()
            .map(str::to_owned)
            .collect();
    let mut observations = ingested.observations();
    observations.push(scirust_verify_model::Observation::new(
        "elastic_runtime",
        "limitations",
        scirust_verify_model::ObservedValue::Json(serde_json::json!(limitations)),
    ));

    let evidence = Evidence::builder(
        evidence_id.clone(),
        EvidenceKind::ExternalAttestation,
        "elastic-runtime-adapter",
    )
    .artifact(artifact_id)
    .scope(VerificationScope {
        execution_mode: Some("external-artifact-ingestion".to_owned()),
        ..Default::default()
    })
    .status(EvidenceStatus::Ok)
    .observations(observations)
    .input(ingested.digest().clone())
    .meta("contract", DOSSIER_CONTRACT)
    .meta("elastic_source_contract", ELASTIC_RUNTIME_CONTRACT)
    .meta("elastic_source_head", ELASTIC_RUNTIME_SOURCE_HEAD)
    .meta("elastic_source_merge", ELASTIC_RUNTIME_SOURCE_MERGE)
    .meta("elastic_runtime_decision_owner", "ElasticXxx")
    .meta("model_quality_verified", false)
    .meta("performance_verified", false)
    .build();
    store
        .add_evidence(&evidence, &BTreeMap::new())
        .map_err(ProcessError::internal)?;

    store
        .append_execution(CheckExecution {
            check_id: check_id.clone(),
            started_at_utc: None,
            ended_at_utc: None,
            status: CheckStatus::Executed { exit_code: None },
            outcome: scirust_verify_model::Verdict::Verified,
            summary: "ElasticXxx runtime evidence v1 structural contract validated; producer COMMIT/ROLLBACK decisions remain source observations."
                .to_owned(),
            observations: Vec::new(),
            evidence_ids: vec![evidence_id.clone()],
            notes: scirust_verify_core::adapters::ElasticRuntimeIngest::limitations()
                .map(str::to_owned)
                .collect(),
        })
        .map_err(ProcessError::internal)?;

    let evaluation = ClaimEvaluation {
        claim_id,
        verdict: scirust_verify_model::Verdict::Verified,
        scope: VerificationScope {
            execution_mode: Some("external-artifact-ingestion".to_owned()),
            ..Default::default()
        },
        reasoning: "The adapter independently revalidated the qualified runtime-evidence schema, source command/config shape, bounded controller/cycle/event structure, unique resource identity, and consistency between COMMIT/ROLLBACK flags and their source runtime events. The verdict is limited to evidence-contract conformance."
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
            "elastic-runtime-adapter".to_owned(),
            "qualified ElasticXxx runtime evidence ingestion".to_owned(),
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
    let commit_count = ingested.commit_count();
    let rollback_count = ingested.rollback_count();
    drop(cleanup);
    let _ = fs::remove_dir_all(&work_root);

    Ok(ProcessSummary {
        run_id,
        commit_count,
        rollback_count,
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
            "scirust-verify-elastic-cli-{}-{id}",
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
