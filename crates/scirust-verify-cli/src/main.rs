//! SciRust-Verify command line interface.
//!
//! Exit codes (documented contract):
//! * `0` — verification succeeded (`PASS` or `PASS_WITH_GAPS`), or the
//!   invoked informational command completed.
//! * `1` — verification did not establish its required claims
//!   (`FAIL`/`NOT_VERIFIED`), or a requested run/report does not exist.
//! * `2` — invalid usage or configuration (bad paths, bad manifests).
//! * `3` — internal execution error (storage failure, spawn infrastructure).

#![deny(missing_docs)]

#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

#[cfg(target_os = "linux")]
use nix::fcntl::{AtFlags, AT_FDCWD};
#[cfg(target_os = "linux")]
use nix::unistd::{linkat, unlinkat, UnlinkatFlags};

use clap::{Parser, Subcommand};
use scirust_verify_cargo::CargoProvider;
use scirust_verify_core::discovery::DiscoveryContext;
use scirust_verify_core::manifest::Manifest;
use scirust_verify_core::pipeline::{self, VerifyOptions};
use scirust_verify_core::planning::ProviderRegistry;
use scirust_verify_core::providers::{
    CustomChecksProvider, NumericChecksProvider, SourceCleanProvider,
};
use scirust_verify_determinism::DeterminismProvider;
use scirust_verify_model::digest::Digest;
use scirust_verify_model::TOOL_IDENTITY;
use scirust_verify_store::RunsRoot;

mod scirust_ingest;

#[derive(Parser)]
#[command(
    name = "scirust-verify",
    version,
    about = "Verification, evidence and provenance layer for the SciRust ecosystem",
    long_about = "SciRust-Verify turns claims into structured evidence dossiers: what was executed, under which scope, which properties were checked, and which verdicts the evidence justifies."
)]
struct Cli {
    /// Machine-readable output on stdout (no ANSI colors).
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a starter scirust-verify.toml for a project.
    Init {
        /// Project directory (default: current directory).
        path: Option<PathBuf>,
        /// Overwrite an existing manifest.
        #[arg(long)]
        force: bool,
    },
    /// Show discovered project facts without running anything heavy.
    Inspect {
        /// Project directory.
        path: Option<PathBuf>,
    },
    /// Show exactly what `verify` would execute.
    Plan {
        /// Project directory.
        path: Option<PathBuf>,
        /// Profile override.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Run verification and produce an evidence dossier.
    Verify {
        /// Project directory.
        path: Option<PathBuf>,
        /// Profile override (basic|scientific|reproducibility|strict).
        #[arg(long)]
        profile: Option<String>,
        /// Target triple override.
        #[arg(long)]
        target: Option<String>,
        /// Missing prerequisites fail instead of producing gaps.
        #[arg(long)]
        strict: bool,
        /// Alternative location for the `.scirust-verify` directory.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Print a stored report (human, JSON or Markdown) without re-running.
    Report {
        /// Run id (or a project path containing `.scirust-verify` plus run id).
        run: String,
        /// Emit the machine-readable report.json.
        #[arg(long)]
        json: bool,
        /// Emit the Markdown report.
        #[arg(long)]
        markdown: bool,
        /// Verify bundle integrity before printing.
        #[arg(long)]
        check_integrity: bool,
    },
    /// Publish a detached OpenSSH signature over an integrity-verified bundle.
    Attest {
        /// Finalized run id to sign.
        run: String,
        /// Principal recorded in the detached envelope.
        #[arg(long)]
        principal: String,
        /// OpenSSH private-key identity used by ssh-keygen.
        #[arg(long)]
        identity: PathBuf,
        /// Detached envelope path (defaults outside the sealed run).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Replace an existing regular envelope file.
        #[arg(long)]
        force: bool,
    },
    /// Verify integrity and detached authorship against an external trust root.
    Authenticate {
        /// Finalized run id whose exact bundle manifest was signed.
        run: String,
        /// Detached attestation envelope produced by `attest`.
        #[arg(long)]
        envelope: PathBuf,
        /// OpenSSH allowed-signers file kept outside .scirust-verify.
        #[arg(long)]
        allowed_signers: PathBuf,
    },
    /// Re-execute a previous run as a NEW run linked to the original.
    Replay {
        /// Run id to replay.
        run: String,
        #[arg(long)]
        strict: bool,
    },
    /// Compare two evidence dossiers.
    Diff {
        /// First run id.
        run_a: String,
        /// Second run id.
        run_b: String,
    },
    /// Probe the local environment for verification tooling.
    Doctor,
    /// Print the persisted-document schema catalog.
    Schema,
    /// Ingest a completed SciRust test-protocol evidence bundle into a new dossier run.
    IngestScirust {
        /// Directory of the protocol bundle containing summary.txt.
        bundle: PathBuf,
        /// Project root the dossier attaches to (default: current directory).
        #[arg(long)]
        project: Option<PathBuf>,
        /// Alternative output root for `.scirust-verify`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Command::Init { path, force } => init(path.unwrap_or_else(current_dir), force),
        Command::Inspect { path } => inspect(path.unwrap_or_else(current_dir), cli.json),
        Command::Plan { path, profile } => {
            plan(path.unwrap_or_else(current_dir), profile, cli.json)
        }
        Command::Verify {
            path,
            profile,
            target,
            strict,
            output,
        } => verify(
            path.unwrap_or_else(current_dir),
            profile,
            target,
            strict,
            output,
            cli.json,
        ),
        Command::Report {
            run,
            json,
            markdown,
            check_integrity,
        } => report(&run, json, markdown, check_integrity),
        Command::Attest {
            run,
            principal,
            identity,
            output,
            force,
        } => attest(&run, &principal, &identity, output, force, cli.json),
        Command::Authenticate {
            run,
            envelope,
            allowed_signers,
        } => authenticate(&run, &envelope, &allowed_signers, cli.json),
        Command::Replay { run, strict } => replay(&run, strict, cli.json),
        Command::Diff { run_a, run_b } => diff(&run_a, &run_b),
        Command::Doctor => doctor(),
        Command::Schema => schema(),
        Command::IngestScirust {
            bundle,
            project,
            output,
        } => ingest_scirust(
            bundle,
            project.unwrap_or_else(current_dir),
            output,
            cli.json,
        ),
    }
}

fn current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Error type for CLI-level failures.
///
/// Exit-code contract: requested-but-missing runs exit 1; usage and
/// configuration problems exit 2; infrastructure failures exit 3.
#[derive(Debug)]
struct CliError {
    message: String,
    exit_code: u8,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }

    fn infrastructure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 3,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn runs_root_for(project: &Path) -> RunsRoot {
    RunsRoot::new(project.join(".scirust-verify").join("runs"))
}

/// Finds the project root for run-scoped commands: either the current
/// directory contains `.scirust-verify`, or we walk up to find one.
fn locate_runs_root() -> Result<PathBuf, CliError> {
    let mut dir = current_dir().canonicalize().unwrap_or(current_dir());
    loop {
        if dir.join(".scirust-verify/runs").is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(CliError::not_found(
                "no `.scirust-verify/runs` found here or in any parent directory; run verify first",
            ));
        }
    }
}

fn build_registry(manifest: &Manifest) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    registry.register(Box::new(CargoProvider::from_section(
        manifest.cargo.clone(),
    )));
    registry.register(Box::new(DeterminismProvider {
        enabled: manifest.determinism.enabled,
        runs: manifest.determinism.runs.unwrap_or(3),
        program: manifest.determinism.program.clone(),
        mode: manifest
            .determinism
            .mode
            .clone()
            .unwrap_or_else(|| "stdout_digest".to_owned()),
        thread_levels: manifest.determinism.thread_levels.clone(),
        thread_env: manifest.determinism.thread_env.clone(),
    }));
    if !manifest.custom_checks.is_empty() {
        registry.register(Box::new(CustomChecksProvider {
            checks: manifest.custom_checks.clone(),
        }));
    }
    if !manifest.numeric_checks.is_empty() {
        registry.register(Box::new(NumericChecksProvider {
            checks: manifest.numeric_checks.clone(),
        }));
    }
    registry.register(Box::new(SourceCleanProvider));
    registry
}

fn load_manifest_or_default(project: &Path) -> Manifest {
    let p = project.join(scirust_verify_core::manifest::MANIFEST_FILE);
    if p.is_file() {
        Manifest::load(&p).unwrap_or_default()
    } else {
        Manifest {
            schema_version: Some(1),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn init(path: PathBuf, force: bool) -> Result<ExitCode, CliError> {
    let ctx = DiscoveryContext::discover(&path).map_err(|e| CliError::usage(e.to_string()))?;
    let manifest_path = path.join(scirust_verify_core::manifest::MANIFEST_FILE);
    if manifest_path.exists() && !force {
        return Err(CliError::usage(format!(
            "{} already exists; pass --force to overwrite",
            manifest_path.display()
        )));
    }

    let cargo_enabled = matches!(
        ctx.kind,
        scirust_verify_core::discovery::ProjectKind::Cargo { .. }
    );
    let name = match &ctx.kind {
        scirust_verify_core::discovery::ProjectKind::Cargo { packages, .. } => {
            packages.first().cloned()
        }
        _ => None,
    };

    let mut manifest = Manifest {
        schema_version: Some(1),
        ..Default::default()
    };
    manifest.cargo.enabled = cargo_enabled;
    // Sensible starter defaults: fmt/clippy recommended, docs optional.
    manifest.claims.insert("builds".into(), "required".into());
    manifest
        .claims
        .insert("tests_pass".into(), "required".into());
    manifest
        .claims
        .insert("lint_clean".into(), "recommended".into());
    manifest
        .claims
        .insert("fmt_clean".into(), "recommended".into());
    manifest
        .claims
        .insert("docs_build".into(), "optional".into());
    if let Some(name) = name {
        manifest.artifact.name = Some(name);
    }

    let body = toml_toml_string(&manifest)?;
    std::fs::write(&manifest_path, body)
        .map_err(|e| CliError::usage(format!("write failed: {e}")))?;
    println!("wrote {}", manifest_path.display());
    println!("next: scirust-verify plan {}", path.display());
    Ok(ExitCode::SUCCESS)
}

fn toml_toml_string(manifest: &Manifest) -> Result<String, CliError> {
    // Serialize through JSON then emit a readable TOML skeleton for the fields
    // that matter; keeps comments stable and avoids exotic toml serializer deps.
    let mut s = String::from("schema_version = 1\n\n");
    if let Some(name) = &manifest.artifact.name {
        s.push_str(&format!("[artifact]\nname = \"{name}\"\n\n"));
    }
    s.push_str("[verification]\nprofile = \"basic\"\n\n");
    let enabled_flag = if manifest.cargo.enabled {
        "true"
    } else {
        "false"
    };
    s.push_str(&format!(
        "[cargo]\nenabled = {enabled_flag}\nfmt = true\nclippy = true\ncheck = false\nbuild = true\ntest = true\ndoc = false\ndeny = \"optional\"\n\n"
    ));
    s.push_str("[determinism]\nenabled = false\nruns = 3\nprogram = [\"cargo\", \"run\", \"--quiet\"]\nmode = \"stdout_digest\"\n# thread_levels = [1, 2, 4]\n# thread_env = \"RAYON_NUM_THREADS\"\n\n");
    s.push_str("[claims]\n");
    let mut sorted: Vec<_> = manifest.claims.iter().collect();
    sorted.sort();
    for (k, v) in sorted {
        s.push_str(&format!("{k} = \"{v}\"\n"));
    }
    Ok(s)
}

fn inspect(path: PathBuf, json: bool) -> Result<ExitCode, CliError> {
    let ctx = DiscoveryContext::discover(&path).map_err(|e| CliError::usage(e.to_string()))?;
    let manifest = load_manifest_or_default(&path);
    let registry = build_registry(&manifest);
    let opts = VerifyOptions::for_root(path.clone());

    let mut providers_json = Vec::new();
    let mut provider_lines = Vec::new();
    for provider in registry.providers() {
        let detection = provider.detect(&ctx);
        let note = match detection {
            scirust_verify_core::planning::Detection::Detected { note } => {
                provider_lines.push(format!("  + {} ({note})", provider.name()));
                Some(note)
            }
            scirust_verify_core::planning::Detection::NotDetected => None,
        };
        providers_json.push(serde_json::json!({
            "provider": provider.name(),
            "detected": note.is_some(),
            "note": note,
        }));
    }

    if json {
        let doc = serde_json::json!({
            "tool": TOOL_IDENTITY,
            "project_root": ctx.project_root,
            "kind": ctx.kind,
            "git": {
                "commit": ctx.source.commit,
                "branch": ctx.source.branch,
                "dirty": format!("{:?}", ctx.source.dirty),
            },
            "has_manifest": ctx.has_manifest,
            "providers": providers_json,
        });
        println!("{doc}");
    } else {
        println!("SciRust-Verify inspect");
        println!("  root:      {}", ctx.project_root.display());
        match &ctx.kind {
            scirust_verify_core::discovery::ProjectKind::Cargo {
                is_workspace,
                packages,
            } => {
                println!(
                    "  kind:      Cargo {}",
                    if *is_workspace {
                        "workspace"
                    } else {
                        "package"
                    }
                );
                println!("  packages:  {}", packages.join(", "));
            }
            scirust_verify_core::discovery::ProjectKind::Unknown => {
                println!("  kind:      unrecognized source tree");
            }
        }
        println!(
            "  git:       commit={} dirty={:?}",
            short(&ctx.source.commit),
            ctx.source.dirty
        );
        println!(
            "  toolchain: {}",
            scirust_verify_core::provenance::probe(&ctx.project_root, &["rustc", "-V"])
                .map(|(_, s)| s.trim_end().to_owned())
                .unwrap_or_else(|| "rustc not found".to_owned())
        );
        println!(
            "  manifest:  {}",
            if ctx.has_manifest {
                "present"
            } else {
                "absent (defaults)"
            }
        );
        println!("  providers:");
        if provider_lines.is_empty() {
            println!("    (none detected)");
        } else {
            for l in provider_lines {
                println!("{l}");
            }
        }
        let _ = opts;
    }
    Ok(ExitCode::SUCCESS)
}

fn short(v: &Option<String>) -> &str {
    v.as_deref().map(|s| &s[..12.min(s.len())]).unwrap_or("?")
}

fn plan(path: PathBuf, profile: Option<String>, json: bool) -> Result<ExitCode, CliError> {
    let opts = VerifyOptions {
        cli_profile: profile,
        ..VerifyOptions::for_root(path)
    };
    let manifest = load_manifest_or_default(&opts.project_root);
    let registry = build_registry(&manifest);
    let prepared =
        pipeline::prepare(&registry, &opts).map_err(|e| CliError::usage(e.to_string()))?;

    if json {
        let checks: Vec<serde_json::Value> = prepared
            .checks
            .iter()
            .map(|c| serde_json::to_value(c).unwrap_or_default())
            .collect();
        let doc = serde_json::json!({
            "tool": TOOL_IDENTITY,
            "plan_digest": prepared.plan_digest.value,
            "checks": checks,
            "claims": prepared.claims.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        });
        println!("{doc}");
    } else {
        println!(
            "Verification plan for `{}` — {} check(s), digest {}…",
            prepared.ctx.project_root.display(),
            prepared.checks.len(),
            &prepared.plan_digest.value[..16]
        );
        println!("{:<28} {:<10} {:<12} PURPOSE", "CHECK", "PROVIDER", "LEVEL");
        for c in &prepared.checks {
            println!(
                "{:<28} {:<10} {:<12}",
                c.id.as_str(),
                c.provider,
                c.requirement.to_string()
            );
            println!("  purpose: {}", c.purpose);
            match &c.action {
                scirust_verify_model::CheckAction::Command { command, .. } => {
                    println!("  command: {} {}", command.program, command.args.join(" "));
                }
                scirust_verify_model::CheckAction::Composite { engine, .. } => {
                    println!("  engine:  {engine}");
                }
            }
        }
        println!("\nrun `scirust-verify verify` to execute this plan.");
    }
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
fn verify(
    path: PathBuf,
    profile: Option<String>,
    target: Option<String>,
    strict: bool,
    output: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode, CliError> {
    let opts = VerifyOptions {
        project_root: path,
        output_root: output,
        cli_profile: profile,
        target,
        strict,
        replay_of: None,
    };
    // Validate manifest up front for crisp errors.
    let manifest_path = opts
        .project_root
        .join(scirust_verify_core::manifest::MANIFEST_FILE);
    if manifest_path.is_file() {
        Manifest::load(&manifest_path).map_err(|e| CliError::usage(e.to_string()))?;
    }
    let manifest = load_manifest_or_default(&opts.project_root);
    let registry = build_registry(&manifest);

    match pipeline::run_verify(&registry, &opts) {
        Ok(outcome) => {
            if json {
                let doc = serde_json::json!({
                    "tool": TOOL_IDENTITY,
                    "run_id": outcome.run_id.to_string(),
                    "overall_verdict": outcome.verdict.label(),
                    "claims": outcome.claim_lines.iter().map(|(id, lvl, v)| serde_json::json!({
                        "claim": id, "level": lvl.to_string(), "verdict": v,
                    })).collect::<Vec<_>>(),
                    "report_json": outcome.report_json,
                    "report_md": outcome.report_md,
                });
                println!("{doc}");
            } else {
                println!("run {}", outcome.run_id);
                for (id, level, verdict) in &outcome.claim_lines {
                    println!("  [{level:>13}] {id:<40} {verdict}");
                }
                println!("overall verdict: {}", outcome.verdict.label());
                println!("report: {}", outcome.report_md.display());
            }
            Ok(if outcome.verdict.exit_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Err(pipeline::PipelineError::Manifest(e)) => Err(CliError::usage(e.to_string())),
        Err(e) => {
            eprintln!("internal error: {e}");
            Err(CliError::usage("verification aborted"))
        }
    }
}

fn open_run(run: &str) -> Result<(PathBuf, scirust_verify_store::RunStore), CliError> {
    let root = locate_runs_root()?;
    let runs = runs_root_for(&root);
    let store = runs.open(run).map_err(|_| {
        CliError::usage(format!(
            "run `{run}` not found under {}",
            runs.path().display()
        ))
    })?;
    Ok((root, store))
}

fn report(
    run: &str,
    json: bool,
    markdown: bool,
    check_integrity: bool,
) -> Result<ExitCode, CliError> {
    let (_root, store) = open_run(run)?;
    let doc = store
        .read_run_document()
        .map_err(|e| CliError::usage(e.to_string()))?;
    if check_integrity {
        match store.verify_integrity() {
            Ok(n) => println!("integrity OK ({n} sealed files)"),
            Err(e) => {
                eprintln!("INTEGRITY FAILURE: {e}");
                return Ok(ExitCode::from(1));
            }
        }
    }
    if json || (!markdown && is_terminal_json_default()) {
        let text = store.read_text("report.json").map_err(|e| {
            CliError::usage(format!(
                "report.json unavailable: {e}; use --regenerate via verify"
            ))
        })?;
        println!("{text}");
    } else if markdown {
        let text = store
            .read_text("report.md")
            .map_err(|e| CliError::usage(e.to_string()))?;
        println!("{text}");
    } else {
        let text = store
            .read_text("report.md")
            .map_err(|e| CliError::usage(e.to_string()))?;
        println!("{text}");
    }
    let _ = doc;
    Ok(ExitCode::SUCCESS)
}

const SSHSIG_NAMESPACE: &str = "scirust-verify-evidence-v1";
const MAX_ATTESTATION_ENVELOPE_BYTES: u64 = 1024 * 1024;

fn signed_attestation_payload(principal: &str, bundle: &[u8]) -> Vec<u8> {
    let mut payload = format!(
        "SCIRUST-VERIFY-ATTESTATION-V1\nprincipal:{principal}\nmanifest-length:{}\n\n",
        bundle.len()
    )
    .into_bytes();
    payload.extend_from_slice(bundle);
    payload
}

fn read_attestation_envelope(path: &Path) -> Result<Vec<u8>, CliError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    let file = options.open(path).map_err(|error| {
        CliError::usage(format!(
            "cannot open regular attestation envelope `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        CliError::usage(format!(
            "cannot inspect attestation envelope `{}`: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::usage(
            "attestation envelope must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ATTESTATION_ENVELOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::infrastructure(format!(
                "cannot read attestation envelope `{}`: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > MAX_ATTESTATION_ENVELOPE_BYTES {
        return Err(CliError::usage(format!(
            "attestation envelope exceeds the {MAX_ATTESTATION_ENVELOPE_BYTES}-byte limit"
        )));
    }
    Ok(bytes)
}

struct PreparedAttestationOutput {
    display_path: PathBuf,
    #[cfg(target_os = "linux")]
    parent: fs::File,
    #[cfg(target_os = "linux")]
    file_name: OsString,
}

#[cfg(target_os = "linux")]
fn descriptor_path(file: &fs::File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(0o600000); // O_DIRECTORY | O_NOFOLLOW
    options.open(path)
}

fn validate_normal_output_path(output: &Path) -> Result<(), CliError> {
    if output.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err(CliError::usage(
            "attestation output must be an absolute, normalized path without dot components",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_attestation_output(
    output: PathBuf,
    runs_root: &Path,
) -> Result<PreparedAttestationOutput, CliError> {
    validate_normal_output_path(&output)?;
    let file_name = output
        .file_name()
        .ok_or_else(|| CliError::usage("attestation output has no file name"))?
        .to_owned();
    let parent = output
        .parent()
        .ok_or_else(|| CliError::usage("attestation output has no parent directory"))?;
    let canonical_runs_root = runs_root
        .canonicalize()
        .map_err(|error| CliError::infrastructure(error.to_string()))?;

    let parent_handle = match open_directory(parent) {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent_name = parent
                .file_name()
                .ok_or_else(|| CliError::usage("attestation parent has no directory name"))?;
            let existing_parent = parent
                .parent()
                .ok_or_else(|| CliError::usage("attestation parent has no existing ancestor"))?;
            let existing_handle = open_directory(existing_parent).map_err(|open_error| {
                CliError::usage(format!(
                    "attestation parent `{}` must already exist: {open_error}",
                    existing_parent.display()
                ))
            })?;
            let anchored_existing = descriptor_path(&existing_handle);
            let canonical_existing = anchored_existing
                .canonicalize()
                .map_err(|canonical_error| CliError::infrastructure(canonical_error.to_string()))?;
            if canonical_existing.starts_with(&canonical_runs_root) {
                return Err(CliError::usage(
                    "detached attestations must be stored outside every sealed run directory",
                ));
            }
            let anchored_parent = anchored_existing.join(parent_name);
            match fs::create_dir(&anchored_parent) {
                Ok(()) => {}
                Err(create_error) if create_error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(create_error) => {
                    return Err(CliError::infrastructure(format!(
                        "cannot create attestation directory `{}`: {create_error}",
                        parent.display()
                    )));
                }
            }
            open_directory(&anchored_parent).map_err(|open_error| {
                CliError::infrastructure(format!(
                    "cannot pin attestation directory `{}`: {open_error}",
                    parent.display()
                ))
            })?
        }
        Err(error) => {
            return Err(CliError::usage(format!(
                "cannot open attestation directory `{}`: {error}",
                parent.display()
            )));
        }
    };

    let canonical_parent = descriptor_path(&parent_handle)
        .canonicalize()
        .map_err(|error| CliError::infrastructure(error.to_string()))?;
    if canonical_parent.starts_with(&canonical_runs_root) {
        return Err(CliError::usage(
            "detached attestations must be stored outside every sealed run directory",
        ));
    }
    Ok(PreparedAttestationOutput {
        display_path: output,
        parent: parent_handle,
        file_name,
    })
}

#[cfg(not(target_os = "linux"))]
fn prepare_attestation_output(
    _output: PathBuf,
    _runs_root: &Path,
) -> Result<PreparedAttestationOutput, CliError> {
    Err(CliError::usage(
        "attestation publication is supported only on Linux, where the checked output directory can remain pinned through publication; authenticate remains portable",
    ))
}

fn attestation_temp_dir(tag: &str) -> Result<PathBuf, CliError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CliError::infrastructure(error.to_string()))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "scirust-verify-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).map_err(|error| {
        CliError::infrastructure(format!("cannot create temporary directory: {error}"))
    })?;
    Ok(path)
}

#[cfg(target_os = "linux")]
fn write_attestation(
    output: &PreparedAttestationOutput,
    bytes: &[u8],
    force: bool,
) -> Result<(), CliError> {
    let path = descriptor_path(&output.parent).join(&output.file_name);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CliError::usage(format!(
                "attestation output `{}` is not a regular file",
                output.display_path.display()
            )));
        }
        if !force {
            return Err(CliError::usage(format!(
                "attestation output `{}` already exists; pass --force to replace it",
                output.display_path.display()
            )));
        }
    }

    // Keep the complete envelope in an unnamed inode until publication. A
    // same-UID process watching the output directory cannot open or mutate it
    // before the final link makes the fully synced bytes visible.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_TMPFILE | nix::libc::O_CLOEXEC)
        .mode(0o600)
        .open(descriptor_path(&output.parent))
        .map_err(|error| {
            CliError::infrastructure(format!(
                "cannot create unnamed temporary attestation: {error}"
            ))
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            CliError::infrastructure(format!("cannot persist attestation: {error}"))
        })?;
    let opened_metadata = file.metadata().map_err(|error| {
        CliError::infrastructure(format!("cannot inspect temporary attestation: {error}"))
    })?;

    if force {
        // Removing first preserves the unnamed-inode guarantee: the new inode
        // is linked directly at the destination and is never exposed through a
        // staging pathname. A racing creator makes linkat fail closed.
        match unlinkat(
            &output.parent,
            output.file_name.as_os_str(),
            UnlinkatFlags::NoRemoveDir,
        ) {
            Ok(()) => {}
            Err(nix::errno::Errno::ENOENT) => {}
            Err(error) => {
                return Err(CliError::infrastructure(format!(
                    "cannot replace attestation `{}`: {error}",
                    output.display_path.display()
                )));
            }
        }
    }

    let source_path = descriptor_path(&file);
    if let Err(error) = linkat(
        AT_FDCWD,
        &source_path,
        &output.parent,
        output.file_name.as_os_str(),
        AtFlags::AT_SYMLINK_FOLLOW,
    ) {
        let message = if error == nix::errno::Errno::EEXIST && !force {
            format!(
                "attestation output `{}` already exists; pass --force to replace it",
                output.display_path.display()
            )
        } else {
            format!(
                "cannot publish attestation `{}`: {error}",
                output.display_path.display()
            )
        };
        return Err(if error == nix::errno::Errno::EEXIST && !force {
            CliError::usage(message)
        } else {
            CliError::infrastructure(message)
        });
    }

    let published_metadata = fs::symlink_metadata(&path).map_err(|error| {
        CliError::infrastructure(format!(
            "cannot verify published attestation `{}`: {error}",
            output.display_path.display()
        ))
    })?;
    if !published_metadata.is_file()
        || opened_metadata.dev() != published_metadata.dev()
        || opened_metadata.ino() != published_metadata.ino()
    {
        return Err(CliError::infrastructure(
            "published attestation does not match the opened unnamed inode",
        ));
    }
    output.parent.sync_all().map_err(|error| {
        CliError::infrastructure(format!(
            "cannot persist attestation directory `{}`: {error}",
            output.display_path.display()
        ))
    })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_attestation(
    output: &PreparedAttestationOutput,
    _bytes: &[u8],
    _force: bool,
) -> Result<(), CliError> {
    Err(CliError::usage(format!(
        "attestation publication for `{}` is supported only on Linux",
        output.display_path.display()
    )))
}

fn attest(
    run: &str,
    principal: &str,
    identity: &Path,
    output: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<ExitCode, CliError> {
    if principal.trim().is_empty() || principal.chars().any(char::is_whitespace) {
        return Err(CliError::usage(
            "principal must be a non-empty OpenSSH allowed-signers principal without whitespace",
        ));
    }
    let (root, store) = open_run(run)?;
    let (bundle, sealed_files) = store
        .verify_integrity_snapshot()
        .map_err(|error| CliError::not_found(format!("integrity verification failed: {error}")))?;
    let runs_root = root.join(".scirust-verify").join("runs");
    let output_path = output.unwrap_or_else(|| {
        root.join(".scirust-verify")
            .join("attestations")
            .join(format!("{run}.json"))
    });
    let output_path = if output_path.is_absolute() {
        output_path
    } else {
        current_dir().join(output_path)
    };
    let output = prepare_attestation_output(output_path, &runs_root)?;
    let identity = identity.canonicalize().map_err(|error| {
        CliError::usage(format!(
            "cannot resolve signing identity `{}`: {error}",
            identity.display()
        ))
    })?;

    let signed_payload = signed_attestation_payload(principal, &bundle);
    let mut child = ProcessCommand::new("ssh-keygen")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(&identity)
        .arg("-n")
        .arg(SSHSIG_NAMESPACE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CliError::infrastructure(format!("cannot execute ssh-keygen: {error}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| CliError::infrastructure("ssh-keygen stdin unavailable"))?
        .write_all(&signed_payload)
        .map_err(|error| {
            CliError::infrastructure(format!("cannot feed signed payload: {error}"))
        })?;
    let sign = child.wait_with_output().map_err(|error| {
        CliError::infrastructure(format!("cannot wait for ssh-keygen: {error}"))
    })?;
    if !sign.status.success() {
        return Err(CliError::infrastructure(format!(
            "ssh-keygen refused to sign the bundle: {}",
            String::from_utf8_lossy(&sign.stderr).trim()
        )));
    }
    let signature = String::from_utf8(sign.stdout).map_err(|error| {
        CliError::infrastructure(format!(
            "ssh-keygen did not publish a UTF-8 signature: {error}"
        ))
    })?;
    let bundle_digest = Digest::sha256_hex(&bundle).value;
    let envelope = serde_json::json!({
        "schema_version": 1,
        "kind": "scirust-verify-detached-sshsig",
        "run_id": run,
        "bundle_sha256": bundle_digest,
        "namespace": SSHSIG_NAMESPACE,
        "signed_payload": "principal-and-exact-bundle-v1",
        "principal": principal,
        "signature": signature,
        "claims": {
            "integrity": "verified_before_signing",
            "authenticity": "unevaluated_until_external_trust_policy_verification",
            "qualification": "not_evaluated"
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|error| CliError::infrastructure(error.to_string()))?;
    bytes.push(b'\n');
    write_attestation(&output, &bytes, force)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "run_id": run,
                "attestation": &output.display_path,
                "bundle_sha256": bundle_digest,
                "principal": principal,
                "integrity": {"status": "verified", "sealed_files": sealed_files},
                "authenticity": {"status": "unevaluated"},
                "qualification": {"status": "not_evaluated"}
            })
        );
    } else {
        println!(
            "published detached attestation: {}",
            output.display_path.display()
        );
        println!("integrity: verified ({sealed_files} sealed files)");
        println!(
            "authenticity: unevaluated until checked against an external allowed-signers file"
        );
        println!("qualification: not evaluated by signing");
    }
    Ok(ExitCode::SUCCESS)
}

fn envelope_string<'a>(envelope: &'a serde_json::Value, field: &str) -> Result<&'a str, CliError> {
    envelope
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CliError::usage(format!("attestation envelope lacks string field `{field}`"))
        })
}

fn authenticate(
    run: &str,
    envelope_path: &Path,
    allowed_signers: &Path,
    json: bool,
) -> Result<ExitCode, CliError> {
    let (root, store) = open_run(run)?;
    let (bundle, sealed_files) = store
        .verify_integrity_snapshot()
        .map_err(|error| CliError::not_found(format!("integrity verification failed: {error}")))?;
    let envelope_bytes = read_attestation_envelope(envelope_path)?;
    let envelope: serde_json::Value = serde_json::from_slice(&envelope_bytes)
        .map_err(|error| CliError::usage(format!("invalid attestation envelope: {error}")))?;
    if envelope
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || envelope_string(&envelope, "kind")? != "scirust-verify-detached-sshsig"
    {
        return Err(CliError::usage("unsupported attestation envelope"));
    }
    if envelope_string(&envelope, "run_id")? != run
        || envelope_string(&envelope, "namespace")? != SSHSIG_NAMESPACE
        || envelope_string(&envelope, "signed_payload")? != "principal-and-exact-bundle-v1"
    {
        return Err(CliError::usage(
            "attestation run identity or namespace does not match the requested dossier",
        ));
    }
    let expected_digest = envelope_string(&envelope, "bundle_sha256")?;
    let actual_digest = Digest::sha256_hex(&bundle).value;
    if expected_digest != actual_digest {
        return Err(CliError::not_found(
            "attestation bundle digest does not match the integrity-verified dossier",
        ));
    }
    let principal = envelope_string(&envelope, "principal")?;
    let signature = envelope_string(&envelope, "signature")?;

    let trust_root = allowed_signers.canonicalize().map_err(|error| {
        CliError::usage(format!(
            "cannot resolve allowed-signers trust root `{}`: {error}",
            allowed_signers.display()
        ))
    })?;
    let verifier_root = root
        .join(".scirust-verify")
        .canonicalize()
        .map_err(|error| CliError::infrastructure(error.to_string()))?;
    if trust_root.starts_with(&verifier_root) {
        return Err(CliError::usage(
            "allowed-signers trust root must be configured independently outside .scirust-verify",
        ));
    }

    let temporary = attestation_temp_dir("verify")?;
    let signature_path = temporary.join("bundle.sshsig");
    fs::write(&signature_path, signature.as_bytes()).map_err(|error| {
        CliError::infrastructure(format!("cannot stage detached signature: {error}"))
    })?;
    let mut child = ProcessCommand::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&trust_root)
        .arg("-I")
        .arg(principal)
        .arg("-n")
        .arg(SSHSIG_NAMESPACE)
        .arg("-s")
        .arg(&signature_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CliError::infrastructure(format!("cannot execute ssh-keygen: {error}")))?;
    let signed_payload = signed_attestation_payload(principal, &bundle);
    child
        .stdin
        .take()
        .ok_or_else(|| CliError::infrastructure("ssh-keygen stdin unavailable"))?
        .write_all(&signed_payload)
        .map_err(|error| CliError::infrastructure(format!("cannot feed signed bundle: {error}")))?;
    let verification = child.wait_with_output().map_err(|error| {
        CliError::infrastructure(format!("cannot wait for ssh-keygen: {error}"))
    })?;
    let _ = fs::remove_dir_all(&temporary);
    let authenticated = verification.status.success();
    let provenance_status = if authenticated {
        "signed_record"
    } else {
        "unverified"
    };
    let provenance_reason = if authenticated {
        "the signer authenticated the sealed provenance record; the environment can still lie"
    } else {
        "the detached signature was not accepted; no signer provenance is established"
    };
    let document = serde_json::json!({
        "run_id": run,
        "bundle_sha256": actual_digest,
        "integrity": {"status": "verified", "sealed_files": sealed_files},
        "authenticity": {
            "status": if authenticated { "verified" } else { "failed" },
            "principal": principal,
            "namespace": SSHSIG_NAMESPACE,
            "trust_root": trust_root,
        },
        "execution_provenance": {
            "status": provenance_status,
            "reason": provenance_reason
        },
        "qualification": {
            "status": "not_evaluated",
            "reason": "authorship and integrity do not re-execute checks or upgrade imported producer claims"
        }
    });
    if json {
        println!("{document}");
    } else {
        println!("integrity: verified ({sealed_files} sealed files)");
        println!(
            "authenticity: {} for principal {principal}",
            if authenticated { "verified" } else { "failed" }
        );
        if authenticated {
            println!("execution provenance: signed record (not independently re-executed)");
        } else {
            println!("execution provenance: unverified (signature not accepted)");
        }
        println!("qualification: not evaluated");
    }
    Ok(if authenticated {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn is_terminal_json_default() -> bool {
    false // human-readable Markdown is the default when neither flag is set
}

fn replay(run: &str, strict: bool, json: bool) -> Result<ExitCode, CliError> {
    let (root, store) = open_run(run)?;
    let original_doc = store
        .read_run_document()
        .map_err(|e| CliError::usage(e.to_string()))?;
    let manifest_text = store
        .read_text("manifest-used.json")
        .map_err(|e| CliError::usage(format!("stored manifest missing: {e}")))?;
    let manifest: Manifest = serde_json::from_str(&manifest_text)
        .map_err(|e| CliError::usage(format!("stored manifest unreadable: {e}")))?;
    let artifact = store
        .read_artifact()
        .map_err(|e| CliError::usage(e.to_string()))?;
    let project_root = artifact.path.clone();
    drop(store);

    // Replay always creates a NEW run; the original bundle stays untouched.
    // New runs land next to the original one.
    let opts = VerifyOptions {
        project_root,
        output_root: Some(root.join(".scirust-verify")),
        cli_profile: manifest.verification.profile.clone(),
        target: manifest.verification.targets.first().cloned(),
        strict,
        replay_of: Some(original_doc.run_id.clone()),
    };

    let registry = build_registry(&manifest);
    match pipeline::run_verify(&registry, &opts) {
        Ok(outcome) => {
            if json {
                let doc = serde_json::json!({
                    "replay_of": original_doc.run_id.to_string(),
                    "new_run_id": outcome.run_id.to_string(),
                    "overall_verdict": outcome.verdict.label(),
                });
                println!("{doc}");
            } else {
                println!("replayed {} as {}", original_doc.run_id, outcome.run_id);
                println!("overall verdict: {}", outcome.verdict.label());
            }
            Ok(if outcome.verdict.exit_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Err(pipeline::PipelineError::Manifest(e)) => Err(CliError::usage(e.to_string())),
        Err(e) => {
            eprintln!("internal error: {e}");
            Err(CliError::usage("replay aborted"))
        }
    }
}

fn diff(run_a: &str, run_b: &str) -> Result<ExitCode, CliError> {
    let (root, _) = open_run(run_a)?;
    let runs = runs_root_for(&root);
    let sa = runs
        .open(run_a)
        .map_err(|e| CliError::usage(e.to_string()))?;
    let sb = runs
        .open(run_b)
        .map_err(|e| CliError::usage(e.to_string()))?;

    let da = run_summary(&sa).map_err(|e| CliError::usage(e.to_string()))?;
    let db = run_summary(&sb).map_err(|e| CliError::usage(e.to_string()))?;

    let mut lines = Vec::new();
    push_diff_line(&mut lines, "commit", &da.commit, &db.commit);
    push_diff_line(&mut lines, "worktree_dirty", &da.dirty, &db.dirty);
    push_diff_line(&mut lines, "rustc", &da.rustc, &db.rustc);
    push_diff_line(&mut lines, "target", &da.target, &db.target);
    push_diff_line(
        &mut lines,
        "overall_verdict",
        &Some(da.verdict.clone()),
        &Some(db.verdict.clone()),
    );

    // Claim-level comparison.
    for claim in da
        .claims
        .keys()
        .chain(db.claims.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let va = da.claims.get(claim);
        let vb = db.claims.get(claim);
        match (va, vb) {
            (Some(a), Some(b)) if a != b => {
                lines.push(format!("changed   claim {claim}: {a} -> {b}"));
            }
            (Some(_), None) => lines.push(format!("removed   claim {claim}")),
            (None, Some(b)) => lines.push(format!("added     claim {claim}: {b}")),
            (Some(_), Some(_)) => {}
            (None, None) => unreachable!(),
        }
    }

    if lines.is_empty() {
        println!("runs {run_a} and {run_b} are equivalent in compared dimensions.");
    } else {
        println!("diff {run_a} -> {run_b}:");
        for l in lines {
            println!("  {l}");
        }
    }

    // Exit 0 regardless of differences: diff is informational.
    Ok(ExitCode::SUCCESS)
}

struct RunSummary {
    commit: Option<String>,
    dirty: Option<String>,
    rustc: Option<String>,
    target: Option<String>,
    verdict: String,
    claims: std::collections::BTreeMap<String, String>,
}

fn run_summary(store: &scirust_verify_store::RunStore) -> Result<RunSummary, String> {
    let prov_text = store
        .read_text("provenance.json")
        .map_err(|e| e.to_string())?;
    let prov: serde_json::Value = serde_json::from_str(&prov_text).map_err(|e| e.to_string())?;
    let env_text = store
        .read_text("environment.json")
        .map_err(|e| e.to_string())?;
    let env: serde_json::Value = serde_json::from_str(&env_text).map_err(|e| e.to_string())?;
    let eval_text = store
        .read_text("evaluations.json")
        .map_err(|e| e.to_string())?;
    let evals: serde_json::Value = serde_json::from_str(&eval_text).map_err(|e| e.to_string())?;
    let rep_text = store.read_text("report.json").map_err(|e| e.to_string())?;
    let report: serde_json::Value = serde_json::from_str(&rep_text).map_err(|e| e.to_string())?;

    let mut claims = std::collections::BTreeMap::new();
    for entry in evals
        .get("evaluations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let ev = entry.get("evaluation").cloned().unwrap_or_default();
        if let (Some(id), Some(verdict)) = (
            ev.get("claim_id").and_then(|v| v.as_str()),
            ev.get("verdict").and_then(|v| v.as_str()),
        ) {
            claims.insert(id.to_owned(), verdict.to_owned());
        }
    }

    Ok(RunSummary {
        commit: prov
            .pointer("/git/commit")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        dirty: prov
            .pointer("/git/dirty_count")
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string()),
        rustc: env
            .pointer("/toolchain/rustc_version")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        target: env
            .pointer("/toolchain/target_triple")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        verdict: report
            .get("overall_verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_owned(),
        claims,
    })
}

fn push_diff_line(out: &mut Vec<String>, label: &str, a: &Option<String>, b: &Option<String>) {
    match (a, b) {
        (Some(a), Some(b)) if a == b => out.push(format!("unchanged {label}: {a}")),
        (Some(a), Some(b)) => out.push(format!("changed   {label}: {a} -> {b}")),
        (Some(a), None) => out.push(format!("removed   {label}: had `{a}`")),
        (None, Some(b)) => out.push(format!("added     {label}: now `{b}`")),
        (None, None) => {}
    }
}

fn ingest_scirust(
    bundle: PathBuf,
    project: PathBuf,
    output: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode, CliError> {
    let opts = scirust_ingest::IngestOptions {
        bundle_dir: bundle,
        project_root: project,
        output_root: output.map(|o| o.join(".scirust-verify")),
    };
    let outcome = scirust_ingest::ingest(&opts).map_err(|e| CliError::usage(e.to_string()))?;
    if json {
        let doc = serde_json::json!({
            "tool": TOOL_IDENTITY,
            "run_id": outcome.run_id.to_string(),
            "overall_verdict": outcome.verdict_label,
            "claims": outcome.claims.iter().map(|(id, lvl, v)| serde_json::json!({
                "claim": id, "level": lvl, "verdict": v,
            })).collect::<Vec<_>>(),
        });
        println!("{doc}");
    } else {
        println!("ingested protocol bundle as run {}", outcome.run_id);
        for (id, level, verdict) in &outcome.claims {
            println!("  [{level:>13}] {id:<44} {verdict}");
        }
        println!("overall verdict: {}", outcome.verdict_label);
    }
    Ok(
        if outcome.verdict_label == "PASS" || outcome.verdict_label == "PASS_WITH_GAPS" {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        },
    )
}

fn doctor() -> Result<ExitCode, CliError> {
    struct Tool {
        name: &'static str,
        program: &'static str,
        args: &'static [&'static str],
        required: bool,
    }
    let tools = [
        Tool {
            name: "git",
            program: "git",
            args: &["--version"],
            required: true,
        },
        Tool {
            name: "cargo",
            program: "cargo",
            args: &["--version"],
            required: true,
        },
        Tool {
            name: "rustc",
            program: "rustc",
            args: &["--version"],
            required: true,
        },
        Tool {
            name: "rustfmt",
            program: "rustfmt",
            args: &["--version"],
            required: false,
        },
        Tool {
            name: "clippy",
            program: "clippy-driver",
            args: &["--version"],
            required: false,
        },
        Tool {
            name: "cargo-deny",
            program: "cargo-deny",
            args: &["--version"],
            required: false,
        },
    ];

    let mut hard_missing = false;
    println!("SciRust-Verify doctor — {}", TOOL_IDENTITY);
    for t in tools {
        let installed = scirust_verify_runner::which(t.program).is_some();
        let version = scirust_verify_core::provenance::probe(
            Path::new("."),
            [t.program]
                .iter()
                .copied()
                .chain(t.args.iter().copied())
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .map(|(_, s)| s.lines().next().unwrap_or("").to_owned())
        .unwrap_or_default();
        let status = if installed {
            "OK "
        } else if t.required {
            "MISSING"
        } else {
            "absent"
        };
        println!(
            "  [{status:^7}] {:<12} {}",
            t.name,
            if version.is_empty() { "-" } else { &version }
        );
        if !installed && t.required {
            hard_missing = true;
        }
        let _ = t.required;
    }

    if hard_missing {
        println!("required tooling missing; basic verification cannot run.");
        return Ok(ExitCode::from(1));
    }
    println!("notes: GPU runtime probes are not implemented in this version (UNSUPPORTED).");
    Ok(ExitCode::SUCCESS)
}

fn schema() -> Result<ExitCode, CliError> {
    let entries = [
        ("run.json", "RunDocument: lifecycle state machine of a run"),
        ("artifact.json", "Artifact identity + source identity"),
        (
            "environment.json",
            "EnvironmentSnapshot (host/toolchain/tools)",
        ),
        (
            "provenance.json",
            "ProvenanceDocument (git, tree digest, probes)",
        ),
        (
            "plan.json",
            "PlanDocument: executed checks + canonical digest",
        ),
        ("claims.json", "ClaimsDocument: registered claims"),
        ("executions.json", "ExecutionsDocument: per-check records"),
        (
            "evaluations.json",
            "Claim evaluations with requirement levels",
        ),
        (
            "evidence/ev-NNNN.json",
            "Evidence objects (immutable once sealed)",
        ),
        ("bundle.json", "Integrity manifest sealing every file"),
        ("report.json / report.md", "Regenerable reports"),
    ];
    println!(
        "document catalog (schema_version = {}):",
        scirust_verify_model::SCHEMA_VERSION
    );
    for (name, desc) in entries {
        println!("  {:<24} {desc}", name);
    }
    Ok(ExitCode::SUCCESS)
}
