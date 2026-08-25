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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
use scirust_verify_model::TOOL_IDENTITY;
use scirust_verify_store::RunsRoot;

mod aggregate_cli;
mod artifacts_cli;
mod scirust_ingest;
mod signature_cli;

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
    /// Aggregate one claim across integrity-verified dossiers and assess scope coverage.
    Aggregate {
        /// Claim id or substring to match (e.g. `cross_process`).
        claim: String,
        /// Run ids to aggregate (at least one).
        runs: Vec<String>,
        /// Project root containing `.scirust-verify/runs`.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Minimum number of distinct normalized execution platforms required for scope certification.
        #[arg(long, default_value_t = 1)]
        min_platforms: usize,
        /// Exit 1 unless source/claim/platform scope is certified in addition to all verdicts being VERIFIED.
        #[arg(long)]
        require_scope: bool,
    },
    /// Generate a fresh Ed25519 dossier-signing keypair.
    Keygen {
        /// Private-key JSON path. Never printed; mode 0600 on Unix.
        #[arg(long)]
        private_key: PathBuf,
        /// Public-key JSON path.
        #[arg(long)]
        public_key: PathBuf,
        /// Overwrite existing regular files (symbolic links remain rejected).
        #[arg(long)]
        force: bool,
    },
    /// Sign a finalized, integrity-valid evidence dossier with Ed25519.
    Sign {
        /// Run id to sign.
        run: String,
        /// Private signing key generated by `keygen`.
        #[arg(long)]
        private_key: PathBuf,
        /// Project root containing `.scirust-verify`.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Replace an existing detached signature for this run/key.
        #[arg(long)]
        force: bool,
    },
    /// Verify a detached dossier signature against an explicit public key.
    VerifySignature {
        /// Run id whose finalized bundle is being authenticated.
        run: String,
        /// Public key whose provenance the caller has chosen to trust.
        #[arg(long)]
        public_key: PathBuf,
        /// Explicit detached signature path; defaults to the key-id-derived path.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// Project root containing `.scirust-verify`.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// Verify a SciCapsule v1 bundle (manifest schema + payload integrity).
    VerifyCapsule {
        /// Directory containing manifest.json and payloads.
        bundle: PathBuf,
        /// Alternative output root for `.scirust-verify`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Ingest a Forge candidate envelope as an integrity attestation.
    IngestForge {
        /// Path to the candidate envelope JSON.
        envelope: PathBuf,
        /// Alternative output root for `.scirust-verify`.
        #[arg(long)]
        output: Option<PathBuf>,
    },
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
        Command::Replay { run, strict } => replay(&run, strict, cli.json),
        Command::Diff { run_a, run_b } => diff(&run_a, &run_b),
        Command::Aggregate {
            claim,
            runs,
            project,
            min_platforms,
            require_scope,
        } => {
            let root = match project {
                Some(p) => p,
                None => locate_runs_root()?,
            };
            let outcome = aggregate_cli::execute(&aggregate_cli::AggregateOptions {
                claim_pattern: &claim,
                runs: &runs,
                project: &root,
                min_platforms,
            })
            .map_err(|error| CliError {
                message: error.to_string(),
                exit_code: error.exit_code(),
            })?;
            if cli.json {
                println!("{}", outcome.document);
            } else {
                print!("{}", outcome.human);
            }
            let established = if require_scope {
                outcome.scope_certified
            } else {
                outcome.all_verified
            };
            Ok(if established {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Doctor => doctor(),
        Command::Schema => schema(),
        Command::Keygen {
            private_key,
            public_key,
            force,
        } => signature_cli::keygen(private_key, public_key, force, cli.json),
        Command::Sign {
            run,
            private_key,
            project,
            force,
        } => signature_cli::sign(&run, private_key, project, force, cli.json),
        Command::VerifySignature {
            run,
            public_key,
            signature,
            project,
        } => signature_cli::verify_signature(&run, public_key, signature, project, cli.json),
        Command::VerifyCapsule { bundle, output } => {
            match artifacts_cli::verify_capsule(&artifacts_cli::IngestOptions {
                input: bundle,
                project_root: current_dir(),
                output_root: output.map(|o| o.join(".scirust-verify")),
            }) {
                Ok(o) => Ok(artifact_exit_ok(&o, cli.json)),
                Err(e) => {
                    eprintln!("error: {e}");
                    Ok(ExitCode::from(2))
                }
            }
        }
        Command::IngestForge { envelope, output } => {
            match artifacts_cli::ingest_forge(&artifacts_cli::IngestOptions {
                input: envelope,
                project_root: current_dir(),
                output_root: output.map(|o| o.join(".scirust-verify")),
            }) {
                Ok(o) => Ok(artifact_exit_ok(&o, cli.json)),
                Err(e) => {
                    eprintln!("error: {e}");
                    Ok(ExitCode::from(2))
                }
            }
        }
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
        if !prepared.manifest.verification.targets.is_empty() {
            println!(
                "  targets:  {}",
                prepared.manifest.verification.targets.join(", ")
            );
        }
        if !prepared.manifest.verification.features.is_empty() {
            println!(
                "  features: {}",
                prepared.manifest.verification.features.join(",")
            );
        }
        println!(
            "  timeout:  {}s per check (default)",
            prepared.settings.timeout.as_secs()
        );
        println!();
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
                    let cwd_note = command
                        .cwd
                        .as_ref()
                        .map(|p| format!(" (cwd: {})", p.display()))
                        .unwrap_or_default();
                    println!(
                        "  command: {} {}{}",
                        command.program,
                        command.args.join(" "),
                        cwd_note
                    );
                }
                scirust_verify_model::CheckAction::Composite { engine, parameters } => {
                    println!("  engine:  {engine}");
                    let mut keys: Vec<_> = parameters.keys().collect();
                    keys.sort();
                    for k in keys {
                        println!("    {k}: {}", parameters[k].to_string().trim_matches('"'));
                    }
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
    push_diff_line(&mut lines, "plan_digest", &da.plan_digest, &db.plan_digest);

    // Check-set comparison: added / removed between plans.
    let removed: Vec<&String> = da
        .checks
        .iter()
        .filter(|c| !db.checks.contains(c))
        .collect();
    let added: Vec<&String> = db
        .checks
        .iter()
        .filter(|c| !da.checks.contains(c))
        .collect();
    for c in removed {
        lines.push(format!("removed   check {c}"));
    }
    for c in added {
        lines.push(format!("added     check {c}"));
    }

    // Limitation drift: coverage differences must be visible in diffs.
    if da.limitations != db.limitations {
        let only_a: Vec<&String> = da
            .limitations
            .iter()
            .filter(|l| !db.limitations.contains(l))
            .collect();
        let only_b: Vec<&String> = db
            .limitations
            .iter()
            .filter(|l| !da.limitations.contains(l))
            .collect();
        for l in only_a {
            lines.push(format!("removed   limitation: {l}"));
        }
        for l in only_b {
            lines.push(format!("added     limitation: {l}"));
        }
    } else if !da.limitations.is_empty() {
        lines.push(format!(
            "unchanged limitations: {} item(s)",
            da.limitations.len()
        ));
    }

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
    plan_digest: Option<String>,
    checks: Vec<String>,
    limitations: Vec<String>,
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
    let plan_text = store.read_text("plan.json").map_err(|e| e.to_string())?;
    let plan: serde_json::Value = serde_json::from_str(&plan_text).map_err(|e| e.to_string())?;
    let checks: Vec<String> = plan
        .get("checks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| c.get("id").and_then(|i| i.as_str()).map(str::to_owned))
        .collect();
    let limitations: Vec<String> = report
        .get("limitations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|l| l.as_str().map(str::to_owned))
        .collect();

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
        plan_digest: loaded_plan_digest(store).ok(),
        checks,
        limitations,
    })
}

fn loaded_plan_digest(store: &scirust_verify_store::RunStore) -> Result<String, String> {
    let text = store.read_text("plan.json").map_err(|e| e.to_string())?;
    let plan: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(plan
        .get("plan_digest")
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_owned())
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

fn artifact_exit_ok(outcome: &artifacts_cli::IngestOutcome, json: bool) -> ExitCode {
    if json {
        let doc = serde_json::json!({
            "run_id": outcome.run_id.to_string(),
            "overall_verdict": outcome.verdict_label,
            "claims": outcome.claims.iter().map(|(id, lvl, v)| serde_json::json!({
                "claim": id, "level": lvl, "verdict": v,
            })).collect::<Vec<_>>(),
        });
        println!("{doc}");
    } else {
        println!("run {}", outcome.run_id);
        for (id, level, verdict) in &outcome.claims {
            println!("  [{level:>13}] {id:<44} {verdict}");
        }
        println!("overall verdict: {}", outcome.verdict_label);
    }
    if outcome.verdict_label == "PASS" || outcome.verdict_label == "PASS_WITH_GAPS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
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
        (
            "signatures/<run>/<key-id>.json",
            "Detached Ed25519 signature metadata",
        ),
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
