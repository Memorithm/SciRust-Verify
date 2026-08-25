//! Determinism verification engine.
//!
//! Levels supported in V0.1:
//!
//! * **Level 1 — repeated execution**: same computation run repeatedly
//!   (in-process determinism is SciRust's own concern; here we observe).
//! * **Level 2 — independent processes**: each repetition is a fresh OS
//!   process; fingerprints must match bit-for-bit.
//! * **Level 3 — thread-count variation**: when configured, the engine sets
//!   the configured environment variable to each level and includes those
//!   runs in the comparison.
//! * **Level 4 — cross-platform**: never inferred from a single host. This
//!   engine only ever claims cross-process determinism for the recorded
//!   host/toolchain scope.
//!
//! Fingerprints establish output *identity*, not correctness.

#![deny(missing_docs)]

use std::collections::BTreeMap;

use chrono::Utc;
use scirust_verify_core::planning::{
    Detection, ExecutionContext, PipelineFailure, PlanContext, ProviderError, VerificationProvider,
};
use scirust_verify_model::{
    Check, CheckAction, CheckExecution, CheckId, CheckStatus, ClaimId, EvidenceKind,
    EvidenceStatus, Observation, ObservedValue, RequirementLevel, Verdict,
};
use scirust_verify_runner::{execute as run_command, CommandSpec};

/// Engine identifier used inside [`CheckAction::Composite`].
pub const ENGINE: &str = "determinism";

/// The determinism provider. Planned from `[determinism]` manifest config.
pub struct DeterminismProvider {
    /// Enable planning.
    pub enabled: bool,
    /// Independent runs to execute (>= 2).
    pub runs: u32,
    /// Program argv per run.
    pub program: Vec<String>,
    /// `stdout_digest` or `structured`.
    pub mode: String,
    /// Thread levels exercised via `thread_env`.
    pub thread_levels: Vec<u32>,
    /// Env var carrying the thread level.
    pub thread_env: Option<String>,
}

impl VerificationProvider for DeterminismProvider {
    fn name(&self) -> &'static str {
        "determinism"
    }

    fn detect(&self, _ctx: &scirust_verify_core::discovery::DiscoveryContext) -> Detection {
        if self.enabled && !self.program.is_empty() {
            Detection::Detected {
                note: format!(
                    "cross-process fingerprinting over {} independent runs",
                    self.runs + self.thread_levels.len() as u32
                ),
            }
        } else {
            Detection::NotDetected
        }
    }

    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError> {
        if !self.enabled || self.program.is_empty() {
            return Ok(Vec::new());
        }
        let mut parameters: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        parameters.insert("runs".into(), serde_json::json!(self.runs));
        parameters.insert("program".into(), serde_json::json!(self.program));
        parameters.insert("mode".into(), serde_json::json!(self.mode));
        if !self.thread_levels.is_empty() {
            parameters.insert(
                "thread_levels".into(),
                serde_json::json!(self.thread_levels),
            );
            parameters.insert(
                "thread_env".into(),
                serde_json::json!(self.thread_env.clone().unwrap_or_default()),
            );
        }
        let level = request
            .claim_levels
            .get("cross_process_deterministic")
            .copied()
            .unwrap_or(RequirementLevel::Optional);
        Ok(vec![Check {
            id: CheckId::new("determinism:cross-process"),
            provider: "determinism".into(),
            purpose: format!(
                "{} independent process executions produce identical canonical fingerprints",
                self.runs + self.thread_levels.len() as u32
            ),
            claims: vec![ClaimId::from("cross_process_deterministic")],
            requirement: level,
            action: CheckAction::Composite {
                engine: ENGINE.to_owned(),
                parameters,
            },
            timeout: request.default_timeout,
            stdout_limit_bytes: request.stdout_limit,
            stderr_limit_bytes: request.stderr_limit,
        }])
    }

    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, PipelineFailure> {
        let CheckAction::Composite { parameters, .. } = &check.action else {
            return Ok(CheckExecution::minimal(
                check.id.clone(),
                CheckStatus::Unsupported {
                    reason: "determinism engine executes composite checks only".into(),
                },
            ));
        };
        let runs = parameters
            .get("runs")
            .and_then(|v| v.as_u64())
            .unwrap_or(3)
            .max(2) as usize;
        let program: Vec<String> = parameters
            .get("program")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let mode = parameters
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("stdout_digest")
            .to_owned();

        // Build the run matrix: base runs + one per thread level.
        struct RunPlan {
            label: String,
            threads: Option<u32>,
        }
        let mut plans = Vec::new();
        for i in 1..=runs {
            plans.push(RunPlan {
                label: format!("run-{i}"),
                threads: None,
            });
        }
        if let Some(env_var) = parameters.get("thread_env").and_then(|v| v.as_str()) {
            if let Some(levels) = parameters.get("thread_levels").and_then(|v| v.as_array()) {
                for l in levels {
                    if let Some(l) = l.as_u64() {
                        plans.push(RunPlan {
                            label: format!("threads-{l}"),
                            threads: Some(l as u32),
                        });
                    }
                }
                let _ = env_var;
            }
        }

        let cwd = env.cwd_base.clone();
        let mut fingerprints: BTreeMap<String, String> = BTreeMap::new();
        let mut all_ok = true;
        let mut any_timeout = false;
        let mut successful_runs = 0usize;
        let mut run_evidence_ids = Vec::new();
        let mut notes = Vec::new();

        for plan in &plans {
            let Some((program_name, args_split)) = program.split_first() else {
                return Ok(CheckExecution::minimal(
                    check.id.clone(),
                    CheckStatus::Unsupported {
                        reason: "determinism program argv is empty".into(),
                    },
                ));
            };
            let mut spec = CommandSpec::new(program_name.clone(), cwd.clone())
                .args(args_split.iter().cloned());
            spec.timeout = check.timeout;
            spec.stdout_limit = check.stdout_limit_bytes.max(1);
            spec.stderr_limit = check.stderr_limit_bytes.max(1);
            spec.env.remove.push("__SVR_UNUSED__".into());
            if let (Some(var), Some(level)) = (
                parameters.get("thread_env").and_then(|v| v.as_str()),
                plan.threads,
            ) {
                spec = spec.env(var, level.to_string());
            }

            let record = run_command(&spec)?;
            let ok = record.succeeded();
            if record.timed_out() {
                any_timeout = true;
            }
            if ok {
                successful_runs += 1;
            } else {
                all_ok = false;
                notes.push(format!("{} did not exit cleanly", plan.label));
            }

            let stdout_path = format!("logs/determinism-{}.out.log", plan.label);
            let stderr_path = format!("logs/determinism-{}.err.log", plan.label);
            let mut payloads = BTreeMap::new();
            payloads.insert(stdout_path.clone(), record.stdout.data.clone());
            payloads.insert(stderr_path.clone(), record.stderr.data.clone());

            let ev_id = env.sink.next_id();
            let fingerprint = fingerprint_of(&mode, &record);
            fingerprints.insert(plan.label.clone(), fingerprint);

            let evidence = scirust_verify_model::Evidence::builder(
                ev_id.clone(),
                EvidenceKind::CommandExecution,
                "determinism-engine",
            )
            .artifact(env.artifact.clone())
            .scope({
                let mut s = env.scope.clone();
                s.threads = plan.threads;
                s.execution_mode = Some("independent-subprocess".to_owned());
                s
            })
            .status(if record.timed_out() {
                EvidenceStatus::TimedOut
            } else if ok {
                EvidenceStatus::Ok
            } else {
                EvidenceStatus::Failed
            })
            .observation(Observation::new(
                "exit_status",
                &plan.label,
                ObservedValue::Int(record.exit_code().unwrap_or(-1) as i64),
            ))
            .output(scirust_verify_model::Digest::sha256_hex(
                &record.stdout.data,
            ))
            .attachment(scirust_verify_model::Attachment {
                path: stdout_path,
                size_bytes: record.stdout.data.len() as u64,
                digest: scirust_verify_model::Digest::sha256_hex(&record.stdout.data),
                media_type: Some("text/plain; charset=utf-8".into()),
            })
            .attachment(scirust_verify_model::Attachment {
                path: stderr_path,
                size_bytes: record.stderr.data.len() as u64,
                digest: scirust_verify_model::Digest::sha256_hex(&record.stderr.data),
                media_type: Some("text/plain; charset=utf-8".into()),
            })
            .meta("timeout_ms", record.timeout_ms)
            .build();
            env.sink.add_evidence(evidence, &payloads)?;
            run_evidence_ids.push(ev_id);

            let _ = program_name;
        }

        // Derived comparison evidence — references the execution evidences it
        // was computed from (evidence graph `derived_from` links).
        let distinct: std::collections::BTreeSet<&String> = fingerprints.values().collect();
        let comparison_id = env.sink.next_id();
        let mut cmp_obs = vec![
            Observation::new(
                "fingerprint_run_count",
                check.id.as_str(),
                ObservedValue::UInt(fingerprints.len() as u64),
            ),
            Observation::new(
                "distinct_fingerprints",
                check.id.as_str(),
                ObservedValue::UInt(distinct.len() as u64),
            ),
        ];
        for (label, fp) in &fingerprints {
            cmp_obs.push(Observation::new(
                "fingerprint",
                label,
                ObservedValue::Text(fp.clone()),
            ));
        }
        let comparison = scirust_verify_model::Evidence::builder(
            comparison_id.clone(),
            EvidenceKind::Fingerprint,
            "determinism-engine",
        )
        .artifact(env.artifact.clone())
        .scope(env.scope.clone())
        .status(if all_ok && distinct.len() == 1 && successful_runs >= 2 {
            EvidenceStatus::Ok
        } else {
            EvidenceStatus::Failed
        })
        .observations(cmp_obs)
        .derived_from(run_evidence_ids.iter().cloned())
        .build();
        env.sink.add_evidence(comparison, &BTreeMap::new())?;

        let (outcome, summary): (Verdict, String) = if any_timeout {
            (
                Verdict::NotVerified,
                "at least one execution timed out; determinism could not be established".to_owned(),
            )
        } else if successful_runs < 2 {
            (
                Verdict::NotVerified,
                format!(
                    "only {successful_runs} of {} executions completed; insufficient evidence",
                    plans.len()
                ),
            )
        } else if distinct.len() == 1 {
            (
                Verdict::Verified,
                format!(
                    "{successful_runs} independent executions produced identical fingerprints under the recorded scope"
                ),
            )
        } else {
            (
                Verdict::Failed,
                format!(
                    "executions produced {distinct_len} distinct fingerprints (outputs diverged across processes)",
                    distinct_len = distinct.len()
                ),
            )
        };

        Ok(CheckExecution {
            check_id: check.id.clone(),
            started_at_utc: None,
            ended_at_utc: Some(Utc::now()),
            status: if all_ok {
                CheckStatus::Executed { exit_code: Some(0) }
            } else {
                CheckStatus::Executed { exit_code: Some(1) }
            },
            outcome,
            summary,
            observations: vec![],
            evidence_ids: {
                let mut ids = run_evidence_ids;
                ids.push(comparison_id);
                ids
            },
            notes,
        })
    }
}

fn fingerprint_of(mode: &str, record: &scirust_verify_runner::ExecutionRecord) -> String {
    match mode {
        "structured" => {
            // Canonical fingerprint over SVOP fingerprint observations only.
            match scirust_verify_numerics::parse_observations(&record.stdout_lossy()) {
                Ok(obs) => {
                    let mut canonical = String::new();
                    for o in &obs {
                        if let scirust_verify_numerics::ValidObservation::Fingerprint {
                            name,
                            value,
                        } = o
                        {
                            canonical.push_str(&format!("{name}={value}\n"));
                        }
                    }
                    scirust_verify_model::Digest::sha256_hex(canonical.as_bytes()).value
                }
                Err(_) => "unparseable-structured-output".to_owned(),
            }
        }
        _ => record.stdout_digest().value,
    }
}
