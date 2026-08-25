//! Report rendering from persisted run documents.
//!
//! Reports are *derived*: they never scrape their own Markdown, and both
//! formats are regenerated from the same structured bundle contents.
//! Regeneration is possible at any time via `scirust-verify report <run>`.

#![deny(missing_docs)]

use std::collections::BTreeMap;

use scirust_verify_model::{DossierVerdict, RequirementLevel};
use scirust_verify_store::RunStore;
use thiserror::Error;

/// Contextual inputs for rendering.
pub struct ReportInputs {
    /// Tool version string recorded in the report header.
    pub tool_version: String,
    /// Schema version of the emitted report.
    pub schema_version: u64,
    /// Providers detected during planning: (name, note).
    pub detected_providers: Vec<(String, String)>,
    /// Whether strict mode was requested.
    pub strict: bool,
}

/// Rendering failures.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct ReportError(pub String);

struct Loaded {
    run_doc_json: serde_json::Value,
    artifact: serde_json::Value,
    environment: serde_json::Value,
    provenance: serde_json::Value,
    plan: serde_json::Value,
    claims: serde_json::Value,
    executions: Vec<serde_json::Value>,
    evidence_index: Vec<serde_json::Value>,
    evaluations: Vec<(String, serde_json::Value)>,
}

fn load(store: &RunStore) -> Result<Loaded, ReportError> {
    let read = |name: &str| -> Result<serde_json::Value, ReportError> {
        let text = store
            .read_text(name)
            .map_err(|e| ReportError(format!("{name}: {e}")))?;
        serde_json::from_str(&text).map_err(|e| ReportError(format!("{name}: {e}")))
    };
    let run_doc = store
        .read_run_document()
        .map_err(|e| ReportError(e.to_string()))?;

    // Executions + evidence are structured APIs; evaluations are JSON docs.
    let executions = store
        .read_executions()
        .map_err(|e| ReportError(e.to_string()))?
        .into_iter()
        .map(|e| serde_json::to_value(e).map_err(|e| ReportError(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;

    let mut evidence_index = Vec::new();
    for ev in store
        .read_all_evidence()
        .map_err(|e| ReportError(e.to_string()))?
    {
        let v = serde_json::to_value(&ev).map_err(|e| ReportError(e.to_string()))?;
        evidence_index.push(v);
    }

    let evaluations_raw = read("evaluations.json")?;
    let evaluations = evaluations_raw
        .get("evaluations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            let level = entry.get("requirement_level")?.as_str()?.to_owned();
            Some((level, entry.get("evaluation")?.clone()))
        })
        .collect();

    Ok(Loaded {
        run_doc_json: serde_json::to_value(&run_doc).map_err(|e| ReportError(e.to_string()))?,
        artifact: read("artifact.json")?,
        environment: read("environment.json")?,
        provenance: read("provenance.json")?,
        plan: read("plan.json")?,
        claims: read("claims.json")?,
        executions,
        evidence_index,
        evaluations,
    })
}

/// Computes limitations from bundle facts. Mandatory in every report:
/// incomplete coverage is never hidden.
pub(crate) fn derive_limitations(loaded: &Loaded) -> Vec<String> {
    let mut limits = Vec::new();

    if let Some(git) = loaded.provenance.get("git") {
        let dirty = git.get("dirty_count").and_then(|v| v.as_u64()).unwrap_or(0);
        if dirty > 0 {
            limits.push(format!(
                "source worktree had {dirty} uncommitted change(s); results refer to that exact state"
            ));
        }
    } else {
        limits.push(
            "no Git identity available; source identified only by tree digest (if present)"
                .to_owned(),
        );
    }

    // Cross-platform honesty: determinism verified on one host only.
    let has_determinism_verified = loaded.evaluations.iter().any(|(lvl, ev)| {
        ev.get("verdict").and_then(|v| v.as_str()) == Some("verified")
            && lvl == "required"
            && ev
                .get("claim_id")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains("determin"))
    });
    let any_determinism_claim = loaded.evaluations.iter().any(|(_, ev)| {
        ev.get("claim_id")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains("determin"))
    });
    if any_determinism_claim {
        limits.push(
            "determinism evidence covers this host/toolchain only; cross-platform determinism was NOT established".to_owned(),
        );
        if !has_determinism_verified {
            // still honest: claim exists but not fully verified
            limits.push(
                "not all determinism claims reached VERIFIED status under the recorded scope"
                    .to_owned(),
            );
        }
    }

    // Numeric sampling honesty.
    let numeric_claims = loaded.evaluations.iter().any(|(_, ev)| {
        ev.get("claim_id")
            .and_then(|c| c.as_str())
            .is_some_and(|c| c.contains("numeric") || c.contains("oracle"))
    });
    if numeric_claims {
        limits.push(
            "numeric/oracle checks exercised a finite sample of inputs; they do not establish the property over an infinite domain".to_owned(),
        );
    }

    // Skipped / unsupported / failed optional work surfaces as limitation.
    for (level, ev) in &loaded.evaluations {
        let verdict = ev.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        let claim = ev
            .get("claim_id")
            .and_then(|c| c.as_str())
            .unwrap_or("?")
            .to_owned();
        match verdict {
            "skipped" => limits.push(format!(
                "`{claim}` ({level}) was skipped — implementation exists but could not run here"
            )),
            "unsupported" => limits.push(format!(
                "`{claim}` ({level}) was unsupported — no implementation exists in this version"
            )),
            "failed" if level != "required" => {
                limits.push(format!(
                    "`{claim}` ({level}) failed; it does not gate the overall verdict"
                ));
            }
            _ => {}
        }
    }

    if loaded
        .environment
        .get("toolchain")
        .and_then(|t| t.get("target_triple"))
        .is_none()
    {
        limits.push("target triple was not pinned; host default target was used".to_owned());
    }

    limits.sort();
    limits.dedup();
    limits
}

fn overall_verdict(loaded: &Loaded) -> DossierVerdict {
    // The gate is recomputed here from persisted evaluations so reports can
    // be regenerated without re-running checks.
    let items: Vec<scirust_verify_model::GatingItem> = loaded
        .evaluations
        .iter()
        .filter_map(|(level, ev)| {
            let lvl: Option<RequirementLevel> = match level.as_str() {
                "required" => Some(RequirementLevel::Required),
                "recommended" => Some(RequirementLevel::Recommended),
                "optional" => Some(RequirementLevel::Optional),
                "informational" => Some(RequirementLevel::Informational),
                _ => None,
            };
            let verdict: scirust_verify_model::Verdict =
                serde_json::from_value(ev.get("verdict")?.clone()).ok()?;
            let lvl = lvl?;
            Some(scirust_verify_model::GatingItem {
                level: lvl,
                verdict,
            })
        })
        .collect();
    scirust_verify_model::aggregate_dossier_verdict(&items)
}

/// Renders the machine-readable `report.json`.
pub fn render_json(store: &RunStore, inputs: &ReportInputs) -> Result<String, ReportError> {
    let loaded = load(store)?;
    let verdict = overall_verdict(&loaded);
    let limitations = derive_limitations(&loaded);

    let doc = serde_json::json!({
        "schema_version": inputs.schema_version,
        "generated_by": inputs.tool_version,
        "generated_at_utc": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "run": loaded.run_doc_json,
        "overall_verdict": serde_json::to_value(&verdict).unwrap_or_default(),
        "strict_mode": inputs.strict,
        "detected_providers": inputs.detected_providers,
        "artifact": loaded.artifact,
        "provenance": loaded.provenance,
        "environment": loaded.environment,
        "plan": {
            "digest": loaded.plan.get("plan_digest"),
            "checks": loaded.plan.get("checks"),
        },
        "claims": loaded.claims.get("claims"),
        "claim_evaluations": loaded.evaluations.iter().map(|(lvl, ev)| serde_json::json!({
            "requirement_level": lvl,
            "evaluation": ev,
        })).collect::<Vec<_>>(),
        "executions": loaded.executions,
        "evidence_index": loaded.evidence_index,
        "limitations": limitations,
    });

    // BTreeMap-style ordering comes free from serde_json's sorted object keys
    // when canonicalizing; pretty print for human-diffable storage.
    let value: BTreeMap<String, serde_json::Value> =
        serde_json::from_value(doc).map_err(|e| ReportError(e.to_string()))?;
    serde_json::to_string_pretty(&value).map_err(|e| ReportError(e.to_string()))
}

fn json_str(v: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for step in path {
        cur = cur.get(step)?;
    }
    cur.as_str().map(str::to_owned)
}

fn fmt_level(level: &str) -> &'static str {
    match level {
        "required" => "REQUIRED",
        "recommended" => "RECOMMENDED",
        "optional" => "OPTIONAL",
        _ => "INFO",
    }
}

fn fmt_verdict(v: &str) -> &'static str {
    match v {
        "verified" => "VERIFIED",
        "failed" => "FAILED",
        "not_verified" => "NOT_VERIFIED",
        "skipped" => "SKIPPED",
        "unsupported" => "UNSUPPORTED",
        _other => "",
    }
}

/// Renders the human-readable `report.md`.
pub fn render_markdown(store: &RunStore, inputs: &ReportInputs) -> Result<String, ReportError> {
    let loaded = load(store)?;
    let verdict = overall_verdict(&loaded);
    let limitations = derive_limitations(&loaded);

    let mut md = String::new();
    md.push_str("# SciRust-Verify Evidence Report\n\n");
    md.push_str(&format!("- Generated by: {}\n", inputs.tool_version));
    md.push_str(&format!(
        "- Run: `{}` (state: {})\n",
        json_str(&loaded.run_doc_json, &["run_id"]).unwrap_or_default(),
        json_str(&loaded.run_doc_json, &["state"]).unwrap_or_default(),
    ));
    if let Some(replay_of) = json_str(&loaded.run_doc_json, &["replay_of"]) {
        md.push_str(&format!("- Replay of: `{replay_of}`\n"));
    }
    md.push_str(&format!("- **Overall Verdict: {}**\n\n", verdict.label()));

    md.push_str("## Artifact\n\n");
    md.push_str("```json\n");
    md.push_str(
        &serde_json::to_string_pretty(&loaded.artifact).map_err(|e| ReportError(e.to_string()))?,
    );
    md.push_str("\n```\n\n");

    md.push_str("## Source Identity & Provenance\n\n");
    if let Some(commit) = json_str(&loaded.provenance, &["git", "commit"]) {
        md.push_str(&format!("- Commit: `{commit}`\n"));
        if let Some(branch) = json_str(&loaded.provenance, &["git", "branch"]) {
            md.push_str(&format!("- Branch: `{branch}`\n"));
        }
        if let Some(count) = loaded
            .provenance
            .pointer("/git/dirty_count")
            .and_then(|v| v.as_u64())
        {
            md.push_str(&format!(
                "- Worktree: {}\n",
                if count == 0 { "clean" } else { "DIRTY" }
            ));
        }
    } else if let Some(digest) = json_str(&loaded.provenance, &["tree_digest", "value"]) {
        md.push_str(&format!(
            "- Content identity only; tree digest `{}…`\n",
            &digest[..16.min(digest.len())]
        ));
    }

    md.push_str("\n## Environment & Toolchain\n\n");
    if let Some(rustc) = json_str(&loaded.environment, &["toolchain", "rustc_version"]) {
        md.push_str(&format!("- rustc: {rustc}\n"));
    }
    if let Some(cargo) = json_str(&loaded.environment, &["toolchain", "cargo_version"]) {
        md.push_str(&format!("- cargo: {cargo}\n"));
    }
    if let Some(target) = json_str(&loaded.environment, &["toolchain", "target_triple"]) {
        md.push_str(&format!("- Target: {target}\n"));
    }
    if let Some(host) = json_str(&loaded.environment, &["host", "triple"]) {
        md.push_str(&format!("- Host: {host}\n"));
    }
    if let Some(flags) = json_str(&loaded.environment, &["toolchain", "rustflags"]) {
        md.push_str(&format!("- RUSTFLAGS: `{flags}`\n"));
    }

    if !inputs.detected_providers.is_empty() {
        md.push_str("\n## Verification Matrix\n\n");
        md.push_str("| Claim | Level | Verdict |\n|---|---|---|\n");
        for (level, ev) in &loaded.evaluations {
            let claim = ev.get("claim_id").and_then(|c| c.as_str()).unwrap_or("?");
            let v = ev.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
            md.push_str(&format!(
                "| `{claim}` | {} | {} |\n",
                fmt_level(level),
                fmt_verdict(v)
            ));
        }
    }

    // Cargo checks section when present.
    let cargo_execs: Vec<&serde_json::Value> = loaded
        .executions
        .iter()
        .filter(|e| {
            e.get("check_id")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .starts_with("cargo:")
        })
        .collect();
    if !cargo_execs.is_empty() {
        md.push_str("\n## Cargo Checks\n\n");
        for exec in cargo_execs {
            let id = exec.get("check_id").and_then(|c| c.as_str()).unwrap_or("?");
            let outcome = exec.get("outcome").and_then(|o| o.as_str()).unwrap_or("?");
            md.push_str(&format!("- `{id}`: {}\n", fmt_verdict(outcome)));
        }
    }

    // Determinism section when fingerprints exist.
    let fingerprint_obs: Vec<String> = loaded
        .evidence_index
        .iter()
        .filter_map(|ev| {
            let obs = ev.get("observations")?.as_array()?;
            Some(
                obs.iter()
                    .filter_map(|o| {
                        let name = o.get("name")?.as_str()?;
                        let kind = o.get("kind")?.as_str()?;
                        if kind.contains("fingerprint") {
                            Some(format!("- fingerprint `{name}`"))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect();
    if !fingerprint_obs.is_empty() {
        md.push_str("\n## Determinism Evidence\n\n");
        for line in fingerprint_obs {
            md.push_str(&line);
            md.push('\n');
        }
    }

    md.push_str("\n## Limitations\n\n");
    if limitations.is_empty() {
        md.push_str("_None derived._\n");
    } else {
        for l in limitations {
            md.push_str(&format!("- {l}\n"));
        }
    }

    md.push_str("\n## Reproduction\n\n");
    md.push_str(&format!(
        "```bash\nscirust-verify replay {}\nscirust-verify report {}\nscirust-verify diff  # against another run id\n```\n",
        json_str(&loaded.run_doc_json, &["run_id"]).unwrap_or_default(),
        json_str(&loaded.run_doc_json, &["run_id"]).unwrap_or_default(),
    ));

    md.push_str("\n## Evidence Index\n\n");
    for ev in &loaded.evidence_index {
        let id = ev.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let kind = ev.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        md.push_str(&format!("- `{id}` ({kind})\n"));
    }

    Ok(md)
}
