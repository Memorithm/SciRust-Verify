//! SciRust functional-acceptance protocol adapter.
//!
//! SciRust owns its internal acceptance (`scripts/test-protocol.sh`); this
//! adapter only *ingests* completed evidence bundles and normalizes them
//! into SciRust-Verify claims without flattening semantics:
//!
//! * source gate statuses (`PASS` / `FAIL` / `SKIP`) are preserved as-is,
//! * normalized verdicts map 1:1 (`PASS→Verified`, `FAIL→Failed`,
//!   `SKIP→Skipped`) — a skipped required gate never becomes verified,
//! * the original `summary.txt` is referenced by digest so normalization
//!   destroys no information.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::path::Path;

use scirust_verify_model::{Digest, Verdict};
use thiserror::Error;

/// Gate status exactly as reported by the SciRust protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    /// Gate ran and passed.
    Pass,
    /// Gate ran and failed.
    Fail,
    /// Gate skipped for missing prerequisites (never treated as pass).
    Skip,
}

impl GateStatus {
    /// Normalized SciRust-Verify verdict. The mapping is deliberately
    /// bijective with the source vocabulary: nothing is flattened.
    pub fn to_verdict(self) -> Verdict {
        match self {
            Self::Pass => Verdict::Verified,
            Self::Fail => Verdict::Failed,
            Self::Skip => Verdict::Skipped,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "PASS" => Some(Self::Pass),
            "FAIL" => Some(Self::Fail),
            "SKIP" => Some(Self::Skip),
            _ => None,
        }
    }
}

/// One gate line from `summary.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateResult {
    /// Gate id (e.g. `fmt`, `test`, `determinism`, `aarch64`).
    pub id: String,
    /// Source status.
    pub status: GateStatus,
    /// Whether the SciRust protocol treats the gate as required.
    pub required: bool,
    /// Recorded duration in seconds when present.
    pub duration_secs: Option<u64>,
    /// Free-form note from the protocol (kept verbatim).
    pub note: String,
}

/// Test tally recorded by the `test` gate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TestTally {
    /// Tests that passed.
    pub passed: u64,
    /// Tests that failed.
    pub failed: u64,
    /// Ignored tests.
    pub ignored: u64,
    /// Number of test groups.
    pub groups: u64,
}

/// Aggregate verdict of the whole protocol run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVerdict {
    /// All required gates green.
    Pass,
    /// Executed required gates green but some were skipped (coverage gaps).
    PassWithGaps,
    /// At least one required gate failed.
    Fail,
}

impl ProtocolVerdict {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "PASS" => Some(Self::Pass),
            "PASS_WITH_GAPS" => Some(Self::PassWithGaps),
            "FAIL" => Some(Self::Fail),
            _ => None,
        }
    }

    /// Coarse dossier-level verdict; per-gate nuance stays in [`GateResult`]s.
    pub fn to_dossier_verdict(self) -> scirust_verify_model::DossierVerdict {
        match self {
            Self::Pass => scirust_verify_model::DossierVerdict::Pass,
            // Gaps are coverage warnings, not failures — same contract as
            // SciRust-Verify's own policy engine.
            Self::PassWithGaps => scirust_verify_model::DossierVerdict::PassWithGaps,
            Self::Fail => scirust_verify_model::DossierVerdict::Fail,
        }
    }
}

/// Parsed `summary.txt`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolSummary {
    /// Commit the protocol ran against (`?` when unavailable).
    pub commit: Option<String>,
    /// Branch name when available.
    pub branch: Option<String>,
    /// UTC timestamp string from the protocol.
    pub timestamp: Option<String>,
    /// Workspace package count.
    pub packages: Option<u64>,
    /// Test tally when the test gate recorded one.
    pub tests: Option<TestTally>,
    /// Number of determinism oracles reproduced across two processes.
    pub determinism_tests: Option<u64>,
    /// Per-gate results in file order.
    pub gates: Vec<GateResult>,
    /// Final verdict line.
    pub verdict: Option<ProtocolVerdict>,
}

/// Adapter errors.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// The summary could not be read.
    #[error("cannot read protocol summary: {0}")]
    Io(String),
    /// A line violated the expected key=value grammar.
    #[error("malformed summary line {line}: {reason}")]
    MalformedLine {
        /// 1-based line number.
        line: usize,
        /// Why.
        reason: String,
    },
}

impl ProtocolSummary {
    /// Parses the machine-readable `summary.txt` emitted by
    /// `scripts/test-protocol.sh`.
    pub fn parse(text: &str) -> Result<Self, AdapterError> {
        let mut s = ProtocolSummary::default();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim_end();
            if line.trim().is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(AdapterError::MalformedLine {
                    line: line_no,
                    reason: format!("expected key=value, got `{line}`"),
                });
            };
            match key {
                "commit" => s.commit = non_q(value).map(str::to_owned),
                "branch" => s.branch = non_q(value).map(str::to_owned),
                "timestamp" => s.timestamp = Some(value.to_owned()),
                "packages" => s.packages = value.parse().ok(),
                "tests_passed" => s.tests_or_default().passed = value.parse().unwrap_or(0),
                "tests_failed" => s.tests_or_default().failed = value.parse().unwrap_or(0),
                "tests_ignored" => s.tests_or_default().ignored = value.parse().unwrap_or(0),
                "test_groups" => s.tests_or_default().groups = value.parse().unwrap_or(0),
                "determinism_tests" => s.determinism_tests = value.parse().ok(),
                "verdict" => {
                    let parsed = ProtocolVerdict::parse(value).ok_or_else(|| {
                        AdapterError::MalformedLine {
                            line: line_no,
                            reason: format!("unknown verdict `{value}`"),
                        }
                    })?;
                    s.verdict = Some(parsed);
                }
                k if k.starts_with("gate.") => {
                    s.gates
                        .push(parse_gate(&k["gate.".len()..], value).ok_or_else(|| {
                            AdapterError::MalformedLine {
                                line: line_no,
                                reason: format!("bad gate entry `{line}`"),
                            }
                        })?);
                }
                other => {
                    return Err(AdapterError::MalformedLine {
                        line: line_no,
                        reason: format!("unknown key `{other}`"),
                    })
                }
            }
        }
        Ok(s)
    }

    /// Parses a `summary.txt` file.
    pub fn load(path: &Path) -> Result<Self, AdapterError> {
        let text = std::fs::read_to_string(path).map_err(|e| AdapterError::Io(e.to_string()))?;
        Self::parse(&text)
    }

    fn tests_or_default(&mut self) -> &mut TestTally {
        self.tests.get_or_insert_with(TestTally::default)
    }

    /// Maps gates onto SciRust-Verify claim slugs + verdicts.
    ///
    /// Known gates map to typed claim kinds where they exist; unknown gates
    /// become custom claims named after the gate. Requirement levels follow
    /// the source protocol's own required/optional classification.
    pub fn claim_map(&self) -> BTreeMap<String, (Verdict, bool)> {
        const KNOWN: &[(&str, &str)] = &[
            ("fmt", "fmt_clean"),
            ("clippy", "lint_clean"),
            ("build", "builds"),
            ("check", "builds"),
            ("test", "tests_pass"),
            ("doc", "docs_build"),
            ("deny", "dependency_policy_passes"),
            ("determinism", "deterministic"),
            ("gpu", "cpu_gpu_parity"),
        ];
        let mut out = BTreeMap::new();
        for gate in &self.gates {
            let slug = KNOWN
                .iter()
                .find(|(gid, _)| *gid == gate.id.as_str())
                .map(|(_, slug)| (*slug).to_owned())
                .unwrap_or_else(|| gate.id.clone());
            // Multiple source gates may support one slug (build+check):
            // combine honestly using failure-dominates semantics.
            let verdict = gate.status.to_verdict();
            let entry = out.entry(slug).or_insert((verdict, gate.required));
            entry.1 |= gate.required;
            let worse = matches!(
                (entry.0, verdict),
                (_, Verdict::Failed)
                    | (Verdict::Verified | Verdict::Skipped, Verdict::NotVerified)
                    | (Verdict::Verified, Verdict::Skipped)
                    | (Verdict::Unsupported, Verdict::Skipped)
            );
            if worse {
                entry.0 = verdict;
            }
        }
        out
    }

    /// Digest of the exact source text this summary was parsed from — the
    /// anchor that keeps the original artifact authoritative.
    pub fn source_digest(text: &str) -> Digest {
        Digest::sha256_hex(text.as_bytes())
    }
}

fn non_q(v: &str) -> Option<&str> {
    if v == "?" || v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn parse_gate(id: &str, value: &str) -> Option<GateResult> {
    // Format: STATUS (required|optional, <n>s[ -- note])
    let value = value.trim();
    let status_str = value.split_whitespace().next()?;
    let status = GateStatus::parse(status_str)?;
    let inner_start = value.find('(')?;
    let inner_end = value.rfind(')')?;
    let inner = &value[inner_start + 1..inner_end];
    let mut parts = inner.splitn(2, ',');
    let required = match parts.next()?.trim() {
        "required" => true,
        "optional" => false,
        _ => return None,
    };
    let rest = parts.next().unwrap_or("").trim();
    // Duration and optional note: `12s` or `12s -- some detail`.
    let (dur_part, note_part) = match rest.split_once("--") {
        Some((d, n)) => (d.trim(), Some(n.trim())),
        None => (rest, None),
    };
    let mut duration_secs = None;
    let mut note = String::new();
    if let Some(stripped) = dur_part.strip_suffix('s') {
        duration_secs = stripped.parse().ok();
    }
    if let Some(n) = note_part {
        note = n.to_owned();
    }
    Some(GateResult {
        id: id.to_owned(),
        status,
        required,
        duration_secs,
        note,
    })
}

#[cfg(test)]
mod tests;
