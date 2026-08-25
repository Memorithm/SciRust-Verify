//! Checks: planned verification work and its recorded execution.

use crate::id::{CheckId, ClaimId, EvidenceId};
use crate::observation::Observation;
use crate::verdict::{RequirementLevel, Verdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// A structural description of a command to execute. The runner turns this
/// into an actual process; nothing here is ever passed through a shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandTemplate {
    /// Program to spawn (resolved through `PATH` when not absolute).
    pub program: String,
    /// Arguments, passed verbatim.
    pub args: Vec<String>,
    /// Working directory, relative to the project root unless absolute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Explicit environment variables supplied to the command.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// What a check actually does when executed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckAction {
    /// Run one external command and interpret its exit status (and any
    /// structured observations it emits).
    Command {
        /// The command template.
        command: CommandTemplate,
        /// Interpretation of a non-zero exit status.
        #[serde(default)]
        expect: ExitExpectation,
    },
    /// A multi-execution check computed by a dedicated engine
    /// (e.g. determinism runs). The engine owns interpretation.
    Composite {
        /// Engine identifier owning the semantics (e.g. `determinism`).
        engine: String,
        /// Engine-specific configuration.
        parameters: serde_json::Map<String, serde_json::Value>,
    },
}

/// How exit statuses map to pass/fail for plain command checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitExpectation {
    /// Exit code 0 => verified, anything else => failed.
    #[default]
    Success,
    /// Command result is informational; failures do not fail the check.
    Ignore,
}

/// A planned unit of verification work.
///
/// Checks exist *before* execution so that `plan` can show the exact
/// workload that `verify` would run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    /// Stable identifier (`<provider>:<slug>[:<index>]`).
    pub id: CheckId,
    /// Provider that planned this check (e.g. `cargo`, `determinism`).
    pub provider: String,
    /// One-line purpose shown in plans and reports.
    pub purpose: String,
    /// Claims this check produces evidence for.
    pub claims: Vec<ClaimId>,
    /// How strongly the outcome gates the dossier.
    pub requirement: RequirementLevel,
    /// What will be executed.
    pub action: CheckAction,
    /// Maximum wall-clock time for this check.
    pub timeout: Duration,
    /// Upper bound on captured stdout bytes.
    pub stdout_limit_bytes: u64,
    /// Upper bound on captured stderr bytes.
    pub stderr_limit_bytes: u64,
}

impl Check {
    /// Duration serialized as whole seconds with sub-second truncation for
    /// display purposes.
    pub fn timeout_display(&self) -> String {
        format!("{}s", self.timeout.as_secs())
    }
}

/// Status of one executed (or non-executed) check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckStatus {
    /// The command/engine ran to completion.
    Executed {
        /// Process exit code, when a single command was involved.
        exit_code: Option<i32>,
    },
    /// Execution exceeded its timeout and was killed.
    TimedOut,
    /// The process could not be spawned at all.
    SpawnFailed {
        /// Why spawning failed.
        reason: String,
    },
    /// Implementation exists but could not run here (tool missing etc.).
    Skipped {
        /// Why the check was skipped.
        reason: String,
    },
    /// No implementation exists for this check in this version.
    Unsupported {
        /// What is missing.
        reason: String,
    },
}

impl CheckStatus {
    /// Maps a status to the default verdict a claim should inherit when no
    /// richer interpretation applies.
    pub fn base_verdict(&self) -> Verdict {
        match self {
            Self::Executed { .. } => Verdict::Verified,
            Self::TimedOut | Self::SpawnFailed { .. } => Verdict::NotVerified,
            Self::Skipped { .. } => Verdict::Skipped,
            Self::Unsupported { .. } => Verdict::Unsupported,
        }
    }
}

/// The record of one check execution attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckExecution {
    /// Which check ran.
    pub check_id: CheckId,
    /// When execution started (UTC).
    pub started_at_utc: Option<DateTime<Utc>>,
    /// When execution ended (UTC).
    pub ended_at_utc: Option<DateTime<Utc>>,
    /// Terminal status.
    pub status: CheckStatus,
    /// Facts extracted from the execution.
    pub observations: Vec<Observation>,
    /// Evidence objects produced by this execution.
    pub evidence_ids: Vec<EvidenceId>,
    /// Free-form notes preserved in reports (e.g. why a verdict was lowered).
    pub notes: Vec<String>,
}

impl CheckExecution {
    /// Creates an execution record for a status without observations.
    pub fn minimal(check_id: CheckId, status: CheckStatus) -> Self {
        Self {
            check_id,
            started_at_utc: None,
            ended_at_utc: None,
            status,
            observations: Vec::new(),
            evidence_ids: Vec::new(),
            notes: Vec::new(),
        }
    }
}
