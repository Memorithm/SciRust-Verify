//! Observations: facts extracted from executions.
//!
//! Observations never carry verdicts; interpretation happens in the verdict
//! engine. They are also the payload of the structured observation protocol
//! (see `scirust-verify-numerics`) used by verified programs to report
//! machine-readable measurements separately from human logs.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A typed observed value. Units are part of the variant so that persisted
/// numbers are never ambiguous (`duration_ns`, not a bare integer).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedValue {
    /// Boolean fact (e.g. `worktree_dirty = false`).
    Bool(bool),
    /// Signed integer count.
    Int(i64),
    /// Unsigned integer count (tests passed, bytes, ...).
    UInt(u64),
    /// Floating-point measurement (max_abs_error, latency seconds, ...).
    Float(f64),
    /// Textual fact (compiler version, fingerprint hex, ...).
    Text(String),
    /// A duration in nanoseconds.
    DurationNs(u64),
    /// A byte count.
    Bytes(u64),
    /// Nested structured data.
    Json(serde_json::Value),
}

impl fmt::Display for ObservedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::UInt(u) => write!(f, "{u}"),
            Self::Float(x) => write!(f, "{x:e}"),
            Self::Text(s) => f.write_str(s),
            Self::DurationNs(ns) => write!(f, "{ns}ns"),
            Self::Bytes(b) => write!(f, "{b}B"),
            Self::Json(v) => write!(f, "{v}"),
        }
    }
}

/// One named fact with an optional unit label for display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Observation kind, e.g. `numeric_comparison`, `exit_status`,
    /// `fingerprint`, `tool_version`.
    pub kind: String,
    /// Stable name within its kind.
    pub name: String,
    /// The measured/observed value.
    pub value: ObservedValue,
    /// Unit annotation for display (`ms`, `MiB`, `ulp`, ...). Values that
    /// embed their unit (`DurationNs`, `Bytes`) may leave this empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl Observation {
    /// Convenience constructor.
    pub fn new(kind: impl Into<String>, name: impl Into<String>, value: ObservedValue) -> Self {
        Self {
            kind: kind.into(),
            name: name.into(),
            value,
            unit: None,
        }
    }

    /// Attaches a display unit.
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }
}
