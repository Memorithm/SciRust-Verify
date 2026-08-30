//! Verification scope: the exact conditions under which a property was checked.

use crate::tolerance::Tolerance;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// CPU identity relevant to hardware-sensitive checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CpuIdentity {
    /// Architecture (e.g. `x86_64`, `aarch64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Relevant instruction-set features actually relied upon
    /// (e.g. `avx2`, `neon`), not the full /proc/cpuinfo dump.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// GPU identity recorded only when a GPU-dependent check actually executed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GpuIdentity {
    /// Backend/runtime (e.g. `vulkan`, `cuda`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Vendor string when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Device name when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Driver version when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
}

impl CpuIdentity {
    fn is_empty(&self) -> bool {
        self.arch.is_none() && self.features.is_empty()
    }
}

impl GpuIdentity {
    fn is_empty(&self) -> bool {
        self.backend.is_none()
            && self.vendor.is_none()
            && self.device.is_none()
            && self.driver.is_none()
    }
}

/// Host machine identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostIdentity {
    /// Operating system family/version (e.g. `linux 6.8`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Host target triple reported by the toolchain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triple: Option<String>,
    /// CPU identity.
    #[serde(skip_serializing_if = "CpuIdentity::is_empty")]
    pub cpu: CpuIdentity,
}

/// Toolchain identity captured at verification time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolchainIdentity {
    /// `rustc -V` output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustc_version: Option<String>,
    /// `cargo -V` output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_version: Option<String>,
    /// Host triple from `rustc -vV`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_triple: Option<String>,
    /// Target triple the artifact was built for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_triple: Option<String>,
    /// Build profile (`dev`, `release`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Important flags affecting codegen (e.g. RUSTFLAGS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustflags: Option<String>,
}

/// A producer-declared execution boundary captured with the run environment.
///
/// This record is provenance, not remote attestation. Once a dossier is
/// finalized it is integrity-bound by `bundle.json`, but the declaration does
/// not by itself prove that the named isolation mechanism was actually active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBoundary {
    /// Isolation mechanism family, for example `bubblewrap`.
    pub mechanism: String,
    /// Versioned profile identifier, for example `bubblewrap-v1`.
    pub profile: String,
    /// What trust can be placed in the declaration itself.
    pub assertion_scope: String,
}

/// The full set of conditions under which verification evidence was gathered.
///
/// Every field is optional: checks record what is relevant to them and never
/// invent placeholder values. Scope is part of every evidence object so that
/// "VERIFIED" is always readable as "VERIFIED *under this scope*".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VerificationScope {
    /// Target triple used for compilation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_triple: Option<String>,
    /// Host identity.
    #[serde(skip_serializing_if = "HostIdentity::is_empty")]
    pub host: HostIdentity,
    /// Toolchain identity.
    #[serde(skip_serializing_if = "ToolchainIdentity::is_empty")]
    pub toolchain: ToolchainIdentity,
    /// Cargo feature set enabled for the check.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Build profile (mirrors [`ToolchainIdentity::profile`] for convenience).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Selected environment variables that materially affected execution
    /// (allowlist; values of secret-like names are redacted upstream).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    /// Seed used by deterministic computations, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Thread count the computation was configured with, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads: Option<u32>,
    /// Execution backend (`cpu`, `wgpu`, `cuda`, ...), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// GPU identity when a GPU-dependent check actually executed. The field is
    /// absent for CPU-only scopes and must never be populated from guesswork.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuIdentity>,
    /// Identifier of the input data set used, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_set: Option<String>,
    /// Numeric tolerances applied by this scope's comparisons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<Tolerance>,
    /// When the scoped activity was recorded (UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_at_utc: Option<DateTime<Utc>>,
    /// How execution happened (`in-process`, `subprocess`, `container`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<String>,
}

impl ToolchainIdentity {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl HostIdentity {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

impl VerificationScope {
    /// Returns true when no concrete GPU identity has been recorded. Report
    /// generation uses this to avoid claiming GPU coverage that does not exist.
    pub fn gpu_is_unknown(&self) -> bool {
        match &self.gpu {
            Some(gpu) => gpu.is_empty(),
            None => true,
        }
    }
}

/// Snapshot of the host + toolchain environment taken once per run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnvironmentSnapshot {
    /// Host identity.
    #[serde(skip_serializing_if = "HostIdentity::is_empty")]
    pub host: HostIdentity,
    /// Toolchain identity.
    #[serde(skip_serializing_if = "ToolchainIdentity::is_empty")]
    pub toolchain: ToolchainIdentity,
    /// Additional tool versions discovered by doctor-style probes
    /// (e.g. `git`, `cargo-deny`), name => version line.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_tools: BTreeMap<String, String>,
    /// Producer-declared process isolation boundary, when a recognized
    /// SciRust-Verify launcher supplied one. Integrity binding after sealing
    /// does not turn this field into a trusted attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_boundary: Option<ExecutionBoundary>,
    /// UTC instant the snapshot was taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_at_utc: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_roundtrips() {
        let s = VerificationScope::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: VerificationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn scope_serializes_only_set_fields() {
        let s = VerificationScope {
            seed: Some(42),
            threads: Some(4),
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"seed\":42"));
        assert!(!json.contains("target_triple"));
    }

    #[test]
    fn gpu_identity_is_explicit_scope_data() {
        let scope = VerificationScope {
            backend: Some("cuda".into()),
            gpu: Some(GpuIdentity {
                backend: Some("cuda".into()),
                vendor: Some("NVIDIA".into()),
                device: Some("Example GPU".into()),
                driver: Some("999.0".into()),
            }),
            ..Default::default()
        };
        assert!(!scope.gpu_is_unknown());
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("Example GPU"));
        let roundtrip: VerificationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, scope);

        let cpu_only = VerificationScope {
            backend: Some("cpu".into()),
            ..Default::default()
        };
        assert!(cpu_only.gpu_is_unknown());
    }

    #[test]
    fn execution_boundary_roundtrips_without_strengthening_semantics() {
        let snapshot = EnvironmentSnapshot {
            execution_boundary: Some(ExecutionBoundary {
                mechanism: "bubblewrap".into(),
                profile: "bubblewrap-v1".into(),
                assertion_scope: "producer_declared_not_attested".into(),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("bubblewrap-v1"));
        assert!(json.contains("producer_declared_not_attested"));
        let roundtrip: EnvironmentSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, snapshot);
    }
}
