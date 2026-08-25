//! `scirust-verify.toml` — the versioned project manifest.

use std::collections::BTreeMap;
use std::path::Path;

use scirust_verify_model::tolerance::{Tolerance, ToleranceError};
use scirust_verify_model::RequirementLevel;
use scirust_verify_policy::Profile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Manifest file name.
pub const MANIFEST_FILE: &str = "scirust-verify.toml";

/// Errors from loading or validating the manifest.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The file could not be read.
    #[error("cannot read `{path}`: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The TOML did not parse against the schema.
    #[error("invalid manifest `{path}`: {source}")]
    Parse {
        /// Offending path.
        path: String,
        /// Underlying error.
        source: toml::de::Error,
    },
    /// Semantic validation failure.
    #[error("invalid manifest `{path}`: {reason}")]
    Invalid {
        /// Offending path.
        path: String,
        /// What is wrong.
        reason: String,
    },
    /// Tolerance bound invalid.
    #[error("invalid tolerance in `{path}`: {source}")]
    Tolerance {
        /// Offending path.
        path: String,
        /// Underlying error.
        source: ToleranceError,
    },
}

/// The full manifest schema (v1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Must be present and equal to 1. Missing/unknown versions are rejected
    /// so files never silently reinterpret across formats.
    #[serde(default)]
    pub schema_version: Option<u64>,
    /// Artifact identity overrides.
    #[serde(default)]
    pub artifact: ArtifactSection,
    /// Verification-wide settings.
    #[serde(default)]
    pub verification: VerificationSection,
    /// Cargo provider configuration.
    #[serde(default)]
    pub cargo: CargoSection,
    /// Determinism engine configuration.
    #[serde(default)]
    pub determinism: DeterminismSection,
    /// Global numeric tolerances used by numeric checks.
    #[serde(default)]
    pub numerics: NumericsSection,
    /// Claim requirement-level overrides keyed by claim kind slug.
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
    /// Project-specific command checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_checks: Vec<CustomCheck>,
    /// Numeric checks driven by the structured observation protocol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub numeric_checks: Vec<NumericCheck>,
}

/// `[artifact]` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSection {
    /// Explicit artifact name; discovered package name otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `[verification]` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSection {
    /// Policy profile name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Default timeout for every check in seconds (> 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Stdout capture limit per command in bytes (> 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_max_bytes: Option<u64>,
    /// Stderr capture limit per command in bytes (> 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_max_bytes: Option<u64>,
    /// Extra target triples for build/test checks (never inferred).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Explicit feature list passed as `--features`; `--all-features` is
    /// deliberately not supported because feature sets may be exclusive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// `[cargo]` provider toggles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoSection {
    /// Master switch for the cargo provider.
    #[serde(default)]
    pub enabled: bool,
    /// Run `cargo fmt --all -- --check`.
    #[serde(default = "default_true")]
    pub fmt: bool,
    /// Run clippy with `-D warnings`.
    #[serde(default = "default_true")]
    pub clippy: bool,
    /// Run `cargo check`.
    #[serde(default)]
    pub check: bool,
    /// Run a full build.
    #[serde(default = "default_true")]
    pub build: bool,
    /// Run the test suite.
    #[serde(default = "default_true")]
    pub test: bool,
    /// Build docs without warnings.
    #[serde(default)]
    pub doc: bool,
    /// Emit an SPDX 2.3 SBOM from resolved dependency metadata.
    #[serde(default)]
    pub sbom: bool,
    /// cargo-deny policy: off | optional | required.
    #[serde(default)]
    pub deny: DenyMode,
}

impl Default for CargoSection {
    fn default() -> Self {
        Self {
            enabled: true,
            fmt: true,
            clippy: true,
            check: false,
            build: true,
            test: true,
            doc: false,
            sbom: false,
            deny: DenyMode::Optional,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Availability requirement for an external tool such as cargo-deny.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyMode {
    /// Do not run the tool.
    Off,
    /// Run when installed; skipped otherwise (gap reported).
    #[default]
    Optional,
    /// Required: absence fails the gate as unsupported coverage.
    Required,
}

/// `[determinism]` engine configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterminismSection {
    /// Enable cross-process determinism verification.
    #[serde(default)]
    pub enabled: bool,
    /// Number of independent process runs (>= 2 when enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs: Option<u32>,
    /// Program argv executed per run (e.g. ["cargo","run","--quiet","--"]).
    #[serde(default)]
    pub program: Vec<String>,
    /// Fingerprint mode: `stdout_digest` (hash of captured stdout) or
    /// `structured` (SVOP fingerprint observations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Thread-count levels exercised via the configured env var.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thread_levels: Vec<u32>,
    /// Env var set to each thread level (e.g. `SCI_THREADS`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_env: Option<String>,
}

/// `[numerics]` global tolerance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumericsSection {
    /// Absolute error bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute: Option<f64>,
    /// Relative error bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative: Option<f64>,
    /// ULP distance bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ulps: Option<u64>,
    /// Distinguish +0/-0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_signed_zero: Option<bool>,
}

impl NumericsSection {
    /// Converts into the model tolerance.
    pub fn to_tolerance(&self) -> Tolerance {
        Tolerance {
            absolute: self.absolute,
            relative: self.relative,
            max_ulps: self.max_ulps,
            strict_signed_zero: self.strict_signed_zero.unwrap_or(false),
        }
    }
}

/// A `[[custom_checks]]` entry: arbitrary command treated as code execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCheck {
    /// Unique check id within the plan.
    pub id: String,
    /// Program to run (validated as non-empty).
    #[serde(default)]
    pub program: String,
    /// Arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory relative to project root (default: root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Per-check timeout override in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Requirement level: required (default) or optional/recommended/informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Claim kind slug this check supports (defaults to a custom claim named after the check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_kind: Option<String>,
}

/// A `[[numeric_checks]]` entry running a program that emits SVOP v1 lines.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumericCheck {
    /// Unique check id within the plan.
    pub id: String,
    /// Program to run (validated as non-empty).
    #[serde(default)]
    pub program: String,
    /// Arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory relative to project root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Timeout override in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// Requirement override string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// Valid requirement strings accepted in manifest positions.
pub fn parse_level(s: &str) -> Result<RequirementLevel, String> {
    match s {
        "required" => Ok(RequirementLevel::Required),
        "recommended" => Ok(RequirementLevel::Recommended),
        "optional" => Ok(RequirementLevel::Optional),
        "informational" => Ok(RequirementLevel::Informational),
        other => Err(format!(
            "`{other}` is not a valid requirement level (required|recommended|optional|informational)"
        )),
    }
}

impl Manifest {
    /// Loads and fully validates the manifest at `path`.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let display = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| ManifestError::Io {
            path: display.clone(),
            source,
        })?;
        let manifest: Manifest = toml::from_str(&text).map_err(|source| ManifestError::Parse {
            path: display.clone(),
            source,
        })?;
        manifest.validate(&display)?;
        Ok(manifest)
    }

    /// Validates semantic constraints. Called by [`Manifest::load`]; public
    /// so generated manifests can be checked before writing.
    pub fn validate(&self, display: &str) -> Result<(), ManifestError> {
        fn invalid(display: &str, reason: impl Into<String>) -> ManifestError {
            ManifestError::Invalid {
                path: display.to_owned(),
                reason: reason.into(),
            }
        }

        match self.schema_version {
            None => return Err(invalid(display, "missing `schema_version`")),
            Some(1) => {}
            Some(other) => {
                return Err(invalid(
                    display,
                    format!("unsupported `schema_version = {other}` (this tool understands 1)"),
                ))
            }
        }

        if let Some(t) = self.verification.timeout_secs {
            if t == 0 {
                return Err(invalid(display, "`timeout_secs` must be > 0".to_owned()));
            }
        }
        for (name, v) in [
            ("stdout_max_bytes", self.verification.stdout_max_bytes),
            ("stderr_max_bytes", self.verification.stderr_max_bytes),
        ] {
            if let Some(v) = v {
                if v == 0 {
                    return Err(invalid(display, format!("`{name}` must be > 0")));
                }
            }
        }

        if let Some(profile) = &self.verification.profile {
            // Validate now so typos fail at load, not at verify time.
            Profile::parse(profile).map_err(|e| invalid(display, e.to_string()))?;
        }

        for t in &self.verification.targets {
            if t.trim().is_empty() || t.contains(char::is_whitespace) {
                return Err(invalid(display, format!("invalid target triple `{t}`")));
            }
        }

        for (slug, level) in &self.claims {
            parse_level(level).map_err(|_| {
                invalid(
                    display,
                    format!("claim `{slug}` has invalid level `{level}`"),
                )
            })?;
            if slug != slug.trim() || slug.is_empty() {
                return Err(invalid(display, "claim keys must be non-empty slugs"));
            }
        }

        if self.determinism.enabled {
            let runs = self.determinism.runs.unwrap_or(3);
            if runs < 2 {
                return Err(invalid(
                    display,
                    "`[determinism] runs` must be >= 2 to compare independent executions",
                ));
            }
            if self.determinism.program.is_empty() {
                return Err(invalid(
                    display,
                    "`[determinism] program` must list the argv of the computation",
                ));
            }
            if let Some(mode) = &self.determinism.mode {
                if mode != "stdout_digest" && mode != "structured" {
                    return Err(invalid(
                        display,
                        format!("unknown determinism mode `{mode}` (stdout_digest|structured)"),
                    ));
                }
            }
            for l in &self.determinism.thread_levels {
                if *l == 0 {
                    return Err(invalid(
                        display,
                        "`thread_levels` entries must be >= 1".to_owned(),
                    ));
                }
            }
            if !self.determinism.thread_levels.is_empty()
                && self
                    .determinism
                    .thread_env
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                return Err(invalid(
                    display,
                    "`thread_env` must name the environment variable used for thread levels",
                ));
            }
        }

        self.numerics
            .to_tolerance()
            .validate()
            .map_err(|source| ManifestError::Tolerance {
                path: display.to_owned(),
                source,
            })?;

        let mut ids = std::collections::BTreeSet::new();
        let all_checks = self
            .custom_checks
            .iter()
            .map(|c| {
                (
                    c.id.as_str(),
                    c.program.as_str(),
                    c.level.as_deref(),
                    c.timeout_secs,
                )
            })
            .chain(self.numeric_checks.iter().map(|c| {
                (
                    c.id.as_str(),
                    c.program.as_str(),
                    c.level.as_deref(),
                    c.timeout_secs,
                )
            }));
        for (id, program, level, timeout) in all_checks {
            let c_id = id;
            let _ = timeout;
            if c_id.trim().is_empty() {
                return Err(invalid(display, "custom checks need non-empty `id`s"));
            }
            if !ids.insert(c_id.to_owned()) {
                return Err(invalid(display, format!("duplicate check id `{c_id}`")));
            }
            if program.trim().is_empty() {
                return Err(invalid(
                    display,
                    format!("check `{c_id}` needs a non-empty `program`"),
                ));
            }
            if let Some(l) = level {
                parse_level(l).map_err(|_| invalid(display, format!("check `{c_id}`: {l}")))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
