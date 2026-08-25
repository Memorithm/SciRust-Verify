//! Policy profiles and gate evaluation.
//!
//! Profiles are named presets over the manifest's claim requirement levels
//! and provider toggles. Precedence is always:
//!
//! ```text
//! built-in defaults  <  profile preset  <  explicit manifest entries  <  CLI overrides
//! ```
//!
//! Only profiles with clear semantics exist:
//!
//! | Profile          | Adds beyond `basic`                                     |
//! |------------------|----------------------------------------------------------|
//! | `basic`          | fmt/clippy/build/test; builds+tests required             |
//! | `scientific`     | determinism recommended, numerics recommended            |
//! | `reproducibility`| cross-process determinism required, source clean required|
//! | `strict`         | everything enabled becomes required                      |

#![deny(missing_docs)]

use scirust_verify_model::{ClaimEvaluation, DossierVerdict, RequirementLevel};
use thiserror::Error;

/// The four built-in policy profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Sensible defaults for any Cargo project.
    #[default]
    Basic,
    /// Scientific workloads: adds deterministic/numeric expectations.
    Scientific,
    /// Reproducibility-first: demands clean sources and cross-process proof.
    Reproducibility,
    /// Everything enabled must hold as required.
    Strict,
}

impl Profile {
    /// Parses a profile from its TOML/CLI name.
    pub fn parse(name: &str) -> Result<Self, ProfileError> {
        match name {
            "basic" => Ok(Self::Basic),
            "scientific" => Ok(Self::Scientific),
            "reproducibility" => Ok(Self::Reproducibility),
            "strict" => Ok(Self::Strict),
            other => Err(ProfileError::UnknownProfile(other.to_owned())),
        }
    }

    /// Canonical profile name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Scientific => "scientific",
            Self::Reproducibility => "reproducibility",
            Self::Strict => "strict",
        }
    }
}

/// Profile-related errors.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ProfileError {
    /// Unknown profile name.
    #[error(
        "unknown verification profile `{0}` (expected basic|scientific|reproducibility|strict)"
    )]
    UnknownProfile(String),
}

/// Requirement-level assignment used by profiles: claim kind slug =>
/// level. `None` means "leave whatever the manifest says".
pub type LevelOverrides = std::collections::BTreeMap<String, Option<RequirementLevel>>;

impl Profile {
    /// Claim-level overrides contributed by this profile. Entries set to
    /// `Some(level)` force a level unless the manifest sets one explicitly;
    /// they are applied before manifest values win by precedence rules in
    /// the core manifest loader.
    pub fn level_overrides(&self) -> LevelOverrides {
        use RequirementLevel::*;
        let mut m = LevelOverrides::new();
        let mut set = |k: &str, v: RequirementLevel| {
            m.insert(k.to_owned(), Some(v));
        };
        match self {
            Self::Basic => {}
            Self::Scientific => {
                set("deterministic", Recommended);
                set("numerically_close", Recommended);
            }
            Self::Reproducibility => {
                set("deterministic", Recommended);
                set("cross_process_deterministic", Required);
                set("source_clean", Required);
            }
            Self::Strict => {
                for k in [
                    "builds",
                    "tests_pass",
                    "lint_clean",
                    "fmt_clean",
                    "source_clean",
                ] {
                    set(k, Required);
                }
            }
        }
        m
    }
}

/// Computes the final dossier gate from claim evaluations plus their
/// configured levels. Thin wrapper over the pure model aggregation so all
/// gating flows through one documented function.
pub fn evaluate_gate(evaluations: &[(RequirementLevel, ClaimEvaluation)]) -> DossierVerdict {
    let items: Vec<_> = evaluations
        .iter()
        .map(|(level, ev)| scirust_verify_model::GatingItem {
            level: *level,
            verdict: ev.verdict,
        })
        .collect();
    scirust_verify_model::aggregate_dossier_verdict(&items)
}
