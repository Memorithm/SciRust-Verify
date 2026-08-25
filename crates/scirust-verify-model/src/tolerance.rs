//! Typed floating-point tolerance model.
//!
//! A [`Tolerance`] states how far an observed value may deviate from the
//! expected value for a numeric comparison to pass. Semantics:
//!
//! * `absolute` — pass when `|observed - expected| <= absolute`.
//! * `relative` — pass when `|observed - expected| <= relative * max(|expected|, |observed|)`.
//! * `max_ulps` — pass when the values are at most `max_ulps` units-in-the-last-place
//!   apart (bit-level distance of their IEEE-754 binary64 representations).
//! * When several fields are set, the comparison passes if **any** satisfied
//!   criterion accepts the pair (an OR), which is the conventional combined
//!   abs/rel behavior. If no field is set, only exact bit equality passes
//!   (with `+0 == -0` treated as equal unless `strict_signed_zero` is set).

use serde::{Deserialize, Serialize};

/// Typed tolerance used by numeric checks; part of a [`crate::VerificationScope`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tolerance {
    /// Maximum allowed absolute error.
    pub absolute: Option<f64>,
    /// Maximum allowed relative error (fraction, not percent).
    pub relative: Option<f64>,
    /// Maximum allowed ULP distance.
    pub max_ulps: Option<u64>,
    /// When true, `+0.0` and `-0.0` are considered different.
    pub strict_signed_zero: bool,
}

impl Tolerance {
    /// Tolerance accepting exact equality only.
    pub fn exact() -> Self {
        Self::default()
    }

    /// True when no numeric criterion is configured (exactness mode).
    pub fn is_exact(&self) -> bool {
        self.absolute.is_none() && self.relative.is_none() && self.max_ulps.is_none()
    }

    /// Validates the tolerance: all configured bounds must be finite and
    /// non-negative, and `relative < 1.0` is not enforced but `relative`
    /// above 1.0 must be flagged by callers wanting strictness — here we
    /// reject negative or non-finite values only.
    pub fn validate(&self) -> Result<(), ToleranceError> {
        for (name, v) in [("absolute", self.absolute), ("relative", self.relative)] {
            if let Some(v) = v {
                if !v.is_finite() || v < 0.0 {
                    return Err(ToleranceError::InvalidBound {
                        name: name.to_owned(),
                        value: v,
                    });
                }
            }
        }
        Ok(())
    }

    /// Human-readable summary, e.g. `abs<=1e-09 OR rel<=1e-06 OR ulps<=4`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(a) = self.absolute {
            parts.push(format!("abs<={a:e}"));
        }
        if let Some(r) = self.relative {
            parts.push(format!("rel<={r:e}"));
        }
        if let Some(u) = self.max_ulps {
            parts.push(format!("ulps<={u}"));
        }
        if parts.is_empty() {
            let base = "exact".to_string();
            if self.strict_signed_zero {
                return format!("{base} (+/-0 distinguished)");
            }
            return base;
        }
        let joined = parts.join(" OR ");
        if self.strict_signed_zero {
            format!("{joined} (+/-0 distinguished)")
        } else {
            joined
        }
    }
}

/// Error produced when a tolerance is structurally invalid.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ToleranceError {
    /// A bound was negative or not finite.
    #[error("tolerance bound `{name}` must be finite and >= 0, got {value}")]
    InvalidBound {
        /// Bound name (`absolute` or `relative`).
        name: String,
        /// The offending value.
        value: f64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_forms() {
        assert_eq!(Tolerance::exact().describe(), "exact");
        let t = Tolerance {
            absolute: Some(1e-9),
            relative: Some(1e-6),
            ..Default::default()
        };
        assert_eq!(t.describe(), "abs<=1e-9 OR rel<=1e-6");
    }

    #[test]
    fn validation_rejects_bad_bounds() {
        assert!(Tolerance {
            absolute: Some(-1.0),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(Tolerance {
            relative: Some(f64::NAN),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(Tolerance {
            max_ulps: Some(4),
            ..Default::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn serde_roundtrip_with_defaults() {
        let t: Tolerance = serde_json::from_str(r#"{"absolute": 0.5}"#).unwrap();
        assert_eq!(
            t,
            Tolerance {
                absolute: Some(0.5),
                ..Default::default()
            }
        );
        let bad: Result<Tolerance, _> = serde_json::from_str(r#"{"nonsense": 1}"#);
        assert!(bad.is_err());
    }
}
