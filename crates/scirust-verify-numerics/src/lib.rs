//! Floating-point comparison engine and the structured observation protocol.
//!
//! # Comparison semantics
//!
//! Given `expected` and `observed` f64 values plus a [`Tolerance`], a pair
//! passes when:
//!
//! * both are NaN and NaN policy is `Match`, or
//! * both are the same infinity, or
//! * signed zeros: equal unless tolerance sets `strict_signed_zero`, or
//! * any configured numeric criterion accepts:
//!   * absolute: `|o - e| <= absolute`
//!   * relative: `|o - e| <= relative * max(|e|, |o|)`
//!   * ulp: ULP distance `<= max_ulps`
//! * with no criterion configured (exact mode), bit equality with `+0 == -0`.
//!
//! ULP distance treats the IEEE-754 binary64 patterns as a two's-complement
//! ordering so that distances across zero behave monotonically. It is only
//! meaningful for finite same-sign-magnitude pairs; across infinities it is
//! undefined and reported as such.
//!
//! # Structured observation protocol (SVOP v1)
//!
//! Verified programs may emit machine-readable observations on stdout using
//! lines of the form:
//!
//! ```text
//! SCIRUST_VERIFY_OBS_V1 {"kind":"numeric_comparison","name":"gamma","expected":1.0,"observed":1.000000001}
//! ```
//!
//! Everything that is not such a marked line is human output and ignored by
//! the protocol parser. A line carrying the marker but failing to parse is a
//! protocol error, not silently skipped.

#![deny(missing_docs)]

use scirust_verify_model::observation::{Observation, ObservedValue};
use scirust_verify_model::tolerance::Tolerance;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result of one comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonOutcome {
    /// True when the pair passed under the tolerance.
    pub pass: bool,
    /// Absolute error when computable (NaN otherwise, e.g. mixed infinities).
    pub abs_error: Option<f64>,
    /// Relative error when computable.
    pub rel_error: Option<f64>,
    /// ULP distance when meaningful.
    pub ulp_distance: Option<u64>,
    /// Which criterion accepted the pair, for reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<&'static str>,
}

fn both_nan(a: f64, b: f64) -> bool {
    a.is_nan() && b.is_nan()
}

fn ulp_distance(a: f64, b: f64) -> Option<u64> {
    if !a.is_finite() || !b.is_finite() {
        return None;
    }
    let to_ordered = |x: f64| -> i64 {
        let bits = x.to_bits() as i64;
        // Map sign-magnitude to monotonic two's complement ordering.
        if bits < 0 {
            i64::MIN - bits
        } else {
            bits
        }
    };
    let (ia, ib) = (to_ordered(a), to_ordered(b));
    Some(ia.abs_diff(ib) as u64)
}

/// Compares `expected` against `observed` under `tolerance`.
pub fn compare(expected: f64, observed: f64, tolerance: &Tolerance) -> ComparisonOutcome {
    let abs_error = if expected.is_infinite() && observed.is_infinite() {
        None
    } else {
        Some((observed - expected).abs())
    };
    let scale = expected.abs().max(observed.abs());
    let rel_error = abs_error.map(|a| if scale > 0.0 { a / scale } else { a });
    let ulps = ulp_distance(expected, observed);

    // --- special-value handling first; never let NaN slip through ---
    if expected.is_nan() || observed.is_nan() {
        let pass = both_nan(expected, observed);
        return ComparisonOutcome {
            pass,
            abs_error: None,
            rel_error: None,
            ulp_distance: None,
            accepted_by: pass.then_some("nan_match"),
        };
    }

    if expected.is_infinite() || observed.is_infinite() {
        let pass = expected == observed;
        return ComparisonOutcome {
            pass,
            abs_error,
            rel_error: None,
            ulp_distance: None,
            accepted_by: pass.then_some("infinity_match"),
        };
    }

    // Signed zeros.
    if expected == 0.0 && observed == 0.0 {
        let pass = !tolerance.strict_signed_zero
            || expected.is_sign_negative() == observed.is_sign_negative();
        return ComparisonOutcome {
            pass,
            abs_error: Some(0.0),
            rel_error: Some(0.0),
            ulp_distance: ulps,
            accepted_by: pass.then_some("zero"),
        };
    }

    // Exact equality always passes regardless of configured criteria.
    if expected.to_bits() == observed.to_bits() {
        return ComparisonOutcome {
            pass: true,
            abs_error: Some(0.0),
            rel_error: Some(0.0),
            ulp_distance: Some(0),
            accepted_by: Some("exact"),
        };
    }

    // With no criterion configured, only bit equality passes (already
    // handled above); anything else must fail.
    let mut outcome = ComparisonOutcome {
        pass: false,
        abs_error,
        rel_error,
        ulp_distance: ulps,
        accepted_by: None,
    };

    if let Some(abs_tol) = tolerance.absolute {
        if let Some(err) = abs_error {
            if err <= abs_tol {
                outcome.pass = true;
                outcome.accepted_by = Some("absolute");
            }
        }
    }
    if let Some(rel_tol) = tolerance.relative {
        if let Some(err) = rel_error {
            if err <= rel_tol {
                outcome.pass = true;
                outcome.accepted_by = Some("relative");
            }
        }
    }
    if let Some(max_ulps) = tolerance.max_ulps {
        if let Some(d) = ulps {
            if d <= max_ulps {
                outcome.pass = true;
                outcome.accepted_by = Some("ulp");
            }
        }
    }

    outcome
}

// ---------------------------------------------------------------------------
// Structured observation protocol (SVOP v1)
// ---------------------------------------------------------------------------

/// Line marker introducing one structured observation.
pub const OBS_MARKER: &str = "SCIRUST_VERIFY_OBS_V1";

/// One structured observation emitted by a verified program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolObservation {
    /// Discriminant of the observation kind (`numeric_comparison`,
    /// `fingerprint`, `metric`, `property`).
    pub kind: String,
    /// Stable name of the observation.
    pub name: String,
    /// For `numeric_comparison`: expected value from the oracle/reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<f64>,
    /// For `numeric_comparison` / `metric`: value produced by the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<f64>,
    /// For `metric`: unit string (never omitted for metrics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// For `fingerprint`: hex-encoded fingerprint value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Optional unit annotation (`m`, `Pa`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// For `property`: whether the property held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds: Option<bool>,
    /// For `property`: what the property means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A validated view over a [`ProtocolObservation`], discriminated by kind.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidObservation {
    /// Numeric comparison: program measured `observed`, oracle says
    /// `expected`; SciRust-Verify re-applies the tolerance independently.
    NumericComparison {
        /// Stable name of the comparison.
        name: String,
        /// Expected value.
        expected: f64,
        /// Observed value.
        observed: f64,
        /// Optional unit.
        unit: Option<String>,
    },
    /// Canonical output fingerprint; identity evidence.
    Fingerprint {
        /// Stable name.
        name: String,
        /// Hex value.
        value: String,
    },
    /// Scalar measurement with explicit unit.
    Metric {
        /// Stable name.
        name: String,
        /// Measured value.
        value: f64,
        /// Unit string.
        unit: String,
    },
    /// Boolean property asserted by the program.
    Property {
        /// Stable name.
        name: String,
        /// Whether it held.
        holds: bool,
        /// Meaning.
        description: String,
    },
}

impl ProtocolObservation {
    /// Validates and discriminates the raw observation.
    pub fn validate(&self) -> Result<ValidObservation, ProtocolError> {
        let non_empty = |s: &str, what: &str| {
            if s.trim().is_empty() {
                Err(ProtocolError::InvalidPayload {
                    name: self.name.clone(),
                    reason: format!("empty {what}"),
                })
            } else {
                Ok(())
            }
        };
        match self.kind.as_str() {
            "numeric_comparison" => {
                non_empty(&self.name, "name")?;
                let expected = self.expected.ok_or_else(|| ProtocolError::InvalidPayload {
                    name: self.name.clone(),
                    reason: "missing `expected`".into(),
                })?;
                let observed = self.observed.ok_or_else(|| ProtocolError::InvalidPayload {
                    name: self.name.clone(),
                    reason: "missing `observed`".into(),
                })?;
                Ok(ValidObservation::NumericComparison {
                    name: self.name.clone(),
                    expected,
                    observed,
                    unit: self.unit.clone(),
                })
            }
            "fingerprint" => {
                non_empty(&self.name, "name")?;
                let value =
                    self.fingerprint
                        .as_deref()
                        .ok_or_else(|| ProtocolError::InvalidPayload {
                            name: self.name.clone(),
                            reason: "missing `fingerprint`".into(),
                        })?;
                non_empty(value, "fingerprint")?;
                if !value.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(ProtocolError::InvalidPayload {
                        name: self.name.clone(),
                        reason: "fingerprint must be hex".into(),
                    });
                }
                Ok(ValidObservation::Fingerprint {
                    name: self.name.clone(),
                    value: value.to_owned(),
                })
            }
            "metric" => {
                non_empty(&self.name, "name")?;
                let value = self.value.ok_or_else(|| ProtocolError::InvalidPayload {
                    name: self.name.clone(),
                    reason: "missing `value`".into(),
                })?;
                let unit = self
                    .unit
                    .clone()
                    .ok_or_else(|| ProtocolError::InvalidPayload {
                        name: self.name.clone(),
                        reason: "metrics require an explicit unit".into(),
                    })?;
                non_empty(&unit, "unit")?;
                Ok(ValidObservation::Metric {
                    name: self.name.clone(),
                    value,
                    unit,
                })
            }
            "property" => {
                non_empty(&self.name, "name")?;
                let holds = self.holds.ok_or_else(|| ProtocolError::InvalidPayload {
                    name: self.name.clone(),
                    reason: "missing `holds`".into(),
                })?;
                let description =
                    self.description
                        .clone()
                        .ok_or_else(|| ProtocolError::InvalidPayload {
                            name: self.name.clone(),
                            reason: "properties require a description".into(),
                        })?;
                non_empty(&description, "description")?;
                Ok(ValidObservation::Property {
                    name: self.name.clone(),
                    holds,
                    description,
                })
            }
            other => Err(ProtocolError::MalformedLine {
                line: 0,
                reason: format!("unknown observation kind `{other}`"),
            }),
        }
    }

    /// The stable name shared by all kinds.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Errors from parsing structured observations out of process output.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ProtocolError {
    /// A line carried the marker but was not valid protocol JSON.
    #[error("malformed SVOP payload at line {line}: {reason}")]
    MalformedLine {
        /// 1-based line number in the captured output.
        line: usize,
        /// Why parsing failed.
        reason: String,
    },
    /// A known observation kind had an invalid payload (e.g. non-finite
    /// where forbidden).
    #[error("invalid SVOP observation `{name}`: {reason}")]
    InvalidPayload {
        /// Observation name.
        name: String,
        /// Why it is invalid.
        reason: String,
    },
}

/// Extracts every structured observation from captured stdout.
///
/// Lines without the marker are ignored (human log). Marked lines must parse
/// and validate; failures surface as [`ProtocolError`] so corrupted or
/// hostile output cannot silently shrink the evidence set. The returned
/// observations are validated [`ValidObservation`]s.
pub fn parse_observations(stdout: &str) -> Result<Vec<ValidObservation>, ProtocolError> {
    let mut out = Vec::new();
    for (idx, line) in stdout.lines().enumerate() {
        let Some(payload) = line.trim().strip_prefix(OBS_MARKER) else {
            continue;
        };
        let payload = payload.trim();
        let raw: ProtocolObservation =
            serde_json::from_str(payload).map_err(|e| ProtocolError::MalformedLine {
                line: idx + 1,
                reason: e.to_string(),
            })?;
        let valid = raw.validate().map_err(|e| match e {
            ProtocolError::MalformedLine { reason, .. } => ProtocolError::MalformedLine {
                line: idx + 1,
                reason,
            },
            other => other,
        })?;
        out.push(valid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
