use scirust_verify_model::tolerance::Tolerance;

use super::*;

fn tol_abs(a: f64) -> Tolerance {
    Tolerance {
        absolute: Some(a),
        ..Default::default()
    }
}

#[test]
fn exact_equality_passes_everywhere() {
    let t = Tolerance::exact();
    assert!(compare(2.0, 2.0, &t).pass);
    // One ULP above 2.0 (spacing at 2.0 is 2*EPSILON, so +EPSILON is exact).
    let next = f64::from_bits(2.0f64.to_bits() + 1);
    assert_ne!(next, 2.0);
    assert!(!compare(2.0, next, &t).pass);
}

#[test]
fn absolute_tolerance() {
    let t = tol_abs(1e-6);
    let o = compare(1.0, 1.0 + 9e-7, &t);
    assert!(o.pass);
    assert_eq!(o.accepted_by, Some("absolute"));
    assert!(!compare(1.0, 1.0 + 1.1e-6, &t).pass);
}

#[test]
fn relative_tolerance_uses_larger_magnitude() {
    let t = Tolerance {
        relative: Some(1e-3),
        ..Default::default()
    };
    // Error is 1e-4 relative to 100 => 1e-6 relative: passes.
    assert!(compare(100.0, 100.0001, &t).pass);
    // Tiny expected values must not be swallowed by relative tolerance.
    assert!(!compare(1e-10, 2e-10, &t).pass);
}

#[test]
fn combined_abs_or_rel() {
    let t = Tolerance {
        absolute: Some(1e-8),
        relative: Some(1e-5),
        ..Default::default()
    };
    // Passes by relative.
    let o = compare(1e6, 1e6 + 5.0, &t);
    assert!(o.pass);
    assert_eq!(o.accepted_by, Some("relative"));
    // Passes by absolute (near zero).
    let o = compare(1e-12, 5e-12, &t);
    assert!(o.pass);
    assert_eq!(o.accepted_by, Some("absolute"));
    // Fails both.
    assert!(!compare(1.0, 1.001, &t).pass);
}

#[test]
fn zero_expected_value_handling() {
    let t = Tolerance {
        absolute: Some(1e-9),
        relative: Some(0.9),
        ..Default::default()
    };
    assert!(compare(0.0, 5e-10, &t).pass);
    // Pure relative with zero expected: scale is max(|e|,|o|)=observed so
    // relative error == 1.0 for any nonzero observed; only abs can save it.
    let t_rel_only = Tolerance {
        relative: Some(0.5),
        ..Default::default()
    };
    assert!(!compare(0.0, 1.0, &t_rel_only).pass);
}

#[test]
fn nan_never_accidentally_passes() {
    let t = tol_abs(1e9); // absurdly loose
    assert!(!compare(1.0, f64::NAN, &t).pass);
    assert!(!compare(f64::NAN, 1.0, &t).pass);
    // NaN == NaN passes only as an explicit match.
    let o = compare(f64::NAN, f64::NAN, &Tolerance::exact());
    assert!(o.pass);
    assert_eq!(o.accepted_by, Some("nan_match"));
}

#[test]
fn infinity_policy() {
    let t = Tolerance::exact();
    assert!(compare(f64::INFINITY, f64::INFINITY, &t).pass);
    assert!(!compare(f64::INFINITY, f64::NEG_INFINITY, &t).pass);
    assert!(!compare(f64::INFINITY, 1.0, &t).pass);
    assert!(compare(f64::NEG_INFINITY, f64::NEG_INFINITY, &t).pass);
}

#[test]
fn signed_zero_policy() {
    let lax = Tolerance::exact();
    assert!(compare(0.0, -0.0, &lax).pass);
    let strict = Tolerance {
        strict_signed_zero: true,
        ..Default::default()
    };
    assert!(!compare(0.0, -0.0, &strict).pass);
    assert!(compare(-0.0, -0.0, &strict).pass);
}

#[test]
fn ulp_boundaries() {
    let one_ulp = Tolerance {
        max_ulps: Some(1),
        ..Default::default()
    };
    let a = 1.0f64;
    let b = f64::from_bits(a.to_bits() + 1);
    assert!(compare(a, b, &one_ulp).pass);
    assert_eq!(ulp_distance(a, b), Some(1));

    // Across the sign boundary of zero.
    let pos_tiny = f64::from_bits(1); // smallest positive subnormal
    let neg_tiny = f64::from_bits((1u64 << 63) | 1); // smallest negative subnormal
    assert_eq!(ulp_distance(pos_tiny, neg_tiny), Some(2));

    // Two ulps away fails a one-ulp bound.
    let c = f64::from_bits(a.to_bits() + 2);
    assert!(!compare(a, c, &one_ulp).pass);

    // ULP distance from 0.0 to smallest subnormal is 1.
    assert_eq!(ulp_distance(0.0, pos_tiny), Some(1));
    assert_eq!(ulp_distance(f64::INFINITY, 1.0), None);
}

#[test]
fn subnormals_and_extreme_magnitudes() {
    let t = tol_abs(1e-315);
    let tiny = 5e-324; // smallest subnormal
    assert!(compare(tiny, 2.0 * tiny, &t).pass);

    let big = Tolerance {
        relative: Some(1e-10),
        ..Default::default()
    };
    assert!(compare(1e300, 1e300 * (1.0 + 1e-12), &big).pass);
    assert!(!compare(1e300, 1e300 * 2.0, &big).pass);
}

// ---------------------------------------------------------------------------
// Protocol parser tests
// ---------------------------------------------------------------------------

#[test]
fn parses_marked_lines_and_ignores_human_output() {
    let obs = parse_observations(
        "running...\nnoisy line\nSCIRUST_VERIFY_OBS_V1 {\"kind\":\"numeric_comparison\",\"name\":\"gamma_oracle\",\"expected\":1.0,\"observed\":1.000000001}\ndone\n",
    )
    .unwrap();
    assert_eq!(obs.len(), 1);
    match &obs[0] {
        ValidObservation::NumericComparison {
            name,
            expected,
            observed,
            ..
        } => {
            assert_eq!(name, "gamma_oracle");
            assert_eq!(*expected, 1.0);
            assert_eq!(*observed, 1.000000001);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn malformed_marked_line_is_an_error_not_skipped() {
    let stdout = "SCIRUST_VERIFY_OBS_V1 {not json}\n";
    let err = parse_observations(stdout).unwrap_err();
    assert!(matches!(err, ProtocolError::MalformedLine { line: 1, .. }));
}

#[test]
fn metric_without_unit_rejected() {
    let stdout =
        format!("{OBS_MARKER} {{\"kind\":\"metric\",\"name\":\"latency\",\"value\":1.5}}\n");
    let err = parse_observations(&stdout).unwrap_err();
    assert!(matches!(err, ProtocolError::InvalidPayload { .. }));
}

#[test]
fn fingerprint_requires_hex() {
    let ok = format!(
        "{OBS_MARKER} {{\"kind\":\"fingerprint\",\"name\":\"out\",\"fingerprint\":\"deadBEEF01\"}}\n"
    );
    assert_eq!(parse_observations(&ok).unwrap().len(), 1);

    let bad = format!(
        "{OBS_MARKER} {{\"kind\":\"fingerprint\",\"name\":\"out\",\"fingerprint\":\"xyz\"}}\n"
    );
    assert!(parse_observations(&bad).is_err());
}

#[test]
fn numeric_comparison_verdict_flow() {
    // End-to-end mini flow: observations -> independent comparison.
    let stdout = format!(
        "{OBS_MARKER} {{\"kind\":\"numeric_comparison\",\"name\":\"x\",\"expected\":2.5,\"observed\":2.5000000001}}\n"
    );
    let obs = parse_observations(&stdout).unwrap();
    let verdicts: Vec<bool> = obs
        .iter()
        .filter_map(|o| match o {
            ValidObservation::NumericComparison {
                expected, observed, ..
            } => Some(compare(*expected, *observed, &tol_abs(1e-6)).pass),
            _ => None,
        })
        .collect();
    assert_eq!(verdicts, vec![true]);
}

#[test]
fn special_values_coerce_from_strings_and_reject_garbage() {
    use scirust_verify_model::tolerance::Tolerance;
    let line = |observed: &str| {
        format!(
            "{OBS_MARKER} {{\"kind\":\"numeric_comparison\",\"name\":\"n\",\"expected\":1.0,\"observed\":\"{observed}\"}}\n"
        )
    };
    // NaN against a finite oracle fails even with absurd tolerance.
    let t = tol_abs(1e9);
    for bad in ["NaN", "inf", "-inf"] {
        let obs = parse_observations(&line(bad)).unwrap();
        match &obs[0] {
            ValidObservation::NumericComparison {
                expected, observed, ..
            } => {
                assert_eq!(*expected, 1.0);
                assert!(
                    !compare(*expected, *observed, &t).pass,
                    "{bad} must not pass"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
    // NaN == NaN passes only as explicit match.
    let nan_line = format!(
        "{OBS_MARKER} {{\"kind\":\"numeric_comparison\",\"name\":\"n\",\"expected\":\"NaN\",\"observed\":\"NaN\"}}\n"
    );
    let obs = parse_observations(&nan_line).unwrap();
    match &obs[0] {
        ValidObservation::NumericComparison {
            expected, observed, ..
        } => {
            assert!(compare(*expected, *observed, &Tolerance::exact()).pass);
            assert!(expected.is_nan() && observed.is_nan());
        }
        other => panic!("wrong variant: {other:?}"),
    }
    // Garbage strings are validation errors, not silent zeros.
    let err = parse_observations(&line("banana")).unwrap_err();
    assert!(matches!(err, ProtocolError::InvalidPayload { .. }));
}

#[test]
fn oracle_identity_is_preserved_end_to_end() {
    let stdout = format!(
        "{OBS_MARKER} {{\"kind\":\"numeric_comparison\",\"name\":\"gamma\",\"expected\":1.0,\"observed\":1.0000000001,\"oracle\":\"analytic-gamma-v1\"}}\n"
    );
    let obs = parse_observations(&stdout).unwrap();
    match &obs[0] {
        ValidObservation::NumericComparison { oracle, .. } => {
            assert_eq!(oracle.as_deref(), Some("analytic-gamma-v1"));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // Oracle identity survives conversion into stored observations.
    let model_obs = obs[0].to_model_observation();
    let text = serde_json::to_string(&model_obs).unwrap();
    assert!(text.contains("analytic-gamma-v1"), "{text}");

    // Absent oracle stays absent; whitespace-only is treated as absent.
    let bare = parse_observations(&format!(
        "{OBS_MARKER} {{\"kind\":\"numeric_comparison\",\"name\":\"g\",\"expected\":1.0,\"observed\":1.0,\"oracle\":\"   \"}}\n"
    ))
    .unwrap();
    match &bare[0] {
        ValidObservation::NumericComparison { oracle, .. } => assert!(oracle.is_none()),
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn nonfinite_model_payloads_roundtrip_without_null() {
    // NaN serialized into a stored observation must come back as "NaN",
    // never JSON null (the historical lossy path).
    let line = format!(
        "{OBS_MARKER} {{\"kind\":\"numeric_comparison\",\"name\":\"x\",\"expected\":\"NaN\",\"observed\":\"NaN\"}}\n"
    );
    let obs = parse_observations(&line).unwrap();
    let text = serde_json::to_string(&obs[0].to_model_observation().value).unwrap();
    assert!(text.contains("NaN"), "{text}");
    assert!(!text.contains("null"), "{text}");
}
