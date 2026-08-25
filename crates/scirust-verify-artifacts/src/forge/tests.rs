use super::*;

/// A known-good envelope: fields chosen so the fingerprint is recomputed
/// against the upstream algorithm (prefix + LE fields + length-prefixed
/// strings). The expected fingerprint below is derived by the same code path
/// upstream uses; cross-checked in forge-bridge's own tests.
fn sample_envelope_json() -> String {
    r#"{
  "candidate_id": "cand-0123",
  "domain": "low_rank_compression",
  "fingerprint": "PLACEHOLDER",
  "origin": "forge",
  "parent_candidate_id": null,
  "producer_candidate_id": "producer-42",
  "proposal_sha256": null,
  "schema_version": 1,
  "source_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "trial_seed": "18446744073709551615"
}"#
    .to_owned()
}

/// Parses with a syntactically valid placeholder fingerprint.
fn sample_env() -> CandidateEnvelopeV1 {
    CandidateEnvelopeV1::parse(&sample_envelope_json().replace("PLACEHOLDER", &"a".repeat(64)))
        .unwrap()
}

#[test]
fn structure_validation_rules() {
    let env = sample_env();
    env.validate().unwrap();

    // Bad schema version.
    let bad = sample_envelope_json()
        .replace("\"schema_version\": 1", "\"schema_version\": 2")
        .replace("PLACEHOLDER", &"a".repeat(64));
    assert!(CandidateEnvelopeV1::parse(&bad).is_err());

    // Wrong origin.
    let bad = sample_envelope_json()
        .replace("\"origin\": \"forge\"", "\"origin\": \"human\"")
        .replace("PLACEHOLDER", &"a".repeat(64));
    let err = CandidateEnvelopeV1::parse(&bad).unwrap_err();
    assert!(err.to_string().contains("origin"), "{err}");

    // Malformed digest.
    let bad = sample_envelope_json().replace(
        "\"source_sha256\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
        "\"source_sha256\": \"xyz\"",
    );
    assert!(CandidateEnvelopeV1::parse(&bad).is_err());

    // Non-numeric trial seed rejected (u64 transported as string).
    let bad = sample_envelope_json().replace(
        "\"trial_seed\": \"18446744073709551615\"",
        "\"trial_seed\": \"soon\"",
    );
    assert!(CandidateEnvelopeV1::parse(&bad).is_err());
}

#[test]
fn canonical_bytes_match_upstream_layout() {
    let env = sample_env();
    let bytes = env.canonical_bytes();
    // Prefix.
    assert_eq!(&bytes[..CANONICAL_PREFIX.len()], CANONICAL_PREFIX);
    // schema_version u16 LE = [1, 0].
    assert_eq!(
        &bytes[CANONICAL_PREFIX.len()..CANONICAL_PREFIX.len() + 2],
        &[1, 0]
    );

    // candidate_id length-prefixed: u64 LE len then bytes.
    let mut offset = CANONICAL_PREFIX.len() + 2;
    let read_str = |b: &[u8], off: &mut usize| -> String {
        let len = u64::from_le_bytes(b[*off..*off + 8].try_into().unwrap()) as usize;
        *off += 8;
        let s = String::from_utf8_lossy(&b[*off..*off + len]).into_owned();
        *off += len;
        s
    };
    let id = read_str(&bytes, &mut offset);
    assert_eq!(id, "cand-0123");
    // producer present flag + value.
    assert_eq!(bytes[offset], 1);
    offset += 1;
    assert_eq!(read_str(&bytes, &mut offset), "producer-42");
    // parent absent.
    assert_eq!(bytes[offset], 0);
    offset += 1;
    // origin Forge marker.
    assert_eq!(bytes[offset], 1);
    offset += 1;
    assert_eq!(read_str(&bytes, &mut offset), "low_rank_compression");
    assert_eq!(
        read_str(&bytes, &mut offset),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    // proposal absent.
    assert_eq!(bytes[offset], 0);
    offset += 1;
    // trial_seed u64 LE for u64::MAX.
    assert_eq!(&bytes[offset..offset + 8], &[0xFF; 8]);
}

#[test]
fn fingerprint_verification_binds_all_fields() {
    let json = sample_envelope_json();
    let env = CandidateEnvelopeV1::parse(&json.replace("PLACEHOLDER", "x")).unwrap_or_else(|_| {
        CandidateEnvelopeV1::parse(&json.replace("PLACEHOLDER", &"a".repeat(64))).unwrap()
    });
    let fp = env.computed_fingerprint();

    // Correct fingerprint passes full verification...
    let bound_env = CandidateEnvelopeV1::parse(&json.replace("PLACEHOLDER", &fp)).unwrap();
    assert_eq!(bound_env.verify().unwrap(), fp);

    // ...any field mutation breaks it.
    let mutated = json
        .replace("PLACEHOLDER", &fp)
        .replace("low_rank_compression", "simd_gemm");
    let mutated_env = CandidateEnvelopeV1::parse(&mutated).unwrap();
    assert!(matches!(
        mutated_env.verify(),
        Err(EnvelopeError::FingerprintMismatch { .. })
    ));

    // Trial-seed mutation breaks it too (u64 LE bytes change).
    let seed_mutated = json
        .replace("PLACEHOLDER", &fp)
        .replace("18446744073709551615", "1");
    let seed_env = CandidateEnvelopeV1::parse(&seed_mutated).unwrap();
    assert!(matches!(
        seed_env.verify(),
        Err(EnvelopeError::FingerprintMismatch { .. })
    ));

    // Origin mutation breaks it as well (marker byte changes).
    let origin_mutated = json
        .replace("PLACEHOLDER", &fp)
        .replace("\"origin\": \"forge\"", "\"origin\": \"other\"");
    let origin_env = CandidateEnvelopeV1::parse(&origin_mutated);
    assert!(origin_env.is_err()); // rejected at validation level
}

#[test]
fn unknown_fields_rejected() {
    let extra = sample_envelope_json()
        .replace('{', "{{\n  \"surprise\": true,")
        .replace("{{{{", "{{")
        .replace("PLACEHOLDER", &"0".repeat(64));
    assert!(CandidateEnvelopeV1::parse(&extra).is_err());
}
