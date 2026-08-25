use super::*;
use std::path::PathBuf;

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "svsig-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_key(path: &PathBuf, contents: &str) {
    std::fs::write(path, format!("{contents}\n")).unwrap();
}

#[test]
fn keypair_generation_is_random_and_verifiable() {
    let (seed1, pub1) = generate_keypair().unwrap();
    let (_seed2, pub2) = generate_keypair().unwrap();
    assert_eq!(seed1.len(), 32);
    assert_ne!(pub1, pub2);

    let dir = tmpdir("gen");
    let sk = dir.join("signing.sk");
    let pk = dir.join("verify.pk");
    write_key(&sk, &hex::encode(&seed1));
    write_key(&pk, &pub1);

    let loaded_pub = load_public_key(&pk).unwrap();
    assert_eq!(loaded_pub, pub1);
}

#[test]
fn key_id_is_deterministic_and_short() {
    let (_, pub_hex) = generate_keypair().unwrap();
    let id1 = key_id(&pub_hex).unwrap();
    let id2 = key_id(&pub_hex).unwrap();
    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 16);
    // Different keys -> different ids.
    let (_, other) = generate_keypair().unwrap();
    assert_ne!(id1, key_id(&other).unwrap());
    // Malformed keys are rejected.
    assert!(key_id("nothex").is_err());
    assert!(key_id(&hex::encode([0u8; 16])).is_err()); // too short
}

#[test]
fn sign_and_verify_roundtrip() {
    let dir = tmpdir("roundtrip");
    let (seed, public) = generate_keypair().unwrap();
    let sk = dir.join("k.sk");
    let pk = dir.join("k.pk");
    write_key(&sk, &hex::encode(&seed));
    write_key(&pk, &public);

    let manifest = br#"{"files":{"run.json":"abc"}}"#;
    let sig_bytes = sign_manifest(&sk, manifest).unwrap();
    let doc = SignatureDocument::parse(&sig_bytes).unwrap();

    // Embedded-key verification succeeds.
    doc.verify_embedded(manifest).unwrap();

    // Pinned verification with the right key id succeeds...
    let id = key_id(&public).unwrap();
    doc.verify_pinned(manifest, &id).unwrap();

    // ...and with the wrong pin fails.
    assert!(matches!(
        doc.verify_pinned(manifest, "0000000000000000"),
        Err(SignatureError::VerificationFailed)
    ));
}

#[test]
fn tampered_manifests_are_rejected() {
    let dir = tmpdir("tamper");
    let (seed, _) = generate_keypair().unwrap();
    let sk = dir.join("k.sk");
    write_key(&sk, &hex::encode(&seed));

    let original = br#"{"files":{}}"#;
    let doc = SignatureDocument::create(&sk, original).unwrap();

    let mut tampered = original.to_vec();
    tampered.extend_from_slice(b" ");
    assert!(matches!(
        doc.verify_embedded(&tampered),
        Err(SignatureError::VerificationFailed)
    ));
}

#[test]
fn foreign_keys_cannot_fool_a_pinned_verifier() {
    // Attacker re-signs a modified manifest with THEIR key.
    let attacker_dir = tmpdir("attacker");
    let (attacker_seed, _) = generate_keypair().unwrap();
    let attacker_sk = attacker_dir.join("evil.sk");
    write_key(&attacker_sk, &hex::encode(&attacker_seed));
    let evil_manifest = br#"{"files":{}}"#;
    let evil_doc = SignatureDocument::create(&attacker_sk, evil_manifest).unwrap();

    // Cryptographically valid against the embedded key:
    evil_doc.verify_embedded(evil_manifest).unwrap();

    // But the pinned verifier (holding the honest key id) rejects it.
    let (_honest_seed, honest_pub) = generate_keypair().unwrap();
    let honest_id = key_id(&honest_pub).unwrap();
    assert!(matches!(
        evil_doc.verify_pinned(evil_manifest, &honest_id),
        Err(SignatureError::VerificationFailed)
    ));
}

#[test]
fn malformed_keys_and_documents_are_rejected() {
    let dir = tmpdir("malformed");
    let bad_sk = dir.join("bad.sk");
    write_key(&bad_sk, "definitely-not-hex");
    assert!(load_secret_key(&bad_sk).is_err());

    let short_sk = dir.join("short.sk");
    write_key(&short_sk, &hex::encode([7u8; 16]));
    assert!(load_secret_key(&short_sk).is_err());

    assert!(SignatureDocument::parse(b"not json").is_err());
    assert!(SignatureDocument::parse(br#"{"schema_version":1}"#).is_err());

    // Unknown algorithm rejected at parse time.
    let (_, pub_hex) = generate_keypair().unwrap();
    let doc = SignatureDocument {
        schema_version: 1,
        algorithm: "rsa".into(),
        key_id: key_id(&pub_hex).unwrap(),
        public_key: pub_hex,
        signature: hex::encode([0u8; 64]),
        signed_document: SIGNED_DOCUMENT.into(),
        created_at_utc: "2026-01-01T00:00:00Z".into(),
        tool_version: "t".into(),
    };
    assert!(matches!(
        SignatureDocument::parse(&serde_json::to_vec(&doc).unwrap()),
        Err(SignatureError::MalformedDocument(_))
    ));
}
