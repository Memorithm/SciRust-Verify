from pathlib import Path


def once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)

p = Path("crates/scirust-verify-cli/src/aggregate_cli.rs")
s = p.read_text()

s = once(
    s,
    '''fn assess_source_consistency(records: &[RunRecord]) -> SourceConsistency {
    let Some(first) = records.first() else {
        return SourceConsistency::NotVerified;
    };
    if records
        .iter()
        .any(|record| record.artifact != first.artifact)
    {
        return SourceConsistency::Mismatched;
    }
    let anchors = records
        .iter()
        .map(|record| record.source_anchor.as_ref())
        .collect::<Vec<_>>();
    if anchors.iter().any(|anchor| anchor.is_none()) {
        return SourceConsistency::NotVerified;
    }
    let first_anchor = anchors[0].expect("checked non-empty anchors");
    if anchors
        .iter()
        .all(|anchor| anchor.is_some_and(|value| value == first_anchor))
    {
        return SourceConsistency::Verified;
    }
    let comparable = anchors.iter().all(|anchor| {
        anchor
            .map(|value| value.kind == first_anchor.kind)
            .unwrap_or(false)
    });
    if comparable {
        SourceConsistency::Mismatched
    } else {
        SourceConsistency::NotVerified
    }
}

fn claim_definitions_consistent(rows: &[Row]) -> bool {
    let mut definitions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for row in rows {
        let Some(digest) = row.claim_definition_digest.as_deref() else {
            return false;
        };
        definitions
            .entry(row.claim.as_str())
            .or_default()
            .insert(digest);
    }
    !definitions.is_empty() && definitions.values().all(|digests| digests.len() == 1)
}
''',
    '''fn assess_source_consistency(records: &[RunRecord]) -> SourceConsistency {
    let Some(first) = records.first() else {
        return SourceConsistency::NotVerified;
    };
    if records
        .iter()
        .any(|record| record.artifact != first.artifact)
    {
        return SourceConsistency::Mismatched;
    }
    let Some(first_anchor) = first.source_anchor.as_ref() else {
        return SourceConsistency::NotVerified;
    };
    if records.iter().any(|record| record.source_anchor.is_none()) {
        return SourceConsistency::NotVerified;
    }
    if records
        .iter()
        .all(|record| record.source_anchor.as_ref() == Some(first_anchor))
    {
        return SourceConsistency::Verified;
    }
    let comparable = records.iter().all(|record| {
        record
            .source_anchor
            .as_ref()
            .is_some_and(|value| value.kind == first_anchor.kind)
    });
    if comparable {
        SourceConsistency::Mismatched
    } else {
        SourceConsistency::NotVerified
    }
}

fn claim_definitions_consistent(rows: &[Row]) -> bool {
    let mut per_run: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    for row in rows {
        let Some(digest) = row.claim_definition_digest.as_deref() else {
            return false;
        };
        let claims = per_run.entry(row.run.as_str()).or_default();
        if let Some(previous) = claims.insert(row.claim.as_str(), digest) {
            if previous != digest {
                return false;
            }
        }
    }
    let mut definitions = per_run.values();
    let Some(first) = definitions.next() else {
        return false;
    };
    definitions.all(|claims| claims == first)
}
''',
    "source and claim consistency",
)

s = once(
    s,
    '''    fn record(id: &str, source: &str) -> RunRecord {
        RunRecord {
            run_id: id.into(),
            artifact: ArtifactMetadata {
                kind: "cargo_workspace".into(),
                name: "demo".into(),
                version: Some("0.1.0".into()),
            },
            source_anchor: Some(SourceAnchor {
                kind: "clean_git_commit",
                value: source.into(),
            }),
            matched_claims: 1,
            integrity_files: 10,
        }
    }
''',
    '''    fn record(id: &str, source: &str) -> RunRecord {
        RunRecord {
            run_id: id.into(),
            artifact: ArtifactMetadata {
                kind: "cargo_workspace".into(),
                name: "demo".into(),
                version: Some("0.1.0".into()),
            },
            source_anchor: Some(SourceAnchor {
                kind: "clean_git_commit",
                value: source.into(),
            }),
            matched_claims: 1,
            integrity_files: 10,
        }
    }

    fn row(run: &str, claim: &str, digest: &str) -> Row {
        Row {
            run: run.into(),
            claim: claim.into(),
            level: "required".into(),
            verdict: Verdict::Verified,
            reasoning: "fixture".into(),
            claim_definition_digest: Some(digest.into()),
            platform: platform("x86_64-unknown-linux-gnu", "cpu", None),
            rustc: None,
        }
    }
''',
    "row test helper",
)

s = once(
    s,
    '''    #[test]
    fn source_consistency_requires_same_provable_source() {
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), record("b", "abc")]),
            SourceConsistency::Verified
        );
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), record("b", "def")]),
            SourceConsistency::Mismatched
        );
        let mut unknown = record("b", "abc");
        unknown.source_anchor = None;
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), unknown]),
            SourceConsistency::NotVerified
        );
    }
''',
    '''    #[test]
    fn source_consistency_requires_same_provable_source() {
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), record("b", "abc")]),
            SourceConsistency::Verified
        );
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), record("b", "def")]),
            SourceConsistency::Mismatched
        );
        let mut unknown = record("b", "abc");
        unknown.source_anchor = None;
        assert_eq!(
            assess_source_consistency(&[record("a", "abc"), unknown]),
            SourceConsistency::NotVerified
        );
    }

    #[test]
    fn claim_consistency_requires_identical_claim_sets_per_run() {
        assert!(claim_definitions_consistent(&[
            row("run-a", "foo@same", "sha256:a"),
            row("run-b", "foo@same", "sha256:a"),
        ]));
        assert!(!claim_definitions_consistent(&[
            row("run-a", "foo@left", "sha256:a"),
            row("run-b", "foo@right", "sha256:b"),
        ]));
        assert!(!claim_definitions_consistent(&[
            row("run-a", "foo@same", "sha256:a"),
            row("run-b", "foo@same", "sha256:b"),
        ]));
    }
''',
    "claim-set regression test",
)

p.write_text(s)
print("V0.3 claim-set hardening applied")
