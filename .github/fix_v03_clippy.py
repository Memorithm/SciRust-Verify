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
    "    Artifact, Claim, ClaimEvaluation, Digest, DirtyState, EnvironmentSnapshot, GpuIdentity,\n    VerificationScope, Verdict, SCHEMA_VERSION, TOOL_IDENTITY,\n",
    "    Artifact, Claim, ClaimEvaluation, Digest, DirtyState, EnvironmentSnapshot,\n    VerificationScope, Verdict, SCHEMA_VERSION, TOOL_IDENTITY,\n",
    "production GpuIdentity import",
)
s = once(
    s,
    "    pub(crate) min_platforms: usize,\n    pub(crate) require_scope: bool,\n",
    "    pub(crate) min_platforms: usize,\n",
    "unused require_scope option",
)
s = once(
    s,
    '''    let human = render_human(
        options,
        &rows,
        all_verified,
        source_consistency,
        claim_definitions_consistent,
        distinct_platforms,
        scope_certified,
        &limitations,
    );
''',
    '''    let human = render_human(
        options,
        &rows,
        all_verified,
        source_consistency,
        scope_certified,
        &limitations,
    );
''',
    "render_human call",
)
s = once(
    s,
    '''fn render_human(
    options: &AggregateOptions<'_>,
    rows: &[Row],
    all_verified: bool,
    source_consistency: SourceConsistency,
    claim_definitions_consistent: bool,
    distinct_platforms: usize,
    scope_certified: bool,
    limitations: &[String],
) -> String {
    let mut out = String::new();
''',
    '''fn render_human(
    options: &AggregateOptions<'_>,
    rows: &[Row],
    all_verified: bool,
    source_consistency: SourceConsistency,
    scope_certified: bool,
    limitations: &[String],
) -> String {
    let claim_definitions_consistent = claim_definitions_consistent(rows);
    let distinct_platforms = rows
        .iter()
        .filter(|row| row.platform.identifiable())
        .map(|row| row.platform.clone())
        .collect::<BTreeSet<_>>()
        .len();
    let mut out = String::new();
''',
    "render_human signature",
)
s = once(
    s,
    "    use scirust_verify_model::{CpuIdentity, HostIdentity, ToolchainIdentity};\n",
    "    use scirust_verify_model::{CpuIdentity, GpuIdentity, HostIdentity, ToolchainIdentity};\n",
    "test GpuIdentity import",
)
p.write_text(s)

main = Path("crates/scirust-verify-cli/src/main.rs")
m = main.read_text()
m = once(
    m,
    '''                project: &root,
                min_platforms,
                require_scope,
            })
''',
    '''                project: &root,
                min_platforms,
            })
''',
    "AggregateOptions construction",
)
main.write_text(m)

print("V0.3 clippy fixes applied")
