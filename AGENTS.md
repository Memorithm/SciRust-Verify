# SciRust-Verify Agent Bootstrap Contract

Before autonomous coding, evidence-schema work, verdict/policy changes, execution-boundary changes, cross-repository adapter work, PR creation, or merge decisions, read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCIRUST_VERIFY_ECOSYSTEM_ROADMAP.yaml
```

If the roadmap cannot be fetched or read, fail closed for major evidence-schema, verdict, trust, execution-boundary, cross-repository, or merge decisions. Read-only diagnosis is allowed.

## Repository role

SciRust-Verify owns evidence dossiers, integrity sealing, scope, claim evaluation, limitations, and verdict semantics. It does not own the scientific/runtime/product semantics of evidence producers.

Never inflate evidence scope:

- integrity does not strengthen the claim being evidenced;
- empirical execution is not formal proof;
- single-host determinism is not cross-platform determinism;
- microbenchmarks are not end-to-end product evidence;
- numerical self-consistency is not physical validation;
- bounded execution is not automatically a sandbox.

Adapters must preserve source semantics instead of flattening every producer to pass/fail.

Required CI must be green on the exact PR head before merge.

Reread the roadmap at every session start, before schema/verdict/trust/execution-boundary changes, before cross-repository adapters, after strategy changes, and before merge decisions.

Do not merge the roadmap itself into the default branch unless the user explicitly requests it.
