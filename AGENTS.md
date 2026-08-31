# SciRust-Verify Agent Bootstrap Contract

Before autonomous coding, evidence-schema work, verdict/policy changes, execution-boundary changes, cross-repository adapter work, PR creation, or merge decisions, read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCIRUST_VERIFY_ECOSYSTEM_ROADMAP.yaml
```

For ML benchmark, model-quality, memory, determinism, distributed, hardware-scope, artifact-lineage, or cross-repository ML evidence work, also read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/ML_MATURITY_5_OF_5.yaml
```

The ML maturity overlay makes 5/5 an evidence-backed exit criterion. A maturity claim must remain tied to exact model/workload/hardware/runtime scope; self-reported PASS, single-host results, microbenchmarks, signatures, or integrity sealing never strengthen the underlying scientific or performance claim by themselves.

If the roadmap or applicable ML overlay cannot be fetched or read, fail closed for major evidence-schema, verdict, trust, execution-boundary, cross-repository, or merge decisions. Read-only diagnosis is allowed.

## Repository role

SciRust-Verify owns evidence dossiers, integrity sealing, scope, claim evaluation, limitations, and verdict semantics. It does not own the scientific/runtime/product semantics of evidence producers.

Never inflate evidence scope:

- integrity does not strengthen the claim being evidenced;
- empirical execution is not formal proof;
- single-host determinism is not cross-platform determinism;
- microbenchmarks are not end-to-end product evidence;
- numerical self-consistency is not physical validation;
- bounded execution is not automatically a sandbox;
- a signed bundle proves origin/integrity under the trust policy, not correctness of the ML claim.

Adapters must preserve source semantics instead of flattening every producer to pass/fail.

Required CI must be green on the exact PR head before merge. A 5/5 ML verification claim additionally requires the applicable model-identity, raw-measurement, independent-threshold, cross-host and limitation gates in the ML overlay.

Reread the roadmap and applicable ML overlay at every session start, before schema/verdict/trust/execution-boundary changes, before cross-repository adapters, after strategy or ML-priority changes, and before merge decisions.

Do not merge the roadmap or ML maturity overlay itself into the default branch unless the user explicitly requests it.
