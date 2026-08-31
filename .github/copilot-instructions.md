# SciRust-Verify repository agent instructions

Before repository changes, fetch and read the persistent off-main ecosystem roadmap:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCIRUST_VERIFY_ECOSYSTEM_ROADMAP.yaml
```

For ML benchmark, model-quality, memory, determinism, distributed, hardware-scope, artifact-lineage, or cross-repository ML evidence work, also read:

```bash
git show origin/agent/ecosystem-roadmap:.agent/ML_MATURITY_5_OF_5.yaml
```

Treat root `AGENTS.md` as mandatory bootstrap policy. If the roadmap or applicable ML overlay is unavailable, fail closed for major evidence-schema, verdict, trust, execution-boundary, cross-repository, or merge decisions.

Preserve evidence scope exactly. Integrity, reproducibility, benchmark execution, numerical validation, model quality, hardware scope and scientific interpretation are distinct evidence classes and must never be silently collapsed into a stronger verdict. A `5/5` ML evidence claim requires exact model/workload/environment identity, raw measurements, independent threshold evaluation where possible, cross-host scope and explicit limitations.
