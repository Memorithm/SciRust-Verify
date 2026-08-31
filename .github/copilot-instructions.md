# SciRust-Verify repository agent instructions

Before repository changes, fetch and read the persistent off-main ecosystem roadmap:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCIRUST_VERIFY_ECOSYSTEM_ROADMAP.yaml
```

Treat root `AGENTS.md` as mandatory bootstrap policy. If the roadmap is unavailable, fail closed for major evidence-schema, verdict, trust, execution-boundary, cross-repository, or merge decisions.

Preserve evidence scope exactly. Integrity, reproducibility, benchmark execution, numerical validation, and scientific interpretation are distinct evidence classes and must never be silently collapsed into a stronger verdict.
