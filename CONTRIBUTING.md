# Contributing

Thanks for helping SciRust-Verify stay honest.

## Toolchain

* Rust stable ≥ 1.89 (workspace `rust-version`).
* `cargo fmt`, `cargo clippy`, `cargo test` must all be clean — CI enforces
  exactly what you should run locally:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

## Rules of the road

1. **No fake verification.** Every claim a check produces must come from real
   execution and recorded evidence. Never set `Verdict::Verified` from config,
   presence of files, or optimism.
2. **Scope discipline.** A `VERIFIED` verdict is always scoped. If evidence
   covers one host/toolchain/seed, say so; derive limitations automatically.
3. **Evidence immutability.** Persisted evidence is never silently rewritten.
   Corrections happen by adding superseding evidence with `derived_from`.
4. **No panics on external input.** `unwrap`/`expect` only in tests or after
   proving invariants. Structured errors for everything else.
5. **Determinism where it matters.** Plans, reports, digests and fingerprints
   must not depend on HashMap iteration order, locale or wall-clock ordering.
6. **Unsafe code is denied** at the workspace level.
7. **Warnings are errors** (`-D warnings`). Fix root causes; do not suppress
   lints globally.
8. **Tests travel with behavior.** Verdict-matrix changes need matrix tests;
   runner changes need process-level tests (success/failure/timeout/spawn/
   truncation); store changes need corruption tests.

## Evidence integrity expectations

If your change touches storage or serialization:

* bump/extend `docs/EVIDENCE_FORMAT.md`;
* keep `schema_version` honest — new documents get version fields;
* add/refresh corruption-detection tests (modified file, deleted attachment,
  duplicate id, broken reference).

## Scientific-claim rules

* Distinguish CLAIM / CHECK / EXECUTION / EVIDENCE / OBSERVATION / VERDICT /
  SCOPE / LIMITATION explicitly in code and docs.
* Never claim cross-platform determinism from single-host evidence.
* Never call empirical execution "formal proof".
* SKIPPED ≠ UNSUPPORTED: implementation-exists-but-could-not-run vs
  no-implementation. Reports preserve the difference.

## Pull requests

* One coherent change per PR; feature branches off `main`.
* Update CHANGELOG.md with actual behavior changes.
* The self-verification gate must pass:
  `cargo run -p scirust-verify-cli -- verify .`
