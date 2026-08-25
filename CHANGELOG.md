# Changelog

All notable changes to SciRust-Verify are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer.

## [0.1.0] — foundation (unreleased)

### Added

- Cargo workspace with eleven crates: model, runner, numerics, store, policy,
  core, cargo provider, determinism engine, report rendering, SciRust adapter
  slot and CLI binary `scirust-verify`.
- Domain model with typed identifiers (ArtifactId/ClaimId/CheckId/EvidenceId/
  RunId), content digests (SHA-256), verification scope, tolerances
  (absolute/relative/ULP, signed-zero policy), claims, checks, evidence,
  observations, requirement levels and five-valued verdicts with a documented
  aggregation contract.
- Safe command runner: structural command specs (no shell), per-command
  timeouts with distinct TimedOut state, bounded stdout/stderr capture with
  truncation evidence, spawn-failure records, environment redaction of
  secret-like variables and allowlisted evidence recording.
- Numerics engine: abs/rel/ULP comparisons with NaN/infinity/signed-zero/
  subnormal policies; SVOP v1 structured observation protocol
  (`SCIRUST_VERIFY_OBS_V1` lines) for numeric comparisons, fingerprints,
  metrics and boolean properties; independent re-application of tolerances by
  the verifier (programs' own verdicts are never trusted).
- Versioned evidence store: run lifecycle state machine, atomic writes,
  content-addressed attachments, structural validation at finalize, SHA-256
  bundle sealing written last, corruption detection on read (modified files,
  deleted payloads, unsealed additions), frozen sealed runs.
- Policy profiles: basic / scientific / reproducibility / strict with
  documented precedence defaults < profile < manifest < CLI; pure dossier
  gate (PASS / PASS_WITH_GAPS / NOT_VERIFIED / FAIL).
- Core pipeline: discovery (Cargo/Git facts), strict manifest validation,
  deterministic planning with canonical plan digest, sequential execution,
  claim evaluation with mandatory reasoning, limitations derivation,
  report generation inside the sealed bundle.
- Generic Cargo provider: fmt/clippy/check/build/test/doc checks, optional or
  required cargo-deny, dependency snapshot via `cargo metadata`, availability
  probes producing honest SKIPPED evidence, explicit features only (never
  --all-features).
- Determinism engine: N independent process executions compared by canonical
  fingerprints (raw stdout digest or SVOP structured mode), thread-count
  variation via configurable env var, derived comparison evidence linked to
  every execution it used.
- Built-in providers: source-clean probe; manifest-declared custom command
  checks; numeric SVOP checks.
- Reports: machine-readable report.json and human Markdown report.md,
  regenerable from stored documents, with mandatory Limitations section.
- CLI commands: init, inspect, plan, verify, report (--json/--markdown/
  --check-integrity), replay (new linked run; original untouched), diff,
  doctor, schema. Stable exit codes 0/1/2/3. JSON mode emits clean stdout.
- Fixture suite: passing-project, failing-tests, deterministic-project,
  nondeterministic-project, timeout-project, large-output-project,
  numeric-pass, numeric-fail — all dependency-free for offline test runs.
- End-to-end CLI tests covering pass/fail verdicts, determinism positive and
  negative paths, numeric tolerance enforcement independent of program exit
  codes, timeout handling, output truncation evidence, tampered-bundle
  detection, invalid manifests and replay/diff flows.
- Self-verification: repository-root scirust-verify.toml drives
  `scirust-verify verify .` as an acceptance gate.
- Documentation: README, ARCHITECTURE, EVIDENCE_FORMAT, THREAT_MODEL,
  SECURITY, CONTRIBUTING and this changelog.
