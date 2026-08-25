# SciRust-Verify Architecture

This document explains how SciRust-Verify is built: the dataflow, the crates,
the provider model, the evidence graph and the trust boundaries.

## The core dataflow

```
project/artifact
      ↓ discovery
manifest (scirust-verify.toml)
      ↓ planning
verification plan  (checks exist BEFORE execution; canonical digest)
      ↓ execution
raw evidence       (bounded captures, timeouts, env redaction)
      ↓ interpretation
structured observations
      ↓ evaluation
claim verdicts     (+ human-readable reasoning, mandatory)
      ↓ aggregation
dossier verdict    (pure policy gate)
      ↓ sealing
evidence dossier   (versioned bundle + integrity manifest)
      ↓ rendering
machine report / human report
```

## Workspace layout

| Crate | Responsibility |
|---|---|
| `scirust-verify-model` | Typed domain vocabulary: ids, digests, artifacts, claims, checks, evidence, observations, scope, tolerances, verdicts. No I/O. |
| `scirust-verify-runner` | Safe bounded command execution: structural `CommandSpec`, timeouts, capture limits, environment redaction. Never a shell. |
| `scirust-verify-numerics` | Floating-point comparison engine (abs/rel/ULP, NaN/inf/±0 policy) and the SVOP v1 structured-observation protocol parser. |
| `scirust-verify-store` | Versioned run bundles: atomic writes, lifecycle states, integrity sealing (`bundle.json`), corruption detection. |
| `scirust-verify-policy` | Policy profiles (`basic`, `scientific`, `reproducibility`, `strict`) and the pure dossier gate. |
| `scirust-verify-core` | Discovery, manifest loading/validation, provider traits, built-in providers, provenance/tree-digest collection, claim evaluation, end-to-end pipeline. |
| `scirust-verify-cargo` | Generic Cargo provider: fmt/clippy/check/build/test/doc/deny/metadata checks with availability probes. Works without SciRust. |
| `scirust-verify-determinism` | Cross-process fingerprinting engine incl. thread-count variation. |
| `scirust-verify-report` | Report rendering from persisted documents only (never scrapes its own Markdown). |
| `scirust-verify-scirust` | SciRust test-protocol adapter: parses protocol `summary.txt` bundles and maps gates to claims bijectively (`PASS→Verified`, `FAIL→Failed`, `SKIP→Skipped`). Wired into the CLI via `scirust-verify ingest-scirust <bundle>`. |
| `scirust-verify-artifacts` | Validation-first ingestion of ecosystem formats: SciCapsule v1 manifests (schema + payload integrity) and Forge candidate envelopes v1 (canonical fingerprint recomputation). Envelope consistency is attested; Forge correctness evaluation is explicitly not independent verification. |
| `scirust-verify-cli` | Thin binary: parse args → library calls → format output → exit code. |

Dependency direction is strictly downward: model ← everything; report/store
are leaf-level consumers of model; core composes runner+store+numerics;
providers sit on core traits; cli composes all.

## Discovery & manifest

`DiscoveryContext::discover(root)` inspects — without heavy execution:

* project kind (`Cargo{is_workspace, packages}` | `Unknown`),
* Git identity: commit, branch, origin URL, dirty state (`Unknown` on failure),
* manifest presence.

The manifest `scirust-verify.toml` carries `schema_version = 1` (missing or
higher versions are rejected), artifact naming, verification-wide settings
(timeout, capture bounds, explicit targets/features), per-provider sections,
claim requirement levels, custom checks and numeric checks. Validation is
strict: unknown fields are rejected, duplicate check ids fail at load time,
tolerances must be finite and non-negative, determinism requires ≥2 runs and
an argv.

Precedence: **built-in defaults < profile preset < manifest < CLI flags.**

## Providers

Providers implement one trait (`core::planning::VerificationProvider`):

```rust
fn name() -> &'static str
fn detect(&ctx) -> Detection                       // applies here?
fn plan(&request) -> Vec<Check>                    // deterministic order
fn execute(&check, env) -> CheckExecution          // evidence via sink
```

V0.1 ships statically compiled providers only:

* `CargoProvider` — cargo checks; availability probes turn missing tools into
  honest `SKIPPED` evidence instead of failures.
* `DeterminismProvider` — composite multi-run engine.
* `CustomChecksProvider` / `NumericChecksProvider` — manifest-declared commands.
* `SourceCleanProvider` — Git hygiene from recorded facts.

Planning happens before any execution so that `plan` shows the exact workload
(provider, command, cwd, timeout, level, supported claims) and a SHA-256 over
the canonical JSON of the sorted plan can be stored (`planned_plan_digest`).

## Runner

Commands are structural (`program`, args, cwd, env policy, timeout, capture
limits) and spawned directly — never through a shell. Output is drained by
reader threads into bounded buffers; excess is discarded but *recorded*
(`stdout_truncated`, `total_bytes`). Every command has a deadline; expiry
kills the child and yields the distinct state `TimedOut`. Spawn failures are
records, not panics. The default environment policy strips secret-like names
(`TOKEN`, `PASSWORD`, `SECRET`, `API_KEY`, `AUTHORIZATION`,
`PRIVATE_KEY`) and records only an allowlist in evidence. This is defense in
depth, not a sandbox.

## Evidence graph

```
Artifact → Claim → Check → Evidence → Observation → Verdict
                        ↑
             Evidence --derived_from--> Evidence
```

Evidence objects are immutable once sealed. Derived evidence must reference
its inputs: e.g. the determinism fingerprint-comparison evidence lists every
per-run execution evidence it was computed from. Claim evaluations reference
their supporting checks and evidence ids, and always carry written reasoning.

## Storage

One directory per run under `.scirust-verify/runs/<run-id>/`; every document
carries `schema_version`. Writes are atomic (temp + rename). Lifecycle:
`planning → running → finalized | aborted`; interrupted runs keep partial
evidence and never look final. Finalization validates structure (unique ids,
valid references, attachment integrity, digest match) and then seals by
writing `bundle.json` last — SHA-256 of every other file. Readers verify all
digests, detect unsealed additions, and refuse to mutate sealed runs.

Attachments are content-addressed under `evidence/files/` by their digest;
log paths inside evidence point into the run directory (`logs/*.log`).

## Verdict semantics

Per-check/provider outcomes map onto five verdicts (see model docs). A claim's
verdict combines its supporting executions: any failure dominates; missing
evidence beats success; checks that merely could not run do not contradict a
verified sibling but surface as limitations. The global gate is pure logic in
the policy crate: required-failed ⇒ FAIL; required-unestablished ⇒
NOT_VERIFIED; required-skipped or degraded-recommended ⇒ PASS_WITH_GAPS;
otherwise PASS.

## Trust boundaries

SciRust-Verify V0.1 executes commands on the host. It is not a sandbox. The
runner interface (`CommandSpec` → record) is deliberately shaped so future
implementations can route execution through containers, VMs or remote workers
without changing the domain model. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Future integration points

* **SciRust** — completed: `ingest-scirust` normalizes finished protocol
  bundles into dossiers while attaching the original summary verbatim.
* **SciCapsule** — implemented for what the upstream schema defines:
  `verify-capsule` validates v1 manifests against the exact contract of
  `scirust-capsule-schema` and verifies every payload digest + byte length.
  Entrypoint execution remains UNSUPPORTED until upstream defines semantics.
* **Forge** — implemented for attestation: `ingest-forge` recomputes the
  candidate envelope fingerprint from canonical bytes and binds fields into
  a dossier; Forge's own evaluation is never treated as independent
  verification (trust scope recorded in evidence metadata).
* **Forge** — candidates become Artifacts; Forge's own evaluation may be
  ingested as evidence but never automatically counts as independent
  verification.
* **SBOM** — implemented: `cargo:sbom` emits an SPDX 2.3 document derived
  strictly from resolved `cargo metadata`; unknown facts are `NOASSERTION`,
  never fabricated. Enabled via `[cargo] sbom = true` plus the
  `sbom_generated` claim at any level.


## Cross-run scope aggregation

Cross-run aggregation is a read-only operation over already finalized dossiers. It first verifies
`bundle.json` integrity for every input run, then evaluates whether the requested claim is present
and verified everywhere. Scope certification additionally requires compatible artifact metadata,
a common strong source anchor, canonical claim-definition identity, and enough distinct normalized
execution platforms. Missing platform/source data produces `NOT_VERIFIED` scope coverage rather
than an inferred identity.

`VerificationScope` carries optional explicit `GpuIdentity` data. The field is populated only by
checks that actually know the GPU backend/device/driver; an execution backend string alone is not
treated as a hardware identity. Aggregation never upgrades per-run success into CPU/GPU output
parity unless the underlying verified claim is itself `cpu_gpu_parity`.
