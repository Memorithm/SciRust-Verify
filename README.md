# SciRust-Verify

**Verification, evidence, provenance and trust layer for the SciRust ecosystem.**

SciRust-Verify turns *claims* into structured **Evidence Dossiers**: versioned,
integrity-sealed bundles that record exactly what was executed, under which
scope, which properties were checked, what raw evidence was captured, and which
verdicts that evidence actually justifies.

> Claims are cheap. Evidence is expensive.
> SciRust-Verify preserves the difference.

## Why does it exist?

Saying "this is deterministic" or "the tests pass" costs nothing. Proving it,
under a recorded scope, with tamper-evident artifacts, is real engineering.
SciRust-Verify exists so that every verification statement in the SciRust
ecosystem can be traced to:

```
SOURCE → ARTIFACT IDENTITY → PROVENANCE → ENVIRONMENT → SCOPE → PLAN
       → EXECUTION → RAW EVIDENCE → OBSERVATIONS → CHECK RESULTS
       → CLAIM EVALUATION → VERDICTS → LIMITATIONS → REPRODUCTION
```

If any link in that chain is broken, the verdict says so.

## What it verifies

Anything that can be executed and observed, starting with generic Cargo
projects (no SciRust required):

* **Build & tests** — `cargo build`, `cargo test` as gated claims.
* **Hygiene** — `cargo clippy -D warnings`, `cargo fmt --check`, `cargo doc`.
* **Supply chain** — `cargo deny check` when installed (optional by default).
* **Cross-process determinism** — N independent process executions compared by
  canonical fingerprints; optional thread-count variation via an env var.
* **Numeric / oracle properties** — programs emit structured observations
  (SVOP v1 protocol); SciRust-Verify *independently re-applies tolerances*
  rather than trusting the program's own verdict.
* **Custom commands** — project-declared checks treated as code execution,
  fully recorded.

## What it does NOT prove

Honesty first. A `VERIFIED` verdict always means *"verified under the recorded
scope"*. It never means:

* universally deterministic across platforms (single-host evidence cannot show that),
* formally proven (execution evidence is empirical),
* sandboxed (V0.1 runs commands on your host; see [THREAT_MODEL](docs/THREAT_MODEL.md)),
* certified for any regulatory regime (this is not compliance theater).

Every report carries a mandatory **Limitations** section derived from the
bundle itself: dirty worktrees, skipped tools, single-host determinism scope,
finite numeric sampling, and more.

## Install

```bash
git clone https://github.com/Memorithm/SciRust-Verify.git
cd SciRust-Verify
cargo install --path crates/scirust-verify-cli
scirust-verify --help
```

## Verify a Cargo project

```bash
cd my-project

# 1. Generate a starter manifest (never overwrites without --force).
scirust-verify init .

# 2. Inspect what was discovered (no heavy execution).
scirust-verify inspect .

# 3. Show exactly what verify would run.
scirust-verify plan .

# 4. Run verification; produces an evidence dossier.
scirust-verify verify .
echo $?

# 5. Read reports from any run, without re-executing anything.
scirust-verify report <run-id> --check-integrity
scirust-verify report <run-id> --markdown
scirust-verify report <run-id> --json

# 6. Re-execute a previous run as a NEW linked run.
scirust-verify replay <run-id>

# 7. Compare two dossiers.
scirust-verify diff <run-a> <run-b>

# 8. Probe the environment.
scirust-verify doctor

# 9. Ingest a completed SciRust test-protocol bundle into a dossier.
scirust-verify ingest-scirust /path/to/protocol-run --project .

# 10. Persisted document catalog.
scirust-verify schema

# 11. Generate an Ed25519 keypair, sign a finalized dossier, and verify it.
scirust-verify keygen --private-key ~/.config/scirust-verify/key.json --public-key ~/.config/scirust-verify/key.pub.json
scirust-verify sign <run-id> --private-key ~/.config/scirust-verify/key.json
scirust-verify verify-signature <run-id> --public-key ~/.config/scirust-verify/key.pub.json
```

Exit codes: `0` pass/pass-with-gaps · `1` verification not established or
requested run missing · `2` invalid usage/configuration (bad paths, bad
manifests) · `3` internal error.

## Where are evidence dossiers stored?

```
.scirust-verify/runs/<run-id>/
├── run.json          lifecycle state machine
├── artifact.json     identity + source identity (git/tree digest)
├── environment.json  host/toolchain snapshot
├── provenance.json   git provenance + hashed probes
├── plan.json         executed checks + canonical plan digest
├── claims.json       registered claims
├── executions.json   per-check records
├── evaluations.json  claim evaluations with requirement levels
├── evidence/         immutable evidence objects (one file each)
│   └── files/        content-addressed attachments (logs)
├── report.json       machine-readable report
├── report.md         human-readable report
└── bundle.json       integrity manifest sealing every file
```

Finalized bundles are sealed: every file's SHA-256 is recorded in
`bundle.json`; readers detect modification, deletion and injection. See
[EVIDENCE_FORMAT](docs/EVIDENCE_FORMAT.md).

## How verdicts work

| Verdict | Meaning |
|---|---|
| `VERIFIED` | Property established by recorded evidence under the recorded scope |
| `FAILED` | Check executed; evidence contradicts the requirement |
| `NOT_VERIFIED` | Insufficient evidence (missing execution, timeout, unparseable output) |
| `SKIPPED` | Implementation exists but could not run here (tool missing) |
| `UNSUPPORTED` | No implementation exists in this version |

Requirement levels gate the dossier: `required` failures give overall `FAIL`;
gaps (`SKIPPED`/`UNSUPPORTED`) on required claims give `PASS_WITH_GAPS`; only
all-required-verified yields clean `PASS`. Optional and informational checks
never gate. Under `--strict`, skipped prerequisites stop being gaps.

## How SciRust integration works

SciRust owns its internal functional acceptance (`scripts/test-protocol.sh`
and its oracle tests). SciRust-Verify owns normalization, provenance, claim
linkage, aggregation, integrity, scope and reporting. The adapter crate
(`scirust-verify-scirust`) ingests completed SciRust protocol evidence
bundles without re-implementing or flattening their semantics — `PASS`,
`PASS (with gaps)` and `FAIL` stay distinct.

## Signed evidence dossiers

Finalized dossiers can be authenticated with detached Ed25519 signatures. The
signature binds the exact `bundle.json` bytes and run id without mutating the
sealed evidence directory. Signature files live under
`.scirust-verify/signatures/<run-id>/`. A successful signature check proves
validity under the **explicitly supplied public key**; it does not by itself
prove signer identity, key authorization/revocation, or trusted timestamping.
See [SIGNATURES.md](docs/SIGNATURES.md).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# Self-verification (the product verifying its own repository):
cargo run -p scirust-verify-cli -- verify .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

PolyForm Noncommercial 1.0.0 — see [LICENSE.md](LICENSE.md).


## Cross-run scope aggregation

`aggregate` can summarize a claim across multiple finalized dossiers and now verifies every
bundle before consuming it:

```bash
scirust-verify aggregate tests_pass RUN_A RUN_B --json
```

For an explicit scope-coverage gate, require a minimum number of distinct normalized execution
platforms:

```bash
scirust-verify aggregate cross_process_deterministic RUN_X86 RUN_ARM \
  --require-scope --min-platforms 2 --json
```

Scope certification requires all requested runs to contain matching `VERIFIED` evaluations,
identical claim definitions, a provably identical source state (tree digest, or a clean Git
commit), integrity-valid finalized dossiers, identifiable execution scope, and the requested
number of distinct normalized platforms. Platform identity uses host/target triples, CPU
architecture/features, backend, and explicit GPU vendor/device/driver data when recorded.

This is **coverage certification, not output comparison**. Two successful runs on CPU and CUDA
do not establish CPU/GPU parity merely because both are present; parity must itself be a verified
`cpu_gpu_parity` claim backed by comparison evidence.


## Cross-run output parity

`compare-runs` compares machine-readable outputs already sealed in two finalized dossiers and
creates a **new derived evidence dossier** for the comparison:

```bash
scirust-verify compare-runs RUN_A RUN_B --absolute 1e-6 --relative 1e-6 --json
```

V1 compares only structured `numeric_comparison.observed` values and canonical `fingerprint`
observations with the same check/name identity. Numeric values are independently re-evaluated by
SciRust-Verify under the explicitly selected tolerance; fingerprints are exact. Missing,
duplicate, malformed, or unit-incompatible outputs produce `NOT_VERIFIED`; complete but unequal
outputs produce `FAILED`; only a complete match produces `VERIFIED`.

The derived dossier records SHA-256 digests of both source `bundle.json` manifests and refuses to
consume either run unless its full dossier integrity verifies first. The two source artifacts must
also have a provably identical source state (same tree digest or same clean Git commit).

For the specialized CPU/GPU claim:

```bash
scirust-verify compare-runs CPU_RUN GPU_RUN --require-cpu-gpu --absolute 1e-6
```

`cpu_gpu_parity` is **not** established from CLI labels. One source endpoint must be recorded as a
CPU scope and the other must carry a concrete GPU backend/device identity in its sealed evidence.
If that identity is absent, SciRust-Verify still writes an auditable derived dossier but returns
`NOT_VERIFIED` even when the numeric outputs happen to match.
