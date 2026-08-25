# Threat Model

Scope: SciRust-Verify V0.1. Read this before verifying any project you do not
trust.

## The one-paragraph summary

**SciRust-Verify is not a sandbox.** Running `verify` on a repository
executes its build scripts, procedural macros, test binaries and custom check
commands **on your host, with your privileges**. This is identical to running
`cargo build` or `cargo test` yourself — which is already arbitrary code
execution. SciRust-Verify's evidence integrity protects the *record* of a
verification run; it cannot make an untrusted *execution* safe.

## Assets

1. **Evidence bundles** — the tamper-evident record of what ran and what was
   observed.
2. **Verdict integrity** — the property that verdicts are derived from
   recorded evidence by documented logic.
3. **The host** — outside V0.1's protection envelope (see below).

## Trust levels

| Subject | Trust level | Rationale |
|---|---|---|
| Your own project | trusted | You wrote it; verification adds provenance + scope discipline |
| A dependency in your lockfile | semi-trusted | Supply-chain checks reduce but do not eliminate risk |
| A cloned untrusted repository | **untrusted** | Assume hostile code execution during verify |

## Threats & mitigations

### Hostile `build.rs` / proc-macro / test binary

*Threat:* arbitrary code runs with your user privileges during cargo checks.

*Mitigation in V0.1:* none beyond what cargo itself provides. Documented
loudly here and in the README.

*Future:* isolated runners (containers/VMs/remote workers) behind the same
`CommandSpec → ExecutionRecord` interface. The domain model already supports
this without redesign (`execution_mode` in scope records exists for exactly
this reason).

### Malicious output volume

*Threat:* a process floods stdout/stderr to exhaust memory or disk.

*Mitigation (implemented):* bounded capture with reader-thread draining;
limits configurable per manifest; truncation recorded as evidence
(`stdout_truncated`, `total_bytes`). Tested against multi-megabyte output.

### Runaway processes

*Threat:* a check hangs forever.

*Mitigation (implemented):* mandatory per-check timeouts; expiry kills the
child and records the distinct `TimedOut` state. Tested.

### Path traversal via attachment paths

*Threat:* crafted relative paths escape the run directory on write/read.

*Mitigation (implemented):* absolute paths and `..` components rejected at
every store write/read path. Content-addressed attachment storage avoids
attacker-controlled filenames for payloads.

### Symlink escape in source-tree hashing

*Threat:* symlinks smuggle external content into (or out of) source identity.

*Mitigation (implemented):* tree hashing records symlinks as links and never
follows them; excluded directories (.git, target, .scirust-verify,
node_modules) are skipped.

### Tampered evidence bundle

*Threat:* post-hoc modification of logs, digests, verdicts or reports.

*Mitigations (implemented):*
* `bundle.json` seals SHA-256 of every file, written atomically last;
* readers verify all digests and reject missing/unsealed files;
* plan digest detects plan mutation after execution;
* attachments carry size+digest verified at finalize and at load;
* sealed runs refuse store-level mutation.

*Residual:* anyone with filesystem write access can rebuild the entire bundle
including `bundle.json`. Sealing detects *accidents and partial tampering*;
it is not cryptographic authorship. Signed dossiers (with established Rust
crypto libraries, identified algorithms and key management) are a planned
extension; unsigned bundles are never labeled signed today.

### Forged provenance

*Threat:* fabricated git identity or toolchain facts.

*Mitigation:* provenance probes run locally and their outputs are hashed into
the dossier; dirty state is recorded honestly. But provenance reflects what
the local environment *reported* — a compromised environment can lie.
Cross-verifying provenance requires external attestation infrastructure
(future work).

### Secret leakage through environment recording

*Threat:* API keys leaking into published dossiers via env dumps.

*Mitigations (implemented):* secret-like variable names are stripped from
child environments entirely and never recorded; evidence records only an
explicit allowlist of variables plus explicitly-set non-secret values;
free-form strings (e.g. RUSTFLAGS) pass redaction screening.

*Residual:* defense in depth only — determined leakage channels (a hostile
build script printing your secrets into stdout logs) are not detectable.
Verify untrusted projects only in environments where exposure is contained.

### Malicious custom commands

*Threat:* `[[custom_checks]]` is arbitrary code execution by design.

*Mitigation:* treated exactly like that: structurally recorded (program,
args, cwd, timeout), executed without a shell, subject to bounds/timeouts.
Reviewing a manifest before running it is *your* responsibility.

## Explicit non-goals for V0.1

* No sandboxing of any kind.
* No cryptographic signatures on dossiers.
* No network-isolation guarantees for executed commands.
* No formal proof artifacts (all current evidence is empirical).

Each limitation appears in generated reports when relevant so downstream
consumers are never misled about coverage.
