# SciRust-Verify Evidence Format

This document specifies every persisted file of an evidence dossier, the
integrity rules, and the canonicalization used for hashing.

## Bundle layout

```
.scirust-verify/runs/<run-id>/
├── run.json
├── artifact.json
├── environment.json
├── provenance.json
├── plan.json
├── claims.json
├── executions.json
├── evaluations.json
├── manifest-used.json        (effective manifest snapshot for replay)
├── evidence/
│   ├── ev-0001.json ...      one immutable Evidence object per file
│   └── files/                (content-addressed attachment payloads)
├── logs/*.log                (attachment payloads referenced by evidence)
├── report.json               (regenerable)
├── report.md                 (regenerable)
└── bundle.json               (written LAST; seals everything above)
```

All JSON is pretty-printed with sorted keys and a trailing newline. Every
top-level persisted document carries `schema_version` (currently `1`);
readers reject higher versions instead of guessing.

## Documents

### `run.json` — RunDocument

| Field | Type | Notes |
|---|---|---|
| `schema_version` | u64 | must be 1 |
| `run_id` | string | `run-<YYYYMMDDTHHMMSSZ>-<8 hex>` |
| `state` | enum | `planning`, `running`, `finalizing`, `finalized`, `aborted` |
| `created_at_utc` | RFC 3339 | UTC only |
| `finalized_at_utc` | optional | set at finalization |
| `replay_of` | optional run id | present when this run replays another |
| `tool_version` | string | producing tool identity |

An interrupted run keeps its last non-final state plus whatever evidence was
already written. Only `finalized` bundles carry `bundle.json`.

### `artifact.json` — Artifact

Identity of the subject: `id`, `kind` (`cargo_workspace`, `binary`,
`source_tree`, ...), `name`, optional `version`, absolute `path`, and the
`source` identity: repository URL, commit, branch, dirty state
(`clean`/`dirty`/`unknown`) and optionally a source-tree digest.

### `environment.json` — EnvironmentSnapshot

Host (os/triple/cpu features), toolchain (rustc/cargo versions, host/target
triples, profile, RUSTFLAGS), extra tool versions probed at run start, and
the UTC capture instant.

### `provenance.json` — ProvenanceDocument

Git provenance when available (`git.commit`, `git.branch`, `git.repository`,
`git.dirty_count`), otherwise a content-only `tree_digest`. Probe commands
are recorded as command + stdout digest pairs — raw outputs are never stored
in this document.

### `plan.json` — PlanDocument

The executed checks in deterministic order (sorted by check id) plus
`plan_digest`: SHA-256 over the canonical JSON serialization of the checks.
Readers recompute the digest from the stored checks and refuse tampered
plans.

### `claims.json` / `executions.json`

Registered claims (id, kind slug, subject, requirement level, statement) and
per-check execution records (status, outcome verdict, summary, observations,
evidence ids).

### `evaluations.json`

Claim evaluations: `{requirement_level, evaluation{claim_id, verdict, scope,
reasoning, evidence_ids, check_ids}}` per claim.

### `evidence/ev-NNNN.json` — Evidence

Sequential ids `ev-0001...` assigned in execution order. Each object records:
kind (command execution, fingerprint, git provenance, numeric comparison,
dependency graph, external attestation, ...), producer, subject artifact,
scope snapshot, UTC instant, producer status, observations, input/output
digests, attachments, `derived_from` links, and structured metadata.

### Structured observation payloads

SVOP `numeric_comparison` observations may declare an optional `oracle`
identity string (e.g. `"oracle":"analytic-gamma-v1"`). It is preserved in the
stored observation payload so dossiers show *which* reference produced each
expected value. Non-finite expected/observed values are stored as their
canonical strings (`"NaN"`, `"inf"`, `"-inf"`) — never JSON `null`.

### Attachments

Referenced by relative path inside the run directory (never absolute, never
containing `..`). Each reference carries size and SHA-256; finalization
verifies existence, size and digest of every referenced attachment.

## Integrity rules

1. Finalization validates structure first: unique evidence ids, valid
   check/claim/evidence references, required documents present.
2. Then it flips `state` to `finalized`, digests **every** file under the run
   directory except `bundle.json`, and writes `bundle.json` atomically as the
   last step.
3. Readers (`report --check-integrity`, library API) verify each sealed file's
   digest, detect missing sealed files, and detect unsealed additions.
4. Sealed runs reject mutation through the store API.

Corruption examples detected: modified evidence text, deleted log payload,
swapped artifact name, injected files, duplicate ids, broken references.

## Canonicalization contract

Wherever structured data is hashed (plan digests, fingerprints):

* serialize to `serde_json::Value` (object keys become lexicographically
  sorted),
* emit compact JSON without whitespace,
* floats use shortest round-trip formatting (stable for f64 across platforms),
* determinism fingerprints over structured output use the sorted
  `name=value` lines of SVOP fingerprint observations.

## Timestamps & units

* All instants are UTC in RFC 3339 with explicit timezone.
* Durations are recorded as `duration_ns`; byte counts carry `Bytes`;
  metrics require an explicit unit string in SVOP.
