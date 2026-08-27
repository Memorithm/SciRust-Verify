# Cross-run output parity

SciRust-Verify parity is a comparison of **recorded evidence**, not a backend label.

## Inputs

Both inputs must be finalized SciRust-Verify runs whose `bundle.json` integrity manifests verify.
The source artifacts must identify the same artifact id, kind, name and version, and the same source
state using either an equal source-tree digest or an equal Git commit recorded from clean worktrees.
A source-tree digest is compared only when both runs carry one; if it is supplemental metadata on
only one side, an identical Git commit recorded clean on both sides remains a valid common source
anchor rather than being rejected merely because the metadata is asymmetric.

V1 compares two structured observation classes:

- `numeric_comparison`: the `observed` value from each run is compared with the selected absolute,
  relative, and/or ULP tolerance. No criterion means exact IEEE-754 equality (subject to the
  signed-zero policy).
- `fingerprint`: canonical hexadecimal values must match exactly.

Keys include the check id, observation kind and observation name. This prevents values emitted by
different checks from being accidentally paired.

When comparable evidence scopes record `input_set`, the two runs must identify the same single
input set and every comparable scope on both sides must carry that identity. Different input sets,
one-sided input identity, or partially missing identity makes parity `NOT_VERIFIED`. If neither run
records `input_set`, V1 can still establish output-only parity, and the derived dossier states that
limitation explicitly rather than inventing an input identity.

## Verdicts

- `VERIFIED`: every eligible output exists exactly once on both sides and every comparison passes.
- `FAILED`: comparison is complete but at least one numeric value/fingerprint disagrees.
- `NOT_VERIFIED`: an output is missing, duplicated, malformed, unit-incompatible, or there are no
  eligible structured outputs.

Scientific mismatch is therefore distinct from insufficient evidence.

## Derived dossier

`compare-runs` creates a new immutable dossier rather than returning an ephemeral boolean. Its
comparison evidence records the source run ids, SHA-256 digests of both source `bundle.json`
files, selected tolerance, endpoint-role assessment, per-output results, and an attached detailed
comparison JSON document. The source bundle digests cryptographically bind the comparison to the
exact source dossiers that were consumed.

## CPU/GPU semantics

`--require-cpu-gpu` changes the derived claim to `cpu_gpu_parity`. The claim can reach `VERIFIED`
only when sealed evidence scopes establish one CPU endpoint and one concrete GPU endpoint. A GPU
endpoint requires both a non-CPU backend and an explicit GPU device identity; `backend = "cuda"`
by itself is not enough. Conversely, an explicit CPU backend is classified as CPU only when no GPU
identity fields are present; partial or contradictory GPU metadata makes the endpoint non-CPU and
non-GPU (`other`) rather than allowing an optimistic classification.

This avoids a common false claim: successful execution of two commands labelled "CPU" and "GPU"
does not prove that the second command actually used a GPU. Hardware/provider integrations must
populate the scope from evidence they can genuinely establish.

Even a verified parity claim remains scoped to the recorded inputs, source state, endpoint
identities and tolerance. It is not a universal statement about all inputs, devices or driver
versions.
