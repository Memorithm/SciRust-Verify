# SciRust Hub integration v1

SciRust-Verify integrates with SciRust Hub as a normal **process component**. Hub remains the orchestration/provenance plane; Verify remains the authority that interprets and integrity-checks SciRust-Verify evidence dossiers.

The v1 integration intentionally exposes one narrow capability:

```text
verify.dossier_integrity@1.0.0
```

It does not evaluate scientific claims and does not convert any dossier verdict into a Hub-level proof statement.

## Artifacts

Input:

```text
application/vnd.scirust.verify-dossier-transport.v1
```

Output:

```text
application/vnd.scirust.verify-hub-inspection.v1+json
```

The input is the deterministic single-file `.svtr` transport defined in `DOSSIER_TRANSPORT_V1.md`. This lets Hub store the complete sealed dossier as one content-addressed artifact instead of weakening the evidence model by transporting only `report.json`.

## Process contract

The checked-in component manifest is:

```text
integrations/scirust-hub/component.json
```

Its process binding runs:

```text
/opt/scirust-verify/bin/scirust-verify-hub \
  inspect \
  --dossier {input:dossier} \
  --result {output:result}
```

Hub substitutes input/output artifact paths directly in argv. No shell is involved.

`scirust-verify-hub` locates `scirust-verify-transport` next to its own executable, creates a private temporary project directory, invokes the transport `unpack` path there, and accepts the input only when reconstruction passes the original `bundle.json` integrity seal. The temporary reconstructed run is removed before the adapter returns.

A successful result has `status = "integrity_valid"` and records the transported run id, transport SHA-256, entry count, payload byte count, media types, and an explicit trust-boundary statement.

## What `integrity_valid` means

It means only:

> The supplied `.svtr` was structurally valid, reconstructed a finalized SciRust-Verify dossier, and that reconstructed dossier passed its original bundle integrity seal.

It does **not** mean:

- the dossier's scientific claims are `VERIFIED`;
- a `FAILED`, `NOT_VERIFIED`, `SKIPPED`, or `UNSUPPORTED` claim changed state;
- the machine that created the dossier was trusted;
- a detached signature identified an authorized signer;
- evidence from one host proves cross-platform determinism;
- Hub execution provides a security sandbox.

The component manifest therefore declares `claim_semantics = "integrity_only"` and `sandbox = "none"`.

## Deployment layout

The process manifest expects both binaries in the same installation directory:

```text
/opt/scirust-verify/bin/scirust-verify-hub
/opt/scirust-verify/bin/scirust-verify-transport
```

The sibling lookup avoids dependence on inherited `PATH`, which is important because Hub constructs an explicit child environment rather than inheriting arbitrary host variables.

## Follow-up composition

Once integrity inspection succeeds, Hub can feed the same content-addressed `.svtr` artifact into later Verify capabilities such as policy evaluation or cross-run aggregation. Those capabilities must retain their own source/environment/signer trust gates; this v1 adapter deliberately does not collapse those trust boundaries.
