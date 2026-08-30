# SciRust Hub integration v1

SciRust-Verify integrates with SciRust Hub as normal **process components**. Hub remains the orchestration/provenance plane; Verify remains the authority that interprets and integrity-checks SciRust-Verify evidence dossiers.

The v1 integration exposes two deliberately separate capabilities:

```text
verify.dossier_integrity@1.0.0
verify.dossier_authenticity@1.0.0
```

Neither evaluates scientific claims and neither converts any dossier verdict into a Hub-level proof statement.

## Integrity-only artifacts

Input:

```text
application/vnd.scirust.verify-dossier-transport.v1
```

Output:

```text
application/vnd.scirust.verify-hub-inspection.v1+json
```

The input is the deterministic single-file `.svtr` transport defined in `DOSSIER_TRANSPORT_V1.md`. This lets Hub store the complete sealed dossier as one content-addressed artifact instead of weakening the evidence model by transporting only `report.json`.

## Integrity process contract

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

## Authenticated transport capability

When Hub receives the authenticated `.svat` transport, the separate manifest is:

```text
integrations/scirust-hub-authenticated/component.json
```

It invokes:

```text
/opt/scirust-verify/bin/scirust-verify-hub-auth \
  --dossier {input:dossier} \
  --result {output:result}
```

`scirust-verify-hub-auth` locates the sibling `scirust-verify-auth-transport` binary and unpacks the artifact in an owner-only temporary project directory on Unix. `scirust-verify-auth-transport` in turn invokes the sibling `scirust-verify-transport` binary for the inner `.svtr` reconstruction. The authenticated transport path verifies dossier integrity and the detached Ed25519 signature under the exact transported public key before the Hub adapter emits its result.

A successful authenticated inspection reports `status = "signature_valid_under_transported_key"` and always reports `signer_authorized = false`. Transported key material is evidence used for signature verification, not a trust root. Signer authorization remains an independent local-policy decision.

## Deployment layout

The checked-in Hub component manifests use sibling executable discovery.

An **integrity-only** deployment requires these two binaries in the same directory:

```text
/opt/scirust-verify/bin/scirust-verify-hub
/opt/scirust-verify/bin/scirust-verify-transport
```

An **authenticated-only** deployment requires these three binaries in the same directory:

```text
/opt/scirust-verify/bin/scirust-verify-hub-auth
/opt/scirust-verify/bin/scirust-verify-auth-transport
/opt/scirust-verify/bin/scirust-verify-transport
```

The ordinary `scirust-verify-hub` binary is not required for authenticated-only inspection. Conversely, `scirust-verify-transport` is a transitive runtime requirement of the authenticated path because the authenticated wrapper delegates reconstruction of its inner `.svtr` payload to that binary.

A deployment that enables **both** integrity and authenticated inspection therefore installs all four binaries:

```text
/opt/scirust-verify/bin/scirust-verify-hub
/opt/scirust-verify/bin/scirust-verify-transport
/opt/scirust-verify/bin/scirust-verify-hub-auth
/opt/scirust-verify/bin/scirust-verify-auth-transport
```

Omitting a required sibling executable causes the relevant adapter to fail rather than silently fall back to a weaker inspection mode.

Sibling lookup avoids dependence on inherited `PATH`, which is important because Hub constructs an explicit child environment rather than inheriting arbitrary host variables.

## Trust boundaries

Integrity inspection establishes only structural transport validity plus the original dossier integrity seal. Authenticated inspection additionally establishes that the detached signature verifies under the exact public key transported with the dossier.

Neither capability establishes human or organization identity, trusted time, remote-host trust, remote attestation, signer authorization, or stronger scientific verdict semantics. Authorization of a transported key must be performed separately, for example through the explicit signature-fingerprint policy surface.

## Follow-up composition

Once integrity or authenticated inspection succeeds, Hub can feed the same content-addressed artifact into later Verify capabilities such as policy evaluation or cross-run aggregation. Those capabilities must retain their own source/environment/signer trust gates; these adapters deliberately do not collapse those trust boundaries.
