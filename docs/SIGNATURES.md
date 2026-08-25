# Detached Evidence-Dossier Signatures

SciRust-Verify supports detached Ed25519 signatures for finalized evidence dossiers.

## What is signed

A finalized run already contains `bundle.json`, the integrity manifest that records the SHA-256 digest of every sealed dossier file. The signature layer does **not** modify that immutable run directory.

Instead, SciRust-Verify signs a domain-separated message containing:

1. the signature protocol context (`SciRust-Verify detached bundle signature v1`),
2. a length-delimited serialization of all detached signature metadata except the signature bytes themselves (schema/signature versions, algorithm, run id, signed-object semantics, bundle digest, key id/fingerprint/public key, signer-reported time, and producing tool),
3. the exact bytes of the finalized `bundle.json` file.

This means metadata cannot be rewritten without invalidating Ed25519. Any change to the integrity manifest, any move to a different run id, or any change to a sealed dossier file detected through the manifest invalidates the verification path.

Detached signature documents are stored under:

```text
.scirust-verify/signatures/<run-id>/<key-id>.json
```

They intentionally live outside `.scirust-verify/runs/<run-id>/` so adding a signature after finalization does not mutate the evidence dossier or create a circular integrity dependency.

## Key generation

```bash
scirust-verify keygen \
  --private-key ~/.config/scirust-verify/signing-key.json \
  --public-key  ~/.config/scirust-verify/signing-key.pub.json
```

The private document contains a randomly generated 32-byte Ed25519 signing seed. On Unix, SciRust-Verify creates the private-key file with mode `0600`. Existing files are not overwritten unless `--force` is supplied. Symbolic-link outputs are rejected.

**V0.2 private-key files are not encrypted at rest.** Mode `0600` reduces accidental local disclosure on Unix but is not a substitute for encrypted storage, OS keyrings, HSMs, or hardware-backed signing. SciRust-Verify zeroizes its explicit transient seed/JSON buffers where practical, but cannot promise elimination of every compiler/runtime copy.

SciRust-Verify never prints the private key material.

The key id is derived from SHA-256 of the raw Ed25519 public key; it is not a user-selected identity label.

## Signing a finalized dossier

```bash
scirust-verify sign <run-id> \
  --private-key ~/.config/scirust-verify/signing-key.json
```

Before signing, SciRust-Verify re-runs the normal dossier integrity check. A corrupted, injected, incomplete, or non-finalized dossier is refused.

The signature metadata records the SHA-256 of `bundle.json` for diagnostics and indexing. All detached metadata fields except `signature_hex` are themselves cryptographically bound, and the Ed25519 signature also covers the exact manifest bytes.

## Verifying a signature

```bash
scirust-verify verify-signature <run-id> \
  --public-key ~/.config/scirust-verify/signing-key.pub.json
```

By default, the CLI locates the detached signature by the key id derived from the supplied public key. An explicit signature document can be selected with `--signature <path>`.

Successful verification establishes all of the following:

- the current dossier passes its normal integrity check;
- the current `bundle.json` is byte-for-byte the object whose digest was recorded at signing time;
- the run id matches the run id bound into the signature message;
- the detached signature was produced by the private key corresponding to the explicitly supplied Ed25519 public key.

## What a valid signature does **not** establish

Cryptographic validity is not the same as identity trust.

A valid signature does **not** by itself prove:

- who owns or controls the supplied public key;
- that the key was authorized by Memorithm, SciRust, or another organization;
- that the key has not been revoked;
- that `signed_at_utc` is a trusted timestamp;
- that a certificate authority or transparency log endorsed the key;
- that the underlying scientific claims are universally true outside the dossier's recorded verification scope.

The public key embedded in a detached signature is for portability and diagnostics only. `verify-signature` requires a caller-supplied public-key document and verifies that it matches the embedded key exactly.

Future versions may add trust stores, revocation, hardware-backed keys, or external timestamp/attestation systems, but V0.2 does not pretend those facilities already exist.

## Recommended key handling

- Keep private signing keys outside project repositories.
- Do not commit private key documents to Git.
- Distribute public keys through a channel whose authenticity you can independently establish.
- Use separate keys for automation and human release signing when their trust roles differ.
- Rotate keys deliberately and keep historical public keys available for old dossiers.

## Machine-readable verification

Global `--json` works with the signature commands:

```bash
scirust-verify --json keygen --private-key key.json --public-key key.pub.json
scirust-verify --json sign <run-id> --private-key key.json
scirust-verify --json verify-signature <run-id> --public-key key.pub.json
```

The verification JSON includes `cryptographically_valid: true` only after successful Ed25519 verification and includes an explicit `trust_scope` field describing the limits above.
