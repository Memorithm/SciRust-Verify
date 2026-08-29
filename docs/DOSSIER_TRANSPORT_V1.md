# SciRust-Verify sealed dossier transport v1

SciRust-Verify evidence dossiers are directories because their canonical trust model is a set of independently inspectable, integrity-sealed documents and attachments. Systems such as SciRust Hub transport artifacts as single content-addressed files. Transport v1 bridges that representation mismatch **without changing the evidence model**.

Media type:

```text
application/vnd.scirust.verify-dossier-transport.v1
```

CLI:

```bash
scirust-verify-transport pack RUN_ID --project . --output evidence.svtr
scirust-verify-transport unpack evidence.svtr --project /target/project
```

## Wire format

All integers are little-endian.

```text
8 bytes   magic/version: 53 56 54 52 00 00 00 01  (SVTR + v1)
u32       entry count
repeat entry count times:
  u16     UTF-8 relative-path byte length
  bytes   relative path
  u64     payload byte length
  bytes   exact payload bytes
```

Entries are emitted in lexicographic path order. A valid transport contains exactly the files named by the dossier's existing `bundle.json`, plus `bundle.json` itself. No timestamps, permissions, host paths, compression metadata, or transport-time fields are encoded, so packing the same sealed dossier twice produces byte-identical transport files.

## Pack trust checks

Before export, SciRust-Verify:

1. opens the requested run from the normal run store;
2. requires matching run identity and finalized lifecycle;
3. verifies the complete existing dossier integrity seal;
4. parses and validates the manifest paths;
5. re-hashes every sealed payload while constructing the transport and refuses bytes that drifted after the initial seal check;
6. verifies `bundle.json` itself did not change during packing.

The transport is therefore a representation of the exact sealed dossier bytes, not a regenerated dossier.

## Unpack trust checks

The decoder fails closed on:

- wrong magic/version;
- zero or excessive entry count;
- non-UTF-8, absolute, traversal or backslash paths;
- duplicate paths;
- excessive path length;
- more than 10,000 entries;
- more than 1 GiB of payload bytes;
- truncated integers, paths or payloads;
- trailing unframed bytes;
- missing `run.json` or `bundle.json`;
- non-finalized run metadata;
- destination run-id collisions.

Decoded bytes first go into an isolated staging directory. The reconstructed run is then passed through the normal SciRust-Verify `bundle.json` integrity verifier. Only an integrity-valid dossier is published into `.scirust-verify/runs/<run-id>`.

## Hub boundary

This format is intentionally suitable for a Hub artifact because Hub's artifact model stores one blob with a media type, digest and size. Hub can content-address and move an `.svtr` file without understanding SciRust-Verify internals.

That does **not** mean Hub has verified the dossier. A consumer must still unpack/verify it with SciRust-Verify before using its claims. Likewise, storing transports from multiple hosts does not establish cross-platform determinism; the existing source/platform aggregation and output-comparison gates remain necessary.

## Signatures

Detached dossier signatures are **not embedded** in transport v1. This is deliberate. `bundle.json` integrity and signer trust are separate layers. A signature may be transported as another artifact and verified against an explicitly trusted public key using the existing signature workflow.

## Security and limitations

Transport v1 is containment for untrusted archive-like input, not a security sandbox. It never executes transported content.

The 1 GiB / 10,000-file limits are parser resource bounds, not sandbox guarantees. Local processes with concurrent write access to the destination filesystem remain outside the transport trust boundary. Operators should serialize imports into a given run store or provide normal filesystem-level access control.
