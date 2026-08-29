# Remote / CI evidence ingestion

SciRust-Verify can consume a finalized dossier produced on another machine or
inside CI without treating its transport as trusted.

```bash
scirust-verify-import /path/to/run-20260829T010203Z-deadbeef --project .
```

The importer is intentionally narrow. It imports an already finalized
SciRust-Verify run directory; it does not execute the remote project, infer
missing provenance, or convert a remote verdict into a stronger claim.

## Import contract

Before a run is published into the local `.scirust-verify/runs` store, the
importer:

1. rejects symbolic links and special files anywhere in the supplied bundle;
2. requires a portable run id and requires the directory name to equal the
   `run_id` sealed in `run.json`;
3. requires the run to be finalized;
4. verifies the complete `bundle.json` SHA-256 integrity seal at the source;
5. rejects unsafe manifest paths, non-SHA-256 manifests, and a manifest that
   attempts to seal itself;
6. copies only the files named by the seal plus `bundle.json` into an isolated
   staging root;
7. verifies the staged copy again, including the exact `bundle.json` digest;
8. atomically renames the staged run into the destination store;
9. refuses to overwrite an existing run id.

A failed import never publishes a partially copied run.

## Identity binding

The command does not invent source, artifact, host, target, backend, GPU, or
other environment identity. Those facts remain exactly the values sealed in
the imported dossier. Cross-run consumers such as `aggregate` and
`compare-runs` continue to apply their existing source/platform identity gates
to the imported evidence.

Therefore importing two dossiers from different machines does **not** by itself
establish cross-platform determinism. It only makes those independently
recorded dossiers available to the local aggregation/comparison machinery.

## Integrity is not signer trust

The importer validates **bundle integrity** only. SciRust-Verify signatures are
detached from run directories, so `scirust-verify-import` does not import or
validate a signature and does not claim an identity for the producer.

If signer authentication is required, transport the detached signature and
public key separately and run the normal `scirust-verify verify-signature`
workflow after import. A valid signature establishes validity under the
explicit public key supplied by the caller; it does not establish PKI,
organizational authorization, revocation status, or trusted timestamping.

## Threat boundary

The imported directory and its transport are considered untrusted inputs. The
importer protects the destination evidence store against path traversal,
symlink/special-file tricks, partial publication, evidence overwrite, and
ordinary or partial content tampering detectable by the sealed manifest.

This is **not** a sandbox for hostile project execution. If the remote CI job
ran hostile code, that execution already happened on the remote worker. The
importer authenticates neither the remote host nor what that host reported;
those require a trusted signer or external attestation infrastructure.

There remains an unavoidable local race if another process with filesystem
write access mutates the source directory while it is being imported. The
second integrity verification makes such a race fail closed when it changes
sealed bytes, but callers that need a stronger acquisition boundary should
first place the received dossier in an immutable or access-controlled staging
location.
