# Bubblewrap containment launcher

`scirust-verify-contain` is an opt-in Linux launcher for verifying projects that should not execute directly on the host.

It uses the real Linux isolation mechanism provided by `bubblewrap` (`bwrap`). It is not a claim of formal safety, and it is not a substitute for a VM when the threat model requires a stronger kernel boundary.

## Invocation

```bash
scirust-verify-contain /path/to/project
scirust-verify-contain /path/to/project -- --profile strict
```

The launcher locates the sibling `scirust-verify` binary from the same installation. It never falls back to directly executing `scirust-verify` when `bwrap` is absent or cannot create the required namespaces.

## Boundary

The v1 containment profile requests:

- a new user namespace;
- a new PID namespace;
- new IPC and UTS namespaces;
- a new network namespace, with no host network sharing;
- the host root mounted read-only;
- only the selected project directory rebound read/write;
- an ephemeral `/tmp`;
- fresh `/proc` and `/dev` views;
- `CARGO_NET_OFFLINE=true` inside the boundary;
- `SCIRUST_VERIFY_CONTAINMENT=bubblewrap-v1` for explicit process-level provenance.

Arguments are passed structurally to `bwrap` and then to `scirust-verify`; no shell command string is constructed.

## What this does not prove

A successful contained verification does not prove that the project is safe, that the Linux kernel or bubblewrap is uncompromised, that the result generalizes to another platform, or that an empirical `VERIFIED` claim is a formal proof.

The project directory remains writable because Cargo builds and SciRust-Verify evidence creation need a writable workspace. A hostile process can therefore modify files inside that project tree. Run on a disposable checkout when source mutation itself is in scope.

The host filesystem outside the project is visible read-only. This limits writes but does not make all readable host data confidential from the contained process. For stronger confidentiality, use a VM or a deliberately minimized filesystem image instead of this profile.

Network is disabled by default. Dependencies and toolchains therefore need to be available locally. Missing prerequisites must surface as failed/not-verified execution rather than causing an unconstrained retry outside containment.

## Relationship to sealed evidence

The launcher adds an execution boundary around the complete `scirust-verify verify` process. Existing dossier verdict semantics remain unchanged: `VERIFIED`, `FAILED`, `NOT_VERIFIED`, `SKIPPED`, and `UNSUPPORTED` are never rewritten by the launcher.

When the verifier starts with the recognized marker `SCIRUST_VERIFY_CONTAINMENT=bubblewrap-v1`, its `EnvironmentSnapshot` records a structured `execution_boundary` object with:

- `mechanism = bubblewrap`;
- `profile = bubblewrap-v1`;
- `assertion_scope = producer_declared_not_attested`.

`environment.json` is part of the finalized evidence dossier and is covered by `bundle.json`, so later modification of this declaration is detected by normal dossier-integrity verification.

This improves **integrity binding**, not **authenticity**. A caller able to start `scirust-verify` directly can forge the same environment variable. Therefore the sealed field proves only that the finalized dossier contained that producer declaration; it does not independently prove that bubblewrap or the requested namespaces were active. Signer trust, remote-host trust, and kernel-backed attestation remain separate concerns.

Unknown containment-marker values do not create an execution-boundary claim.
