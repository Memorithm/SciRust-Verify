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

## Relationship to evidence

The launcher adds an execution boundary around the complete `scirust-verify verify` process. Existing dossier verdict semantics remain unchanged: `VERIFIED`, `FAILED`, `NOT_VERIFIED`, `SKIPPED`, and `UNSUPPORTED` are never rewritten by the launcher.

The `SCIRUST_VERIFY_CONTAINMENT` environment marker is intentionally explicit, but the current dossier schema still records the verifier pipeline execution mode independently. Until the core pipeline consumes this marker directly, consumers must not infer a cryptographically bound containment claim from the dossier alone. This launcher is therefore a real containment mechanism with an explicitly documented evidence-binding limitation, not a remote-attestation mechanism.
