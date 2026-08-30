# Threat Model

Scope: current SciRust-Verify implementation. Read this before verifying any project you do not trust.

## Summary

A plain `scirust-verify verify` executes Cargo build scripts, procedural macros, test binaries and custom commands directly on the host with the invoking user's privileges. That path is **not contained**.

For hostile-project execution on Linux, SciRust-Verify also provides the opt-in `scirust-verify-contain` launcher. It uses the real `bubblewrap` isolation mechanism, fails closed when bubblewrap is unavailable, creates separate user/PID/IPC/UTS/network namespaces, mounts the host root read-only, rebinds only the selected project tree read/write, and uses an ephemeral `/tmp`. CI executes this path with real bubblewrap.

This is operating-system containment, not a formal safety proof, VM isolation, remote attestation, or evidence that the kernel/bubblewrap implementation is uncompromised. Host files outside the project remain potentially readable through the read-only root mount. Use a VM or stronger isolation when confidentiality from hostile code is required.

## Assets

1. **Evidence dossiers** — the integrity-sealed record of what ran and what was observed.
2. **Verdict integrity** — verdicts remain derived from recorded evidence under documented semantics.
3. **Source/artifact/environment identity** — inputs that bind evidence to what was actually evaluated.
4. **Signer authorization state** — local policy over exact public-key fingerprints, distinct from cryptographic validity.
5. **The host** — protected only when an explicit containment mechanism is selected; plain `verify` does not protect it.

## Execution boundaries

### Plain verification

`scirust-verify verify` uses direct subprocess execution. Treat an untrusted repository exactly as arbitrary code execution on the host.

### Bubblewrap containment

`scirust-verify-contain <project>` is an opt-in Linux execution boundary. It never silently falls back to direct host execution.

The produced dossier records a structured `execution_boundary` declaration in sealed `environment.json` using the profile `bubblewrap-v1` and assertion scope `producer_declared_not_attested`. The declaration is integrity-bound after dossier finalization. That proves only that the sealed dossier contains the declaration; it is not cryptographic attestation that the boundary actually ran on an uncompromised host.

`scirust-verify-boundary-policy` can fail closed unless a finalized integrity-valid dossier contains the exact boundary declaration required by local policy. Policy satisfaction does not strengthen the scientific verdicts in the dossier.

## Threats and mitigations

### Hostile `build.rs`, proc macro, test binary, or custom command

**Threat:** arbitrary code executes during verification.

**Plain `verify`:** no containment. The process runs with the invoking user's host privileges.

**`scirust-verify-contain`:** bubblewrap namespaces, network isolation, read-only host root, project-only writable bind, fresh `/proc` and `/dev`, and ephemeral `/tmp` provide a real Linux containment boundary.

**Residual:** the project remains writable; the read-only host filesystem can still be readable; kernel/bubblewrap vulnerabilities and host compromise are outside this guarantee. A VM/minimal-root worker is stronger for hostile code.

### Malicious output volume

**Threat:** a process floods stdout/stderr to exhaust memory or disk.

**Mitigation:** bounded capture with reader-thread draining. Truncation and total byte counts are recorded as evidence rather than hidden.

### Runaway processes

**Threat:** a check hangs indefinitely or leaves descendants behind.

**Mitigation:** mandatory timeouts and process-group termination. Timeout remains distinct from a scientific assertion failure.

### Path traversal and filesystem tricks

**Threat:** crafted attachment or imported evidence paths escape their intended directory.

**Mitigation:** store paths reject absolute paths and parent traversal; remote dossier import rejects symlinks/special files and validates sealed paths before publication. Imported evidence is staged, verified, copied and verified again before atomic publication.

### Symlink escape in source-tree hashing

**Threat:** symlinks smuggle external content into source identity.

**Mitigation:** source-tree hashing records symlinks as links and does not follow them.

### Tampered evidence dossier

**Threat:** post-hoc modification, deletion or injection of evidence files.

**Mitigation:** `bundle.json` seals SHA-256 of every dossier file; readers verify the entire manifest and reject missing, modified or unsealed files. Finalized runs refuse store-level mutation.

**Residual:** integrity sealing alone is not authorship. Anyone with filesystem write access can replace an entire unsigned dossier and recompute its bundle.

### Forged dossier authorship

**Threat:** an attacker replaces a dossier and recomputes the integrity seal.

**Mitigation:** finalized dossiers can be signed with detached Ed25519 signatures binding the exact `bundle.json` bytes and run id.

**Important trust split:** signature validity answers only "does this signature verify under this supplied public key?" It does not answer "do I trust this key?".

`scirust-verify-signature-policy` provides a separate machine-readable local authorization layer over exact SHA-256 public-key fingerprints, with explicit revocation taking precedence over allowlisting.

**Residual:** fingerprint authorization is local policy, not human identity, PKI certification, key provenance, trusted timestamping or remote attestation.

### Forged provenance or execution-boundary declaration

**Threat:** a compromised producer reports false git/toolchain/host/boundary information.

**Mitigation:** the reported provenance and environment are integrity-bound into the finalized dossier and can be compared or policy-gated.

**Residual:** a compromised producer can lie before sealing. Cross-host trust requires an external attestation mechanism; SciRust-Verify does not currently provide hardware-rooted remote attestation.

### Remote/CI evidence substitution

**Threat:** evidence produced elsewhere is modified, mixed with another run, or injected into the local store.

**Mitigation:** remote import requires a finalized integrity-valid dossier, exact run-id consistency, safe sealed paths, staging, double integrity verification and no overwrite of an existing run. Cross-run aggregation additionally requires compatible source identity and scope information where relevant.

**Residual:** importing valid bytes does not establish that the remote machine was honest. Signer policy and external worker trust remain separate decisions.

### Cross-platform determinism overclaim

**Threat:** a single-host deterministic run is presented as cross-platform determinism.

**Mitigation:** scope-aware aggregation requires multiple finalized integrity-valid runs and records distinct normalized execution platforms. Output parity is a separate comparison operation; platform coverage alone is never treated as output equivalence.

### Secret leakage

**Threat:** credentials leak through inherited environment or recorded evidence.

**Mitigation:** secret-like environment-variable names are removed from child environments and never recorded; evidence records only an allowlist plus explicitly-set non-secret variables.

**Residual:** hostile code can deliberately exfiltrate information it can read through stdout, files or other channels. Use stronger isolation for untrusted code and sensitive hosts.

## Scientific semantics are unchanged by trust features

Containment, integrity seals, signatures, signer policy, boundary policy and remote import do not convert empirical evidence into a formal proof.

The verdict vocabulary remains:

- `VERIFIED`
- `FAILED`
- `NOT_VERIFIED`
- `SKIPPED`
- `UNSUPPORTED`

A `VERIFIED` result always means the property was established by the recorded evidence **under the recorded scope**. It does not imply universal cross-platform validity, formal correctness or trusted execution unless those are separately evidenced and supported.

## Current explicit non-goals / residual boundaries

- No hardware-rooted remote attestation of workers or hosts.
- No claim that bubblewrap containment is equivalent to a VM or proves confidentiality from hostile code.
- No built-in PKI or human/organization identity certification for signing keys.
- No trusted timestamping or key-history service.
- No formal-proof claim for empirical verification evidence.
- No inference that single-host determinism proves cross-platform determinism.

These are trust boundaries, not hidden prerequisites. Downstream policy should fail closed when it requires evidence SciRust-Verify does not record or establish.
