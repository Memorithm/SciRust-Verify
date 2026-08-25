# Security Policy

## Reporting a vulnerability

Please open a GitHub Security Advisory on this repository
(<https://github.com/Memorithm/SciRust-Verify/security/advisories/new>) or, if
you cannot, a minimal public issue asking for a private channel — do not
include exploit details in public issues.

We aim to acknowledge reports within 7 days and to publish advisories with
fixed releases.

## Scope notes

* SciRust-Verify executes project commands on the host. Running it on
  untrusted repositories is **not** sandboxed; see
  [docs/THREAT_MODEL.md](THREAT_MODEL.md) before doing so.
* Evidence sealing detects accidental or partial tampering. It is not
  cryptographic authorship; signed dossiers are future work.
* Secret redaction in environment recording is defense in depth, not
  guaranteed leakage prevention.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | yes (best effort during foundation phase) |
