//! Validation-first ingestion of ecosystem artifact formats.
//!
//! Two formats are supported, both implemented against their upstream
//! specifications rather than invented:
//!
//! * **SciCapsule v1 manifests** — mirroring `scirust-capsule-schema` v1
//!   (Memorithm/scirust): strict path rules, lowercase-hex SHA-256 payload
//!   digests, exact byte lengths, payloads strictly ordered by path,
//!   entrypoint present. Structural + integrity verification only; entrypoint
//!   *execution* semantics are not defined upstream and stay UNSUPPORTED.
//! * **Forge candidate envelopes v1** — mirroring `forge-bridge`
//!   `CandidateEnvelopeV1`: wire JSON fields, canonical fingerprint bytes
//!   recomputed and compared. Envelope integrity is attested; Forge's own
//!   correctness evaluation is explicitly NOT treated as independent
//!   verification.

#![deny(missing_docs)]

pub mod forge;
pub mod scicap;
