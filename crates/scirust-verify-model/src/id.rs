//! Strongly typed identifiers.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

macro_rules! string_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// The canonical prefix used when generating identifiers of this kind.
            pub const PREFIX: &'static str = $prefix;

            /// Creates an identifier from a raw string without validation.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// The identifier value.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier and returns the inner string.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

string_id!(
    ArtifactId,
    "artifact",
    "Identifies an artifact under verification."
);
string_id!(ClaimId, "claim", "Identifies a claim within a dossier.");
string_id!(
    CheckId,
    "check",
    "Identifies a check within a verification plan."
);
string_id!(
    EvidenceId,
    "ev",
    "Identifies one evidence object within a run."
);

impl EvidenceId {
    /// Builds the sequential evidence identifier `ev-<NNNN>` (1-based).
    ///
    /// Derivation contract: numbers are assigned in execution order inside a
    /// run and formatted with at least four digits.
    pub fn sequential(n: usize) -> Self {
        Self(format!("ev-{n:04}"))
    }
}

/// Identifies a verification run.
///
/// Shape: `run-<YYYYMMDDTHHMMSSZ>-<8 lowercase hex>`. The hex suffix is
/// derived (see [`new_run_id_suffix`]) so runs created within the same second
/// remain distinguishable while staying stable for replay bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RunId(String);

impl RunId {
    /// Creates a run id from an existing string (e.g. loaded from storage).
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The identifier value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the identifier and returns the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Derives the 8-hex-character suffix used by [`RunId`].
///
/// Contract: SHA-256 over `<utc_compact_second>|<entropy source string>`,
/// truncated to 8 lowercase hex characters. Callers pass any cheap entropy
/// source available in their context (e.g. nanosecond clock + path); the
/// function itself is pure.
pub fn new_run_id_suffix(entropy_source: &str) -> String {
    let hash = Sha256::digest(entropy_source.as_bytes());
    let mut out = hex::encode(&hash[..4]);
    out.truncate(8);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_sequential_format() {
        assert_eq!(EvidenceId::sequential(1).as_str(), "ev-0001");
        assert_eq!(EvidenceId::sequential(12_345).as_str(), "ev-12345");
    }

    #[test]
    fn ids_order_and_roundtrip() {
        let mut ids = vec![ClaimId::new("b"), ClaimId::new("a"), ClaimId::new("c")];
        ids.sort();
        let roundtrip: Vec<String> =
            serde_json::from_str::<Vec<ClaimId>>(&serde_json::to_string(&ids).unwrap())
                .unwrap()
                .into_iter()
                .map(|i| i.into_inner())
                .collect();
        assert_eq!(roundtrip, vec!["a", "b", "c"]);
    }

    #[test]
    fn run_id_suffix_is_stable_hex() {
        let s1 = new_run_id_suffix("20260825T120000Z|/tmp/a");
        let s2 = new_run_id_suffix("20260825T120000Z|/tmp/b");
        assert_eq!(s1.len(), 8);
        assert_eq!(s1, new_run_id_suffix("20260825T120000Z|/tmp/a"));
        assert_ne!(s1, s2);
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
