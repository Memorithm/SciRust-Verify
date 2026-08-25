//! Content digests and canonical serialization used for hashing.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Hash algorithms recognized by SciRust-Verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    /// SHA-256, hex-encoded lowercase. The default algorithm.
    Sha256,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("sha256"),
        }
    }
}

/// A content digest. Never call this a signature: a digest establishes
/// content identity, not authorship or trust.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest {
    /// Algorithm used to compute [`Digest::value`].
    pub algorithm: DigestAlgorithm,
    /// Hex-encoded lowercase digest value.
    pub value: String,
}

impl Digest {
    /// Computes the SHA-256 digest of `bytes`.
    pub fn sha256_hex(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self {
            algorithm: DigestAlgorithm::Sha256,
            value: hex::encode(hasher.finalize()),
        }
    }

    /// Returns the digest of the canonical JSON encoding of a serializable
    /// value (see [`crate::canonical_json`]).
    pub fn of_canonical_json<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        Ok(Self::sha256_hex(canonical_json(value)?.as_bytes()))
    }

    /// True when both algorithm and value match.
    pub fn matches(&self, other: &Digest) -> bool {
        self == other
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.value)
    }
}

/// Produces the canonical JSON form of a serializable value.
///
/// Contract (used anywhere SciRust-Verify hashes structured data):
///
/// * object keys are sorted lexicographically (`serde_json::Value` uses a
///   `BTreeMap`, so key order is normalized);
/// * no insignificant whitespace;
/// * floats use the shortest representation that round-trips (Rust `ryu`
///   formatting), which is stable across platforms for `f64`;
/// * strings are UTF-8 JSON escapes as produced by `serde_json`.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let json_value = serde_json::to_value(value)?;
    serde_json::to_string(&json_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn digest_is_deterministic_and_prefixed() {
        let d1 = Digest::sha256_hex(b"hello");
        let d2 = Digest::sha256_hex(b"hello");
        assert_eq!(d1, d2);
        assert_eq!(d1.algorithm, DigestAlgorithm::Sha256);
        assert_eq!(d1.value.len(), 64);
        assert!(d1
            .value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(format!("{d1}"), format!("sha256:{}", d1.value));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        // Insertion order differs; canonical form must not.
        let mut a = BTreeMap::new();
        a.insert("zeta", 1);
        a.insert("alpha", 2);
        let b = serde_json::json!({ "alpha": 2, "zeta": 1 });
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(canonical_json(&b).unwrap(), r#"{"alpha":2,"zeta":1}"#);
    }

    #[test]
    fn canonical_digest_of_struct() {
        #[derive(Serialize)]
        struct S {
            b: u32,
            a: u32,
        }
        let d = Digest::of_canonical_json(&S { b: 1, a: 2 }).unwrap();
        let e = Digest::of_canonical_json(&serde_json::json!({"a":2,"b":1})).unwrap();
        assert_eq!(d, e);
    }
}
