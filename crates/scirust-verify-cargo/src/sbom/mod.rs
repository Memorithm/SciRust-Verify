//! SPDX 2.3 SBOM generation from resolved Cargo metadata.
//!
//! Honesty discipline: only fields derivable from `cargo metadata` are
//! emitted. Everything not knowable from the manifest graph is expressed
//! with SPDX's own `NOASSERTION` value — never invented:
//!
//! * `downloadLocation` — registry packages map to their crates.io URL;
//!   git sources to the repository URL; everything else `NOASSERTION`;
//! * `licenseConcluded` / `copyrightText` — always `NOASSERTION` (we do not
//!   scan files);
//! * `licenseDeclared` — the manifest's declared license when present,
//!   otherwise `NOASSERTION`;
//! * `filesAnalyzed: false` — we describe packages, not file inventories.

use serde::Serialize;
use thiserror::Error;

/// SPDX specification version emitted.
pub const SPDX_VERSION: &str = "SPDX-2.3";
/// SPDX data license (mandated by the spec).
pub const DATA_LICENSE: &str = "CC0-1.0";

/// Errors from SBOM generation.
#[derive(Debug, Error)]
pub enum SbomError {
    /// The cargo metadata JSON could not be parsed.
    #[error("cannot parse cargo metadata: {0}")]
    Metadata(String),
}

/// One package as consumed from `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct MetadataPackage {
    /// Crate name.
    pub name: String,
    /// Declared version.
    pub version: String,
    /// Source identifier (`registry+...`, a git URL, or absent for path deps).
    #[serde(default)]
    pub source: Option<String>,
    /// Declared license string when the manifest carries one.
    #[serde(default)]
    pub license: Option<String>,
    /// Manifest path; used to identify workspace members.
    #[serde(default)]
    pub manifest_path: Option<String>,
}

/// Minimal but spec-conformant SPDX 2.3 document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpdxDocument {
    /// Always `SPDX-2.3`.
    #[serde(rename = "spdxVersion")]
    pub spdx_version: String,
    /// Always `CC0-1.0`.
    #[serde(rename = "dataLicense")]
    pub data_license: String,
    /// Document element id.
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Document name (artifact under analysis).
    pub name: String,
    /// Creation info.
    #[serde(rename = "creationInfo")]
    pub creation_info: CreationInfo,
    /// Packages described.
    pub packages: Vec<SpdxPackage>,
    /// Document-level relationships.
    pub relationships: Vec<Relationship>,
}

/// Creation information block.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreationInfo {
    /// UTC creation instant (RFC 3339).
    pub created: String,
    /// Creators (`Tool: ...` entries).
    pub creators: Vec<String>,
}

/// One described package.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpdxPackage {
    /// Package name.
    pub name: String,
    /// SPDX element id (`SPDXRef-Package-N`).
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Version string.
    #[serde(rename = "versionInfo")]
    pub version_info: String,
    /// Where the package can be obtained, or `NOASSERTION`.
    #[serde(rename = "downloadLocation")]
    pub download_location: String,
    /// Always false: no file inventory is analyzed.
    #[serde(rename = "filesAnalyzed")]
    pub files_analyzed: bool,
    /// Always `NOASSERTION`: no license scanning is performed.
    #[serde(rename = "licenseConcluded")]
    pub license_concluded: String,
    /// Declared license from the manifest, or `NOASSERTION`.
    #[serde(rename = "licenseDeclared")]
    pub license_declared: String,
    /// Always `NOASSERTION`.
    #[serde(rename = "copyrightText")]
    pub copyright_text: String,
    /// External source reference when derivable.
    #[serde(skip_serializing_if = "Option::is_none", rename = "externalRefs")]
    pub external_refs: Option<Vec<ExternalRef>>,
}

/// Reference to an external source system.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExternalRef {
    /// Reference category.
    #[serde(rename = "referenceCategory")]
    pub reference_category: String,
    /// Reference type.
    #[serde(rename = "referenceType")]
    pub reference_type: String,
    /// Locator string.
    pub reference_locator: String,
}

/// A document/package relationship.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Relationship {
    /// Left side of the relationship.
    #[serde(rename = "spdxElementId")]
    pub spdx_element_id: String,
    /// Relationship verb.
    #[serde(rename = "relationshipType")]
    pub relationship_type: String,
    /// Right side.
    #[serde(rename = "relatedSpdxElement")]
    pub related_spdx_element: String,
}

/// Builds an SPDX 2.3 document from parsed cargo metadata packages.
///
/// `document_name` names the analyzed artifact; `created_utc` must already be
/// RFC 3339 formatted; `tool_version` becomes the tool creator entry.
pub fn build_spdx(
    document_name: &str,
    created_utc: &str,
    tool_version: &str,
    packages: &[MetadataPackage],
) -> SpdxDocument {
    let mut spdx_packages = Vec::new();
    let mut relationships = Vec::new();
    for (idx, pkg) in packages.iter().enumerate() {
        let spdx_id = format!("SPDXRef-Package-{idx}");
        relationships.push(Relationship {
            spdx_element_id: "SPDXRef-DOCUMENT".to_owned(),
            relationship_type: "DESCRIBES".to_owned(),
            related_spdx_element: spdx_id.clone(),
        });
        spdx_packages.push(SpdxPackage {
            name: pkg.name.clone(),
            spdx_id,
            version_info: pkg.version.clone(),
            download_location: download_location(pkg),
            files_analyzed: false,
            license_concluded: NO_ASSERTION.to_owned(),
            license_declared: pkg
                .license
                .clone()
                .unwrap_or_else(|| NO_ASSERTION.to_owned()),
            copyright_text: NO_ASSERTION.to_owned(),
            external_refs: external_refs(pkg),
        });
    }
    SpdxDocument {
        spdx_version: SPDX_VERSION.to_owned(),
        data_license: DATA_LICENSE.to_owned(),
        spdx_id: "SPDXRef-DOCUMENT".to_owned(),
        name: document_name.to_owned(),
        creation_info: CreationInfo {
            created: created_utc.to_owned(),
            creators: vec![format!("Tool: {tool_version}")],
        },
        packages: spdx_packages,
        relationships,
    }
}

/// SPDX value meaning "we do not assert this field".
pub const NO_ASSERTION: &str = "NOASSERTION";

fn download_location(pkg: &MetadataPackage) -> String {
    match pkg.source.as_deref() {
        Some(s) if s.starts_with("registry+") => {
            format!("https://crates.io/crates/{}/{}", pkg.name, pkg.version)
        }
        Some(s) if s.starts_with("git+") => s
            .trim_start_matches("git+")
            .split('#')
            .next()
            .unwrap_or("NOASSERTION")
            .to_owned(),
        _ => NO_ASSERTION.to_owned(),
    }
}

fn external_refs(pkg: &MetadataPackage) -> Option<Vec<ExternalRef>> {
    match pkg.source.as_deref() {
        Some(s) if s.starts_with("registry+") => Some(vec![ExternalRef {
            reference_category: "PACKAGE-MANAGER".to_owned(),
            reference_type: "purl".to_owned(),
            reference_locator: format!("pkg:cargo/{}@{}", pkg.name, pkg.version),
        }]),
        _ => None,
    }
}

/// Parses raw `cargo metadata --format-version 1` output and builds the SPDX
/// document from its `packages` array.
pub fn from_cargo_metadata(
    metadata_json: &str,
    document_name: &str,
    created_utc: &str,
    tool_version: &str,
) -> Result<SpdxDocument, SbomError> {
    let value: serde_json::Value =
        serde_json::from_str(metadata_json).map_err(|e| SbomError::Metadata(e.to_string()))?;
    let raw = value
        .get("packages")
        .and_then(|p| p.as_array())
        .cloned()
        .ok_or_else(|| SbomError::Metadata("missing `packages` array".into()))?;
    let packages: Vec<MetadataPackage> = raw
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|e| SbomError::Metadata(e.to_string())))
        .collect::<Result<_, _>>()?;
    Ok(build_spdx(
        document_name,
        created_utc,
        tool_version,
        &packages,
    ))
}

#[cfg(test)]
mod tests;
