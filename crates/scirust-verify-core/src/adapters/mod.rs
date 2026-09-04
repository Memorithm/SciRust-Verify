//! Adapters for evidence produced by external ecosystem components.
//!
//! Adapters preserve source semantics and normalize observations. They do not
//! self-authorize claims or silently strengthen producer-reported outcomes.

mod forge_soup;
mod forge_soup_qualified;

pub use forge_soup::{
    ForgeSoupAdapterError, ForgeSoupIngest, ForgeSoupRecordSummary,
    FORGE_SOUP_DOMAIN_MERGE, FORGE_SOUP_EVIDENCE_SCHEMA_VERSION, FORGE_SOUP_HUB_MERGE,
    FORGE_SOUP_QUALIFIED_SOUP_COMMIT, FORGE_SOUP_REPOSITORY, FORGE_SOUP_RUNNER_MERGE,
};
pub use forge_soup_qualified::{
    ingest_qualified_forge_soup, ForgeSoupQualifiedIngest, ForgeSoupSourceIdentity,
};
