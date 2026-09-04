//! SciRust-Verify core: discovery context, manifest handling, provider
//! architecture, claim evaluation and the end-to-end verification pipeline.

#![deny(missing_docs)]

pub mod adapters;
pub mod discovery;
pub mod manifest;
pub mod pipeline;
pub mod planning;
pub mod provenance;
pub mod providers;
pub mod tree_digest;
pub mod verdict_engine;

pub use discovery::{DiscoveryContext, ProjectKind};
pub use manifest::ManifestError;
pub use pipeline::{run_verify, VerifyOptions, VerifyOutcome};
pub use planning::{
    CheckSink, ExecutionContext, PlanContext, ProviderRegistry, VerificationProvider,
};
pub use verdict_engine::{evaluate_claims, ClaimGateInputs};
