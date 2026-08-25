//! Provider architecture: detection, planning and execution interfaces.
//!
//! V0.1 uses statically compiled providers only. The traits below keep the
//! door open for future remote/sandboxed runners without redesigning the
//! domain model.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use scirust_verify_model::{
    ArtifactId, Check, CheckExecution, Evidence, EvidenceId, VerificationScope,
};
use thiserror::Error;

use crate::discovery::DiscoveryContext;

/// Errors providers may surface.
#[derive(Debug, Error)]
pub enum ProviderError {
    /// The provider cannot plan/execute in the current context.
    #[error("provider `{provider}`: {reason}")]
    InvalidContext {
        /// Provider name.
        provider: &'static str,
        /// What is wrong.
        reason: String,
    },
}

/// Detection result reported by a provider.
#[derive(Debug, Clone, PartialEq)]
pub enum Detection {
    /// Provider applies to this project.
    Detected {
        /// Human-readable justification recorded in inspect output.
        note: String,
    },
    /// Provider does not apply.
    NotDetected,
}

/// Context for planning: discovery facts plus effective manifest settings.
pub struct PlanContext<'a> {
    /// Discovery results.
    pub ctx: &'a DiscoveryContext,
    /// Artifact id claims will attach to.
    pub artifact_id: ArtifactId,
    /// Effective claim requirement levels (slug => level), after profile
    /// precedence resolution.
    pub claim_levels: &'a BTreeMap<String, scirust_verify_model::RequirementLevel>,
    /// Default timeout applied when a check does not override it.
    pub default_timeout: std::time::Duration,
    /// Stdout capture limit in bytes.
    pub stdout_limit: u64,
    /// Stderr capture limit in bytes.
    pub stderr_limit: u64,
    /// Extra targets requested by configuration.
    pub targets: &'a [String],
    /// Explicit features requested by configuration.
    pub features: &'a [String],
}

/// Sink receiving evidence produced during execution.
///
/// Implementations persist evidence into the run store. Evidence ids are
/// sequential (`ev-0001`, ...) assigned in execution order; providers obtain
/// them up front via [`CheckSink::next_id`] so every evidence object is born
/// with its final identity.
pub trait CheckSink {
    /// Returns the next sequential evidence id.
    fn next_id(&mut self) -> EvidenceId;

    /// Persists one evidence object with its attachment payloads.
    fn add_evidence(
        &mut self,
        evidence: Evidence,
        attachments: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), PipelineFailure>;
}

/// Failures that can abort (or degrade) pipeline execution.
#[derive(Debug, Error)]
pub enum PipelineFailure {
    /// A provider could not proceed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Persisting evidence failed.
    #[error("evidence persistence failed: {0}")]
    Store(#[from] scirust_verify_store::StoreError),
    /// Command infrastructure failure (not a scientific failure).
    #[error("runner failure: {0}")]
    Runner(#[from] scirust_verify_runner::RunnerError),
}

/// Execution services handed to `VerificationProvider::execute`.
pub struct ExecutionContext<'a> {
    /// Project root (absolute).
    pub project_root: &'a Path,
    /// Subject artifact id.
    pub artifact: ArtifactId,
    /// Scope under which checks execute (host/toolchain snapshot).
    pub scope: VerificationScope,
    /// Evidence sink wired to the run store.
    pub sink: &'a mut dyn CheckSink,
    /// Working-directory helper resolving relative cwds against the root.
    pub cwd_base: PathBuf,
}

impl<'a> ExecutionContext<'a> {
    /// Resolves a possibly-relative cwd to an absolute directory.
    pub fn resolve_cwd(&self, cwd: Option<&Path>) -> PathBuf {
        match cwd {
            Some(p) if p.is_absolute() => p.to_path_buf(),
            Some(p) => self.cwd_base.join(p),
            None => self.cwd_base.to_path_buf(),
        }
    }
}

/// A verification provider.
pub trait VerificationProvider {
    /// Stable provider name used in check ids (`<provider>:...`).
    fn name(&self) -> &'static str;

    /// Does this provider apply to the discovered project?
    fn detect(&self, ctx: &DiscoveryContext) -> Detection;

    /// Plans the checks this provider would execute. Must be deterministic:
    /// identical inputs produce identically ordered plans.
    fn plan(&self, request: &PlanContext<'_>) -> Result<Vec<Check>, ProviderError>;

    /// Executes one previously planned check, producing observations and
    /// evidence through the sink.
    fn execute(
        &self,
        check: &Check,
        env: &mut ExecutionContext<'_>,
    ) -> Result<CheckExecution, PipelineFailure>;
}

/// Ordered set of active providers.
pub struct ProviderRegistry {
    providers: Vec<Box<dyn VerificationProvider>>,
}

impl ProviderRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Registers a provider (order matters only for reporting).
    pub fn register(&mut self, provider: Box<dyn VerificationProvider>) {
        self.providers.push(provider);
    }

    /// All registered providers.
    pub fn providers(&self) -> &[Box<dyn VerificationProvider>] {
        &self.providers
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}
