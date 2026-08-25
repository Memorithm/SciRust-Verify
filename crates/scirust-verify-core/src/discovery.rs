//! Project discovery: what kind of project is at a given path.

use std::path::{Path, PathBuf};

use scirust_verify_model::SourceIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The kind of project found at the discovery root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProjectKind {
    /// A Cargo package or workspace. Rich metadata is captured by the cargo
    /// provider; this variant records only the universal facts.
    Cargo {
        /// True when the root `Cargo.toml` declares `[workspace]`.
        is_workspace: bool,
        /// Package names discovered (workspace members or single package).
        packages: Vec<String>,
    },
    /// A directory without recognized structure.
    Unknown,
}

/// Context handed to providers during detection and planning.
#[derive(Debug, Clone)]
pub struct DiscoveryContext {
    /// Absolute path of the project root.
    pub project_root: PathBuf,
    /// Recognized project kind.
    pub kind: ProjectKind,
    /// Source identity (Git/tree digest) gathered during discovery.
    pub source: SourceIdentity,
    /// Whether a `scirust-verify.toml` manifest exists at the root.
    pub has_manifest: bool,
}

impl DiscoveryContext {
    /// Performs lightweight discovery of `root` (no heavy execution).
    ///
    /// Git identity is probed via `git` when available; failures degrade to
    /// [`scirust_verify_model::DirtyState::Unknown`] rather than errors.
    pub fn discover(root: &Path) -> Result<Self, DiscoveryError> {
        let root: PathBuf = root
            .canonicalize()
            .map_err(|source| DiscoveryError::UnusableRoot {
                path: root.display().to_string(),
                source,
            })?;

        let kind = if root.join("Cargo.toml").is_file() {
            let (is_workspace, packages) = read_cargo_summary(&root);
            ProjectKind::Cargo {
                is_workspace,
                packages,
            }
        } else {
            ProjectKind::Unknown
        };

        let source = probe_git_identity(&root);
        let has_manifest = root.join(crate::manifest::MANIFEST_FILE).is_file();

        Ok(Self {
            project_root: root,
            kind,
            source,
            has_manifest,
        })
    }
}

/// Discovery failures.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The path does not exist or cannot be accessed.
    #[error("project root `{path}` is not usable: {source}")]
    UnusableRoot {
        /// Offending path.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
}

fn read_cargo_summary(root: &Path) -> (bool, Vec<String>) {
    // Deliberately minimal: parse just enough of Cargo.toml to know whether
    // this is a workspace and list member/package names. Full resolution is
    // delegated to `cargo metadata` by the cargo provider.
    let text = match std::fs::read_to_string(root.join("Cargo.toml")) {
        Ok(t) => t,
        Err(_) => return (false, Vec::new()),
    };
    let value: toml::Value = match toml::from_str(&text) {
        Ok(v) => v,
        Err(_) => return (false, Vec::new()),
    };
    let is_workspace = value.get("workspace").is_some();
    let mut packages = Vec::new();
    if is_workspace {
        if let Some(members) = value
            .get("workspace")
            .and_then(|w| w.get("members"))
            .and_then(|m| m.as_array())
        {
            for m in members {
                if let Some(s) = m.as_str() {
                    // Glob-free: record literal member paths only.
                    if !s.contains('*') && !s.contains('?') {
                        packages.push(
                            std::fs::read_to_string(root.join(s).join("Cargo.toml"))
                                .ok()
                                .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
                                .and_then(|v| {
                                    v.get("package")
                                        .and_then(|p| p.get("name"))
                                        .and_then(|n| n.as_str().map(str::to_owned))
                                })
                                .unwrap_or_else(|| s.to_owned()),
                        );
                    }
                }
            }
        }
    } else if let Some(name) = value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
    {
        packages.push(name.to_owned());
    }
    (is_workspace, packages)
}

fn probe_git_identity(root: &Path) -> SourceIdentity {
    let mut source = SourceIdentity::default();
    if git(root, &["rev-parse", "--git-dir"]).is_err() {
        return source;
    }
    if let Ok(out) = git(root, &["rev-parse", "HEAD"]) {
        source.commit = Some(out.trim().to_owned());
    }
    if let Ok(out) = git(root, &["branch", "--show-current"]) {
        let branch = out.trim();
        if !branch.is_empty() {
            source.branch = Some(branch.to_owned());
        }
    }
    if let Ok(out) = git(root, &["remote", "get-url", "origin"]) {
        source.repository = Some(out.trim().to_owned());
    }
    if let Ok(out) = git(root, &["status", "--porcelain"]) {
        let dirty_count = out.lines().filter(|l| !l.trim().is_empty()).count() as u64;
        source.dirty = if dirty_count == 0 {
            scirust_verify_model::DirtyState::Clean
        } else {
            scirust_verify_model::DirtyState::Dirty
        };
    } else {
        source.dirty = scirust_verify_model::DirtyState::Unknown;
    }
    source
}

fn git(cwd: &Path, args: &[&str]) -> Result<String, std::io::Error> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_kind_for_plain_directory() {
        let dir = std::env::temp_dir().join(format!("svd-unknown-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = DiscoveryContext::discover(&dir).unwrap();
        assert_eq!(ctx.kind, ProjectKind::Unknown);
        assert!(!ctx.has_manifest);
    }

    #[test]
    fn missing_root_is_an_error() {
        assert!(DiscoveryContext::discover(Path::new("/definitely/not/here")).is_err());
    }

    #[test]
    fn self_discovery_finds_workspace_and_git() {
        // This crate lives in a git checkout of SciRust-Verify itself.
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("crate under crates/");
        let ctx = DiscoveryContext::discover(repo_root).unwrap();
        match &ctx.kind {
            ProjectKind::Cargo {
                is_workspace,
                packages,
            } => {
                assert!(is_workspace);
                assert!(packages.contains(&"scirust-verify-core".to_owned()));
            }
            other => panic!("expected cargo workspace, got {other:?}"),
        }
        assert_ne!(ctx.source.dirty, scirust_verify_model::DirtyState::Unknown);
    }
}
