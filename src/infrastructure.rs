//! Ports for external effects. Concrete filesystem/Git adapters remain behind these boundaries.
use std::path::Path;
pub trait SourceResolver {
    fn resolve(&self, source: &str) -> anyhow::Result<std::path::PathBuf>;
}
pub trait ArtifactInstaller {
    fn install(&self, source: &Path, destination: &Path) -> anyhow::Result<()>;
}
