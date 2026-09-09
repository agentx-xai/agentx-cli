use crate::{
    domain::Source,
    infrastructure::filesystem::{project_path, root},
};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct ResolvedSource {
    pub(crate) path: PathBuf,
    pub(crate) source: String,
    pub(crate) requested_ref: Option<String>,
    pub(crate) revision: Option<String>,
}

pub(crate) fn resolve_source(source: &Source) -> Result<ResolvedSource> {
    match source {
        Source::Local { path } => {
            let resolved = project_path(path, "skill source", true)?;
            Ok(ResolvedSource {
                path: resolved,
                source: path.clone(),
                requested_ref: None,
                revision: None,
            })
        }
        Source::Git { url, r#ref } => {
            let reference = r#ref
                .as_deref()
                .context("git skill sources require a fixed ref")?;
            let mut key = Sha256::new();
            key.update(url.as_bytes());
            key.update([0]);
            key.update(reference.as_bytes());
            let cache = root()?
                .join(".agentx/cache/git")
                .join(format!("{:x}", key.finalize()));
            if !cache.is_dir() {
                let parent = cache.parent().context("invalid git cache path")?;
                fs::create_dir_all(parent)?;
                let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
                let temp = parent.join(format!("clone-{stamp}"));
                let mut command = Command::new("git");
                command.args(["clone", "--depth", "1", "--branch", reference]);
                command.arg(url).arg(&temp);
                let status = command
                    .status()
                    .context("git is required for git sources")?;
                if !status.success() {
                    let _ = fs::remove_dir_all(&temp);
                    bail!("failed to clone skill source {url} at ref {reference}");
                }
                fs::rename(&temp, &cache)?;
            }
            let output = Command::new("git")
                .arg("-C")
                .arg(&cache)
                .args(["rev-parse", "HEAD"])
                .output()
                .context("git is required for git sources")?;
            if !output.status.success() {
                bail!("cannot resolve git revision for {url} at ref {reference}");
            }
            let revision = String::from_utf8(output.stdout)
                .context("git returned a non-UTF-8 revision")?
                .trim()
                .to_string();
            if revision.len() < 40 || !revision.bytes().all(|value| value.is_ascii_hexdigit()) {
                bail!("git returned an invalid revision for {url} at ref {reference}");
            }
            Ok(ResolvedSource {
                path: cache,
                source: url.clone(),
                requested_ref: Some(reference.to_string()),
                revision: Some(revision),
            })
        }
    }
}
