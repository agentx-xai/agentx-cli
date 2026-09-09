use crate::domain::validate_relative_path;
use anyhow::{Context, Result, bail};
use directories::BaseDirs;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;

pub(crate) fn root() -> Result<PathBuf> {
    std::env::current_dir().context("cannot determine current directory")
}

pub(crate) fn home() -> Result<PathBuf> {
    Ok(BaseDirs::new()
        .context("cannot find home directory")?
        .home_dir()
        .to_path_buf())
}

pub(crate) fn project_path(raw: &str, kind: &str, directory: bool) -> Result<PathBuf> {
    validate_relative_path(raw, kind)?;
    let project = root()?
        .canonicalize()
        .context("cannot resolve project root")?;
    let mut candidate = project.clone();
    for part in Path::new(raw).components() {
        if let Component::Normal(value) = part {
            candidate.push(value);
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    bail!(
                        "{kind} must not traverse a symlink: {}",
                        candidate.display()
                    )
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    let resolved = candidate
        .canonicalize()
        .with_context(|| format!("cannot resolve {kind}: {}", candidate.display()))?;
    if !resolved.starts_with(&project) {
        bail!("{kind} escapes the project root: {raw:?}");
    }
    if (directory && !resolved.is_dir()) || (!directory && !resolved.is_file()) {
        bail!(
            "{kind} is not a regular {}: {}",
            if directory { "directory" } else { "file" },
            resolved.display()
        );
    }
    Ok(resolved)
}

pub(crate) fn sha256_dir(path: &Path) -> Result<String> {
    let mut files = Vec::new();
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    let mut hash = Sha256::new();
    hash.update(b"agentx-directory-v1\0");
    for file in files {
        let relative = file
            .strip_prefix(path)?
            .to_str()
            .context("skill path must be valid UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let bytes = fs::read(file)?;
        hash.update((relative.len() as u64).to_be_bytes());
        hash.update(relative.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

pub(crate) fn read_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "managed file path is not a regular file: {}",
                path.display()
            )
        }
        Ok(_) => Ok(Some(fs::read(path)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn operation_nonce() -> Result<String> {
    Ok(format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ))
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("managed file has no parent")?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("managed file name must be UTF-8")?;
    let nonce = operation_nonce()?;
    let temp = parent.join(format!(".{name}.agentx-tmp-{nonce}"));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .with_context(|| format!("cannot create atomic temporary file: {}", temp.display()))?;
    output.write_all(bytes)?;
    output.sync_all()?;
    drop(output);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

pub(crate) fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let output = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&output)?;
        } else if entry.file_type().is_file() {
            fs::copy(entry.path(), &output)?;
        }
    }
    Ok(())
}
