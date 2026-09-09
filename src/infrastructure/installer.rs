use crate::{
    domain::{RemoteAction, SUPPORTED_TARGETS, validate_package_name},
    infrastructure::{
        artifacts::security_scan,
        filesystem::{copy_dir, root, sha256_dir, write_atomic},
        targets::{mcp_summary_path, native_mcp_path, rule_destination, target_root},
    },
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) enum PlannedContent {
    Directory(PathBuf),
    File(Vec<u8>),
    Absent,
}

pub(crate) struct PlannedChange {
    pub(crate) destination: PathBuf,
    pub(crate) content: PlannedContent,
    pub(crate) description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RollbackJournal {
    pub(crate) version: u32,
    pub(crate) backup_root: PathBuf,
    pub(crate) entries: Vec<RollbackEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RollbackEntry {
    pub(crate) destination: PathBuf,
    pub(crate) backup: Option<PathBuf>,
    pub(crate) directory: bool,
}

pub(crate) struct StagedDirectory {
    destination: PathBuf,
    path: PathBuf,
}

fn agent_backup_path(root: &Path, package: &str) -> PathBuf {
    root.join(format!(".{package}.agentx-device-backup"))
}

fn managed_directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "managed skill path is not a regular directory: {}",
                path.display()
            )
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn apply_agent_plan(
    target: &str,
    actions: &[RemoteAction],
    staging: &Path,
) -> Result<()> {
    apply_agent_plan_to(&target_root(target)?, actions, staging)
}

pub(crate) fn apply_agent_plan_to(
    destination_root: &Path,
    actions: &[RemoteAction],
    staging: &Path,
) -> Result<()> {
    fs::create_dir_all(destination_root)?;
    for action in actions {
        validate_package_name(&action.package)?;
        if action.kind != "remove" && !staging.join(&action.package).is_dir() {
            bail!("staged package is missing: {}", action.package);
        }
        managed_directory(&destination_root.join(&action.package))?;
        managed_directory(&agent_backup_path(destination_root, &action.package))?;
    }
    for action in actions {
        let backup = agent_backup_path(destination_root, &action.package);
        if managed_directory(&backup)? {
            fs::remove_dir_all(&backup)?;
        }
    }
    let mut changed: Vec<(PathBuf, PathBuf)> = Vec::new();
    let result = (|| -> Result<()> {
        for action in actions {
            let destination = destination_root.join(&action.package);
            let backup = agent_backup_path(destination_root, &action.package);
            if managed_directory(&destination)? {
                fs::rename(&destination, &backup)?;
            }
            changed.push((destination.clone(), backup));
            if action.kind == "remove" {
                continue;
            }
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let temporary =
                destination_root.join(format!(".{}.agentx-install-{stamp}", action.package));
            copy_dir(&staging.join(&action.package), &temporary)?;
            security_scan(&temporary)?;
            fs::rename(&temporary, &destination)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        for (destination, backup) in changed.iter().rev() {
            if managed_directory(destination).unwrap_or(false) {
                let _ = fs::remove_dir_all(destination);
            }
            if managed_directory(backup).unwrap_or(false) {
                let _ = fs::rename(backup, destination);
            }
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn rollback_agent_files(target: &str, packages: &[String]) -> Result<()> {
    rollback_agent_files_from(&target_root(target)?, packages)
}

pub(crate) fn rollback_agent_files_from(
    destination_root: &Path,
    packages: &[String],
) -> Result<()> {
    let unique: BTreeSet<&String> = packages.iter().collect();
    for package in &unique {
        validate_package_name(package)?;
        managed_directory(&destination_root.join(package.as_str()))?;
        managed_directory(&agent_backup_path(destination_root, package))?;
    }
    for package in unique {
        let destination = destination_root.join(package);
        let backup = agent_backup_path(destination_root, package);
        if managed_directory(&destination)? {
            fs::remove_dir_all(&destination)?;
        }
        if managed_directory(&backup)? {
            fs::rename(backup, destination)?;
        }
    }
    Ok(())
}

pub(crate) fn prepare_staged_directories(
    plan: &[PlannedChange],
    nonce: &str,
) -> Result<Vec<StagedDirectory>> {
    let mut staged = Vec::new();
    for (index, change) in plan.iter().enumerate() {
        let PlannedContent::Directory(source) = &change.content else {
            continue;
        };
        match stage_directory(source, &change.destination, nonce, index) {
            Ok(item) => staged.push(item),
            Err(error) => {
                cleanup_staged_directories(&staged);
                return Err(error);
            }
        }
    }
    Ok(staged)
}

fn stage_directory(
    source: &Path,
    destination: &Path,
    nonce: &str,
    index: usize,
) -> Result<StagedDirectory> {
    let parent = destination
        .parent()
        .context("install destination has no parent")?;
    fs::create_dir_all(parent)?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .context("install destination name must be UTF-8")?;
    let path = parent.join(format!(".{name}.agentx-stage-{nonce}-{index}"));
    if path.exists() {
        bail!("staging path already exists: {}", path.display());
    }
    let result = (|| -> Result<()> {
        copy_dir(source, &path)?;
        security_scan(&path)?;
        if sha256_dir(source)? != sha256_dir(&path)? {
            bail!("staged skill hash mismatch for {}", destination.display());
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&path);
        return Err(error);
    }
    Ok(StagedDirectory {
        destination: destination.to_path_buf(),
        path,
    })
}

pub(crate) fn cleanup_staged_directories(staged: &[StagedDirectory]) {
    for item in staged {
        if item.path.is_dir() {
            let _ = fs::remove_dir_all(&item.path);
        }
    }
}

pub(crate) fn snapshot_plan(plan: &[PlannedChange], nonce: &str) -> Result<RollbackJournal> {
    let backup_root = root()?.join(".agentx/backups").join(nonce);
    let items = backup_root.join("items");
    fs::create_dir_all(&items)?;
    let mut entries = Vec::new();
    for (index, change) in plan.iter().enumerate() {
        let metadata = match fs::symlink_metadata(&change.destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "managed destination must not be a symlink: {}",
                    change.destination.display()
                )
            }
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if matches!(change.content, PlannedContent::Directory(_)) {
            if let Some(metadata) = &metadata {
                if !metadata.is_dir() {
                    bail!(
                        "skill destination is not a directory: {}",
                        change.destination.display()
                    );
                }
                security_scan(&change.destination)?;
            }
        } else if let Some(metadata) = &metadata {
            if !metadata.is_file() {
                bail!(
                    "managed destination is not a file: {}",
                    change.destination.display()
                );
            }
        }
        let backup = if let Some(metadata) = &metadata {
            let backup = items.join(format!("{index:04}"));
            if metadata.is_dir() {
                copy_dir(&change.destination, &backup)?;
            } else {
                fs::copy(&change.destination, &backup)?;
            }
            Some(backup)
        } else {
            None
        };
        entries.push(RollbackEntry {
            destination: change.destination.clone(),
            backup,
            directory: matches!(change.content, PlannedContent::Directory(_)),
        });
    }
    Ok(RollbackJournal {
        version: 1,
        backup_root,
        entries,
    })
}

fn remove_managed_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "managed destination must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn replace_directory(source: &Path, destination: &Path, nonce: &str) -> Result<()> {
    let parent = destination
        .parent()
        .context("install destination has no parent")?;
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .context("install destination name must be UTF-8")?;
    let previous = parent.join(format!(".{name}.agentx-previous-{nonce}"));
    if previous.exists() {
        bail!("replacement path already exists: {}", previous.display());
    }
    let existed = destination.exists();
    if existed {
        fs::rename(destination, &previous)?;
    }
    if let Err(error) = fs::rename(source, destination) {
        if existed {
            let _ = fs::rename(&previous, destination);
        }
        return Err(error.into());
    }
    if existed {
        fs::remove_dir_all(previous)?;
    }
    Ok(())
}

pub(crate) fn apply_install_plan(
    plan: &[PlannedChange],
    staged: &[StagedDirectory],
    nonce: &str,
) -> Result<()> {
    let staged: BTreeMap<_, _> = staged
        .iter()
        .map(|item| (item.destination.as_path(), item.path.as_path()))
        .collect();
    for change in plan {
        match &change.content {
            PlannedContent::Directory(_) => replace_directory(
                staged
                    .get(change.destination.as_path())
                    .context("staged skill directory is missing")?,
                &change.destination,
                nonce,
            )?,
            PlannedContent::File(bytes) => write_atomic(&change.destination, bytes)?,
            PlannedContent::Absent => remove_managed_path(&change.destination)?,
        }
    }
    Ok(())
}

pub(crate) fn restore_journal(journal: &RollbackJournal, nonce: &str) -> Result<()> {
    for (index, entry) in journal.entries.iter().enumerate().rev() {
        remove_managed_path(&entry.destination)?;
        let Some(backup) = &entry.backup else {
            continue;
        };
        if entry.directory {
            let parent = entry
                .destination
                .parent()
                .context("rollback destination has no parent")?;
            fs::create_dir_all(parent)?;
            let stage = parent.join(format!(".agentx-restore-{nonce}-{index}"));
            copy_dir(backup, &stage)?;
            replace_directory(&stage, &entry.destination, nonce)?;
        } else {
            write_atomic(&entry.destination, &fs::read(backup)?)?;
        }
    }
    Ok(())
}

pub(crate) fn rollback_journal_path() -> Result<PathBuf> {
    Ok(root()?.join(".agentx/rollback.json"))
}

pub(crate) fn validate_rollback_journal(journal: &RollbackJournal) -> Result<()> {
    if journal.version != 1 {
        bail!("unsupported rollback journal version {}", journal.version);
    }
    let backup_parent = root()?.join(".agentx/backups");
    if journal.backup_root.parent() != Some(backup_parent.as_path()) {
        bail!("rollback backup root is outside the AgentX backup directory");
    }
    let mut allowed_files = BTreeSet::new();
    allowed_files.insert(root()?.join("agentx.lock"));
    let mut skill_roots = Vec::new();
    for target in SUPPORTED_TARGETS {
        allowed_files.insert(rule_destination(target)?.0);
        allowed_files.insert(mcp_summary_path(target)?);
        allowed_files.insert(native_mcp_path(target)?);
        skill_roots.push(target_root(target)?);
    }
    let mut destinations = BTreeSet::new();
    for entry in &journal.entries {
        if !destinations.insert(entry.destination.clone()) {
            bail!("rollback journal contains a duplicate destination");
        }
        let skill_destination = entry.directory
            && skill_roots
                .iter()
                .any(|skill_root| entry.destination.parent() == Some(skill_root.as_path()))
            && entry
                .destination
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| validate_package_name(name).is_ok());
        if !allowed_files.contains(&entry.destination) && !skill_destination {
            bail!(
                "rollback journal contains an unmanaged destination: {}",
                entry.destination.display()
            );
        }
        if let Some(backup) = &entry.backup {
            if backup.parent() != Some(journal.backup_root.join("items").as_path()) {
                bail!("rollback entry points outside its backup directory");
            }
            let metadata = fs::symlink_metadata(backup)
                .with_context(|| format!("rollback backup is missing: {}", backup.display()))?;
            if metadata.file_type().is_symlink()
                || (entry.directory && !metadata.is_dir())
                || (!entry.directory && !metadata.is_file())
            {
                bail!(
                    "rollback backup has an unexpected type: {}",
                    backup.display()
                );
            }
        }
    }
    Ok(())
}
