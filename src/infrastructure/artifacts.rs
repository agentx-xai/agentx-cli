use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
use tar::{Archive, Builder, EntryType, Header, HeaderMode};
use walkdir::WalkDir;

const MAX_PACKAGE_BYTES: usize = 51 << 20;
const MAX_PACKAGE_UNCOMPRESSED_BYTES: u64 = 100 << 20;
const MAX_PACKAGE_FILES: usize = 4096;

pub(crate) fn build_skill_archive(source: &Path) -> Result<Vec<u8>> {
    if !source.join("SKILL.md").is_file() {
        bail!("skill package root must contain SKILL.md");
    }
    security_scan(source)?;
    let mut files = Vec::new();
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    if files.len() > MAX_PACKAGE_FILES {
        bail!("skill package contains more than {MAX_PACKAGE_FILES} files");
    }
    let encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut archive = Builder::new(encoder);
    archive.mode(HeaderMode::Deterministic);
    for file in files {
        let relative = file.strip_prefix(source)?;
        validate_package_path(relative)?;
        let mut input = fs::File::open(&file)?;
        let size = input.metadata()?.len();
        let mut header = Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        archive.append_data(&mut header, relative, &mut input)?;
    }
    let encoder = archive.into_inner()?;
    let bytes = encoder.finish()?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        bail!("skill package exceeds {MAX_PACKAGE_BYTES} bytes");
    }
    Ok(bytes)
}

pub(crate) fn read_skill_archive(payload: &[u8]) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    if payload.len() > MAX_PACKAGE_BYTES {
        bail!("skill package exceeds {MAX_PACKAGE_BYTES} bytes");
    }
    let decoder = GzDecoder::new(payload);
    let mut archive = Archive::new(decoder);
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for entry in archive
        .entries()
        .context("artifact must be a gzip tar archive")?
    {
        let mut entry = entry.context("invalid skill package archive")?;
        let kind = entry.header().entry_type();
        let path = entry.path()?.into_owned();
        validate_package_path(&path)?;
        if kind == EntryType::Directory {
            continue;
        }
        if kind != EntryType::Regular {
            bail!(
                "skill package entry is not a regular file: {}",
                path.display()
            );
        }
        if entry.header().mode()? & 0o111 != 0 {
            bail!("executable file is not allowed: {}", path.display());
        }
        if forbidden_credential_path(&path) {
            bail!("credential-like file is not allowed: {}", path.display());
        }
        if files.contains_key(&path) {
            bail!("duplicate skill package path: {}", path.display());
        }
        let size = entry.header().size()?;
        total = total
            .checked_add(size)
            .context("skill package size overflow")?;
        if total > MAX_PACKAGE_UNCOMPRESSED_BYTES {
            bail!(
                "skill package uncompressed content exceeds {MAX_PACKAGE_UNCOMPRESSED_BYTES} bytes"
            );
        }
        let mut data = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
        entry.read_to_end(&mut data)?;
        files.insert(path, data);
        if files.len() > MAX_PACKAGE_FILES {
            bail!("skill package contains more than {MAX_PACKAGE_FILES} files");
        }
    }
    if !files.contains_key(Path::new("SKILL.md")) {
        bail!("skill package root must contain SKILL.md");
    }
    Ok(files)
}

pub(crate) fn unpack_skill_archive(payload: &[u8], destination: &Path) -> Result<()> {
    let files = read_skill_archive(payload)?;
    fs::create_dir_all(destination)?;
    for (relative, data) in files {
        let output = destination.join(relative);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, data)?;
    }
    security_scan(destination)
}

pub(crate) fn validate_package_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("unsafe skill package path: {}", path.display());
    }
    if forbidden_credential_path(path) {
        bail!("credential-like file is not allowed: {}", path.display());
    }
    Ok(())
}

fn forbidden_credential_path(path: &Path) -> bool {
    let Some(base) = path.file_name().and_then(|value| value.to_str()) else {
        return true;
    };
    let base = base.to_ascii_lowercase();
    base == ".env"
        || base.starts_with(".env.")
        || matches!(
            base.as_str(),
            "credentials.json" | "cookies.json" | "session.json" | "id_rsa" | "id_ed25519"
        )
        || base.ends_with(".pem")
        || base.ends_with(".key")
}

pub(crate) fn security_scan(path: &Path) -> Result<()> {
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "symlink is not allowed in skill package: {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_file() && entry.metadata()?.len() > 2_000_000 {
            bail!("skill file exceeds 2MB: {}", entry.path().display());
        }
        if entry.file_type().is_file() && forbidden_credential_path(entry.path()) {
            bail!(
                "credential-like file is not allowed in skill package: {}",
                entry.path().display()
            );
        }
        #[cfg(unix)]
        if entry.file_type().is_file() {
            use std::os::unix::fs::PermissionsExt;
            if entry.metadata()?.permissions().mode() & 0o111 != 0 {
                bail!("executable file is not allowed: {}", entry.path().display());
            }
        }
    }
    Ok(())
}
