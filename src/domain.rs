//! Portable AgentX models and validation rules.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

pub(crate) const SUPPORTED_TARGETS: &[&str] = &[
    "codex", "claude", "cursor", "windsurf", "gemini", "copilot", "cline", "grok",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TeamManifestDocument {
    pub(crate) version: u32,
    pub(crate) packages: Vec<TeamPackage>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TeamPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Manifest {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) skills: Vec<Skill>,
    #[serde(default)]
    pub(crate) rules: Vec<Rule>,
    #[serde(default)]
    pub(crate) mcp: Vec<Mcp>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Skill {
    pub(crate) name: String,
    pub(crate) source: Source,
    #[serde(default)]
    pub(crate) targets: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Rule {
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) targets: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Mcp {
    pub(crate) name: String,
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default)]
    pub(crate) targets: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub(crate) enum Source {
    #[serde(rename = "local")]
    Local { path: String },
    #[serde(rename = "git")]
    Git {
        url: String,
        #[serde(default)]
        r#ref: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Lock {
    pub(crate) version: u32,
    pub(crate) packages: Vec<LockedPackage>,
    #[serde(default)]
    pub(crate) rules: Vec<LockedRule>,
    #[serde(default)]
    pub(crate) mcp: Vec<LockedMcp>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LockedPackage {
    pub(crate) name: String,
    pub(crate) source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) r#ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revision: Option<String>,
    pub(crate) sha256: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LockedRule {
    pub(crate) source: String,
    pub(crate) targets: Vec<String>,
    pub(crate) sha256: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LockedMcp {
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemotePlan {
    pub(crate) actions: Vec<RemoteAction>,
    pub(crate) manifest_revision: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoteAction {
    pub(crate) package: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) to: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct AgentState {
    pub(crate) manifest_revision: i64,
    pub(crate) installed_packages: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) target: Option<String>,
    #[serde(default)]
    pub(crate) changed_packages: Vec<String>,
}

pub(crate) fn validate_target(target: &str) -> Result<()> {
    if !SUPPORTED_TARGETS.contains(&target) {
        bail!(
            "unsupported target {target}; use {}",
            SUPPORTED_TARGETS.join(", ")
        );
    }
    Ok(())
}

pub(crate) fn validate_package_name(name: &str) -> Result<()> {
    validate_safe_name(name, "package")
}

pub(crate) fn validate_device_name(name: &str) -> Result<()> {
    validate_safe_name(name, "device")
}

pub(crate) fn validate_workspace_id(name: &str) -> Result<()> {
    validate_safe_name(name, "workspace ID")
}

fn validate_safe_name(name: &str, kind: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'))
    {
        bail!("unsafe {kind} name {name:?}");
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, kind: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("invalid SHA-256 for {kind}");
    }
    Ok(())
}

pub(crate) fn validate_team_manifest(document: &TeamManifestDocument) -> Result<()> {
    if document.version != 1 {
        bail!("unsupported team manifest version {}", document.version);
    }
    let mut names = BTreeSet::new();
    for package in &document.packages {
        validate_package_name(&package.name)?;
        semver::Version::parse(&package.version)
            .with_context(|| format!("invalid version for team package {:?}", package.name))?;
        validate_sha256(&package.sha256, &format!("team package {:?}", package.name))?;
        if !names.insert(package.name.as_str()) {
            bail!("duplicate team package name {:?}", package.name);
        }
    }
    Ok(())
}

pub(crate) fn validate_manifest(manifest: &Manifest) -> Result<()> {
    let mut skill_names = BTreeSet::new();
    for skill in &manifest.skills {
        validate_package_name(&skill.name)?;
        if !skill_names.insert(skill.name.as_str()) {
            bail!("duplicate skill name {:?}", skill.name);
        }
        validate_targets(&skill.targets)?;
        match &skill.source {
            Source::Local { path } => validate_relative_path(path, "skill source")?,
            Source::Git { url, r#ref } => {
                if url.trim().is_empty() || url.starts_with('-') {
                    bail!("git source URL must be non-empty and must not start with '-'");
                }
                let reference = r#ref
                    .as_deref()
                    .context("git skill sources require a fixed ref")?;
                if reference.trim().is_empty()
                    || reference.len() > 256
                    || reference.starts_with('-')
                {
                    bail!(
                        "git source ref must be non-empty, at most 256 bytes, and must not start with '-'"
                    );
                }
            }
        }
    }
    for rule in &manifest.rules {
        validate_relative_path(&rule.source, "rule source")?;
        validate_targets(&rule.targets)?;
    }
    let mut mcp_names = BTreeSet::new();
    for mcp in &manifest.mcp {
        validate_package_name(&mcp.name)?;
        if !mcp_names.insert(mcp.name.as_str()) {
            bail!("duplicate MCP name {:?}", mcp.name);
        }
        if mcp.command.trim().is_empty() || mcp.command.contains('\0') {
            bail!(
                "MCP command for {:?} must be non-empty and contain no NUL byte",
                mcp.name
            );
        }
        if mcp.args.iter().any(|arg| arg.contains('\0')) {
            bail!("MCP arguments for {:?} must contain no NUL byte", mcp.name);
        }
        validate_targets(&mcp.targets)?;
    }
    Ok(())
}

pub(crate) fn validate_relative_path(raw: &str, kind: &str) -> Result<()> {
    let path = Path::new(raw);
    if raw.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::CurDir | Component::Normal(_)))
    {
        bail!("{kind} must be a contained relative path: {raw:?}");
    }
    Ok(())
}

fn validate_targets(targets: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for target in targets {
        validate_target(target)?;
        if !seen.insert(target.as_str()) {
            bail!("duplicate target {target:?}");
        }
    }
    Ok(())
}
