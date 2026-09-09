use crate::{
    domain::{
        AgentState, Lock, LockedMcp, LockedPackage, LockedRule, Manifest, Mcp, RemotePlan,
        SUPPORTED_TARGETS, TeamManifestDocument, validate_manifest, validate_package_name,
        validate_target, validate_team_manifest,
    },
    infrastructure::{
        artifacts::{build_skill_archive, read_skill_archive, security_scan, unpack_skill_archive},
        filesystem::{
            operation_nonce, project_path, read_regular_file, root, sha256_dir, sha256_file,
            write_atomic,
        },
        installer::{
            PlannedChange, PlannedContent, RollbackJournal, apply_agent_plan, apply_install_plan,
            cleanup_staged_directories, prepare_staged_directories, restore_journal,
            rollback_agent_files, rollback_journal_path, snapshot_plan, validate_rollback_journal,
        },
        registry::RegistryClient,
        sources::resolve_source,
        targets::{
            mcp_summary_path, native_mcp_path, render_managed_rules, render_mcp_native,
            rule_destination, target_root,
        },
    },
    interface::{AgentCommands, Commands, RegistryCommands, TeamCommands, parse},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn run() -> Result<()> {
    let cli = parse();
    match cli.command {
        Commands::Init => init(),
        Commands::Install {
            target,
            yes,
            frozen,
        } => install(target.as_deref(), yes, frozen),
        Commands::Diff { target } => diff(target.as_deref()),
        Commands::Doctor => doctor(),
        Commands::Lock => lock_manifest(),
        Commands::Rollback => rollback(),
        Commands::Registry { command } => registry(command),
        Commands::Team { command } => team(command),
        Commands::Agent { command } => agent(command),
    }
}

fn agent(command: AgentCommands) -> Result<()> {
    let client = RegistryClient::load()?;
    client.require_workspace("agent commands")?;
    let device = match &command {
        AgentCommands::Plan { device }
        | AgentCommands::Sync { device, .. }
        | AgentCommands::Rollback { device, .. } => device.clone(),
    };
    crate::domain::validate_device_name(&device)?;
    let state_dir = root()?.join(".agentx/devices").join(&device);
    fs::create_dir_all(&state_dir)?;
    let state_path = state_dir.join("state.json");
    let backup_path = state_dir.join("previous.json");
    match command {
        AgentCommands::Plan { .. } => {
            let plan = client.reconcile_plan(&device)?;
            println!("manifest revision {}", plan.manifest_revision);
            for action in plan.actions {
                println!("{} {} {}", action.kind, action.package, action.to);
            }
        }
        AgentCommands::Sync { target, .. } => {
            validate_target(&target)?;
            let plan: RemotePlan = client.reconcile_plan(&device)?;
            let old: AgentState = fs::read_to_string(&state_path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_default();
            if let Some(previous_target) = &old.target {
                if previous_target != &target && !old.installed_packages.is_empty() {
                    bail!(
                        "device state belongs to target {previous_target}; use --target {previous_target}"
                    );
                }
            }
            if plan.actions.is_empty() {
                client.heartbeat(&device, &old.installed_packages)?;
                println!(
                    "device {} already matches manifest revision {}",
                    device, plan.manifest_revision
                );
                return Ok(());
            }
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let staging = state_dir.join(format!("staging-{stamp}"));
            fs::create_dir_all(&staging)?;
            let cache = state_dir.join("artifacts");
            fs::create_dir_all(&cache)?;
            let mut installed = old.installed_packages.clone();
            for action in &plan.actions {
                validate_package_name(&action.package)?;
                match action.kind.as_str() {
                    "remove" => {
                        installed.remove(&action.package);
                    }
                    "install" | "update" => {
                        let bytes = client.download_artifact(&action.to)?;
                        let cached = cache.join(&action.to);
                        write_atomic(&cached, &bytes)?;
                        unpack_skill_archive(&bytes, &staging.join(&action.package))?;
                        installed.insert(action.package.clone(), action.to.clone());
                    }
                    _ => bail!("unsupported reconcile action {}", action.kind),
                }
            }
            write_atomic(&backup_path, &serde_json::to_vec_pretty(&old)?)?;
            if let Err(err) = apply_agent_plan(&target, &plan.actions, &staging) {
                let _ = fs::remove_dir_all(&staging);
                return Err(err);
            }
            let _ = fs::remove_dir_all(&staging);
            let new_state = AgentState {
                manifest_revision: plan.manifest_revision,
                installed_packages: installed.clone(),
                target: Some(target),
                changed_packages: plan
                    .actions
                    .iter()
                    .map(|action| action.package.clone())
                    .collect(),
            };
            write_atomic(&state_path, &serde_json::to_vec_pretty(&new_state)?)?;
            client.heartbeat(&device, &installed)?;
            println!(
                "synced device {} to manifest revision {}",
                device, plan.manifest_revision
            );
        }
        AgentCommands::Rollback { target, .. } => {
            validate_target(&target)?;
            let current: AgentState = serde_json::from_str(
                &fs::read_to_string(&state_path).context("no current agent state to roll back")?,
            )?;
            let mut previous: AgentState = serde_json::from_str(
                &fs::read_to_string(&backup_path)
                    .context("no previous agent state to roll back")?,
            )?;
            if current.target.as_deref() != Some(target.as_str()) {
                bail!("current device state does not belong to target {target}");
            }
            rollback_agent_files(&target, &current.changed_packages)?;
            previous.target = Some(target);
            previous.changed_packages.clear();
            write_atomic(&state_path, &serde_json::to_vec_pretty(&previous)?)?;
            client.heartbeat(&device, &previous.installed_packages)?;
            println!(
                "rolled back device {} to manifest revision {}",
                device, previous.manifest_revision
            );
        }
    }
    Ok(())
}
fn team(command: TeamCommands) -> Result<()> {
    let client = RegistryClient::load()?;
    client.require_workspace("team commands")?;
    match command {
        TeamCommands::Pull { output } => {
            let document = client.fetch_team_manifest()?;
            validate_team_manifest(&document)?;
            let raw = serde_yaml::to_string(&document).context("manifest is not serializable")?;
            write_atomic(&output, raw.as_bytes())?;
            println!("pulled team manifest -> {}", output.display());
            Ok(())
        }
        TeamCommands::Push { input } => {
            let raw = fs::read_to_string(&input)
                .with_context(|| format!("cannot read {}", input.display()))?;
            let document: TeamManifestDocument =
                serde_yaml::from_str(&raw).context("invalid team manifest YAML")?;
            validate_team_manifest(&document)?;
            let revision = client.replace_team_manifest(&document)?;
            println!("pushed team manifest revision {}", revision);
            Ok(())
        }
    }
}
fn registry(command: RegistryCommands) -> Result<()> {
    match command {
        RegistryCommands::Login {
            url,
            token,
            token_stdin,
            oidc,
            workspace,
        } => {
            let path = if oidc {
                let authorization = RegistryClient::start_oidc_device_login(&url, workspace)?;
                println!("Open this URL in a browser:");
                println!("{}", authorization.verification_url());
                println!("Confirm code: {}", authorization.user_code());
                io::stdout()
                    .flush()
                    .context("cannot flush OIDC login instructions")?;
                authorization.finish()?
            } else {
                let token = if let Some(token) = token {
                    token
                } else if token_stdin {
                    let mut value = String::new();
                    io::stdin()
                        .read_to_string(&mut value)
                        .context("cannot read Registry token from stdin")?;
                    value.trim_end_matches(['\r', '\n']).to_string()
                } else {
                    std::env::var("AGENTX_TOKEN").context(
                        "provide --oidc, --token-stdin, --token, or the AGENTX_TOKEN environment variable",
                    )?
                };
                RegistryClient::save_login(&url, &token, workspace)?
            };
            println!("saved Registry credentials to {}", path.display());
            Ok(())
        }
        RegistryCommands::Workspaces => {
            for workspace in RegistryClient::load()?.list_workspaces()? {
                println!("{}\t{}\t{}", workspace.id, workspace.slug, workspace.name);
            }
            Ok(())
        }
        RegistryCommands::Use { workspace } => {
            let path = RegistryClient::select_workspace(&workspace)?;
            println!("selected workspace {} in {}", workspace, path.display());
            Ok(())
        }
        RegistryCommands::Logout => {
            let path = RegistryClient::logout()?;
            println!("removed Registry credentials from {}", path.display());
            Ok(())
        }
        RegistryCommands::Publish {
            name,
            version,
            file,
            signature,
        } => {
            validate_package_name(&name)?;
            semver::Version::parse(&version).context("package version must be SemVer")?;
            let bytes = if file.is_dir() {
                build_skill_archive(&file)?
            } else {
                let bytes =
                    fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
                read_skill_archive(&bytes)?;
                bytes
            };
            let file_name = file
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("artifact");
            let digest =
                RegistryClient::load()?.publish(&name, &version, file_name, bytes, signature)?;
            println!("published {}@{} (sha256 {})", name, version, digest);
            Ok(())
        }
        RegistryCommands::Pull {
            name,
            version,
            output,
        } => {
            validate_package_name(&name)?;
            semver::Version::parse(&version).context("package version must be SemVer")?;
            let bytes = RegistryClient::load()?.pull(&name, &version)?;
            read_skill_archive(&bytes)?;
            write_atomic(&output, &bytes)?;
            println!("downloaded {}@{} -> {}", name, version, output.display());
            Ok(())
        }
    }
}
fn load_manifest() -> Result<Manifest> {
    let path = root()?.join("agentx.yaml");
    let raw =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let m: Manifest = serde_yaml::from_str(&raw).context("invalid agentx.yaml")?;
    if m.version != 1 {
        bail!("unsupported manifest version {}", m.version);
    }
    validate_manifest(&m)?;
    Ok(m)
}
fn init() -> Result<()> {
    let path = root()?.join("agentx.yaml");
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    fs::write(&path, "version: 1\nskills: []\nrules: []\nmcp: []\n")?;
    println!("created {}", path.display());
    Ok(())
}

fn resolve_manifest(m: &Manifest) -> Result<(Lock, BTreeMap<String, PathBuf>)> {
    let mut packages = Vec::new();
    let mut sources = BTreeMap::new();
    for skill in &m.skills {
        let resolved = resolve_source(&skill.source)?;
        if !resolved.path.join("SKILL.md").is_file() {
            bail!("skill {:?} must contain a root SKILL.md", skill.name);
        }
        security_scan(&resolved.path)?;
        packages.push(LockedPackage {
            name: skill.name.clone(),
            source: resolved.source,
            r#ref: resolved.requested_ref,
            revision: resolved.revision,
            sha256: sha256_dir(&resolved.path)?,
        });
        sources.insert(skill.name.clone(), resolved.path);
    }
    let mut rules = Vec::new();
    for rule in &m.rules {
        let path = project_path(&rule.source, "rule source", false)?;
        rules.push(LockedRule {
            source: rule.source.clone(),
            targets: rule.targets.clone(),
            sha256: sha256_file(&path)?,
        });
    }
    let mcp = m
        .mcp
        .iter()
        .map(|entry| LockedMcp {
            name: entry.name.clone(),
            command: entry.command.clone(),
            args: entry.args.clone(),
            targets: entry.targets.clone(),
        })
        .collect();
    Ok((
        Lock {
            version: 2,
            packages,
            rules,
            mcp,
        },
        sources,
    ))
}

fn planned_rule_change(m: &Manifest, target: &str) -> Result<Option<PlannedChange>> {
    let mut text = String::new();
    for rule in &m.rules {
        if rule.targets.is_empty() || rule.targets.iter().any(|value| value == target) {
            let path = project_path(&rule.source, "rule source", false)?;
            text.push_str(
                &fs::read_to_string(&path)
                    .with_context(|| format!("rule source must be UTF-8: {}", path.display()))?,
            );
            text.push_str("\n\n");
        }
    }
    let text = text.trim_end().to_string();
    let (destination, shared) = rule_destination(target)?;
    let existing = read_regular_file(&destination)?;
    let desired = if shared {
        let current = match &existing {
            Some(bytes) => std::str::from_utf8(bytes).with_context(|| {
                format!(
                    "managed rules file must be UTF-8: {}",
                    destination.display()
                )
            })?,
            None => "",
        };
        Some(render_managed_rules(current, &text)?.into_bytes())
    } else if text.is_empty() {
        None
    } else if target == "cursor" {
        Some(
            format!(
                "---\ndescription: AgentX managed project rules\nalwaysApply: true\n---\n\n{text}\n"
            )
            .into_bytes(),
        )
    } else {
        Some(format!("{text}\n").into_bytes())
    };
    match (&existing, &desired) {
        (None, None) => Ok(None),
        (Some(current), Some(next)) if current == next => Ok(None),
        (None, Some(next)) if next.is_empty() => Ok(None),
        _ => Ok(Some(PlannedChange {
            destination,
            content: desired.map_or(PlannedContent::Absent, PlannedContent::File),
            description: format!("{target} rules"),
        })),
    }
}

fn planned_mcp_changes(m: &Manifest, target: &str) -> Result<Vec<PlannedChange>> {
    let selected: Vec<_> = m
        .mcp
        .iter()
        .filter(|entry| {
            entry.targets.is_empty() || entry.targets.iter().any(|value| value == target)
        })
        .collect();
    let summary_path = mcp_summary_path(target)?;
    let previous_summary = read_regular_file(&summary_path)?;
    let previous_entries: Vec<Mcp> = match &previous_summary {
        Some(bytes) => serde_json::from_slice(bytes)
            .with_context(|| format!("invalid AgentX MCP summary: {}", summary_path.display()))?,
        None => Vec::new(),
    };
    let previous: BTreeSet<_> = previous_entries
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    if selected.is_empty() && previous.is_empty() {
        return Ok(Vec::new());
    }
    let native_path = native_mcp_path(target)?;
    let existing_native = read_regular_file(&native_path)?;
    let desired_native =
        render_mcp_native(target, existing_native.as_deref(), &previous, &selected)?;
    let summary = selected
        .iter()
        .map(|entry| {
            serde_json::json!({"name": entry.name, "command": entry.command, "args": entry.args})
        })
        .collect::<Vec<_>>();
    let desired_summary = serde_json::to_vec_pretty(&summary)?;
    let mut changes = Vec::new();
    if existing_native.as_deref() != Some(desired_native.as_slice()) {
        changes.push(PlannedChange {
            destination: native_path,
            content: PlannedContent::File(desired_native),
            description: format!("{target} MCP configuration"),
        });
    }
    if previous_summary.as_deref() != Some(desired_summary.as_slice()) {
        changes.push(PlannedChange {
            destination: summary_path,
            content: PlannedContent::File(desired_summary),
            description: format!("{target} AgentX MCP ownership record"),
        });
    }
    Ok(changes)
}

fn build_install_plan(
    m: &Manifest,
    targets: &[String],
    sources: &BTreeMap<String, PathBuf>,
    lock: &Lock,
) -> Result<Vec<PlannedChange>> {
    let mut plan = Vec::new();
    let mut destinations = BTreeSet::new();
    for target in targets {
        let destination_root = target_root(target)?;
        for skill in &m.skills {
            if !skill.targets.is_empty() && !skill.targets.iter().any(|value| value == target) {
                continue;
            }
            let destination = destination_root.join(&skill.name);
            if !destinations.insert(destination.clone()) {
                bail!(
                    "multiple install operations target {}",
                    destination.display()
                );
            }
            plan.push(PlannedChange {
                destination,
                content: PlannedContent::Directory(
                    sources
                        .get(&skill.name)
                        .context("resolved skill source is missing")?
                        .clone(),
                ),
                description: format!("{target} skill {}", skill.name),
            });
        }
        if let Some(change) = planned_rule_change(m, target)? {
            if !destinations.insert(change.destination.clone()) {
                bail!(
                    "multiple install operations target {}",
                    change.destination.display()
                );
            }
            plan.push(change);
        }
        for change in planned_mcp_changes(m, target)? {
            if !destinations.insert(change.destination.clone()) {
                bail!(
                    "multiple install operations target {}",
                    change.destination.display()
                );
            }
            plan.push(change);
        }
    }
    let lock_path = root()?.join("agentx.lock");
    if !destinations.insert(lock_path.clone()) {
        bail!("multiple install operations target {}", lock_path.display());
    }
    plan.push(PlannedChange {
        destination: lock_path,
        content: PlannedContent::File(serde_yaml::to_string(lock)?.into_bytes()),
        description: "lockfile".into(),
    });
    Ok(plan)
}

fn install(target: Option<&str>, yes: bool, frozen: bool) -> Result<()> {
    let m = load_manifest()?;
    let targets = target
        .map(|x| vec![x.to_string()])
        .unwrap_or_else(|| vec!["codex".into(), "claude".into()]);
    for target in &targets {
        if !SUPPORTED_TARGETS.contains(&target.as_str()) {
            bail!(
                "unsupported target {target}; use {}",
                SUPPORTED_TARGETS.join(", ")
            );
        }
    }
    let (mut lock, sources) = resolve_manifest(&m)?;
    let lock_path = root()?.join("agentx.lock");
    if frozen && lock_path.exists() {
        let existing: Lock = serde_yaml::from_str(&fs::read_to_string(&lock_path)?)?;
        if existing != lock {
            bail!("lockfile does not match sources; run `agentx lock` first");
        }
        lock = existing;
    } else if frozen {
        bail!("agentx.lock is required with --frozen");
    }
    let plan = build_install_plan(&m, &targets, &sources, &lock)?;
    let journal_path = rollback_journal_path()?;
    let previous = read_regular_file(&journal_path)?
        .map(|bytes| serde_json::from_slice::<RollbackJournal>(&bytes))
        .transpose()
        .context("invalid previous rollback journal")?;
    if let Some(journal) = &previous {
        validate_rollback_journal(journal)?;
    }
    if !yes {
        println!("planned changes:");
        for change in &plan {
            println!(
                "  {} -> {}",
                change.description,
                change.destination.display()
            );
        }
        for target in &targets {
            for mcp in &m.mcp {
                if mcp.targets.is_empty() || mcp.targets.iter().any(|value| value == target) {
                    println!(
                        "  {target} MCP command: {} {}",
                        mcp.command,
                        mcp.args.join(" ")
                    );
                }
            }
        }
        println!("apply {} change(s)? [y/N]", plan.len());
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("cancelled");
            return Ok(());
        }
    }
    let nonce = operation_nonce()?;
    let staged = prepare_staged_directories(&plan, &nonce)?;
    let journal = match snapshot_plan(&plan, &nonce) {
        Ok(journal) => journal,
        Err(error) => {
            cleanup_staged_directories(&staged);
            let _ = fs::remove_dir_all(root()?.join(".agentx/backups").join(&nonce));
            return Err(error);
        }
    };
    if let Err(error) = apply_install_plan(&plan, &staged, &nonce) {
        cleanup_staged_directories(&staged);
        let restore = restore_journal(&journal, &format!("failed-{nonce}"));
        return match restore {
            Ok(()) => {
                let _ = fs::remove_dir_all(&journal.backup_root);
                Err(error.context("installation failed; previous state restored"))
            }
            Err(restore_error) => Err(error.context(format!(
                "installation failed and automatic rollback also failed; recovery data remains at {}: {restore_error:#}",
                journal.backup_root.display()
            ))),
        };
    }
    cleanup_staged_directories(&staged);
    if let Err(error) = write_atomic(&journal_path, &serde_json::to_vec_pretty(&journal)?) {
        return match restore_journal(&journal, &format!("journal-failed-{nonce}")) {
            Ok(()) => {
                let _ = fs::remove_dir_all(&journal.backup_root);
                Err(error.context("could not save rollback journal; previous state restored"))
            }
            Err(restore_error) => Err(error.context(format!(
                "could not save rollback journal and automatic rollback failed; recovery data remains at {}: {restore_error:#}",
                journal.backup_root.display()
            ))),
        };
    }
    if let Some(previous) = previous {
        if previous.backup_root != journal.backup_root
            && previous
                .backup_root
                .starts_with(root()?.join(".agentx/backups"))
        {
            let _ = fs::remove_dir_all(previous.backup_root);
        }
    }
    for change in &plan {
        println!(
            "installed {} -> {}",
            change.description,
            change.destination.display()
        );
    }
    Ok(())
}
fn lock_manifest() -> Result<()> {
    let m = load_manifest()?;
    let (lock, _) = resolve_manifest(&m)?;
    fs::write(root()?.join("agentx.lock"), serde_yaml::to_string(&lock)?)?;
    println!("wrote agentx.lock");
    Ok(())
}
fn rollback() -> Result<()> {
    let path = rollback_journal_path()?;
    let bytes = read_regular_file(&path)?.context("no local installation to roll back")?;
    let journal: RollbackJournal =
        serde_json::from_slice(&bytes).context("invalid rollback journal")?;
    validate_rollback_journal(&journal)?;
    let restored = journal.entries.len();
    restore_journal(&journal, &format!("rollback-{}", operation_nonce()?))?;
    fs::remove_file(path)?;
    fs::remove_dir_all(&journal.backup_root)?;
    println!("restored {restored} managed path(s)");
    Ok(())
}

fn diff(target: Option<&str>) -> Result<()> {
    let m = load_manifest()?;
    let (expected_lock, sources) = resolve_manifest(&m)?;
    let targets: Vec<_> = match target {
        Some(value) => {
            validate_target(value)?;
            vec![value]
        }
        None => SUPPORTED_TARGETS.to_vec(),
    };
    for target in targets {
        let dest = target_root(target)?;
        for skill in &m.skills {
            if !skill.targets.is_empty() && !skill.targets.iter().any(|value| value == target) {
                continue;
            }
            let expected = sha256_dir(
                sources
                    .get(&skill.name)
                    .context("resolved skill source is missing")?,
            )?;
            let actual = dest.join(&skill.name);
            if !actual.exists() {
                println!("{target}: missing {}", skill.name);
            } else {
                let got = sha256_dir(&actual)?;
                println!(
                    "{target}: {} {}",
                    skill.name,
                    if got == expected { "ok" } else { "drift" }
                );
            }
        }
        println!(
            "{target}: rules {}",
            if planned_rule_change(&m, target)?.is_none() {
                "ok"
            } else {
                "drift"
            }
        );
        println!(
            "{target}: MCP {}",
            if planned_mcp_changes(&m, target)?.is_empty() {
                "ok"
            } else {
                "drift"
            }
        );
    }
    let lock_path = root()?.join("agentx.lock");
    let lock_ok = read_regular_file(&lock_path)?
        .and_then(|bytes| serde_yaml::from_slice::<Lock>(&bytes).ok())
        .is_some_and(|actual| actual == expected_lock);
    println!("lockfile: {}", if lock_ok { "ok" } else { "drift" });
    Ok(())
}
fn doctor() -> Result<()> {
    for target in SUPPORTED_TARGETS {
        let bin = target;
        let found = std::process::Command::new("sh")
            .args(["-lc", &format!("command -v {bin}")])
            .output()?
            .status
            .success();
        let configured = target_root(target)?
            .parent()
            .map(Path::exists)
            .unwrap_or(false);
        println!(
            "{target}: {}",
            if found || configured {
                "detected"
            } else {
                "not found"
            }
        );
        println!("  skills dir: {}", target_root(target)?.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::RemoteAction,
        infrastructure::{
            artifacts::validate_package_path,
            installer::{RollbackEntry, apply_agent_plan_to, rollback_agent_files_from},
            targets::RULES_START,
        },
    };
    use flate2::{Compression, GzBuilder};
    use std::fs;
    use tar::{Builder, Header};

    fn test_archive(path: &str, mode: u32, body: &[u8]) -> Vec<u8> {
        let encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::default());
        let mut archive = Builder::new(encoder);
        let mut skill = Header::new_gnu();
        skill.set_size(7);
        skill.set_mode(0o644);
        skill.set_cksum();
        archive
            .append_data(&mut skill, "SKILL.md", &b"# Demo\n"[..])
            .unwrap();
        let mut header = Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        archive.append_data(&mut header, path, body).unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn directory_hash_is_deterministic() {
        let dir = std::env::temp_dir().join(format!("agentx-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), "hello").unwrap();
        let first = sha256_dir(&dir).unwrap();
        let second = sha256_dir(&dir).unwrap();
        assert_eq!(first, second);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn directory_hash_frames_paths_and_contents() {
        let base = std::env::temp_dir().join(format!(
            "agentx-hash-framing-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = base.join("first");
        let second = base.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("a"), "bc").unwrap();
        fs::write(second.join("ab"), "c").unwrap();
        assert_ne!(sha256_dir(&first).unwrap(), sha256_dir(&second).unwrap());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn security_scan_rejects_large_files() {
        let dir = std::env::temp_dir().join(format!("agentx-large-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("large");
        fs::write(&file, vec![0_u8; 2_000_001]).unwrap();
        assert!(security_scan(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn skill_archive_is_deterministic_and_rejects_executables() {
        let dir = std::env::temp_dir().join(format!("agentx-archive-{}", std::process::id()));
        fs::create_dir_all(dir.join("references")).unwrap();
        fs::write(dir.join("SKILL.md"), "# Demo\n").unwrap();
        fs::write(dir.join("references/guide.md"), "guide\n").unwrap();
        let first = build_skill_archive(&dir).unwrap();
        let second = build_skill_archive(&dir).unwrap();
        assert_eq!(first, second);
        let files = read_skill_archive(&first).unwrap();
        assert_eq!(files[Path::new("SKILL.md")], b"# Demo\n");
        let executable = test_archive("run.sh", 0o755, b"exit 0");
        assert!(read_skill_archive(&executable).is_err());
        assert!(validate_package_path(Path::new("../secret")).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn agent_plan_installs_and_rolls_back_skill_directories() {
        let base = std::env::temp_dir().join(format!(
            "agentx-agent-plan-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let destination = base.join("target");
        let staging = base.join("staging");
        fs::create_dir_all(destination.join("demo")).unwrap();
        fs::create_dir_all(staging.join("demo")).unwrap();
        fs::write(destination.join("demo/SKILL.md"), "# Old\n").unwrap();
        fs::write(staging.join("demo/SKILL.md"), "# New\n").unwrap();
        let actions = vec![RemoteAction {
            package: "demo".into(),
            kind: "update".into(),
            to: "digest".into(),
        }];
        apply_agent_plan_to(&destination, &actions, &staging).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("demo/SKILL.md")).unwrap(),
            "# New\n"
        );
        rollback_agent_files_from(&destination, &["demo".into()]).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("demo/SKILL.md")).unwrap(),
            "# Old\n"
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn all_supported_targets_have_distinct_skill_roots() {
        let roots: Vec<_> = SUPPORTED_TARGETS
            .iter()
            .map(|target| target_root(target).unwrap())
            .collect();
        for (index, root) in roots.iter().enumerate() {
            assert!(
                root.ends_with("skills"),
                "unexpected root: {}",
                root.display()
            );
            assert!(
                roots.iter().skip(index + 1).all(|other| other != root),
                "duplicate root: {}",
                root.display()
            );
        }
    }

    #[test]
    fn json_mcp_adapter_preserves_existing_servers() {
        let existing = br#"{"mcpServers":{"existing":{"command":"keep"}},"other":true}"#;
        let mcp = Mcp {
            name: "docs".into(),
            command: "npx".into(),
            args: vec!["-y".into(), "docs-mcp".into()],
            targets: vec![],
        };
        let bytes = render_mcp_native("cursor", Some(existing), &BTreeSet::new(), &[&mcp]).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["other"], true);
        assert_eq!(value["mcpServers"]["existing"]["command"], "keep");
        assert_eq!(value["mcpServers"]["docs"]["command"], "npx");
    }

    #[test]
    fn managed_rules_preserve_user_text() {
        let first = render_managed_rules("# User\n", "# Team").unwrap();
        assert!(first.starts_with("# User\n\n"));
        let second = render_managed_rules(&first, "# Updated").unwrap();
        assert!(second.starts_with("# User\n\n"));
        assert!(second.contains("# Updated"));
        assert!(!second.contains("# Team"));
        let removed = render_managed_rules(&second, "").unwrap();
        assert!(removed.contains("# User"));
        assert!(!removed.contains(RULES_START));
    }

    #[test]
    fn failed_plan_can_restore_every_applied_change() {
        let base = std::env::temp_dir().join(format!(
            "agentx-plan-rollback-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let first = base.join("first.txt");
        let backup = base.join("backup.txt");
        fs::write(&first, "old").unwrap();
        fs::write(&backup, "old").unwrap();
        let blocker = base.join("blocker");
        fs::write(&blocker, "not a directory").unwrap();
        let plan = vec![
            PlannedChange {
                destination: first.clone(),
                content: PlannedContent::File(b"new".to_vec()),
                description: "first".into(),
            },
            PlannedChange {
                destination: blocker.join("second.txt"),
                content: PlannedContent::File(b"never written".to_vec()),
                description: "second".into(),
            },
        ];
        let journal = RollbackJournal {
            version: 1,
            backup_root: base.clone(),
            entries: vec![RollbackEntry {
                destination: first.clone(),
                backup: Some(backup),
                directory: false,
            }],
        };
        assert!(apply_install_plan(&plan, &[], "test").is_err());
        assert_eq!(fs::read_to_string(&first).unwrap(), "new");
        restore_journal(&journal, "test-restore").unwrap();
        assert_eq!(fs::read_to_string(&first).unwrap(), "old");
        fs::remove_dir_all(base).unwrap();
    }
}
