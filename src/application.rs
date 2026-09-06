use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
use reqwest::blocking::{Client, multipart};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "agentx", about = "Reproducible AI agent environments")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Init,
    Install {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        frozen: bool,
    },
    Diff,
    Doctor,
    Lock,
    Rollback,
    Registry {
        #[command(subcommand)]
        command: RegistryCommands,
    },
    Team {
        #[command(subcommand)]
        command: TeamCommands,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
}
#[derive(Subcommand)]
enum RegistryCommands {
    Login {
        url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        workspace: Option<String>,
    },
    Publish {
        name: String,
        version: String,
        file: PathBuf,
        #[arg(long)]
        signature: Option<String>,
    },
    Pull {
        name: String,
        version: String,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum TeamCommands {
    Pull {
        #[arg(long, default_value = "agentx.yaml")]
        output: PathBuf,
    },
    Push {
        #[arg(long, default_value = "agentx.yaml")]
        input: PathBuf,
    },
}
#[derive(Subcommand)]
enum AgentCommands {
    Plan {
        #[arg(long)]
        device: String,
    },
    Sync {
        #[arg(long)]
        device: String,
    },
    Rollback {
        #[arg(long)]
        device: String,
    },
}
#[derive(Debug, Serialize, Deserialize, Default)]
struct RegistryCredentials {
    url: String,
    token: String,
    #[serde(default)]
    workspace_id: Option<String>,
}
#[derive(Debug, Deserialize)]
struct RemoteRelease {
    name: String,
    version: String,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RemoteReleasePage {
    Legacy(Vec<RemoteRelease>),
    Paged {
        items: Vec<RemoteRelease>,
        #[serde(default)]
        next_cursor: Option<String>,
    },
}
#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    version: u32,
    #[serde(default)]
    skills: Vec<Skill>,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    mcp: Vec<Mcp>,
}
#[derive(Debug, Deserialize, Serialize)]
struct Skill {
    name: String,
    source: Source,
    #[serde(default)]
    targets: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
struct Rule {
    source: String,
    #[serde(default)]
    targets: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
struct Mcp {
    name: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    targets: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum Source {
    #[serde(rename = "local")]
    Local { path: String },
    #[serde(rename = "git")]
    Git {
        url: String,
        #[serde(default)]
        r#ref: Option<String>,
    },
}
#[derive(Debug, Serialize, Deserialize)]
struct Lock {
    version: u32,
    packages: Vec<LockedPackage>,
}
#[derive(Debug, Serialize, Deserialize)]
struct LockedPackage {
    name: String,
    source: String,
    sha256: String,
}

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => init(),
        Commands::Install {
            target,
            yes,
            frozen,
        } => install(target.as_deref(), yes, frozen),
        Commands::Diff => diff(),
        Commands::Doctor => doctor(),
        Commands::Lock => lock_manifest(),
        Commands::Rollback => rollback(),
        Commands::Registry { command } => registry(command),
        Commands::Team { command } => team(command),
        Commands::Agent { command } => agent(command),
    }
}

#[derive(Debug, Deserialize)]
struct RemotePlan {
    actions: Vec<RemoteAction>,
    manifest_revision: i64,
}
#[derive(Debug, Deserialize)]
struct RemoteAction {
    package: String,
    kind: String,
    #[serde(default)]
    to: String,
}
#[derive(Debug, Serialize, Deserialize, Default)]
struct AgentState {
    manifest_revision: i64,
    installed_packages: std::collections::BTreeMap<String, String>,
}

fn agent(command: AgentCommands) -> Result<()> {
    let credentials = read_credentials()?;
    credentials
        .workspace_id
        .as_deref()
        .context("registry credentials require --workspace for agent commands")?;
    let device = match &command {
        AgentCommands::Plan { device }
        | AgentCommands::Sync { device }
        | AgentCommands::Rollback { device } => device,
    };
    let state_dir = root()?.join(".agentx/devices").join(device);
    fs::create_dir_all(&state_dir)?;
    let state_path = state_dir.join("state.json");
    let backup_path = state_dir.join("previous.json");
    let client = Client::new();
    match command {
        AgentCommands::Plan { .. } => {
            let response = client
                .get(format!(
                    "{}{}/devices/{}/plan",
                    credentials.url,
                    workspace_prefix(&credentials),
                    device
                ))
                .bearer_auth(&credentials.token)
                .send()?;
            if !response.status().is_success() {
                bail!("reconcile plan failed ({})", response.status());
            }
            let plan: RemotePlan = response.json().context("invalid reconcile plan")?;
            println!("manifest revision {}", plan.manifest_revision);
            for action in plan.actions {
                println!("{} {} {}", action.kind, action.package, action.to);
            }
        }
        AgentCommands::Sync { .. } => {
            let response = client
                .get(format!(
                    "{}{}/devices/{}/plan",
                    credentials.url,
                    workspace_prefix(&credentials),
                    device
                ))
                .bearer_auth(&credentials.token)
                .send()?;
            if !response.status().is_success() {
                bail!("reconcile plan failed ({})", response.status());
            }
            let plan: RemotePlan = response.json().context("invalid reconcile plan")?;
            let old: AgentState = fs::read_to_string(&state_path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_default();
            fs::write(&backup_path, serde_json::to_vec_pretty(&old)?)?;
            let mut installed = old.installed_packages;
            for action in &plan.actions {
                match action.kind.as_str() {
                    "remove" => {
                        installed.remove(&action.package);
                    }
                    "install" | "update" => {
                        let artifact = client
                            .get(format!(
                                "{}{}/artifacts/{}",
                                credentials.url,
                                workspace_prefix(&credentials),
                                action.to
                            ))
                            .bearer_auth(&credentials.token)
                            .send()?;
                        if !artifact.status().is_success() {
                            bail!(
                                "artifact download failed for {} ({})",
                                action.package,
                                artifact.status()
                            );
                        }
                        let bytes = artifact.bytes()?;
                        let actual = format!("{:x}", Sha256::digest(&bytes));
                        if actual != action.to {
                            bail!(
                                "artifact hash mismatch for {}: expected {}, got {}",
                                action.package,
                                action.to,
                                actual
                            );
                        }
                        let cache = state_dir.join("artifacts");
                        fs::create_dir_all(&cache)?;
                        fs::write(cache.join(&action.to), &bytes)?;
                        installed.insert(action.package.clone(), action.to.clone());
                    }
                    _ => bail!("unsupported reconcile action {}", action.kind),
                }
            }
            let new_state = AgentState {
                manifest_revision: plan.manifest_revision,
                installed_packages: installed.clone(),
            };
            fs::write(&state_path, serde_json::to_vec_pretty(&new_state)?)?;
            heartbeat(&client, &credentials, device, &installed)?;
            println!(
                "synced device {} to manifest revision {}",
                device, plan.manifest_revision
            );
        }
        AgentCommands::Rollback { .. } => {
            let previous: AgentState = serde_json::from_str(
                &fs::read_to_string(&backup_path)
                    .context("no previous agent state to roll back")?,
            )?;
            fs::write(&state_path, serde_json::to_vec_pretty(&previous)?)?;
            heartbeat(&client, &credentials, device, &previous.installed_packages)?;
            println!(
                "rolled back device {} to manifest revision {}",
                device, previous.manifest_revision
            );
        }
    }
    Ok(())
}

fn heartbeat(
    client: &Client,
    credentials: &RegistryCredentials,
    device: &str,
    installed: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let response = client
        .post(format!(
            "{}{}/devices/{}/heartbeat",
            credentials.url,
            workspace_prefix(credentials),
            device
        ))
        .bearer_auth(&credentials.token)
        .json(&serde_json::json!({"agent":"agentx","installed_packages":installed}))
        .send()?;
    if !response.status().is_success() {
        bail!("heartbeat failed ({})", response.status());
    }
    Ok(())
}
fn team(command: TeamCommands) -> Result<()> {
    let credentials = read_credentials()?;
    let client = Client::new();
    let workspace = credentials
        .workspace_id
        .as_deref()
        .context("registry credentials require --workspace for team commands")?;
    match command {
        TeamCommands::Pull { output } => {
            let response = client
                .get(format!(
                    "{}/v1/workspaces/{}/manifest",
                    credentials.url, workspace
                ))
                .bearer_auth(&credentials.token)
                .send()?;
            if !response.status().is_success() {
                bail!("team manifest pull failed ({})", response.status())
            }
            let body: serde_json::Value = response.json()?;
            let document = body.get("document").cloned().unwrap_or(body);
            let raw = serde_yaml::to_string(&document).context("manifest is not serializable")?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, raw)?;
            println!("pulled team manifest -> {}", output.display());
            Ok(())
        }
        TeamCommands::Push { input } => {
            let raw = fs::read_to_string(&input)
                .with_context(|| format!("cannot read {}", input.display()))?;
            let document: serde_json::Value =
                serde_yaml::from_str(&raw).context("invalid team manifest YAML")?;
            let response = client
                .put(format!(
                    "{}/v1/workspaces/{}/manifest",
                    credentials.url, workspace
                ))
                .bearer_auth(&credentials.token)
                .json(&serde_json::json!({"document": document}))
                .send()?;
            if !response.status().is_success() {
                bail!("team manifest push failed ({})", response.status())
            }
            let revision = response
                .json::<serde_json::Value>()?
                .get("revision")
                .and_then(|value| value.as_i64())
                .unwrap_or_default();
            println!("pushed team manifest revision {}", revision);
            Ok(())
        }
    }
}
fn credentials_path() -> Result<PathBuf> {
    let dirs = BaseDirs::new().context("cannot find home directory")?;
    Ok(dirs.config_dir().join("agentx/credentials.json"))
}
fn read_credentials() -> Result<RegistryCredentials> {
    let p = credentials_path()?;
    let raw = fs::read_to_string(&p).with_context(|| {
        format!(
            "not logged in; run `agentx registry login <url> --token <token>` ({})",
            p.display()
        )
    })?;
    Ok(serde_json::from_str(&raw)?)
}
fn registry(command: RegistryCommands) -> Result<()> {
    match command {
        RegistryCommands::Login {
            url,
            token,
            workspace,
        } => {
            let p = credentials_path()?;
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?
            };
            let c = RegistryCredentials {
                url: url.trim_end_matches('/').to_string(),
                token,
                workspace_id: workspace,
            };
            fs::write(&p, serde_json::to_vec_pretty(&c)?)?;
            println!("saved Registry credentials to {}", p.display());
            Ok(())
        }
        RegistryCommands::Publish {
            name,
            version,
            file,
            signature,
        } => {
            let c = read_credentials()?;
            let bytes =
                fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let mut form = multipart::Form::new()
                .text("version", version.clone())
                .part(
                    "artifact",
                    multipart::Part::bytes(bytes).file_name(
                        file.file_name()
                            .and_then(|x| x.to_str())
                            .unwrap_or("artifact")
                            .to_string(),
                    ),
                );
            if let Some(sig) = signature {
                form = form.text("signature", sig)
            };
            let response = Client::new()
                .post(format!(
                    "{}{}/packages/{}/releases",
                    c.url,
                    workspace_prefix(&c),
                    name
                ))
                .bearer_auth(c.token)
                .header(
                    "Idempotency-Key",
                    format!("{}@{}:{}", name, version, digest),
                )
                .multipart(form)
                .send()?;
            if !response.status().is_success() {
                bail!(
                    "publish failed ({}): {}",
                    response.status(),
                    response.text().unwrap_or_default()
                )
            };
            let release: RemoteRelease = response.json().context("invalid publish response")?;
            if release.name != name || release.version != version || release.sha256 != digest {
                bail!(
                    "publish response mismatch: expected {}@{} {}, got {}@{} {}",
                    name,
                    version,
                    digest,
                    release.name,
                    release.version,
                    release.sha256
                )
            }
            println!("published {}@{} (sha256 {})", name, version, digest);
            Ok(())
        }
        RegistryCommands::Pull {
            name,
            version,
            output,
        } => {
            let c = read_credentials()?;
            let releases = list_remote_releases(&c)?;
            let release = releases
                .into_iter()
                .find(|r| r.name == name && r.version == version)
                .context("release not found")?;
            let body = Client::new()
                .get(format!(
                    "{}{}/artifacts/{}",
                    c.url,
                    workspace_prefix(&c),
                    release.sha256
                ))
                .bearer_auth(c.token)
                .send()?;
            if !body.status().is_success() {
                bail!("artifact download failed ({})", body.status())
            };
            let bytes = body.bytes()?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if actual != release.sha256 {
                bail!(
                    "artifact hash mismatch: expected {}, got {}",
                    release.sha256,
                    actual
                )
            };
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?
            };
            fs::write(&output, &bytes)?;
            println!("downloaded {}@{} -> {}", name, version, output.display());
            Ok(())
        }
    }
}
fn list_remote_releases(credentials: &RegistryCredentials) -> Result<Vec<RemoteRelease>> {
    let client = Client::new();
    let mut cursor: Option<String> = None;
    let mut releases = Vec::new();
    loop {
        let mut url = format!(
            "{}{}/packages?limit=200",
            credentials.url,
            workspace_prefix(credentials)
        );
        if let Some(value) = &cursor {
            url.push_str("&cursor=");
            url.push_str(value);
        }
        let response = client.get(url).bearer_auth(&credentials.token).send()?;
        if !response.status().is_success() {
            bail!("package listing failed ({})", response.status())
        }
        match response.json::<RemoteReleasePage>()? {
            RemoteReleasePage::Legacy(items) => {
                releases.extend(items);
                break;
            }
            RemoteReleasePage::Paged { items, next_cursor } => {
                releases.extend(items);
                match next_cursor {
                    Some(value) if !value.is_empty() => cursor = Some(value),
                    _ => break,
                }
            }
        }
    }
    Ok(releases)
}
fn workspace_prefix(credentials: &RegistryCredentials) -> String {
    credentials
        .workspace_id
        .as_deref()
        .map(|id| format!("/v1/workspaces/{}", id))
        .unwrap_or_else(|| "/v1".to_string())
}
fn root() -> Result<PathBuf> {
    std::env::current_dir().context("cannot determine current directory")
}
fn load_manifest() -> Result<Manifest> {
    let path = root()?.join("agentx.yaml");
    let raw =
        fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
    let m: Manifest = serde_yaml::from_str(&raw).context("invalid agentx.yaml")?;
    if m.version != 1 {
        bail!("unsupported manifest version {}", m.version);
    }
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
fn source_path(source: &Source) -> Result<PathBuf> {
    match source {
        Source::Local { path } => {
            let p = root()?.join(path);
            if !p.is_dir() {
                bail!("skill source is not a directory: {}", p.display());
            }
            Ok(p)
        }
        Source::Git { url, r#ref } => {
            if let Some(reference) = r#ref {
                let mut key = Sha256::new();
                key.update(url.as_bytes());
                key.update([0]);
                key.update(reference.as_bytes());
                let cache = root()?
                    .join(".agentx/cache/git")
                    .join(format!("{:x}", key.finalize()));
                if cache.is_dir() {
                    return Ok(cache);
                }
                let parent = cache.parent().context("invalid git cache path")?;
                fs::create_dir_all(parent)?;
                let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
                let temp = parent.join(format!("clone-{stamp}"));
                let mut cmd = Command::new("git");
                cmd.args(["clone", "--depth", "1", "--branch", reference]);
                cmd.args([url, temp.to_str().context("invalid temp path")?]);
                let status = cmd.status().context("git is required for git sources")?;
                if !status.success() {
                    let _ = fs::remove_dir_all(&temp);
                    bail!("failed to clone skill source {url}");
                }
                fs::rename(&temp, &cache)?;
                return Ok(cache);
            }
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let p = std::env::temp_dir().join(format!("agentx-{stamp}"));
            let mut cmd = Command::new("git");
            cmd.args(["clone", "--depth", "1"]);
            if let Some(reference) = r#ref {
                cmd.args(["--branch", reference]);
            }
            cmd.args([url, p.to_str().context("invalid temp path")?]);
            let status = cmd.status().context("git is required for git sources")?;
            if !status.success() {
                bail!("failed to clone skill source {url}");
            }
            Ok(p)
        }
    }
}
fn sha256_dir(path: &Path) -> Result<String> {
    let mut files = Vec::new();
    for entry in WalkDir::new(path).follow_links(false) {
        let e = entry?;
        if e.file_type().is_file() {
            files.push(e.path().to_path_buf());
        }
    }
    files.sort();
    let mut h = Sha256::new();
    for file in files {
        h.update(file.strip_prefix(path)?.to_string_lossy().as_bytes());
        h.update(fs::read(file)?);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn target_root(target: &str) -> Result<PathBuf> {
    let dirs = BaseDirs::new().context("cannot find home directory")?;
    let home = dirs.home_dir();
    match target {
        "codex" => Ok(home.join(".codex/skills")),
        "claude" => Ok(home.join(".claude/skills")),
        _ => bail!("unsupported target {target}; use codex or claude"),
    }
}
fn install(target: Option<&str>, yes: bool, frozen: bool) -> Result<()> {
    let m = load_manifest()?;
    let targets = target
        .map(|x| vec![x.to_string()])
        .unwrap_or_else(|| vec!["codex".into(), "claude".into()]);
    let mut lock = Lock {
        version: 1,
        packages: Vec::new(),
    };
    for skill in &m.skills {
        let source = source_path(&skill.source)?;
        let source_text = match &skill.source {
            Source::Local { path } => path.clone(),
            Source::Git { url, .. } => url.clone(),
        };
        lock.packages.push(LockedPackage {
            name: skill.name.clone(),
            source: source_text,
            sha256: sha256_dir(&source)?,
        });
    }
    let lock_path = root()?.join("agentx.lock");
    if frozen && lock_path.exists() {
        let existing: Lock = serde_yaml::from_str(&fs::read_to_string(&lock_path)?)?;
        if existing.packages.len() != lock.packages.len()
            || existing
                .packages
                .iter()
                .zip(&lock.packages)
                .any(|(a, b)| a.name != b.name || a.sha256 != b.sha256)
        {
            bail!("lockfile does not match sources; run `agentx lock` first");
        }
        lock = existing;
    } else if frozen {
        bail!("agentx.lock is required with --frozen");
    }
    if !yes {
        println!(
            "install {} skill(s) for {}? [y/N]",
            m.skills.len(),
            targets.join(", ")
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("cancelled");
            return Ok(());
        }
    }
    for t in &targets {
        let dest = target_root(t)?;
        fs::create_dir_all(&dest)?;
        for skill in &m.skills {
            if !skill.targets.is_empty() && !skill.targets.iter().any(|x| x == t) {
                continue;
            }
            let src = source_path(&skill.source)?;
            let out = dest.join(&skill.name);
            if out.exists() {
                let backup = out.with_extension("agentx-backup");
                if backup.exists() {
                    fs::remove_dir_all(&backup)?;
                }
                fs::rename(&out, &backup)?;
            }
            copy_dir(&src, &out)?;
            security_scan(&out)?;
            println!("installed {} -> {}", skill.name, out.display());
        }
        install_rules(&m, t)?;
        install_mcp(&m, t)?;
        for mcp in &m.mcp {
            if mcp.targets.is_empty() || mcp.targets.iter().any(|x| x == t) {
                println!("MCP declared: {} ({})", mcp.name, mcp.command);
            }
        }
    }
    fs::write(lock_path, serde_yaml::to_string(&lock)?)?;
    Ok(())
}
fn lock_manifest() -> Result<()> {
    let m = load_manifest()?;
    let mut packages = Vec::new();
    for skill in &m.skills {
        let path = source_path(&skill.source)?;
        let source = match &skill.source {
            Source::Local { path } => path.clone(),
            Source::Git { url, .. } => url.clone(),
        };
        packages.push(LockedPackage {
            name: skill.name.clone(),
            source,
            sha256: sha256_dir(&path)?,
        });
    }
    fs::write(
        root()?.join("agentx.lock"),
        serde_yaml::to_string(&Lock {
            version: 1,
            packages,
        })?,
    )?;
    println!("wrote agentx.lock");
    Ok(())
}
fn install_mcp(m: &Manifest, target: &str) -> Result<()> {
    let selected: Vec<_> = m
        .mcp
        .iter()
        .filter(|x| x.targets.is_empty() || x.targets.iter().any(|t| t == target))
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let config = target_root(target)?
        .parent()
        .context("invalid target path")?
        .join("agentx-mcp.json");
    let entries: Vec<_> = selected
        .iter()
        .map(|m| serde_json::json!({"name": m.name, "command": m.command, "args": m.args}))
        .collect();
    write_atomic(&config, serde_json::to_vec_pretty(&entries)?.as_slice())?;
    match target {
        "codex" => install_codex_mcp(&selected)?,
        "claude" => install_claude_mcp(&selected)?,
        _ => {}
    }
    Ok(())
}

fn install_codex_mcp(selected: &[&Mcp]) -> Result<()> {
    let dirs = BaseDirs::new().context("cannot find home directory")?;
    let path = dirs.home_dir().join(".codex/config.toml");
    let mut document = if path.exists() {
        toml::from_str::<toml::Value>(&fs::read_to_string(&path)?)?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let root = document
        .as_table_mut()
        .context("Codex config must be a TOML table")?;
    let servers = root
        .entry("mcp_servers")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .context("Codex mcp_servers must be a TOML table")?;
    for mcp in selected {
        let mut entry = toml::map::Map::new();
        entry.insert("command".into(), toml::Value::String(mcp.command.clone()));
        entry.insert(
            "args".into(),
            toml::Value::Array(mcp.args.iter().cloned().map(toml::Value::String).collect()),
        );
        servers.insert(mcp.name.clone(), toml::Value::Table(entry));
    }
    write_atomic(&path, toml::to_string_pretty(&document)?.as_bytes())
}

fn install_claude_mcp(selected: &[&Mcp]) -> Result<()> {
    let dirs = BaseDirs::new().context("cannot find home directory")?;
    let path = dirs.home_dir().join(".claude.json");
    let mut document = if path.exists() {
        serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path)?)?
    } else {
        serde_json::json!({})
    };
    let root = document
        .as_object_mut()
        .context("Claude config must be a JSON object")?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context("Claude mcpServers must be a JSON object")?;
    for mcp in selected {
        servers.insert(
            mcp.name.clone(),
            serde_json::json!({"command": mcp.command, "args": mcp.args}),
        );
    }
    write_atomic(&path, serde_json::to_vec_pretty(&document)?.as_slice())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("agentx-tmp");
    fs::write(&temp, bytes)?;
    fs::rename(temp, path)?;
    Ok(())
}
fn rollback() -> Result<()> {
    let mut restored = 0;
    for target in ["codex", "claude"] {
        let root = target_root(target)?;
        if !root.exists() {
            continue;
        }
        for entry in fs::read_dir(&root)? {
            let path = entry?.path();
            if path.extension().and_then(|x| x.to_str()) == Some("agentx-backup") {
                let original = path.with_extension("");
                if original.exists() {
                    fs::remove_dir_all(&original)?;
                }
                fs::rename(path, original)?;
                restored += 1;
            }
        }
    }
    println!("restored {restored} backup(s)");
    Ok(())
}
fn install_rules(m: &Manifest, target: &str) -> Result<()> {
    let mut text = String::new();
    for rule in &m.rules {
        if rule.targets.is_empty() || rule.targets.iter().any(|x| x == target) {
            let p = root()?.join(&rule.source);
            text.push_str(&fs::read_to_string(p)?);
            text.push_str("\n\n");
        }
    }
    if text.is_empty() {
        return Ok(());
    }
    let filename = if target == "codex" {
        "AGENTS.md"
    } else {
        "CLAUDE.md"
    };
    fs::write(root()?.join(filename), text)?;
    Ok(())
}
fn security_scan(path: &Path) -> Result<()> {
    for entry in WalkDir::new(path).follow_links(false) {
        let e = entry?;
        if e.file_type().is_symlink() {
            bail!(
                "symlink is not allowed in skill package: {}",
                e.path().display()
            );
        }
        if e.file_type().is_file() && e.metadata()?.len() > 2_000_000 {
            bail!("skill file exceeds 2MB: {}", e.path().display());
        }
    }
    Ok(())
}
fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in WalkDir::new(src).follow_links(false) {
        let e = entry?;
        let rel = e.path().strip_prefix(src)?;
        let out = dst.join(rel);
        if e.file_type().is_dir() {
            fs::create_dir_all(&out)?;
        } else if e.file_type().is_file() {
            fs::copy(e.path(), &out)?;
        }
    }
    Ok(())
}
fn diff() -> Result<()> {
    let m = load_manifest()?;
    for target in ["codex", "claude"] {
        let dest = target_root(target)?;
        for skill in &m.skills {
            let expected = sha256_dir(&source_path(&skill.source)?)?;
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
    }
    Ok(())
}
fn doctor() -> Result<()> {
    for target in ["codex", "claude"] {
        let bin = target;
        let found = std::process::Command::new("sh")
            .args(["-lc", &format!("command -v {bin}")])
            .output()?
            .status
            .success();
        println!("{target}: {}", if found { "detected" } else { "not found" });
        println!("  skills dir: {}", target_root(target)?.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
    fn security_scan_rejects_large_files() {
        let dir = std::env::temp_dir().join(format!("agentx-large-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("large");
        fs::write(&file, vec![0_u8; 2_000_001]).unwrap();
        assert!(security_scan(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
