use crate::{
    domain::{Mcp, SUPPORTED_TARGETS},
    infrastructure::filesystem::{home, root},
};
use anyhow::{Context, Result, bail};
use std::{collections::BTreeSet, path::PathBuf};

pub(crate) const RULES_START: &str = "<!-- agentx:rules:start -->";
const RULES_END: &str = "<!-- agentx:rules:end -->";

pub(crate) fn target_root(target: &str) -> Result<PathBuf> {
    let home = home()?;
    match target {
        "codex" => Ok(home.join(".codex/skills")),
        "claude" => Ok(home.join(".claude/skills")),
        "cursor" => Ok(root()?.join(".cursor/skills")),
        "windsurf" => Ok(root()?.join(".windsurf/skills")),
        "gemini" => Ok(root()?.join(".gemini/skills")),
        "copilot" => Ok(root()?.join(".github/skills")),
        "cline" => Ok(root()?.join(".cline/skills")),
        "grok" => Ok(root()?.join(".grok/skills")),
        _ => bail!(
            "unsupported target {target}; use {}",
            SUPPORTED_TARGETS.join(", ")
        ),
    }
}

pub(crate) fn rule_destination(target: &str) -> Result<(PathBuf, bool)> {
    let project = root()?;
    match target {
        "codex" => Ok((project.join("AGENTS.md"), true)),
        "claude" => Ok((project.join("CLAUDE.md"), true)),
        "cursor" => Ok((project.join(".cursor/rules/agentx.mdc"), false)),
        "windsurf" => Ok((project.join(".windsurf/rules/agentx.md"), false)),
        "gemini" => Ok((project.join("GEMINI.md"), true)),
        "copilot" => Ok((project.join(".github/copilot-instructions.md"), true)),
        "cline" => Ok((project.join(".clinerules/agentx.md"), false)),
        "grok" => Ok((project.join(".grok/rules/agentx.md"), false)),
        _ => bail!("unsupported target {target}"),
    }
}

pub(crate) fn render_managed_rules(existing: &str, rules: &str) -> Result<String> {
    let starts: Vec<_> = existing.match_indices(RULES_START).collect();
    let ends: Vec<_> = existing.match_indices(RULES_END).collect();
    if starts.len() > 1 || ends.len() > 1 || starts.len() != ends.len() {
        bail!("managed rules markers are malformed");
    }
    let block = if rules.is_empty() {
        String::new()
    } else {
        format!("{RULES_START}\n{}\n{RULES_END}", rules.trim_end())
    };
    if let (Some((start, _)), Some((end, _))) = (starts.first(), ends.first()) {
        if start > end {
            bail!("managed rules markers are out of order");
        }
        let after = end + RULES_END.len();
        return Ok(format!(
            "{}{}{}",
            &existing[..*start],
            block,
            &existing[after..]
        ));
    }
    if block.is_empty() {
        return Ok(existing.to_string());
    }
    let separator = if existing.is_empty() || existing.ends_with("\n\n") {
        ""
    } else if existing.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    Ok(format!("{existing}{separator}{block}\n"))
}

pub(crate) fn mcp_summary_path(target: &str) -> Result<PathBuf> {
    Ok(target_root(target)?
        .parent()
        .context("invalid target path")?
        .join("agentx-mcp.json"))
}

pub(crate) fn native_mcp_path(target: &str) -> Result<PathBuf> {
    let project = root()?;
    let home = home()?;
    match target {
        "codex" => Ok(home.join(".codex/config.toml")),
        "claude" => Ok(home.join(".claude.json")),
        "cursor" => Ok(project.join(".cursor/mcp.json")),
        "windsurf" => Ok(home.join(".codeium/windsurf/mcp_config.json")),
        "gemini" => Ok(project.join(".gemini/settings.json")),
        "copilot" => Ok(home.join(".copilot/mcp-config.json")),
        "cline" => Ok(home.join(".cline/mcp.json")),
        "grok" => Ok(project.join(".grok/config.toml")),
        _ => bail!("unsupported target {target}"),
    }
}

pub(crate) fn render_mcp_native(
    target: &str,
    existing: Option<&[u8]>,
    previous: &BTreeSet<String>,
    selected: &[&Mcp],
) -> Result<Vec<u8>> {
    if matches!(target, "codex" | "grok") {
        let mut document = match existing {
            Some(bytes) => toml::from_str::<toml::Value>(std::str::from_utf8(bytes)?)?,
            None => toml::Value::Table(toml::map::Map::new()),
        };
        let root = document
            .as_table_mut()
            .context("MCP config must be a TOML table")?;
        let servers = root
            .entry("mcp_servers")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .context("mcp_servers must be a TOML table")?;
        for name in previous {
            servers.remove(name);
        }
        for mcp in selected {
            let mut entry = toml::map::Map::new();
            entry.insert("command".into(), toml::Value::String(mcp.command.clone()));
            entry.insert(
                "args".into(),
                toml::Value::Array(mcp.args.iter().cloned().map(toml::Value::String).collect()),
            );
            servers.insert(mcp.name.clone(), toml::Value::Table(entry));
        }
        return Ok(toml::to_string_pretty(&document)?.into_bytes());
    }
    let mut document = match existing {
        Some(bytes) => serde_json::from_slice::<serde_json::Value>(bytes)?,
        None => serde_json::json!({}),
    };
    let servers = document
        .as_object_mut()
        .context("MCP config must be a JSON object")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context("MCP server collection must be a JSON object")?;
    for name in previous {
        servers.remove(name);
    }
    for mcp in selected {
        servers.insert(
            mcp.name.clone(),
            serde_json::json!({"command": mcp.command, "args": mcp.args}),
        );
    }
    Ok(serde_json::to_vec_pretty(&document)?)
}
