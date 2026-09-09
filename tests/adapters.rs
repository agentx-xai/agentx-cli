use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("agentx-{label}-{stamp}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn install(project: &Path, home: &Path, target: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .args(["install", "--target", target, "--yes"])
        .current_dir(project)
        .env("HOME", home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "target {target} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn install_compiles_all_supported_target_formats() {
    let project = temp_dir("adapter-project");
    let home = temp_dir("adapter-home");
    fs::create_dir_all(project.join("skills/demo")).unwrap();
    fs::create_dir_all(project.join("rules")).unwrap();
    fs::create_dir_all(project.join(".grok")).unwrap();
    fs::write(
        project.join(".grok/config.toml"),
        "[ui]\ntheme = \"dark\"\n",
    )
    .unwrap();
    fs::write(project.join("skills/demo/SKILL.md"), "# Demo\n").unwrap();
    fs::write(project.join("rules/team.md"), "# Team rules\n").unwrap();
    fs::write(
        project.join("agentx.yaml"),
        "version: 1\nskills:\n  - name: demo\n    source: { type: local, path: skills/demo }\nrules:\n  - source: rules/team.md\nmcp:\n  - name: docs\n    command: npx\n    args: [\"-y\", \"docs-mcp\"]\n",
    )
    .unwrap();

    for target in [
        "codex", "claude", "cursor", "windsurf", "gemini", "copilot", "cline", "grok",
    ] {
        install(&project, &home, target);
    }

    let expected = [
        project.join("AGENTS.md"),
        project.join("CLAUDE.md"),
        project.join(".cursor/rules/agentx.mdc"),
        project.join(".windsurf/rules/agentx.md"),
        project.join("GEMINI.md"),
        project.join(".github/copilot-instructions.md"),
        project.join(".clinerules/agentx.md"),
        project.join(".grok/rules/agentx.md"),
    ];
    for path in expected {
        assert!(
            path.is_file(),
            "missing generated rules: {}",
            path.display()
        );
    }

    for path in [
        home.join(".codex/skills/demo/SKILL.md"),
        home.join(".claude/skills/demo/SKILL.md"),
        project.join(".cursor/skills/demo/SKILL.md"),
        project.join(".windsurf/skills/demo/SKILL.md"),
        project.join(".gemini/skills/demo/SKILL.md"),
        project.join(".github/skills/demo/SKILL.md"),
        project.join(".cline/skills/demo/SKILL.md"),
        project.join(".grok/skills/demo/SKILL.md"),
    ] {
        assert!(
            path.is_file(),
            "missing generated skill: {}",
            path.display()
        );
    }

    for path in [
        home.join(".codex/config.toml"),
        home.join(".claude.json"),
        project.join(".cursor/mcp.json"),
        home.join(".codeium/windsurf/mcp_config.json"),
        project.join(".gemini/settings.json"),
        home.join(".copilot/mcp-config.json"),
        home.join(".cline/mcp.json"),
        project.join(".grok/config.toml"),
    ] {
        assert!(
            path.is_file(),
            "missing generated MCP config: {}",
            path.display()
        );
    }

    let grok_rules = fs::read_to_string(project.join(".grok/rules/agentx.md")).unwrap();
    assert!(grok_rules.contains("# Team rules"));
    let grok_config: toml::Value =
        toml::from_str(&fs::read_to_string(project.join(".grok/config.toml")).unwrap()).unwrap();
    assert_eq!(grok_config["ui"]["theme"].as_str(), Some("dark"));
    assert_eq!(
        grok_config["mcp_servers"]["docs"]["command"].as_str(),
        Some("npx")
    );
    assert_eq!(
        grok_config["mcp_servers"]["docs"]["args"][0].as_str(),
        Some("-y")
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn install_rejects_unsafe_names_and_escaping_sources_before_mutation() {
    let project = temp_dir("unsafe-project");
    let home = temp_dir("unsafe-home");
    let outside = temp_dir("unsafe-outside");
    fs::write(outside.join("SKILL.md"), "# Outside\n").unwrap();
    fs::write(
        project.join("agentx.yaml"),
        format!(
            "version: 1\nskills:\n  - name: ../escape\n    source: {{ type: local, path: {} }}\n",
            outside.display()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .args(["install", "--target", "codex", "--yes"])
        .current_dir(&project)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!home.join(".codex/skills").exists());

    fs::write(
        project.join("agentx.yaml"),
        "version: 1\nskills:\n  - name: demo\n    source: { type: local, path: ../unsafe-outside }\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .args(["install", "--target", "codex", "--yes"])
        .current_dir(&project)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!home.join(".codex/skills").exists());

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[test]
fn rollback_restores_skills_rules_mcp_and_lockfile() {
    let project = temp_dir("rollback-project");
    let home = temp_dir("rollback-home");
    for name in ["foo.bar", "foo.baz"] {
        fs::create_dir_all(project.join("skills").join(name)).unwrap();
        fs::write(
            project.join("skills").join(name).join("SKILL.md"),
            format!("# New {name}\n"),
        )
        .unwrap();
        fs::create_dir_all(home.join(".codex/skills").join(name)).unwrap();
        fs::write(
            home.join(".codex/skills").join(name).join("SKILL.md"),
            format!("# Old {name}\n"),
        )
        .unwrap();
    }
    fs::create_dir_all(project.join("rules")).unwrap();
    fs::write(project.join("rules/team.md"), "# Team rules\n").unwrap();
    fs::write(project.join("AGENTS.md"), "# User rules\n").unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::write(
        home.join(".codex/config.toml"),
        "[mcp_servers.existing]\ncommand = \"keep\"\n",
    )
    .unwrap();
    fs::write(project.join("agentx.lock"), "old lock\n").unwrap();
    fs::write(
        project.join("agentx.yaml"),
        "version: 1\nskills:\n  - name: foo.bar\n    source: { type: local, path: skills/foo.bar }\n  - name: foo.baz\n    source: { type: local, path: skills/foo.baz }\nrules:\n  - source: rules/team.md\nmcp:\n  - name: docs\n    command: npx\n    args: [\"-y\", \"docs-mcp\"]\n",
    )
    .unwrap();

    install(&project, &home, "codex");
    let rules = fs::read_to_string(project.join("AGENTS.md")).unwrap();
    assert!(rules.contains("# User rules"));
    assert!(rules.contains("# Team rules"));
    let config = fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert!(config.contains("mcp_servers.existing"));
    assert!(config.contains("mcp_servers.docs"));

    let output = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .arg("rollback")
        .current_dir(&project)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(project.join("AGENTS.md")).unwrap(),
        "# User rules\n"
    );
    assert_eq!(
        fs::read_to_string(project.join("agentx.lock")).unwrap(),
        "old lock\n"
    );
    assert_eq!(
        fs::read_to_string(home.join(".codex/config.toml")).unwrap(),
        "[mcp_servers.existing]\ncommand = \"keep\"\n"
    );
    for name in ["foo.bar", "foo.baz"] {
        assert_eq!(
            fs::read_to_string(home.join(".codex/skills").join(name).join("SKILL.md")).unwrap(),
            format!("# Old {name}\n")
        );
    }
    assert!(!project.join(".agentx/rollback.json").exists());

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
}
