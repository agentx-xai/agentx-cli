use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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

#[test]
fn install_plan_discloses_commands_arguments_and_target_paths() {
    let project = temp_dir("plan-project");
    let home = temp_dir("plan-home");
    fs::create_dir_all(project.join("skills/demo")).unwrap();
    fs::write(project.join("skills/demo/SKILL.md"), "# Demo\n").unwrap();
    fs::write(
        project.join("agentx.yaml"),
        "version: 1\nskills:\n  - name: demo\n    source: { type: local, path: skills/demo }\nmcp:\n  - name: docs\n    command: sh\n    args: [\"-lc\", \"docs --token $DOCS_TOKEN\"]\n    targets: [codex]\n",
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .args(["install", "--target", "codex"])
        .current_dir(&project)
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("command \"sh\"; args [\"-lc\", \"docs --token $DOCS_TOKEN\"]"));
    assert!(stdout.contains("environment refs [DOCS_TOKEN]"));
    assert!(stdout.contains(&home.join(".codex/config.toml").display().to_string()));
    assert!(stdout.contains(&home.join(".codex/skills/demo").display().to_string()));

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
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

fn rollback(project: &Path, home: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_agentx"))
        .arg("rollback")
        .current_dir(project)
        .env("HOME", home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rollback failed: {}",
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
        project.join(".mcp.json"),
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

    rollback(&project, &home);
    for path in [
        project.join("AGENTS.md"),
        project.join("CLAUDE.md"),
        project.join(".mcp.json"),
        home.join(".codex/config.toml"),
        home.join(".codeium/windsurf/mcp_config.json"),
        home.join(".cline/mcp.json"),
    ] {
        assert!(
            !path.exists(),
            "rollback left generated path: {}",
            path.display()
        );
    }

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
}
