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
    fs::write(project.join("skills/demo/SKILL.md"), "# Demo\n").unwrap();
    fs::write(project.join("rules/team.md"), "# Team rules\n").unwrap();
    fs::write(
        project.join("agentx.yaml"),
        "version: 1\nskills:\n  - name: demo\n    source: { type: local, path: skills/demo }\nrules:\n  - source: rules/team.md\nmcp:\n  - name: docs\n    command: npx\n    args: [\"-y\", \"docs-mcp\"]\n",
    )
    .unwrap();

    for target in [
        "codex", "claude", "cursor", "windsurf", "gemini", "copilot", "cline",
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
        project.join(".windsurf/mcp_config.json"),
        project.join(".gemini/settings.json"),
        home.join(".copilot/mcp-config.json"),
        project.join(".cline/mcp_settings.json"),
    ] {
        assert!(
            path.is_file(),
            "missing generated MCP config: {}",
            path.display()
        );
    }

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
}
