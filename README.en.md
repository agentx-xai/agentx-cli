# AgentX CLI

[中文](README.md) | English

AgentX CLI turns one declarative `agentx.yaml` into reproducible Skills, Rules, and MCP configuration for Codex, Claude Code, Cursor, Windsurf, Gemini CLI, GitHub Copilot, Cline, and Grok Build.

## Quick start

```bash
cargo run -- init
cargo run -- lock
cargo run -- install --yes --frozen
cargo run -- diff
```

Use `--target` to install or inspect one adapter:

```bash
agentx install --target cursor --yes --frozen
agentx diff --target grok
```

Without `--target`, the backwards-compatible default installs Codex and Claude Code.

## Adapter matrix

| Target | Rules | Skills | MCP |
| --- | --- | --- | --- |
| `codex` | project `AGENTS.md` managed block | `~/.codex/skills` | `~/.codex/config.toml` |
| `claude` | project `CLAUDE.md` managed block | `~/.claude/skills` | project `.mcp.json` |
| `cursor` | `.cursor/rules/agentx.mdc` | `.cursor/skills` | `.cursor/mcp.json` |
| `windsurf` | `.windsurf/rules/agentx.md` | `.windsurf/skills` | `.windsurf/mcp_config.json` |
| `gemini` | `GEMINI.md` | `.gemini/skills` | `.gemini/settings.json` |
| `copilot` | `.github/copilot-instructions.md` | `.github/skills` | `~/.copilot/mcp-config.json` |
| `cline` | `.clinerules/agentx.md` | `.cline/skills` | `.cline/mcp_settings.json` |
| `grok` | `.grok/rules/agentx.md` | `.grok/skills` | `.grok/config.toml`, `[mcp_servers.<name>]` |

Codex and Claude rules preserve user content outside AgentX managed markers. Existing JSON/TOML configuration is preserved and only the declared server entries are updated. The current manifest format supports MCP `command` and `args`; URL, headers, and environment-specific transports are intentionally not synthesized.

## Registry and devices

```bash
agentx registry login https://registry.example.com --token "$AGENTX_TOKEN" --workspace "$AGENTX_WORKSPACE_ID"
agentx team pull --output agentx.yaml
agentx agent plan --device "$AGENTX_DEVICE_ID"
agentx agent sync --device "$AGENTX_DEVICE_ID"
agentx agent rollback --device "$AGENTX_DEVICE_ID"
```

Registry credentials are stored in the user configuration directory, never in the project manifest. Artifact downloads are checked against SHA-256. Workspace policies can require Ed25519 signatures and administrator approval.

## Development

```bash
cargo fmt --check
cargo test
cargo build --release
```

Push a semantic version tag such as `v0.1.2` to create a release. The tag workflow runs tests and builds first; the release workflow publishes the Linux archive, README, and `SHA256SUMS`. See [`PRODUCT.en.md`](PRODUCT.en.md) for the complete manifest, security, hosted Registry, and rollback model.
