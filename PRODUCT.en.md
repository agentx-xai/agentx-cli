# AgentX Product Guide

[中文](PRODUCT.md) | English

## Product scope

AgentX is a local-first environment compiler. A project manifest describes Skills, Rules, MCP servers, and target agents. The CLI resolves sources, records a lockfile, scans content, writes native adapter files, reports drift, and can restore the previous installation. It does not copy API keys, login sessions, chat history, or caches.

The hosted components are the Registry API and Web Console. The Registry stores team Workspaces, memberships, policies, manifests, immutable artifacts, devices, audit events, and outbox jobs.

## Manifest

```yaml
version: 1
skills:
  - name: review
    source: { type: local, path: skills/review }
    targets: [codex, claude]
rules:
  - source: rules/team.md
    targets: [codex, claude]
mcp:
  - name: docs
    command: npx
    args: [-y, '@example/docs-mcp']
    targets: [codex]
```

Skills use a local directory or a Git URL with an optional fixed `ref`. Relative paths are resolved from the project root; traversal, symlinks, oversized files, unsafe names, and unsupported targets are rejected. MCP entries currently contain only `name`, `command`, `args`, and optional `targets`. URL, headers, and environment-variable transports are not represented by this schema and must be configured natively.

The supported output locations are listed in [`README.en.md`](README.en.md). Rules and MCP files are backed up before installation. `rollback` restores those files and Skill directories; pre-existing Codex and Claude rule text outside the managed markers is retained.

## Lock, install, diff

`agentx lock` records each Skill source, Git ref, and content SHA-256 in `agentx.lock`. `agentx install --frozen` refuses changed source content. `agentx diff` checks Skills, Rules, and MCP for the selected target; `--target` accepts one of `codex`, `claude`, `cursor`, `windsurf`, `gemini`, `copilot`, `cline`, or `grok`. `doctor` reports CLI availability and configured adapter locations.

Installation runs a security scan before mutating files. The scan rejects symlinks and files larger than 2 MiB in Skill sources. MCP commands are executable on a developer machine, so review a team manifest before installing it.

## Registry model

The CLI can use a local file-backed Server or a hosted PostgreSQL/S3 deployment:

```bash
agentx registry login https://registry.example.com --token "$AGENTX_TOKEN" --workspace "$AGENTX_WORKSPACE_ID"
agentx registry publish review-skill 1.2.3 ./review-skill.tar --signature "$SIGNATURE"
agentx registry pull review-skill 1.2.3 --output ./review-skill.tar
agentx team pull --output agentx.yaml
agentx team push --input agentx.yaml
```

Artifacts are immutable and addressed by SHA-256. A Workspace Manifest records desired package name, version, and digest. `team push` is an administrator operation. A policy may require a verified Ed25519 signature and/or approval; pending releases cannot be downloaded through scoped endpoints.

## Devices, drift, and rollback

Devices report installed package digests through heartbeat. `agentx agent plan` returns `install`, `update`, and `remove` actions from the Workspace Manifest. `agentx agent sync` downloads and verifies artifacts, saves the previous state under `.agentx/devices/<id>/`, then sends heartbeat. `agentx agent rollback` restores that state and reports it to the Registry. Server Drift compares observed device packages with the Workspace Manifest, while the Web Console exposes the same view.

## Hosted mode and security

Server hosted mode uses PostgreSQL for Workspace-scoped state and optionally S3/MinIO for artifact objects. OIDC discovery/JWKS, HMAC JWT, or a Bearer API token can protect the API. Legacy unscoped routes are disabled by default and must be explicitly enabled with `AGENTX_ALLOW_LEGACY_UNSCOPED=true` for development. Do not place tokens, cloud credentials, or untrusted executable MCP commands in source control.

## Verification and releases

Run `cargo fmt --check`, `cargo test`, and `cargo build --release` before publishing. A semantic version tag (`vMAJOR.MINOR.PATCH`) triggers the tag workflow, which repeats checks. The release workflow uploads the binary archive and `SHA256SUMS`; consumers should run `sha256sum -c SHA256SUMS`.
