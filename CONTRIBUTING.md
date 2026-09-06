# Contributing to AgentX CLI

Use the [organization contribution guide](https://github.com/agentx-xai/.github/blob/main/CONTRIBUTING.md) for the shared review and security rules.

## Local checks

```bash
cargo fmt --manifest-path Cargo.toml -- --check
cargo test --manifest-path Cargo.toml
cargo build --manifest-path Cargo.toml --release
```

Adapter changes should include target-specific tests. Do not copy credentials, sessions, caches, or generated build output into a package. Changes to Manifest or lockfile behavior must document compatibility impact in the pull request.
