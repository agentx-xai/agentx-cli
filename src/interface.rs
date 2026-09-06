//! CLI interface adapter. Command parsing is kept separate from the application facade.
/// Agent formats supported by the local compiler.
pub const SUPPORTED_TARGETS: &[&str] = &[
    "codex", "claude", "cursor", "windsurf", "gemini", "copilot", "cline", "grok",
];
