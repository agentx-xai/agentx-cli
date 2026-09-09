//! Command-line parsing adapter.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "agentx", about = "Reproducible AI agent environments")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Init,
    Install {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        frozen: bool,
    },
    Diff {
        #[arg(long)]
        target: Option<String>,
    },
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
pub(crate) enum RegistryCommands {
    Login {
        url: String,
        #[arg(long, conflicts_with_all = ["token_stdin", "oidc"])]
        token: Option<String>,
        #[arg(long, conflicts_with_all = ["token", "oidc"])]
        token_stdin: bool,
        #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
        oidc: bool,
        #[arg(long)]
        workspace: Option<String>,
    },
    Workspaces,
    Use {
        workspace: String,
    },
    Logout,
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
pub(crate) enum TeamCommands {
    Pull {
        #[arg(long, default_value = "agentx.team.yaml")]
        output: PathBuf,
    },
    Push {
        #[arg(long, default_value = "agentx.team.yaml")]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum AgentCommands {
    Plan {
        #[arg(long)]
        device: String,
    },
    Sync {
        #[arg(long)]
        device: String,
        #[arg(long, default_value = "codex")]
        target: String,
    },
    Rollback {
        #[arg(long)]
        device: String,
        #[arg(long, default_value = "codex")]
        target: String,
    },
}

pub(crate) fn parse() -> Cli {
    Cli::parse()
}
