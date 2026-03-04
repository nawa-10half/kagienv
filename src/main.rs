mod commands;
mod vault;

use clap::{Parser, Subcommand};

/// A local-first secret manager for developers
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a secret to the vault
    Add {
        /// Name of the secret
        name: String,
        /// Value of the secret
        value: String,
    },
    /// List all secrets in the vault
    List,
    /// Delete a secret from the vault
    Delete {
        /// Name of the secret to delete
        name: String,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Scan the codebase for hardcoded secrets
    Scan,
    /// Install git hooks for secret scanning
    InstallHooks,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Add { name, value } => commands::add::execute(&name, &value),
        Commands::List => commands::list::execute(),
        Commands::Delete { name } => commands::delete::execute(&name),
        Commands::Run { command } => commands::run::execute(&command),
        Commands::Scan => commands::scan::execute(),
        Commands::InstallHooks => commands::install_hooks::execute(),
    }
}
